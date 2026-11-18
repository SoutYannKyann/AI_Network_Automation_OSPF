"""Parsers for IOS show output + running-config diff/rollback helpers."""
from __future__ import annotations

import ipaddress
import re

from app.safety import normalize_ifname

IP = r"\d{1,3}(?:\.\d{1,3}){3}"

# Lines IOS prints that mean the command failed.
ERROR_RE = re.compile(r"^\s*(% ?(Invalid|Incomplete|Ambiguous|Unknown|Unrecognized|Bad mask|Error|"
                      r".*overlaps with|.*not enabled|.*does not exist)|%Error)", re.IGNORECASE | re.MULTILINE)
# Informational messages that look like errors but are safe.
BENIGN_RE = re.compile(r"% OSPF: Reload or use \"clear ip ospf process\"", re.IGNORECASE)


def find_error(output: str) -> str | None:
    for line in output.splitlines():
        if BENIGN_RE.search(line):
            continue
        if ERROR_RE.search(line):
            return line.strip()
    return None


# ------------------------------------------------------------------ show parsers
def parse_ip_int_brief(text: str) -> list[dict]:
    rows = []
    rx = re.compile(rf"^(\S+)\s+({IP}|unassigned)\s+(YES|NO)\s+(\S+)\s+(administratively down|up|down)\s+(up|down)",
                    re.IGNORECASE)
    for line in text.splitlines():
        m = rx.match(line.strip())
        if m:
            rows.append({"name": m.group(1), "ip": m.group(2), "status": m.group(5), "protocol": m.group(6)})
    return rows


def parse_ospf_neighbors(text: str) -> list[dict]:
    rx = re.compile(rf"^(?P<rid>{IP})\s+(?P<pri>\d+)\s+(?P<state>[A-Z0-9\-]+)/\s*(?P<role>[A-Z\-]*)\s+"
                    rf"(?P<dead>\S+)\s+(?P<addr>{IP})\s+(?P<intf>\S+)")
    out = []
    for line in text.splitlines():
        m = rx.match(line.strip())
        if m:
            out.append({"router_id": m["rid"], "state": m["state"], "role": m["role"] or "-",
                        "address": m["addr"], "interface": m["intf"]})
    return out


def parse_ospf_routes(text: str) -> list[dict]:
    """Handles both '10.2.0.0/24 [110/2] via' and classful-header styles ('is subnetted')."""
    out, default_len = [], None
    hdr = re.compile(rf"^\s*({IP})/(\d+) is (variably )?subnetted")
    rx = re.compile(rf"^O(?:\s+(?:IA|E1|E2|N1|N2))?\s+({IP})(/\d+)?\s+\[(\d+)/(\d+)\]\s+via\s+({IP})")
    for line in text.splitlines():
        h = hdr.match(line)
        if h:
            default_len = None if h.group(3) else int(h.group(2))
            continue
        m = rx.match(line.strip())
        if m:
            plen = int(m.group(2)[1:]) if m.group(2) else (default_len or 32)
            out.append({"prefix": str(ipaddress.IPv4Network(f"{m.group(1)}/{plen}", strict=False)),
                        "ad": int(m.group(3)), "metric": int(m.group(4)), "next_hop": m.group(5)})
    return out


def parse_ip_protocols(text: str) -> dict:
    pid = re.search(r'Routing Protocol is "ospf (\d+)"', text)
    rid = re.search(rf"Router ID ({IP})", text)
    passive: list[str] = []
    lines = text.splitlines()
    for n, line in enumerate(lines):
        if "Passive Interface(s):" in line:
            indent = len(line) - len(line.lstrip())
            for entry in lines[n + 1:]:
                if not entry.strip() or len(entry) - len(entry.lstrip()) <= indent or ":" in entry:
                    break
                passive.append(normalize_ifname(entry.strip()))
    return {"ospf_process": int(pid.group(1)) if pid else None,
            "router_id": rid.group(1) if rid else None, "passive_interfaces": passive}


def parse_ping(text: str) -> dict:
    m = re.search(r"Success rate is (\d+) percent \((\d+)/(\d+)\)", text)
    if not m:
        return {"success_rate": 0, "received": 0, "sent": 0}
    return {"success_rate": int(m.group(1)), "received": int(m.group(2)), "sent": int(m.group(3))}


# ------------------------------------------------------------------ config diff (idempotency)
def parse_config_blocks(text: str) -> tuple[set[str], dict[str, list[str]]]:
    """Split IOS config into top-level single lines and {header: [children]} blocks."""
    singles: set[str] = set()
    blocks: dict[str, list[str]] = {}
    current = None
    for raw in text.splitlines():
        line = raw.rstrip()
        if not line.strip() or line.strip().startswith("!") or line.strip() in ("end", "exit"):
            if line.strip().startswith("!"):
                current = None
            continue
        if line.startswith(" ") and current is not None:
            blocks[current].append(line.strip())
        else:
            current = None
            key = _norm_header(line.strip())
            if re.match(r"^(interface|router|line|ip vrf|vrf definition|key chain)\b", key, re.IGNORECASE):
                current = key
                blocks.setdefault(current, [])
            else:
                singles.add(key)
    return singles, blocks


def _norm_header(line: str) -> str:
    m = re.match(r"^interface\s+(\S+)$", line, re.IGNORECASE)
    return f"interface {normalize_ifname(m.group(1))}" if m else line


def _child_present(child: str, running_children: list[str]) -> bool:
    if child == "no shutdown":
        return "shutdown" not in running_children
    if child.startswith("passive-interface "):
        name = normalize_ifname(child.split(None, 1)[1])
        return any(c.startswith("passive-interface ") and normalize_ifname(c.split(None, 1)[1]) == name
                   for c in running_children)
    return child in running_children


def _ip_line(children: list[str]) -> ipaddress.IPv4Interface | None:
    for c in children:
        m = re.match(rf"^ip address ({IP}) ({IP})$", c)
        if m:
            return ipaddress.IPv4Interface(f"{m.group(1)}/{m.group(2)}")
    return None


def cleanup_lines(desired: str, running: str, protected: set[str] | None = None) -> list[str]:
    """Lines that remove state conflicting with `desired`, so a corrected plan (e.g. a remapped
    interface or a changed topology) can be redeployed without touching the router by hand:
      * `no ip address` on any non-protected interface whose current IP sits in a plan subnet but is
        not exactly what the plan wants there (avoids '% ... overlaps with ...');
      * `no network` / `no passive-interface` lines under the planned OSPF process that the plan
        no longer contains. Protected (management) interfaces are never touched."""
    protected = {normalize_ifname(p) for p in (protected or set()) if p}
    _, want_blocks = parse_config_blocks(desired)
    _, have_blocks = parse_config_blocks(running)
    plan_nets = []
    for header, ch in want_blocks.items():
        if header.startswith("interface "):
            a = _ip_line(ch)
            if a:
                plan_nets.append(a.network)
    out: list[str] = []
    for header, ch in have_blocks.items():
        if not header.startswith("interface ") or header.split(None, 1)[1] in protected:
            continue
        cur = _ip_line(ch)
        if cur is None or not any(cur.ip in n for n in plan_nets):
            continue
        wanted = _ip_line(want_blocks.get(header, []))
        if wanted != cur:
            out += [header, " no ip address", " exit"]
    for header, want_ch in want_blocks.items():
        if not header.startswith("router ospf"):
            continue
        want_pass = {normalize_ifname(c.split(None, 1)[1]) for c in want_ch if c.startswith("passive-interface ")}
        stale = [c for c in have_blocks.get(header, [])
                 if (c.startswith("network ") and c not in want_ch)
                 or (c.startswith("passive-interface ") and normalize_ifname(c.split(None, 1)[1]) not in want_pass)]
        if stale:
            out += [header] + [f" no {c}" for c in stale] + [" exit"]
    return out


def diff_config(desired: str, running: str, protected: set[str] | None = None) -> list[str]:
    """Return the minimal list of config-mode lines (with headers) needed to reach `desired`:
    cleanup of conflicting state first, then missing lines. Empty list = already compliant
    (idempotent no-op)."""
    want_singles, want_blocks = parse_config_blocks(desired)
    have_singles, have_blocks = parse_config_blocks(running)
    todo: list[str] = []
    for s in sorted(want_singles):
        if s not in have_singles:
            todo.append(s)
    todo += cleanup_lines(desired, running, protected)  # an address is only cleared when it differs
    for header, children in want_blocks.items():
        have = have_blocks.get(header)
        missing = [c for c in children if have is None or not _child_present(c, have)]
        if have is None or missing:
            todo.append(header)
            todo.extend(f" {c}" for c in missing)
            todo.append(" exit")
    return todo


_PHYSICAL_RE = re.compile(r"^((fast|gigabit|tengigabit)?ethernet|serial)", re.IGNORECASE)


def reset_lines(running: str, protected: set[str] | None = None) -> list[str]:
    """Undeploy: config-mode lines that return the data plane to its pre-deployment state.
    Non-protected physical interfaces lose their ip address / description / 'ip ospf' lines and are
    shut; Loopbacks are deleted; every OSPF process is removed. Protected (management) interfaces,
    hostname, users, SSH and vty settings are never touched. Empty list = already reset."""
    protected = {normalize_ifname(p) for p in (protected or set()) if p}
    _, blocks = parse_config_blocks(running)
    out: list[str] = []
    for header, ch in blocks.items():
        if header.startswith("interface "):
            name = header.split(None, 1)[1]
            if name in protected:
                continue
            if name.lower().startswith("loopback"):
                out.append(f"no {header}")
                continue
            if not _PHYSICAL_RE.match(name):
                continue
            sub = []
            if any(c.startswith("ip address ") for c in ch):
                sub.append(" no ip address")
            if any(c.startswith("description ") for c in ch):
                sub.append(" no description")
            sub += [f" no {c}" for c in ch if c.startswith("ip ospf ")]
            if "shutdown" not in ch:
                sub.append(" shutdown")
            if sub:
                out += [header, *sub, " exit"]
        elif re.match(r"^router ospf \d+$", header, re.IGNORECASE):
            out.append(f"no {header}")
    return out


def rollback_lines(applied: list[str], running_before: str) -> list[str]:
    """Compensating commands for lines actually applied (reverse order). The management
    interface is never in `applied`, so rollback cannot cut SSH access."""
    have_singles, have_blocks = parse_config_blocks(running_before)
    out: list[str] = []
    header = None
    groups: list[tuple[str | None, list[str]]] = []
    for line in applied:
        if line.strip() == "exit":
            continue
        if not line.startswith(" "):
            header = line.strip()
            groups.append((header, []))
        elif groups:
            groups[-1][1].append(line.strip())
    for header, children in reversed(groups):
        is_block = bool(re.match(r"^(interface|router)\b", header, re.IGNORECASE))
        if not is_block:
            if header.startswith("hostname "):
                old = next((s for s in have_singles if s.startswith("hostname ")), None)
                if old:
                    out.append(old)
            else:
                out.append(_negate(header))
            continue
        existed = _norm_header(header) in have_blocks
        if header.lower().startswith("router ") and not existed:
            out.append(f"no {header}")
            continue
        if header.lower().startswith("interface loopback") and not existed:
            out.append(f"no {header}")
            continue
        old_children = have_blocks.get(_norm_header(header), [])
        out.append(header)
        for c in reversed(children):
            if c == "no ip address":
                keyword = "ip address "          # undo a cleanup: restore the old address
            else:
                keyword = next((k for k in ("ip address ", "description ") if c.startswith(k)), None)
            previous = next((o for o in old_children if keyword and o.startswith(keyword)), None)
            out.append(f" {previous}" if previous else f" {_negate(c)}")  # restore old value if there was one
        out.append(" exit")
    return out


def _negate(line: str) -> str:
    s = line.strip()
    if s == "no shutdown":
        return "shutdown"
    if s.startswith("no "):
        return s[3:]
    if s.startswith("ip address "):
        return "no ip address"
    if s.startswith("description "):
        return "no description"
    return f"no {s}"
