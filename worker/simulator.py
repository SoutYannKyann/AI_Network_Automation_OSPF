"""Tiny in-process Cisco IOS simulator (SIMULATE_DEVICES=1) so the whole Kafka/worker pipeline can
be demonstrated and tested without GNS3. It models just enough: running-config, interface state,
OSPF adjacency between simulated routers that share an advertised, non-passive subnet, OSPF routes
and ping reachability. Not used when talking to real routers."""
from __future__ import annotations

import ipaddress
import re
import threading

from app.safety import normalize_ifname

_REGISTRY: dict[str, "SimRouter"] = {}
_LOCK = threading.Lock()


def reset_simulation() -> None:
    with _LOCK:
        _REGISTRY.clear()


def get_sim(device: str, mgmt_ip: str, interfaces: list[str]) -> "SimRouter":
    with _LOCK:
        if device not in _REGISTRY:
            _REGISTRY[device] = SimRouter(device, mgmt_ip, interfaces)
        return _REGISTRY[device]


class SimRouter:
    def __init__(self, device: str, mgmt_ip: str, interfaces: list[str]):
        self.hostname = "Router"
        self.mgmt_if = normalize_ifname(interfaces[0])
        self.ifaces: dict[str, list[str]] = {normalize_ifname(n): ["shutdown"] for n in interfaces}
        self.ifaces[self.mgmt_if] = [f"ip address {mgmt_ip} 255.255.255.0"]
        self.router: dict[str, list[str]] = {}
        self.mode: str | None = None  # None=exec, "global", or block header
        self.saved = False

    # interface the worker expects -------------------------------------------------
    def connect(self):
        return self

    def close(self):
        self.mode = None

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()

    def send(self, command: str, timeout: float | None = None) -> str:
        cmd = command.strip()
        if "INVALID" in cmd:
            return "% Invalid input detected at '^' marker."
        if self.mode is not None:
            return self._config(cmd)
        if cmd.startswith("terminal"):
            return ""
        if cmd in ("configure terminal", "conf t"):
            self.mode = "global"
            return "Enter configuration commands, one per line.  End with CNTL/Z."
        if cmd.startswith("show running-config") or cmd == "show run":
            return self.running_config()
        if cmd == "show ip interface brief":
            return self._ip_brief()
        if cmd == "show ip ospf neighbor":
            return self._neighbors_text()
        if cmd == "show ip route ospf":
            return self._routes_text()
        if cmd == "show ip protocols":
            return self._protocols_text()
        if cmd.startswith("ping "):
            return self._ping(cmd)
        if cmd in ("write memory", "copy running-config startup-config"):
            self.saved = True
            return "Building configuration...\n[OK]"
        if cmd.startswith("show"):
            return ""
        return "% Invalid input detected at '^' marker."

    # config mode -------------------------------------------------------------------
    def _config(self, cmd: str) -> str:
        if cmd == "end":
            self.mode = None
            return ""
        if cmd == "exit":
            self.mode = "global" if self.mode != "global" else None
            return ""
        m = re.match(r"^interface\s+(\S+)$", cmd)
        if m:
            name = normalize_ifname(m.group(1))
            if name not in self.ifaces:
                if name.startswith("Loopback"):
                    self.ifaces[name] = []
                else:
                    return "% Invalid input detected at '^' marker."
            self.mode = f"interface {name}"
            return ""
        if cmd.startswith("no interface Loopback"):
            self.ifaces.pop(normalize_ifname(cmd.split()[-1]), None)
            return ""
        m = re.match(r"^router ospf (\d+)$", cmd)
        if m:
            self.router.setdefault(m.group(1), [])
            self.mode = f"router ospf {m.group(1)}"
            return ""
        m = re.match(r"^no router ospf (\d+)$", cmd)
        if m:
            self.router.pop(m.group(1), None)
            return ""
        if cmd.startswith("hostname "):
            self.hostname = cmd.split(None, 1)[1]
            return ""
        if self.mode == "global":
            return "% Invalid input detected at '^' marker."
        children = self._children(self.mode)
        if self.mode.startswith("interface ") and self.mode.split()[1] == self.mgmt_if:
            pass  # allowed by the simulator; the worker's own guard prevents this
        if cmd.startswith("no "):
            body = cmd[3:]
            if body == "shutdown":
                children[:] = [c for c in children if c != "shutdown"]
            elif body == "ip address":
                children[:] = [c for c in children if not c.startswith("ip address")]
            elif body == "description":
                children[:] = [c for c in children if not c.startswith("description")]
            else:
                children[:] = [c for c in children if c != body]
            return ""
        if cmd.startswith("ip address "):
            parts = cmd.split()
            try:
                new = ipaddress.IPv4Interface(f"{parts[2]}/{parts[3]}")
            except (ValueError, IndexError):
                return "% Invalid input detected at '^' marker."
            for other, ch in self.ifaces.items():
                if f"interface {other}" == self.mode:
                    continue
                for c in ch:
                    if c.startswith("ip address"):
                        o = ipaddress.IPv4Interface("/".join(c.split()[2:4]))
                        if o.network.overlaps(new.network):
                            return f"% {new.network} overlaps with {other}"
            children[:] = [c for c in children if not c.startswith("ip address")]
        if cmd.startswith("description "):
            children[:] = [c for c in children if not c.startswith("description")]
        if cmd.startswith("router-id "):
            children[:] = [c for c in children if not c.startswith("router-id")]
        if cmd not in children:
            children.append(cmd)
        return ""

    def _children(self, header: str) -> list[str]:
        if header.startswith("interface "):
            return self.ifaces[header.split()[1]]
        return self.router[header.split()[2]]

    # state helpers -----------------------------------------------------------------
    def _addr(self, name: str):
        for c in self.ifaces.get(name, []):
            if c.startswith("ip address"):
                p = c.split()
                return ipaddress.IPv4Interface(f"{p[2]}/{p[3]}")
        return None

    def _up(self, name: str) -> bool:
        return "shutdown" not in self.ifaces.get(name, [])

    def _ospf(self):
        if not self.router:
            return None, []
        pid, ch = next(iter(self.router.items()))
        return pid, ch

    def router_id(self) -> str | None:
        _, ch = self._ospf()
        rid = next((c.split()[1] for c in ch if c.startswith("router-id")), None)
        return rid

    def _enabled_ifaces(self) -> list[tuple[str, ipaddress.IPv4Interface, bool]]:
        pid, ch = self._ospf()
        if pid is None:
            return []
        nets = []
        for c in ch:
            m = re.match(r"^network (\S+) (\S+) area 0$", c)
            if m:
                mask = str(ipaddress.IPv4Address(int(ipaddress.IPv4Address(m.group(2))) ^ 0xFFFFFFFF))
                nets.append(ipaddress.IPv4Network(f"{m.group(1)}/{mask}", strict=False))
        passive = {normalize_ifname(c.split()[1]) for c in ch if c.startswith("passive-interface ")}
        out = []
        for name in self.ifaces:
            a = self._addr(name)
            if a and self._up(name) and any(a.ip in n for n in nets):
                out.append((name, a, name in passive))
        return out

    def neighbors(self) -> list[dict]:
        out = []
        for name, a, passive in self._enabled_ifaces():
            if passive:
                continue
            for other in list(_REGISTRY.values()):
                if other is self or not other.router_id() or not self.router_id():
                    continue
                for oname, oa, opassive in other._enabled_ifaces():
                    if not opassive and oa.network == a.network:
                        out.append({"rid": other.router_id(), "addr": str(oa.ip), "intf": name, "peer": other})
        return out

    def connected(self) -> list[ipaddress.IPv4Network]:
        return [self._addr(n).network for n in self.ifaces if self._addr(n) and self._up(n)]

    def ospf_routes(self) -> list[tuple[ipaddress.IPv4Network, str, str]]:
        """Networks advertised by any router reachable through FULL adjacencies (BFS), minus connected."""
        mine = set(self.connected())
        routes, seen, frontier = {}, {id(self)}, [(n, n["addr"], n["intf"]) for n in self.neighbors()]
        while frontier:
            nb, nh, intf = frontier.pop(0)
            peer = nb["peer"]
            if id(peer) in seen:
                continue
            seen.add(id(peer))
            for _, oa, _ in peer._enabled_ifaces():
                if oa.network not in mine and oa.network not in routes:
                    routes[oa.network] = (nh, intf)
            frontier.extend((n2, nh, intf) for n2 in peer.neighbors())
        return [(net, nh, intf) for net, (nh, intf) in sorted(routes.items())]

    # show output ---------------------------------------------------------------------
    def running_config(self) -> str:
        lines = ["Building configuration...", "", "Current configuration : 1024 bytes", "!",
                 f"hostname {self.hostname}", "!"]
        for name, ch in self.ifaces.items():
            lines.append(f"interface {name}")
            if not any(c.startswith("ip address") for c in ch):
                lines.append(" no ip address")
            lines.extend(f" {c}" for c in ch)
            lines.append("!")
        for pid, ch in self.router.items():
            lines.append(f"router ospf {pid}")
            order = sorted(ch, key=lambda c: (not c.startswith("router-id"), not c.startswith("passive"), c))
            lines.extend(f" {c}" for c in order)
            lines.append("!")
        lines += ["line vty 0 4", " login local", " transport input ssh", "!", "end"]
        return "\n".join(lines)

    def _ip_brief(self) -> str:
        rows = ["Interface                  IP-Address      OK? Method Status                Protocol"]
        for name in self.ifaces:
            a = self._addr(name)
            st = "up" if self._up(name) else "administratively down"
            pr = "up" if self._up(name) else "down"
            rows.append(f"{name:<26} {str(a.ip) if a else 'unassigned':<15} YES manual {st:<21} {pr}")
        return "\n".join(rows)

    def _neighbors_text(self) -> str:
        rows = ["Neighbor ID     Pri   State           Dead Time   Address         Interface"]
        for n in self.neighbors():
            rows.append(f"{n['rid']:<15} {0:>3}   FULL/  -        00:00:35    {n['addr']:<15} {n['intf']}")
        return "\n".join(rows)

    def _routes_text(self) -> str:
        rows = ["Codes: L - local, C - connected, S - static, R - RIP, M - mobile, B - BGP", "",
                "Gateway of last resort is not set", ""]
        for net, nh, intf in self.ospf_routes():
            rows.append(f"O        {net} [110/2] via {nh}, 00:00:12, {intf}")
        return "\n".join(rows)

    def _protocols_text(self) -> str:
        pid, ch = self._ospf()
        if pid is None:
            return '*** IP Routing is NSF aware ***\n'
        passive = [c.split()[1] for c in ch if c.startswith("passive-interface ")]
        txt = [f'Routing Protocol is "ospf {pid}"', f"  Router ID {self.router_id() or '0.0.0.0'}",
               "  Number of areas in this router is 1. 1 normal 0 stub 0 nssa", "  Routing for Networks:"]
        txt += [f"    {' '.join(c.split()[1:3])} area 0" for c in ch if c.startswith("network ")]
        if passive:
            txt.append("  Passive Interface(s):")
            txt += [f"    {p}" for p in passive]
        txt.append("  Distance: (default is 110)")
        return "\n".join(txt) + "\n"

    def _ping(self, cmd: str) -> str:
        m = re.match(r"^ping (\S+)(?: source (\S+))?", cmd)
        target = ipaddress.IPv4Address(m.group(1))
        reachable = any(target in n for n in self.connected()) or any(target in net for net, _, _ in self.ospf_routes())
        owner = any(any(a and a.ip == target for a in (r._addr(n) for n in r.ifaces)) for r in _REGISTRY.values())
        ok = reachable and owner
        bang = "!!!!!" if ok else "....."
        rate = 100 if ok else 0
        return (f"Type escape sequence to abort.\nSending 5, 100-byte ICMP Echos to {target}, timeout is 2 seconds:\n"
                f"{bang}\nSuccess rate is {rate} percent ({5 if ok else 0}/5)")
