"""Safety primitives shared by API and worker: deny-list, redaction, approval tokens, hashing."""
from __future__ import annotations

import hashlib
import hmac
import os
import re

# Commands that are never allowed in an automated deployment. Disruptive commands
# (reload/erase) would need a separate, explicit confirmation flow which this system
# intentionally does not offer; management-plane commands could lock us out.
DENY_PATTERNS = [
    r"^\s*reload\b",
    r"^\s*(write\s+erase|erase\b)",
    r"^\s*delete\b",
    r"^\s*format\b",
    r"^\s*crypto\s+key\s+(zeroize|generate)",
    r"^\s*no\s+username\b",
    r"^\s*username\b",
    r"^\s*(no\s+)?enable\s+(secret|password)\b",
    r"^\s*(no\s+)?ip\s+ssh\b",
    r"^\s*line\s+(vty|con|aux)\b",
    r"^\s*(no\s+)?aaa\b",
    r"^\s*(no\s+)?ip\s+route\b",          # exam rule: no static routes replacing OSPF
    r"^\s*(no\s+)?ip\s+default-gateway\b",  # on routers
    r"^\s*(no\s+)?access-class\b",
    r"^\s*(no\s+)?transport\s+input\b",
    r"^\s*clear\b",
    r"^\s*config(ure)?\s+replace\b",
    r"^\s*(no\s+)?boot\b",
    r"^\s*(no\s+)?vrf\b",
    r"^\s*(no\s+)?ip\s+vrf\b",
]
_DENY_RE = [re.compile(p, re.IGNORECASE) for p in DENY_PATTERNS]

READ_ONLY_RE = re.compile(r"^\s*(show|ping|terminal)\b", re.IGNORECASE)


def denied_lines(config_text: str) -> list[str]:
    """Return config lines matching the deny-list."""
    bad = []
    for line in config_text.splitlines():
        if any(r.search(line) for r in _DENY_RE):
            bad.append(line.strip())
    return bad


def touches_interface(config_text: str, interface_name: str | None) -> bool:
    """True if the config contains an `interface <name>` block for the given interface."""
    if not interface_name:
        return False
    target = normalize_ifname(interface_name)
    for line in config_text.splitlines():
        m = re.match(r"^\s*interface\s+(\S+)", line, re.IGNORECASE)
        if m and normalize_ifname(m.group(1)) == target:
            return True
    return False


_IF_ABBREV = {
    "gi": "GigabitEthernet", "gig": "GigabitEthernet", "gigabitethernet": "GigabitEthernet",
    "fa": "FastEthernet", "fastethernet": "FastEthernet",
    "e": "Ethernet", "eth": "Ethernet", "ethernet": "Ethernet",
    "te": "TenGigabitEthernet", "tengigabitethernet": "TenGigabitEthernet",
    "se": "Serial", "serial": "Serial", "lo": "Loopback", "loopback": "Loopback",
}


def normalize_ifname(name: str) -> str:
    m = re.match(r"^([A-Za-z\-]+)\s*([\d/.:]+)$", name.strip())
    if not m:
        return name.strip()
    prefix = _IF_ABBREV.get(m.group(1).lower(), m.group(1))
    return f"{prefix}{m.group(2)}"


# ------------------------------------------------------------------ redaction
_REDACT_RES = [
    (re.compile(r"(\b(?:password|secret|key-string|key)\s+(?:\d\s+)?)(\S+)", re.IGNORECASE), r"\1***"),
    (re.compile(r"(\bsnmp-server\s+community\s+)(\S+)", re.IGNORECASE), r"\1***"),
    (re.compile(r"(sk-ant-[A-Za-z0-9_\-]{4})[A-Za-z0-9_\-]+"), r"\1***"),
    (re.compile(r"(AIza[A-Za-z0-9_\-]{4})[A-Za-z0-9_\-]{20,}"), r"\1***"),  # Google API keys
]

_SECRET_ENV_HINTS = ("PASSWORD", "SECRET", "TOKEN", "API_KEY")


def _secret_values() -> list[str]:
    vals = []
    for k, v in os.environ.items():
        if v and len(v) >= 4 and any(h in k.upper() for h in _SECRET_ENV_HINTS):
            vals.append(v)
    return sorted(set(vals), key=len, reverse=True)


def redact(text: str) -> str:
    """Mask credentials in any text that is logged, published to Kafka or shown in the UI."""
    if not text:
        return text
    for value in _secret_values():
        text = text.replace(value, "***")
    for rx, repl in _REDACT_RES:
        text = rx.sub(repl, text)
    return text


# ------------------------------------------------------------------ hashing / approval tokens
def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def approval_token(secret: str, approval_id: str, config_id: str, device: str, sha256: str) -> str:
    msg = f"{approval_id}|{config_id}|{device}|{sha256}".encode()
    return hmac.new(secret.encode(), msg, hashlib.sha256).hexdigest()


def verify_approval_token(secret: str, token: str, approval_id: str, config_id: str,
                          device: str, sha256: str) -> bool:
    expected = approval_token(secret, approval_id, config_id, device, sha256)
    return hmac.compare_digest(expected, token or "")
