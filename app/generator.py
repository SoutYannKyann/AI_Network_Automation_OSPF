"""Cisco IOS / OSPFv2 config generator (Jinja2). Nothing is hardcoded to the exam topology:
everything is derived from the validated Extraction + discovered interface names."""
from __future__ import annotations

import ipaddress
import json
from dataclasses import dataclass, field
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, StrictUndefined

from .models import Extraction, Role, VerifyExpectation
from .safety import sha256_text

_env = Environment(loader=FileSystemLoader(Path(__file__).parent / "templates"),
                   undefined=StrictUndefined, trim_blocks=False, lstrip_blocks=False,
                   keep_trailing_newline=True)


@dataclass
class DeviceConfig:
    device: str
    role: str
    text: str
    sha256: str
    deployable: bool
    verification_cmds: list[str] = field(default_factory=list)
    expect: dict | None = None


def wildcard(mask: str) -> str:
    return str(ipaddress.IPv4Network(f"0.0.0.0/{mask}").hostmask)


def plan_hash(ex: Extraction) -> str:
    return sha256_text(json.dumps(ex.model_dump(mode="json"), sort_keys=True))


def _link_peer(ex: Extraction, link_id: str, me: str):
    link = next(l for l in ex.links if l.id == link_id)
    for ep in link.endpoints:
        if ep.device != me:
            d = ex.device(ep.device)
            i = next(x for x in d.interfaces if x.id == ep.interface)
            return link, d, i
    raise ValueError(f"link {link_id} has no peer for {me}")


def build_router_context(ex: Extraction, hostname: str, mgmt_interface: str | None = None,
                         loopback: bool = False) -> dict:
    r = ex.device(hostname)
    interfaces, passive, networks = [], [], []
    for i in sorted(r.interfaces, key=lambda x: x.id):
        link, peer, peer_if = _link_peer(ex, i.link, hostname)
        p2p = link.kind == "transit"
        interfaces.append({
            "name": i.name,
            "ip": i.ip, "mask": i.mask,
            "description": f"{'P2P' if p2p else 'LAN'} to {peer.hostname} ({link.subnet})",
            "p2p": p2p,
        })
        if link.kind == "lan" and ex.routing.passive_lan_interfaces:
            passive.append(i.name)
        net = ipaddress.IPv4Interface(f"{i.ip}/{i.mask}").network
        networks.append({"network": str(net.network_address), "wildcard": wildcard(i.mask)})
    return {
        "hostname": hostname, "router_id": r.router_id, "process_id": ex.routing.process_id,
        "area": ex.routing.area, "interfaces": interfaces, "passive": passive, "networks": networks,
        "mgmt_interface": mgmt_interface, "loopback": loopback, "plan_hash": plan_hash(ex),
    }


def router_expectation(ex: Extraction, hostname: str) -> VerifyExpectation:
    """What `verify` must observe on this router: FULL neighbors, remote prefixes as O routes, pings."""
    r = ex.device(hostname)
    local_nets = {str(ipaddress.IPv4Interface(f"{i.ip}/{i.mask}").network) for i in r.interfaces}
    neighbors, passive = [], []
    for i in r.interfaces:
        link, peer, _ = _link_peer(ex, i.link, hostname)
        if link.kind == "transit" and peer.router_id:
            neighbors.append(peer.router_id)
        if link.kind == "lan" and ex.routing.passive_lan_interfaces:
            passive.append(i.name)
    remote = sorted({l.subnet for l in ex.links} - local_nets)
    pings = []
    my_lans = [i for i in r.interfaces if _link_peer(ex, i.link, hostname)[0].kind == "lan"]
    if my_lans:
        src = my_lans[0].ip
        for other in ex.routers():
            if other.hostname == hostname:
                continue
            for oi in other.interfaces:
                link, peer, peer_if = _link_peer(ex, oi.link, other.hostname)
                if link.kind == "lan":
                    # remote router LAN interface: proves routing without depending on the PC
                    pings.append({"target": oi.ip, "source": src, "required": True})
                    if peer.role == Role.host:
                        # the remote PC itself: the end-to-end goal (needs the PC to be up)
                        pings.append({"target": peer_if.ip, "source": src, "required": False})
    return VerifyExpectation(process_id=ex.routing.process_id, router_id=r.router_id,
                             neighbors=sorted(set(neighbors)), ospf_prefixes=remote,
                             passive_interfaces=passive, pings=pings)


VERIFY_CMDS = ["show ip ospf neighbor", "show ip route ospf", "show ip protocols", "show ip interface brief"]
RESET_CMDS = ["show ip interface brief", "show ip protocols"]


def reset_spec(device: str) -> str:
    """The fixed, human-readable specification an Undeploy approval is bound to (its sha256 goes
    into the HMAC approval token, exactly like a deploy config). The worker computes the concrete
    removal lines from the router's running-config (worker.ios_parse.reset_lines)."""
    return (f"! reset-data-plane v1 for {device}\n"
            "! remove: ip address, description and 'ip ospf' lines on every non-management physical interface,\n"
            "!         shut those interfaces, delete Loopback interfaces, remove every 'router ospf' process\n"
            "! keep:   management interface, hostname, users, enable secret, SSH, vty lines\n")


def generate(ex: Extraction, discovery: dict | None = None, loopback: bool = False) -> list[DeviceConfig]:
    discovery = discovery or {}
    out: list[DeviceConfig] = []
    tpl_r = _env.get_template("router_ios.j2")
    tpl_h = _env.get_template("host_vpcs.j2")
    for d in ex.devices:
        if d.role == Role.router:
            ctx = build_router_context(ex, d.hostname, (discovery.get(d.hostname) or {}).get("mgmt_interface"),
                                       loopback)
            text = tpl_r.render(**ctx)
            out.append(DeviceConfig(d.hostname, "router", text, sha256_text(text), True, VERIFY_CMDS,
                                    router_expectation(ex, d.hostname).model_dump()))
        else:
            i = d.interfaces[0]
            gw = next((a.gateway for a in ex.addressing_plan if a.device == d.hostname and a.gateway), "")
            net = ipaddress.IPv4Interface(f"{i.ip}/{i.mask}")
            text = tpl_h.render(hostname=d.hostname, ip=i.ip, mask=i.mask, prefixlen=net.network.prefixlen,
                                gateway=gw)
            out.append(DeviceConfig(d.hostname, "host", text, sha256_text(text), False,
                                    ["show ip", f"ping {gw}"]))
    return out


def config_lines(text: str) -> list[str]:
    """Config lines to push (comments, '!' separators and 'end' removed; indentation kept)."""
    lines = []
    for raw in text.splitlines():
        s = raw.rstrip()
        if not s.strip() or s.strip().startswith("!") or s.strip() == "end":
            continue
        lines.append(s)
    return lines
