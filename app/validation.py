"""Plan validation: addressing, subnet consistency, gateways, interface mapping, OSPF and management.

Each check yields an Issue(level, code, message, path). Any `error` blocks approval.
"""
from __future__ import annotations

import ipaddress
from collections import defaultdict
from dataclasses import asdict, dataclass

from .models import Extraction, Role
from .safety import normalize_ifname


@dataclass
class Issue:
    level: str  # error | warning | info
    code: str
    message: str
    path: str = ""

    def dict(self) -> dict:
        return asdict(self)


def _iface(ip: str, mask: str) -> ipaddress.IPv4Interface:
    return ipaddress.IPv4Interface(f"{ip}/{mask}")


def _valid_net(s: str) -> bool:
    try:
        ipaddress.IPv4Network(s, strict=False)
        return True
    except ValueError:
        return False


def _valid_ip(s: str) -> bool:
    try:
        ipaddress.IPv4Address(s)
        return True
    except ValueError:
        return False


def validate_mask(mask: str) -> bool:
    try:
        ipaddress.IPv4Network(f"0.0.0.0/{mask}")
        return True
    except ValueError:
        return False


def validate_plan(ex: Extraction, inventory: dict | None = None, discovery: dict | None = None,
                  reachability: dict | None = None, require_mapping: bool = False) -> list[Issue]:
    inventory = inventory or {}
    discovery = discovery or {}
    issues: list[Issue] = []
    add = lambda lvl, code, msg, path="": issues.append(Issue(lvl, code, msg, path))  # noqa: E731

    # ---- devices / interfaces
    hostnames = [d.hostname for d in ex.devices]
    for h in {h for h in hostnames if hostnames.count(h) > 1}:
        add("error", "DUP_DEVICE", f"Duplicate device hostname {h}", "devices")
    link_ids = {l.id for l in ex.links}
    iface_index: dict[tuple[str, str], tuple] = {}
    for d in ex.devices:
        if not d.interfaces:
            add("error", "NO_INTERFACES", f"{d.hostname} has no interfaces", f"devices.{d.hostname}")
        for i in d.interfaces:
            path = f"devices.{d.hostname}.interfaces.{i.id}"
            if (d.hostname, i.id) in iface_index:
                add("error", "DUP_IFACE_ID", f"Duplicate interface id {i.id} on {d.hostname}", path)
            try:
                ipaddress.IPv4Address(i.ip)
            except ValueError:
                add("error", "BAD_IP", f"{d.hostname}/{i.id}: invalid IPv4 address '{i.ip}'", path)
                continue
            if not validate_mask(i.mask):
                add("error", "BAD_MASK", f"{d.hostname}/{i.id}: invalid subnet mask '{i.mask}'", path)
                continue
            itf = _iface(i.ip, i.mask)
            net = itf.network
            if net.prefixlen < 31 and itf.ip in (net.network_address, net.broadcast_address):
                add("error", "HOST_IS_NET_OR_BCAST",
                    f"{d.hostname}/{i.id}: {i.ip} is the network or broadcast address of {net}", path)
            if i.link not in link_ids:
                add("error", "UNKNOWN_LINK", f"{d.hostname}/{i.id} references unknown link {i.link}", path)
            iface_index[(d.hostname, i.id)] = (d, i, itf)

    # ---- duplicate IPs
    seen_ips: dict[str, str] = {}
    for (host, iid), (_, i, _) in iface_index.items():
        if i.ip in seen_ips:
            add("error", "DUP_IP", f"IP {i.ip} used by both {seen_ips[i.ip]} and {host}/{iid}", "devices")
        else:
            seen_ips[i.ip] = f"{host}/{iid}"

    # ---- links
    subnets_seen: dict[ipaddress.IPv4Network, str] = {}
    for l in ex.links:
        path = f"links.{l.id}"
        try:
            net = ipaddress.IPv4Network(l.subnet, strict=True)
        except ValueError as e:
            add("error", "BAD_SUBNET", f"Link {l.id}: invalid subnet {l.subnet} ({e})", path)
            continue
        for other, oid in subnets_seen.items():
            if net.overlaps(other):
                add("error", "OVERLAP_SUBNET", f"Link {l.id} subnet {net} overlaps {oid} ({other})", path)
        subnets_seen[net] = l.id
        if len(l.endpoints) != 2:
            add("error", "LINK_ENDPOINTS", f"Link {l.id} must have exactly 2 endpoints, has {len(l.endpoints)}", path)
        roles = []
        for ep in l.endpoints:
            entry = iface_index.get((ep.device, ep.interface))
            if not entry:
                add("error", "BAD_ENDPOINT", f"Link {l.id}: endpoint {ep.device}/{ep.interface} not found", path)
                continue
            d, i, itf = entry
            roles.append(d.role)
            if i.link != l.id:
                add("error", "ENDPOINT_LINK_MISMATCH",
                    f"{ep.device}/{ep.interface} says link {i.link} but is an endpoint of {l.id}", path)
            if itf.network != net:
                add("error", "SUBNET_MISMATCH",
                    f"{ep.device}/{ep.interface} {itf.with_prefixlen} is not in link subnet {net}", path)
        if len(roles) == 2:
            expected = "transit" if roles.count(Role.router) == 2 else "lan"
            if roles.count(Role.router) == 0:
                add("error", "NO_ROUTER_ON_LINK", f"Link {l.id} connects two hosts - unsupported", path)
            elif l.kind != expected:
                add("error", "LINK_KIND", f"Link {l.id} is marked {l.kind} but connects "
                                          f"{[r.value for r in roles]} (expected {expected})", path)

    # ---- addressing plan consistency + gateways
    for n, a in enumerate(ex.addressing_plan):
        path = f"addressing_plan[{n}]"
        entry = iface_index.get((a.device, a.interface))
        if not entry:
            add("error", "PLAN_UNKNOWN_IFACE", f"Addressing entry {a.device}/{a.interface} has no matching interface", path)
            continue
        d, i, itf = entry
        if (a.ip, a.mask) != (i.ip, i.mask):
            add("error", "PLAN_MISMATCH", f"Addressing plan {a.device}/{a.interface} {a.ip}/{a.mask} differs "
                                          f"from interface {i.ip}/{i.mask}", path)
        if d.role == Role.host:
            if not a.gateway:
                add("error", "NO_GATEWAY", f"Host {a.device} has no default gateway", path)
                continue
            link = next((l for l in ex.links if l.id == i.link), None)
            gw_ok = False
            if link:
                for ep in link.endpoints:
                    peer = iface_index.get((ep.device, ep.interface))
                    if peer and peer[0].role == Role.router and peer[1].ip == a.gateway:
                        gw_ok = True
            if not gw_ok:
                add("error", "BAD_GATEWAY", f"Host {a.device} gateway {a.gateway} is not the IP of the attached "
                                            f"router interface on link {i.link}", path)
    planned = {(a.device, a.interface) for a in ex.addressing_plan}
    for (host, iid) in iface_index:
        if (host, iid) not in planned:
            add("warning", "PLAN_MISSING", f"{host}/{iid} is not listed in addressing_plan", "addressing_plan")

    # ---- OSPF
    rt = ex.routing
    if rt.protocol != "ospf" or rt.area != 0:
        add("error", "OSPF_AREA", "Routing must be OSPFv2 area 0", "routing")
    rids = []
    for r in ex.routers():
        path = f"devices.{r.hostname}.router_id"
        if not r.router_id:
            add("error", "NO_ROUTER_ID", f"{r.hostname} has no OSPF router-id", path)
            continue
        try:
            ipaddress.IPv4Address(r.router_id)
        except ValueError:
            add("error", "BAD_ROUTER_ID", f"{r.hostname} router-id '{r.router_id}' is not dotted-quad", path)
        rids.append(r.router_id)
    for rid in {x for x in rids if rids.count(x) > 1}:
        add("error", "DUP_ROUTER_ID", f"Router-id {rid} used by more than one router", "devices")
    if len(ex.routers()) < 2:
        add("warning", "FEW_ROUTERS", "Fewer than two routers - no OSPF adjacency will form", "devices")
    if not any(l.kind == "transit" for l in ex.links):
        add("warning", "NO_TRANSIT", "No router-to-router link - OSPF adjacency impossible", "links")

    # ---- interface mapping (physical names discovered from the routers)
    for r in ex.routers():
        disc = discovery.get(r.hostname) or {}
        disc_names = {normalize_ifname(x["name"]): x for x in disc.get("interfaces", [])}
        mgmt_if = normalize_ifname(disc["mgmt_interface"]) if disc.get("mgmt_interface") else None
        used = defaultdict(list)
        if not disc_names and require_mapping:
            add("error", "NOT_DISCOVERED", f"{r.hostname}: interfaces not discovered yet - run Discover",
                f"devices.{r.hostname}")
        if disc_names and not mgmt_if:
            add("error", "MGMT_IFACE_UNKNOWN", f"{r.hostname}: no interface holds the management IP - set "
                                               f"mgmt_interface for {r.hostname} in inventory.yaml so it can be "
                                               f"protected", f"devices.{r.hostname}")
        plan_nets = [ipaddress.IPv4Network(l.subnet, strict=False) for l in ex.links
                     if _valid_net(l.subnet)]
        for i in r.interfaces:
            path = f"devices.{r.hostname}.interfaces.{i.id}.name"
            if not i.name:
                add("error" if require_mapping else "warning", "UNMAPPED_IFACE",
                    f"{r.hostname}/{i.id} ({i.ip}) is not mapped to a physical interface", path)
                continue
            n = normalize_ifname(i.name)
            used[n].append(i.id)
            if disc_names and n not in disc_names:
                add("error", "IFACE_NOT_ON_DEVICE", f"{r.hostname}: interface {i.name} does not exist on the router "
                                                    f"(discovered: {', '.join(sorted(disc_names))})", path)
            if mgmt_if and n == mgmt_if:
                add("error", "MGMT_IFACE", f"{r.hostname}: {i.name} is the management interface and must not be "
                                           f"reconfigured", path)
            cur = (disc_names.get(n) or {}).get("ip")
            if cur and cur != "unassigned" and _valid_ip(cur) and \
                    not any(ipaddress.IPv4Address(cur) in net for net in plan_nets):
                add("warning", "FOREIGN_IP", f"{r.hostname}: {i.name} currently has {cur}, outside every plan "
                                             f"subnet - make sure it is not used for management", path)
        for n, ids in used.items():
            if len(ids) > 1:
                add("error", "IFACE_REUSED", f"{r.hostname}: {n} mapped to several logical interfaces {ids}",
                    f"devices.{r.hostname}")

    # ---- management plane
    for r in ex.routers():
        inv = inventory.get(r.hostname)
        if not inv:
            add("error", "NOT_IN_INVENTORY", f"{r.hostname} not found in inventory.yaml (no management IP)",
                f"devices.{r.hostname}")
            continue
        try:
            mip = ipaddress.IPv4Address(inv["mgmt_ip"])
        except (ValueError, KeyError):
            add("error", "BAD_MGMT_IP", f"{r.hostname}: invalid management IP in inventory", "inventory")
            continue
        for net in subnets_seen:
            if mip in net:
                add("error", "MGMT_OVERLAP", f"{r.hostname} management IP {mip} lies inside data-plane subnet "
                                             f"{net} - deployment could cut SSH access", "inventory")
        if reachability is not None:
            if reachability.get(r.hostname):
                add("info", "MGMT_REACHABLE", f"{r.hostname} management {mip}:{inv.get('port', 22)} reachable")
            else:
                add("error", "MGMT_UNREACHABLE", f"{r.hostname} management {mip}:{inv.get('port', 22)} not reachable",
                    "inventory")

    # ---- unresolved ambiguities from extraction
    for n, a in enumerate(ex.ambiguities):
        if not a.resolved:
            add("warning", "AMBIGUITY", f"Unresolved: {a.field} - {a.issue}", f"ambiguities[{n}]")
    if ex.confidence < 0.7:
        add("warning", "LOW_CONFIDENCE", f"AI extraction confidence {ex.confidence:.2f} - review carefully")
    return issues


def has_errors(issues: list[Issue]) -> bool:
    return any(i.level == "error" for i in issues)
