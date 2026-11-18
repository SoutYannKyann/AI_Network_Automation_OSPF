from app.generator import config_lines, generate, wildcard
from app.validation import has_errors, validate_plan
from tests.conftest import INV, map_all


def _cfg(cfgs, name):
    return next(c for c in cfgs if c.device == name)


def codes(issues):
    return {i.code for i in issues if i.level == "error"}


def test_exam_plan_valid_and_configs(exam):
    ex = map_all(exam)
    issues = validate_plan(ex, INV)
    assert not has_errors(issues), issues
    cfgs = generate(ex)
    r1, r2 = _cfg(cfgs, "R1").text, _cfg(cfgs, "R2").text
    assert "router ospf 1" in r1 and "router-id 1.1.1.1" in r1 and "router-id 2.2.2.2" in r2
    for net in ("10.0.0.0", "10.1.0.0"):
        assert f" network {net} 0.0.0.255 area 0" in r1
    for net in ("10.1.0.0", "10.2.0.0"):
        assert f" network {net} 0.0.0.255 area 0" in r2
    assert " passive-interface GigabitEthernet0/1" in r1    # R1-L1 = LAN to PC1
    assert " passive-interface GigabitEthernet0/2" in r2    # R2-L3 = LAN to PC2
    assert "passive-interface GigabitEthernet0/2" not in r1  # transit link is NOT passive
    assert " ip address 10.0.0.1 255.255.255.0" in r1 and " ip address 10.2.0.2 255.255.255.0" in r2
    assert r1.count(" no shutdown") == 2
    assert "ip route" not in r1 + r2
    pc1 = _cfg(cfgs, "PC1")
    assert not pc1.deployable and "ip 10.0.0.10/24 10.0.0.1" in pc1.text
    exp = _cfg(cfgs, "R1").expect
    assert exp["neighbors"] == ["2.2.2.2"] and exp["ospf_prefixes"] == ["10.2.0.0/24"]


def test_alternate_plan_not_hardcoded(alt):
    ex = map_all(alt, ("Ethernet0/0", "Ethernet0/1"))
    assert not has_errors(validate_plan(ex, INV))
    cfgs = generate(ex)
    a = _cfg(cfgs, "RTR-A").text
    assert "router-id 10.255.0.1" in a
    assert " network 192.168.10.0 0.0.0.127 area 0" in a
    assert " network 172.16.0.0 0.0.0.3 area 0" in a
    assert "10.0.0" not in a
    assert _cfg(cfgs, "RTR-B").expect["ospf_prefixes"] == ["192.168.10.0/25"]


def test_wildcards():
    assert wildcard("255.255.255.0") == "0.0.0.255"
    assert wildcard("255.255.255.252") == "0.0.0.3"


def test_config_lines_strip_comments(exam):
    lines = config_lines(_cfg(generate(map_all(exam)), "R1").text)
    assert lines and all(not l.strip().startswith("!") and l.strip() != "end" for l in lines)


def test_bad_gateway_detected(exam):
    ex = map_all(exam)
    ex.addressing_plan[0].gateway = "10.0.0.254"
    assert "BAD_GATEWAY" in codes(validate_plan(ex, INV))


def test_duplicate_ip(exam):
    ex = map_all(exam)
    ex.device("R2").interfaces[0].ip = "10.1.0.1"
    assert "DUP_IP" in codes(validate_plan(ex, INV))


def test_subnet_mismatch(exam):
    ex = map_all(exam)
    ex.device("R2").interfaces[0].ip = "10.9.0.2"
    assert "SUBNET_MISMATCH" in codes(validate_plan(ex, INV))


def test_bad_mask_and_link_endpoints(exam):
    ex = map_all(exam)
    ex.device("R1").interfaces[0].mask = "255.0.255.0"
    ex.links[1].endpoints = ex.links[1].endpoints[:1]
    assert {"BAD_MASK", "LINK_ENDPOINTS"} <= codes(validate_plan(ex, INV))


def test_mapping_rules(exam):
    ex = map_all(exam)
    disc = {"R1": {"interfaces": [{"name": "GigabitEthernet0/0"}, {"name": "GigabitEthernet0/1"},
                                  {"name": "GigabitEthernet0/2"}], "mgmt_interface": "GigabitEthernet0/0"}}
    ex.device("R1").interfaces[0].name = "GigabitEthernet0/0"  # the management interface
    ex.device("R1").interfaces[1].name = "GigabitEthernet0/9"  # does not exist on the router
    assert {"MGMT_IFACE", "IFACE_NOT_ON_DEVICE"} <= codes(validate_plan(ex, INV, disc))


def test_unmapped_requires_mapping(exam):
    assert "UNMAPPED_IFACE" in codes(validate_plan(exam, INV, require_mapping=True))


def test_router_id_and_mgmt_checks(exam):
    ex = map_all(exam)
    ex.device("R2").router_id = "1.1.1.1"
    inv = {**INV, "R1": {"mgmt_ip": "10.0.0.50"}}
    c = codes(validate_plan(ex, inv, reachability={"R1": True, "R2": False}))
    assert {"DUP_ROUTER_ID", "MGMT_OVERLAP", "MGMT_UNREACHABLE"} <= c


def test_mgmt_interface_unknown_blocks(exam):
    ex = map_all(exam)
    disc = {"R1": {"interfaces": [{"name": "GigabitEthernet0/1", "ip": "unassigned"},
                                  {"name": "GigabitEthernet0/2", "ip": "198.51.100.7"}], "mgmt_interface": None}}
    issues = validate_plan(ex, INV, disc)
    assert "MGMT_IFACE_UNKNOWN" in codes(issues)
    assert any(i.code == "FOREIGN_IP" for i in issues)
