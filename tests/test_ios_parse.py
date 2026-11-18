from worker import ios_parse as P

NEI = """Neighbor ID     Pri   State           Dead Time   Address         Interface
2.2.2.2           0   FULL/  -        00:00:33    10.1.0.2        GigabitEthernet0/2
3.3.3.3           1   FULL/DR         00:00:31    10.9.0.3        GigabitEthernet0/3
4.4.4.4           1   INIT/DROTHER    00:00:39    10.9.0.4        GigabitEthernet0/3
"""
ROUTES_NEW = """Gateway of last resort is not set

      10.0.0.0/8 is variably subnetted, 4 subnets, 2 masks
O        10.2.0.0/24 [110/2] via 10.1.0.2, 00:01:02, GigabitEthernet0/2
"""
ROUTES_OLD = """     10.0.0.0/24 is subnetted, 3 subnets
O       10.2.0.0 [110/2] via 10.1.0.2, 00:00:05, FastEthernet0/1
"""
PROTO = """Routing Protocol is "ospf 1"
  Outgoing update filter list for all interfaces is not set
  Router ID 1.1.1.1
  Number of areas in this router is 1. 1 normal 0 stub 0 nssa
  Passive Interface(s):
    GigabitEthernet0/1
  Routing Information Sources:
"""
BRIEF = """Interface                  IP-Address      OK? Method Status                Protocol
GigabitEthernet0/0         192.168.122.11  YES DHCP   up                    up
GigabitEthernet0/1         unassigned      YES unset  administratively down down
"""


def test_neighbors():
    n = P.parse_ospf_neighbors(NEI)
    assert [(x["router_id"], x["state"]) for x in n] == [("2.2.2.2", "FULL"), ("3.3.3.3", "FULL"),
                                                          ("4.4.4.4", "INIT")]


def test_routes_both_formats():
    assert P.parse_ospf_routes(ROUTES_NEW)[0]["prefix"] == "10.2.0.0/24"
    assert P.parse_ospf_routes(ROUTES_OLD)[0]["prefix"] == "10.2.0.0/24"


def test_protocols_and_brief():
    p = P.parse_ip_protocols(PROTO)
    assert p == {"ospf_process": 1, "router_id": "1.1.1.1", "passive_interfaces": ["GigabitEthernet0/1"]}
    b = P.parse_ip_int_brief(BRIEF)
    assert b[0]["ip"] == "192.168.122.11" and b[1]["status"] == "administratively down"


def test_error_detection():
    assert P.find_error("% Invalid input detected at '^' marker.")
    assert P.find_error("% 10.1.0.0 overlaps with GigabitEthernet0/1")
    assert P.find_error('% OSPF: Reload or use "clear ip ospf process" command, for this to take effect') is None
    assert P.find_error("Success rate is 100 percent (5/5)") is None


RUNNING = """hostname Router
!
interface GigabitEthernet0/0
 ip address 192.168.122.11 255.255.255.0
!
interface GigabitEthernet0/1
 no ip address
 shutdown
!
interface GigabitEthernet0/2
 ip address 10.1.0.1 255.255.255.0
 ip ospf network point-to-point
 description old
!
end"""
DESIRED = """hostname R1
interface GigabitEthernet0/1
 description LAN
 ip address 10.0.0.1 255.255.255.0
 no shutdown
interface GigabitEthernet0/2
 description old
 ip address 10.1.0.1 255.255.255.0
 ip ospf network point-to-point
 no shutdown
router ospf 1
 router-id 1.1.1.1
 passive-interface Gi0/1
 network 10.0.0.0 0.0.0.255 area 0"""


def test_diff_only_missing_lines():
    todo = P.diff_config(DESIRED, RUNNING)
    assert todo[0] == "hostname R1"
    assert "interface GigabitEthernet0/2" not in todo  # already compliant -> untouched
    assert " ip address 10.0.0.1 255.255.255.0" in todo and "router ospf 1" in todo


def test_diff_idempotent_when_compliant():
    assert P.diff_config(DESIRED, DESIRED.replace("Gi0/1", "GigabitEthernet0/1")) == []


def test_rollback_restores_previous_values():
    todo = P.diff_config(DESIRED, RUNNING)
    rb = P.rollback_lines(todo, RUNNING)
    assert rb[0] == "no router ospf 1"
    assert "hostname Router" in rb
    assert " shutdown" in rb and " no ip address" in rb


def test_reset_lines_on_real_c7200_style_config():
    running = """hostname R1
interface FastEthernet0/0
 description MGMT - do not touch
 ip address 192.168.239.11 255.255.255.0
 duplex half
interface FastEthernet0/1
 description LAN to PC1 (10.0.0.0/24)
 ip address 10.0.0.1 255.255.255.0
 duplex half
interface FastEthernet1/0
 description P2P to R2 (10.1.0.0/24)
 ip address 10.1.0.1 255.255.255.0
 ip ospf network point-to-point
 duplex half
interface FastEthernet1/1
 no ip address
 shutdown
interface Loopback0
 ip address 1.1.1.1 255.255.255.255
router ospf 1
 router-id 1.1.1.1
 network 10.0.0.0 0.0.0.255 area 0
line vty 0 4
 login local
 transport input ssh
"""
    out = P.reset_lines(running, {"FastEthernet0/0"})
    text = "\n".join(out)
    assert "FastEthernet0/0" not in text and "vty" not in text and "hostname" not in text
    assert "duplex" not in text and "FastEthernet1/1" not in text          # unused port already clean
    assert out[:5] == ["interface FastEthernet0/1", " no ip address", " no description", " shutdown", " exit"]
    assert " no ip ospf network point-to-point" in out
    assert "no interface Loopback0" in out and "no router ospf 1" in out
    after = """interface FastEthernet0/0
 ip address 192.168.239.11 255.255.255.0
interface FastEthernet0/1
 no ip address
 shutdown
"""
    assert P.reset_lines(after, {"FastEthernet0/0"}) == []                 # idempotent
