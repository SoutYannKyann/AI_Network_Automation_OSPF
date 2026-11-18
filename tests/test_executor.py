import pytest

from app.config import Settings
from app.generator import generate
from app.models import ApprovalRef, ConfigRef, JobMessage, JobStatus, JobType
from app.safety import approval_token, sha256_text
from tests.conftest import map_all
from worker.executor import Claim, ClaimRejected, Executor
from worker.simulator import get_sim, reset_simulation

SECRET = "test-secret"
DEV = {"R1": {"mgmt_ip": "192.168.122.11"}, "R2": {"mgmt_ip": "192.168.122.12"}}


@pytest.fixture(autouse=True)
def _sim():
    reset_simulation()
    yield


def settings(tmp_path):
    return Settings(simulate_devices=True, approval_secret=SECRET, audit_log_path=tmp_path / "audit.jsonl",
                    backup_dir=tmp_path / "bk", verify_timeout=2, verify_interval=0)


def deploy_job(device, text, token_secret=SECRET, job_id=None):
    sha = sha256_text(text)
    tok = approval_token(token_secret, "a1", "c1", device, sha)
    return JobMessage(job_id=job_id or f"j-{device}", job_type=JobType.deploy, project_id="p", device_id=device,
                      config_ref=ConfigRef(config_id="c1", sha256=sha),
                      approval=ApprovalRef(approval_id="a1", approver="t", approved_at="now", token=tok),
                      verification_cmds=["show ip protocols"]).model_dump(mode="json")


def run(tmp_path, job, text, device):
    results = []
    ex = Executor(settings(tmp_path), lambda j: Claim(DEV[device], text, sha256_text(text) if text else None),
                  results.append)
    return ex.process(job), results


def router_cfgs(exam):
    return {c.device: c for c in generate(map_all(exam))}


def test_deploy_then_idempotent_rerun(tmp_path, exam):
    cfg = router_cfgs(exam)["R1"].text
    final, events = run(tmp_path, deploy_job("R1", cfg), cfg, "R1")
    assert final.status == JobStatus.SUCCESS and not final.noop and final.applied_lines
    assert any(not e.final and e.status == JobStatus.RUNNING for e in events)  # progress reported
    final2, _ = run(tmp_path, deploy_job("R1", cfg, job_id="again"), cfg, "R1")
    assert final2.status == JobStatus.SUCCESS and final2.noop and not final2.applied_lines
    assert (tmp_path / "audit.jsonl").read_text().count('"event": "config"') >= 5


def reset_job(device, token_secret=SECRET, job_id=None):
    from app.generator import RESET_CMDS, reset_spec
    sha = sha256_text(reset_spec(device))
    cid = f"reset:{device}:a9"
    tok = approval_token(token_secret, "a9", cid, device, sha)
    return JobMessage(job_id=job_id or f"r-{device}", job_type=JobType.reset, project_id="p", device_id=device,
                      config_ref=ConfigRef(config_id=cid, sha256=sha),
                      approval=ApprovalRef(approval_id="a9", approver="t", approved_at="now", token=tok),
                      verification_cmds=RESET_CMDS).model_dump(mode="json")


def test_undeploy_resets_data_plane_and_keeps_management(tmp_path, exam):
    from app.generator import reset_spec
    cfg = router_cfgs(exam)["R1"].text
    assert run(tmp_path, deploy_job("R1", cfg), cfg, "R1")[0].status == JobStatus.SUCCESS
    sim = get_sim("R1", DEV["R1"]["mgmt_ip"], [])
    mgmt_before = list(sim.ifaces["GigabitEthernet0/0"])
    final, _ = run(tmp_path, reset_job("R1"), reset_spec("R1"), "R1")
    assert final.status == JobStatus.SUCCESS and final.applied_lines and "untouched" in final.message
    assert not sim.router                                                 # OSPF process removed
    for name, ch in sim.ifaces.items():
        if name == "GigabitEthernet0/0":
            assert ch == mgmt_before                                      # management untouched
        else:
            assert not any(c.startswith(("ip address", "ip ospf", "description")) for c in ch) and "shutdown" in ch
    again, _ = run(tmp_path, reset_job("R1", job_id="r2"), reset_spec("R1"), "R1")
    assert again.status == JobStatus.SUCCESS and again.noop               # idempotent
    # and the approved plan can be deployed again afterwards
    assert run(tmp_path, deploy_job("R1", cfg, job_id="redeploy"), cfg, "R1")[0].status == JobStatus.SUCCESS


def test_undeploy_refuses_forged_approval_and_wrong_spec(tmp_path):
    from app.generator import reset_spec
    final, _ = run(tmp_path, reset_job("R1", token_secret="forged"), reset_spec("R1"), "R1")
    assert final.status == JobStatus.FAILED and final.error_kind == "approval"
    final, _ = run(tmp_path, reset_job("R1"), reset_spec("R1") + "! tampered", "R1")
    assert final.error_kind == "integrity"


def test_bad_token_refused(tmp_path, exam):
    cfg = router_cfgs(exam)["R1"].text
    final, _ = run(tmp_path, deploy_job("R1", cfg, token_secret="forged"), cfg, "R1")
    assert final.status == JobStatus.FAILED and final.error_kind == "approval"


def test_hash_mismatch_refused(tmp_path, exam):
    cfg = router_cfgs(exam)["R1"].text
    final, _ = run(tmp_path, deploy_job("R1", cfg), cfg + "\n! tampered", "R1")
    assert final.error_kind == "integrity"


def test_deny_list_refused(tmp_path):
    text = "hostname R1\nip route 0.0.0.0 0.0.0.0 10.1.0.2\n"
    final, _ = run(tmp_path, deploy_job("R1", text), text, "R1")
    assert final.error_kind == "safety"


def test_mgmt_interface_refused(tmp_path):
    text = "interface GigabitEthernet0/0\n ip address 10.0.0.1 255.255.255.0\n"
    final, _ = run(tmp_path, deploy_job("R1", text), text, "R1")
    assert final.error_kind == "safety" and "management" in final.message


def test_command_error_halts_and_rolls_back(tmp_path, exam):
    good = router_cfgs(exam)["R1"].text
    bad = good.replace(" network 10.1.0.0 0.0.0.255 area 0", " network 10.1.0.0 0.0.0.255 area 0 INVALID")
    final, _ = run(tmp_path, deploy_job("R1", bad), bad, "R1")
    assert final.status == JobStatus.FAILED and final.error_kind == "command" and final.rolled_back
    sim = get_sim("R1", "192.168.122.11", [])
    assert sim.router == {}                                   # router ospf removed again
    assert "shutdown" in sim.ifaces["GigabitEthernet0/1"]      # interface back to shutdown
    assert sim.hostname == "Router"                            # hostname restored


def test_secrets_redacted_in_audit(tmp_path, monkeypatch):
    from app.safety import redact
    from worker.ssh_executor import AuditLog
    monkeypatch.setenv("SSH_PASSWORD", "SuperSecret123")
    log = AuditLog(tmp_path / "a.jsonl")
    log.write("j", "R1", "command", "login with SuperSecret123\nusername admin secret 5 $1$abc$xyz",
              command="enable secret hunter2")
    text = (tmp_path / "a.jsonl").read_text()
    assert "SuperSecret123" not in text and "$1$abc$xyz" not in text and "hunter2" not in text
    assert redact("snmp-server community public RO") == "snmp-server community *** RO"


def test_duplicate_claim_skipped(tmp_path):
    def claim(_):
        raise ClaimRejected("duplicate", "already SUCCESS")
    ex = Executor(settings(tmp_path), claim, lambda r: None)
    assert ex.process(deploy_job("R1", "hostname R1")) is None


def test_verify_full_adjacency_and_routes(tmp_path, exam):
    cfgs = router_cfgs(exam)
    for d in ("R1", "R2"):
        f, _ = run(tmp_path, deploy_job(d, cfgs[d].text), cfgs[d].text, d)
        assert f.status == JobStatus.SUCCESS
    for d in ("R1", "R2"):
        job = JobMessage(job_id=f"v-{d}", job_type=JobType.verify, project_id="p", device_id=d,
                         expect=cfgs[d].expect).model_dump(mode="json")
        final, _ = run(tmp_path, job, None, d)
        assert final.status == JobStatus.SUCCESS, final.verification
        checks = final.verification["checks"]
        assert checks["neighbors_full"]["ok"] and checks["ospf_routes"]["ok"] and checks["pings"]["ok"]


def test_verify_fails_when_peer_not_configured(tmp_path, exam):
    cfgs = router_cfgs(exam)
    run(tmp_path, deploy_job("R1", cfgs["R1"].text), cfgs["R1"].text, "R1")
    job = JobMessage(job_id="v", job_type=JobType.verify, project_id="p", device_id="R1",
                     expect=cfgs["R1"].expect).model_dump(mode="json")
    final, _ = run(tmp_path, job, None, "R1")
    assert final.status == JobStatus.FAILED and final.error_kind == "verification"
    assert not final.verification["checks"]["neighbors_full"]["ok"]


def test_remap_and_redeploy_recovers_without_manual_cli(tmp_path, exam):
    """Wrong mapping deployed first (LAN/transit swapped) - corrected plan must still deploy."""
    wrong = {c.device: c.text for c in generate(map_all(exam, ("GigabitEthernet0/2", "GigabitEthernet0/1")))}
    right = {c.device: c.text for c in generate(map_all(exam))}
    f1, _ = run(tmp_path, deploy_job("R1", wrong["R1"], job_id="w"), wrong["R1"], "R1")
    assert f1.status == JobStatus.SUCCESS
    f2, _ = run(tmp_path, deploy_job("R1", right["R1"], job_id="r"), right["R1"], "R1")
    assert f2.status == JobStatus.SUCCESS, f2.message
    assert " no ip address" in f2.applied_lines and " no passive-interface GigabitEthernet0/2" in f2.applied_lines
    sim = get_sim("R1", "192.168.122.11", [])
    assert "ip address 10.0.0.1 255.255.255.0" in sim.ifaces["GigabitEthernet0/1"]
    assert "ip address 192.168.122.11 255.255.255.0" in sim.ifaces["GigabitEthernet0/0"]  # mgmt untouched
    f3, _ = run(tmp_path, deploy_job("R1", right["R1"], job_id="r2"), right["R1"], "R1")
    assert f3.noop


def test_changed_topology_removes_stale_ospf_networks(tmp_path, exam, alt):
    first = {c.device: c.text for c in generate(map_all(exam))}["R1"]
    run(tmp_path, deploy_job("R1", first, job_id="a"), first, "R1")
    alt_plan = map_all(alt)
    alt_plan.device("RTR-A").hostname = "RTR-A"
    second = {c.device: c.text for c in generate(alt_plan)}["RTR-A"]
    f, _ = run(tmp_path, deploy_job("R1", second, job_id="b"), second, "R1")
    assert f.status == JobStatus.SUCCESS, f.message
    sim = get_sim("R1", "192.168.122.11", [])
    nets = [c for c in sim.router["1"] if c.startswith("network")]
    assert nets == ["network 192.168.10.0 0.0.0.127 area 0", "network 172.16.0.0 0.0.0.3 area 0"]


def test_deploy_refused_when_mgmt_interface_unknown(tmp_path, exam):
    cfg = router_cfgs(exam)["R1"].text
    results = []
    ex = Executor(settings(tmp_path), lambda j: Claim({"mgmt_ip": "203.0.113.9"}, cfg, sha256_text(cfg)),
                  results.append, session_factory=lambda job, dev: get_sim("R1", "192.168.122.11",
                                                                           ["Gi0/0", "Gi0/1", "Gi0/2"]))
    final = ex.process(deploy_job("R1", cfg))
    assert final.status == JobStatus.FAILED and final.error_kind == "safety" and "management" in final.message
    # explicit inventory override makes it safe again
    ex2 = Executor(settings(tmp_path), lambda j: Claim({"mgmt_ip": "203.0.113.9", "mgmt_interface": "Gi0/0"},
                                                       cfg, sha256_text(cfg)), results.append,
                   session_factory=lambda job, dev: get_sim("R1", "192.168.122.11", []))
    assert ex2.process(deploy_job("R1", cfg, job_id="x")).status == JobStatus.SUCCESS
