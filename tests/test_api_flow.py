"""End-to-end through the real FastAPI app with the in-memory bus standing in for Kafka and the
IOS simulator standing in for GNS3. Exercises claim/approval re-check, duplicate guard, auto-verify."""
import pytest
from fastapi.testclient import TestClient

from tests.conftest import ROOT

WORKER = {"X-Worker-Token": "wrk"}


@pytest.fixture
def env(tmp_path, monkeypatch):
    for k, v in {"BUS_BACKEND": "memory", "DATA_DIR": str(tmp_path), "WORKER_TOKEN": "wrk",
                 "APPROVAL_HMAC_SECRET": "hmac", "SIMULATE_DEVICES": "1", "VERIFY_TIMEOUT": "3",
                 "VERIFY_INTERVAL": "0", "AUDIT_LOG_PATH": str(tmp_path / "audit.jsonl"),
                 "BACKUP_DIR": str(tmp_path / "bk"), "INVENTORY_PATH": str(ROOT / "inventory.example.yaml")}.items():
        monkeypatch.setenv(k, v)
    from app import api
    from app.config import get_settings
    from worker.simulator import reset_simulation
    reset_simulation()
    api.STATE = api.State(get_settings())
    with TestClient(api.app) as client:
        yield api, client
    api.STATE = None


def pump(api, client):
    """Play the Kafka consumer + worker: drain the jobs topic, claim via the real HTTP endpoint."""
    from worker.executor import Claim, ClaimRejected, Executor

    def claim(job):
        r = client.post(f"/api/internal/jobs/{job.job_id}/claim", headers=WORKER,
                        json={"device_id": job.device_id, "job_type": job.job_type.value,
                              "config_sha256": job.config_ref.sha256 if job.config_ref else None})
        if r.status_code == 409:
            raise ClaimRejected("duplicate", r.text)
        if r.status_code != 200:
            raise ClaimRejected("approval", r.text)
        b = r.json()
        return Claim(b["device"], b["config_text"], b["config_sha256"])

    ex = Executor(api.STATE.s, claim, lambda r: api.handle_result(r.model_dump(mode="json")))
    n = 0
    while True:
        batch = list(api.STATE.bus.drain(api.STATE.s.jobs_topic))
        if not batch:
            return n
        for msg in batch:
            ex.process(msg)
            n += 1


def test_full_workflow(env):
    api, c = env
    png = (ROOT / "samples" / "network_diagram.png").read_bytes()
    assert c.post("/api/projects", files={"file": ("d.gif", b"GIF89a", "image/gif")}).status_code == 415
    pid = c.post("/api/projects", files={"file": ("d.png", png, "image/png")}, data={"notes": "x"}).json()["project_id"]
    sample = c.get("/api/samples/exam_plan").json()
    assert c.put(f"/api/projects/{pid}/extraction", json={"extraction": sample}).status_code == 200

    assert c.post(f"/api/projects/{pid}/generate").status_code == 409          # unmapped interfaces
    assert c.post(f"/api/projects/{pid}/discover").status_code == 200
    assert pump(api, c) == 2
    disc = c.get(f"/api/projects/{pid}").json()["discovery"]
    assert disc["R1"]["mgmt_interface"] == "GigabitEthernet0/0"
    assert disc["R1"]["data_interfaces"] == ["GigabitEthernet0/1", "GigabitEthernet0/2"]

    c.post(f"/api/projects/{pid}/mapping/suggest")
    ex = c.get(f"/api/projects/{pid}").json()["extraction"]
    mapping = {d["hostname"]: {i["id"]: i["name"] for i in d["interfaces"]}
               for d in ex["devices"] if d["role"] == "router"}
    assert "GigabitEthernet0/0" not in str(mapping)                              # mgmt never suggested
    assert c.put(f"/api/projects/{pid}/mapping", json={"mapping": mapping}).status_code == 200

    gen = c.post(f"/api/projects/{pid}/generate").json()["configs"]
    assert {g["device"] for g in gen} == {"R1", "R2", "PC1", "PC2"}

    assert c.post(f"/api/projects/{pid}/deploy").status_code == 409   # not approved
    rev = c.post(f"/api/projects/{pid}/review").json()
    assert rev["ok"], rev["issues"]
    assert c.post(f"/api/projects/{pid}/approve", json={"approver": "  "}).status_code == 422  # name required
    assert c.post(f"/api/projects/{pid}/approve",
                  json={"approver": "alice"}).status_code == 409                       # warnings not acknowledged
    ap = c.post(f"/api/projects/{pid}/approve",
                json={"approver": "alice", "acknowledge_warnings": True}).json()
    assert {a["device"] for a in ap["approved"]} == {"R1", "R2"}

    # resolving an AI flag is metadata only: configs and approvals must survive it
    flags = c.get(f"/api/projects/{pid}").json()["extraction"]["ambiguities"]
    open_idx = next(i for i, a in enumerate(flags) if not a["resolved"])
    assert c.post(f"/api/projects/{pid}/ambiguities/resolve", json={"index": open_idx}).status_code == 200
    proj = c.get(f"/api/projects/{pid}").json()
    assert proj["extraction"]["ambiguities"][open_idx]["resolved"]
    assert all(cfg["approval"] for cfg in proj["configs"] if cfg["deployable"])

    c.post(f"/api/projects/{pid}/deploy")
    kafka = [v for t, _, v in api.STATE.bus.log if t == "network-config-jobs" and v["job_type"] == "deploy"]
    assert len(kafka) == 2 and all("config" not in m and m["config_ref"]["sha256"] for m in kafka)

    api.STATE.bus.publish("network-config-jobs", "R1", kafka[0])   # duplicate delivery
    pump(api, c)

    jobs = c.get(f"/api/jobs?project_id={pid}").json()
    by = {(j["job_type"], j["device"]): j for j in jobs}
    assert by[("deploy", "R1")]["status"] == "SUCCESS" and by[("deploy", "R2")]["status"] == "SUCCESS"
    assert by[("verify", "R1")]["status"] == "SUCCESS", by[("verify", "R1")]["message"]
    checks = by[("verify", "R2")]["verification"]["checks"]
    assert checks["neighbors_full"]["ok"] and checks["ospf_routes"]["ok"] and checks["pings"]["ok"]
    assert sum(1 for j in jobs if j["job_type"] == "deploy") == 2
    assert all(j["started_at"] and j["finished_at"] for j in jobs)
    r1_deploy_events = [e["message"] for e in by[("deploy", "R1")]["events"]]
    assert sum("claimed by worker" in m for m in r1_deploy_events) == 1     # executed exactly once

    c.post(f"/api/projects/{pid}/generate")                                     # regenerate -> approvals revoked
    assert c.post(f"/api/projects/{pid}/deploy").status_code == 409

    # undeploy: explicit approver, through the bus + claim (approval re-check), management kept
    assert c.post(f"/api/projects/{pid}/undeploy", json={"approver": " "}).status_code == 422
    un = c.post(f"/api/projects/{pid}/undeploy", json={"approver": "alice"}).json()
    kafka = [v for t, _, v in api.STATE.bus.log if t == "network-config-jobs" and v["job_type"] == "reset"]
    assert len(kafka) == 2 and all(m["config_ref"]["config_id"].startswith("reset:") for m in kafka)
    pump(api, c)
    resets = [j for j in c.get(f"/api/jobs?project_id={pid}").json() if j["batch_id"] == un["batch_id"]]
    assert {j["status"] for j in resets} == {"SUCCESS"} and all(j["job_type"] == "reset" for j in resets)
    from worker.simulator import get_sim
    sim = get_sim("R1", "192.168.122.11", [])
    assert not sim.router and any(c.startswith("ip address 192.168.122.11") for c in sim.ifaces["GigabitEthernet0/0"])

    audit = c.get(f"/api/audit?project_id={pid}").json()
    assert {"approve", "approval_revoked", "deploy", "undeploy"} <= {a["action"] for a in audit}


def test_only_listed_approvers_may_approve_or_undeploy(env, monkeypatch):
    api, c = env
    monkeypatch.setenv("APPROVERS", "Htet Lin Aung, Prof. Smith")
    from app.config import get_settings
    api.STATE.s = get_settings()
    assert c.get("/api/approvers").json() == {"approvers": ["Htet Lin Aung", "Prof. Smith"], "restricted": True}
    png = (ROOT / "samples" / "network_diagram.png").read_bytes()
    pid = c.post("/api/projects", files={"file": ("d.png", png, "image/png")}).json()["project_id"]
    c.put(f"/api/projects/{pid}/extraction", json={"extraction": c.get("/api/samples/exam_plan").json()})
    r = c.post(f"/api/projects/{pid}/undeploy", json={"approver": "mallory"})
    assert r.status_code == 403 and "not an authorised approver" in r.json()["detail"]
    assert c.post(f"/api/projects/{pid}/approve", json={"approver": "mallory"}).status_code == 403
    ok = c.post(f"/api/projects/{pid}/undeploy", json={"approver": "prof. smith"})   # case-insensitive
    assert ok.status_code == 200
    audit = c.get(f"/api/audit?project_id={pid}").json()
    assert any(a["action"] == "undeploy" and a["actor"] == "admin:Prof. Smith" for a in audit)  # canonical name stored


def test_claim_endpoint_guards(env):
    _, c = env
    assert c.post("/api/internal/jobs/x/claim", json={"device_id": "R1", "job_type": "deploy"}).status_code == 401
    assert c.post("/api/internal/jobs/x/claim", headers=WORKER,
                  json={"device_id": "R1", "job_type": "deploy"}).status_code == 404


def test_inventory_has_no_secrets(env):
    _, c = env
    inv = c.get("/api/inventory").json()
    assert inv["R1"]["mgmt_ip"] and not any(k.endswith("_env") or "password" in k for k in inv["R1"])


def test_lost_worker_job_expires(env):
    api, c = env
    db = api.STATE.db
    db.x("INSERT INTO jobs(id,project_id,device,job_type,status,created_at,started_at) "
         "VALUES('j1','p','R1','deploy','RUNNING','2026-01-01T00:00:00+00:00','2026-01-01T00:00:00+00:00')")
    jobs = c.get("/api/jobs").json()
    j = next(x for x in jobs if x["id"] == "j1")
    assert j["status"] == "FAILED" and "worker lost" in j["message"]


def test_router_ids_and_plan_checks_use_inventory(env):
    """AI left router-ids null (diagram has none): plan checks must not claim R1/R2 are missing from
    the inventory, and router-ids entered with the mapping resolve the NO_ROUTER_ID errors."""
    api, c = env
    png = (ROOT / "samples" / "network_diagram.png").read_bytes()
    pid = c.post("/api/projects", files={"file": ("d.png", png, "image/png")}).json()["project_id"]
    plan = c.get("/api/samples/exam_plan").json()
    for d in plan["devices"]:
        d["router_id"] = None
    plan["ambiguities"].append({"field": "devices.R1.router_id", "issue": "not shown", "suggestion": None,
                                "resolved": False})
    r = c.put(f"/api/projects/{pid}/extraction", json={"extraction": plan}).json()
    codes = {i["code"] for i in r["issues"] if i["level"] == "error"}
    assert "NO_ROUTER_ID" in codes and "NOT_IN_INVENTORY" not in codes
    c.put(f"/api/projects/{pid}/mapping", json={"router_ids": {"R1": "1.1.1.1", "R2": "2.2.2.2"}})
    p = c.get(f"/api/projects/{pid}").json()
    assert "NO_ROUTER_ID" not in {i["code"] for i in p["issues"]}
    assert all(a["resolved"] for a in p["extraction"]["ambiguities"] if "router_id" in a["field"])
    assert c.put(f"/api/projects/{pid}/mapping", json={"router_ids": {"PC1": "9.9.9.9"}}).status_code == 422
