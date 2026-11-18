"""FastAPI backend: upload -> extract (AI) -> discover -> generate -> review -> approve -> deploy -> status.

Run: uvicorn app.api:app --host 0.0.0.0 --port 8000
"""
from __future__ import annotations

import hmac
import json
import logging
import socket
import threading
from contextlib import asynccontextmanager
from pathlib import Path

import yaml
from fastapi import Depends, FastAPI, File, Form, Header, HTTPException, UploadFile
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from . import generator
from .bus import make_bus
from .config import ROOT, Settings, get_settings
from .db import DB, new_id
from .extractor import ExtractionError, extract_from_image
from .models import (Ambiguity, ApprovalRef, ConfigRef, Extraction, JobMessage, JobStatus, JobType,
                     ResultMessage, Role, VerifyExpectation, utcnow)
from .safety import approval_token, denied_lines, redact, sha256_text
from .validation import has_errors, validate_plan

log = logging.getLogger("api")
STATIC = Path(__file__).parent / "static"
ALLOWED_IMAGES = {"image/png": ".png", "image/jpeg": ".jpg"}


# ============================================================================ state
class State:
    def __init__(self, s: Settings, bus=None):
        self.s = s
        self.db = DB(s.data_dir / "netauto.db")
        self.bus = bus or make_bus(s)
        self.stop = threading.Event()
        self.thread: threading.Thread | None = None
        self.progress: dict[str, dict] = {}  # pid -> live status of a running AI analysis (for the UI)

    def inventory(self) -> dict:
        path = self.s.inventory_path
        if not path.exists():
            path = ROOT / "inventory.example.yaml"
        raw = yaml.safe_load(path.read_text()) or {}
        defaults = raw.get("defaults", {})
        inv = {}
        for name, d in (raw.get("devices") or {}).items():
            entry = {**defaults, **(d or {}), "hostname": name}
            for k in list(entry):  # defensive: never let literal secrets through
                if k in ("password", "secret", "enable_secret"):
                    entry.pop(k)
            inv[name] = entry
        return inv

    def resolve(self, hostname: str) -> dict | None:
        inv = self.inventory()
        if hostname in inv:
            return inv[hostname]
        return next((v for v in inv.values() if hostname in (v.get("aliases") or [])), None)


STATE: State | None = None


def st() -> State:
    assert STATE is not None
    return STATE


@asynccontextmanager
async def lifespan(app: FastAPI):
    global STATE
    if STATE is None:
        STATE = State(get_settings())
    s = STATE.s
    if s.bus_backend == "kafka":
        try:
            STATE.bus.ensure_topics()
        except Exception as e:  # Kafka may still be starting; consumer thread keeps retrying
            log.warning("ensure_topics failed: %s", e)
        STATE.thread = threading.Thread(target=_results_loop, daemon=True, name="results-consumer")
        STATE.thread.start()
    elif s.inprocess_worker:
        STATE.thread = threading.Thread(target=_inprocess_worker, daemon=True, name="inprocess-worker")
        STATE.thread.start()
    yield
    STATE.stop.set()


app = FastAPI(title="AI Network Automation (OSPF)", lifespan=lifespan)
app.mount("/static", StaticFiles(directory=STATIC), name="static")


@app.middleware("http")
async def no_stale_ui(request, call_next):
    """Browsers must revalidate the page and its scripts, or an old cached app.js can break a new page."""
    resp = await call_next(request)
    if request.url.path == "/" or request.url.path.startswith("/static/"):
        resp.headers["Cache-Control"] = "no-cache"
    return resp


# ============================================================================ auth helpers
# The web UI has no login: approval is an explicit Approve action with the approver's name
# (exam: "explicit administrator approval"). Only the internal worker endpoints are protected.
def require_worker(x_worker_token: str = Header(default="")) -> None:
    tok = st().s.worker_token
    if not tok or not hmac.compare_digest(tok, x_worker_token):
        raise HTTPException(401, "worker token required")


# ============================================================================ helpers
def _project(pid: str) -> dict:
    p = st().db.one("SELECT * FROM projects WHERE id=?", pid)
    if not p:
        raise HTTPException(404, "project not found")
    return p


def _extraction(p: dict) -> Extraction:
    if not p["extraction"]:
        raise HTTPException(409, "no extraction yet - run Analyze or load JSON first")
    return Extraction.model_validate_json(p["extraction"])


def _inventory_for(ex: Extraction) -> dict:
    out = {}
    for r in ex.routers():
        entry = st().resolve(r.hostname) or next((st().resolve(a) for a in r.aliases if st().resolve(a)), None)
        if entry:
            out[r.hostname] = entry
    return out


def _tcp_reachable(host: str, port: int, timeout: float = 3.0) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def suggest_mapping(ex: Extraction, discovery: dict) -> Extraction:
    """Fill unmapped router interfaces with unused discovered data-plane interfaces (in order) and
    flag every suggestion as an ambiguity the admin must confirm."""
    import ipaddress
    plan_nets = [ipaddress.IPv4Network(l.subnet, strict=False) for l in ex.links]

    def foreign(ip: str | None) -> bool:  # has an address outside every plan subnet -> maybe management
        try:
            return bool(ip) and not any(ipaddress.IPv4Address(ip) in n for n in plan_nets)
        except ValueError:
            return False

    for r in ex.routers():
        disc = discovery.get(r.hostname) or {}
        ips = {x["name"]: x.get("ip") for x in disc.get("interfaces", [])}
        free = [n for n in disc.get("data_interfaces", [])
                if n not in {i.name for i in r.interfaces} and not foreign(ips.get(n))]
        for i in sorted(r.interfaces, key=lambda x: x.id):
            if not i.name and free:
                i.name = free.pop(0)
                ex.ambiguities.append(Ambiguity(
                    field=f"devices.{r.hostname}.interfaces.{i.id}.name",
                    issue=f"Auto-suggested {i.name} for {i.ip} (link {i.link})",
                    suggestion="Confirm against the GNS3 cabling before approving"))
    return ex


def _job_row_to_api(j: dict) -> dict:
    j = dict(j)
    for k in ("verification", "applied_lines", "kafka_message"):
        if j.get(k):
            j[k] = json.loads(j[k])
    j["events"] = st().db.q("SELECT ts,status,message FROM events WHERE job_id=? ORDER BY id", j["id"])
    return j


def _publish_job(job: JobMessage, project_id: str, config_id: str | None = None,
                 approval_id: str | None = None) -> None:
    db = st().db
    msg = job.model_dump(mode="json")
    redacted = {**msg, "approval": {**msg["approval"], "token": msg["approval"]["token"][:8] + "..."}} \
        if msg.get("approval") else msg
    db.x("INSERT INTO jobs(id,project_id,batch_id,device,job_type,status,config_id,approval_id,created_at,"
         "kafka_message) VALUES(?,?,?,?,?,?,?,?,?,?)", job.job_id, project_id, job.batch_id, job.device_id,
         job.job_type.value, JobStatus.PENDING.value, config_id, approval_id, utcnow(), json.dumps(redacted))
    db.x("INSERT INTO events(job_id,ts,status,message) VALUES(?,?,?,?)", job.job_id, utcnow(), "PENDING",
         f"published to {st().s.jobs_topic}")
    try:
        st().bus.publish(st().s.jobs_topic, job.device_id, msg)
    except Exception as e:
        db.x("UPDATE jobs SET status='FAILED', message=?, finished_at=? WHERE id=?",
             f"Kafka publish failed: {e}", utcnow(), job.job_id)
        raise HTTPException(503, f"Kafka unavailable: {e}")


# ============================================================================ dev-only in-process worker
def _inprocess_worker() -> None:
    """BUS_BACKEND=memory + INPROCESS_WORKER=1 only (UI rehearsal without Kafka). Runs the real
    worker Executor against the in-memory bus; the claim goes through the same approval re-check.
    The graded pipeline always uses Kafka + the separate worker process."""
    import time
    from worker.executor import Claim, ClaimRejected, Executor

    def claim_fn(job: JobMessage) -> Claim:
        try:
            body = _claim_core(job.job_id, ClaimIn(device_id=job.device_id, job_type=job.job_type.value,
                                                   config_sha256=job.config_ref.sha256 if job.config_ref else None))
        except HTTPException as e:
            raise ClaimRejected("duplicate" if e.status_code == 409 else "approval", str(e.detail))
        return Claim(body["device"], body["config_text"], body["config_sha256"])

    ex = Executor(st().s, claim_fn, lambda r: handle_result(r.model_dump(mode="json")))
    log.warning("DEV MODE: in-process worker on the memory bus (no Kafka)")
    while not st().stop.is_set():
        for msg in st().bus.drain(st().s.jobs_topic):
            try:
                ex.process(msg)
            except Exception:
                log.exception("in-process worker failed on a job")
        time.sleep(0.3)


# ============================================================================ results consumer
def _results_loop() -> None:
    import time
    while not st().stop.is_set():
        try:
            st().bus.consume(st().s.results_topic, st().s.api_group, handle_result, stop=st().stop.is_set)
        except Exception as e:
            log.warning("results consumer error (retrying): %s", e)
            time.sleep(3)


def handle_result(payload: dict) -> None:
    """Idempotent: progress events are appended; the first final event wins."""
    db = st().db
    try:
        r = ResultMessage.model_validate(payload)
    except Exception as e:
        log.error("bad result message: %s", e)
        return
    job = db.one("SELECT * FROM jobs WHERE id=?", r.job_id)
    if not job:
        return
    db.x("INSERT INTO events(job_id,ts,status,message) VALUES(?,?,?,?)", r.job_id, r.ts, r.status.value,
         redact(r.message))
    if not r.final or job["status"] in ("SUCCESS", "FAILED"):
        return
    output = "\n".join(f"{job['device']}# {c.command}\n{c.output}" for c in r.commands)
    db.x("UPDATE jobs SET status=?, finished_at=?, message=?, error_kind=?, output=?, verification=?, "
         "applied_lines=?, rolled_back=?, noop=?, worker=? WHERE id=?",
         r.status.value, r.ts, redact(r.message), r.error_kind, redact(output),
         json.dumps(r.verification) if r.verification else None, json.dumps(r.applied_lines),
         int(r.rolled_back), int(r.noop), r.worker, r.job_id)
    db.audit(r.worker or "worker", f"job_{r.status.value.lower()}", job["project_id"], r.job_id, r.message)
    if r.job_type == JobType.discover and r.discovery and r.status == JobStatus.SUCCESS:
        p = _project(job["project_id"])
        disc = json.loads(p["discovery"] or "{}")
        disc[job["device"]] = r.discovery
        db.x("UPDATE projects SET discovery=? WHERE id=?", json.dumps(disc), job["project_id"])
    if r.job_type == JobType.deploy and r.status == JobStatus.SUCCESS and job["batch_id"]:
        _maybe_start_verification(job["project_id"], job["batch_id"])


def _maybe_start_verification(project_id: str, batch_id: str) -> None:
    db = st().db
    with db.lock:
        jobs = db.q("SELECT * FROM jobs WHERE batch_id=?", batch_id)
        deploys = [j for j in jobs if j["job_type"] == "deploy"]
        if any(j["job_type"] == "verify" for j in jobs) or not all(j["status"] == "SUCCESS" for j in deploys):
            return
        for j in deploys:
            cfg = db.one("SELECT * FROM configs WHERE id=?", j["config_id"])
            expect = VerifyExpectation.model_validate_json(cfg["expect"])
            _publish_job(JobMessage(job_id=new_id(), job_type=JobType.verify, project_id=project_id,
                                    batch_id=batch_id, device_id=j["device"], expect=expect,
                                    verification_cmds=generator.VERIFY_CMDS), project_id)
        db.audit("system", "verification_started", project_id, None, {"batch_id": batch_id})


# ============================================================================ routes: UI + misc
@app.get("/")
def index():
    return FileResponse(STATIC / "index.html")


@app.get("/api/health")
def health():
    return {"ok": True, "bus": st().s.bus_backend, "jobs_topic": st().s.jobs_topic,
            "results_topic": st().s.results_topic, "simulate_devices": st().s.simulate_devices}


@app.get("/api/inventory")
def inventory():
    """Inventory without secrets (only env-var *names* are stored there)."""
    return {k: {kk: vv for kk, vv in v.items() if not kk.endswith("_env")} for k, v in st().inventory().items()}


@app.get("/api/samples/{name}")
def sample(name: str):
    if name not in ("exam_plan", "alt_plan"):
        raise HTTPException(404)
    return json.loads((ROOT / "samples" / f"{name}.json").read_text())


# ============================================================================ routes: workflow
@app.post("/api/projects")
async def upload(file: UploadFile = File(...), notes: str = Form("")):
    if file.content_type not in ALLOWED_IMAGES:
        raise HTTPException(415, "upload a PNG or JPG diagram")
    data = await file.read()
    if len(data) > 10 * 1024 * 1024:
        raise HTTPException(413, "image larger than 10 MB")
    pid = new_id()
    path = st().s.data_dir / "uploads" / f"{pid}{ALLOWED_IMAGES[file.content_type]}"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    st().db.x("INSERT INTO projects(id,created_at,image_path,notes) VALUES(?,?,?,?)",
              pid, utcnow(), str(path), notes[:4000])
    st().db.audit("user", "upload", pid, None, {"file": file.filename, "bytes": len(data)})
    return {"project_id": pid}


@app.get("/api/projects/{pid}")
def get_project(pid: str):
    p = _project(pid)
    configs = st().db.q("SELECT id,device,role,text,sha256,deployable,created_at FROM configs "
                        "WHERE project_id=? AND superseded=0 ORDER BY device", pid)
    for c in configs:
        c["approval"] = st().db.one("SELECT id,approver,approved_at FROM approvals WHERE config_id=? AND revoked=0",
                                    c["id"])
    return {"id": p["id"], "created_at": p["created_at"], "notes": p["notes"],
            "image_url": f"/api/projects/{pid}/image" if p["image_path"] else None,
            "extraction": json.loads(p["extraction"]) if p["extraction"] else None,
            "discovery": json.loads(p["discovery"] or "{}"),
            "validation": json.loads(p["validation"]) if p["validation"] else None,
            "issues": _plan_issues(p, _extraction(p)) if p["extraction"] else [],
            "configs": configs}


def _plan_issues(p: dict, ex: Extraction) -> list[dict]:
    """Plan checks with full context (inventory + discovery), shown next to the extraction."""
    return [i.dict() for i in validate_plan(ex, _inventory_for(ex), json.loads(p["discovery"] or "{}"))]


@app.get("/api/projects/{pid}/image")
def project_image(pid: str):
    p = _project(pid)
    return FileResponse(p["image_path"])


@app.post("/api/projects/{pid}/extract")
def extract(pid: str):
    """Task 2: AI analysis of the diagram -> structured JSON (+ ambiguity flags)."""
    p = _project(pid)
    img = Path(p["image_path"])
    media = "image/png" if img.suffix == ".png" else "image/jpeg"

    def report(msg: str) -> None:  # live status for GET /api/projects/{pid}/progress
        st().progress[pid] = {"running": True, "message": redact(msg), "ts": utcnow()}

    report("starting AI analysis")
    try:
        ex = extract_from_image(st().s, img.read_bytes(), media, p["notes"] or "", progress=report)
    except ExtractionError as e:
        st().progress[pid] = {"running": False, "message": redact(str(e)), "ts": utcnow(), "ok": False}
        raise HTTPException(502, str(e))
    st().progress[pid] = {"running": False, "message": "AI analysis finished", "ts": utcnow(), "ok": True}
    _store_extraction(pid, ex, "ai")
    return {"extraction": ex.model_dump(mode="json"), "issues": _plan_issues(p, ex)}


@app.get("/api/projects/{pid}/progress")
def extract_progress(pid: str):
    """What the running AI analysis is doing right now (model, retries, fallbacks)."""
    _project(pid)
    return st().progress.get(pid, {"running": False, "message": ""})


class ExtractionIn(BaseModel):
    extraction: dict


@app.put("/api/projects/{pid}/extraction")
def override_extraction(pid: str, body: ExtractionIn):
    """Admin correction / manual JSON (fallback when the AI is unavailable)."""
    p = _project(pid)
    try:
        ex = Extraction.model_validate(body.extraction)
    except Exception as e:
        raise HTTPException(422, f"invalid extraction JSON: {e}")
    _store_extraction(pid, ex, "manual-edit")
    return {"extraction": ex.model_dump(mode="json"), "issues": _plan_issues(p, ex)}


def _store_extraction(pid: str, ex: Extraction, how: str) -> None:
    db = st().db
    db.x("UPDATE projects SET extraction=?, validation=NULL WHERE id=?", ex.model_dump_json(), pid)
    _supersede(pid, f"extraction changed ({how})")
    db.audit("user" if how != "ai" else "ai", f"extraction_{how}", pid, None,
             {"devices": len(ex.devices), "ambiguities": len(ex.ambiguities), "confidence": ex.confidence})


def _supersede(pid: str, reason: str) -> None:
    db = st().db
    ids = [c["id"] for c in db.q("SELECT id FROM configs WHERE project_id=? AND superseded=0", pid)]
    for cid in ids:
        db.x("UPDATE configs SET superseded=1 WHERE id=?", cid)
        if db.x("UPDATE approvals SET revoked=1 WHERE config_id=? AND revoked=0", cid):
            db.audit("system", "approval_revoked", pid, None, {"config_id": cid, "reason": reason})


@app.post("/api/projects/{pid}/discover")
def discover(pid: str):
    """Read-only discovery of real interface names via Kafka -> worker -> Paramiko."""
    ex = _extraction(_project(pid))
    inv = _inventory_for(ex)
    jobs = []
    for r in ex.routers():
        if r.hostname not in inv:
            raise HTTPException(409, f"{r.hostname} not in inventory.yaml")
        job = JobMessage(job_id=new_id(), job_type=JobType.discover, project_id=pid, device_id=r.hostname,
                         verification_cmds=["show ip interface brief"])
        _publish_job(job, pid)
        jobs.append(job.job_id)
    st().db.audit("user", "discover", pid, None, {"jobs": jobs})
    return {"jobs": jobs}


@app.post("/api/projects/{pid}/mapping/suggest")
def mapping_suggest(pid: str):
    p = _project(pid)
    ex = suggest_mapping(_extraction(p), json.loads(p["discovery"] or "{}"))
    _store_extraction(pid, ex, "mapping-suggest")
    return {"extraction": ex.model_dump(mode="json")}


class MappingIn(BaseModel):
    mapping: dict[str, dict[str, str | None]] = {}  # {router: {logical_if_id: physical_name}}
    router_ids: dict[str, str] = {}                 # {router: "1.1.1.1"} - admin-confirmed OSPF router-ids


@app.put("/api/projects/{pid}/mapping")
def set_mapping(pid: str, body: MappingIn):
    ex = _extraction(_project(pid))
    for host, m in body.mapping.items():
        d = ex.device(host)
        if not d:
            raise HTTPException(422, f"unknown device {host}")
        for i in d.interfaces:
            if i.id in m:
                i.name = m[i.id] or None
    for host, rid in body.router_ids.items():
        d = ex.device(host)
        if not d or d.role != Role.router:
            raise HTTPException(422, f"unknown router {host}")
        d.router_id = rid.strip() or None
    mapped = all(i.name for r in ex.routers() for i in r.interfaces)
    rids = all(r.router_id for r in ex.routers())
    for a in ex.ambiguities:  # the admin has explicitly confirmed these values
        f = a.field.lower()
        if mapped and "interface" in f and f.endswith("name"):
            a.resolved = True
        if rids and "router_id" in f:
            a.resolved = True
    _store_extraction(pid, ex, "mapping")
    return {"extraction": ex.model_dump(mode="json")}


class AmbiguityIn(BaseModel):
    index: int
    resolved: bool = True


@app.post("/api/projects/{pid}/ambiguities/resolve")
def resolve_ambiguity(pid: str, body: AmbiguityIn):
    ex = _extraction(_project(pid))
    if not 0 <= body.index < len(ex.ambiguities):
        raise HTTPException(404)
    ex.ambiguities[body.index].resolved = body.resolved
    # A flag is metadata: resolving it changes no address, interface or OSPF value, so the generated
    # configs (and any approval bound to their hash) stay valid. Only the review must be re-run.
    st().db.x("UPDATE projects SET extraction=?, validation=NULL WHERE id=?", ex.model_dump_json(), pid)
    st().db.audit("user", "ambiguity_resolved" if body.resolved else "ambiguity_reopened", pid, None,
                  {"field": ex.ambiguities[body.index].field})
    return {"extraction": ex.model_dump(mode="json")}


@app.post("/api/projects/{pid}/generate")
def generate(pid: str, loopback: bool = False):
    """Task 3: per-device IOS/OSPF config (Jinja2)."""
    p = _project(pid)
    ex = _extraction(p)
    issues = validate_plan(ex, _inventory_for(ex), json.loads(p["discovery"] or "{}"))
    structural = [i for i in issues if i.level == "error" and i.code not in
                  ("UNMAPPED_IFACE", "NOT_DISCOVERED", "MGMT_UNREACHABLE", "NOT_IN_INVENTORY")]
    if structural:
        raise HTTPException(422, {"message": "fix the plan first", "issues": [i.dict() for i in issues]})
    unmapped = [f"{r.hostname}/{i.id}" for r in ex.routers() for i in r.interfaces if not i.name]
    if unmapped:
        raise HTTPException(409, {"message": "map router interfaces first (Discover -> mapping)",
                                  "unmapped": unmapped})
    _supersede(pid, "regenerated")
    out = []
    for c in generator.generate(ex, json.loads(p["discovery"] or "{}"), loopback=loopback):
        cid = new_id()
        st().db.x("INSERT INTO configs(id,project_id,device,role,text,sha256,deployable,verification_cmds,"
                  "expect,created_at) VALUES(?,?,?,?,?,?,?,?,?,?)", cid, pid, c.device, c.role, c.text, c.sha256,
                  int(c.deployable), json.dumps(c.verification_cmds), json.dumps(c.expect), utcnow())
        out.append({"id": cid, "device": c.device, "role": c.role, "text": c.text, "sha256": c.sha256,
                    "deployable": c.deployable, "verification_cmds": c.verification_cmds})
    st().db.x("UPDATE projects SET validation=NULL WHERE id=?", pid)
    st().db.audit("user", "generate", pid, None, {"configs": [o["id"] for o in out]})
    return {"configs": out}


def _review(pid: str) -> dict:
    p = _project(pid)
    ex = _extraction(p)
    inv = _inventory_for(ex)
    reach = {h: _tcp_reachable(e["mgmt_ip"], int(e.get("port", 22))) for h, e in inv.items()}
    if st().s.simulate_devices:
        reach = {h: True for h in inv}
    issues = validate_plan(ex, inv, json.loads(p["discovery"] or "{}"), reach, require_mapping=True)
    configs = st().db.q("SELECT * FROM configs WHERE project_id=? AND superseded=0", pid)
    if not configs:
        issues_d = [i.dict() for i in issues] + [{"level": "error", "code": "NO_CONFIGS",
                                                  "message": "Generate configurations first", "path": ""}]
    else:
        issues_d = [i.dict() for i in issues]
        for c in configs:
            bad = denied_lines(c["text"])
            if bad:
                issues_d.append({"level": "error", "code": "DENY_LIST", "message": f"{c['device']}: {bad}",
                                 "path": ""})
            if c["role"] == "router" and "ip route " in c["text"]:
                issues_d.append({"level": "error", "code": "STATIC_ROUTE", "message": "static routes not allowed",
                                 "path": ""})
    result = {"ok": not any(i["level"] == "error" for i in issues_d), "issues": issues_d, "reachability": reach,
              "config_sha256": {c["device"]: c["sha256"] for c in configs}, "ts": utcnow()}
    st().db.x("UPDATE projects SET validation=?, reachability=? WHERE id=?", json.dumps(result),
              json.dumps(reach), pid)
    return result


@app.post("/api/projects/{pid}/review")
def review(pid: str):
    """Task 4: validation report (addressing, subnets, mapping, OSPF, management reachability)."""
    return _review(pid)


def _authorised_approver(name: str) -> str:
    """Return the canonical approver name. With APPROVERS set, only listed names may approve or undeploy."""
    name = (name or "").strip()
    if not name:
        raise HTTPException(422, "approver name required")
    allowed = st().s.approvers
    if not allowed:
        return name
    match = next((a for a in allowed if a.casefold() == name.casefold()), None)
    if not match:
        raise HTTPException(403, f"'{name}' is not an authorised approver (APPROVERS in .env)")
    return match


@app.get("/api/approvers")
def approvers():
    """Authorised approver names for the UI drop-down (empty list = free text)."""
    return {"approvers": list(st().s.approvers), "restricted": bool(st().s.approvers)}


class ApproveIn(BaseModel):
    approver: str
    acknowledge_warnings: bool = False
    devices: list[str] | None = None


@app.post("/api/projects/{pid}/approve")
def approve(pid: str, body: ApproveIn):
    """Explicit administrator approval. Re-validates; binds approval to the config hash (HMAC)."""
    s = st().s
    if not s.approval_secret:
        raise HTTPException(500, "APPROVAL_HMAC_SECRET not configured")
    approver = _authorised_approver(body.approver)
    result = _review(pid)
    if not result["ok"]:
        raise HTTPException(409, {"message": "validation errors - cannot approve", "issues": result["issues"]})
    if any(i["level"] == "warning" for i in result["issues"]) and not body.acknowledge_warnings:
        raise HTTPException(409, {"message": "warnings present - tick 'acknowledge warnings' to approve",
                                  "issues": result["issues"]})
    configs = st().db.q("SELECT * FROM configs WHERE project_id=? AND superseded=0 AND deployable=1", pid)
    approved = []
    for c in configs:
        if body.devices and c["device"] not in body.devices:
            continue
        st().db.x("UPDATE approvals SET revoked=1 WHERE config_id=?", c["id"])
        aid = new_id()
        tok = approval_token(s.approval_secret, aid, c["id"], c["device"], c["sha256"])
        st().db.x("INSERT INTO approvals(id,config_id,device,sha256,approver,approved_at,token) VALUES(?,?,?,?,?,?,?)",
                  aid, c["id"], c["device"], c["sha256"], approver, utcnow(), tok)
        approved.append({"device": c["device"], "approval_id": aid, "config_id": c["id"], "sha256": c["sha256"]})
    st().db.audit(f"admin:{approver}", "approve", pid, None, approved)
    return {"approved": approved}


@app.post("/api/projects/{pid}/deploy")
def deploy(pid: str):
    """Task 5: publish approved jobs to Kafka `network-config-jobs` (reference to config, not the config)."""
    db = st().db
    _expire_lost_jobs()
    active = db.q("SELECT id FROM jobs WHERE project_id=? AND job_type IN ('deploy','verify','reset') "
                  "AND status IN ('PENDING','RUNNING')", pid)
    if active:
        raise HTTPException(409, "a deployment or undeploy is already in progress")
    rows = db.q("SELECT c.*, a.id AS approval_id, a.approver, a.approved_at, a.token, a.sha256 AS a_sha "
                "FROM configs c JOIN approvals a ON a.config_id=c.id AND a.revoked=0 "
                "WHERE c.project_id=? AND c.superseded=0 AND c.deployable=1", pid)
    deployable = db.q("SELECT device FROM configs WHERE project_id=? AND superseded=0 AND deployable=1", pid)
    if not rows or len(rows) != len(deployable):
        raise HTTPException(409, "every router config must be approved before deployment")
    batch = new_id()
    jobs = []
    for r in rows:
        if r["a_sha"] != r["sha256"] or sha256_text(r["text"]) != r["sha256"] or denied_lines(r["text"]):
            raise HTTPException(409, f"{r['device']}: integrity/safety check failed - re-approve")
        job = JobMessage(job_id=new_id(), job_type=JobType.deploy, project_id=pid, batch_id=batch,
                         device_id=r["device"], config_ref=ConfigRef(config_id=r["id"], sha256=r["sha256"]),
                         approval=ApprovalRef(approval_id=r["approval_id"], approver=r["approver"],
                                              approved_at=r["approved_at"], token=r["token"]),
                         verification_cmds=json.loads(r["verification_cmds"]))
        _publish_job(job, pid, r["id"], r["approval_id"])
        jobs.append({"job_id": job.job_id, "device": r["device"]})
    db.audit("user", "deploy", pid, None, {"batch_id": batch, "jobs": jobs})
    return {"batch_id": batch, "jobs": jobs}


class UndeployIn(BaseModel):
    approver: str


@app.post("/api/projects/{pid}/undeploy")
def undeploy(pid: str, body: UndeployIn):
    """Approved undeploy: reset R1/R2 data-plane config (interface IPs + OSPF) through Kafka -> worker ->
    Paramiko, keeping management SSH. Same approval model as deploy: an HMAC token per router bound to
    the fixed reset specification (generator.reset_spec), re-checked by the worker's claim."""
    s, db = st().s, st().db
    if not s.approval_secret:
        raise HTTPException(500, "APPROVAL_HMAC_SECRET not configured")
    approver = _authorised_approver(body.approver)
    p = _project(pid)
    _expire_lost_jobs()
    if db.q("SELECT id FROM jobs WHERE project_id=? AND job_type IN ('deploy','verify','reset') "
            "AND status IN ('PENDING','RUNNING')", pid):
        raise HTTPException(409, "a deployment or undeploy is already in progress")
    if p["extraction"]:
        routers = [h for h in _inventory_for(_extraction(p))]
    else:
        routers = list(st().inventory())
    if not routers:
        raise HTTPException(409, "no routers found in inventory.yaml")
    batch, jobs, now = new_id(), [], utcnow()
    for dev in routers:
        spec = generator.reset_spec(dev)
        sha, aid = sha256_text(spec), new_id()
        cid = f"reset:{dev}:{aid}"
        tok = approval_token(s.approval_secret, aid, cid, dev, sha)
        db.x("INSERT INTO approvals(id,config_id,device,sha256,approver,approved_at,token) VALUES(?,?,?,?,?,?,?)",
             aid, cid, dev, sha, approver, now, tok)
        job = JobMessage(job_id=new_id(), job_type=JobType.reset, project_id=pid, batch_id=batch, device_id=dev,
                         config_ref=ConfigRef(config_id=cid, sha256=sha),
                         approval=ApprovalRef(approval_id=aid, approver=approver, approved_at=now, token=tok),
                         verification_cmds=generator.RESET_CMDS)
        _publish_job(job, pid, cid, aid)
        jobs.append({"job_id": job.job_id, "device": dev})
    db.audit(f"admin:{approver}", "undeploy", pid, None, {"batch_id": batch, "jobs": jobs})
    return {"batch_id": batch, "jobs": jobs}


def _expire_lost_jobs() -> None:
    """A worker that died after claiming leaves a job RUNNING; after the lease it is marked FAILED
    ('worker lost') so the UI shows the truth and a new deployment can be started."""
    from datetime import datetime, timedelta, timezone
    s, db = st().s, st().db
    cutoff = (datetime.now(timezone.utc) - timedelta(seconds=s.job_lease_seconds)).isoformat(timespec="seconds")
    for j in db.q("SELECT id, project_id FROM jobs WHERE status='RUNNING' AND started_at < ?", cutoff):
        if db.x("UPDATE jobs SET status='FAILED', finished_at=?, error_kind='internal', message=? "
                "WHERE id=? AND status='RUNNING'", utcnow(),
                "worker lost: no result within the lease - check router state/backups", j["id"]):
            db.x("INSERT INTO events(job_id,ts,status,message) VALUES(?,?,?,?)", j["id"], utcnow(), "FAILED",
                 "lease expired (worker lost)")
            db.audit("system", "job_expired", j["project_id"], j["id"])


@app.get("/api/jobs")
def list_jobs(project_id: str | None = None, limit: int = 50):
    _expire_lost_jobs()
    if project_id:
        rows = st().db.q("SELECT * FROM jobs WHERE project_id=? ORDER BY created_at DESC LIMIT ?", project_id, limit)
    else:
        rows = st().db.q("SELECT * FROM jobs ORDER BY created_at DESC LIMIT ?", limit)
    return [_job_row_to_api(j) for j in rows]


@app.get("/api/jobs/{job_id}")
def get_job(job_id: str):
    j = st().db.one("SELECT * FROM jobs WHERE id=?", job_id)
    if not j:
        raise HTTPException(404)
    return _job_row_to_api(j)


@app.get("/api/audit")
def audit(project_id: str | None = None, limit: int = 200):
    if project_id:
        return st().db.q("SELECT * FROM audit WHERE project_id=? ORDER BY id DESC LIMIT ?", project_id, limit)
    return st().db.q("SELECT * FROM audit ORDER BY id DESC LIMIT ?", limit)


# ============================================================================ internal (worker)
class ClaimIn(BaseModel):
    device_id: str
    job_type: str
    config_sha256: str | None = None


@app.post("/api/internal/jobs/{job_id}/claim", dependencies=[Depends(require_worker)])
def claim(job_id: str, body: ClaimIn):
    """Worker re-checks approval with the backend and atomically claims the job (duplicate guard)."""
    return _claim_core(job_id, body)


def _claim_core(job_id: str, body: ClaimIn) -> dict:
    db = st().db
    j = db.one("SELECT * FROM jobs WHERE id=?", job_id)
    if not j:
        raise HTTPException(404, "unknown job")
    if j["device"] != body.device_id or j["job_type"] != body.job_type:
        raise HTTPException(403, "job metadata does not match backend record")
    if j["status"] in ("SUCCESS", "FAILED"):
        raise HTTPException(409, f"job already {j['status']}")
    device = st().resolve(j["device"])
    if not device:
        raise HTTPException(403, f"{j['device']} not in inventory")
    resp = {"device": device, "config_text": None, "config_sha256": None}
    if j["job_type"] == "deploy":
        a = db.one("SELECT * FROM approvals WHERE id=?", j["approval_id"])
        c = db.one("SELECT * FROM configs WHERE id=?", j["config_id"])
        if not a or a["revoked"] or not c or c["superseded"]:
            raise HTTPException(403, "approval missing, revoked or config superseded")
        if not (a["sha256"] == c["sha256"] == body.config_sha256 == sha256_text(c["text"])):
            raise HTTPException(403, "config hash does not match the approved hash")
        resp.update(config_text=c["text"], config_sha256=c["sha256"])
    if j["job_type"] == "reset":
        a = db.one("SELECT * FROM approvals WHERE id=?", j["approval_id"])
        spec = generator.reset_spec(j["device"])
        if not a or a["revoked"] or a["config_id"] != j["config_id"] or a["device"] != j["device"]:
            raise HTTPException(403, "undeploy approval missing or revoked")
        if not (a["sha256"] == body.config_sha256 == sha256_text(spec)):
            raise HTTPException(403, "reset specification hash does not match the approved hash")
        resp.update(config_text=spec, config_sha256=a["sha256"])
    if not db.claim_job(job_id, st().s.job_lease_seconds):
        raise HTTPException(409, "job already claimed by another worker")
    db.x("INSERT INTO events(job_id,ts,status,message) VALUES(?,?,?,?)", job_id, utcnow(), "RUNNING",
         "claimed by worker (approval re-checked)")
    db.audit("worker", "claim", j["project_id"], job_id)
    return resp
