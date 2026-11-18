"""Job processing logic (transport-agnostic, unit-testable).

deploy:   claim (approval re-check) -> integrity/safety checks -> backup -> diff -> apply line by line
          -> halt + compensating rollback on error -> post-apply diff -> per-device show commands
discover: read-only `show ip interface brief` -> management interface detection
verify:   read-only; polls OSPF neighbor/route/protocol state until expectations hold, then pings
"""
from __future__ import annotations

import logging
import os
import socket
import time
from dataclasses import dataclass
from typing import Callable, Protocol

from app.config import Settings
from app.generator import config_lines
from app.models import CommandRecord, JobMessage, JobStatus, JobType, ResultMessage
from app.safety import (READ_ONLY_RE, denied_lines, normalize_ifname, redact, sha256_text,
                        touches_interface, verify_approval_token)

from . import ios_parse as P
from .ssh_executor import AuditLog, DeviceError, IOSSession

log = logging.getLogger("worker.executor")
WORKER_ID = f"{socket.gethostname()}-{os.getpid()}"


def find_mgmt_interface(brief: list[dict], device: dict) -> str | None:
    """Inventory override wins (needed when SSH arrives via NAT/console server); otherwise the
    interface that holds the inventory management IP."""
    if device.get("mgmt_interface"):
        return normalize_ifname(device["mgmt_interface"])
    return next((r["name"] for r in brief if r["ip"] == device.get("mgmt_ip")), None)


class Session(Protocol):
    def connect(self): ...
    def close(self): ...
    def send(self, command: str, timeout: float | None = None) -> str: ...


class ClaimRejected(Exception):
    def __init__(self, kind: str, message: str):
        super().__init__(message)
        self.kind = kind  # duplicate | approval | not_found


@dataclass
class Claim:
    device: dict            # inventory entry (no secrets): mgmt_ip, port, *_env names, sim_interfaces
    config_text: str | None
    config_sha256: str | None


class Executor:
    def __init__(self, s: Settings, claim_fn: Callable[[JobMessage], Claim],
                 publish_fn: Callable[[ResultMessage], None],
                 session_factory: Callable[[JobMessage, dict], Session] | None = None):
        self.s = s
        self.claim_fn = claim_fn
        self.publish_fn = publish_fn
        self.audit = AuditLog(s.audit_log_path)
        self.session_factory = session_factory or self._default_session

    # ------------------------------------------------------------------ sessions
    def _default_session(self, job: JobMessage, dev: dict) -> Session:
        if self.s.simulate_devices:
            from .simulator import get_sim
            return get_sim(job.device_id, dev["mgmt_ip"], dev.get("sim_interfaces") or
                           ["GigabitEthernet0/0", "GigabitEthernet0/1", "GigabitEthernet0/2"])
        user = os.environ.get(dev.get("username_env", "SSH_USERNAME"))
        pwd = os.environ.get(dev.get("password_env", "SSH_PASSWORD"))
        enable = os.environ.get(dev.get("enable_secret_env", "SSH_ENABLE_SECRET"))
        if not user or not pwd:
            raise DeviceError("auth", f"Credentials env vars {dev.get('username_env')}/{dev.get('password_env')} "
                                      f"are not set in the worker environment")
        return IOSSession(dev["mgmt_ip"], int(dev.get("port", 22)), user, pwd, enable,
                          timeout=self.s.ssh_timeout, command_timeout=self.s.ssh_command_timeout,
                          host_key_policy=self.s.ssh_host_key_policy, known_hosts=self.s.ssh_known_hosts,
                          legacy_algorithms=self.s.ssh_legacy_algorithms, audit=self.audit,
                          job_id=job.job_id, device=job.device_id)

    # ------------------------------------------------------------------ helpers
    def _result(self, job: JobMessage, status: JobStatus, final: bool, message: str, **kw) -> ResultMessage:
        r = ResultMessage(job_id=job.job_id, device_id=job.device_id, job_type=job.job_type, status=status,
                          final=final, message=redact(message), worker=WORKER_ID, **kw)
        for c in r.commands:
            c.output = redact(c.output)
        self.publish_fn(r)
        return r

    def _progress(self, job: JobMessage, message: str) -> None:
        self.audit.write(job.job_id, job.device_id, "progress", message)
        self._result(job, JobStatus.RUNNING, False, message)

    def _run(self, sess: Session, job: JobMessage, cmd: str, records: list[CommandRecord],
             read_only: bool = False, timeout: float | None = None) -> str:
        if read_only and not READ_ONLY_RE.match(cmd):
            raise DeviceError("command", f"Refusing non read-only command in {job.job_type.value} job: {cmd}")
        out = sess.send(cmd, timeout)
        if not isinstance(sess, IOSSession):  # IOSSession audits itself
            self.audit.write(job.job_id, job.device_id, "command", out, command=cmd)
        err = P.find_error(out)
        records.append(CommandRecord(command=cmd, output=out, ok=err is None))
        return out

    # ------------------------------------------------------------------ entry point
    def process(self, raw: dict) -> ResultMessage | None:
        try:
            job = JobMessage.model_validate(raw)
        except Exception as e:  # malformed message: cannot even report against a job id reliably
            log.error("invalid job message dropped: %s", e)
            self.audit.write(str(raw.get("job_id", "?")), str(raw.get("device_id", "?")), "rejected", str(e))
            return None
        self.audit.write(job.job_id, job.device_id, "received", job.job_type.value)
        try:
            claim = self.claim_fn(job)
        except ClaimRejected as e:
            self.audit.write(job.job_id, job.device_id, "claim_rejected", str(e), kind=e.kind)
            if e.kind == "duplicate":
                log.info("job %s already claimed/finished - skipping duplicate delivery", job.job_id)
                return None
            return self._result(job, JobStatus.FAILED, True, str(e), error_kind="approval")
        self._progress(job, f"claimed by {WORKER_ID}")
        try:
            if job.job_type == JobType.deploy:
                return self._deploy(job, claim)
            if job.job_type == JobType.discover:
                return self._discover(job, claim)
            if job.job_type == JobType.reset:
                return self._reset(job, claim)
            return self._verify(job, claim)
        except DeviceError as e:
            self.audit.write(job.job_id, job.device_id, "error", str(e), kind=e.kind)
            return self._result(job, JobStatus.FAILED, True, str(e), error_kind=e.kind)
        except Exception as e:  # never leave a job RUNNING silently
            log.exception("job %s crashed", job.job_id)
            return self._result(job, JobStatus.FAILED, True, f"internal error: {e}", error_kind="internal")

    # ------------------------------------------------------------------ deploy
    def _deploy(self, job: JobMessage, claim: Claim) -> ResultMessage:
        if not (job.config_ref and job.approval):
            return self._result(job, JobStatus.FAILED, True, "deploy job lacks config_ref/approval",
                                error_kind="approval")
        if not self.s.approval_secret or not verify_approval_token(
                self.s.approval_secret, job.approval.token, job.approval.approval_id,
                job.config_ref.config_id, job.device_id, job.config_ref.sha256):
            return self._result(job, JobStatus.FAILED, True, "approval token signature invalid",
                                error_kind="approval")
        text = claim.config_text or ""
        if sha256_text(text) != job.config_ref.sha256 or claim.config_sha256 != job.config_ref.sha256:
            return self._result(job, JobStatus.FAILED, True, "config hash mismatch - config changed after approval",
                                error_kind="integrity")
        bad = denied_lines(text)
        if bad:
            return self._result(job, JobStatus.FAILED, True, f"deny-listed commands present: {bad}",
                                error_kind="safety")

        records: list[CommandRecord] = []
        sess = self.session_factory(job, claim.device)
        sess.connect()
        applied: list[str] = []
        try:
            self._progress(job, "connected; reading interfaces and running-config")
            brief = P.parse_ip_int_brief(self._run(sess, job, "show ip interface brief", records))
            mgmt_if = find_mgmt_interface(brief, claim.device)
            if not mgmt_if:
                return self._result(job, JobStatus.FAILED, True,
                                    f"cannot identify the management interface (no interface holds "
                                    f"{claim.device['mgmt_ip']}); set mgmt_interface in inventory.yaml - refused",
                                    error_kind="safety", commands=records)
            if touches_interface(text, mgmt_if):
                return self._result(job, JobStatus.FAILED, True,
                                    f"config touches management interface {mgmt_if} - refused",
                                    error_kind="safety", commands=records)
            running = self._run(sess, job, "show running-config", records)
            backup = self.s.backup_dir / f"{job.job_id}-{job.device_id}.cfg"
            backup.parent.mkdir(parents=True, exist_ok=True)
            backup.write_text(redact(running), encoding="utf-8")

            desired = "\n".join(config_lines(text))
            todo = P.diff_config(desired, running, {mgmt_if})
            if not todo:
                self._progress(job, "running-config already matches approved config (idempotent no-op)")
                noop = True
            else:
                noop = False
                self._progress(job, f"applying {sum(1 for l in todo if l.strip() != 'exit')} line(s)")
                self._run(sess, job, "configure terminal", records)
                for line in todo:
                    out = sess.send(line)
                    self.audit.write(job.job_id, job.device_id, "config", out, command=line)
                    err = P.find_error(out)
                    records.append(CommandRecord(command=line, output=out, ok=err is None))
                    if err:
                        sess.send("end")
                        rolled = self._rollback(sess, job, applied, running, records)
                        return self._result(job, JobStatus.FAILED, True,
                                            f"command failed: '{line.strip()}' -> {err}; halted"
                                            + (" and rolled back" if rolled else ""),
                                            error_kind="command", applied_lines=applied, rolled_back=rolled,
                                            commands=records)
                    applied.append(line)
                sess.send("end")
            after = self._run(sess, job, "show running-config", records)
            remaining = P.diff_config(desired, after, {mgmt_if})
            if remaining:
                rolled = self._rollback(sess, job, applied, running, records)
                return self._result(job, JobStatus.FAILED, True, f"post-check: lines still missing {remaining}",
                                    error_kind="command", applied_lines=applied, rolled_back=rolled,
                                    commands=records)
            for cmd in job.verification_cmds:
                if cmd in ("show ip interface brief", "show ip protocols"):
                    self._run(sess, job, cmd, records, read_only=True)
            if self.s.save_config and not noop:
                self._run(sess, job, "write memory", records, timeout=60)
            return self._result(job, JobStatus.SUCCESS, True,
                                "no changes needed" if noop else f"applied {len(applied)} line(s)",
                                applied_lines=applied, noop=noop, commands=records)
        finally:
            sess.close()

    def _rollback(self, sess: Session, job: JobMessage, applied: list[str], running_before: str,
                  records: list[CommandRecord]) -> bool:
        if not applied or not self.s.rollback_on_failure:
            return False
        lines = P.rollback_lines(applied, running_before)
        self._progress(job, f"rolling back {len(lines)} line(s)")
        try:
            sess.send("configure terminal")
            for line in lines:
                out = sess.send(line)
                self.audit.write(job.job_id, job.device_id, "rollback", out, command=line)
                records.append(CommandRecord(command=f"[rollback] {line}", output=out, ok=P.find_error(out) is None))
            sess.send("end")
            return True
        except DeviceError as e:
            self.audit.write(job.job_id, job.device_id, "rollback_failed", str(e))
            return False

    # ------------------------------------------------------------------ reset (undeploy)
    def _reset(self, job: JobMessage, claim: Claim) -> ResultMessage:
        """Approved undeploy: same approval/integrity checks as deploy, removal lines computed from the
        running-config, management interface protected, post-check. On a command error it halts and
        reports (no automatic rollback); recovery = deploy the approved plan again (backup is saved)."""
        if not (job.config_ref and job.approval):
            return self._result(job, JobStatus.FAILED, True, "reset job lacks config_ref/approval",
                                error_kind="approval")
        if not self.s.approval_secret or not verify_approval_token(
                self.s.approval_secret, job.approval.token, job.approval.approval_id,
                job.config_ref.config_id, job.device_id, job.config_ref.sha256):
            return self._result(job, JobStatus.FAILED, True, "approval token signature invalid",
                                error_kind="approval")
        spec = claim.config_text or ""
        if sha256_text(spec) != job.config_ref.sha256 or claim.config_sha256 != job.config_ref.sha256:
            return self._result(job, JobStatus.FAILED, True, "reset specification hash mismatch",
                                error_kind="integrity")
        records: list[CommandRecord] = []
        sess = self.session_factory(job, claim.device)
        sess.connect()
        applied: list[str] = []
        try:
            self._progress(job, "connected; reading interfaces and running-config")
            brief = P.parse_ip_int_brief(self._run(sess, job, "show ip interface brief", records))
            mgmt_if = find_mgmt_interface(brief, claim.device)
            if not mgmt_if:
                return self._result(job, JobStatus.FAILED, True,
                                    f"cannot identify the management interface (no interface holds "
                                    f"{claim.device['mgmt_ip']}) - reset refused", error_kind="safety",
                                    commands=records)
            running = self._run(sess, job, "show running-config", records)
            backup = self.s.backup_dir / f"{job.job_id}-{job.device_id}-before-reset.cfg"
            backup.parent.mkdir(parents=True, exist_ok=True)
            backup.write_text(redact(running), encoding="utf-8")
            todo = P.reset_lines(running, {mgmt_if})
            text = "\n".join(todo)
            if touches_interface(text, mgmt_if) or denied_lines(text):
                return self._result(job, JobStatus.FAILED, True, "reset would touch protected config - refused",
                                    error_kind="safety", commands=records)
            if not todo:
                self._progress(job, "data plane already reset (idempotent no-op)")
            else:
                self._progress(job, f"removing data-plane config ({sum(1 for l in todo if l.strip() != 'exit')} line(s)); "
                                    f"{mgmt_if} is protected")
                self._run(sess, job, "configure terminal", records)
                for line in todo:
                    out = sess.send(line)
                    self.audit.write(job.job_id, job.device_id, "config", out, command=line)
                    err = P.find_error(out)
                    records.append(CommandRecord(command=line, output=out, ok=err is None))
                    if err:
                        sess.send("end")
                        return self._result(job, JobStatus.FAILED, True,
                                            f"command failed: '{line.strip()}' -> {err}; reset halted (not rolled "
                                            f"back - deploy the approved plan again to restore)",
                                            error_kind="command", applied_lines=applied, commands=records)
                    applied.append(line)
                sess.send("end")
            after = self._run(sess, job, "show running-config", records)
            remaining = P.reset_lines(after, {mgmt_if})
            if remaining:
                return self._result(job, JobStatus.FAILED, True, f"post-check: data-plane config still present {remaining}",
                                    error_kind="command", applied_lines=applied, commands=records)
            for cmd in job.verification_cmds:
                self._run(sess, job, cmd, records, read_only=True)
            if self.s.save_config and applied:
                self._run(sess, job, "write memory", records, timeout=60)
            return self._result(job, JobStatus.SUCCESS, True,
                                "already reset - no changes needed" if not applied else
                                f"data plane reset ({sum(1 for l in applied if l.strip() != 'exit')} line(s)); "
                                f"management {mgmt_if} untouched",
                                applied_lines=applied, noop=not applied, commands=records)
        finally:
            sess.close()

    # ------------------------------------------------------------------ discover
    def _discover(self, job: JobMessage, claim: Claim) -> ResultMessage:
        records: list[CommandRecord] = []
        sess = self.session_factory(job, claim.device)
        sess.connect()
        try:
            brief = P.parse_ip_int_brief(self._run(sess, job, "show ip interface brief", records, read_only=True))
        finally:
            sess.close()
        mgmt = find_mgmt_interface(brief, claim.device)
        physical = [r for r in brief if not r["name"].lower().startswith(("loopback", "null", "tunnel", "vlan"))]
        data = [r for r in physical if normalize_ifname(r["name"]) != (normalize_ifname(mgmt) if mgmt else None)]
        return self._result(job, JobStatus.SUCCESS, True,
                            f"{len(data)} data-plane interface(s); management on {mgmt or 'unknown'}",
                            discovery={"interfaces": physical, "mgmt_interface": mgmt,
                                       "data_interfaces": [r["name"] for r in data]},
                            commands=records)

    # ------------------------------------------------------------------ verify
    def _verify(self, job: JobMessage, claim: Claim) -> ResultMessage:
        exp = job.expect
        if exp is None:
            return self._result(job, JobStatus.FAILED, True, "verify job without expectations", error_kind="internal")
        sess = self.session_factory(job, claim.device)
        sess.connect()
        deadline = time.monotonic() + self.s.verify_timeout
        attempt, checks, records = 0, {}, []
        try:
            while True:
                attempt += 1
                records = []
                nbrs = P.parse_ospf_neighbors(self._run(sess, job, "show ip ospf neighbor", records, True))
                routes = P.parse_ospf_routes(self._run(sess, job, "show ip route ospf", records, True))
                proto = P.parse_ip_protocols(self._run(sess, job, "show ip protocols", records, True))
                full = {n["router_id"] for n in nbrs if n["state"].upper() == "FULL"}
                learned = {r["prefix"] for r in routes}
                checks = {
                    "ospf_process": {"ok": proto["ospf_process"] == exp.process_id,
                                     "expected": exp.process_id, "actual": proto["ospf_process"]},
                    "router_id": {"ok": proto["router_id"] == exp.router_id,
                                  "expected": exp.router_id, "actual": proto["router_id"]},
                    "neighbors_full": {"ok": set(exp.neighbors) <= full,
                                       "expected": exp.neighbors, "actual": nbrs},
                    "ospf_routes": {"ok": set(exp.ospf_prefixes) <= learned,
                                    "expected": exp.ospf_prefixes, "actual": sorted(learned)},
                    "passive_interfaces": {
                        "ok": {normalize_ifname(p) for p in exp.passive_interfaces}
                              <= set(proto["passive_interfaces"]),
                        "expected": exp.passive_interfaces, "actual": proto["passive_interfaces"]},
                }
                if all(c["ok"] for c in checks.values()) or time.monotonic() >= deadline:
                    break
                self._progress(job, f"waiting for OSPF convergence (attempt {attempt}): "
                                    + ", ".join(k for k, v in checks.items() if not v["ok"]))
                time.sleep(self.s.verify_interval)
            pings = []
            for p in exp.pings:
                out = self._run(sess, job, f"ping {p['target']} source {p['source']}", records, True, timeout=60)
                res = P.parse_ping(out)
                pings.append({**p, **res, "ok": res["success_rate"] >= 60})
            checks["pings"] = {"ok": all(p["ok"] for p in pings if p.get("required")), "results": pings}
        finally:
            sess.close()
        ok = all(c["ok"] for c in checks.values())
        failed = [k for k, v in checks.items() if not v["ok"]]
        return self._result(job, JobStatus.SUCCESS if ok else JobStatus.FAILED, True,
                            "all OSPF checks passed" if ok else f"verification failed: {failed}",
                            error_kind=None if ok else "verification",
                            verification={"attempts": attempt, "checks": checks}, commands=records)

