"""Worker entry point: `python -m worker.main`.

Consumes `network-config-jobs` (group `network-config-workers`), re-checks approval with the
backend (atomic claim = duplicate guard), executes via Paramiko, publishes to
`network-config-results`, then commits the Kafka offset (at-least-once + idempotent execution).
"""
from __future__ import annotations

import logging
import signal
import time

import httpx

from app.bus import make_bus
from app.config import get_settings
from app.models import JobMessage, ResultMessage

from .executor import Claim, ClaimRejected, Executor

log = logging.getLogger("worker")


class ApiClaimer:
    """Asks the API to atomically move the job PENDING -> RUNNING after re-validating approval."""

    def __init__(self, base_url: str, token: str, retries: int = 5):
        self.http = httpx.Client(base_url=base_url, timeout=10, headers={"X-Worker-Token": token})
        self.retries = retries

    def __call__(self, job: JobMessage) -> Claim:
        last = None
        for attempt in range(self.retries):
            try:
                r = self.http.post(f"/api/internal/jobs/{job.job_id}/claim",
                                   json={"device_id": job.device_id, "job_type": job.job_type.value,
                                         "config_sha256": job.config_ref.sha256 if job.config_ref else None})
            except httpx.HTTPError as e:  # API down: back off, then let Kafka redeliver
                last = e
                time.sleep(2 ** attempt)
                continue
            if r.status_code == 200:
                body = r.json()
                return Claim(device=body["device"], config_text=body.get("config_text"),
                             config_sha256=body.get("config_sha256"))
            if r.status_code == 409:
                raise ClaimRejected("duplicate", r.json().get("detail", "already claimed"))
            if r.status_code in (403, 404, 422):
                raise ClaimRejected("approval", f"backend refused job: {r.json().get('detail', r.text)}")
            last = RuntimeError(f"claim HTTP {r.status_code}: {r.text}")
            time.sleep(2 ** attempt)
        raise RuntimeError(f"cannot reach backend to claim job {job.job_id}: {last}")


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    s = get_settings()
    if not s.worker_token or not s.approval_secret:
        raise SystemExit("WORKER_TOKEN and APPROVAL_HMAC_SECRET must be set")
    bus = make_bus(s)
    bus.ensure_topics()

    def publish(r: ResultMessage) -> None:
        bus.publish(s.results_topic, r.job_id, r.model_dump(mode="json"))

    executor = Executor(s, ApiClaimer(s.api_base_url, s.worker_token), publish)
    stopping = {"flag": False}
    signal.signal(signal.SIGTERM, lambda *_: stopping.update(flag=True))
    signal.signal(signal.SIGINT, lambda *_: stopping.update(flag=True))
    log.info("worker consuming %s as group %s (simulate=%s)", s.jobs_topic, s.worker_group, s.simulate_devices)
    bus.consume(s.jobs_topic, s.worker_group, executor.process, stop=lambda: stopping["flag"])


if __name__ == "__main__":
    main()
