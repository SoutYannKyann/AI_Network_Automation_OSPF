"""Central settings. Everything comes from environment variables - no secrets in code."""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def _env(name: str, default: str | None = None) -> str | None:
    value = os.environ.get(name)
    return value if value not in (None, "") else default


def _bool(name: str, default: bool) -> bool:
    return str(_env(name, str(default))).strip().lower() in {"1", "true", "yes", "on"}


@dataclass(frozen=True)
class Settings:
    # Kafka
    kafka_bootstrap: str = field(default_factory=lambda: _env("KAFKA_BOOTSTRAP", "localhost:29092"))
    jobs_topic: str = field(default_factory=lambda: _env("KAFKA_JOBS_TOPIC", "network-config-jobs"))
    results_topic: str = field(default_factory=lambda: _env("KAFKA_RESULTS_TOPIC", "network-config-results"))
    worker_group: str = field(default_factory=lambda: _env("KAFKA_WORKER_GROUP", "network-config-workers"))
    api_group: str = field(default_factory=lambda: _env("KAFKA_API_GROUP", "network-config-api"))
    bus_backend: str = field(default_factory=lambda: _env("BUS_BACKEND", "kafka"))  # kafka | memory (tests)
    # dev only: with BUS_BACKEND=memory, run the worker inside the API process (UI rehearsal, no Kafka)
    inprocess_worker: bool = field(default_factory=lambda: _bool("INPROCESS_WORKER", False))

    # API / storage
    api_base_url: str = field(default_factory=lambda: _env("API_BASE_URL", "http://localhost:8000"))
    data_dir: Path = field(default_factory=lambda: Path(_env("DATA_DIR", str(ROOT / "data"))))
    inventory_path: Path = field(default_factory=lambda: Path(_env("INVENTORY_PATH", str(ROOT / "inventory.yaml"))))

    # Security (shared secrets between API and worker; set them in .env, never commit)
    worker_token: str | None = field(default_factory=lambda: _env("WORKER_TOKEN"))
    approval_secret: str | None = field(default_factory=lambda: _env("APPROVAL_HMAC_SECRET"))
    job_lease_seconds: int = field(default_factory=lambda: int(_env("JOB_LEASE_SECONDS", "600")))
    # authorised approvers (comma separated names). Empty = any non-empty name is accepted.
    approvers: tuple[str, ...] = field(default_factory=lambda: tuple(
        n.strip() for n in (_env("APPROVERS", "") or "").split(",") if n.strip()))

    # AI extraction: "anthropic" (Claude API), "gemini" (Google Gemini API) or "ollama" (local, no key)
    ai_provider: str = field(default_factory=lambda: _env("AI_PROVIDER", "anthropic").strip().lower())
    anthropic_model: str = field(default_factory=lambda: _env("ANTHROPIC_MODEL", "claude-opus-5-5"))
    extraction_effort: str = field(default_factory=lambda: _env("EXTRACTION_EFFORT", "high"))
    gemini_api_key: str | None = field(default_factory=lambda: _env("GEMINI_API_KEY"))
    gemini_model: str = field(default_factory=lambda: _env("GEMINI_MODEL", "gemini-3.8-flash"))
    gemini_url: str = field(default_factory=lambda: _env(
        "GEMINI_URL", "https://generativelanguage.googleapis.com/v1beta").rstrip("/"))
    gemini_timeout: float = field(default_factory=lambda: float(_env("GEMINI_TIMEOUT", "180")))
    # free-tier backup models tried in order when the primary is busy/unavailable (empty = none)
    gemini_fallback_models: tuple[str, ...] = field(default_factory=lambda: tuple(
        m.strip() for m in (_env("GEMINI_FALLBACK_MODELS", "gemini-3.5-flash-lite,gemini-3.6-flash")
                            if os.environ.get("GEMINI_FALLBACK_MODELS") is None
                            else os.environ["GEMINI_FALLBACK_MODELS"]).split(",") if m.strip()))
    gemini_retries: int = field(default_factory=lambda: int(_env("GEMINI_RETRIES", "2")))
    ollama_url: str = field(default_factory=lambda: _env("OLLAMA_URL", "http://localhost:11434").rstrip("/"))
    ollama_model: str = field(default_factory=lambda: _env("OLLAMA_MODEL", "qwen2.5vl:7b"))
    ollama_timeout: float = field(default_factory=lambda: float(_env("OLLAMA_TIMEOUT", "600")))
    # layers to put on the GPU; unset = Ollama decides, 0 = CPU only (e.g. when the CUDA backend crashes)
    ollama_num_gpu: int | None = field(default_factory=lambda: int(v) if (v := _env("OLLAMA_NUM_GPU")) else None)

    # Worker / SSH
    simulate_devices: bool = field(default_factory=lambda: _bool("SIMULATE_DEVICES", False))
    ssh_timeout: float = field(default_factory=lambda: float(_env("SSH_TIMEOUT", "15")))
    ssh_command_timeout: float = field(default_factory=lambda: float(_env("SSH_COMMAND_TIMEOUT", "30")))
    ssh_host_key_policy: str = field(default_factory=lambda: _env("SSH_HOST_KEY_POLICY", "warn"))  # reject|warn|autoadd
    ssh_known_hosts: str | None = field(default_factory=lambda: _env("SSH_KNOWN_HOSTS"))
    ssh_legacy_algorithms: bool = field(default_factory=lambda: _bool("SSH_LEGACY_ALGORITHMS", False))
    rollback_on_failure: bool = field(default_factory=lambda: _bool("ROLLBACK_ON_FAILURE", True))
    save_config: bool = field(default_factory=lambda: _bool("SAVE_CONFIG", False))
    verify_timeout: int = field(default_factory=lambda: int(_env("VERIFY_TIMEOUT", "120")))
    verify_interval: int = field(default_factory=lambda: int(_env("VERIFY_INTERVAL", "10")))
    audit_log_path: Path = field(default_factory=lambda: Path(_env("AUDIT_LOG_PATH", str(ROOT / "data" / "audit.jsonl"))))
    backup_dir: Path = field(default_factory=lambda: Path(_env("BACKUP_DIR", str(ROOT / "data" / "backups"))))


def get_settings() -> Settings:
    return Settings()
