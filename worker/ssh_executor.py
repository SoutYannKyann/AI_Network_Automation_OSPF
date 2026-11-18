"""Paramiko-based Cisco IOS session: interactive shell, prompt detection, enable, error capture,
audit logging of every command/output (redacted)."""
from __future__ import annotations

import json
import logging
import re
import socket
import threading
import time
from pathlib import Path

import paramiko

from app.models import utcnow
from app.safety import redact

log = logging.getLogger("worker.ssh")

_PROMPT = r"[\w.\-/:]+(?:\([\w.\-/: ]+\))?[>#]"
PROMPT_RE = re.compile(rf"^{_PROMPT}\s?$")               # a whole line that is a prompt
PROMPT_END_RE = re.compile(rf"(?:^|\n){_PROMPT}\s*$")     # buffer currently ends with a prompt


class DeviceError(Exception):
    """Raised with a machine-readable kind: auth | timeout | unreachable | ssh | command."""

    def __init__(self, kind: str, message: str):
        super().__init__(message)
        self.kind = kind


class AuditLog:
    """Append-only JSONL audit trail (one record per command), thread-safe."""

    def __init__(self, path: Path):
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()

    def write(self, job_id: str, device: str, event: str, data: str = "", **extra) -> None:
        extra = {k: redact(v) if isinstance(v, str) else v for k, v in extra.items()}
        rec = {"ts": utcnow(), "job_id": job_id, "device": device, "event": event, "data": redact(data), **extra}
        with self._lock, self.path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(rec) + "\n")


class IOSSession:
    def __init__(self, host: str, port: int, username: str, password: str, enable_secret: str | None,
                 *, timeout: float = 15, command_timeout: float = 30, host_key_policy: str = "warn",
                 known_hosts: str | None = None, legacy_algorithms: bool = False,
                 audit: AuditLog | None = None, job_id: str = "", device: str = ""):
        self.host, self.port = host, port
        self._username, self._password, self._enable = username, password, enable_secret
        self.timeout, self.command_timeout = timeout, command_timeout
        self.host_key_policy, self.known_hosts = host_key_policy, known_hosts
        self.legacy = legacy_algorithms
        self.audit, self.job_id, self.device = audit, job_id, device
        self.client: paramiko.SSHClient | None = None
        self.chan = None

    # ---------------------------------------------------------------- connection
    def connect(self) -> "IOSSession":
        client = paramiko.SSHClient()
        if self.known_hosts:
            client.load_host_keys(self.known_hosts)
        else:
            client.load_system_host_keys()
        policy = {"reject": paramiko.RejectPolicy, "autoadd": paramiko.AutoAddPolicy}.get(
            self.host_key_policy, paramiko.WarningPolicy)
        client.set_missing_host_key_policy(policy())
        kwargs = dict(hostname=self.host, port=self.port, username=self._username, password=self._password,
                      timeout=self.timeout, banner_timeout=self.timeout, auth_timeout=self.timeout,
                      look_for_keys=False, allow_agent=False)
        if self.legacy:
            # Old IOS images (common in GNS3) only offer ssh-rsa host keys / SHA1 KEX.
            kwargs["disabled_algorithms"] = {"pubkeys": ["rsa-sha2-256", "rsa-sha2-512"]}
        try:
            client.connect(**kwargs)
        except paramiko.AuthenticationException as e:
            raise DeviceError("auth", f"SSH authentication failed for {self.device} ({e})") from e
        except (socket.timeout, TimeoutError) as e:
            raise DeviceError("timeout", f"SSH connection to {self.host}:{self.port} timed out") from e
        except (paramiko.ssh_exception.NoValidConnectionsError, ConnectionRefusedError, OSError) as e:
            raise DeviceError("unreachable", f"Cannot reach {self.host}:{self.port} ({e})") from e
        except paramiko.SSHException as e:
            raise DeviceError("ssh", f"SSH negotiation failed with {self.host}: {e}") from e
        self.client = client
        self.chan = client.invoke_shell(width=511, height=0)
        self.chan.settimeout(self.command_timeout)
        banner = self._read_until_prompt(self.command_timeout)
        self._log("connect", banner)
        if banner.rstrip().endswith(">"):
            self._enable_mode()
        self.send("terminal length 0")
        self.send("terminal width 511")
        return self

    def _enable_mode(self) -> None:
        if not self._enable:
            raise DeviceError("auth", f"{self.device} is in user EXEC mode and no enable secret is configured")
        self.chan.send("enable\n")
        out = self._read_until(re.compile(r"[Pp]assword:\s*$"), 10)
        self.chan.send(self._enable + "\n")
        out += self._read_until_prompt(10)
        self._log("enable", "enable <secret>")
        if not out.rstrip().endswith("#"):
            raise DeviceError("auth", f"Enable authentication failed on {self.device}")

    def close(self) -> None:
        try:
            if self.client:
                self.client.close()
        finally:
            self.client = self.chan = None

    def __enter__(self):
        return self.connect()

    def __exit__(self, *exc):
        self.close()

    # ---------------------------------------------------------------- I/O
    def _read_until(self, pattern: re.Pattern, timeout: float) -> str:
        buf, deadline = "", time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self.chan.recv_ready():
                buf += self.chan.recv(65535).decode("utf-8", errors="replace")
                tail = buf[-300:].replace("\r", "")
                if pattern.search(tail):
                    return buf
            elif self.chan.closed or self.chan.exit_status_ready():
                raise DeviceError("ssh", f"Channel to {self.device} closed unexpectedly")
            else:
                time.sleep(0.05)
        raise DeviceError("timeout", f"Timed out waiting for prompt on {self.device}; last output: {buf[-200:]!r}")

    def _read_until_prompt(self, timeout: float) -> str:
        return self._read_until(PROMPT_END_RE, timeout)

    def send(self, command: str, timeout: float | None = None) -> str:
        """Send one line, wait for the prompt, return output without echo/prompt."""
        self.chan.send(command + "\n")
        raw = self._read_until_prompt(timeout or self.command_timeout)
        lines = raw.replace("\r", "").split("\n")
        if lines and command.strip() and command.strip() in lines[0]:
            lines = lines[1:]
        if lines and PROMPT_RE.match(lines[-1].strip()):
            lines = lines[:-1]
        out = "\n".join(lines).strip("\n")
        self._log("command", out, command=command)
        return out

    def _log(self, event: str, data: str, **extra) -> None:
        if self.audit:
            self.audit.write(self.job_id, self.device, event, data, **{k: redact(v) for k, v in extra.items()})
