"""IOSSession I/O against a fake Paramiko channel: echo/prompt stripping, enable, error kinds."""
import socket

import paramiko
import pytest

from worker.ssh_executor import DeviceError, IOSSession


class FakeChan:
    def __init__(self, hostname="R1", start=">"):
        self.host, self.mode, self.out, self.closed = hostname, start, [f"\r\n{hostname}{start}"], False
        self.awaiting_pw = False

    def settimeout(self, t): ...
    def exit_status_ready(self): return False
    def recv_ready(self): return bool(self.out)
    def recv(self, n): return self.out.pop(0).encode()

    def send(self, data):
        cmd = data.strip()
        if self.awaiting_pw:
            self.awaiting_pw = False
            self.mode = "#" if cmd == "s3cret" else ">"
            self.out.append(f"\r\n{self.host}{self.mode}")
            return
        if cmd == "enable":
            self.awaiting_pw = True
            self.out.append("enable\r\nPassword: ")
            return
        body = {"show clock": "*10:00:00.000 UTC Wed Nov 18 2026",
                "configure terminal": "Enter configuration commands, one per line.  End with CNTL/Z."}.get(cmd, "")
        if cmd == "configure terminal":
            self.mode = "(config)#"
        self.out.append(f"{cmd}\r\n{body}\r\n{self.host}{self.mode}")


class FakeClient:
    def __init__(self, chan=None, exc=None):
        self.chan, self.exc = chan, exc

    def load_system_host_keys(self): ...
    def load_host_keys(self, p): ...
    def set_missing_host_key_policy(self, p): ...
    def connect(self, **kw):
        if self.exc:
            raise self.exc
    def invoke_shell(self, **kw): return self.chan
    def close(self): ...


def make(monkeypatch, client, enable="s3cret"):
    monkeypatch.setattr(paramiko, "SSHClient", lambda: client)
    return IOSSession("192.0.2.1", 22, "u", "p", enable, timeout=1, command_timeout=2, device="R1")


def test_enable_and_output_stripping(monkeypatch):
    chan = FakeChan()
    s = make(monkeypatch, FakeClient(chan)).connect()
    assert chan.mode == "#"
    assert s.send("show clock") == "*10:00:00.000 UTC Wed Nov 18 2026"
    assert "Enter configuration" in s.send("configure terminal")  # config-mode prompt R1(config)# detected


def test_wrong_enable_secret(monkeypatch):
    with pytest.raises(DeviceError) as e:
        make(monkeypatch, FakeClient(FakeChan()), enable="wrong").connect()
    assert e.value.kind == "auth"


@pytest.mark.parametrize("exc,kind", [
    (paramiko.AuthenticationException("bad"), "auth"),
    (socket.timeout("t"), "timeout"),
    (ConnectionRefusedError("refused"), "unreachable"),
    (paramiko.SSHException("kex"), "ssh"),
])
def test_connect_errors_classified(monkeypatch, exc, kind):
    with pytest.raises(DeviceError) as e:
        make(monkeypatch, FakeClient(exc=exc)).connect()
    assert e.value.kind == kind
