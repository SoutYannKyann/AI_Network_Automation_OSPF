"""Data contracts: extraction (topology/addressing plan), Kafka job, worker result.

`python scripts/export_schemas.py` writes these as JSON Schema files into /schemas.
"""
from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Literal, Optional

from pydantic import BaseModel, ConfigDict, Field


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


# --------------------------------------------------------------------------- extraction
class Role(str, Enum):
    router = "router"
    host = "host"


class Interface(BaseModel):
    model_config = ConfigDict(extra="forbid")
    id: str = Field(description="Logical id unique per device, e.g. 'R1-L1' (diagrams rarely show port names)")
    name: Optional[str] = Field(None, description="Physical IOS interface name, e.g. GigabitEthernet0/1. "
                                                  "Null until mapped from router discovery.")
    ip: str = Field(description="IPv4 address, dotted decimal")
    mask: str = Field(description="Subnet mask, dotted decimal, e.g. 255.255.255.0")
    link: str = Field(description="Id of the link this interface attaches to")


class Device(BaseModel):
    model_config = ConfigDict(extra="forbid")
    hostname: str
    role: Role
    aliases: list[str] = Field(default_factory=list, description="Other labels seen in the diagram, e.g. 'router1'")
    router_id: Optional[str] = Field(None, description="OSPF router-id (routers only)")
    interfaces: list[Interface]


class Endpoint(BaseModel):
    model_config = ConfigDict(extra="forbid")
    device: str
    interface: str = Field(description="Logical interface id on that device")


class Link(BaseModel):
    model_config = ConfigDict(extra="forbid")
    id: str
    subnet: str = Field(description="CIDR, e.g. 10.1.0.0/24")
    kind: Literal["lan", "transit"] = Field(description="lan = router-to-host segment, transit = router-to-router")
    endpoints: list[Endpoint]


class AddressingEntry(BaseModel):
    model_config = ConfigDict(extra="forbid")
    device: str
    interface: str = Field(description="Logical interface id")
    ip: str
    mask: str
    gateway: Optional[str] = Field(None, description="Default gateway (hosts only)")


class Routing(BaseModel):
    model_config = ConfigDict(extra="forbid")
    protocol: Literal["ospf"] = "ospf"
    process_id: int = Field(1, ge=1, le=65535)
    area: int = Field(0, ge=0)
    passive_lan_interfaces: bool = True


class Ambiguity(BaseModel):
    model_config = ConfigDict(extra="forbid")
    field: str = Field(description="JSON path or topic the issue concerns")
    issue: str
    suggestion: Optional[str] = None
    resolved: bool = False


class Extraction(BaseModel):
    """Topology + addressing plan extracted from the diagram (or entered/overridden by the admin)."""
    model_config = ConfigDict(extra="forbid")
    devices: list[Device]
    links: list[Link]
    addressing_plan: list[AddressingEntry]
    routing: Routing = Field(default_factory=Routing)
    ambiguities: list[Ambiguity] = Field(default_factory=list)
    confidence: float = Field(1.0, ge=0.0, le=1.0)
    source: Literal["ai", "manual", "sample"] = "manual"

    def device(self, hostname: str) -> Device | None:
        return next((d for d in self.devices if d.hostname == hostname), None)

    def routers(self) -> list[Device]:
        return [d for d in self.devices if d.role == Role.router]


# --------------------------------------------------------------------------- Kafka job
class JobType(str, Enum):
    discover = "discover"  # read-only: show ip interface brief
    deploy = "deploy"      # apply approved config
    verify = "verify"      # read-only: OSPF + reachability checks after all deploys succeed
    reset = "reset"        # approved undeploy: remove data-plane config, keep management access


class JobStatus(str, Enum):
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    SUCCESS = "SUCCESS"
    FAILED = "FAILED"


class ConfigRef(BaseModel):
    model_config = ConfigDict(extra="forbid")
    config_id: str
    sha256: str


class ApprovalRef(BaseModel):
    model_config = ConfigDict(extra="forbid")
    approval_id: str
    approver: str
    approved_at: str
    token: str = Field(description="HMAC-SHA256(APPROVAL_HMAC_SECRET, approval_id|config_id|device|sha256)")


class VerifyExpectation(BaseModel):
    model_config = ConfigDict(extra="forbid")
    process_id: int
    router_id: str
    neighbors: list[str] = Field(description="Router-ids expected in FULL state")
    ospf_prefixes: list[str] = Field(description="Remote CIDRs that must appear as 'O' routes")
    passive_interfaces: list[str] = Field(default_factory=list)
    pings: list[dict] = Field(default_factory=list,
                              description="[{target, source, required}] - required pings gate SUCCESS")


class JobMessage(BaseModel):
    """Message on topic `network-config-jobs` (key = device_id)."""
    model_config = ConfigDict(extra="forbid")
    schema_version: Literal[1] = 1
    job_id: str
    job_type: JobType
    project_id: str
    batch_id: Optional[str] = None
    device_id: str
    config_ref: Optional[ConfigRef] = None      # required for deploy and reset
    approval: Optional[ApprovalRef] = None      # required for deploy and reset
    verification_cmds: list[str] = Field(default_factory=list)
    expect: Optional[VerifyExpectation] = None  # verify jobs only
    created_at: str = Field(default_factory=utcnow)


# --------------------------------------------------------------------------- worker result
class CommandRecord(BaseModel):
    model_config = ConfigDict(extra="forbid")
    command: str
    output: str
    ok: bool = True


class ResultMessage(BaseModel):
    """Message on topic `network-config-results` (key = job_id)."""
    model_config = ConfigDict(extra="forbid")
    schema_version: Literal[1] = 1
    job_id: str
    device_id: str
    job_type: JobType
    status: JobStatus
    final: bool = Field(description="False for progress events, True for the terminal SUCCESS/FAILED event")
    message: str = ""
    error_kind: Optional[Literal["auth", "timeout", "unreachable", "ssh", "command", "approval",
                                 "integrity", "safety", "verification", "internal"]] = None
    applied_lines: list[str] = Field(default_factory=list)
    rolled_back: bool = False
    noop: bool = Field(False, description="True when running-config already matched (idempotent re-run)")
    commands: list[CommandRecord] = Field(default_factory=list)
    verification: Optional[dict] = None
    discovery: Optional[dict] = None
    worker: str = ""
    ts: str = Field(default_factory=utcnow)
