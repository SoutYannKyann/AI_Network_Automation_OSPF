# AI Network Automation System: OSPFv2 Area 0

A web application takes a topology diagram and turns it into working router configs. An image-capable AI model reads the diagram into a validated plan. The system generates Cisco IOS/OSPF configs, and an administrator reviews and approves them. Approved jobs go out over **Apache Kafka** to a **Python Worker**, which deploys them over SSH with **Paramiko**. The worker then checks that the OSPF adjacency is FULL, that each router learns the remote LAN through OSPF, and that the remote LAN answers pings.

Key design rules: jobs go to the Kafka topic `network-config-jobs`, interface names are discovered from the routers rather than read from the diagram, LAN interfaces are passive, the worker re-checks approval with the backend, and static routes are never used. Section 11 explains each choice.

---

## 1. Architecture Overview

**Stack choice:**
- **Backend:** FastAPI. It is async and typed, uses Pydantic for the data contracts, and generates OpenAPI docs.
- **Database:** SQLite. One file, zero setup; enough for a lab, and it can be swapped for Postgres.
- **Frontend:** a single page in plain HTML and JavaScript, served by the API. There is no build step, which makes it easy to demo.
- **Vision model** (`AI_PROVIDER`): Claude (`claude-opus-5-5`) through the Anthropic SDK, Google Gemini (`gemini`, default `gemini-3.8-flash`, REST `generateContent`; on 503/429 it retries, then tries the free-tier backup models in `GEMINI_FALLBACK_MODELS`, default `gemini-3.5-flash-lite,gemini-3.6-flash`, and notes in the flags which model answered), or a local Ollama vision model (`ollama`, default `qwen2.5vl:7b`, no API key). All three use structured JSON-schema output and the same strict validation.

```
 Browser (index.html)
   │ upload PNG/JPG ─ Analyze ─ Discover ─ Generate ─ Review ─ Approve ─ Deploy ─ Monitor
   ▼
 FastAPI (app/api.py) ──────────────► Claude vision model  (reads the image only; never sees creds/routers)
   │  SQLite: projects, configs(sha256), approvals(HMAC), jobs, events, audit
   │
   │ produce (key=device_id, acks=all, idempotent producer)
   ▼
 Kafka topic  network-config-jobs  (3 partitions)          Kafka UI :8080 (evidence)
   │ consumer group network-config-workers, manual commit
   ▼
 Python Worker (worker/main.py → executor.py)
   │ 1. POST /api/internal/jobs/{id}/claim  ← re-checks approval + hash, atomic PENDING→RUNNING
   │ 2. verify HMAC approval token + sha256 + deny-list + "not the management interface"
   │ 3. Paramiko SSH → backup running-config → diff → apply missing lines → post-check
   │    on error: halt → compensating rollback
   │ 4. publish progress/final result
   ▼
 Kafka topic  network-config-results   ── consumer group network-config-api ──► API updates job state
                                                     └─ when all deploys in a batch succeed → verify jobs
```

**Topics**

| Topic | Key | Producer → Consumer | Content |
|---|---|---|---|
| `network-config-jobs` | `device_id` | API → worker group `network-config-workers` | discover / deploy / verify jobs (`schemas/job.schema.json`) |
| `network-config-results` | `job_id` | worker → API group `network-config-api` | RUNNING progress events plus one final SUCCESS/FAILED (`schemas/result.schema.json`) |

**Sequence (happy path)**

1. **Upload.** `POST /api/projects` stores the image.
2. **Extract.** `POST /extract` sends the image to Claude, which returns JSON matching the extraction schema. The response is validated with Pydantic and the plan rules, and every ambiguity is shown as a flag.
3. **Discover.** `POST /discover` sends a read-only `discover` job per router through Kafka. The worker runs `show ip interface brief` and finds the management interface by matching the inventory management IP.
4. **Map.** The admin confirms or edits the suggested logical→physical interface mapping.
5. **Generate.** `POST /generate` renders the Jinja2 templates. Each config gets a sha256.
6. **Review.** `POST /review` checks addressing, subnets, gateways, interface mapping, OSPF settings, the deny-list and SSH reachability (TCP 22).
7. **Approve.** The administrator clicks **Approve** and confirms; an approver name is required. For each router config, an approval record and an HMAC token bound to `approval_id|config_id|device|sha256` are created.
8. **Deploy.** One `deploy` job per router goes to `network-config-jobs`. Each job carries a reference to the config, not the config text.
9. **Execute.** The worker claims the job, fetches the config by reference, re-verifies everything and applies it.
10. **Verify.** When every deploy in the batch has succeeded, the API publishes `verify` jobs. The worker polls `show ip ospf neighbor`, `show ip route ospf` and `show ip protocols` until the checks pass or the timeout expires, then runs the pings.
11. **Monitor.** The UI polls `/api/jobs` and shows PENDING/RUNNING/SUCCESS/FAILED with the router, timestamps, timeline, device output and verification checks.

## 2. Directory Structure

```
AI_Network_Automation_OSPF/
├── app/
│   ├── api.py            # FastAPI endpoints, results consumer, auto-verification trigger
│   ├── bus.py            # Kafka producer/consumer (confluent-kafka); MemoryBus for tests only
│   ├── config.py         # all settings from env vars
│   ├── db.py             # SQLite schema + atomic job claim
│   ├── extractor.py      # Claude vision → Extraction JSON (structured outputs)
│   ├── generator.py      # Jinja2 rendering, OSPF networks/wildcards, verify expectations
│   ├── models.py         # Pydantic data contracts (extraction / job / result)
│   ├── safety.py         # deny-list, redaction, HMAC approval tokens, sha256
│   ├── validation.py     # plan validation rules
│   ├── templates/router_ios.j2, host_vpcs.j2
│   └── static/index.html, app.js, style.css
├── worker/
│   ├── main.py           # Kafka consumer loop + HTTP claim client
│   ├── executor.py       # deploy / discover / verify logic, rollback
│   ├── ssh_executor.py   # Paramiko IOS session, prompt handling, audit log
│   ├── ios_parse.py      # show-output parsers, running-config diff, rollback generator
│   └── simulator.py      # in-process IOS simulator (SIMULATE_DEVICES=1, rehearsal/tests)
├── schemas/              # exported JSON Schemas (scripts/export_schemas.py)
├── samples/              # example diagram, exam_plan.json (example topology), alt_plan.json (alternate addressing)
├── tests/                # 66 pytest tests (generator, validator, parsers, executor, SSH, AI extraction (mocked), API flow)
├── docker-compose.yml    # Kafka (KRaft) + Kafka UI + API + worker
├── Dockerfile  requirements.txt  .env.example  inventory.example.yaml
└── REPORT.md             # short architecture/test report + evidence checklist
```

## 3. Dependencies

`requirements.txt` pins exact versions, the ones the test suite ran with on Python 3.12. To upgrade, change a pin, run `pytest`, then commit.

```
fastapi==0.163.2          uvicorn[standard]==0.54.0   python-multipart==0.0.34
pydantic==2.14.3          Jinja2==3.1.6               PyYAML==6.0.3
httpx==0.28.1             paramiko==3.5.1             confluent-kafka==2.16.1
anthropic==2.10.0         pytest==9.2.0
```

Infrastructure images: `apache/kafka:3.9.0` (KRaft, no ZooKeeper) and `provectuslabs/kafka-ui:v0.7.2`.

## 4. Data Contracts (JSON)

The full JSON Schemas live in [`schemas/`](schemas/) and are generated from [`app/models.py`](app/models.py). Condensed versions follow.

**`extraction`**: topology and addressing plan, produced by the AI and editable by the admin.
```json
{
  "devices": [{ "hostname": "R1", "role": "router|host", "aliases": ["router1"], "router_id": "1.1.1.1|null",
                "interfaces": [{ "id": "R1-L1", "name": "GigabitEthernet0/1|null", "ip": "10.0.0.1",
                                 "mask": "255.255.255.0", "link": "L1" }] }],
  "links": [{ "id": "L1", "subnet": "10.0.0.0/24", "kind": "lan|transit",
              "endpoints": [{ "device": "PC1", "interface": "PC1-L1" }, { "device": "R1", "interface": "R1-L1" }] }],
  "addressing_plan": [{ "device": "PC1", "interface": "PC1-L1", "ip": "10.0.0.10", "mask": "255.255.255.0",
                        "gateway": "10.0.0.1" }],
  "routing": { "protocol": "ospf", "process_id": 1, "area": 0, "passive_lan_interfaces": true },
  "ambiguities": [{ "field": "devices[*].interfaces[*].name", "issue": "no port names in diagram",
                    "suggestion": "map from discovery", "resolved": false }],
  "confidence": 0.9, "source": "ai|manual|sample"
}
```

Validation rules ([`app/validation.py`](app/validation.py)) block approval when any of these fail:
- Every link has exactly 2 endpoints, and those interfaces exist.
- IPv4 addresses and masks are valid, and no interface uses the network or broadcast address.
- Every endpoint is inside its link subnet.
- No IP is used twice, and no subnets overlap.
- The link kind matches the device roles.
- The addressing plan matches the interfaces.
- Each host gateway equals the IP of the router interface on the same link.
- OSPF is area 0, and router-ids are present, valid and unique.
- The mapped physical interface exists on the router, is not the management interface, and is used only once.
- The management IP is not inside a data-plane subnet, and SSH (TCP 22) is reachable.

Unresolved ambiguities and confidence below 0.7 are warnings. The admin must acknowledge warnings before approving.

**`job`**: Kafka message on `network-config-jobs`.
```json
{ "schema_version": 1, "job_id": "9f2c…", "job_type": "deploy|discover|verify", "project_id": "…",
  "batch_id": "…", "device_id": "R1",
  "config_ref": { "config_id": "c41…", "sha256": "e3b0…" },
  "approval":   { "approval_id": "a77…", "approver": "alice", "approved_at": "2026-11-18T10:00:00+00:00",
                  "token": "<HMAC-SHA256>" },
  "verification_cmds": ["show ip ospf neighbor", "show ip route ospf", "show ip protocols", "show ip interface brief"],
  "expect": null,
  "created_at": "…" }
```
A `verify` job carries `expect` and no config:
`{"process_id":1,"router_id":"1.1.1.1","neighbors":["2.2.2.2"],"ospf_prefixes":["10.2.0.0/24"],"passive_interfaces":["GigabitEthernet0/1"],"pings":[{"target":"10.2.0.2","source":"10.0.0.1","required":true},{"target":"10.2.0.10","source":"10.0.0.1","required":false}]}`.

**`result`**: worker output on `network-config-results`.
```json
{ "schema_version": 1, "job_id": "9f2c…", "device_id": "R1", "job_type": "deploy", "status": "RUNNING|SUCCESS|FAILED",
  "final": true, "message": "applied 9 line(s)",
  "error_kind": "auth|timeout|unreachable|ssh|command|approval|integrity|safety|verification|internal|null",
  "applied_lines": ["hostname R1", "interface GigabitEthernet0/1", " ip address 10.0.0.1 255.255.255.0", "…"],
  "rolled_back": false, "noop": false,
  "commands": [{ "command": "show ip interface brief", "output": "…(redacted)…", "ok": true }],
  "verification": { "attempts": 3, "checks": { "neighbors_full": {"ok": true, "expected": ["2.2.2.2"], "actual": […]},
                    "ospf_routes": {…}, "router_id": {…}, "ospf_process": {…}, "passive_interfaces": {…}, "pings": {…} } },
  "discovery": null, "worker": "host-1234", "ts": "…" }
```

## 5. Config Generator

[`app/generator.py`](app/generator.py) builds everything from the validated plan; nothing is tied to the example addressing.
- A `network <net> <wildcard> area 0` line is emitted for each connected subnet.
- A `passive-interface` line is emitted for each LAN interface.
- The transit link uses `ip ospf network point-to-point`. Both sides get it, so there is no DR/BDR election wait and adjacency forms faster.
- The router-id comes from the plan. An optional Loopback0 (`?loopback=true`) is never advertised.
- PCs get GNS3 VPCS syntax for display only. The worker never deploys to PCs.

[`app/templates/router_ios.j2`](app/templates/router_ios.j2):
```jinja
hostname {{ hostname }}
{% for i in interfaces -%}
interface {{ i.name }}
 description {{ i.description }}
 ip address {{ i.ip }} {{ i.mask }}
{% if i.p2p %} ip ospf network point-to-point
{% endif %} no shutdown
!
{% endfor -%}
router ospf {{ process_id }}
 router-id {{ router_id }}
{% for p in passive %} passive-interface {{ p }}
{% endfor %}{% for n in networks %} network {{ n.network }} {{ n.wildcard }} area {{ area }}
{% endfor %}!
end
```

Rendered output for the example topology. The physical names come from discovery; the ones shown are examples.
```
! R1                                        ! R2
hostname R1                                 hostname R2
interface GigabitEthernet0/1                interface GigabitEthernet0/1
 description LAN to PC1 (10.0.0.0/24)        description P2P to R1 (10.1.0.0/24)
 ip address 10.0.0.1 255.255.255.0           ip address 10.1.0.2 255.255.255.0
 no shutdown                                 ip ospf network point-to-point
interface GigabitEthernet0/2                 no shutdown
 description P2P to R2 (10.1.0.0/24)        interface GigabitEthernet0/2
 ip address 10.1.0.1 255.255.255.0           description LAN to PC2 (10.2.0.0/24)
 ip ospf network point-to-point              ip address 10.2.0.2 255.255.255.0
 no shutdown                                 no shutdown
router ospf 1                               router ospf 1
 router-id 1.1.1.1                           router-id 2.2.2.2
 passive-interface GigabitEthernet0/1        passive-interface GigabitEthernet0/2
 network 10.0.0.0 0.0.0.255 area 0           network 10.1.0.0 0.0.0.255 area 0
 network 10.1.0.0 0.0.0.255 area 0           network 10.2.0.0 0.0.0.255 area 0
```
PC1 (VPCS): `ip 10.0.0.10/24 10.0.0.1`. PC2 (VPCS): `ip 10.2.0.10/24 10.2.0.2`.

Each router config also includes these verification commands: `show ip ospf neighbor`, `show ip route ospf`, `show ip protocols` and `show ip interface brief`.

## 6. Python Worker

The worker is [`worker/main.py`](worker/main.py) (consumer), [`worker/executor.py`](worker/executor.py) (logic) and [`worker/ssh_executor.py`](worker/ssh_executor.py) (Paramiko).

- **Delivery semantics:** at-least-once, with idempotent execution.
  - `enable.auto.commit=false`. The offset is committed only after the result has been published and flushed.
  - If the worker crashes, Kafka redelivers the job.
  - If the worker crashes **before** claiming, Kafka redelivers the job and it runs normally.
  - The claim endpoint changes the job from PENDING to RUNNING in one atomic step. A second delivery gets HTTP 409 and is skipped.
  - If the worker crashes **after** claiming, the redelivery is also skipped as a duplicate. After `JOB_LEASE_SECONDS` the API marks the job `FAILED` with "worker lost". The admin then clicks Deploy again; this is safe because of the next point.
  - On the device, the running-config diff makes a re-run a no-op (`noop: true`).
- **Approval gate in the worker.** The worker refuses a deploy job when any of these is true:
  - the backend claim is refused (approval missing or revoked, config superseded, or hash mismatch);
  - the HMAC token is invalid;
  - the config's `sha256` does not match the approved hash;
  - a line matches the deny-list;
  - the management interface cannot be identified. It is taken from `mgmt_interface` in the inventory, or else from the interface that holds the management IP, found live;
  - the config contains an `interface` block for the management interface.
- **Paramiko.** The worker opens an interactive shell and waits for the prompt (`>`, `#`, `(config…)#`).
  - It enters enable mode using the secret from an environment variable, then runs `terminal length 0`.
  - Every command and its output is written to the audit log after redaction.
  - Connection errors are classified as `auth`, `timeout`, `unreachable` or `ssh`.
  - Old GNS3 IOS images can be supported with `SSH_LEGACY_ALGORITHMS`. Host-key checking is set with `SSH_HOST_KEY_POLICY`.
  - Paramiko is pinned to 3.5.1 on purpose: paramiko 4+ removed SHA-1 key exchange and `ssh-rsa` host keys, which are the only ones c7200 IOS 15.x offers.
- **Apply strategy.** The worker:
  1. backs up the `show running-config` output to `BACKUP_DIR` (redacted);
  2. diffs it against the approved config (`ios_parse.diff_config`). The diff first emits cleanup lines:
     - `no ip address` on any non-management interface whose address is inside a plan subnet but is not the planned address there;
     - `no network` and `no passive-interface` for OSPF lines the plan no longer contains.

     This lets a corrected interface mapping or a changed topology be redeployed with no manual router CLI.
  3. runs `configure terminal` and sends the cleanup and missing lines one at a time;
  4. checks each line's output for `% Invalid`, `% Incomplete`, `% Ambiguous`, `overlaps with` and similar errors.
- **Failure strategy: halt, then roll back.** On the first failing line, the worker:
  1. stops sending lines;
  2. sends `end`;
  3. applies compensating commands for the lines it already applied, in reverse order (`rollback_lines`). Old IP addresses, descriptions and the old hostname are restored, an OSPF process that the job created is removed, and `no shutdown` is reverted only where the interface was shut before;
  4. reports `FAILED` with `rolled_back: true`.

  After applying, the worker diffs again; any line still missing also counts as a failure. The management interface is never part of the change set, so a rollback cannot cut SSH access. The backup file is the manual recovery point.
- **Verification job.** The worker polls every `VERIFY_INTERVAL` seconds, up to `VERIFY_TIMEOUT`, until all of these hold:
  - the OSPF process and router-id are correct;
  - each expected neighbor is `FULL`;
  - each remote LAN appears as an `O` route;
  - the passive interfaces are correct.

  It then pings the remote router's LAN interface from its own LAN interface (required). It also pings the remote PC (reported, but not required, because the PC must be up for it to answer).

Core loop, condensed:
```python
claim = claim_fn(job)                               # HTTP: approval re-check + atomic claim (409 → skip duplicate)
assert verify_approval_token(...) and sha256(text) == job.config_ref.sha256 and not denied_lines(text)
with IOSSession(...) as s:                          # Paramiko; errors → DeviceError(kind)
    mgmt_if = iface_with_ip(s.send("show ip interface brief"), mgmt_ip); refuse if config touches it
    running = s.send("show running-config"); backup(running)
    todo = diff_config(text, running)               # [] → idempotent no-op
    s.send("configure terminal")
    for line in todo:
        out = s.send(line); audit(line, out)
        if find_error(out): s.send("end"); rollback(applied); publish(FAILED); return
        applied.append(line)
    s.send("end"); assert diff_config(text, s.send("show running-config")) == []
publish(SUCCESS)                                    # then the Kafka offset is committed
```

## 7. API & Web UI

| Method & path | Purpose | Auth |
|---|---|---|
| `POST /api/projects` (multipart `file`, `notes`) | upload a PNG/JPG (≤10 MB) | – |
| `GET /api/projects/{id}` | project state: extraction, discovery, configs, validation | – |
| `POST /api/projects/{id}/extract` | AI diagram analysis | – |
| `PUT /api/projects/{id}/extraction` | admin correction or manual JSON (fallback) | – |
| `POST /api/projects/{id}/ambiguities/resolve` | mark a flag resolved | – |
| `POST /api/projects/{id}/discover` | read-only interface discovery via Kafka | admin |
| `POST /api/projects/{id}/mapping/suggest` / `PUT …/mapping` | suggest or confirm the interface mapping | – |
| `POST /api/projects/{id}/generate` | generate configs (supersedes old configs, revokes their approvals) | – |
| `POST /api/projects/{id}/review` | run validation and the reachability check | – |
| `POST /api/projects/{id}/approve` `{approver, acknowledge_warnings}` | explicit approval, bound to the config hash | admin |
| `POST /api/projects/{id}/deploy` | publish deploy jobs to `network-config-jobs` | admin |
| `GET /api/jobs?project_id=` / `GET /api/jobs/{id}` | status, timestamps, timeline, output, verification | – |
| `GET /api/audit?project_id=` | audit trail | – |
| `POST /api/internal/jobs/{id}/claim` | worker approval re-check and atomic claim | worker token |
| `GET /api/health`, `GET /api/inventory` | health; inventory without secrets | – |

The UI is a single page at `http://localhost:8000` and follows the workflow in order:
1. **Upload** and preview the diagram.
2. **Analyze with AI.** The editable JSON appears beside a list of flags; each flag has a "Mark resolved" button.
3. **Discover interfaces**, then **Suggest mapping**. Adjust the dropdowns, enter the OSPF router ID for each router (the diagram doesn't show them), and click **Confirm mapping**.
4. **Generate**, then **Review**. The review shows VALID or BLOCKED with every issue.
5. **Approve.** This needs an explicit click plus confirmation, an approver name, and the "acknowledge warnings" tick when warnings exist.
6. **Deploy.**

A job table refreshes every 2 seconds and shows status badges (PENDING, RUNNING, SUCCESS, FAILED), the router, and created, started and finished times. Clicking a job opens its details: the timeline, the applied lines, the Kafka message (approval token truncated), the device output and the verification check cards.

## 8. Verification Plan

The worker runs these checks automatically. The commands below are for the live demonstration and evidence screenshots.

1. **OSPF adjacency.** Run on both R1 and R2:
   ```
   R1# show ip ospf neighbor
   Neighbor ID     Pri   State      Dead Time   Address      Interface
   2.2.2.2           0   FULL/  -   00:00:36    10.1.0.2     GigabitEthernet0/2
   ```
   Pass: R1 sees 2.2.2.2 as FULL, and R2 sees 1.1.1.1 as FULL.
2. **Remote LAN learned through OSPF.**
   ```
   R1# show ip route ospf      →  O  10.2.0.0/24 [110/2] via 10.1.0.2, …
   R2# show ip route ospf      →  O  10.0.0.0/24 [110/2] via 10.1.0.1, …
   ```
3. **Protocol settings.** `show ip protocols` should show `Routing Protocol is "ospf 1"`, `Router ID 1.1.1.1` (or 2.2.2.2), all three networks under "Routing for Networks", and the LAN interface under "Passive Interface(s)".
4. **No static routes.** `show running-config | include ^ip route` must return nothing.
5. **Router-level data plane.** Automated: `R1# ping 10.2.0.2 source 10.0.0.1` and `R2# ping 10.0.0.1 source 10.2.0.2` must succeed.
6. **End to end, which is the acceptance test.** On the VPCS hosts:
   ```
   PC1> show ip            → 10.0.0.10/24, gateway 10.0.0.1
   PC1> ping 10.2.0.10     → 84 bytes from 10.2.0.10 icmp_seq=1 ttl=62 …
   PC2> ping 10.0.0.10     → replies (reverse path)
   PC1> trace 10.2.0.10    → 10.0.0.1 → 10.1.0.2 → 10.2.0.10
   ```
   TTL 62 shows two router hops, so the traffic is routed by R1 and R2 as intended.
7. **Kafka evidence.** In Kafka UI at `http://localhost:8080`, go to Topics → `network-config-jobs` → Messages. You will see one deploy message per router and then the verify messages. The `network-config-results` topic shows RUNNING events followed by SUCCESS.

## 9. Safety & Compliance Notes

- **Secrets:**
  - All secrets live in `.env`, which is git-ignored; `.env.example` holds placeholders only.
  - SSH credentials are read only by the worker, through the variable names given in `inventory.yaml`. The API never has them.
  - The Anthropic key is read only by the API.
  - `WORKER_TOKEN` and `APPROVAL_HMAC_SECRET` should be random 32-byte hex strings. The inventory loader also drops any literal `password` or `secret` key.
- **Redaction:** `safety.redact()` runs on everything that is logged, published to Kafka or shown in the UI. It removes:
  - the value of any environment variable whose name contains PASSWORD, SECRET, TOKEN or API_KEY;
  - values after `password`, `secret`, `key` and `snmp-server community`;
  - `sk-ant-…` keys.

  The approval token is truncated in the stored Kafka message.
- **Approval gating:**
  - Approval is an explicit administrator action: the **Approve** button, a confirmation dialog and the approver's name, recorded in the audit log.
  - Approval re-runs validation and needs warnings acknowledged.
  - The approval is HMAC-bound to the exact config hash.
  - Regenerating or editing the plan revokes existing approvals.
  - Deploy requires every router config to be approved.
  - The worker re-checks the approval with the backend (claim) and checks the HMAC and hash again itself.
- **Disruptive commands:** blocked at Review and again in the worker. The blocked list:
  - `reload`, `erase`, `write erase`, `delete`, `format`, `boot`, `clear`, `configure replace`;
  - `username`, `enable secret`, `ip ssh`, `line vty|con|aux`, `aaa`, `transport input`, `access-class`, `crypto key`;
  - `ip route`, which enforces the rule that OSPF, not static routes, connects the LANs.

  There is deliberately no path that applies them. Read-only jobs (discover, verify) can only run `show`, `ping` and `terminal`.
- **Management plane:** the management interface is excluded at three points: mapping, validation and the worker guard. It is found live by its IP, or set explicitly with `mgmt_interface` in `inventory.yaml` when SSH arrives through NAT or a console server. If it cannot be identified, approval is blocked (`MGMT_IFACE_UNKNOWN`) and the worker refuses to deploy. An interface whose current IP is outside every plan subnet is never suggested for the mapping, and mapping it raises a `FOREIGN_IP` warning.
- **Audit:** the worker writes `audit.jsonl` with one record per command and output, plus job id, device and timestamp. The API keeps an `audit` table covering upload, extraction, approve, revoke, deploy, claim and job results. Running-config backups are kept for each job.
- **Least privilege:** use a dedicated SSH user for automation, privilege 15 or an enable secret that is provisioned out of band. `SSH_HOST_KEY_POLICY=reject` with a pinned `SSH_KNOWN_HOSTS` is recommended outside the lab.
- **AI boundary:** the model receives only the image and the admin notes. It cannot execute anything, and its output is untrusted until it passes validation and human approval.

## 10. Run/Deploy Instructions

**Prerequisites:**
- Docker Desktop or Docker Engine with Compose v2.
- GNS3, with R1 and R2 reachable for SSH on their management IPs, so the hosts running the worker can reach them (see *GNS3 lab setup* below).
- An image-capable AI model: an Anthropic API key (`AI_PROVIDER=anthropic`), a Gemini API key (`AI_PROVIDER=gemini`, `GEMINI_API_KEY`), or Ollama on the host with a vision model (`AI_PROVIDER=ollama`, then `ollama pull qwen2.5vl:7b`; no key needed).

```bash
cp .env.example .env
```
Fill in `AI_PROVIDER` (and `ANTHROPIC_API_KEY` if you use Claude), the two random secrets (`WORKER_TOKEN`, `APPROVAL_HMAC_SECRET`) and `SSH_USERNAME`, `SSH_PASSWORD` and `SSH_ENABLE_SECRET`. For c7200 routers also set `SSH_LEGACY_ALGORITHMS=true`. Then create the inventory:
```bash
cp inventory.example.yaml inventory.yaml
```
Set the management IP of R1 and R2. Start the stack:
```bash
docker compose up -d --build
```
- UI: http://localhost:8000
- Kafka UI: http://localhost:8080
- API docs: http://localhost:8000/docs

Follow the worker logs while you run the demo:
```bash
docker compose logs -f worker
```

If the worker container cannot reach the GNS3 management network, run the worker on the host instead (Kafka is published on `localhost:29092`). Stop the container first:
```bash
docker compose stop worker
```
Then create a virtual environment, install the requirements and start the worker. Set `API_BASE_URL=http://localhost:8000` and load the `.env` values into the shell before starting it.
```bash
python -m venv .venv && .venv/Scripts/pip install -r requirements.txt
```
```bash
.venv/Scripts/python -m worker.main
```

**GNS3 lab setup (c7200 / Dynamips inside the GNS3 VM, management on VMnet1 192.168.239.0/24):**

This is one-time lab preparation: it gives the routers management SSH access that is independent of the data plane. It is not part of the automated workflow.

0. **GNS3 VM (VMware Workstation).** Its first adapter is host-only (VMnet1), so the VM is at 192.168.239.x (here .128) and Windows sits at 192.168.239.1.
   - Windows hosts running Docker Desktop (WSL2) or VBS run Windows' hypervisor, and VMware then cannot offer nested VT-x. Set `vhv.enable = "FALSE"` in `GNS3 VM.vmx` while the VM is off and VMware is closed. GNS3 2.2 only adds `vhv.enable = "TRUE"` when the line is missing, so an explicit `FALSE` is kept. Do not toggle *Virtualize Intel VT-x* in VMware's VM settings afterwards: that deletes the line. Dynamips c7200 does not need nested VT-x.
   - GNS3: *Preferences > VMware*, vmrun path `C:\Program Files\VMware\VMware Workstation\vmrun.exe`; *Preferences > GNS3 VM*, enabled, VMware, VM name `GNS3 VM`. *Preferences > Server*, UDP tunnelling range `30000-40000` (NVIDIA services occupy ports around 10010-10012 on some laptops and break links).
1. Add a c7200 template that **runs on the GNS3 VM** (IOS 15.x image). Slot 0: `C7200-IO-2FE`, slot 1: `PA-FE-TX`. Each router then has `FastEthernet0/0` (management), `FastEthernet0/1` and `FastEthernet1/0`.
2. Build the topology with **every node on the GNS3 VM**:
   - `Cloud` node on the GNS3 VM bound to **eth0** (the VM's VMnet1 adapter), connected to an Ethernet switch. Do not use a Cloud on the local PC bound to a Windows VMware adapter: Npcap injects the routers' replies onto the vmnet, not into Windows' own network stack, so Windows never reaches the routers.
   - R1 Fa0/0 and R2 Fa0/0 to that switch (management only).
   - PC1 (VPCS) to R1 Fa0/1, R1 Fa1/0 to R2 Fa0/1, R2 Fa1/0 to PC2 (VPCS). With this cabling, **Suggest mapping** proposes the right interfaces; still confirm them.
3. On each router console, paste the management bootstrap (R2: hostname `R2`, IP `192.168.239.12`). Use your own username and passwords, and put the same values in `.env`:
   ```
   enable
   configure terminal
   hostname R1
   no ip domain-lookup
   ip domain-name lab.local
   username <SSH_USERNAME> privilege 15 secret <SSH_PASSWORD>
   enable secret <SSH_ENABLE_SECRET>
   interface FastEthernet0/0
    description MGMT - do not touch
    ip address 192.168.239.11 255.255.255.0
    no shutdown
   exit
   crypto key generate rsa modulus 2048
   ip ssh version 2
   line vty 0 4
    transport input ssh
    login local
   end
   write memory
   ```
4. Set the PCs (VPCS console): PC1 `ip 10.0.0.10/24 10.0.0.1` then `save`; PC2 `ip 10.2.0.10/24 10.2.0.2` then `save`.
5. Check from Windows: `ping 192.168.239.11` and `.12`, then `ssh -o KexAlgorithms=+diffie-hellman-group14-sha1 -o HostKeyAlgorithms=+ssh-rsa <user>@192.168.239.11`. The c7200 (IOS 15.2(4)S6) offers `SSH-2.0-Cisco-1.25` with an `ssh-rsa` host key, `aes128-cbc` and `hmac-sha1`. Then run **Discover** from the UI as the first real test; it is read-only.

**Walkthrough:**
1. Start from clean routers (use **Undeploy** if they were configured before). Management access stays in place.
2. Open the UI at http://localhost:8000.
3. **Step 1:** choose the diagram (it previews). In the notes, add any requirement the image lacks, for example: `OSPF process 1 area 0; R1 router-id 1.1.1.1; R2 router-id 2.2.2.2; LAN interfaces passive`. Click **Generate plan**. The status line next to the button shows each automatic stage:
   - upload;
   - AI analysis;
   - read-only interface discovery on R1/R2 through Kafka → worker → Paramiko;
   - mapping to the real interface names;
   - config generation;
   - validation.

   If a stage needs input (AI failure, missing router ID, cabling that differs from the suggestion), a popup says so and the *Advanced* section lets you edit the JSON or the mapping. Then click **Generate plan** again; it keeps the edits.
   If the diagram and notes give no router IDs, a popup asks you to confirm them. It suggests R*n* → n.n.n.n; the AI flags them rather than guessing.
4. **Step 2:** show the interface plan, the AI flags (mark them resolved if you like; this keeps the configs) and the R1/R2 configs. **Review** re-runs the checks (it should show VALID). Enter the approver, tick *I have reviewed…*, and click **Approve**. Approval is the last human step: deployment to Kafka starts automatically, and failures open a popup with the reason.
5. The full extraction JSON is under *Advanced*.
6. **Step 3:** deployment is already running (the **Deploy** button re-deploys). The job table shows local times and durations; a verify job's **details** show the OSPF neighbour (FULL), OSPF route, protocol and ping tables.

   **Undeploy (reset R1/R2)** returns the routers to their clean starting state, so the full workflow can be rerun:
   - The admin enters a name and confirms. One HMAC-signed approval per router is bound to the fixed reset specification (`generator.reset_spec`).
   - `reset` jobs go through Kafka, and the worker re-checks the approval in its claim.
   - On every non-management interface the worker removes the IP address, description and `ip ospf` lines, then shuts the interface. It also removes `router ospf` and any Loopbacks. The management interface, hostname, users, SSH and vty are never touched.
   - A running-config backup is saved first, and a post-check confirms nothing data-plane remains.
   - **Deploy** (same approval) brings the configuration back.

   **New Session** (header) clears the page for a fresh diagram; old projects stay saved.

   **Branding:** the default look is neutral. `UI_WATERMARK` in `.env` adds a text next to the status dot, and `UI_SCHOOL_BRANDING=true` shows a university logo and name in the header.

   **Approvers:** `APPROVERS` in `.env` is a comma-separated list, e.g. `APPROVERS=Alice,Bob`. When it's set, the approver fields become a drop-down, and the API rejects any other name for Approve and Undeploy (HTTP 403); matching ignores case, and the canonical name is stored in the audit log. Apply a change with `docker compose up -d api`. An empty list accepts any name.

   The **Deploy** button stays disabled until the plan is approved, because approval deploys automatically. After that it reads **Deploy again** and re-sends the same approved configuration. Watch R1 and R2 move from PENDING to RUNNING to SUCCESS, then the two verify jobs reach SUCCESS. Open the verify job to show FULL adjacency, the O routes and the pings.
7. Show Kafka UI with the topic messages, then run `ping 10.2.0.10` from PC1.

**Rehearsal without GNS3:** set `SIMULATE_DEVICES=true` and run the same stack. The worker then uses the built-in IOS simulator.

**UI rehearsal without Docker or Kafka (dev only):** set `BUS_BACKEND=memory`, `INPROCESS_WORKER=1` and `SIMULATE_DEVICES=1`, plus `WORKER_TOKEN` and `APPROVAL_HMAC_SECRET`, then start the API alone. The real worker code runs inside the API process on an in-memory bus. The `api-ui-preview` entry in `.claude/launch.json` does exactly this. Never use this mode for a real deployment, which must go through Kafka.

**Tests:**
```bash
pip install -r requirements.txt && python -m pytest -q
```
Expect 66 passing tests. Kafka is replaced by an in-memory bus only inside the tests.

## 11. Assumptions

- **Messaging and approval contract:**
  - The topic is `network-config-jobs`, not `deploy-jobs`, and results go to `network-config-results`.
  - Jobs carry a config reference (id plus sha256) rather than the config text.
  - The worker re-checks approval with the backend.
  - The PENDING, RUNNING, SUCCESS and FAILED states are exactly as listed.
- **Addressing:** from the diagram. The example topology uses:
  - PC1 10.0.0.10/24, gateway 10.0.0.1.
  - R1 10.0.0.1/24 (LAN) and 10.1.0.1/24 (transit).
  - R2 10.1.0.2/24 (transit) and 10.2.0.2/24 (LAN).
  - PC2 10.2.0.10/24, gateway 10.2.0.2.
  - OSPF process 1, area 0, router-ids 1.1.1.1 and 2.2.2.2.

  The diagram does not show router-ids. They come from the admin notes or are flagged.
- **Router-id:** set with the `router-id` command, not a loopback. A loopback would add an extra /32 the plan does not need. A loopback is optional (`?loopback=true`) and is never advertised.
- **Interface names:** the diagram does not show them. They come from `show ip interface brief` on each router. The suggested mapping takes free data interfaces in order and is always flagged for the admin to confirm against the GNS3 cabling.
- **Management:** each router has an out-of-band management IP, listed in `inventory.yaml` and outside every data-plane subnet. Its interface already holds that IP and is never touched. SSH, user accounts and enable access are pre-provisioned (see *GNS3 lab setup*).
- **PCs:** assumed to be GNS3 VPCS with no SSH, addressed beforehand. Their configs are generated for display and evidence only. If they are IOS devices, the template shows the equivalent commands.
- **Transit link:** `ip ospf network point-to-point` is used on the R1–R2 link for faster adjacency (no DR election). Adjacency is still FULL.
- **Saving config:** the config is not saved to startup unless `SAVE_CONFIG=true`. Undeploy resets the routers anyway.
- **Platform:** single-node Kafka, replication factor 1, SQLite and one worker instance are enough for a lab. More workers can join the same consumer group; the claim endpoint prevents double execution.

## 12. Self-Check

- [x] **Extraction schema is complete and validated.**
  - Schema: [`schemas/extraction.schema.json`](schemas/extraction.schema.json).
  - Rules: two endpoints per link, IPv4 and mask validity, subnet membership, duplicate IPs and overlaps, gateway equals the attached router IP, router-ids, interface mapping and management. Ambiguities are surfaced and must be resolved or acknowledged.
  - Tested in `tests/test_generator_validation.py`.
- [x] **R1/R2 configs are valid IOS with OSPFv2 area 0 for all three /24 networks.**
  - The configs include `router ospf 1`, `router-id`, `network … area 0` lines, passive LAN interfaces and `no shutdown`, with no static routes.
  - The alternate-addressing plan proves nothing is hardcoded.
- [x] **Kafka topics, messages and worker flow are defined with approval gating and idempotency.**
  - Approval is enforced by the HMAC token, the hash binding, the backend claim (409 on duplicates) and the running-config diff, which makes re-runs no-ops.
  - Offsets are committed manually, giving at-least-once delivery.
- [x] **Paramiko executor:** classifies auth, timeout, unreachable and ssh errors, captures output per command, writes the audit JSONL, backs up the config first, halts on the first error and rolls back, and checks the result afterwards. Tested against a fake channel and the simulator.
- [x] **Secrets are externalized and redacted.** `.env` and `inventory.yaml` hold variable names only, the API never holds SSH credentials, and `redact()` covers logs, Kafka, the UI and the audit trail.
- [x] **Verification proves PC1→PC2:**
  - automated FULL neighbor, `O` routes for the remote LANs, `show ip protocols` and router-sourced pings;
  - the manual `PC1> ping 10.2.0.10` acceptance step in section 8.
- [x] **Assumptions are stated** in section 11.
- [x] **Verified on a real lab:** Docker with a live Kafka broker, GNS3 c7200 routers (IOS 15.2(4)S6) and live Gemini calls. Discover, deploy, OSPF verification (FULL adjacency, remote LANs learned via OSPF, pings) and PC1 → PC2 ping all succeeded. The Claude and Ollama providers are tested against mocked clients only.
