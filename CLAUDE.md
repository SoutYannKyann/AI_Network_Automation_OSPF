# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

A student lab-exam project (spec: `AI_Network_Automation_OSPF_Student_Lab_Exam.docx`). A web app takes a topology diagram, uses Claude vision to extract a plan, and generates Cisco IOS OSPFv2 area 0 configs for R1/R2. After admin approval it deploys them via Kafka → Python worker → Paramiko SSH, then verifies PC1 can reach PC2.

**When the exam sheet and other instructions disagree, the exam sheet wins.** Some exam rules are easy to break by accident:
- The jobs topic is `network-config-jobs`.
- Jobs carry a config *reference*: config_id plus sha256.
- The worker re-checks approval with the backend.
- Physical interface names come from the routers, not the diagram.
- LAN interfaces are passive.
- No static routes.
- The AI never touches routers.
- The instructor may swap in a different topology, so nothing may be hardcoded to the 10.x plan.

## Commands

On Windows, use the project venv at `.venv`, and set `PYTHONUTF8=1` because the console is cp1252 and output contains non-ASCII characters.

```bash
PYTHONUTF8=1 .venv/Scripts/python.exe -m pytest -q                                   # full suite (65 tests)
PYTHONUTF8=1 .venv/Scripts/python.exe -m pytest -q tests/test_executor.py::test_command_error_halts_and_rolls_back   # one test
.venv/Scripts/python.exe scripts/export_schemas.py        # regenerate schemas/*.json after changing app/models.py
.venv/Scripts/python.exe -m uvicorn app.api:app --port 8000   # API + UI
.venv/Scripts/python.exe -m worker.main                     # worker (needs Kafka, WORKER_TOKEN, APPROVAL_HMAC_SECRET)
docker compose up -d --build                                # Kafka (KRaft) + Kafka UI :8080 + api :8000 + worker
```

There is no linter configured. `.claude/launch.json` runs the API with `BUS_BACKEND=memory`, `SIMULATE_DEVICES=1` and `INPROCESS_WORKER=1` (on port 8000, or 8001 for a second copy). In that mode `api._inprocess_worker` runs the real `Executor` inside the API process, claiming through `_claim_core`, so the whole UI flow works without Kafka. The setup is dev-only; the graded path is always Kafka plus `worker.main`.

## Architecture (cross-file flow)

**Pipeline**
1. UI (`app/static/app.js`) calls API (`app/api.py`).
2. The API extracts (`app/extractor.py`), validates (`app/validation.py`) and generates configs (`app/generator.py` + `app/templates/*.j2`).
3. Approval records an HMAC (`app/safety.py`) over `approval_id|config_id|device|sha256`.
4. The API publishes `JobMessage` (`app/models.py`) to `network-config-jobs`, keyed by device.
5. The worker (`worker/main.py` → `worker/executor.py`) consumes it.
6. The worker POSTs `/api/internal/jobs/{id}/claim`. The API re-checks approval and the hash, then atomically sets PENDING→RUNNING. A 409 means a duplicate, and the worker skips it.
7. The worker connects over SSH (`worker/ssh_executor.py`) and publishes `ResultMessage` to `network-config-results`.
8. The API's background consumer (`handle_result`) updates SQLite.

When every deploy job in a `batch_id` succeeds, `_maybe_start_verification` publishes `verify` jobs. Verification must run only after *both* routers are configured.

**Job types:** `discover`, `deploy`, `verify` and `reset`.
- `reset` (Undeploy, `POST /api/projects/{pid}/undeploy`) is approved like a deploy: an HMAC token per router over `approval_id|reset:<dev>:<aid>|device|sha256(reset_spec(dev))`, re-checked in `_claim_core`. The worker's `_reset` computes `ios_parse.reset_lines(running, {mgmt_if})`, applies it, halts without rollback on error and post-checks. It never triggers verification.
- `discover` and `verify` are read-only. `_run(..., read_only=True)` allows only `show`, `ping` and `terminal`.
- Discovery results are stored in `projects.discovery`. They feed interface mapping, validation and the management-interface exclusion.

**Logical vs physical interfaces**
- The extraction uses logical interface ids such as `R1-L1`, with `name: null`.
- After discovery, `mapping/suggest` or `PUT mapping` fills in `name`.
- `generate` refuses while any router interface is unmapped.
- Diagrams usually carry no router IDs, so the AI leaves `router_id` null, which validation reports as `NO_ROUTER_ID`. The admin supplies the IDs in one of two ways: in the notes before Analyze, or in the router-ID inputs, which are sent as `router_ids` with `PUT mapping`. That call also marks the related ambiguities as resolved.
- `GET /api/projects/{id}` returns `issues`, which are the plan checks run with inventory and discovery. Always validate with that full context; a bare `validate_plan(ex)` reports false `NOT_IN_INVENTORY` errors.

**Deploy semantics** (`worker/ios_parse.py`)
- `diff_config(desired, running, protected)` emits cleanup lines first:
  - `no ip address` on conflicting non-management interfaces;
  - stale `network` and `passive-interface` lines.
- It then emits only the missing lines. An empty diff means an idempotent no-op.
- On the first IOS error the worker halts and `rollback_lines` applies compensating commands in reverse, restoring old addresses and hostname and removing a newly created OSPF process.
- A post-apply diff must be empty.

**Management-interface protection**
- The management interface is `inventory.yaml` `mgmt_interface` if set, else the interface holding `mgmt_ip` (`find_mgmt_interface`).
- It is enforced in three places: mapping suggestion, validation (`MGMT_IFACE`, `MGMT_IFACE_UNKNOWN`) and the worker guard.
- Deploys are refused if it can't be identified. Keep all three in sync.

**UI flow** (`app/static/app.js`): three steps. **Generate plan** chains the existing endpoints client-side: upload → `extract` (skipped if an extraction exists) → `discover` and wait for the jobs → `mapping/suggest` → `PUT mapping` (with the router IDs) → `generate` → `review`. Progress shows as one coloured status line next to the button (`status()` / `step()`). It stops with a popup (`showError`) when input is needed, or asks for missing router IDs in `#ridDialog`. While the AI runs it polls `GET /api/projects/{pid}/progress`, which is fed by the extractor's `progress` callback. Step 2 is Review + Approve (approver name plus a "reviewed" tick, which maps to `acknowledge_warnings`); Approve then calls `deploy` automatically. Step 3 is Deploy (re-deploy), Undeploy (`#undDialog`), the jobs table (local times and durations) and `renderEvidence()` tables for verify jobs. `renderFinal()` draws the banner for the latest deploy or reset batch. **New run** clears the page. Job details expand inline under their row (`renderJobs()`, `openDetails`). `updateDeployButton()` keeps Deploy disabled until the configs are approved, then labels it "Deploy again". `APPROVERS` (Settings.approvers) is enforced by `_authorised_approver()` on approve and undeploy, and turns the approver inputs into selects through `GET /api/approvers`. The theme comes from `<html data-theme>`, toggled by `#btnTheme` and saved in localStorage. The page and `/static` are served `Cache-Control: no-cache`; bump `?v=` in index.html when changing JS or CSS. Manual JSON and mapping editing lives in the collapsed *Advanced* section. There is no admin token.

**Invalidation**
- Any extraction or mapping change calls `_store_extraction`, which calls `_supersede`. Old configs are marked superseded and their approvals revoked.
- Exception: `ambiguities/resolve` only flips the flag and clears `validation`. A flag changes no config value, so configs and approvals stay valid.
- RUNNING jobs older than `JOB_LEASE_SECONDS` are marked FAILED ("worker lost") by `_expire_lost_jobs`.

**Settings**
- All settings come from env vars via `app/config.py` (`Settings` is a frozen dataclass read at construction).
- SSH credentials are referenced by env-var *name* in `inventory.yaml`. Only the worker reads them.
- `safety.redact()` must wrap anything logged, published or returned to the UI.
- `safety.DENY_PATTERNS` is checked at Review, before dispatch, and again in the worker.

## Testing approach

- `BUS_BACKEND=memory` (`app.bus.MemoryBus`) and `SIMULATE_DEVICES=1` (`worker/simulator.py`, a small in-process IOS model with OSPF adjacency, routes, ping and overlap errors) exist so the whole flow is testable without Docker or GNS3.
- `tests/test_api_flow.py::pump` plays the role of the Kafka consumer and worker against the real FastAPI app.
- The simulator registry is global; call `reset_simulation()` between tests.
- Lines containing `INVALID` make the simulator return `% Invalid input`, which is used to test rollback.
- The Anthropic client is mocked in `tests/test_extractor.py`.
- Samples: `samples/exam_plan.json` (exam topology) and `samples/alt_plan.json` (different addressing, used to prove nothing is hardcoded).

**Never exercised here:** live Kafka, real GNS3 routers and a real Claude API call. Prompt detection and legacy-SSH settings (`SSH_LEGACY_ALGORITHMS`, `SSH_HOST_KEY_POLICY`) in `ssh_executor.py` are verified only against a fake channel.

## Claude API usage

`app/extractor.py` calls the Claude API with:
- `client.beta.messages.create`;
- model `claude-opus-5-5`, overridable with `ANTHROPIC_MODEL`;
- `output_config.format` json_schema (`LLM_SCHEMA`) and `output_config.effort`;
- `betas=["server-side-fallback-2026-07-01"]` and `fallbacks="default"`.

Opus 5.5 rejects `thinking: {type: "disabled"}`, `budget_tokens`, prefill and forced `tool_choice`. The response's physical interface names are never trusted; they are flagged as ambiguities.

`AI_PROVIDER=ollama` switches to a local vision model instead (`_call_ollama`: Ollama `/api/chat` with `format=LLM_SCHEMA`, `OLLAMA_URL`, `OLLAMA_MODEL` default `qwen2.5vl:7b`). `AI_PROVIDER=gemini` calls Gemini REST `generateContent` (`_call_gemini`: key in the `x-goog-api-key` header, never the URL; `generationConfig.responseJsonSchema=LLM_SCHEMA`; `GEMINI_MODEL` default `gemini-3.8-flash`). On 429/5xx/timeouts `_call_gemini` retries (`GEMINI_RETRIES`, default 2), then tries `GEMINI_FALLBACK_MODELS` (free-tier only, default `gemini-3.5-flash-lite,gemini-3.6-flash`); 404 skips to the next model, 401/403 fail at once. A backup answer adds a resolved `extraction.model` ambiguity naming the model. Google's docs also show a newer Interactions API; this project uses `generateContent`. All providers feed the same `_finish` post-processing; any malformed output becomes `ExtractionError` (HTTP 502), never a 500.

## Real lab constraints

- The user's lab is GNS3 c7200 (Dynamips) with every node on the GNS3 VM (192.168.239.128) and the management Cloud bound to the VM's eth0 (VMnet1, 192.168.239.0/24); R1/R2 are .11/.12. See README "GNS3 lab setup". A Cloud on the local PC bound to a Windows VMware adapter does not work (Windows never receives the replies).
- Docker Desktop (WSL2) keeps Windows' hypervisor on, so the GNS3 VM must have `vhv.enable = "FALSE"` in its .vmx. GNS3 only adds TRUE when the line is missing; toggling VT-x in VMware's settings deletes it.
- Paramiko is pinned to 3.5.1: paramiko 4+/5+ removed SHA-1 KEX and `ssh-rsa` host keys, the only ones c7200 IOS 15.x offers. Don't bump it without checking against the routers.
