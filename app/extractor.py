"""Diagram -> Extraction JSON using an image-capable AI model with structured (JSON-schema) output.

Providers (AI_PROVIDER): "anthropic" = Claude API; "gemini" = Google Gemini API;
"ollama" = a local vision model (no API key).
The AI only *reads* the diagram. It never sees credentials and never talks to routers.
"""
from __future__ import annotations

import base64
import json
import logging
import time

from .config import Settings
from .models import Ambiguity, Extraction

log = logging.getLogger("extractor")

SYSTEM = """You are a network engineer reading a lab topology diagram. Extract devices, links,
interface IPs, subnets, default gateways and routing requirements into the JSON schema.

Rules:
- Report only what the diagram (or the admin's notes) actually states. Never invent values.
- Diagrams usually show host octets like '.1' next to a link labelled with a subnet such as
  10.0.0.0/24: combine them into a full address (10.0.0.1) and the subnet mask (255.255.255.0).
- Physical interface names (GigabitEthernet0/0 ...) are normally NOT in the diagram: set "name"
  to null - they are mapped later from the real routers. Do not guess them.
- Give every interface a logical id '<hostname>-<link id>' and every link an id (L1, L2, ...).
- kind = "lan" for router-to-host links, "transit" for router-to-router links.
- Hosts get gateway = the IP of the router interface on the same link.
- Use the short device name as hostname (R1, R2, PC1, PC2) and put other labels
  (e.g. 'router1') in aliases.
- router_id: only if stated in the diagram or the notes, else null and add an ambiguity.
- Routing defaults to OSPF process 1 area 0 with passive LAN interfaces unless stated otherwise.
- Every uncertainty, conflict, unreadable label or assumption MUST be listed in "ambiguities"
  (resolved=false). Set confidence (0-1) to reflect how sure you are overall.
"""

# JSON schema sent to the model (kept simple for structured outputs); the response is then
# validated strictly with the pydantic Extraction model + validation.validate_plan.
_IFACE = {"type": "object", "additionalProperties": False,
          "required": ["id", "name", "ip", "mask", "link"],
          "properties": {"id": {"type": "string"}, "name": {"type": ["string", "null"]},
                         "ip": {"type": "string"}, "mask": {"type": "string"}, "link": {"type": "string"}}}
LLM_SCHEMA = {
    "type": "object", "additionalProperties": False,
    "required": ["devices", "links", "addressing_plan", "routing", "ambiguities", "confidence"],
    "properties": {
        "devices": {"type": "array", "items": {
            "type": "object", "additionalProperties": False,
            "required": ["hostname", "role", "aliases", "router_id", "interfaces"],
            "properties": {"hostname": {"type": "string"}, "role": {"type": "string", "enum": ["router", "host"]},
                           "aliases": {"type": "array", "items": {"type": "string"}},
                           "router_id": {"type": ["string", "null"]},
                           "interfaces": {"type": "array", "items": _IFACE}}}},
        "links": {"type": "array", "items": {
            "type": "object", "additionalProperties": False, "required": ["id", "subnet", "kind", "endpoints"],
            "properties": {"id": {"type": "string"}, "subnet": {"type": "string"},
                           "kind": {"type": "string", "enum": ["lan", "transit"]},
                           "endpoints": {"type": "array", "items": {
                               "type": "object", "additionalProperties": False, "required": ["device", "interface"],
                               "properties": {"device": {"type": "string"}, "interface": {"type": "string"}}}}}}},
        "addressing_plan": {"type": "array", "items": {
            "type": "object", "additionalProperties": False,
            "required": ["device", "interface", "ip", "mask", "gateway"],
            "properties": {"device": {"type": "string"}, "interface": {"type": "string"}, "ip": {"type": "string"},
                           "mask": {"type": "string"}, "gateway": {"type": ["string", "null"]}}}},
        "routing": {"type": "object", "additionalProperties": False,
                    "required": ["protocol", "process_id", "area", "passive_lan_interfaces"],
                    "properties": {"protocol": {"type": "string", "enum": ["ospf"]},
                                   "process_id": {"type": "integer"}, "area": {"type": "integer"},
                                   "passive_lan_interfaces": {"type": "boolean"}}},
        "ambiguities": {"type": "array", "items": {
            "type": "object", "additionalProperties": False,
            "required": ["field", "issue", "suggestion", "resolved"],
            "properties": {"field": {"type": "string"}, "issue": {"type": "string"},
                           "suggestion": {"type": ["string", "null"]}, "resolved": {"type": "boolean"}}}},
        "confidence": {"type": "number"},
    },
}


class ExtractionError(Exception):
    pass


def _prompt(notes: str) -> str:
    return ("Extract the topology and addressing plan from this diagram."
            + (f"\n\nAdministrator notes / requirements (authoritative):\n{notes}" if notes else ""))


def _no_progress(_msg: str) -> None:
    pass


def extract_from_image(s: Settings, image_bytes: bytes, media_type: str, notes: str = "",
                       progress=_no_progress) -> Extraction:
    """`progress(msg)` receives short human-readable status updates (shown live in the web UI)."""
    if s.ai_provider == "ollama":
        progress(f"local model {s.ollama_model} is reading the diagram (can take minutes on CPU)")
        return _finish(_call_ollama(s, image_bytes, notes))
    if s.ai_provider == "gemini":
        text, used, failures = _call_gemini(s, image_bytes, media_type, notes, progress)
        progress(f"{used} answered - validating the result")
        ex = _finish(text)
        if used != s.gemini_model:  # informational, does not block approval
            ex.ambiguities.append(Ambiguity(
                field="extraction.model",
                issue=f"Analysed by {used} because {s.gemini_model} was busy ({'; '.join(failures)})",
                suggestion=None, resolved=True))
        return ex
    if s.ai_provider != "anthropic":
        raise ExtractionError(f"Unknown AI_PROVIDER '{s.ai_provider}' (use 'anthropic', 'gemini' or 'ollama')")
    progress(f"{s.anthropic_model} is reading the diagram")
    return _finish(_call_anthropic(s, image_bytes, media_type, notes))


class _GeminiTransient(Exception):
    """Overload / rate limit / network blip: retry, then try the next model."""


class _GeminiModelUnavailable(Exception):
    """Model not found or not enabled for this key: skip to the next model."""


_GEMINI_BACKOFF = (2, 5, 10)


def _call_gemini(s: Settings, image_bytes: bytes, media_type: str, notes: str,
                 progress=_no_progress) -> tuple[str, str, list[str]]:
    """Google Gemini generateContent with a JSON-schema response (structured output).
    Tries the primary model with retries, then each free-tier backup model.
    Returns (text, model_that_answered, failure_notes)."""
    if not s.gemini_api_key:
        raise ExtractionError("No Gemini API key - set GEMINI_API_KEY in .env and restart the API")
    body = {
        "systemInstruction": {"parts": [{"text": SYSTEM}]},
        "contents": [{"role": "user", "parts": [
            {"text": _prompt(notes)},  # Gemini guidance: text before a single image
            {"inlineData": {"mimeType": media_type, "data": base64.standard_b64encode(image_bytes).decode()}},
        ]}],
        "generationConfig": {"temperature": 0, "responseMimeType": "application/json",
                             "responseJsonSchema": LLM_SCHEMA},
    }
    models = [s.gemini_model, *(m for m in s.gemini_fallback_models if m != s.gemini_model)]
    failures: list[str] = []
    tries = 1 + max(0, s.gemini_retries)
    for n, model in enumerate(models):
        if n:
            progress(f"switching to backup model {model} (free tier)")
        for attempt in range(tries):
            progress(f"asking {model}" + (f" - attempt {attempt + 1}/{tries}" if attempt else ""))
            try:
                text = _gemini_once(s, model, body)
                if model != s.gemini_model:
                    log.warning("gemini: %s answered after the primary failed (%s)", model, "; ".join(failures))
                return text, model, failures
            except _GeminiModelUnavailable as e:
                failures.append(f"{model}: {e}")
                progress(f"{model} is not available for this key - skipping it")
                break
            except _GeminiTransient as e:
                log.warning("gemini: %s attempt %d failed: %s", model, attempt + 1, e)
                short = str(e).split(" This model")[0][:80]
                if attempt < s.gemini_retries:
                    wait = _GEMINI_BACKOFF[min(attempt, len(_GEMINI_BACKOFF) - 1)]
                    progress(f"{model} busy ({short}) - retrying in {wait}s ({attempt + 2}/{tries})")
                    time.sleep(wait)
                else:
                    failures.append(f"{model}: {e} (x{attempt + 1})")
                    progress(f"{model} still busy after {tries} attempts ({short})")
    raise ExtractionError("All Gemini models busy or unavailable - " + "; ".join(failures))


def _gemini_once(s: Settings, model: str, body: dict) -> str:
    """One generateContent call. Raises _GeminiTransient / _GeminiModelUnavailable for errors another
    attempt or model can fix, ExtractionError for the rest (key, request, blocked, truncated)."""
    import httpx

    url = f"{s.gemini_url}/models/{model}:generateContent"
    try:  # key in a header, never in the URL (URLs end up in logs)
        r = httpx.post(url, json=body, headers={"x-goog-api-key": s.gemini_api_key}, timeout=s.gemini_timeout)
    except httpx.ConnectError as e:
        raise _GeminiTransient("cannot reach the Gemini API") from e
    except httpx.TimeoutException as e:
        raise _GeminiTransient(f"no answer within {s.gemini_timeout:.0f}s") from e
    except httpx.HTTPError as e:
        raise ExtractionError(f"Gemini request failed: {type(e).__name__}") from e
    if r.status_code != 200:
        try:
            err = r.json().get("error", {})
            msg = f"{err.get('status', '')} {err.get('message', '')}".strip()
        except ValueError:
            msg = r.text
        msg = msg[:200]
        if r.status_code == 404:
            raise _GeminiModelUnavailable(f"404 model not found - check GEMINI_MODEL / GEMINI_FALLBACK_MODELS: {msg}")
        if r.status_code == 429:
            raise _GeminiTransient(f"429 quota or rate limit: {msg}")
        if r.status_code in (500, 502, 503, 504):
            raise _GeminiTransient(f"{r.status_code} {msg}")
        hint = {401: " - check GEMINI_API_KEY", 403: " - check GEMINI_API_KEY / API enabled"}.get(r.status_code, "")
        raise ExtractionError(f"Gemini API error {r.status_code}{hint}: {msg}")
    resp = r.json()
    if (resp.get("promptFeedback") or {}).get("blockReason"):
        raise ExtractionError(f"Gemini blocked the request: {resp['promptFeedback']['blockReason']}")
    cands = resp.get("candidates") or []
    if not cands:
        raise ExtractionError("Gemini returned no answer")
    reason = cands[0].get("finishReason")
    if reason == "MAX_TOKENS":
        raise ExtractionError("Model output truncated (max tokens)")
    if reason not in (None, "STOP"):
        raise ExtractionError(f"Gemini stopped early: {reason}")
    log.info("gemini extraction: model=%s usage=%s", model, resp.get("usageMetadata"))
    parts = (cands[0].get("content") or {}).get("parts") or []
    return "".join(p.get("text", "") for p in parts if not p.get("thought"))


def _call_ollama(s: Settings, image_bytes: bytes, notes: str) -> str:
    """Local vision model via Ollama's /api/chat with a JSON-schema `format` (structured output)."""
    import httpx

    options = {"temperature": 0, "num_ctx": 8192, "num_predict": 4096}
    if s.ollama_num_gpu is not None:
        options["num_gpu"] = s.ollama_num_gpu
    body = {
        "model": s.ollama_model,
        "stream": False,
        "format": LLM_SCHEMA,
        "options": options,
        "messages": [
            {"role": "system", "content": SYSTEM},
            {"role": "user", "content": _prompt(notes),
             "images": [base64.standard_b64encode(image_bytes).decode()]},
        ],
    }
    try:
        r = httpx.post(f"{s.ollama_url}/api/chat", json=body, timeout=s.ollama_timeout)
    except httpx.ConnectError as e:
        raise ExtractionError(f"Cannot reach Ollama at {s.ollama_url} - is Ollama running?") from e
    except httpx.TimeoutException as e:
        raise ExtractionError(f"Ollama did not answer within {s.ollama_timeout:.0f}s (raise OLLAMA_TIMEOUT)") from e
    except httpx.HTTPError as e:
        raise ExtractionError(f"Ollama request failed: {e}") from e
    if r.status_code == 404:
        raise ExtractionError(f"Ollama model '{s.ollama_model}' is not installed - run: ollama pull {s.ollama_model}")
    if r.status_code != 200:
        raise ExtractionError(f"Ollama error {r.status_code}: {r.text[:300]}")
    resp = r.json()
    if resp.get("done_reason") == "length":
        raise ExtractionError("Model output truncated (num_predict)")
    log.info("ollama extraction: model=%s eval_count=%s total_ms=%s", s.ollama_model, resp.get("eval_count"),
             int(resp.get("total_duration", 0) / 1e6))
    return (resp.get("message") or {}).get("content", "")


def _call_anthropic(s: Settings, image_bytes: bytes, media_type: str, notes: str) -> str:
    import anthropic  # lazy: the rest of the system works without the SDK configured

    content = [
        {"type": "image", "source": {"type": "base64", "media_type": media_type,
                                     "data": base64.standard_b64encode(image_bytes).decode()}},
        {"type": "text", "text": _prompt(notes)},
    ]
    no_creds = getattr(anthropic, "CredentialsError", None)
    try:
        client = anthropic.Anthropic()  # reads ANTHROPIC_API_KEY (or an `ant auth login` profile)
        resp = client.beta.messages.create(
            model=s.anthropic_model,
            max_tokens=16000,
            system=SYSTEM,
            messages=[{"role": "user", "content": content}],
            output_config={"effort": s.extraction_effort,
                           "format": {"type": "json_schema", "schema": LLM_SCHEMA}},
            betas=["server-side-fallback-2026-07-01"],
            fallbacks="default",  # re-run on a fallback model if the primary declines
        )
    except anthropic.AuthenticationError as e:
        raise ExtractionError("Anthropic API authentication failed - set ANTHROPIC_API_KEY") from e
    except anthropic.RateLimitError as e:
        raise ExtractionError("Anthropic API rate limited - retry shortly") from e
    except anthropic.APIStatusError as e:
        raise ExtractionError(f"Anthropic API error {e.status_code}: {e.message}") from e
    except anthropic.APIConnectionError as e:
        raise ExtractionError("Cannot reach the Anthropic API") from e
    except anthropic.AnthropicError as e:  # e.g. CredentialsError: no API key and no login profile
        if no_creds and isinstance(e, no_creds):
            raise ExtractionError("No Anthropic API credentials - set ANTHROPIC_API_KEY (or run `ant auth login`)"
                                  " and restart the API, or use Load sample JSON / edit the JSON manually") from e
        raise ExtractionError(f"Anthropic SDK error: {type(e).__name__}: {e}") from e

    if resp.stop_reason == "refusal":
        raise ExtractionError("Model declined the request")
    if resp.stop_reason == "max_tokens":
        raise ExtractionError("Model output truncated (max_tokens)")
    log.info("extraction usage: %s", getattr(resp, "usage", None))
    return next((b.text for b in resp.content if b.type == "text"), "")


def _finish(text: str) -> Extraction:
    """Provider-independent post-processing: parse, clamp, distrust physical names, validate strictly."""
    try:
        data = json.loads(text)
    except json.JSONDecodeError as e:
        raise ExtractionError(f"Model did not return JSON: {e}") from e
    if not isinstance(data, dict):
        raise ExtractionError("Model did not return a JSON object")
    try:
        data["source"] = "ai"
        data["confidence"] = max(0.0, min(1.0, float(data.get("confidence", 0))))
        for d in data.get("devices", []):  # never trust model-provided physical names
            for i in d.get("interfaces", []):
                if i.get("name"):
                    data.setdefault("ambiguities", []).append({
                        "field": f"devices.{d['hostname']}.interfaces.{i['id']}.name",
                        "issue": f"Model proposed physical name '{i['name']}' - must be confirmed against discovery",
                        "suggestion": None, "resolved": False})
        return Extraction.model_validate(data)
    except (ValueError, TypeError, KeyError, AttributeError) as e:  # incl. pydantic ValidationError -> 502, not 500
        raise ExtractionError(f"Model output failed validation: {str(e)[:500]}") from e
