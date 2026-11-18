"""AI extraction post-processing with a mocked Anthropic client (no network, no cost)."""
import json
import sys
import types
from types import SimpleNamespace

import pytest

from app.config import Settings
from app.extractor import LLM_SCHEMA, ExtractionError, extract_from_image
from tests.conftest import ROOT


def fake_anthropic(monkeypatch, payload, stop_reason="end_turn", capture=None):
    import anthropic

    class Msgs:
        def create(self, **kw):
            if capture is not None:
                capture.update(kw)
            return SimpleNamespace(stop_reason=stop_reason, usage=None,
                                   content=[SimpleNamespace(type="text", text=payload)])

    client = SimpleNamespace(beta=SimpleNamespace(messages=Msgs()))
    monkeypatch.setattr(anthropic, "Anthropic", lambda *a, **k: client)


def sample_text(**overrides):
    d = json.loads((ROOT / "samples" / "exam_plan.json").read_text())
    d.pop("source")
    d.update(overrides)
    return json.dumps(d)


def test_extraction_parsed_and_flagged(monkeypatch):
    d = json.loads(sample_text(confidence=1.7))
    d["devices"][1]["interfaces"][0]["name"] = "Gi0/0"   # model guessed a port name
    sent = {}
    fake_anthropic(monkeypatch, json.dumps(d), capture=sent)
    ex = extract_from_image(Settings(), b"\x89PNG", "image/png", notes="R1 router-id 1.1.1.1")
    assert ex.source == "ai" and ex.confidence == 1.0
    assert any("must be confirmed against discovery" in a.issue for a in ex.ambiguities)
    assert sent["model"] == "claude-opus-5-5" and sent["output_config"]["format"]["schema"] is LLM_SCHEMA
    assert sent["messages"][0]["content"][0]["type"] == "image"
    assert "R1 router-id 1.1.1.1" in sent["messages"][0]["content"][1]["text"]


@pytest.mark.parametrize("payload,stop", [("not json", "end_turn"), ("{}", "refusal"), ("{", "max_tokens")])
def test_extraction_errors(monkeypatch, payload, stop):
    fake_anthropic(monkeypatch, payload, stop)
    with pytest.raises(ExtractionError):
        extract_from_image(Settings(), b"x", "image/png")


def test_sdk_errors_become_extraction_errors(monkeypatch):
    """Missing credentials (CredentialsError) and other non-HTTP SDK errors must not escape as a 500."""
    import anthropic

    def boom(*a, **k):
        raise anthropic.CredentialsError("Credentials file not found")
    monkeypatch.setattr(anthropic, "Anthropic", boom)
    with pytest.raises(ExtractionError, match="No Anthropic API credentials"):
        extract_from_image(Settings(), b"x", "image/png")

    class Msgs:
        def create(self, **kw):
            raise anthropic.AnthropicError("something odd")
    monkeypatch.setattr(anthropic, "Anthropic", lambda *a, **k: SimpleNamespace(beta=SimpleNamespace(messages=Msgs())))
    with pytest.raises(ExtractionError, match="Anthropic SDK error"):
        extract_from_image(Settings(), b"x", "image/png")


def ollama_settings(monkeypatch):
    monkeypatch.setenv("AI_PROVIDER", "ollama")
    monkeypatch.setenv("OLLAMA_URL", "http://ollama.test:11434/")
    monkeypatch.setenv("OLLAMA_MODEL", "vision-test")
    return Settings()


def fake_ollama(monkeypatch, status=200, json_body=None, raise_exc=None, capture=None):
    import httpx

    def post(url, json=None, timeout=None):
        if capture is not None:
            capture.update(url=url, body=json, timeout=timeout)
        if raise_exc:
            raise raise_exc
        return SimpleNamespace(status_code=status, text="err", json=lambda: json_body)
    monkeypatch.setattr(httpx, "post", post)


def test_ollama_extraction(monkeypatch):
    """Local vision model: same schema, same post-processing (physical names distrusted)."""
    s = ollama_settings(monkeypatch)
    d = json.loads(sample_text())
    d["devices"][0]["interfaces"][0]["name"] = "Fa0/0"
    sent = {}
    fake_ollama(monkeypatch, json_body={"message": {"content": json.dumps(d)}, "done_reason": "stop"}, capture=sent)
    ex = extract_from_image(s, b"\x89PNG", "image/png", notes="R1 router-id 1.1.1.1")
    assert ex.source == "ai" and any("must be confirmed against discovery" in a.issue for a in ex.ambiguities)
    assert sent["url"] == "http://ollama.test:11434/api/chat"
    body = sent["body"]
    assert body["model"] == "vision-test" and body["format"] is LLM_SCHEMA and body["stream"] is False
    assert body["messages"][1]["images"] and "R1 router-id 1.1.1.1" in body["messages"][1]["content"]
    assert "num_gpu" not in body["options"]
    monkeypatch.setenv("OLLAMA_NUM_GPU", "0")
    extract_from_image(Settings(), b"\x89PNG", "image/png")
    assert sent["body"]["options"]["num_gpu"] == 0


def test_ollama_errors(monkeypatch):
    import httpx
    s = ollama_settings(monkeypatch)
    fake_ollama(monkeypatch, raise_exc=httpx.ConnectError("refused"))
    with pytest.raises(ExtractionError, match="Cannot reach Ollama"):
        extract_from_image(s, b"x", "image/png")
    fake_ollama(monkeypatch, status=404, json_body={})
    with pytest.raises(ExtractionError, match="ollama pull vision-test"):
        extract_from_image(s, b"x", "image/png")
    fake_ollama(monkeypatch, json_body={"message": {"content": "{"}, "done_reason": "length"})
    with pytest.raises(ExtractionError, match="truncated"):
        extract_from_image(s, b"x", "image/png")
    fake_ollama(monkeypatch, json_body={"message": {"content": json.dumps({"devices": 5})}, "done_reason": "stop"})
    with pytest.raises(ExtractionError, match="failed validation"):
        extract_from_image(s, b"x", "image/png")


def gemini_settings(monkeypatch, key="AIzaTESTKEY0123456789abcdefghijklmnop"):
    monkeypatch.setenv("AI_PROVIDER", "gemini")
    monkeypatch.setenv("GEMINI_API_KEY", key)
    monkeypatch.setenv("GEMINI_MODEL", "gemini-test")
    return Settings()


def fake_gemini(monkeypatch, status=200, json_body=None, capture=None):
    import httpx

    def post(url, json=None, headers=None, timeout=None):
        if capture is not None:
            capture.update(url=url, body=json, headers=headers)
        return SimpleNamespace(status_code=status, text="err", json=lambda: json_body)
    monkeypatch.setattr(httpx, "post", post)


def gemini_ok(text, reason="STOP"):
    return {"candidates": [{"content": {"parts": [{"text": text}]}, "finishReason": reason}]}


def test_gemini_extraction(monkeypatch):
    s = gemini_settings(monkeypatch)
    sent = {}
    fake_gemini(monkeypatch, json_body=gemini_ok(sample_text()), capture=sent)
    ex = extract_from_image(s, b"\x89PNG", "image/png", notes="R1 router-id 1.1.1.1")
    assert ex.source == "ai" and len(ex.routers()) == 2
    assert sent["url"].endswith("/models/gemini-test:generateContent")
    assert "key=" not in sent["url"] and sent["headers"]["x-goog-api-key"] == s.gemini_api_key
    cfg = sent["body"]["generationConfig"]
    assert cfg["responseMimeType"] == "application/json" and cfg["responseJsonSchema"] is LLM_SCHEMA
    parts = sent["body"]["contents"][0]["parts"]
    assert "R1 router-id 1.1.1.1" in parts[0]["text"] and parts[1]["inlineData"]["mimeType"] == "image/png"


def test_gemini_errors(monkeypatch):
    monkeypatch.setattr("app.extractor.time.sleep", lambda _s: None)
    monkeypatch.setenv("AI_PROVIDER", "gemini")
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    with pytest.raises(ExtractionError, match="No Gemini API key"):
        extract_from_image(Settings(), b"x", "image/png")
    s = gemini_settings(monkeypatch)
    fake_gemini(monkeypatch, status=404, json_body={"error": {"status": "NOT_FOUND", "message": "no model"}})
    with pytest.raises(ExtractionError, match="GEMINI_MODEL"):
        extract_from_image(s, b"x", "image/png")
    fake_gemini(monkeypatch, status=429, json_body={"error": {"status": "RESOURCE_EXHAUSTED", "message": "q"}})
    with pytest.raises(ExtractionError, match="quota"):
        extract_from_image(s, b"x", "image/png")
    fake_gemini(monkeypatch, json_body=gemini_ok("{", "MAX_TOKENS"))
    with pytest.raises(ExtractionError, match="truncated"):
        extract_from_image(s, b"x", "image/png")
    fake_gemini(monkeypatch, json_body={"promptFeedback": {"blockReason": "SAFETY"}})
    with pytest.raises(ExtractionError, match="blocked"):
        extract_from_image(s, b"x", "image/png")


def fake_gemini_seq(monkeypatch, responder, calls):
    """responder(model, n) -> (status, json); n = call number for that model (1-based)."""
    import httpx

    def post(url, json=None, headers=None, timeout=None):
        model = url.rsplit("/models/", 1)[1].split(":")[0]
        calls.append(model)
        status, body = responder(model, calls.count(model))
        return SimpleNamespace(status_code=status, text="err", json=lambda: body)
    monkeypatch.setattr(httpx, "post", post)
    monkeypatch.setattr("app.extractor.time.sleep", lambda _s: None)


BUSY = (503, {"error": {"status": "UNAVAILABLE", "message": "high demand"}})


def test_gemini_retries_primary_then_succeeds(monkeypatch):
    s = gemini_settings(monkeypatch)
    calls = []
    fake_gemini_seq(monkeypatch, lambda m, n: BUSY if n < 3 else (200, gemini_ok(sample_text())), calls)
    ex = extract_from_image(s, b"x", "image/png")
    assert calls == ["gemini-test"] * 3
    assert not any(a.field == "extraction.model" for a in ex.ambiguities)


def test_gemini_falls_back_to_free_backup_model(monkeypatch):
    monkeypatch.setenv("GEMINI_FALLBACK_MODELS", "backup-a, backup-b")
    s = gemini_settings(monkeypatch)
    calls = []
    fake_gemini_seq(monkeypatch, lambda m, n: BUSY if m == "gemini-test" else (200, gemini_ok(sample_text())), calls)
    ex = extract_from_image(s, b"x", "image/png")
    assert calls == ["gemini-test"] * 3 + ["backup-a"]
    note = [a for a in ex.ambiguities if a.field == "extraction.model"]
    assert note and note[0].resolved and "backup-a" in note[0].issue and "gemini-test" in note[0].issue


def test_gemini_404_skips_straight_to_backup(monkeypatch):
    monkeypatch.setenv("GEMINI_FALLBACK_MODELS", "backup-a")
    s = gemini_settings(monkeypatch)
    calls = []
    fake_gemini_seq(monkeypatch, lambda m, n: (404, {"error": {"message": "no model"}}) if m == "gemini-test"
                    else (200, gemini_ok(sample_text())), calls)
    extract_from_image(s, b"x", "image/png")
    assert calls == ["gemini-test", "backup-a"]


def test_gemini_key_error_does_not_try_backups(monkeypatch):
    monkeypatch.setenv("GEMINI_FALLBACK_MODELS", "backup-a")
    s = gemini_settings(monkeypatch)
    calls = []
    fake_gemini_seq(monkeypatch, lambda m, n: (401, {"error": {"message": "bad key"}}), calls)
    with pytest.raises(ExtractionError, match="GEMINI_API_KEY"):
        extract_from_image(s, b"x", "image/png")
    assert calls == ["gemini-test"]


def test_gemini_all_models_busy(monkeypatch):
    monkeypatch.setenv("GEMINI_FALLBACK_MODELS", "backup-a,backup-b")
    monkeypatch.setenv("GEMINI_RETRIES", "1")
    s = gemini_settings(monkeypatch)
    calls = []
    fake_gemini_seq(monkeypatch, lambda m, n: BUSY, calls)
    with pytest.raises(ExtractionError, match="All Gemini models busy") as e:
        extract_from_image(s, b"x", "image/png")
    assert all(m in str(e.value) for m in ("gemini-test", "backup-a", "backup-b"))
    assert len(calls) == 6


def test_gemini_reports_live_progress(monkeypatch):
    monkeypatch.setenv("GEMINI_FALLBACK_MODELS", "backup-a")
    monkeypatch.setenv("GEMINI_RETRIES", "1")
    s = gemini_settings(monkeypatch)
    calls, msgs = [], []
    fake_gemini_seq(monkeypatch, lambda m, n: BUSY if m == "gemini-test" else (200, gemini_ok(sample_text())), calls)
    extract_from_image(s, b"x", "image/png", progress=msgs.append)
    text = " | ".join(msgs)
    assert "asking gemini-test" in text and "retrying in" in text and "still busy" in text
    assert "switching to backup model backup-a" in text and "backup-a answered" in text


def test_gemini_no_backups_configured(monkeypatch):
    monkeypatch.setenv("GEMINI_FALLBACK_MODELS", "")
    s = gemini_settings(monkeypatch)
    assert s.gemini_fallback_models == ()
    calls = []
    fake_gemini_seq(monkeypatch, lambda m, n: BUSY, calls)
    with pytest.raises(ExtractionError, match="gemini-test"):
        extract_from_image(s, b"x", "image/png")
    assert calls == ["gemini-test"] * 3


def test_google_key_redacted():
    from app.safety import redact
    assert "0123456789abcdefghij" not in redact("key AIzaTESTKEY0123456789abcdefghijklmnop leaked")


def test_invalid_structure_rejected(monkeypatch):
    fake_anthropic(monkeypatch, json.dumps({"devices": [], "links": [], "addressing_plan": [],
                                            "routing": {"protocol": "rip"}, "ambiguities": [], "confidence": 1}))
    with pytest.raises(Exception):
        extract_from_image(Settings(), b"x", "image/png")
