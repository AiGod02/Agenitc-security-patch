import json
from pathlib import Path

import pytest

from agent.llm import (
    LLMClientError,
    MetaLLMClient,
    StructuredOutputError,
    parse_and_validate_structured_text,
)
from contracts import LLMCaps, ModelRole


def test_invalid_structured_response_rejected_without_silent_repair():
    schema = {
        "type": "object",
        "properties": {"verdict": {"type": "string"}, "count": {"type": "integer"}},
        "required": ["verdict", "count"],
        "additionalProperties": False,
    }
    with pytest.raises(StructuredOutputError):
        parse_and_validate_structured_text("```json\n{\"verdict\": \"ok\", \"count\": 1}\n```", schema)

    with pytest.raises(StructuredOutputError):
        parse_and_validate_structured_text('{"verdict": "ok"}', schema)

    with pytest.raises(StructuredOutputError):
        parse_and_validate_structured_text('{"verdict": "ok", "count": 1, "extra": true}', schema)


def test_missing_api_key_rejected(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    monkeypatch.delenv("MODEL_API_KEY", raising=False)
    # Point load_dotenv_if_present away by passing explicit empty api_key
    with pytest.raises(LLMClientError):
        MetaLLMClient(api_key="   ", cache_dir=tmp_path / "cache")


def test_live_fast_and_reasoning_calls_cache_and_cost_log(tmp_path: Path):
    cache_dir = tmp_path / "llm_cache"
    log_path = tmp_path / "llm_calls.jsonl"
    client = MetaLLMClient(cache_dir=cache_dir, log_path=log_path, use_cache=True)

    schema = {
        "type": "object",
        "properties": {
            "role_ack": {"type": "string"},
            "ready": {"type": "boolean"},
        },
        "required": ["role_ack", "ready"],
        "additionalProperties": False,
    }

    # 1. Live call on FAST role (muse-spark-1.3) with structured JSON
    r_fast_1 = client.call(
        role=ModelRole.FAST,
        system="Return strict JSON matching the schema.",
        user="Set role_ack='spark' and ready=true.",
        schema=schema,
        caps=LLMCaps(reasoning_effort="low", timeout_s=60.0),
    )
    assert r_fast_1.cache_hit is False
    assert r_fast_1.model_id == "muse-spark-1.3"
    assert r_fast_1.parsed == {"role_ack": "spark", "ready": True}
    assert r_fast_1.usage is not None
    assert r_fast_1.usage["total_tokens"] > 0

    # 2. Repeat identical call -> must be a cache hit with zero live call increment
    r_fast_2 = client.call(
        role=ModelRole.FAST,
        system="Return strict JSON matching the schema.",
        user="Set role_ack='spark' and ready=true.",
        schema=schema,
        caps=LLMCaps(reasoning_effort="low", timeout_s=60.0),
    )
    assert r_fast_2.cache_hit is True
    assert r_fast_2.parsed == {"role_ack": "spark", "ready": True}
    assert r_fast_2.request_hash == r_fast_1.request_hash
    assert client.live_calls == 1
    assert client.cache_hits == 1

    # 3. Live call on REASONING role (muse-wonder-1.0)
    r_reason = client.call(
        role=ModelRole.REASONING,
        system="Reply concisely.",
        user="Reply with the single word: wonder_ok",
        caps=LLMCaps(timeout_s=60.0),
    )
    assert r_reason.cache_hit is False
    assert r_reason.model_id == "muse-wonder-1.0"
    assert "wonder_ok" in r_reason.text.lower()
    assert r_reason.usage is not None

    # 4. Verify telemetry/cost log entries and ensure secret key is never logged
    raw_log = log_path.read_text(encoding="utf-8")
    assert "LLM_" not in raw_log
    entries = [json.loads(line) for line in raw_log.splitlines() if line.strip()]
    assert len(entries) == 3
    assert entries[0]["cache_hit"] is False
    assert entries[0]["cost_usd"] == "unknown"
    assert entries[1]["cache_hit"] is True
    assert entries[2]["model_id"] == "muse-wonder-1.0"
