"""Meta Model API client (/v1/responses), structured output validator, cache, and cost logger (Slice S4)."""

from __future__ import annotations

import json
import os
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import httpx

from agent.llm.cache import DiskLLMCache, compute_request_hash
from contracts import LLMCaps, LLMResult, ModelRole


class LLMClientError(RuntimeError):
    """Raised when the Meta Model API fails or credentials are missing."""


class StructuredOutputError(ValueError):
    """Raised when a structured response is invalid JSON or violates the requested schema."""


class BudgetExceededError(RuntimeError):
    """Raised when per-run call or token budget caps are exceeded."""


def load_dotenv_if_present(env_path: Path | None = None) -> None:
    """Minimal .env loader (avoids unverified third-party dotenv packages; never logs values)."""
    target = env_path or Path(__file__).resolve().parents[2] / ".env"
    if not target.exists():
        return
    for raw_line in target.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, val = line.split("=", 1)
        key = key.strip()
        val = val.strip().strip('"').strip("'")
        if key and key not in os.environ:
            os.environ[key] = val


def validate_json_against_schema(data: Any, schema: dict[str, Any], path: str = "$") -> None:
    """Strict recursive validator for the JSON Schema subset used in structured outputs."""
    expected_type = schema.get("type")
    if expected_type == "object":
        if not isinstance(data, dict):
            raise StructuredOutputError(f"{path}: expected object, got {type(data).__name__}")
        required = schema.get("required") or []
        for req_key in required:
            if req_key not in data:
                raise StructuredOutputError(f"{path}: missing required key '{req_key}'")
        props = schema.get("properties") or {}
        if schema.get("additionalProperties") is False:
            extra = set(data.keys()) - set(props.keys())
            if extra:
                raise StructuredOutputError(f"{path}: unexpected additional keys {sorted(extra)}")
        for k, v in data.items():
            if k in props:
                validate_json_against_schema(v, props[k], f"{path}.{k}")
    elif expected_type == "array":
        if not isinstance(data, list):
            raise StructuredOutputError(f"{path}: expected array, got {type(data).__name__}")
        item_schema = schema.get("items")
        if isinstance(item_schema, dict):
            for idx, item in enumerate(data):
                validate_json_against_schema(item, item_schema, f"{path}[{idx}]")
    elif expected_type == "string":
        if not isinstance(data, str):
            raise StructuredOutputError(f"{path}: expected string, got {type(data).__name__}")
        enum_vals = schema.get("enum")
        if enum_vals is not None and data not in enum_vals:
            raise StructuredOutputError(f"{path}: '{data}' not in enum {enum_vals}")
    elif expected_type == "integer":
        if isinstance(data, bool) or not isinstance(data, int):
            raise StructuredOutputError(f"{path}: expected integer, got {type(data).__name__}")
    elif expected_type == "number":
        if isinstance(data, bool) or not isinstance(data, (int, float)):
            raise StructuredOutputError(f"{path}: expected number, got {type(data).__name__}")
    elif expected_type == "boolean":
        if not isinstance(data, bool):
            raise StructuredOutputError(f"{path}: expected boolean, got {type(data).__name__}")


def parse_and_validate_structured_text(raw_text: str, schema: dict[str, Any]) -> dict[str, Any]:
    """Parse strict JSON without silent repair and validate against schema."""
    try:
        parsed = json.loads(raw_text)
    except json.JSONDecodeError as exc:
        raise StructuredOutputError(f"Model returned invalid JSON: {exc}") from exc
    if not isinstance(parsed, dict):
        raise StructuredOutputError("Top-level structured response must be a JSON object")
    validate_json_against_schema(parsed, schema)
    return parsed


def extract_output_text(response_body: dict[str, Any]) -> str:
    """Extract assistant output_text from Meta /v1/responses payload."""
    chunks: list[str] = []
    for item in response_body.get("output") or []:
        if not isinstance(item, dict):
            continue
        if item.get("type") == "message":
            for part in item.get("content") or []:
                if isinstance(part, dict) and part.get("type") == "output_text":
                    chunks.append(str(part.get("text") or ""))
    return "".join(chunks)


class MetaLLMClient:
    """Live Meta Model API client backed by POST /v1/responses with caching and cost logging."""

    def __init__(
        self,
        api_key: str | None = None,
        base_url: str | None = None,
        fast_model: str | None = None,
        reasoning_model: str | None = None,
        cache_dir: Path | None = None,
        log_path: Path | None = None,
        use_cache: bool = True,
        max_calls_per_run: int = 120,
        max_tokens_per_run: int = 1_500_000,
    ) -> None:
        load_dotenv_if_present()
        resolved_key = api_key if api_key is not None else os.environ.get("MODEL_API_KEY", "")
        if not resolved_key.strip():
            raise LLMClientError("MODEL_API_KEY is missing; set it in environment or .env")
        self._api_key = resolved_key.strip()
        self.base_url = (base_url or os.environ.get("META_API_BASE_URL") or "https://api.meta.ai/v1").rstrip("/")
        self.fast_model = fast_model or os.environ.get("META_FAST_MODEL") or "muse-spark-1.3"
        self.reasoning_model = reasoning_model or os.environ.get("META_REASONING_MODEL") or "muse-wonder-1.0"
        self.use_cache = use_cache
        root_dir = Path(__file__).resolve().parents[2]
        self.cache = DiskLLMCache(cache_dir or (root_dir / ".llm_cache"))
        self.log_path = log_path
        self.max_calls_per_run = max_calls_per_run
        self.max_tokens_per_run = max_tokens_per_run
        self.live_calls = 0
        self.cache_hits = 0
        self.total_live_tokens = 0

    def _model_for_role(self, role: ModelRole) -> tuple[str, str]:
        if role == ModelRole.FAST:
            return self.fast_model, "low"
        if role == ModelRole.REASONING:
            return self.reasoning_model, "high"
        raise ValueError(f"Unsupported role: {role}")

    def _append_log(
        self,
        *,
        model_id: str,
        role: ModelRole,
        request_hash: str,
        latency_ms: int,
        retries: int,
        cache_hit: bool,
        usage: dict[str, Any] | None,
        error: str | None = None,
    ) -> None:
        if self.log_path is None:
            return
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        record = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "model_id": model_id,
            "role": str(role),
            "request_hash": request_hash,
            "latency_ms": latency_ms,
            "retries": retries,
            "cache_hit": cache_hit,
            "usage": usage,
            "cost_usd": "unknown",
            "error": error,
        }
        with self.log_path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(record, sort_keys=True) + "\n")

    def call(
        self,
        role: ModelRole,
        system: str,
        user: str,
        schema: dict[str, Any] | None = None,
        caps: LLMCaps | None = None,
    ) -> LLMResult:
        effective_caps = caps or LLMCaps()
        model_id, default_effort = self._model_for_role(role)
        effort = effective_caps.reasoning_effort or default_effort

        req_hash = compute_request_hash(
            model_id=model_id,
            system=system,
            user=user,
            schema=schema,
            reasoning_effort=effort,
            max_output_tokens=effective_caps.max_output_tokens,
        )

        if self.use_cache:
            cached = self.cache.get(req_hash)
            if cached is not None:
                text = str(cached.get("text") or "")
                parsed = parse_and_validate_structured_text(text, schema) if schema is not None else None
                usage = cached.get("usage")
                self.cache_hits += 1
                self._append_log(
                    model_id=model_id,
                    role=role,
                    request_hash=req_hash,
                    latency_ms=0,
                    retries=0,
                    cache_hit=True,
                    usage=usage,
                )
                return LLMResult(
                    parsed=parsed,
                    text=text,
                    usage=usage,
                    latency_ms=0,
                    cache_hit=True,
                    model_id=model_id,
                    request_hash=req_hash,
                )

        if self.live_calls >= self.max_calls_per_run:
            raise BudgetExceededError(f"Exceeded max_calls_per_run ({self.max_calls_per_run})")
        if self.total_live_tokens >= self.max_tokens_per_run:
            raise BudgetExceededError(f"Exceeded max_tokens_per_run ({self.max_tokens_per_run})")

        payload: dict[str, Any] = {
            "model": model_id,
            "instructions": system,
            "input": user,
            "reasoning": {"effort": effort},
        }
        if effective_caps.max_output_tokens is not None:
            payload["max_output_tokens"] = effective_caps.max_output_tokens
        if schema is not None:
            payload["text"] = {
                "format": {
                    "type": "json_schema",
                    "name": "structured_response",
                    "strict": True,
                    "schema": schema,
                }
            }

        headers = {
            "Authorization": f"Bearer {self._api_key}",
            "Content-Type": "application/json",
        }

        last_err: Exception | None = None
        retries_used = 0
        start = time.perf_counter()

        for attempt in range(effective_caps.max_retries + 1):
            retries_used = attempt
            try:
                with httpx.Client(timeout=effective_caps.timeout_s) as client:
                    resp = client.post(f"{self.base_url}/responses", headers=headers, json=payload)
                if resp.status_code in (429, 500, 502, 503, 504) and attempt < effective_caps.max_retries:
                    time.sleep(min(2.0 ** attempt, 6.0))
                    continue
                if resp.status_code != 200:
                    err_msg = f"Meta API HTTP {resp.status_code}: {resp.text[:400]}"
                    self._append_log(
                        model_id=model_id,
                        role=role,
                        request_hash=req_hash,
                        latency_ms=int((time.perf_counter() - start) * 1000),
                        retries=retries_used,
                        cache_hit=False,
                        usage=None,
                        error=err_msg,
                    )
                    raise LLMClientError(err_msg)

                body = resp.json()
                latency_ms = int((time.perf_counter() - start) * 1000)
                text = extract_output_text(body)
                usage = body.get("usage") if isinstance(body.get("usage"), dict) else None

                self.live_calls += 1
                if usage and isinstance(usage.get("total_tokens"), int):
                    self.total_live_tokens += usage["total_tokens"]

                parsed = parse_and_validate_structured_text(text, schema) if schema is not None else None

                if self.use_cache:
                    self.cache.put(req_hash, {"model_id": model_id, "text": text, "usage": usage})

                self._append_log(
                    model_id=model_id,
                    role=role,
                    request_hash=req_hash,
                    latency_ms=latency_ms,
                    retries=retries_used,
                    cache_hit=False,
                    usage=usage,
                )
                return LLMResult(
                    parsed=parsed,
                    text=text,
                    usage=usage,
                    latency_ms=latency_ms,
                    cache_hit=False,
                    model_id=model_id,
                    request_hash=req_hash,
                )
            except (httpx.TimeoutException, httpx.TransportError) as exc:
                last_err = exc
                if attempt < effective_caps.max_retries:
                    time.sleep(min(2.0 ** attempt, 6.0))
                    continue
                err_msg = f"Meta API transport failure after {attempt + 1} attempts: {exc}"
                self._append_log(
                    model_id=model_id,
                    role=role,
                    request_hash=req_hash,
                    latency_ms=int((time.perf_counter() - start) * 1000),
                    retries=retries_used,
                    cache_hit=False,
                    usage=None,
                    error=err_msg,
                )
                raise LLMClientError(err_msg) from exc

        raise LLMClientError(f"Meta API call failed: {last_err}")
