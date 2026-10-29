"""Append-only JSONL event logger and transparent wrappers for LLM and Dispatcher (Slice S10)."""

from __future__ import annotations

import hashlib
import json
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from contracts import Event, LLMCaps, LLMClient, LLMResult, ModelRole, ToolResult

SENSITIVE_KEYS = {"api_key", "authorization", "secret", "password", "model_api_key"}


def sanitize_args(obj: Any) -> Any:
    if isinstance(obj, dict):
        cleaned: dict[str, Any] = {}
        for k, v in obj.items():
            if str(k).lower() in SENSITIVE_KEYS:
                cleaned[k] = "<REDACTED>"
            else:
                cleaned[k] = sanitize_args(v)
        return cleaned
    if isinstance(obj, list):
        return [sanitize_args(item) for item in obj]
    if isinstance(obj, str) and len(obj) > 2000:
        return obj[:2000] + "...<truncated>"
    return obj


def _hash_payload(payload: Any) -> str:
    raw = json.dumps(payload, sort_keys=True, default=str)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


class EventLogger:
    """Append-only JSONL event log with content-addressed result blobs for deterministic replay."""

    def __init__(self, run_dir: Path, run_id: str) -> None:
        self.run_dir = run_dir
        self.run_id = run_id
        self.events_path = self.run_dir / "events.jsonl"
        self.blobs_dir = self.run_dir / "blobs"
        self.run_dir.mkdir(parents=True, exist_ok=True)
        self.blobs_dir.mkdir(parents=True, exist_ok=True)
        self._seq = 0
        if self.events_path.exists():
            existing = [ln for ln in self.events_path.read_text(encoding="utf-8").splitlines() if ln.strip()]
            self._seq = len(existing)
        self.current_stage = "INIT"

    def set_stage(self, stage: str) -> Event:
        self.current_stage = stage
        return self.record(
            event_type="stage_transition",
            args={"stage": stage},
            result_payload={"stage": stage},
            exit_code=0,
            duration_ms=0,
        )

    def _store_blob(self, payload: Any) -> str:
        digest = _hash_payload(payload)
        rel_ref = f"blobs/{digest}.json"
        blob_path = self.run_dir / rel_ref
        if not blob_path.exists():
            blob_path.write_text(json.dumps(payload, indent=2, sort_keys=True, default=str), encoding="utf-8")
        return rel_ref

    def record(
        self,
        *,
        event_type: str,
        args: dict[str, Any],
        result_payload: Any = None,
        exit_code: int | None = None,
        duration_ms: int = 0,
        error: str | None = None,
    ) -> Event:
        self._seq += 1
        safe_args = sanitize_args(args)
        input_hash = _hash_payload(safe_args)
        result_ref = self._store_blob(result_payload) if result_payload is not None else None
        ev = Event(
            seq=self._seq,
            run_id=self.run_id,
            timestamp=datetime.now(timezone.utc).isoformat(),
            stage=self.current_stage,
            event_type=event_type,  # type: ignore[arg-type]
            input_hash=input_hash,
            args=safe_args,
            result_ref=result_ref,
            exit_code=exit_code,
            duration_ms=max(0, duration_ms),
            error=error,
        )
        with self.events_path.open("a", encoding="utf-8") as fh:
            fh.write(ev.model_dump_json() + "\n")
        return ev


class LoggingDispatcherWrapper:
    """Wraps a ToolDispatcher so every tool call is logged to EventLogger."""

    def __init__(self, inner: Any, logger: EventLogger) -> None:
        self._inner = inner
        self._logger = logger

    @property
    def workspace(self) -> Path | None:
        return getattr(self._inner, "workspace", None)

    def call(self, run_id: str, tool_name: str, args: dict[str, Any]) -> ToolResult:
        res = self._inner.call(run_id, tool_name, args)
        self._logger.record(
            event_type="tool_call",
            args={"tool_name": tool_name, "tool_args": args},
            result_payload=res.model_dump(),
            exit_code=res.exit_code,
            duration_ms=res.duration_ms,
            error=res.rejection_reason if not res.ok else None,
        )
        return res


class LoggingLLMWrapper:
    """Wraps an LLMClient so every model call is logged to EventLogger."""

    def __init__(self, inner: LLMClient, logger: EventLogger) -> None:
        self._inner = inner
        self._logger = logger

    def call(
        self,
        role: ModelRole,
        system: str,
        user: str,
        schema: dict[str, Any] | None = None,
        caps: LLMCaps | None = None,
    ) -> LLMResult:
        start = time.perf_counter()
        try:
            res = self._inner.call(role=role, system=system, user=user, schema=schema, caps=caps)
            self._logger.record(
                event_type="model_call",
                args={
                    "role": str(role),
                    "model_id": res.model_id,
                    "request_hash": res.request_hash,
                    "has_schema": schema is not None,
                    "cache_hit": res.cache_hit,
                },
                result_payload=res.model_dump(),
                exit_code=0,
                duration_ms=res.latency_ms,
            )
            return res
        except Exception as exc:
            elapsed = int((time.perf_counter() - start) * 1000)
            self._logger.record(
                event_type="model_call",
                args={"role": str(role), "has_schema": schema is not None},
                result_payload=None,
                exit_code=1,
                duration_ms=elapsed,
                error=str(exc),
            )
            raise
