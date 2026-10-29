"""Deterministic request hashing and disk response cache (Slice S4, Section 9)."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any


def compute_request_hash(
    model_id: str,
    system: str,
    user: str,
    schema: dict[str, Any] | None,
    reasoning_effort: str | None,
    max_output_tokens: int | None,
) -> str:
    normalized = {
        "model_id": model_id,
        "system": system,
        "user": user,
        "schema": schema,
        "reasoning_effort": reasoning_effort,
        "max_output_tokens": max_output_tokens,
    }
    canonical = json.dumps(normalized, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


class DiskLLMCache:
    def __init__(self, cache_dir: Path) -> None:
        self.cache_dir = cache_dir
        self.cache_dir.mkdir(parents=True, exist_ok=True)

    def _entry_path(self, request_hash: str) -> Path:
        return self.cache_dir / f"{request_hash}.json"

    def get(self, request_hash: str) -> dict[str, Any] | None:
        path = self._entry_path(request_hash)
        if not path.exists():
            return None
        return json.loads(path.read_text(encoding="utf-8"))

    def put(self, request_hash: str, entry: dict[str, Any]) -> None:
        path = self._entry_path(request_hash)
        path.write_text(json.dumps(entry, indent=2, sort_keys=True), encoding="utf-8")
