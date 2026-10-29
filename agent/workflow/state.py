"""Multi-stage state management, atomic artifact envelopes, corruption detection, and event-log state derivation (Part 1)."""

from __future__ import annotations

import hashlib
import json
import os
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from agent.evidence.event_log import EventLogger
from contracts import ArtifactEnvelope, CandidateState, Event, RunState


class IllegalStateTransitionError(ValueError):
    """Raised when a run or candidate attempts a disallowed state transition."""


class CorruptedArtifactError(ValueError):
    """Raised when a saved stage artifact fails JSON schema or SHA-256 integrity checks."""


class StaleArtifactInputError(ValueError):
    """Raised when an existing artifact's input_hash does not match current upstream inputs."""


TERMINAL_RUN_STATES: frozenset[RunState] = frozenset({RunState.FAILED, RunState.CANCELLED})

ALLOWED_RUN_TRANSITIONS: dict[RunState, frozenset[RunState]] = {
    RunState.CREATED: frozenset({RunState.CREATED, RunState.RECON, RunState.FAILED, RunState.CANCELLED}),
    RunState.RECON: frozenset({RunState.RECON, RunState.CANDIDATES, RunState.FAILED, RunState.CANCELLED}),
    RunState.CANDIDATES: frozenset({RunState.CANDIDATES, RunState.VERIFYING, RunState.FAILED, RunState.CANCELLED}),
    RunState.VERIFYING: frozenset({RunState.VERIFYING, RunState.PATCHING, RunState.AWAITING_APPROVAL, RunState.FAILED, RunState.CANCELLED}),
    RunState.PATCHING: frozenset({RunState.PATCHING, RunState.CHECKING, RunState.FAILED, RunState.CANCELLED}),
    RunState.CHECKING: frozenset({RunState.CHECKING, RunState.PATCHING, RunState.AWAITING_APPROVAL, RunState.FAILED, RunState.CANCELLED}),
    RunState.AWAITING_APPROVAL: frozenset(
        {
            RunState.AWAITING_APPROVAL,
            RunState.APPROVED,
            RunState.PATCHING,
            RunState.CHECKING,
            RunState.FAILED,
            RunState.CANCELLED,
        }
    ),
    RunState.APPROVED: frozenset(
        {RunState.APPROVED, RunState.APPLIED, RunState.AWAITING_APPROVAL, RunState.FAILED, RunState.CANCELLED}
    ),
    RunState.APPLIED: frozenset({RunState.APPLIED, RunState.AWAITING_APPROVAL, RunState.APPROVED}),
    RunState.FAILED: frozenset(),
    RunState.CANCELLED: frozenset(),
}

ALLOWED_CANDIDATE_TRANSITIONS: dict[CandidateState, frozenset[CandidateState]] = {
    CandidateState.PROPOSED: frozenset({CandidateState.INVALID, CandidateState.TEST_WRITTEN}),
    CandidateState.INVALID: frozenset(),
    CandidateState.TEST_WRITTEN: frozenset(
        {
            CandidateState.TEST_WRITTEN,
            CandidateState.VERIFIED_REPRODUCER,
            CandidateState.NOT_REPRODUCED,
            CandidateState.INCONCLUSIVE,
        }
    ),
    CandidateState.NOT_REPRODUCED: frozenset(),
    CandidateState.INCONCLUSIVE: frozenset(),
    CandidateState.VERIFIED_REPRODUCER: frozenset({CandidateState.PLANNED, CandidateState.PATCH_FAILED}),
    CandidateState.PLANNED: frozenset({CandidateState.PATCH_PROPOSED, CandidateState.PATCH_FAILED}),
    CandidateState.PATCH_PROPOSED: frozenset(
        {
            CandidateState.GUARD_REJECTED,
            CandidateState.PATCH_FAILED,
            CandidateState.CHECKS_PASSED,
            CandidateState.REGRESSION,
        }
    ),
    CandidateState.GUARD_REJECTED: frozenset({CandidateState.PATCH_PROPOSED}),
    CandidateState.PATCH_FAILED: frozenset({CandidateState.PATCH_PROPOSED}),
    CandidateState.REGRESSION: frozenset({CandidateState.PATCH_PROPOSED}),
    CandidateState.CHECKS_PASSED: frozenset({CandidateState.AWAITING_APPROVAL}),
    CandidateState.AWAITING_APPROVAL: frozenset({CandidateState.APPROVED, CandidateState.REJECTED}),
    CandidateState.REJECTED: frozenset(),
    CandidateState.APPROVED: frozenset({CandidateState.APPLIED, CandidateState.CHECKS_PASSED}),
    CandidateState.APPLIED: frozenset(),
}


def canonical_sha256(data: Any) -> str:
    serialized = json.dumps(data, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()


def atomic_write_text(path: Path, content: str) -> None:
    """Write text atomically via temp file in same directory + fsync + os.replace."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = path.parent / f".{path.name}.tmp.{os.getpid()}.{uuid.uuid4().hex[:8]}"
    try:
        with tmp_path.open("w", encoding="utf-8", newline="\n") as fh:
            fh.write(content)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp_path, path)
    finally:
        if tmp_path.exists():
            try:
                tmp_path.unlink()
            except OSError:
                pass


def atomic_write_json(path: Path, payload: Any) -> None:
    atomic_write_text(path, json.dumps(payload, indent=2, sort_keys=True, default=str) + "\n")


def _find_run_root_for_artifact(artifact_path: Path) -> Path | None:
    cur = artifact_path.resolve().parent
    for _ in range(4):
        if (cur / "events.jsonl").exists():
            return cur
        if cur.parent == cur:
            break
        cur = cur.parent
    return None


def _latest_logged_artifact_sha(run_dir: Path, rel_path: str) -> str | None:
    events_path = run_dir / "events.jsonl"
    if not events_path.exists():
        return None
    latest: str | None = None
    for raw in events_path.read_text(encoding="utf-8").splitlines():
        if not raw.strip():
            continue
        ev = json.loads(raw)
        if ev.get("event_type") == "artifact_event":
            args = ev.get("args") or {}
            if args.get("action") == "artifact_written" and args.get("path") == rel_path:
                latest = args.get("payload_sha256")
    return latest


def read_stage_artifact(
    path: Path,
    expected_input_hash: str | None = None,
) -> ArtifactEnvelope:
    """Read and mechanically verify a stage artifact envelope against its SHA-256 and event log."""
    if not path.exists() or not path.is_file():
        raise CorruptedArtifactError(f"Artifact file missing: {path}")
    try:
        raw_text = path.read_text(encoding="utf-8")
        env = ArtifactEnvelope.model_validate_json(raw_text)
    except (OSError, ValidationError, ValueError) as exc:
        raise CorruptedArtifactError(f"Malformed artifact envelope at {path}: {exc}") from exc

    actual_sha = canonical_sha256(env.payload)
    if actual_sha != env.payload_sha256:
        raise CorruptedArtifactError(
            f"Artifact payload SHA-256 mismatch at {path}: envelope={env.payload_sha256}, actual={actual_sha}"
        )

    run_root = _find_run_root_for_artifact(path)
    if run_root is not None:
        rel_path = path.resolve().relative_to(run_root.resolve()).as_posix()
        logged_sha = _latest_logged_artifact_sha(run_root, rel_path)
        if logged_sha is not None and logged_sha != actual_sha:
            raise CorruptedArtifactError(
                f"Artifact {rel_path} disagrees with events.jsonl SHA-256 ({logged_sha} != {actual_sha})"
            )

    if expected_input_hash is not None and env.input_hash != expected_input_hash:
        raise StaleArtifactInputError(
            f"Artifact {path.name} input_hash {env.input_hash} != expected {expected_input_hash}"
        )
    return env


def _comparable_state_dict(state_doc: dict[str, Any]) -> dict[str, Any]:
    return {
        "run_id": state_doc.get("run_id"),
        "run_state": state_doc.get("run_state"),
        "failure_reason": state_doc.get("failure_reason"),
        "candidates": state_doc.get("candidates", {}),
        "last_event_seq": state_doc.get("last_event_seq", 0),
    }


def rebuild_state_from_events(run_dir: Path) -> dict[str, Any]:
    """Derive canonical state.json strictly by replaying append-only events.jsonl."""
    events_path = run_dir / "events.jsonl"
    if not events_path.exists():
        raise FileNotFoundError(f"Cannot rebuild state: missing {events_path}")

    run_id = run_dir.name
    run_state = RunState.CREATED.value
    failure_reason: str | None = None
    candidates: dict[str, dict[str, Any]] = {}
    last_seq = 0

    for raw in events_path.read_text(encoding="utf-8").splitlines():
        if not raw.strip():
            continue
        ev = Event.model_validate_json(raw)
        last_seq = ev.seq
        run_id = ev.run_id
        if ev.event_type != "state_transition" or ev.exit_code != 0:
            continue

        args = ev.args
        kind = args.get("entity")
        if kind == "run":
            run_state = str(args["to_state"])
            if run_state == RunState.FAILED.value:
                failure_reason = str(args.get("reason") or "unspecified_failure")
        elif kind == "candidate":
            cid = str(args["candidate_id"])
            entry = candidates.setdefault(
                cid,
                {
                    "state": CandidateState.PROPOSED.value,
                    "repair_count": 0,
                    "failure_signatures": [],
                    "last_reason": None,
                },
            )
            entry["state"] = str(args["to_state"])
            if args.get("reason"):
                entry["last_reason"] = str(args["reason"])
        elif kind == "candidate_repair":
            cid = str(args["candidate_id"])
            entry = candidates.setdefault(
                cid,
                {
                    "state": CandidateState.PROPOSED.value,
                    "repair_count": 0,
                    "failure_signatures": [],
                    "last_reason": None,
                },
            )
            entry["repair_count"] = int(entry.get("repair_count", 0)) + 1
            sig = str(args.get("signature") or "")
            if sig and sig not in entry["failure_signatures"]:
                entry["failure_signatures"].append(sig)
            if args.get("reason"):
                entry["last_reason"] = str(args["reason"])

    derived = {
        "run_id": run_id,
        "run_state": run_state,
        "failure_reason": failure_reason,
        "candidates": candidates,
        "last_event_seq": last_seq,
        "derived_at": datetime.now(timezone.utc).isoformat(),
    }
    atomic_write_json(run_dir / "state.json", derived)
    return derived


def ensure_synced_state(run_dir: Path) -> dict[str, Any]:
    """Ensure state.json exists and agrees with events.jsonl; if not, events.jsonl wins."""
    state_path = run_dir / "state.json"
    events_path = run_dir / "events.jsonl"
    if not events_path.exists():
        raise FileNotFoundError(f"Missing events.jsonl in {run_dir}")

    existing: dict[str, Any] | None = None
    if state_path.exists():
        try:
            existing = json.loads(state_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            existing = None

    rebuilt = rebuild_state_from_events(run_dir)
    if existing is None or _comparable_state_dict(existing) != _comparable_state_dict(rebuilt):
        logger = EventLogger(run_dir=run_dir, run_id=rebuilt["run_id"])
        logger.record(
            event_type="artifact_event",
            args={
                "action": "state_rebuilt_from_events",
                "had_existing": existing is not None,
            },
            result_payload={"run_state": rebuilt["run_state"]},
            exit_code=0,
            duration_ms=0,
        )
        rebuilt = rebuild_state_from_events(run_dir)
    return rebuilt


class StateManager:
    """Instance-scoped multi-stage state & envelope manager (zero module-level mutable state)."""

    def __init__(self, run_dir: Path, run_id: str | None = None) -> None:
        self.run_dir = run_dir.resolve()
        self.run_dir.mkdir(parents=True, exist_ok=True)
        events_path = self.run_dir / "events.jsonl"
        inferred_id = run_id or self.run_dir.name
        if events_path.exists():
            first_lines = [ln for ln in events_path.read_text(encoding="utf-8").splitlines() if ln.strip()]
            if first_lines:
                inferred_id = json.loads(first_lines[0]).get("run_id") or inferred_id
        self.run_id = inferred_id
        self.logger = EventLogger(run_dir=self.run_dir, run_id=self.run_id)

        if not events_path.exists() or events_path.stat().st_size == 0:
            self.logger.current_stage = RunState.CREATED.value
            self.logger.record(
                event_type="state_transition",
                args={
                    "entity": "run",
                    "from_state": None,
                    "to_state": RunState.CREATED.value,
                    "reason": "run_initialized",
                },
                result_payload={"run_state": RunState.CREATED.value},
                exit_code=0,
                duration_ms=0,
            )
            rebuild_state_from_events(self.run_dir)
        else:
            synced = ensure_synced_state(self.run_dir)
            self.logger.current_stage = str(synced["run_state"])

    def snapshot(self) -> dict[str, Any]:
        return ensure_synced_state(self.run_dir)

    def get_run_state(self) -> RunState:
        return RunState(self.snapshot()["run_state"])

    def get_candidate_state(self, candidate_id: str) -> CandidateState:
        snap = self.snapshot()
        if candidate_id not in snap["candidates"]:
            raise KeyError(f"Unknown candidate_id: {candidate_id}")
        return CandidateState(snap["candidates"][candidate_id]["state"])

    def has_candidate(self, candidate_id: str) -> bool:
        return candidate_id in self.snapshot()["candidates"]

    def get_candidate_repair_info(self, candidate_id: str) -> dict[str, Any]:
        snap = self.snapshot()
        info = snap["candidates"].get(candidate_id)
        if info is None:
            return {"repair_count": 0, "failure_signatures": [], "last_reason": None}
        return {
            "repair_count": int(info.get("repair_count", 0)),
            "failure_signatures": list(info.get("failure_signatures", [])),
            "last_reason": info.get("last_reason"),
        }

    def transition_run(
        self,
        to_state: RunState,
        reason: str = "",
        allow_stage_redo: bool = False,
    ) -> dict[str, Any]:
        cur = self.get_run_state()
        if to_state == RunState.FAILED and not reason.strip():
            msg = f"Illegal run transition {cur.value} -> FAILED: non-empty reason is required"
            self.logger.record(
                event_type="state_transition",
                args={"entity": "run", "from_state": cur.value, "to_state": to_state.value},
                exit_code=1,
                error=msg,
            )
            raise IllegalStateTransitionError(msg)

        allowed = ALLOWED_RUN_TRANSITIONS.get(cur, frozenset())
        if to_state not in allowed and not (allow_stage_redo and cur not in TERMINAL_RUN_STATES):
            msg = f"Illegal run transition {cur.value} -> {to_state.value}"
            self.logger.record(
                event_type="state_transition",
                args={"entity": "run", "from_state": cur.value, "to_state": to_state.value, "reason": reason},
                exit_code=1,
                error=msg,
            )
            raise IllegalStateTransitionError(msg)

        self.logger.current_stage = to_state.value
        self.logger.record(
            event_type="state_transition",
            args={
                "entity": "run",
                "from_state": cur.value,
                "to_state": to_state.value,
                "reason": reason,
            },
            result_payload={"run_state": to_state.value},
            exit_code=0,
            duration_ms=0,
        )
        return rebuild_state_from_events(self.run_dir)

    def init_candidate(self, candidate_id: str) -> dict[str, Any]:
        snap = self.snapshot()
        if candidate_id in snap["candidates"]:
            return snap
        self.logger.record(
            event_type="state_transition",
            args={
                "entity": "candidate",
                "candidate_id": candidate_id,
                "from_state": None,
                "to_state": CandidateState.PROPOSED.value,
                "reason": "candidate_proposed",
            },
            result_payload={"candidate_id": candidate_id, "state": CandidateState.PROPOSED.value},
            exit_code=0,
            duration_ms=0,
        )
        return rebuild_state_from_events(self.run_dir)

    def transition_candidate(
        self,
        candidate_id: str,
        to_state: CandidateState,
        reason: str = "",
        void_approval: bool = False,
        max_repairs: int = 2,
    ) -> dict[str, Any]:
        cur = self.get_candidate_state(candidate_id)
        allowed = ALLOWED_CANDIDATE_TRANSITIONS.get(cur, frozenset())

        if cur == CandidateState.APPROVED and to_state == CandidateState.CHECKS_PASSED and not void_approval:
            msg = f"Illegal candidate transition {candidate_id}: APPROVED -> CHECKS_PASSED requires void_approval=True"
            self.logger.record(
                event_type="state_transition",
                args={
                    "entity": "candidate",
                    "candidate_id": candidate_id,
                    "from_state": cur.value,
                    "to_state": to_state.value,
                    "reason": reason,
                },
                exit_code=1,
                error=msg,
            )
            raise IllegalStateTransitionError(msg)

        if cur in (
            CandidateState.GUARD_REJECTED,
            CandidateState.PATCH_FAILED,
            CandidateState.REGRESSION,
        ) and to_state == CandidateState.PATCH_PROPOSED:
            rep = self.get_candidate_repair_info(candidate_id)
            if rep["repair_count"] > max_repairs:
                msg = (
                    f"Illegal candidate transition {candidate_id}: {cur.value} -> PATCH_PROPOSED "
                    f"exceeds max_repairs={max_repairs}"
                )
                self.logger.record(
                    event_type="state_transition",
                    args={
                        "entity": "candidate",
                        "candidate_id": candidate_id,
                        "from_state": cur.value,
                        "to_state": to_state.value,
                        "reason": reason,
                    },
                    exit_code=1,
                    error=msg,
                )
                raise IllegalStateTransitionError(msg)

        if to_state not in allowed:
            msg = f"Illegal candidate transition {candidate_id}: {cur.value} -> {to_state.value}"
            self.logger.record(
                event_type="state_transition",
                args={
                    "entity": "candidate",
                    "candidate_id": candidate_id,
                    "from_state": cur.value,
                    "to_state": to_state.value,
                    "reason": reason,
                },
                exit_code=1,
                error=msg,
            )
            raise IllegalStateTransitionError(msg)

        self.logger.record(
            event_type="state_transition",
            args={
                "entity": "candidate",
                "candidate_id": candidate_id,
                "from_state": cur.value,
                "to_state": to_state.value,
                "reason": reason,
            },
            result_payload={"candidate_id": candidate_id, "state": to_state.value},
            exit_code=0,
            duration_ms=0,
        )
        return rebuild_state_from_events(self.run_dir)

    def record_candidate_repair_failure(
        self,
        candidate_id: str,
        signature: str,
        reason: str,
    ) -> dict[str, Any]:
        """Persist per-candidate repair count and failure signature inside the run directory."""
        self.logger.record(
            event_type="state_transition",
            args={
                "entity": "candidate_repair",
                "candidate_id": candidate_id,
                "signature": signature,
                "reason": reason,
            },
            result_payload={"candidate_id": candidate_id, "signature": signature},
            exit_code=0,
            duration_ms=0,
        )
        return rebuild_state_from_events(self.run_dir)

    def write_envelope(
        self,
        path: Path,
        *,
        stage: str,
        input_hash: str,
        status: str,
        payload: dict[str, Any],
        candidate_id: str | None = None,
    ) -> ArtifactEnvelope:
        """Atomically write stage envelope (temp file -> rename), then append event to events.jsonl."""
        payload_sha = canonical_sha256(payload)
        env = ArtifactEnvelope(
            run_id=self.run_id,
            stage=stage,
            candidate_id=candidate_id,
            input_hash=input_hash,
            created_at=datetime.now(timezone.utc).isoformat(),
            status=status,
            payload_sha256=payload_sha,
            payload=payload,
        )
        resolved = path.resolve()
        rel_path = resolved.relative_to(self.run_dir).as_posix()
        atomic_write_text(resolved, env.model_dump_json(indent=2) + "\n")
        self.logger.record(
            event_type="artifact_event",
            args={
                "action": "artifact_written",
                "stage": stage,
                "candidate_id": candidate_id,
                "path": rel_path,
                "input_hash": input_hash,
                "payload_sha256": payload_sha,
                "status": status,
            },
            result_payload={"path": rel_path, "payload_sha256": payload_sha},
            exit_code=0,
            duration_ms=0,
        )
        return env

    def try_load_valid_artifact(
        self,
        path: Path,
        expected_input_hash: str,
        stage: str,
        candidate_id: str | None = None,
    ) -> ArtifactEnvelope | None:
        """Return valid cached stage artifact on resume, or log corruption/staleness and return None."""
        resolved = path.resolve()
        if not resolved.exists():
            return None
        rel_path = resolved.relative_to(self.run_dir).as_posix()
        try:
            env = read_stage_artifact(resolved, expected_input_hash=expected_input_hash)
            self.logger.record(
                event_type="artifact_event",
                args={
                    "action": "stage_skipped_resumed",
                    "stage": stage,
                    "candidate_id": candidate_id,
                    "path": rel_path,
                    "input_hash": expected_input_hash,
                },
                result_payload={"skipped": True, "path": rel_path},
                exit_code=0,
                duration_ms=0,
            )
            return env
        except CorruptedArtifactError as exc:
            self.logger.record(
                event_type="artifact_event",
                args={
                    "action": "artifact_corrupted",
                    "stage": stage,
                    "candidate_id": candidate_id,
                    "path": rel_path,
                },
                exit_code=1,
                error=str(exc),
            )
            return None
        except StaleArtifactInputError as exc:
            self.logger.record(
                event_type="artifact_event",
                args={
                    "action": "artifact_stale_redoing",
                    "stage": stage,
                    "candidate_id": candidate_id,
                    "path": rel_path,
                },
                exit_code=0,
                error=str(exc),
            )
            return None

