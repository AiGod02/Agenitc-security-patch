"""Deterministic replay inspector for recorded run events (Slice S10, Section 9)."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from contracts import Event

REPLAY_BANNER = "[REPLAY MODE — RECORDED ARTIFACTS ONLY, NO LIVE MODEL OR SANDBOX EXECUTION]"


@dataclass
class ReplayStep:
    event: Event
    recorded_outcome: Any


@dataclass
class ReplayReport:
    banner: str
    run_id: str
    total_events: int
    stages_seen: list[str]
    steps: list[ReplayStep]

    def format_text(self) -> str:
        lines = [
            self.banner,
            f"[REPLAY] run_id={self.run_id} total_events={self.total_events} stages={','.join(self.stages_seen)}",
        ]
        for step in self.steps:
            ev = step.event
            detail = ev.args.get("tool_name") or ev.args.get("model_id") or ev.args.get("stage") or ev.event_type
            lines.append(
                f"[REPLAY] seq={ev.seq:03d} stage={ev.stage} type={ev.event_type} detail={detail} exit={ev.exit_code} ms={ev.duration_ms}"
            )
        return "\n".join(lines)


def replay_run(run_dir: Path) -> ReplayReport:
    """Reconstruct and inspect a recorded run without calling models or executing commands."""
    events_path = run_dir / "events.jsonl"
    if not events_path.exists():
        raise FileNotFoundError(f"No events.jsonl found in {run_dir}")

    raw_lines = [ln for ln in events_path.read_text(encoding="utf-8").splitlines() if ln.strip()]
    if not raw_lines:
        raise ValueError(f"events.jsonl is empty in {run_dir}")

    steps: list[ReplayStep] = []
    stages_seen: list[str] = []
    expected_seq = 1
    run_id = ""

    for raw in raw_lines:
        ev = Event.model_validate_json(raw)
        if ev.seq != expected_seq:
            raise ValueError(f"Event sequence gap: expected seq={expected_seq}, got {ev.seq}")
        expected_seq += 1
        run_id = ev.run_id
        if ev.stage not in stages_seen:
            stages_seen.append(ev.stage)

        outcome: Any = None
        if ev.result_ref:
            blob_path = run_dir / ev.result_ref
            if not blob_path.exists():
                raise FileNotFoundError(f"Missing recorded result blob: {blob_path}")
            outcome = json.loads(blob_path.read_text(encoding="utf-8"))
        steps.append(ReplayStep(event=ev, recorded_outcome=outcome))

    return ReplayReport(
        banner=REPLAY_BANNER,
        run_id=run_id,
        total_events=len(steps),
        stages_seen=stages_seen,
        steps=steps,
    )
