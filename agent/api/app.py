"""Thin FastAPI wrapper over verified CLI/evidence/approval functions (Slice S13)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse
from pydantic import BaseModel

from agent.advisory import generate_architecture_advisory
from agent.evidence import (
    ApprovalError,
    apply_approved_patch_to_branch,
    approve_finding_patch,
    replay_run,
)
from agent.llm import MetaLLMClient
from eval.report import score_single_run


class ApprovePayload(BaseModel):
    reviewer: str
    patch_sha256: str
    target_branch: str
    notes: str = ""


class ApplyPayload(BaseModel):
    repo_dir: str
    target_branch: str | None = None
    subdir_in_repo: str = ""


def create_review_api(
    runs_root: Path | None = None,
    ground_truth_path: Path | None = None,
    ui_html_path: Path | None = None,
) -> FastAPI:
    root_dir = Path(__file__).resolve().parents[2]
    effective_runs = (runs_root or (root_dir / "runs")).resolve()
    effective_gt = (ground_truth_path or (root_dir / "ground_truth.json")).resolve()
    effective_ui = (ui_html_path or (root_dir / "ui" / "index.html")).resolve()

    app = FastAPI(title="Verified Security Patch Agent Review API", version="0.1.0")

    def _resolve_run(run_id: str) -> Path:
        candidate = (effective_runs / run_id).resolve()
        try:
            candidate.relative_to(effective_runs)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail="Invalid run_id") from exc
        if not candidate.exists() or not (candidate / "run_summary.json").exists():
            raise HTTPException(status_code=404, detail=f"Run not found: {run_id}")
        return candidate

    def _resolve_bundle(run_id: str, finding_id: str) -> Path:
        run_dir = _resolve_run(run_id)
        bundle = (run_dir / "bundles" / finding_id).resolve()
        try:
            bundle.relative_to(run_dir)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail="Invalid finding_id") from exc
        if not bundle.exists() or not (bundle / "finding.json").exists():
            raise HTTPException(status_code=404, detail=f"Bundle not found: {finding_id}")
        return bundle

    @app.get("/", response_class=HTMLResponse)
    def serve_ui() -> str:
        if not effective_ui.exists():
            raise HTTPException(status_code=404, detail="UI file not found")
        return effective_ui.read_text(encoding="utf-8")

    @app.get("/api/runs")
    def list_runs() -> dict[str, list[dict[str, Any]]]:
        if not effective_runs.exists():
            return {"runs": []}
        items: list[dict[str, Any]] = []
        for summary_file in sorted(effective_runs.glob("*/run_summary.json")):
            items.append(json.loads(summary_file.read_text(encoding="utf-8")))
        return {"runs": items}

    @app.get("/api/runs/{run_id}")
    def get_run_detail(run_id: str) -> dict[str, Any]:
        run_dir = _resolve_run(run_id)
        summary = json.loads((run_dir / "run_summary.json").read_text(encoding="utf-8"))
        bundles_dir = run_dir / "bundles"
        findings: list[dict[str, Any]] = []
        if bundles_dir.exists():
            for fjson in sorted(bundles_dir.glob("*/finding.json")):
                data = json.loads(fjson.read_text(encoding="utf-8"))
                approval_file = fjson.parent / "approval.json"
                data["approval"] = (
                    json.loads(approval_file.read_text(encoding="utf-8"))
                    if approval_file.exists()
                    else None
                )
                findings.append(data)
        metrics = score_single_run(run_dir, effective_gt) if effective_gt.exists() else None
        return {"summary": summary, "findings": findings, "metrics": metrics}

    @app.get("/api/runs/{run_id}/replay")
    def get_run_replay(run_id: str) -> dict[str, Any]:
        run_dir = _resolve_run(run_id)
        rep = replay_run(run_dir)
        return {
            "banner": rep.banner,
            "run_id": rep.run_id,
            "total_events": rep.total_events,
            "stages_seen": rep.stages_seen,
            "formatted": rep.format_text(),
        }

    @app.post("/api/runs/{run_id}/bundles/{finding_id}/approve")
    def post_approve(run_id: str, finding_id: str, payload: ApprovePayload) -> dict[str, Any]:
        bundle = _resolve_bundle(run_id, finding_id)
        try:
            rec = approve_finding_patch(
                bundle_dir=bundle,
                reviewer=payload.reviewer,
                expected_patch_sha256=payload.patch_sha256,
                target_branch=payload.target_branch,
                notes=payload.notes,
            )
            return rec.model_dump()
        except ApprovalError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.post("/api/runs/{run_id}/bundles/{finding_id}/apply")
    def post_apply(run_id: str, finding_id: str, payload: ApplyPayload) -> dict[str, Any]:
        bundle = _resolve_bundle(run_id, finding_id)
        try:
            return apply_approved_patch_to_branch(
                repo_dir=Path(payload.repo_dir),
                bundle_dir=bundle,
                target_branch=payload.target_branch,
                subdir_in_repo=payload.subdir_in_repo,
            )
        except ApprovalError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.post("/api/runs/{run_id}/bundles/{finding_id}/advisory")
    def post_advisory(run_id: str, finding_id: str) -> dict[str, Any]:
        bundle = _resolve_bundle(run_id, finding_id)
        try:
            llm = MetaLLMClient(use_cache=True)
            return generate_architecture_advisory(bundle, llm)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    return app


app = create_review_api()

