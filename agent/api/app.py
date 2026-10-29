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
from agent.workflow import stage_apply, stage_approve
from contracts import FinalPatchStatus, VerificationStatus
from eval.report import score_single_run


def _summarize_run_dir(run_dir: Path) -> dict[str, Any]:
    summary_file = run_dir / "run_summary.json"
    if summary_file.exists():
        return json.loads(summary_file.read_text(encoding="utf-8"))

    state_doc = json.loads((run_dir / "state.json").read_text(encoding="utf-8"))
    routes_count = 0
    if (run_dir / "01_recon.json").exists():
        r_doc = json.loads((run_dir / "01_recon.json").read_text(encoding="utf-8"))
        routes_count = len((r_doc.get("payload") or {}).get("routes") or [])

    cand_acc = 0
    cand_rej = 0
    if (run_dir / "02_candidates.json").exists():
        c_doc = json.loads((run_dir / "02_candidates.json").read_text(encoding="utf-8"))
        cp = c_doc.get("payload") or {}
        cand_acc = len(cp.get("accepted") or [])
        cand_rej = len(cp.get("rejected") or [])

    ver_rep = 0
    not_rep = 0
    inconc = 0
    ver_dir = run_dir / "03_verification"
    if ver_dir.exists():
        for fp in sorted(ver_dir.glob("*.json")):
            if fp.name.endswith(".jest.json"):
                continue
            st = json.loads(fp.read_text(encoding="utf-8")).get("status")
            if st == VerificationStatus.VERIFIED_REPRODUCER.value:
                ver_rep += 1
            elif st == VerificationStatus.NOT_REPRODUCED.value:
                not_rep += 1
            else:
                inconc += 1

    p_pass = 0
    p_fail = 0
    chk_dir = run_dir / "05_checks"
    if chk_dir.exists():
        for fp in sorted(chk_dir.glob("*.json")):
            st = json.loads(fp.read_text(encoding="utf-8")).get("status")
            if st == FinalPatchStatus.PASS.value:
                p_pass += 1
            else:
                p_fail += 1

    return {
        "run_id": state_doc.get("run_id", run_dir.name),
        "duration_ms": 0,
        "routes_discovered": routes_count,
        "candidates_accepted": cand_acc,
        "candidates_rejected": cand_rej,
        "verified_reproducers": ver_rep,
        "not_reproduced": not_rep,
        "inconclusive": inconc,
        "patches_passed": p_pass,
        "patches_failed": p_fail,
        "state": state_doc.get("run_state", "UNKNOWN"),
    }


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
        if not candidate.exists() or not (
            (candidate / "run_summary.json").exists() or (candidate / "state.json").exists()
        ):
            raise HTTPException(status_code=404, detail=f"Run not found: {run_id}")
        return candidate

    def _resolve_bundle(run_id: str, finding_id: str) -> Path:
        run_dir = _resolve_run(run_id)
        for sub in ("06_evidence", "bundles"):
            bundle = (run_dir / sub / finding_id).resolve()
            try:
                bundle.relative_to(run_dir)
            except ValueError as exc:
                raise HTTPException(status_code=400, detail="Invalid finding_id") from exc
            if bundle.exists() and (bundle / "finding.json").exists():
                return bundle
        raise HTTPException(status_code=404, detail=f"Bundle not found: {finding_id}")

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
        for entry in sorted(effective_runs.iterdir()):
            if entry.is_dir() and ((entry / "run_summary.json").exists() or (entry / "state.json").exists()):
                items.append(_summarize_run_dir(entry))
        return {"runs": items}

    @app.get("/api/runs/{run_id}")
    def get_run_detail(run_id: str) -> dict[str, Any]:
        run_dir = _resolve_run(run_id)
        summary = _summarize_run_dir(run_dir)
        evidence_root = (run_dir / "06_evidence") if (run_dir / "06_evidence").exists() else (run_dir / "bundles")
        findings: list[dict[str, Any]] = []
        if evidence_root.exists():
            for fjson in sorted(evidence_root.glob("*/finding.json")):
                data = json.loads(fjson.read_text(encoding="utf-8"))
                approval_file = fjson.parent / "approval.json"
                data["approval"] = (
                    json.loads(approval_file.read_text(encoding="utf-8"))
                    if approval_file.exists()
                    else None
                )
                adv_file = fjson.parent / "advisory.md"
                data["advisory_markdown"] = adv_file.read_text(encoding="utf-8") if adv_file.exists() else None
                findings.append(data)
        has_candidates = (run_dir / "02_candidates.json").exists() or (run_dir / "candidates.json").exists()
        metrics = score_single_run(run_dir, effective_gt) if (effective_gt.exists() and has_candidates) else None
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
        run_dir = _resolve_run(run_id)
        bundle = _resolve_bundle(run_id, finding_id)
        try:
            if (run_dir / "state.json").exists() and (run_dir / "06_evidence" / finding_id).exists():
                rec = stage_approve(
                    run_dir=run_dir,
                    candidate_id=finding_id,
                    reviewer=payload.reviewer,
                    expected_patch_sha256=payload.patch_sha256,
                    target_branch=payload.target_branch,
                    notes=payload.notes,
                )
                return rec.model_dump()
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
        run_dir = _resolve_run(run_id)
        bundle = _resolve_bundle(run_id, finding_id)
        try:
            if (run_dir / "state.json").exists() and (run_dir / "06_evidence" / finding_id).exists():
                return stage_apply(
                    run_dir=run_dir,
                    repo_dir=Path(payload.repo_dir),
                    candidate_id=finding_id,
                    target_branch=payload.target_branch,
                    subdir_in_repo=payload.subdir_in_repo,
                )
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

