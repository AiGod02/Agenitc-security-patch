"""Thin FastAPI wrapper over verified CLI/evidence/approval/pipeline functions + live repository ingestion."""

from __future__ import annotations

from datetime import datetime, timezone
import json
from pathlib import Path
import re
import threading
from typing import Any
import uuid

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
from agent.ingest import prepare_ingested_target
from agent.llm import MetaLLMClient
from agent.sandbox import DockerSandbox
from agent.workflow import run_pipeline, stage_apply, stage_approve
from agent.workflow.state import atomic_write_json
from contracts import FinalPatchStatus, VerificationStatus
from eval.report import score_single_run


def _summarize_run_dir(run_dir: Path) -> dict[str, Any]:
    summary_file = run_dir / "run_summary.json"
    if summary_file.exists():
        return json.loads(summary_file.read_text(encoding="utf-8"))

    state_doc: dict[str, Any] = {}
    if (run_dir / "state.json").exists():
        state_doc = json.loads((run_dir / "state.json").read_text(encoding="utf-8"))
    elif (run_dir / "live_job.json").exists():
        job_doc = json.loads((run_dir / "live_job.json").read_text(encoding="utf-8"))
        state_doc = {"run_id": job_doc.get("run_id", run_dir.name), "run_state": job_doc.get("job_status", "PREPARING")}

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


class StartRunPayload(BaseModel):
    repo_source: str
    subdir: str = ""
    run_id: str | None = None
    max_candidates: int | None = 3
    use_cache: bool = True


class ApprovePayload(BaseModel):
    reviewer: str
    patch_sha256: str
    target_branch: str
    notes: str = ""


class ApplyPayload(BaseModel):
    repo_dir: str = ""
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

    app = FastAPI(title="Verified Security Patch Agent Review API", version="0.2.0")

    def _resolve_run(run_id: str) -> Path:
        candidate = (effective_runs / run_id).resolve()
        try:
            candidate.relative_to(effective_runs)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail="Invalid run_id") from exc
        if not candidate.exists() or not (
            (candidate / "run_summary.json").exists()
            or (candidate / "state.json").exists()
            or (candidate / "live_job.json").exists()
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
        for entry in sorted(effective_runs.iterdir(), reverse=True):
            if entry.is_dir() and (
                (entry / "run_summary.json").exists()
                or (entry / "state.json").exists()
                or (entry / "live_job.json").exists()
            ):
                items.append(_summarize_run_dir(entry))
        return {"runs": items}

    @app.post("/api/runs/start")
    def post_start_run(payload: StartRunPayload) -> dict[str, Any]:
        repo_src = payload.repo_source.strip()
        if not repo_src:
            raise HTTPException(status_code=400, detail="repo_source is required")

        if payload.run_id:
            clean_id = re.sub(r"[^A-Za-z0-9_.-]+", "-", payload.run_id.strip()).strip("-")
            if not clean_id:
                raise HTTPException(status_code=400, detail="Invalid run_id")
        else:
            slug_base = repo_src.rstrip("/").split("/")[-1].replace(".git", "")
            slug = re.sub(r"[^A-Za-z0-9]+", "-", slug_base).strip("-").lower()[:24] or "scan"
            clean_id = f"{slug}-{uuid.uuid4().hex[:6]}"

        effective_runs.mkdir(parents=True, exist_ok=True)
        run_dir = (effective_runs / clean_id).resolve()
        try:
            run_dir.relative_to(effective_runs)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail="Invalid run_id") from exc

        run_dir.mkdir(parents=True, exist_ok=True)
        job_file = run_dir / "live_job.json"
        atomic_write_json(
            job_file,
            {
                "run_id": clean_id,
                "repo_source": repo_src,
                "subdir": payload.subdir,
                "max_candidates": payload.max_candidates,
                "job_status": "PREPARING",
                "phase_detail": "Cloning repository & preparing offline Docker sandbox image...",
                "started_at": datetime.now(timezone.utc).isoformat(),
                "error": None,
            },
        )

        def _worker() -> None:
            try:
                meta = prepare_ingested_target(
                    repo_source=repo_src,
                    run_dir=run_dir,
                    subdir=payload.subdir,
                    build_custom_image=True,
                )
                atomic_write_json(
                    job_file,
                    {
                        "run_id": clean_id,
                        "repo_source": repo_src,
                        "subdir": payload.subdir,
                        "max_candidates": payload.max_candidates,
                        "job_status": "RUNNING",
                        "phase_detail": f"Executing staged pipeline in isolated container ({meta['sandbox_image']})...",
                        "sandbox_image": meta["sandbox_image"],
                        "started_at": datetime.now(timezone.utc).isoformat(),
                        "error": None,
                    },
                )
                sandbox = DockerSandbox(image=meta["sandbox_image"], agent_tag=clean_id[:12])
                gt_arg = effective_gt if (meta.get("is_builtin_fixture") and effective_gt.exists()) else None
                run_pipeline(
                    target_dir=Path(meta["prepared_target"]),
                    run_dir=run_dir,
                    run_id=clean_id,
                    max_candidates=payload.max_candidates,
                    ground_truth_path=gt_arg,
                    sandbox=sandbox,
                    use_cache=payload.use_cache,
                )
                final_state = "AWAITING_APPROVAL"
                if (run_dir / "state.json").exists():
                    final_state = json.loads((run_dir / "state.json").read_text(encoding="utf-8")).get(
                        "run_state", "AWAITING_APPROVAL"
                    )
                routes_found = 0
                if (run_dir / "01_recon.json").exists():
                    try:
                        r_doc = json.loads((run_dir / "01_recon.json").read_text(encoding="utf-8"))
                        routes_found = len((r_doc.get("payload") or {}).get("routes") or [])
                    except Exception:
                        pass

                if routes_found == 0:
                    phase_msg = "Recon complete: 0 Express routes detected. Target is not a Node.js/Express backend or has no standard app.get/post/router routes."
                else:
                    phase_msg = "Pipeline complete. Ready for human review & SHA-256 approval."

                atomic_write_json(
                    job_file,
                    {
                        "run_id": clean_id,
                        "repo_source": repo_src,
                        "subdir": payload.subdir,
                        "max_candidates": payload.max_candidates,
                        "job_status": final_state,
                        "phase_detail": phase_msg,
                        "sandbox_image": meta["sandbox_image"],
                        "finished_at": datetime.now(timezone.utc).isoformat(),
                        "error": None,
                    },
                )
            except Exception as exc:
                atomic_write_json(
                    job_file,
                    {
                        "run_id": clean_id,
                        "repo_source": repo_src,
                        "subdir": payload.subdir,
                        "max_candidates": payload.max_candidates,
                        "job_status": "FAILED",
                        "phase_detail": f"Failed: {exc}",
                        "finished_at": datetime.now(timezone.utc).isoformat(),
                        "error": str(exc),
                    },
                )

        t = threading.Thread(target=_worker, name=f"psa-run-{clean_id}", daemon=True)
        t.start()
        return {"run_id": clean_id, "job_status": "PREPARING"}

    @app.get("/api/runs/{run_id}/live")
    def get_run_live_status(run_id: str) -> dict[str, Any]:
        run_dir = _resolve_run(run_id)
        job_doc: dict[str, Any] = {}
        if (run_dir / "live_job.json").exists():
            job_doc = json.loads((run_dir / "live_job.json").read_text(encoding="utf-8"))

        ingest_doc: dict[str, Any] = {}
        if (run_dir / "ingest_meta.json").exists():
            ingest_doc = json.loads((run_dir / "ingest_meta.json").read_text(encoding="utf-8"))

        state_doc: dict[str, Any] = {}
        if (run_dir / "state.json").exists():
            state_doc = json.loads((run_dir / "state.json").read_text(encoding="utf-8"))

        summary = _summarize_run_dir(run_dir)
        cand_states = state_doc.get("candidates") or {}

        candidates_view: list[dict[str, Any]] = []
        if (run_dir / "02_candidates.json").exists():
            c_env = json.loads((run_dir / "02_candidates.json").read_text(encoding="utf-8"))
            for c in (c_env.get("payload") or {}).get("accepted") or []:
                cid = str(c["id"])
                st_info = cand_states.get(cid) or {}
                candidates_view.append(
                    {
                        "id": cid,
                        "vulnerability_class": c.get("vulnerability_class"),
                        "route": c.get("route"),
                        "file": f"{c.get('file')}:{c.get('start_line')}-{c.get('end_line')}",
                        "invariant_id": c.get("invariant_id"),
                        "state": st_info.get("state", "PROPOSED"),
                        "repair_count": st_info.get("repair_count", 0),
                        "last_reason": st_info.get("last_reason"),
                    }
                )

        recent_events: list[dict[str, Any]] = []
        events_fp = run_dir / "events.jsonl"
        if events_fp.exists():
            raw_lines = [ln for ln in events_fp.read_text(encoding="utf-8").splitlines() if ln.strip()]
            for ln in raw_lines[-30:]:
                try:
                    ev = json.loads(ln)
                    recent_events.append(
                        {
                            "seq": ev.get("seq"),
                            "timestamp": ev.get("timestamp"),
                            "stage": ev.get("stage"),
                            "event_type": ev.get("event_type"),
                            "args": ev.get("args"),
                            "duration_ms": ev.get("duration_ms"),
                            "error": ev.get("error"),
                        }
                    )
                except Exception:
                    continue

        run_state = state_doc.get("run_state") or summary.get("state") or "PREPARING"
        job_status = job_doc.get("job_status") or run_state
        if job_status == "RUNNING" and run_state in ("AWAITING_APPROVAL", "APPROVED", "APPLIED"):
            job_status = run_state

        return {
            "run_id": summary["run_id"],
            "job_status": job_status,
            "run_state": run_state,
            "phase_detail": job_doc.get("phase_detail") or f"Stage: {run_state}",
            "error": job_doc.get("error"),
            "ingest": ingest_doc,
            "routes_discovered": summary["routes_discovered"],
            "candidates_accepted": summary["candidates_accepted"],
            "verified_reproducers": summary["verified_reproducers"],
            "not_reproduced": summary["not_reproduced"],
            "patches_passed": summary["patches_passed"],
            "candidates": candidates_view,
            "recent_events": recent_events,
        }

    @app.get("/api/runs/{run_id}")
    def get_run_detail(run_id: str) -> dict[str, Any]:
        run_dir = _resolve_run(run_id)
        summary = _summarize_run_dir(run_dir)
        ingest_doc: dict[str, Any] = {}
        if (run_dir / "ingest_meta.json").exists():
            ingest_doc = json.loads((run_dir / "ingest_meta.json").read_text(encoding="utf-8"))

        evidence_root = (run_dir / "06_evidence") if (run_dir / "06_evidence").exists() else (run_dir / "bundles")
        findings: list[dict[str, Any]] = []
        if evidence_root.exists():
            for fjson in sorted(evidence_root.glob("*/finding.json")):
                data = json.loads(fjson.read_text(encoding="utf-8"))
                cid = str((data.get("candidate") or {}).get("id") or fjson.parent.name)
                approval_file = fjson.parent / "approval.json"
                data["approval"] = (
                    json.loads(approval_file.read_text(encoding="utf-8"))
                    if approval_file.exists()
                    else None
                )
                adv_file = fjson.parent / "advisory.md"
                data["advisory_markdown"] = adv_file.read_text(encoding="utf-8") if adv_file.exists() else None
                plan_file = run_dir / "04_patches" / cid / "patch_plan.json"
                if plan_file.exists():
                    try:
                        data["patch_plan"] = json.loads(plan_file.read_text(encoding="utf-8")).get("payload")
                    except Exception:
                        data["patch_plan"] = None
                findings.append(data)

        has_candidates = (run_dir / "02_candidates.json").exists() or (run_dir / "candidates.json").exists()
        is_fixture = bool(ingest_doc.get("is_builtin_fixture", True))
        metrics = (
            score_single_run(run_dir, effective_gt)
            if (effective_gt.exists() and has_candidates and is_fixture)
            else None
        )
        return {"summary": summary, "ingest": ingest_doc, "findings": findings, "metrics": metrics}

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
        eff_repo_str = payload.repo_dir.strip()
        eff_subdir = payload.subdir_in_repo.strip()
        if not eff_repo_str and (run_dir / "ingest_meta.json").exists():
            meta = json.loads((run_dir / "ingest_meta.json").read_text(encoding="utf-8"))
            eff_repo_str = str(meta.get("apply_repo_dir") or "").strip()
            if not eff_subdir:
                eff_subdir = str(meta.get("apply_subdir") or "").strip()
        if not eff_repo_str:
            raise HTTPException(
                status_code=400,
                detail="No cloned git repository associated with this run; supply repo_dir explicitly.",
            )

        try:
            if (run_dir / "state.json").exists() and (run_dir / "06_evidence" / finding_id).exists():
                return stage_apply(
                    run_dir=run_dir,
                    repo_dir=Path(eff_repo_str),
                    candidate_id=finding_id,
                    target_branch=payload.target_branch,
                    subdir_in_repo=eff_subdir,
                )
            return apply_approved_patch_to_branch(
                repo_dir=Path(eff_repo_str),
                bundle_dir=bundle,
                target_branch=payload.target_branch,
                subdir_in_repo=eff_subdir,
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
