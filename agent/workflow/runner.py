"""End-to-end workflow state machine (Slice S11, Section 4)."""

from __future__ import annotations

import json
import shutil
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from agent.detect import generate_candidates
from agent.evidence import (
    EventLogger,
    LoggingDispatcherWrapper,
    LoggingLLMWrapper,
    write_evidence_bundle,
)
from agent.llm import MetaLLMClient
from agent.patch import remediate_verified_finding
from agent.recon import build_route_inventory
from agent.sandbox import DockerSandbox
from agent.tools import ToolDispatcher
from agent.verify import SingleVerifyOutcome, verify_candidate
from contracts import (
    Candidate,
    FinalPatchStatus,
    LLMClient,
    PatchResult,
    RouteEntry,
    SandboxRunner,
    VerificationResult,
    VerificationStatus,
    VulnerabilityClass,
)


@dataclass
class WorkflowRunArtifacts:
    run_id: str
    run_dir: Path
    routes: list[RouteEntry]
    candidates: list[Candidate]
    rejected_candidates: list[dict[str, Any]]
    verifications: list[VerificationResult]
    patches: list[PatchResult]
    bundles: dict[str, Path]
    duration_ms: int


def run_security_workflow(
    target_dir: Path,
    runs_root: Path,
    run_id: str | None = None,
    sandbox: SandboxRunner | None = None,
    llm: LLMClient | None = None,
    use_cache: bool = True,
    max_candidates: int | None = None,
    skip_patch: bool = False,
    enabled_classes: set[VulnerabilityClass] | None = None,
) -> WorkflowRunArtifacts:
    """Execute RECON -> CANDIDATES -> EXPECTED_FAILURE -> TEST_GEN -> VERIFY -> PATCH -> CHECKS -> EVIDENCE -> AWAITING_APPROVAL."""
    start_time = time.perf_counter()
    effective_run_id = run_id or f"run-{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}-{uuid.uuid4().hex[:6]}"
    run_dir = (runs_root / effective_run_id).resolve()
    run_dir.mkdir(parents=True, exist_ok=True)

    # Work exclusively in a disposable copy of target_dir (Section 7: original repo never modified before approval)
    disposable_ws = run_dir / "workspace_copy"
    if disposable_ws.exists():
        shutil.rmtree(disposable_ws)
    shutil.copytree(
        target_dir.resolve(),
        disposable_ws,
        ignore=shutil.ignore_patterns("node_modules", ".git", "runs", ".llm_cache"),
    )

    event_logger = EventLogger(run_dir=run_dir, run_id=effective_run_id)
    effective_sandbox = sandbox or DockerSandbox(image="psa-sandbox:latest", agent_tag=effective_run_id[:12])
    raw_llm = llm or MetaLLMClient(log_path=run_dir / "llm_calls.jsonl", use_cache=use_cache)

    wrapped_llm = LoggingLLMWrapper(raw_llm, event_logger)
    base_disp = ToolDispatcher(disposable_ws, effective_sandbox, max_calls=500)
    wrapped_disp = LoggingDispatcherWrapper(base_disp, event_logger)

    # Stage 1: RECON
    event_logger.set_stage("RECON")
    routes = build_route_inventory(effective_run_id, wrapped_disp)
    (run_dir / "recon_routes.json").write_text(
        json.dumps([r.model_dump() for r in routes], indent=2),
        encoding="utf-8",
    )

    # Stage 2 & 3: CANDIDATES & EXPECTED_FAILURE
    event_logger.set_stage("CANDIDATES")
    cand_batch = generate_candidates(
        run_id=effective_run_id,
        dispatcher=wrapped_disp,
        llm=wrapped_llm,
        routes=routes,
        enabled_classes=enabled_classes,
    )
    event_logger.set_stage("EXPECTED_FAILURE")
    selected_candidates = (
        cand_batch.accepted[:max_candidates] if max_candidates is not None else cand_batch.accepted
    )
    rejected_serialized = [{"raw": r.raw, "reason": r.reason} for r in cand_batch.rejected]
    (run_dir / "candidates.json").write_text(
        json.dumps(
            {
                "accepted": [c.model_dump() for c in selected_candidates],
                "rejected": rejected_serialized,
            },
            indent=2,
        ),
        encoding="utf-8",
    )

    # Stage 4 & 5: TEST_GEN & VERIFY
    verifications: list[VerificationResult] = []
    verified_outcomes: list[SingleVerifyOutcome] = []

    for cand in selected_candidates:
        event_logger.set_stage("TEST_GEN")
        event_logger.set_stage("VERIFY")
        outcome = verify_candidate(
            run_id=effective_run_id,
            candidate=cand,
            dispatcher=wrapped_disp,
            llm=wrapped_llm,
            keep_generated_files=False,
        )
        # Clean up any verified test files left on disposable_ws so the next candidate verifies cleanly
        for rel in (outcome.verification.test_path, outcome.verification.companion_test_path):
            if rel and (disposable_ws / rel).exists():
                (disposable_ws / rel).unlink()

        verifications.append(outcome.verification)
        if outcome.verification.status == VerificationStatus.VERIFIED_REPRODUCER and outcome.verified_finding is not None:
            verified_outcomes.append(outcome)

    # Stage 6, 7, 8: PATCH -> CHECKS -> EVIDENCE -> AWAITING_APPROVAL
    patches: list[PatchResult] = []
    bundles: dict[str, Path] = {}

    for v_outcome in verified_outcomes:
        vf = v_outcome.verified_finding
        assert vf is not None
        patch_res: PatchResult | None = None
        if not skip_patch:
            event_logger.set_stage("PATCH")
            event_logger.set_stage("CHECKS")
            patch_res = remediate_verified_finding(
                run_id=effective_run_id,
                verified_finding=vf,
                security_test_code=v_outcome.security_test_code,
                companion_test_code=v_outcome.companion_test_code,
                source_workspace=disposable_ws,
                sandbox=effective_sandbox,
                llm=wrapped_llm,
            )
            patches.append(patch_res)
            vf.verification.patched_security_exit_code = patch_res.patched_security_exit_code
            vf.verification.companion_after_exit_code = patch_res.companion_after_exit_code
            vf.verification.full_suite_exit_code = patch_res.full_suite_exit_code
            vf.verification.guards_passed = patch_res.guards_passed
            vf.verification.final_status = patch_res.final_status

        event_logger.set_stage("EVIDENCE")
        bundle_path = write_evidence_bundle(
            run_dir=run_dir,
            verified_finding=vf,
            security_test_code=v_outcome.security_test_code,
            companion_test_code=v_outcome.companion_test_code,
            baseline_stdout=v_outcome.baseline_stdout,
            patch_result=patch_res,
        )
        bundles[vf.candidate.id] = bundle_path

    event_logger.set_stage("AWAITING_APPROVAL")

    (run_dir / "verifications.json").write_text(
        json.dumps([v.model_dump() for v in verifications], indent=2),
        encoding="utf-8",
    )
    (run_dir / "patches.json").write_text(
        json.dumps([p.model_dump() for p in patches], indent=2),
        encoding="utf-8",
    )

    duration_ms = int((time.perf_counter() - start_time) * 1000)
    summary = {
        "run_id": effective_run_id,
        "target_dir": str(target_dir.resolve()),
        "duration_ms": duration_ms,
        "routes_discovered": len(routes),
        "candidates_accepted": len(selected_candidates),
        "candidates_rejected": len(rejected_serialized),
        "verified_reproducers": sum(1 for v in verifications if v.status == VerificationStatus.VERIFIED_REPRODUCER),
        "not_reproduced": sum(1 for v in verifications if v.status == VerificationStatus.NOT_REPRODUCED),
        "inconclusive": sum(1 for v in verifications if v.status == VerificationStatus.INCONCLUSIVE),
        "patches_passed": sum(1 for p in patches if p.final_status == FinalPatchStatus.PASS),
        "patches_failed": sum(1 for p in patches if p.final_status != FinalPatchStatus.PASS),
        "state": "AWAITING_APPROVAL",
    }
    (run_dir / "run_summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")

    return WorkflowRunArtifacts(
        run_id=effective_run_id,
        run_dir=run_dir,
        routes=routes,
        candidates=selected_candidates,
        rejected_candidates=rejected_serialized,
        verifications=verifications,
        patches=patches,
        bundles=bundles,
        duration_ms=duration_ms,
    )
