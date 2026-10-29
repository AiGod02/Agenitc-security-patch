"""Artifact-driven multi-stage pipeline wrapping existing modules (Part 1, extended in Parts 2-4)."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from agent.advisory import generate_architecture_advisory
from agent.detect import generate_candidates
from agent.evidence import (
    ApprovalError,
    LoggingDispatcherWrapper,
    LoggingLLMWrapper,
    apply_approved_patch_to_branch,
    approve_finding_patch,
    write_evidence_bundle,
)
from agent.llm import MetaLLMClient
from agent.patch.guards import normalize_failure_signature
from agent.patch.loop import PATCH_DIFF_SCHEMA, PATCH_SYSTEM_PROMPT, _strip_line_numbers, validate_candidate_diff_on_workspace
from agent.recon import build_route_inventory, extract_exported_symbols
from agent.sandbox import DockerSandbox
from agent.tools import ToolDispatcher
from agent.verify import verify_candidate
from agent.workflow.state import (
    CorruptedArtifactError,
    StateManager,
    atomic_write_json,
    atomic_write_text,
    canonical_sha256,
    read_stage_artifact,
)
from contracts import (
    ApprovalRecord,
    ArtifactEnvelope,
    Candidate,
    CandidateState,
    FinalPatchStatus,
    LLMCaps,
    LLMClient,
    ModelRole,
    PatchResult,
    RouteEntry,
    RunState,
    SandboxRunner,
    VerificationStatus,
    VerifiedFinding,
)


def _ensure_workspace_copy(run_dir: Path, target_dir: Path | None = None) -> Path:
    ws_copy = run_dir / "workspace_copy"
    meta_path = run_dir / "target_meta.json"
    if target_dir is not None:
        resolved_target = target_dir.resolve()
        if not resolved_target.exists() or not resolved_target.is_dir():
            raise FileNotFoundError(f"Target directory does not exist: {resolved_target}")
        if not ws_copy.exists():
            shutil.copytree(
                resolved_target,
                ws_copy,
                ignore=shutil.ignore_patterns("node_modules", ".git", "runs", ".llm_cache"),
            )
        atomic_write_json(meta_path, {"target_dir": str(resolved_target)})
    if not ws_copy.exists():
        if meta_path.exists():
            saved_target = Path(json.loads(meta_path.read_text(encoding="utf-8"))["target_dir"])
            if saved_target.exists():
                shutil.copytree(
                    saved_target,
                    ws_copy,
                    ignore=shutil.ignore_patterns("node_modules", ".git", "runs", ".llm_cache"),
                )
        if not ws_copy.exists():
            raise FileNotFoundError(f"Missing workspace_copy in {run_dir}; run 'recon --target <dir>' first")
    return ws_copy


def _compute_workspace_source_hash(ws_copy: Path) -> str:
    entries: dict[str, str] = {}
    for root, dirs, files in os.walk(ws_copy, followlinks=False):
        dirs[:] = sorted(d for d in dirs if d not in {"node_modules", ".git", "__pycache__"})
        for fname in sorted(files):
            fp = Path(root) / fname
            if fp.is_file() and not fp.is_symlink():
                rel = fp.relative_to(ws_copy).as_posix()
                if not rel.startswith("tests/generated/"):
                    entries[rel] = hashlib.sha256(fp.read_bytes()).hexdigest()
    return canonical_sha256(entries)


def _make_sandbox_and_llm(
    sm: StateManager,
    sandbox: SandboxRunner | None = None,
    llm: LLMClient | None = None,
    use_cache: bool = True,
) -> tuple[SandboxRunner, LoggingLLMWrapper]:
    eff_sandbox = sandbox or DockerSandbox(image="psa-sandbox:latest", agent_tag=sm.run_id[:12])
    raw_llm = llm or MetaLLMClient(log_path=sm.run_dir / "llm_calls.jsonl", use_cache=use_cache)
    return eff_sandbox, LoggingLLMWrapper(raw_llm, sm.logger)


def _read_upstream_or_redo(
    sm: StateManager,
    path: Path,
    stage_label: str,
    redo_fn: Callable[[], Any] | None = None,
) -> ArtifactEnvelope:
    try:
        return read_stage_artifact(path)
    except CorruptedArtifactError as exc:
        rel = path.resolve().relative_to(sm.run_dir).as_posix() if path.exists() else path.name
        sm.logger.record(
            event_type="artifact_event",
            args={"action": "artifact_corrupted", "stage": stage_label, "path": rel},
            exit_code=1,
            error=str(exc),
        )
        if redo_fn is not None:
            redo_fn()
            return read_stage_artifact(path)
        raise


def stage_recon(
    run_dir: Path,
    target_dir: Path | None = None,
    run_id: str | None = None,
    sandbox: SandboxRunner | None = None,
) -> Path:
    """Stage 1 (RECON): static route + export + sink/middleware/ownership inventory -> 01_recon.json."""
    sm = StateManager(run_dir, run_id=run_id)
    ws_copy = _ensure_workspace_copy(sm.run_dir, target_dir=target_dir)
    ws_hash = _compute_workspace_source_hash(ws_copy)
    out_path = sm.run_dir / "01_recon.json"

    cached = sm.try_load_valid_artifact(out_path, expected_input_hash=ws_hash, stage="RECON")
    if cached is not None:
        return out_path

    sm.transition_run(RunState.RECON, reason="starting_recon", allow_stage_redo=True)
    eff_sandbox = sandbox or DockerSandbox(image="psa-sandbox:latest", agent_tag=sm.run_id[:12])
    disp = LoggingDispatcherWrapper(ToolDispatcher(ws_copy, eff_sandbox, max_calls=500), sm.logger)

    # Use rich route inventory if available (Part 2), else base route inventory
    from agent import recon as recon_mod

    rich_builder = getattr(recon_mod, "build_rich_route_inventory", None)
    if rich_builder is not None:
        routes = rich_builder(sm.run_id, disp)
    else:
        routes = build_route_inventory(sm.run_id, disp)
    exports_map = extract_exported_symbols(sm.run_id, disp)

    payload = {
        "routes": [r.model_dump() for r in routes],
        "exports": exports_map,
    }
    sm.write_envelope(
        out_path,
        stage="RECON",
        input_hash=ws_hash,
        status="OK",
        payload=payload,
    )
    return out_path


def stage_detect(
    run_dir: Path,
    llm: LLMClient | None = None,
    sandbox: SandboxRunner | None = None,
    use_cache: bool = True,
) -> Path:
    """Stage 2 (CANDIDATES): reads ONLY 01_recon.json -> writes 02_candidates.json."""
    sm = StateManager(run_dir)
    ws_copy = _ensure_workspace_copy(sm.run_dir)
    recon_env = _read_upstream_or_redo(
        sm,
        sm.run_dir / "01_recon.json",
        "RECON",
        redo_fn=lambda: stage_recon(sm.run_dir, sandbox=sandbox),
    )
    out_path = sm.run_dir / "02_candidates.json"
    cached = sm.try_load_valid_artifact(out_path, expected_input_hash=recon_env.payload_sha256, stage="CANDIDATES")
    if cached is not None:
        return out_path

    sm.transition_run(RunState.CANDIDATES, reason="starting_candidate_detection", allow_stage_redo=True)
    eff_sandbox, wrapped_llm = _make_sandbox_and_llm(sm, sandbox=sandbox, llm=llm, use_cache=use_cache)
    disp = LoggingDispatcherWrapper(ToolDispatcher(ws_copy, eff_sandbox, max_calls=500), sm.logger)

    raw_routes = recon_env.payload.get("routes", [])
    base_routes = [
        RouteEntry(method=r["method"], path=r["path"], file=r["file"], line=r["line"])
        for r in raw_routes
    ]

    # Pass rich route metadata slice if present on recon routes
    detect_kwargs: dict[str, Any] = {
        "run_id": sm.run_id,
        "dispatcher": disp,
        "llm": wrapped_llm,
        "routes": base_routes,
    }
    import inspect

    if "rich_routes_data" in inspect.signature(generate_candidates).parameters:
        detect_kwargs["rich_routes_data"] = raw_routes

    batch = generate_candidates(**detect_kwargs)
    for cand in batch.accepted:
        sm.init_candidate(cand.id)

    rejected_serialized: list[dict[str, Any]] = []
    for idx, rej in enumerate(batch.rejected, start=1):
        rej_id = str(rej.raw.get("id") or f"INVALID-{idx:03d}")
        if not sm.has_candidate(rej_id):
            sm.init_candidate(rej_id)
            sm.transition_candidate(rej_id, CandidateState.INVALID, reason=rej.reason)
        rejected_serialized.append({"id": rej_id, "raw": rej.raw, "reason": rej.reason})

    payload = {
        "accepted": [c.model_dump() for c in batch.accepted],
        "rejected": rejected_serialized,
    }
    sm.write_envelope(
        out_path,
        stage="CANDIDATES",
        input_hash=recon_env.payload_sha256,
        status="OK",
        payload=payload,
    )
    return out_path


def stage_verify(
    run_dir: Path,
    candidate_id: str | None = None,
    max_candidates: int | None = None,
    llm: LLMClient | None = None,
    sandbox: SandboxRunner | None = None,
    use_cache: bool = True,
) -> list[Path]:
    """Stage 3 (VERIFYING): reads ONLY 02_candidates.json -> writes 03_verification/<cid>.json + tests + baseline JSON."""
    sm = StateManager(run_dir)
    ws_copy = _ensure_workspace_copy(sm.run_dir)
    cand_env = _read_upstream_or_redo(
        sm,
        sm.run_dir / "02_candidates.json",
        "CANDIDATES",
        redo_fn=lambda: stage_detect(sm.run_dir, llm=llm, sandbox=sandbox, use_cache=use_cache),
    )

    sm.transition_run(RunState.VERIFYING, reason="verifying_candidates", allow_stage_redo=True)
    eff_sandbox, wrapped_llm = _make_sandbox_and_llm(sm, sandbox=sandbox, llm=llm, use_cache=use_cache)
    disp = LoggingDispatcherWrapper(ToolDispatcher(ws_copy, eff_sandbox, max_calls=800), sm.logger)

    all_accepted = [Candidate.model_validate(c) for c in cand_env.payload.get("accepted", [])]
    if candidate_id is not None:
        selected = [c for c in all_accepted if c.id == candidate_id]
        if not selected:
            raise ValueError(f"Candidate {candidate_id} not found in 02_candidates.json")
    elif max_candidates is not None:
        selected = all_accepted[:max_candidates]
    else:
        selected = all_accepted

    ver_dir = sm.run_dir / "03_verification"
    ver_dir.mkdir(parents=True, exist_ok=True)
    written_paths: list[Path] = []

    for cand in selected:
        sm.init_candidate(cand.id)
        cid_input_hash = canonical_sha256({"candidate": cand.model_dump(), "candidates_sha": cand_env.payload_sha256})
        env_path = ver_dir / f"{cand.id}.json"
        sec_path = ver_dir / f"{cand.id}.security.test.js"
        comp_path = ver_dir / f"{cand.id}.companion.test.js"
        jest_path = ver_dir / f"{cand.id}.baseline.jest.json"

        cached = sm.try_load_valid_artifact(
            env_path,
            expected_input_hash=cid_input_hash,
            stage="VERIFYING",
            candidate_id=cand.id,
        )
        if cached is not None and sec_path.exists() and comp_path.exists() and jest_path.exists():
            written_paths.append(env_path)
            continue

        cur_cstate = sm.get_candidate_state(cand.id)
        if cur_cstate == CandidateState.PROPOSED:
            sm.transition_candidate(cand.id, CandidateState.TEST_WRITTEN, reason="generating_verification_tests")

        outcome = verify_candidate(
            run_id=sm.run_id,
            candidate=cand,
            dispatcher=disp,
            llm=wrapped_llm,
            keep_generated_files=False,
        )
        for rel in (outcome.verification.test_path, outcome.verification.companion_test_path):
            if rel and (ws_copy / rel).exists():
                (ws_copy / rel).unlink()

        atomic_write_text(sec_path, outcome.security_test_code)
        atomic_write_text(comp_path, outcome.companion_test_code)
        atomic_write_text(jest_path, outcome.baseline_stdout)

        payload = {
            "candidate": cand.model_dump(),
            "verification": outcome.verification.model_dump(),
            "verified_finding": outcome.verified_finding.model_dump() if outcome.verified_finding else None,
            "security_test_file": f"03_verification/{cand.id}.security.test.js",
            "companion_test_file": f"03_verification/{cand.id}.companion.test.js",
            "baseline_jest_file": f"03_verification/{cand.id}.baseline.jest.json",
        }
        sm.write_envelope(
            env_path,
            stage="VERIFYING",
            candidate_id=cand.id,
            input_hash=cid_input_hash,
            status=outcome.verification.status.value,
            payload=payload,
        )

        # Transition candidate from TEST_WRITTEN to terminal/next verify state if currently TEST_WRITTEN
        cur_after = sm.get_candidate_state(cand.id)
        if cur_after == CandidateState.TEST_WRITTEN:
            if outcome.verification.status == VerificationStatus.VERIFIED_REPRODUCER:
                sm.transition_candidate(cand.id, CandidateState.VERIFIED_REPRODUCER, reason="tagged_invariant_reproduced")
            elif outcome.verification.status == VerificationStatus.NOT_REPRODUCED:
                sm.transition_candidate(cand.id, CandidateState.NOT_REPRODUCED, reason="baseline_test_passed")
            else:
                sm.transition_candidate(cand.id, CandidateState.INCONCLUSIVE, reason=str(outcome.verification.match_reason))

        written_paths.append(env_path)

    return written_paths


def _iter_verified_envelopes(sm: StateManager, candidate_id: str | None = None) -> list[ArtifactEnvelope]:
    ver_dir = sm.run_dir / "03_verification"
    if not ver_dir.exists():
        return []
    out: list[ArtifactEnvelope] = []
    for fp in sorted(ver_dir.glob("*.json")):
        if fp.name.endswith(".baseline.jest.json"):
            continue
        env = read_stage_artifact(fp)
        if candidate_id is not None and env.candidate_id != candidate_id:
            continue
        if env.status == VerificationStatus.VERIFIED_REPRODUCER.value:
            out.append(env)
    return out


def stage_plan(
    run_dir: Path,
    candidate_id: str | None = None,
    llm: LLMClient | None = None,
    sandbox: SandboxRunner | None = None,
    use_cache: bool = True,
) -> list[Path]:
    """Stage 4 (PLAN): reads ONLY 03_verification/<cid>.json & 01_recon.json -> writes 04_patches/<cid>/patch_plan.json."""
    sm = StateManager(run_dir)
    ws_copy = _ensure_workspace_copy(sm.run_dir)
    recon_env = read_stage_artifact(sm.run_dir / "01_recon.json")
    verified_envs = _iter_verified_envelopes(sm, candidate_id=candidate_id)

    sm.transition_run(RunState.PATCHING, reason="planning_patches", allow_stage_redo=True)
    eff_sandbox, wrapped_llm = _make_sandbox_and_llm(sm, sandbox=sandbox, llm=llm, use_cache=use_cache)
    disp = LoggingDispatcherWrapper(ToolDispatcher(ws_copy, eff_sandbox, max_calls=500), sm.logger)

    # Delegate to Part 2 deep logic planner if present
    planner_fn = None
    try:
        from agent.plan.planner import create_verified_patch_plan

        planner_fn = create_verified_patch_plan
    except ImportError:
        planner_fn = None

    written: list[Path] = []
    for v_env in verified_envs:
        cid = str(v_env.candidate_id)
        vf = VerifiedFinding.model_validate(v_env.payload["verified_finding"])
        plan_path = sm.run_dir / "04_patches" / cid / "patch_plan.json"
        plan_input_hash = canonical_sha256({"ver_sha": v_env.payload_sha256, "recon_sha": recon_env.payload_sha256})

        cached = sm.try_load_valid_artifact(
            plan_path,
            expected_input_hash=plan_input_hash,
            stage="PLAN",
            candidate_id=cid,
        )
        if cached is not None:
            written.append(plan_path)
            continue

        if planner_fn is not None:
            sec_code = (sm.run_dir / v_env.payload["security_test_file"]).read_text(encoding="utf-8")
            comp_code = (sm.run_dir / v_env.payload["companion_test_file"]).read_text(encoding="utf-8")
            ok, plan_payload, fail_reason = planner_fn(
                run_id=sm.run_id,
                verified_finding=vf,
                recon_routes=recon_env.payload.get("routes", []),
                security_test_code=sec_code,
                companion_test_code=comp_code,
                dispatcher=disp,
                llm=wrapped_llm,
                workspace=ws_copy,
            )
            if not ok:
                sm.write_envelope(
                    plan_path,
                    stage="PLAN",
                    candidate_id=cid,
                    input_hash=plan_input_hash,
                    status="FAILED",
                    payload={"error": fail_reason, "plan": plan_payload},
                )
                if sm.get_candidate_state(cid) == CandidateState.VERIFIED_REPRODUCER:
                    sm.transition_candidate(cid, CandidateState.PATCH_FAILED, reason=fail_reason)
                written.append(plan_path)
                continue
        else:
            plan_payload = {
                "candidate_id": cid,
                "violated_invariant": vf.candidate.invariant_id,
                "expected_scope_files": [vf.candidate.file],
                "expected_approx_lines": 10,
                "root_cause": vf.candidate.reason,
            }

        sm.write_envelope(
            plan_path,
            stage="PLAN",
            candidate_id=cid,
            input_hash=plan_input_hash,
            status="PLANNED",
            payload=plan_payload,
        )
        if sm.get_candidate_state(cid) == CandidateState.VERIFIED_REPRODUCER:
            sm.transition_candidate(cid, CandidateState.PLANNED, reason="patch_plan_validated")
        written.append(plan_path)

    return written


def _propose_single_diff_via_llm(
    run_id: str,
    vf: VerifiedFinding,
    plan_payload: dict[str, Any],
    sec_code: str,
    comp_code: str,
    ws_copy: Path,
    sandbox: SandboxRunner,
    llm: LLMClient,
    feedback: str = "",
) -> str:
    read_disp = ToolDispatcher(ws_copy, sandbox)
    target_numbered = read_disp.call(run_id, "read_file", {"path": vf.candidate.file})
    if not target_numbered.ok or not isinstance(target_numbered.output, str):
        raise RuntimeError(f"Cannot read {vf.candidate.file}")
    target_plain = _strip_line_numbers(target_numbered.output)

    helper_blocks: list[str] = []
    for helper_path in ("src/middleware/auth.js", "src/db.js", "src/store.js"):
        if helper_path == vf.candidate.file:
            continue
        h_res = read_disp.call(run_id, "read_file", {"path": helper_path})
        if h_res.ok and isinstance(h_res.output, str):
            helper_blocks.append(f'<untrusted_source_file path="{helper_path}">\n{h_res.output}\n</untrusted_source_file>')

    user_prompt = (
        f"Approved Patch Plan (MUST fix root_cause within expected_scope_files; reuse existing helpers/middleware):\n"
        f"{json.dumps(plan_payload, indent=2)}\n\n"
        f"Verified Finding:\n{vf.candidate.model_dump_json(indent=2)}\n\n"
        f"Target File (`{vf.candidate.file}`) with 1-based line numbers:\n"
        f'<untrusted_source_file path="{vf.candidate.file}">\n{target_numbered.output}\n</untrusted_source_file>\n\n'
        f"Exact raw text of `{vf.candidate.file}` (use exact 3-line context for unified diff):\n"
        f"```javascript\n{target_plain}\n```\n\n"
        + ("\n\n".join(helper_blocks))
        + f"\n\nFailing Demonstrating Security Test (`{vf.security_test_path}`):\n```javascript\n{sec_code}\n```\n\n"
        + f"Passing Companion Positive Test (`{vf.companion_test_path}`):\n```javascript\n{comp_code}\n```\n"
        + "\nIMPORTANT ANTI-OVERFITTING RULE: Never hardcode test-specific user IDs, invoice IDs, filenames, or test literals into production code. Enforce general authorization/validation logic.\n"
        + feedback
    )
    res = llm.call(
        role=ModelRole.REASONING,
        system=PATCH_SYSTEM_PROMPT,
        user=user_prompt,
        schema=PATCH_DIFF_SCHEMA,
        caps=LLMCaps(reasoning_effort="high", timeout_s=120.0),
    )
    return str((res.parsed or {}).get("unified_diff") or "")


def stage_patch(
    run_dir: Path,
    candidate_id: str | None = None,
    llm: LLMClient | None = None,
    sandbox: SandboxRunner | None = None,
    use_cache: bool = True,
    feedback_by_cid: dict[str, str] | None = None,
    force_repropose: bool = False,
) -> list[Path]:
    """Stage 5 (PATCH): reads ONLY 04_patches/<cid>/patch_plan.json & 03_verification/<cid>.json -> writes diff + sha256 + variant baseline."""
    sm = StateManager(run_dir)
    ws_copy = _ensure_workspace_copy(sm.run_dir)
    sm.transition_run(RunState.PATCHING, reason="proposing_patches", allow_stage_redo=True)
    eff_sandbox, wrapped_llm = _make_sandbox_and_llm(sm, sandbox=sandbox, llm=llm, use_cache=use_cache)

    # Check if Part 3 deep_patch variant generator is available
    deep_variant_fn = None
    try:
        from agent.patch.deep_patch import ensure_heldout_variant_test

        deep_variant_fn = ensure_heldout_variant_test
    except ImportError:
        deep_variant_fn = None

    patches_root = sm.run_dir / "04_patches"
    if not patches_root.exists():
        return []

    written: list[Path] = []
    for cid_dir in sorted(p for p in patches_root.iterdir() if p.is_dir()):
        cid = cid_dir.name
        if candidate_id is not None and cid != candidate_id:
            continue
        plan_file = cid_dir / "patch_plan.json"
        if not plan_file.exists():
            continue
        plan_env = read_stage_artifact(plan_file)
        if plan_env.status != "PLANNED":
            continue

        ver_env = read_stage_artifact(sm.run_dir / "03_verification" / f"{cid}.json")
        vf = VerifiedFinding.model_validate(ver_env.payload["verified_finding"])
        sec_code = (sm.run_dir / ver_env.payload["security_test_file"]).read_text(encoding="utf-8")
        comp_code = (sm.run_dir / ver_env.payload["companion_test_file"]).read_text(encoding="utf-8")

        repair_info = sm.get_candidate_repair_info(cid)
        patch_env_path = cid_dir / "patch_envelope.json"
        patch_input_hash = canonical_sha256(
            {
                "plan_sha": plan_env.payload_sha256,
                "ver_sha": ver_env.payload_sha256,
                "repair_count": repair_info["repair_count"],
            }
        )

        if not force_repropose:
            cached = sm.try_load_valid_artifact(
                patch_env_path,
                expected_input_hash=patch_input_hash,
                stage="PATCHING",
                candidate_id=cid,
            )
            if cached is not None and (cid_dir / "patch.diff").exists():
                written.append(patch_env_path)
                continue

        # 3b: Generate held-out variant security test BEFORE patching (never shown to patch model!)
        variant_meta_path = cid_dir / "variant_test_results.json"
        if deep_variant_fn is not None and not variant_meta_path.exists():
            disp = LoggingDispatcherWrapper(ToolDispatcher(ws_copy, eff_sandbox, max_calls=200), sm.logger)
            deep_variant_fn(
                run_id=sm.run_id,
                cid_patch_dir=cid_dir,
                verified_finding=vf,
                original_security_test_code=sec_code,
                companion_test_code=comp_code,
                dispatcher=disp,
                llm=wrapped_llm,
                workspace=ws_copy,
            )
        elif not variant_meta_path.exists():
            atomic_write_json(variant_meta_path, {"status": "not_configured"})

        fb = (feedback_by_cid or {}).get(cid, "")
        diff_text = _propose_single_diff_via_llm(
            run_id=sm.run_id,
            vf=vf,
            plan_payload=plan_env.payload,
            sec_code=sec_code,
            comp_code=comp_code,
            ws_copy=ws_copy,
            sandbox=eff_sandbox,
            llm=wrapped_llm,
            feedback=fb,
        )
        patch_sha = hashlib.sha256(diff_text.encode("utf-8")).hexdigest()
        atomic_write_text(cid_dir / "patch.diff", diff_text)
        atomic_write_text(cid_dir / "patch.sha256", patch_sha + "\n")

        attempts_path = cid_dir / "repair_attempts.json"
        attempts_list: list[dict[str, Any]] = []
        if attempts_path.exists():
            try:
                attempts_list = json.loads(attempts_path.read_text(encoding="utf-8"))
            except json.JSONDecodeError:
                attempts_list = []
        attempts_list.append(
            {
                "attempt": len(attempts_list) + 1,
                "patch_sha256": patch_sha,
                "proposed_at": datetime.now(timezone.utc).isoformat(),
            }
        )
        atomic_write_json(attempts_path, attempts_list)

        cur_cstate = sm.get_candidate_state(cid)
        if cur_cstate in (
            CandidateState.PLANNED,
            CandidateState.GUARD_REJECTED,
            CandidateState.PATCH_FAILED,
            CandidateState.REGRESSION,
        ):
            sm.transition_candidate(cid, CandidateState.PATCH_PROPOSED, reason=f"attempt_{len(attempts_list)}")

        sm.write_envelope(
            patch_env_path,
            stage="PATCHING",
            candidate_id=cid,
            input_hash=patch_input_hash,
            status="PATCH_PROPOSED",
            payload={
                "candidate_id": cid,
                "patch_sha256": patch_sha,
                "attempt": len(attempts_list),
                "patch_diff_file": f"04_patches/{cid}/patch.diff",
                "repair_attempts_file": f"04_patches/{cid}/repair_attempts.json",
                "variant_test_results_file": f"04_patches/{cid}/variant_test_results.json",
            },
        )
        written.append(patch_env_path)

    return written


def stage_check(
    run_dir: Path,
    candidate_id: str | None = None,
    sandbox: SandboxRunner | None = None,
    transition_to_awaiting_approval: bool = True,
) -> list[Path]:
    """Stage 6 (CHECKING): reads ONLY 04_patches/<cid>/ & 03_verification/<cid>.json -> writes 05_checks/<cid>.json + 06_evidence/<cid>/."""
    sm = StateManager(run_dir)
    ws_copy = _ensure_workspace_copy(sm.run_dir)
    sm.transition_run(RunState.CHECKING, reason="checking_patches", allow_stage_redo=True)
    eff_sandbox = sandbox or DockerSandbox(image="psa-sandbox:latest", agent_tag=sm.run_id[:12])

    deep_check_fn = None
    try:
        from agent.patch.deep_patch import evaluate_deep_patch_checks

        deep_check_fn = evaluate_deep_patch_checks
    except ImportError:
        deep_check_fn = None

    patches_root = sm.run_dir / "04_patches"
    checks_dir = sm.run_dir / "05_checks"
    checks_dir.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []

    if patches_root.exists():
        for cid_dir in sorted(p for p in patches_root.iterdir() if p.is_dir()):
            cid = cid_dir.name
            if candidate_id is not None and cid != candidate_id:
                continue
            patch_env_file = cid_dir / "patch_envelope.json"
            if not patch_env_file.exists():
                continue
            patch_env = read_stage_artifact(patch_env_file)
            plan_env = read_stage_artifact(cid_dir / "patch_plan.json")
            ver_env = read_stage_artifact(sm.run_dir / "03_verification" / f"{cid}.json")

            check_out_path = checks_dir / f"{cid}.json"
            check_input_hash = canonical_sha256(
                {
                    "patch_sha": patch_env.payload_sha256,
                    "plan_sha": plan_env.payload_sha256,
                    "ver_sha": ver_env.payload_sha256,
                }
            )
            cached = sm.try_load_valid_artifact(
                check_out_path,
                expected_input_hash=check_input_hash,
                stage="CHECKING",
                candidate_id=cid,
            )
            if cached is not None:
                written.append(check_out_path)
                continue

            vf = VerifiedFinding.model_validate(ver_env.payload["verified_finding"])
            sec_code = (sm.run_dir / ver_env.payload["security_test_file"]).read_text(encoding="utf-8")
            comp_code = (sm.run_dir / ver_env.payload["companion_test_file"]).read_text(encoding="utf-8")
            baseline_stdout = (sm.run_dir / ver_env.payload["baseline_jest_file"]).read_text(encoding="utf-8")
            diff_text = (cid_dir / "patch.diff").read_text(encoding="utf-8")
            attempt_num = int(patch_env.payload.get("attempt", 1))

            if deep_check_fn is not None:
                patch_res, extra_checks = deep_check_fn(
                    run_id=sm.run_id,
                    verified_finding=vf,
                    plan_payload=plan_env.payload,
                    cid_patch_dir=cid_dir,
                    security_test_code=sec_code,
                    companion_test_code=comp_code,
                    unified_diff=diff_text,
                    source_workspace=ws_copy,
                    sandbox=eff_sandbox,
                    attempt_num=attempt_num,
                )
            else:
                patch_res = validate_candidate_diff_on_workspace(
                    run_id=sm.run_id,
                    verified_finding=vf,
                    security_test_code=sec_code,
                    companion_test_code=comp_code,
                    unified_diff=diff_text,
                    source_workspace=ws_copy,
                    sandbox=eff_sandbox,
                    attempt_num=attempt_num,
                )
                extra_checks = {}

            # Update repair_attempts.json with outcome
            attempts_path = cid_dir / "repair_attempts.json"
            if attempts_path.exists():
                attempts_list = json.loads(attempts_path.read_text(encoding="utf-8"))
                if attempts_list:
                    attempts_list[-1]["final_status"] = patch_res.final_status.value
                    attempts_list[-1]["failure_reason"] = patch_res.failure_reason
                    atomic_write_json(attempts_path, attempts_list)

            check_payload = {
                "patch_result": patch_res.model_dump(),
                "extra_checks": extra_checks,
            }
            sm.write_envelope(
                check_out_path,
                stage="CHECKING",
                candidate_id=cid,
                input_hash=check_input_hash,
                status=patch_res.final_status.value,
                payload=check_payload,
            )

            ev_bundle_dir = sm.run_dir / "06_evidence" / cid
            write_evidence_bundle(
                run_dir=sm.run_dir,
                verified_finding=vf,
                security_test_code=sec_code,
                companion_test_code=comp_code,
                baseline_stdout=baseline_stdout,
                patch_result=patch_res,
                bundle_dir_override=ev_bundle_dir,
            )

            cur_cstate = sm.get_candidate_state(cid)
            if cur_cstate == CandidateState.PATCH_PROPOSED:
                if patch_res.final_status == FinalPatchStatus.PASS:
                    sm.transition_candidate(cid, CandidateState.CHECKS_PASSED, reason="all_gates_and_guards_passed")
                    if transition_to_awaiting_approval:
                        sm.transition_candidate(cid, CandidateState.AWAITING_APPROVAL, reason="ready_for_human_review")
                else:
                    reason_str = patch_res.failure_reason or "patch_check_failed"
                    sig = normalize_failure_signature(reason_str)
                    sm.record_candidate_repair_failure(cid, sig, reason_str)
                    if not patch_res.guards_passed and patch_res.guards is not None:
                        sm.transition_candidate(cid, CandidateState.GUARD_REJECTED, reason=reason_str)
                    elif (
                        patch_res.patched_security_exit_code == 0
                        and (patch_res.companion_after_exit_code != 0 or patch_res.full_suite_exit_code != 0)
                    ):
                        sm.transition_candidate(cid, CandidateState.REGRESSION, reason=reason_str)
                    else:
                        sm.transition_candidate(cid, CandidateState.PATCH_FAILED, reason=reason_str)

            written.append(check_out_path)

    if transition_to_awaiting_approval:
        sm.transition_run(RunState.AWAITING_APPROVAL, reason="checks_completed", allow_stage_redo=True)
    return written


def verify_approval_or_void(run_dir: Path, candidate_id: str) -> ApprovalRecord:
    """Verify exact SHA-256 of patch.diff against approval.json; if modified, void approval and revert to CHECKS_PASSED."""
    sm = StateManager(run_dir)
    ev_dir = sm.run_dir / "06_evidence" / candidate_id
    approval_file = ev_dir / "approval.json"
    if not approval_file.exists():
        raise ApprovalError(f"Missing approval.json in {ev_dir}; human approval required")

    raw_doc = json.loads(approval_file.read_text(encoding="utf-8"))
    if raw_doc.get("voided") is True:
        raise ApprovalError(f"Approval for {candidate_id} was voided due to patch hash change")

    approval = ApprovalRecord.model_validate(raw_doc)

    # Check both 04_patches/<cid>/patch.diff and 06_evidence/<cid>/patch.diff
    patch_locations = [
        sm.run_dir / "04_patches" / candidate_id / "patch.diff",
        ev_dir / "patch.diff",
    ]
    observed_hashes: set[str] = set()
    for p in patch_locations:
        if p.exists():
            observed_hashes.add(hashlib.sha256(p.read_text(encoding="utf-8").encode("utf-8")).hexdigest())

    if not observed_hashes or observed_hashes != {approval.patch_sha256}:
        voided_doc = dict(raw_doc)
        voided_doc["voided"] = True
        voided_doc["voided_at"] = datetime.now(timezone.utc).isoformat()
        voided_doc["observed_hashes"] = sorted(observed_hashes)
        atomic_write_json(approval_file, voided_doc)

        if sm.has_candidate(candidate_id) and sm.get_candidate_state(candidate_id) == CandidateState.APPROVED:
            sm.transition_candidate(
                candidate_id,
                CandidateState.CHECKS_PASSED,
                reason="approval_voided_patch_hash_changed",
                void_approval=True,
            )
        snap = sm.snapshot()
        any_still_approved = any(
            c.get("state") == CandidateState.APPROVED.value for c in snap["candidates"].values()
        )
        if not any_still_approved and sm.get_run_state() == RunState.APPROVED:
            sm.transition_run(RunState.AWAITING_APPROVAL, reason="approval_voided")

        raise ApprovalError(
            f"Approval voided for {candidate_id}: patch.diff SHA-256 changed from approved {approval.patch_sha256}"
        )

    return approval


def stage_approve(
    run_dir: Path,
    candidate_id: str,
    reviewer: str,
    expected_patch_sha256: str,
    target_branch: str,
    notes: str = "",
) -> ApprovalRecord:
    """Stage 7 (APPROVE): bind human approval to exact patch SHA-256."""
    sm = StateManager(run_dir)
    ev_dir = sm.run_dir / "06_evidence" / candidate_id
    patch_stage_diff = sm.run_dir / "04_patches" / candidate_id / "patch.diff"
    if patch_stage_diff.exists():
        stage_sha = hashlib.sha256(patch_stage_diff.read_text(encoding="utf-8").encode("utf-8")).hexdigest()
        if stage_sha != expected_patch_sha256.strip().lower():
            raise ApprovalError(
                f"04_patches/{candidate_id}/patch.diff SHA-256 ({stage_sha}) != expected {expected_patch_sha256}"
            )

    cur_cstate = sm.get_candidate_state(candidate_id)
    if cur_cstate == CandidateState.CHECKS_PASSED:
        sm.transition_candidate(candidate_id, CandidateState.AWAITING_APPROVAL, reason="entering_approval")
        cur_cstate = CandidateState.AWAITING_APPROVAL
    if cur_cstate != CandidateState.AWAITING_APPROVAL:
        raise ApprovalError(
            f"Candidate {candidate_id} must be in AWAITING_APPROVAL or CHECKS_PASSED to approve (got {cur_cstate})"
        )

    rec = approve_finding_patch(
        bundle_dir=ev_dir,
        reviewer=reviewer,
        expected_patch_sha256=expected_patch_sha256,
        target_branch=target_branch,
        notes=notes,
    )
    sm.logger.record(
        event_type="approval",
        args={
            "candidate_id": candidate_id,
            "reviewer": reviewer,
            "patch_sha256": rec.patch_sha256,
            "target_branch": target_branch,
        },
        result_payload=rec.model_dump(),
        exit_code=0,
        duration_ms=0,
    )
    sm.transition_candidate(candidate_id, CandidateState.APPROVED, reason=f"approved_by_{reviewer}")
    sm.transition_run(RunState.APPROVED, reason=f"approved_{candidate_id}", allow_stage_redo=True)
    return rec


def stage_apply(
    run_dir: Path,
    repo_dir: Path,
    candidate_id: str,
    target_branch: str | None = None,
    subdir_in_repo: str = "",
) -> dict[str, Any]:
    """Stage 8 (APPLY): verify approval hash is un-tampered, then apply to non-main branch via git worktree."""
    verify_approval_or_void(run_dir, candidate_id)
    sm = StateManager(run_dir)
    if sm.get_candidate_state(candidate_id) != CandidateState.APPROVED:
        raise ApprovalError(f"Candidate {candidate_id} is not in APPROVED state")

    ev_dir = sm.run_dir / "06_evidence" / candidate_id
    applied = apply_approved_patch_to_branch(
        repo_dir=repo_dir,
        bundle_dir=ev_dir,
        target_branch=target_branch,
        subdir_in_repo=subdir_in_repo,
    )
    sm.transition_candidate(candidate_id, CandidateState.APPLIED, reason=f"applied_to_{applied['branch']}")
    sm.transition_run(RunState.APPLIED, reason=f"applied_{candidate_id}", allow_stage_redo=True)
    return applied


def stage_advise(
    run_dir: Path,
    candidate_id: str | None = None,
    ground_truth_path: Path | None = None,
    llm: LLMClient | None = None,
    use_cache: bool = True,
) -> list[Path]:
    """Stage 9 (ADVISE): generate 06_evidence/<cid>/advisory.md ONLY for passing findings + runs/<run_id>/report.md."""
    sm = StateManager(run_dir)
    _, wrapped_llm = _make_sandbox_and_llm(sm, llm=llm, use_cache=use_cache)

    comp_advise_fn = None
    run_report_fn = None
    try:
        from agent.advisory_report import generate_comprehensive_advisory, generate_run_aggregate_report

        comp_advise_fn = generate_comprehensive_advisory
        run_report_fn = generate_run_aggregate_report
    except ImportError:
        comp_advise_fn = None

    checks_dir = sm.run_dir / "05_checks"
    written: list[Path] = []
    if checks_dir.exists():
        for chk_fp in sorted(checks_dir.glob("*.json")):
            chk_env = read_stage_artifact(chk_fp)
            cid = str(chk_env.candidate_id)
            if candidate_id is not None and cid != candidate_id:
                continue
            ev_dir = sm.run_dir / "06_evidence" / cid
            adv_path = ev_dir / "advisory.md"

            # Never produce advisory for a candidate whose checks failed (4d)
            if chk_env.status != FinalPatchStatus.PASS.value:
                if adv_path.exists():
                    adv_path.unlink()
                continue

            if comp_advise_fn is not None:
                ws_copy = _ensure_workspace_copy(sm.run_dir)
                comp_advise_fn(run_dir=sm.run_dir, candidate_id=cid, workspace=ws_copy, llm=wrapped_llm)
            else:
                generate_architecture_advisory(ev_dir, wrapped_llm)
            written.append(adv_path)

    if run_report_fn is not None and candidate_id is None:
        gt = ground_truth_path or Path("ground_truth.json")
        if gt.exists():
            rep_path = run_report_fn(sm.run_dir, gt)
            written.append(rep_path)

    return written


def run_pipeline(
    target_dir: Path,
    run_dir: Path,
    run_id: str | None = None,
    max_candidates: int | None = None,
    ground_truth_path: Path | None = None,
    llm: LLMClient | None = None,
    sandbox: SandboxRunner | None = None,
    use_cache: bool = True,
    max_repair_retries: int = 2,
) -> Path:
    """Execute full artifact-driven pipeline: RECON -> DETECT -> VERIFY -> PLAN -> (PATCH <-> CHECK) -> ADVISE."""
    stage_recon(run_dir=run_dir, target_dir=target_dir, run_id=run_id, sandbox=sandbox)
    stage_detect(run_dir=run_dir, llm=llm, sandbox=sandbox, use_cache=use_cache)
    stage_verify(
        run_dir=run_dir,
        max_candidates=max_candidates,
        llm=llm,
        sandbox=sandbox,
        use_cache=use_cache,
    )
    stage_plan(run_dir=run_dir, llm=llm, sandbox=sandbox, use_cache=use_cache)

    # Bounded per-candidate patch + check repair loop reading strictly from stage artifacts
    sm = StateManager(run_dir, run_id=run_id)
    patches_root = sm.run_dir / "04_patches"
    planned_cids: list[str] = []
    if patches_root.exists():
        for p in sorted(patches_root.iterdir()):
            if p.is_dir() and (p / "patch_plan.json").exists():
                plan_env = read_stage_artifact(p / "patch_plan.json")
                if plan_env.status == "PLANNED":
                    planned_cids.append(p.name)

    for cid in planned_cids:
        feedback = ""
        total_attempts = 1 + max(0, min(max_repair_retries, 2))
        for attempt_idx in range(total_attempts):
            prev_sigs = set(sm.get_candidate_repair_info(cid)["failure_signatures"])
            stage_patch(
                run_dir=run_dir,
                candidate_id=cid,
                llm=llm,
                sandbox=sandbox,
                use_cache=use_cache,
                feedback_by_cid={cid: feedback} if feedback else None,
                force_repropose=attempt_idx > 0,
            )
            stage_check(
                run_dir=run_dir,
                candidate_id=cid,
                sandbox=sandbox,
                transition_to_awaiting_approval=False,
            )
            cstate = sm.get_candidate_state(cid)
            if cstate == CandidateState.CHECKS_PASSED:
                sm.transition_candidate(cid, CandidateState.AWAITING_APPROVAL, reason="ready_for_human_review")
                break

            chk_env = read_stage_artifact(sm.run_dir / "05_checks" / f"{cid}.json")
            fail_reason = str((chk_env.payload.get("patch_result") or {}).get("failure_reason") or "patch_failed")
            new_sig = normalize_failure_signature(fail_reason)
            if new_sig in prev_sigs:
                # Repeated normalized failure signature -> stop immediately
                break
            prev_diff = (sm.run_dir / "04_patches" / cid / "patch.diff").read_text(encoding="utf-8")
            feedback = (
                f"\n\nREPAIR ATTEMPT {attempt_idx + 1} FAILED — FIX ROOT CAUSE WITHOUT VANDALISM:\n"
                f"- Failure reason: {fail_reason}\n"
                f"- Previous rejected diff:\n```diff\n{prev_diff[:1500]}\n```\n"
            )

    sm.transition_run(RunState.AWAITING_APPROVAL, reason="pipeline_checks_complete", allow_stage_redo=True)
    stage_advise(run_dir=run_dir, ground_truth_path=ground_truth_path, llm=llm, use_cache=use_cache)
    return sm.run_dir

