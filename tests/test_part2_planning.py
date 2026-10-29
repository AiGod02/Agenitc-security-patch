"""Part 2 tests (written first): rich static recon (middleware, auth, sinks, ownership) & deep logic PLAN stage."""

from __future__ import annotations

import shutil
from pathlib import Path
from typing import Any

from agent.llm import MetaLLMClient
from agent.plan import validate_patch_plan_mechanically
from agent.recon import build_rich_route_inventory
from agent.sandbox import DockerSandbox
from agent.tools import ToolDispatcher
from agent.workflow import StateManager, read_stage_artifact, stage_plan, stage_recon
from contracts import (
    Candidate,
    CandidateState,
    LLMCaps,
    LLMResult,
    MatchReason,
    ModelRole,
    RunState,
    VerificationResult,
    VerificationStatus,
    VerifiedFinding,
    VulnerabilityClass,
)

ROOT = Path(__file__).resolve().parent.parent
FIXTURE_DIR = ROOT / "fixture" / "express-fixture"
REPRO_DIR = ROOT / "fixture" / "reproducers"


def _make_idor_verified_finding() -> VerifiedFinding:
    cand = Candidate(
        id="C-IDOR-01",
        vulnerability_class=VulnerabilityClass.IDOR,
        file="src/routes/invoices.js",
        start_line=30,
        end_line=36,
        route="GET /api/invoices/:id",
        reason="Route fetches invoice by req.params.id without checking invoice.ownerId === req.user.id",
        evidence="const invoice = store.getInvoice(req.params.id);",
        confidence=0.95,
        expected_security_failure="Authenticated Bob reads Alice's invoice inv-1001 with HTTP 200",
        invariant_id="IDOR-INVOICE-READ",
    )
    ver = VerificationResult(
        candidate_id="C-IDOR-01",
        test_path="tests/generated/c_idor_01.security.test.js",
        companion_test_path="tests/generated/c_idor_01.companion.test.js",
        baseline_exit_code=1,
        rerun_exit_code=1,
        timed_out=False,
        tagged_assertion_matched=True,
        match_reason=MatchReason.TAG_MATCHED,
        companion_baseline_exit_code=0,
        status=VerificationStatus.VERIFIED_REPRODUCER,
    )
    return VerifiedFinding(
        candidate=cand,
        verification=ver,
        security_test_path=ver.test_path,
        companion_test_path="tests/generated/c_idor_01.companion.test.js",
        baseline_failure_summary="Matched SECURITY_INVARIANT_VIOLATED:IDOR-INVOICE-READ",
    )


def test_rich_recon_matches_handmade_list_for_fixture_routes(tmp_path: Path):
    ws = tmp_path / "ws"
    shutil.copytree(FIXTURE_DIR, ws, ignore=shutil.ignore_patterns("node_modules"))
    sandbox = DockerSandbox(image="psa-sandbox:latest", agent_tag="p2recon")
    disp = ToolDispatcher(ws, sandbox)

    rich_routes = build_rich_route_inventory("run-p2-recon", disp)
    by_key = {(r.method, r.path): r for r in rich_routes}

    # Hand-made reference comparison across 6 fixture routes (Acceptance #9)
    r_inv_list = by_key[("GET", "/api/invoices")]
    assert r_inv_list.file == "src/routes/invoices.js"
    assert r_inv_list.line == 8
    assert r_inv_list.middleware_chain == ["express.json", "requireAuth"]
    assert r_inv_list.has_auth_check is True
    assert "req.user.id" in r_inv_list.identity_fields

    r_inv_get = by_key[("GET", "/api/invoices/:id")]
    assert r_inv_get.file == "src/routes/invoices.js"
    assert r_inv_get.line == 30
    assert r_inv_get.middleware_chain == ["express.json", "requireAuth"]
    assert r_inv_get.has_auth_check is True
    assert r_inv_get.identity_fields == []
    assert r_inv_get.ownership_comparisons == []

    r_file_dl = by_key[("GET", "/api/files/download")]
    assert r_file_dl.file == "src/routes/files.js"
    assert r_file_dl.line == 20
    assert r_file_dl.middleware_chain == ["express.json", "requireAuth"]
    assert r_file_dl.has_auth_check is True
    assert any(
        s["sink_type"] == "filesystem" and s["param"] == "req.query.name"
        for s in r_file_dl.sinks_reached
    )

    r_search_logs = by_key[("GET", "/api/search/logs")]
    assert r_search_logs.file == "src/routes/search.js"
    assert r_search_logs.line == 12
    assert any(
        s["sink_type"] == "command" and s["param"] == "req.query.keyword"
        for s in r_search_logs.sinks_reached
    )

    r_admin_stats = by_key[("GET", "/api/admin/stats")]
    assert r_admin_stats.middleware_chain == ["express.json", "requireAuth", "requireAdmin"]
    assert r_admin_stats.has_auth_check is True

    r_admin_audit = by_key[("GET", "/api/admin/audit-log")]
    assert r_admin_audit.middleware_chain == ["express.json"]
    assert r_admin_audit.has_auth_check is False


def test_mechanical_plan_validator_rejects_bad_line_wrong_invariant_and_single_option(tmp_path: Path):
    ws = tmp_path / "ws"
    shutil.copytree(FIXTURE_DIR, ws, ignore=shutil.ignore_patterns("node_modules"))
    vf = _make_idor_verified_finding()

    base_valid_plan: dict[str, Any] = {
        "candidate_id": "C-IDOR-01",
        "violated_invariant": "IDOR-INVOICE-READ",
        "root_cause": "Handler returns invoice without checking invoice.ownerId against req.user.id.",
        "root_cause_evidence": [
            {
                "file": "src/routes/invoices.js",
                "line": 31,
                "snippet": "const invoice = store.getInvoice(req.params.id);",
            }
        ],
        "context_read": ["src/routes/invoices.js", "src/store.js", "src/middleware/auth.js"],
        "candidate_fixes": [
            {
                "option_id": "OPT-1",
                "summary": "Check invoice.ownerId !== req.user.id && req.user.role !== 'admin' in handler",
                "layer": "handler",
                "pros_and_cons": "Minimal 3-line change local to route; does not alter store API.",
            },
            {
                "option_id": "OPT-2",
                "summary": "Change store.getInvoice(id, userId) in data_access layer",
                "layer": "data_access",
                "pros_and_cons": "Centralizes lookup but changes store signature for all callers.",
            },
        ],
        "chosen_option_id": "OPT-1",
        "chosen_rationale": "Minimal handler check preserves store.getInvoice signature.",
        "fix_layer": "handler",
        "fix_layer_justification": "Authorization uses req.user claims attached by requireAuth.",
        "helper_reuse_note": "Reuses req.user populated by existing requireAuth middleware.",
        "behavioral_risks": "Must still allow invoice owner and admin role to read invoice.",
        "protecting_companion_test": "f001.companion.test.js",
        "expected_scope_files": ["src/routes/invoices.js"],
        "expected_approx_lines": 4,
    }

    ok, parsed, err = validate_patch_plan_mechanically(base_valid_plan, vf, ws)
    assert ok is True, err
    assert parsed is not None

    # 1. Nonexistent line number -> MUST reject (Acceptance #10)
    bad_line = {
        **base_valid_plan,
        "root_cause_evidence": [
            {"file": "src/routes/invoices.js", "line": 999, "snippet": "const invoice = store.getInvoice(req.params.id);"}
        ],
    }
    ok1, _, err1 = validate_patch_plan_mechanically(bad_line, vf, ws)
    assert ok1 is False
    assert "out of range" in err1.lower() or "line 999" in err1.lower()

    # 2. Existing line number whose text does NOT match snippet -> MUST reject
    wrong_line = {
        **base_valid_plan,
        "root_cause_evidence": [
            {"file": "src/routes/invoices.js", "line": 8, "snippet": "const invoice = store.getInvoice(req.params.id);"}
        ],
    }
    ok2, _, err2 = validate_patch_plan_mechanically(wrong_line, vf, ws)
    assert ok2 is False
    assert "snippet" in err2.lower()

    # 3. Mismatched invariant_id -> MUST reject
    wrong_inv = {**base_valid_plan, "violated_invariant": "WRONG-INV"}
    ok3, _, err3 = validate_patch_plan_mechanically(wrong_inv, vf, ws)
    assert ok3 is False
    assert "invariant" in err3.lower()

    # 4. Fewer than two options -> MUST reject
    one_opt = {**base_valid_plan, "candidate_fixes": [base_valid_plan["candidate_fixes"][0]]}
    ok4, _, _ = validate_patch_plan_mechanically(one_opt, vf, ws)
    assert ok4 is False


class BadLinePlanLLMForRetryUnitTestOnly:
    """Unit-test-only fake verifying 2c retry-once-then-PATCH_FAILED behavior."""

    def __init__(self) -> None:
        self.calls = 0

    def call(
        self,
        role: ModelRole,
        system: str,
        user: str,
        schema: dict[str, Any] | None = None,
        caps: LLMCaps | None = None,
    ) -> LLMResult:
        self.calls += 1
        bad_plan = {
            "candidate_id": "C-IDOR-01",
            "violated_invariant": "IDOR-INVOICE-READ",
            "root_cause": "Bad citation",
            "root_cause_evidence": [{"file": "src/routes/invoices.js", "line": 888, "snippet": "nonexistent"}],
            "context_read": ["src/routes/invoices.js"],
            "candidate_fixes": [
                {"option_id": "A", "summary": "opt A", "layer": "handler", "pros_and_cons": "p"},
                {"option_id": "B", "summary": "opt B", "layer": "data_access", "pros_and_cons": "p"},
            ],
            "chosen_option_id": "A",
            "chosen_rationale": "r",
            "fix_layer": "handler",
            "fix_layer_justification": "j",
            "helper_reuse_note": "h",
            "behavioral_risks": "b",
            "protecting_companion_test": "comp",
            "expected_scope_files": ["src/routes/invoices.js"],
            "expected_approx_lines": 3,
        }
        return LLMResult(
            parsed=bad_plan,
            text="{}",
            usage=None,
            latency_ms=1,
            cache_hit=False,
            model_id="unit-test-plan-retry",
            request_hash="1" * 64,
        )


def test_failing_plan_retried_once_then_candidate_becomes_patch_failed(tmp_path: Path):
    run_dir = tmp_path / "runs" / "run-plan-fail"
    stage_recon(run_dir=run_dir, target_dir=FIXTURE_DIR, run_id="run-plan-fail")
    sm = StateManager(run_dir, "run-plan-fail")
    sm.transition_run(RunState.CANDIDATES)
    sm.init_candidate("C-IDOR-01")
    sm.transition_run(RunState.VERIFYING)
    sm.transition_candidate("C-IDOR-01", CandidateState.TEST_WRITTEN)
    sm.transition_candidate("C-IDOR-01", CandidateState.VERIFIED_REPRODUCER)

    vf = _make_idor_verified_finding()
    ver_dir = run_dir / "03_verification"
    ver_dir.mkdir(parents=True, exist_ok=True)
    (ver_dir / "C-IDOR-01.security.test.js").write_text(
        (REPRO_DIR / "f001.security.test.js").read_text(encoding="utf-8"), encoding="utf-8"
    )
    (ver_dir / "C-IDOR-01.companion.test.js").write_text(
        (REPRO_DIR / "f001.companion.test.js").read_text(encoding="utf-8"), encoding="utf-8"
    )
    (ver_dir / "C-IDOR-01.baseline.jest.json").write_text('{"numFailedTests":1}', encoding="utf-8")
    sm.write_envelope(
        ver_dir / "C-IDOR-01.json",
        stage="VERIFYING",
        candidate_id="C-IDOR-01",
        input_hash="a" * 64,
        status=VerificationStatus.VERIFIED_REPRODUCER.value,
        payload={
            "candidate": vf.candidate.model_dump(),
            "verification": vf.verification.model_dump(),
            "verified_finding": vf.model_dump(),
            "security_test_file": "03_verification/C-IDOR-01.security.test.js",
            "companion_test_file": "03_verification/C-IDOR-01.companion.test.js",
            "baseline_jest_file": "03_verification/C-IDOR-01.baseline.jest.json",
        },
    )

    fake_llm = BadLinePlanLLMForRetryUnitTestOnly()
    stage_plan(run_dir=run_dir, candidate_id="C-IDOR-01", llm=fake_llm)
    assert fake_llm.calls == 2  # initial + 1 retry
    assert sm.get_candidate_state("C-IDOR-01") == CandidateState.PATCH_FAILED


def test_live_idor_plan_names_missing_ownership_check_with_real_file_and_line(tmp_path: Path):
    run_dir = tmp_path / "runs" / "run-live-plan"
    stage_recon(run_dir=run_dir, target_dir=FIXTURE_DIR, run_id="run-live-plan")
    sm = StateManager(run_dir, "run-live-plan")
    sm.transition_run(RunState.CANDIDATES)
    sm.init_candidate("C-IDOR-01")
    sm.transition_run(RunState.VERIFYING)
    sm.transition_candidate("C-IDOR-01", CandidateState.TEST_WRITTEN)
    sm.transition_candidate("C-IDOR-01", CandidateState.VERIFIED_REPRODUCER)

    vf = _make_idor_verified_finding()
    ver_dir = run_dir / "03_verification"
    ver_dir.mkdir(parents=True, exist_ok=True)
    (ver_dir / "C-IDOR-01.security.test.js").write_text(
        (REPRO_DIR / "f001.security.test.js").read_text(encoding="utf-8"), encoding="utf-8"
    )
    (ver_dir / "C-IDOR-01.companion.test.js").write_text(
        (REPRO_DIR / "f001.companion.test.js").read_text(encoding="utf-8"), encoding="utf-8"
    )
    (ver_dir / "C-IDOR-01.baseline.jest.json").write_text('{"numFailedTests":1}', encoding="utf-8")
    sm.write_envelope(
        ver_dir / "C-IDOR-01.json",
        stage="VERIFYING",
        candidate_id="C-IDOR-01",
        input_hash="b" * 64,
        status=VerificationStatus.VERIFIED_REPRODUCER.value,
        payload={
            "candidate": vf.candidate.model_dump(),
            "verification": vf.verification.model_dump(),
            "verified_finding": vf.model_dump(),
            "security_test_file": "03_verification/C-IDOR-01.security.test.js",
            "companion_test_file": "03_verification/C-IDOR-01.companion.test.js",
            "baseline_jest_file": "03_verification/C-IDOR-01.baseline.jest.json",
        },
    )

    llm = MetaLLMClient(log_path=run_dir / "llm_calls.jsonl", use_cache=True)
    outs = stage_plan(run_dir=run_dir, candidate_id="C-IDOR-01", llm=llm)
    assert len(outs) == 1
    assert sm.get_candidate_state("C-IDOR-01") == CandidateState.PLANNED

    plan_env = read_stage_artifact(run_dir / "04_patches" / "C-IDOR-01" / "patch_plan.json")
    assert plan_env.status == "PLANNED"
    p = plan_env.payload
    assert p["violated_invariant"] == "IDOR-INVOICE-READ"
    assert len(p["candidate_fixes"]) >= 2
    assert any(
        ev["file"] == "src/routes/invoices.js" and 30 <= ev["line"] <= 36
        for ev in p["root_cause_evidence"]
    )
    assert "owner" in p["root_cause"].lower() or "req.user" in p["root_cause"].lower()

