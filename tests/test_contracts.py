import hashlib

import pytest
from pydantic import ValidationError

from contracts import (
    ApprovalRecord,
    Candidate,
    CLIExitCode,
    Event,
    FinalPatchStatus,
    GuardCheckResult,
    LLMCaps,
    LLMResult,
    MatchReason,
    MatchResult,
    ModelRole,
    PatchResult,
    RouteEntry,
    RunResult,
    ToolName,
    ToolResult,
    VerificationResult,
    VerificationStatus,
    VerifiedFinding,
    VulnerabilityClass,
)


def make_candidate() -> Candidate:
    return Candidate(
        id="C-001",
        vulnerability_class=VulnerabilityClass.IDOR,
        file="routes/invoices.js",
        start_line=42,
        end_line=55,
        route="GET /invoices/:id",
        reason="Missing ownership check on invoice lookup",
        evidence="const inv = db.getInvoice(req.params.id); res.json(inv);",
        confidence=0.82,
        expected_security_failure="Bob receives Alice's invoice body with HTTP 200",
        invariant_id="IDOR-INVOICE-OWNER",
    )


def test_candidate_validation():
    c = make_candidate()
    assert c.vulnerability_class == VulnerabilityClass.IDOR

    with pytest.raises(ValidationError):
        Candidate(
            id="C-002",
            vulnerability_class=VulnerabilityClass.IDOR,
            file="routes/invoices.js",
            start_line=55,
            end_line=42,
            route="GET /invoices/:id",
            reason="Reversed lines",
            evidence="line",
            confidence=0.5,
            expected_security_failure="fail",
            invariant_id="IDOR-1",
        )

    with pytest.raises(ValidationError):
        Candidate(
            id="C-003",
            vulnerability_class=VulnerabilityClass.IDOR,
            file="routes/invoices.js",
            start_line=10,
            end_line=12,
            route="GET /invoices/:id",
            reason="Bad invariant id with colon",
            evidence="line",
            confidence=0.5,
            expected_security_failure="fail",
            invariant_id="BAD:ID",
        )


def test_match_result_consistency():
    ok = MatchResult(matched=True, reason=MatchReason.TAG_MATCHED, detail="matched tag")
    assert ok.matched is True

    with pytest.raises(ValidationError):
        MatchResult(matched=True, reason=MatchReason.PASSED)

    with pytest.raises(ValidationError):
        MatchResult(matched=False, reason=MatchReason.TAG_MATCHED)


def test_verified_finding_rejects_unverified():
    cand = make_candidate()
    ver_ok = VerificationResult(
        candidate_id=cand.id,
        test_path="tests/generated/c001.security.test.js",
        companion_test_path="tests/generated/c001.companion.test.js",
        baseline_exit_code=1,
        rerun_exit_code=1,
        timed_out=False,
        tagged_assertion_matched=True,
        match_reason=MatchReason.TAG_MATCHED,
        companion_baseline_exit_code=0,
        status=VerificationStatus.VERIFIED_REPRODUCER,
    )
    vf = VerifiedFinding(
        candidate=cand,
        verification=ver_ok,
        security_test_path=ver_ok.test_path,
        companion_test_path="tests/generated/c001.companion.test.js",
        baseline_failure_summary="SECURITY_INVARIANT_VIOLATED:IDOR-INVOICE-OWNER",
    )
    assert vf.candidate.id == "C-001"

    ver_unverified = ver_ok.model_copy(update={"status": VerificationStatus.NOT_REPRODUCED})
    with pytest.raises(ValidationError):
        VerifiedFinding(
            candidate=cand,
            verification=ver_unverified,
            security_test_path=ver_ok.test_path,
            companion_test_path="tests/generated/c001.companion.test.js",
            baseline_failure_summary="passed unexpectedly",
        )


def test_patch_and_approval_and_cli_codes():
    sha = hashlib.sha256(b"diff --git a/x b/x").hexdigest()
    guards = GuardCheckResult(
        passed=True,
        test_count_before=10,
        test_count_after=12,
        skipped_tests_after=0,
        test_files_untouched=True,
        routes_identical=True,
        exports_intact=True,
        forbidden_files_untouched=True,
        changed_lines=6,
    )
    pr = PatchResult(
        candidate_id="C-001",
        unified_diff="diff --git a/x b/x",
        patch_sha256=sha,
        attempts=1,
        patched_security_exit_code=0,
        companion_after_exit_code=0,
        full_suite_exit_code=0,
        guards=guards,
        guards_passed=True,
        final_status=FinalPatchStatus.PASS,
    )
    approval = ApprovalRecord(
        finding_id="C-001",
        reviewer="alice",
        approved_at="2026-10-29T05:15:00Z",
        patch_sha256=pr.patch_sha256,
        target_branch="psa/approved-c-001",
    )
    assert approval.patch_sha256 == sha
    assert CLIExitCode.PASS == 0
    assert CLIExitCode.VULNERABLE_OR_UNVERIFIED == 1
    assert CLIExitCode.INCONCLUSIVE_OR_ERROR == 2
    assert len(list(ToolName)) == 8
    assert ModelRole.FAST == "fast"
    assert ModelRole.REASONING == "reasoning"


def test_runtime_records():
    rr = RunResult(exit_code=0, stdout="ok", stderr="", timed_out=False, duration_ms=120)
    assert not rr.timed_out
    caps = LLMCaps(max_output_tokens=1024, reasoning_effort="low")
    assert caps.max_retries == 2
    res = LLMResult(
        parsed={"ok": True},
        text='{"ok": true}',
        usage={"total_tokens": 25},
        latency_ms=410,
        cache_hit=False,
        model_id="muse-spark-1.3",
        request_hash="a" * 64,
    )
    assert res.model_id == "muse-spark-1.3"
    tr = ToolResult(ok=True, tool_name="list_files", output=["app.js"])
    assert tr.ok
    ev = Event(
        seq=1,
        run_id="run-01",
        timestamp="2026-10-29T05:15:00Z",
        stage="RECON",
        event_type="tool_call",
        input_hash="b" * 64,
        args={"path": "."},
        duration_ms=5,
    )
    assert ev.seq == 1
