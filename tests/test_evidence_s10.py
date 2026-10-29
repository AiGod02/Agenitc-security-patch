# Tests append-only event log, secret redaction, evidence bundle writer, and labeled replay (Slice S10).
import hashlib
from pathlib import Path

from agent.evidence import (
    EventLogger,
    REPLAY_BANNER,
    replay_run,
    write_evidence_bundle,
)
from contracts import (
    Candidate,
    FinalPatchStatus,
    GuardCheckResult,
    MatchReason,
    PatchResult,
    VerificationResult,
    VerificationStatus,
    VerifiedFinding,
    VulnerabilityClass,
)


def test_event_log_redaction_bundle_and_replay(tmp_path: Path):
    run_dir = tmp_path / "runs" / "run-s10"
    logger = EventLogger(run_dir=run_dir, run_id="run-s10")
    logger.set_stage("RECON")
    logger.record(
        event_type="tool_call",
        args={"tool_name": "list_files", "api_key": "SUPER_SECRET_NEVER_LOG"},
        result_payload={"files": ["src/app.js"]},
        exit_code=0,
        duration_ms=4,
    )
    logger.set_stage("EVIDENCE")

    # Verify raw secret was redacted in events.jsonl
    raw_events = (run_dir / "events.jsonl").read_text(encoding="utf-8")
    assert "SUPER_SECRET_NEVER_LOG" not in raw_events
    assert "<REDACTED>" in raw_events

    cand = Candidate(
        id="C-001",
        vulnerability_class=VulnerabilityClass.IDOR,
        file="src/routes/invoices.js",
        start_line=30,
        end_line=36,
        route="GET /api/invoices/:id",
        reason="Missing ownership check",
        evidence="store.getInvoice(req.params.id)",
        confidence=0.9,
        expected_security_failure="Bob reads Alice invoice",
        invariant_id="IDOR-INVOICE-READ",
    )
    ver = VerificationResult(
        candidate_id="C-001",
        test_path="tests/generated/c_001.security.test.js",
        companion_test_path="tests/generated/c_001.companion.test.js",
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
        verification=ver,
        security_test_path=ver.test_path,
        companion_test_path="tests/generated/c_001.companion.test.js",
        baseline_failure_summary="Matched SECURITY_INVARIANT_VIOLATED:IDOR-INVOICE-READ",
    )
    diff_text = "--- a/src/routes/invoices.js\n+++ b/src/routes/invoices.js\n@@ -30,1 +30,1 @@\n-old\n+new\n"
    guards = GuardCheckResult(
        passed=True,
        test_count_before=8,
        test_count_after=8,
        skipped_tests_after=0,
        test_files_untouched=True,
        routes_identical=True,
        exports_intact=True,
        forbidden_files_untouched=True,
        changed_lines=2,
    )
    pr = PatchResult(
        candidate_id="C-001",
        unified_diff=diff_text,
        patch_sha256=hashlib.sha256(diff_text.encode("utf-8")).hexdigest(),
        attempts=1,
        patched_security_exit_code=0,
        companion_after_exit_code=0,
        full_suite_exit_code=0,
        guards=guards,
        guards_passed=True,
        final_status=FinalPatchStatus.PASS,
    )

    bundle_dir = write_evidence_bundle(
        run_dir=run_dir,
        verified_finding=vf,
        security_test_code="test('sec', () => {});",
        companion_test_code="test('comp', () => {});",
        baseline_stdout='{"numFailedTests":1}',
        patch_result=pr,
    )
    assert (bundle_dir / "finding.json").exists()
    assert (bundle_dir / "patch.diff").exists()
    assert (bundle_dir / "patch.sha256").exists()
    assert (bundle_dir / "guards.json").exists()
    assert (bundle_dir / "summary.md").exists()

    replay = replay_run(run_dir)
    formatted = replay.format_text()
    assert REPLAY_BANNER in formatted
    assert replay.total_events == 3
    assert replay.steps[1].recorded_outcome == {"files": ["src/app.js"]}
