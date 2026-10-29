# Tests evaluation scorer/report (Slice S12), thin FastAPI review endpoints (Slice S13), and post-fix advisory (Slice S14).
import asyncio
import hashlib
import json
from pathlib import Path

import httpx
import pytest

from agent.advisory import generate_architecture_advisory
from agent.api import create_review_api
from agent.evidence import EventLogger, write_evidence_bundle
from agent.llm import MetaLLMClient
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
from eval.report import format_evaluation_markdown, score_single_run

ROOT = Path(__file__).resolve().parent.parent
GROUND_TRUTH = ROOT / "ground_truth.json"


def _seed_sample_run_artifact(runs_root: Path, run_id: str, include_clean_fp: bool = True) -> tuple[Path, str]:
    run_dir = runs_root / run_id
    logger = EventLogger(run_dir, run_id)
    logger.set_stage("RECON")
    logger.set_stage("EVIDENCE")

    cand_tp = Candidate(
        id="C-001",
        vulnerability_class=VulnerabilityClass.IDOR,
        file="src/routes/invoices.js",
        start_line=30,
        end_line=36,
        route="GET /api/invoices/:id",
        reason="Missing owner check",
        evidence="store.getInvoice(req.params.id)",
        confidence=0.92,
        expected_security_failure="Bob reads Alice invoice",
        invariant_id="IDOR-INVOICE-READ",
    )
    cand_fp = Candidate(
        id="C-002",
        vulnerability_class=VulnerabilityClass.MISSING_AUTH,
        file="src/routes/admin.js",
        start_line=8,
        end_line=10,
        route="GET /api/admin/stats",
        reason="Suspected missing auth",
        evidence="router.get('/stats', ...)",
        confidence=0.35,
        expected_security_failure="Unauth 200",
        invariant_id="FP-STATS",
    )

    accepted = [cand_tp.model_dump()]
    if include_clean_fp:
        accepted.append(cand_fp.model_dump())

    (run_dir / "candidates.json").write_text(
        json.dumps({"accepted": accepted, "rejected": []}, indent=2),
        encoding="utf-8",
    )

    ver_tp = VerificationResult(
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
        patched_security_exit_code=0,
        companion_after_exit_code=0,
        full_suite_exit_code=0,
        guards_passed=True,
        final_status=FinalPatchStatus.PASS,
    )
    vers = [ver_tp.model_dump()]
    if include_clean_fp:
        ver_fp = VerificationResult(
            candidate_id="C-002",
            test_path="tests/generated/c_002.security.test.js",
            companion_test_path="tests/generated/c_002.companion.test.js",
            baseline_exit_code=0,
            timed_out=False,
            tagged_assertion_matched=False,
            match_reason=MatchReason.PASSED,
            companion_baseline_exit_code=0,
            status=VerificationStatus.NOT_REPRODUCED,
        )
        vers.append(ver_fp.model_dump())
    (run_dir / "verifications.json").write_text(json.dumps(vers, indent=2), encoding="utf-8")

    diff_text = (
        "--- a/src/routes/invoices.js\n"
        "+++ b/src/routes/invoices.js\n"
        "@@ -30,4 +30,7 @@\n"
        "   router.get(\"/:id\", requireAuth, (req, res) => {\n"
        "     const invoice = store.getInvoice(req.params.id);\n"
        "+    if (invoice && invoice.ownerId !== req.user.id && req.user.role !== \"admin\") {\n"
        "+      return res.status(403).json({ error: \"Forbidden\" });\n"
        "+    }\n"
        "     if (!invoice) {\n"
    )
    sha = hashlib.sha256(diff_text.encode("utf-8")).hexdigest()
    guards = GuardCheckResult(
        passed=True,
        test_count_before=8,
        test_count_after=8,
        skipped_tests_after=0,
        test_files_untouched=True,
        routes_identical=True,
        exports_intact=True,
        forbidden_files_untouched=True,
        changed_lines=3,
    )
    pr = PatchResult(
        candidate_id="C-001",
        unified_diff=diff_text,
        patch_sha256=sha,
        attempts=1,
        patched_security_exit_code=0,
        companion_after_exit_code=0,
        full_suite_exit_code=0,
        guards=guards,
        guards_passed=True,
        final_status=FinalPatchStatus.PASS,
    )
    (run_dir / "patches.json").write_text(json.dumps([pr.model_dump()], indent=2), encoding="utf-8")
    (run_dir / "run_summary.json").write_text(
        json.dumps(
            {
                "run_id": run_id,
                "duration_ms": 1200,
                "routes_discovered": 18,
                "candidates_accepted": len(accepted),
                "candidates_rejected": 0,
                "verified_reproducers": 1,
                "not_reproduced": 1 if include_clean_fp else 0,
                "inconclusive": 0,
                "patches_passed": 1,
                "patches_failed": 0,
                "state": "AWAITING_APPROVAL",
            },
            indent=2,
        ),
        encoding="utf-8",
    )

    vf = VerifiedFinding(
        candidate=cand_tp,
        verification=ver_tp,
        security_test_path=ver_tp.test_path,
        companion_test_path="tests/generated/c_001.companion.test.js",
        baseline_failure_summary="Matched SECURITY_INVARIANT_VIOLATED:IDOR-INVOICE-READ",
    )
    bundle_dir = write_evidence_bundle(run_dir, vf, "test('s',()=>{});", "test('c',()=>{});", "{}", pr)
    return bundle_dir, sha


def test_eval_scoring_denominators_and_three_run_markdown(tmp_path: Path):
    runs_root = tmp_path / "runs"
    _seed_sample_run_artifact(runs_root, "eval-01", include_clean_fp=True)
    _seed_sample_run_artifact(runs_root, "eval-02", include_clean_fp=False)
    _seed_sample_run_artifact(runs_root, "eval-03", include_clean_fp=True)

    s1 = score_single_run(runs_root / "eval-01", GROUND_TRUTH)
    assert s1["overall"]["recall_denominator"] == "1/12"
    assert s1["overall"]["false_positive_rate_denominator"] == "1/2"
    assert s1["overall"]["patch_success_denominator"] == "1/1"
    assert s1["telemetry"]["cost_usd"] == "unknown"
    assert "F-002" in s1["per_class"]["IDOR"]["missed_flaw_ids"]

    s2 = score_single_run(runs_root / "eval-02", GROUND_TRUTH)
    s3 = score_single_run(runs_root / "eval-03", GROUND_TRUTH)
    md = format_evaluation_markdown([s1, s2, s3])
    assert "`n = 3` runs" in md
    assert "do not prove universal vulnerability detection" in md
    assert "Semgrep" in md


def test_fastapi_review_endpoints_and_live_advisory(tmp_path: Path):
    runs_root = tmp_path / "runs"
    bundle_dir, sha = _seed_sample_run_artifact(runs_root, "api-run-01", include_clean_fp=True)
    api = create_review_api(runs_root=runs_root, ground_truth_path=GROUND_TRUTH)

    async def exercise_api() -> None:
        transport = httpx.ASGITransport(app=api)
        async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
            ui_resp = await client.get("/")
            assert ui_resp.status_code == 200
            assert "Verified Security Patch Agent" in ui_resp.text

            runs_resp = await client.get("/api/runs")
            assert runs_resp.status_code == 200
            assert len(runs_resp.json()["runs"]) == 1

            detail_resp = await client.get("/api/runs/api-run-01")
            assert detail_resp.status_code == 200
            assert detail_resp.json()["summary"]["verified_reproducers"] == 1

            replay_resp = await client.get("/api/runs/api-run-01/replay")
            assert replay_resp.status_code == 200
            assert "REPLAY MODE" in replay_resp.json()["banner"]

            # Bad SHA-256 rejected with 400
            bad_app = await client.post(
                "/api/runs/api-run-01/bundles/C-001/approve",
                json={"reviewer": "bob", "patch_sha256": "0" * 64, "target_branch": "psa/fix-c-001"},
            )
            assert bad_app.status_code == 400

            # Exact SHA-256 approved
            ok_app = await client.post(
                "/api/runs/api-run-01/bundles/C-001/approve",
                json={"reviewer": "bob", "patch_sha256": sha, "target_branch": "psa/fix-c-001"},
            )
            assert ok_app.status_code == 200
            assert ok_app.json()["patch_sha256"] == sha

    asyncio.run(exercise_api())

    # Live S14 advisory on verified PASS bundle
    llm = MetaLLMClient(use_cache=True)
    adv = generate_architecture_advisory(bundle_dir, llm)
    assert len(adv["observed_facts"]) >= 1
    assert len(adv["recommendations"]) >= 1
    assert (bundle_dir / "advisory.md").exists()

    # Reject advisory on non-PASS finding
    unpatched_dir = tmp_path / "unpatched"
    unpatched_dir.mkdir()
    (unpatched_dir / "finding.json").write_text(
        json.dumps({"candidate": {"id": "C-99"}, "patch_result": {"final_status": "FAIL"}}),
        encoding="utf-8",
    )
    with pytest.raises(ValueError):
        generate_architecture_advisory(unpatched_dir, llm)

