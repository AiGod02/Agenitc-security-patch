"""Part 4 tests (written first): 9-section comprehensive advisory, mechanical file:line & snippet validation, failed-candidate exclusion, aggregate report.md, and side-by-side review API."""

from __future__ import annotations

import asyncio
import hashlib
import json
import re
from pathlib import Path

import httpx
import pytest

from agent.advisory_report import (
    AdvisoryValidationError,
    generate_comprehensive_advisory,
    generate_run_aggregate_report,
    validate_advisory_markdown_references,
)
from agent.api import create_review_api
from agent.evidence import write_evidence_bundle
from agent.llm import MetaLLMClient
from agent.sandbox import DockerSandbox
from agent.workflow import (
    StateManager,
    read_stage_artifact,
    stage_advise,
    stage_check,
    stage_patch,
    stage_plan,
    stage_recon,
)
from contracts import (
    Candidate,
    CandidateState,
    FinalPatchStatus,
    MatchReason,
    PatchResult,
    RunState,
    VerificationResult,
    VerificationStatus,
    VerifiedFinding,
    VulnerabilityClass,
)

ROOT = Path(__file__).resolve().parent.parent
FIXTURE_DIR = ROOT / "fixture" / "express-fixture"
REPRO_DIR = ROOT / "fixture" / "reproducers"
GROUND_TRUTH = ROOT / "ground_truth.json"


def _hash_tree(directory: Path) -> dict[str, str]:
    hashes: dict[str, str] = {}
    for fp in sorted(directory.rglob("*")):
        if fp.is_file():
            rel = fp.relative_to(directory).as_posix()
            hashes[rel] = hashlib.sha256(fp.read_bytes()).hexdigest()
    return hashes


def _seed_staged_run_with_pass_and_fail_candidates(run_dir: Path) -> tuple[StateManager, Path]:
    stage_recon(run_dir=run_dir, target_dir=FIXTURE_DIR, run_id=run_dir.name)
    sm = StateManager(run_dir, run_dir.name)
    sm.transition_run(RunState.CANDIDATES)

    cand_pass = Candidate(
        id="C-001",
        vulnerability_class=VulnerabilityClass.IDOR,
        file="src/routes/invoices.js",
        start_line=30,
        end_line=36,
        route="GET /api/invoices/:id",
        reason="Missing invoice.ownerId === req.user.id authorization check",
        evidence="const invoice = store.getInvoice(req.params.id);",
        confidence=0.95,
        expected_security_failure="Bob reads Alice invoice inv-1001 with HTTP 200",
        invariant_id="IDOR-INVOICE-READ",
    )
    cand_fail = Candidate(
        id="C-002",
        vulnerability_class=VulnerabilityClass.PATH_TRAVERSAL,
        file="src/routes/files.js",
        start_line=15,
        end_line=23,
        route="GET /api/files/download",
        reason="Uncontained path.join traversal",
        evidence="const targetPath = path.join(FILES_ROOT, requested);",
        confidence=0.90,
        expected_security_failure="Traversal escapes storage/files",
        invariant_id="PATH-TRAVERSAL-FILES",
    )

    sm.init_candidate("C-001")
    sm.init_candidate("C-002")
    sm.write_envelope(
        run_dir / "02_candidates.json",
        stage="CANDIDATES",
        candidate_id=None,
        input_hash="a" * 64,
        status="OK",
        payload={
            "accepted": [cand_pass.model_dump(), cand_fail.model_dump()],
            "rejected": [],
        },
    )

    sm.transition_run(RunState.VERIFYING)
    sm.transition_candidate("C-001", CandidateState.TEST_WRITTEN)
    sm.transition_candidate("C-001", CandidateState.VERIFIED_REPRODUCER)
    sm.transition_candidate("C-002", CandidateState.TEST_WRITTEN)
    sm.transition_candidate("C-002", CandidateState.VERIFIED_REPRODUCER)

    ver_pass = VerificationResult(
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
    vf_pass = VerifiedFinding(
        candidate=cand_pass,
        verification=ver_pass,
        security_test_path=ver_pass.test_path,
        companion_test_path=ver_pass.companion_test_path,
        baseline_failure_summary="Matched SECURITY_INVARIANT_VIOLATED:IDOR-INVOICE-READ",
    )
    sec_code = (REPRO_DIR / "f001.security.test.js").read_text(encoding="utf-8")
    comp_code = (REPRO_DIR / "f001.companion.test.js").read_text(encoding="utf-8")

    ver_dir = run_dir / "03_verification"
    ver_dir.mkdir(parents=True, exist_ok=True)
    (ver_dir / "C-001.security.test.js").write_text(sec_code, encoding="utf-8")
    (ver_dir / "C-001.companion.test.js").write_text(comp_code, encoding="utf-8")
    (ver_dir / "C-001.baseline.jest.json").write_text(
        json.dumps({"numFailedTests": 1, "tag": "SECURITY_INVARIANT_VIOLATED:IDOR-INVOICE-READ"}),
        encoding="utf-8",
    )
    sm.write_envelope(
        ver_dir / "C-001.json",
        stage="VERIFYING",
        candidate_id="C-001",
        input_hash="b" * 64,
        status=VerificationStatus.VERIFIED_REPRODUCER.value,
        payload={
            "candidate": cand_pass.model_dump(),
            "verification": ver_pass.model_dump(),
            "verified_finding": vf_pass.model_dump(),
            "security_test_file": "03_verification/C-001.security.test.js",
            "companion_test_file": "03_verification/C-001.companion.test.js",
            "baseline_jest_file": "03_verification/C-001.baseline.jest.json",
        },
    )

    # Seed C-002 as a failed candidate (PATCH_FAILED with 05_checks/C-002.json status="FAIL")
    ver_fail = VerificationResult(
        candidate_id="C-002",
        test_path="tests/generated/c_002.security.test.js",
        companion_test_path="tests/generated/c_002.companion.test.js",
        baseline_exit_code=1,
        rerun_exit_code=1,
        timed_out=False,
        tagged_assertion_matched=True,
        match_reason=MatchReason.TAG_MATCHED,
        companion_baseline_exit_code=0,
        status=VerificationStatus.VERIFIED_REPRODUCER,
    )
    vf_fail = VerifiedFinding(
        candidate=cand_fail,
        verification=ver_fail,
        security_test_path=ver_fail.test_path,
        companion_test_path=ver_fail.companion_test_path,
        baseline_failure_summary="Matched SECURITY_INVARIANT_VIOLATED:PATH-TRAVERSAL-FILES",
    )
    sm.write_envelope(
        ver_dir / "C-002.json",
        stage="VERIFYING",
        candidate_id="C-002",
        input_hash="c" * 64,
        status=VerificationStatus.VERIFIED_REPRODUCER.value,
        payload={
            "candidate": cand_fail.model_dump(),
            "verification": ver_fail.model_dump(),
            "verified_finding": vf_fail.model_dump(),
            "security_test_file": "03_verification/C-001.security.test.js",
            "companion_test_file": "03_verification/C-001.companion.test.js",
            "baseline_jest_file": "03_verification/C-001.baseline.jest.json",
        },
    )
    sm.transition_candidate("C-002", CandidateState.PLANNED)
    sm.transition_candidate("C-002", CandidateState.PATCH_PROPOSED)
    sm.transition_candidate("C-002", CandidateState.PATCH_FAILED, reason="security_test_still_failing")

    fail_pr = PatchResult(
        candidate_id="C-002",
        unified_diff="",
        patch_sha256="0" * 64,
        attempts=1,
        patched_security_exit_code=1,
        companion_after_exit_code=0,
        full_suite_exit_code=0,
        guards_passed=False,
        final_status=FinalPatchStatus.FAIL,
        failure_reason="Demonstrating security test failed after patch",
    )
    checks_dir = run_dir / "05_checks"
    checks_dir.mkdir(parents=True, exist_ok=True)
    sm.write_envelope(
        checks_dir / "C-002.json",
        stage="CHECKING",
        candidate_id="C-002",
        input_hash="d" * 64,
        status=FinalPatchStatus.FAIL.value,
        payload={"patch_result": fail_pr.model_dump(), "extra_checks": {}},
    )
    write_evidence_bundle(
        run_dir=run_dir,
        verified_finding=vf_fail,
        security_test_code=sec_code,
        companion_test_code=comp_code,
        baseline_stdout="{}",
        patch_result=fail_pr,
        bundle_dir_override=run_dir / "06_evidence" / "C-002",
    )

    return sm, run_dir / "workspace_copy"


def test_comprehensive_advisory_9_sections_tamper_detection_and_failed_candidate_exclusion(tmp_path: Path):
    run_dir = tmp_path / "runs" / "run-p4-advisory"
    sm, ws = _seed_staged_run_with_pass_and_fail_candidates(run_dir)
    sandbox = DockerSandbox(image="psa-sandbox:latest", agent_tag="p4adv")
    llm = MetaLLMClient(log_path=run_dir / "llm_calls.jsonl", use_cache=True)

    # Plan, patch, and check C-001 for real
    stage_plan(run_dir=run_dir, candidate_id="C-001", llm=llm, sandbox=sandbox)
    stage_patch(run_dir=run_dir, candidate_id="C-001", llm=llm, sandbox=sandbox)
    stage_check(run_dir=run_dir, candidate_id="C-001", sandbox=sandbox)
    assert sm.get_candidate_state("C-001") == CandidateState.AWAITING_APPROVAL

    # Snapshot workspace hashes BEFORE stage_advise to prove advisory never modifies code (4d)
    ws_before = _hash_tree(ws)

    # Plant a stale advisory on failed candidate C-002 to verify stage_advise refuses & cleans failed candidates
    stale_fail_adv = run_dir / "06_evidence" / "C-002" / "advisory.md"
    stale_fail_adv.write_text("stale", encoding="utf-8")

    written = stage_advise(run_dir=run_dir, ground_truth_path=GROUND_TRUTH, llm=llm)
    ws_after = _hash_tree(ws)
    assert ws_after == ws_before, "Advisory generation must NEVER modify workspace files"

    # 1. Passing candidate C-001 gets 06_evidence/C-001/advisory.md
    adv_c001 = run_dir / "06_evidence" / "C-001" / "advisory.md"
    assert adv_c001 in written
    assert adv_c001.exists()
    assert not (run_dir / "06_evidence" / "C-001" / "approval.json").exists(), "Advisory must never bypass approval"

    # 2. Failed candidate C-002 produces NO advisory (4d & Acceptance #14)
    assert not stale_fail_adv.exists()
    with pytest.raises(AdvisoryValidationError):
        generate_comprehensive_advisory(run_dir=run_dir, candidate_id="C-002", workspace=ws, llm=llm)

    # 3. Verify all 9 required sections appear in exact order (4a)
    adv_text = adv_c001.read_text(encoding="utf-8")
    expected_headings = [
        "## 1. Summary",
        "## 2. Observed Facts",
        "## 3. Root Cause",
        "## 4. What Changed and Why It Is Minimal",
        "## 5. Verification Evidence",
        "## 6. Architectural Observations",
        "## 7. Possible Variants",
        "## 8. Recommended Follow-Ups",
        "## 9. Residual Risks and What Was Not Tested",
    ]
    positions: list[int] = []
    for h in expected_headings:
        pos = adv_text.find(h)
        assert pos != -1, f"Missing required heading '{h}' in advisory.md"
        positions.append(pos)
    assert positions == sorted(positions), f"Advisory sections out of order: {positions}"

    # Section 7 must list possible variants from 3d (e.g., src/routes/users.js:17) without calling them confirmed vulnerable
    assert "possible variant" in adv_text.lower()
    assert "src/routes/users.js:17" in adv_text

    # 4. Mechanical reference check passes on real advisory.md (4b)
    ok_real, errs_real = validate_advisory_markdown_references(adv_text, workspace=ws, run_dir=run_dir)
    assert ok_real is True, f"Valid advisory failed reference validation: {errs_real}"

    # 5. Reference check catches a deliberately altered line number (Acceptance #14):
    #    (a) Out-of-bounds line number (:31 -> :999)
    m_cit = re.search(r"`(src/routes/invoices\.js):(\d+)`", adv_text)
    assert m_cit is not None, "Expected file:line citation to src/routes/invoices.js in advisory.md"
    orig_token = m_cit.group(0)
    tampered_oob = adv_text.replace(orig_token, "`src/routes/invoices.js:999`", 1)
    ok_oob, errs_oob = validate_advisory_markdown_references(tampered_oob, workspace=ws, run_dir=run_dir)
    assert ok_oob is False
    assert any("999" in e for e in errs_oob)

    #    (b) Wrong in-bounds line number where verbatim snippet does not match (:line -> :1)
    m_snip_cit = re.search(r"`(src/routes/invoices\.js):([2-9]\d*)`\s*\(verbatim snippet:\s*`([^`]+)`\)", adv_text)
    assert m_snip_cit is not None, "Expected file:line citation with verbatim snippet in advisory.md"
    tampered_wrong_line = adv_text.replace(
        m_snip_cit.group(0),
        f"`src/routes/invoices.js:1` (verbatim snippet: `{m_snip_cit.group(3)}`)",
        1,
    )
    ok_wrong, errs_wrong = validate_advisory_markdown_references(tampered_wrong_line, workspace=ws, run_dir=run_dir)
    assert ok_wrong is False
    assert any("src/routes/invoices.js:1" in e for e in errs_wrong)

    # 6. Aggregate runs/<run_id>/report.md (4c)
    rep_md_path = run_dir / "report.md"
    assert rep_md_path in written
    assert rep_md_path.exists()
    rep_text = rep_md_path.read_text(encoding="utf-8")
    assert "| `IDOR` |" in rep_text
    assert "`2/12`" in rep_text  # exact recall denominator (C-001 + C-002 verified TPs out of 12 planted)
    assert "`1/2`" in rep_text   # exact patch pass denominator (C-001 PASS, C-002 FAIL)
    assert "`C-001`" in rep_text
    assert "`C-002`" in rep_text


def test_review_api_serves_staged_run_advisory_next_to_diff_before_approval(tmp_path: Path):
    runs_root = tmp_path / "runs"
    run_dir = runs_root / "staged-ui-01"
    sm, ws = _seed_staged_run_with_pass_and_fail_candidates(run_dir)
    sandbox = DockerSandbox(image="psa-sandbox:latest", agent_tag="p4ui")
    llm = MetaLLMClient(log_path=run_dir / "llm_calls.jsonl", use_cache=True)

    stage_plan(run_dir=run_dir, candidate_id="C-001", llm=llm, sandbox=sandbox)
    stage_patch(run_dir=run_dir, candidate_id="C-001", llm=llm, sandbox=sandbox)
    stage_check(run_dir=run_dir, candidate_id="C-001", sandbox=sandbox)
    stage_advise(run_dir=run_dir, ground_truth_path=GROUND_TRUTH, llm=llm)

    api = create_review_api(runs_root=runs_root, ground_truth_path=GROUND_TRUTH)

    async def exercise_staged_api() -> None:
        transport = httpx.ASGITransport(app=api)
        async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
            ui_resp = await client.get("/")
            assert ui_resp.status_code == 200
            assert "advisory_markdown" in ui_resp.text

            runs_resp = await client.get("/api/runs")
            assert runs_resp.status_code == 200
            run_ids = [r["run_id"] for r in runs_resp.json()["runs"]]
            assert "staged-ui-01" in run_ids

            detail_resp = await client.get("/api/runs/staged-ui-01")
            assert detail_resp.status_code == 200
            payload = detail_resp.json()
            c001 = next(f for f in payload["findings"] if f["candidate"]["id"] == "C-001")
            c002 = next(f for f in payload["findings"] if f["candidate"]["id"] == "C-002")

            # Shown next to diff BEFORE approval
            assert c001["approval"] is None
            assert c001["patch_result"]["unified_diff"].startswith("--- a/src/routes/invoices.js")
            assert "## 1. Summary" in (c001["advisory_markdown"] or "")
            assert c002["advisory_markdown"] is None

            # Approve via API updates staged state.json -> APPROVED
            sha = c001["patch_result"]["patch_sha256"]
            app_resp = await client.post(
                "/api/runs/staged-ui-01/bundles/C-001/approve",
                json={"reviewer": "sec-lead", "patch_sha256": sha, "target_branch": "psa/fix-c001"},
            )
            assert app_resp.status_code == 200
            assert app_resp.json()["patch_sha256"] == sha

    asyncio.run(exercise_staged_api())
    assert sm.get_candidate_state("C-001") == CandidateState.APPROVED
    assert generate_run_aggregate_report(run_dir, GROUND_TRUTH).exists()
