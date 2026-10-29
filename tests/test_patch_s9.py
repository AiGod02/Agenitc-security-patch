# Tests anti-vandalism guards and live end-to-end remediation patches in DockerSandbox (Slice S9).
import shutil
from pathlib import Path

from agent.llm import MetaLLMClient
from agent.patch import remediate_verified_finding, validate_candidate_diff_on_workspace
from agent.sandbox import DockerSandbox
from contracts import (
    Candidate,
    FinalPatchStatus,
    MatchReason,
    VerificationResult,
    VerificationStatus,
    VerifiedFinding,
    VulnerabilityClass,
)

ROOT = Path(__file__).resolve().parent.parent
FIXTURE_DIR = ROOT / "fixture" / "express-fixture"
REPRO_DIR = ROOT / "fixture" / "reproducers"


def _make_verified_f007() -> tuple[VerifiedFinding, str, str]:
    cand = Candidate(
        id="C-007",
        vulnerability_class=VulnerabilityClass.MISSING_AUTH,
        file="src/routes/admin.js",
        start_line=13,
        end_line=15,
        route="GET /api/admin/audit-log",
        reason="Missing requireAuth and requireAdmin middleware on /audit-log",
        evidence='router.get("/audit-log", (_req, res) => {',
        confidence=0.95,
        expected_security_failure="Unauthenticated GET /api/admin/audit-log returns HTTP 200",
        invariant_id="AUTH-ADMIN-AUDIT",
    )
    ver = VerificationResult(
        candidate_id="C-007",
        test_path="tests/generated/c_007.security.test.js",
        companion_test_path="tests/generated/c_007.companion.test.js",
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
        companion_test_path="tests/generated/c_007.companion.test.js",
        baseline_failure_summary="Matched SECURITY_INVARIANT_VIOLATED:AUTH-ADMIN-AUDIT",
    )
    sec_code = (REPRO_DIR / "f007.security.test.js").read_text(encoding="utf-8")
    comp_code = (REPRO_DIR / "f007.companion.test.js").read_text(encoding="utf-8")
    return vf, sec_code, comp_code


def test_guards_reject_route_deletion_test_tampering_and_oversize_diff(tmp_path: Path):
    ws = tmp_path / "ws"
    shutil.copytree(FIXTURE_DIR, ws, ignore=shutil.ignore_patterns("node_modules"))
    sandbox = DockerSandbox(image="psa-sandbox:latest", agent_tag="s9guard")
    vf, sec_code, comp_code = _make_verified_f007()

    # 1. Vandalizing patch that DELETES GET /api/admin/audit-log (returns 404 so security test might pass ifcompanion didn't catch, and route guard catches route removal!)
    delete_route_diff = """--- a/src/routes/admin.js
+++ b/src/routes/admin.js
@@ -11,6 +11,2 @@
-  // Retrieve recent administrative audit trail entries
-  router.get("/audit-log", (_req, res) => {
-    return res.json({ entries: store.getAuditLog() });
-  });
-
   // Mark an existing user account as inactive
"""
    r_del = validate_candidate_diff_on_workspace(
        "run-s9-del", vf, sec_code, comp_code, delete_route_diff, ws, sandbox
    )
    assert r_del.final_status == FinalPatchStatus.FAIL
    assert r_del.guards_passed is False
    assert r_del.guards is not None and r_del.guards.routes_identical is False

    # 2. Patch attempting to edit tests/ -> rejected by test_files_untouched guard
    edit_test_diff = """--- a/tests/baseline.test.js
+++ b/tests/baseline.test.js
@@ -1,3 +1,3 @@
 const request = require("supertest");
+// tampered comment
 const { createApp } = require("../src/app");
"""
    r_test = validate_candidate_diff_on_workspace(
        "run-s9-test", vf, sec_code, comp_code, edit_test_diff, ws, sandbox
    )
    assert r_test.final_status == FinalPatchStatus.FAIL
    assert r_test.guards_passed is False
    assert "tests/" in (r_test.failure_reason or "")

    # 3. Clean patch exceeding strict line_cap=1 -> flagged for human review, never auto-passed
    valid_but_capped_diff = """--- a/src/routes/admin.js
+++ b/src/routes/admin.js
@@ -12,4 +12,4 @@
   // Retrieve recent administrative audit trail entries
-  router.get("/audit-log", (_req, res) => {
+  router.get("/audit-log", requireAuth, requireAdmin, (_req, res) => {
     return res.json({ entries: store.getAuditLog() });
   });
"""
    r_cap = validate_candidate_diff_on_workspace(
        "run-s9-cap", vf, sec_code, comp_code, valid_but_capped_diff, ws, sandbox, line_cap=1
    )
    assert r_cap.final_status == FinalPatchStatus.FAIL
    assert r_cap.guards is not None
    assert r_cap.guards.flagged_for_human_review is True


def test_live_patch_loop_produces_at_least_three_end_to_end_pass_patches(tmp_path: Path):
    ws = tmp_path / "ws"
    shutil.copytree(FIXTURE_DIR, ws, ignore=shutil.ignore_patterns("node_modules"))
    sandbox = DockerSandbox(image="psa-sandbox:latest", agent_tag="s9live")
    llm = MetaLLMClient(use_cache=True)

    # Test 4 diverse verified flaws across IDOR, PATH_TRAVERSAL, INJECTION, MISSING_AUTH
    cases = [
        (
            "C-F001",
            VulnerabilityClass.IDOR,
            "src/routes/invoices.js",
            30,
            36,
            "GET /api/invoices/:id",
            "IDOR-INVOICE-READ",
            "Bob receives HTTP 200 and Alice's invoice inv-1001",
            "f001",
        ),
        (
            "C-F003",
            VulnerabilityClass.PATH_TRAVERSAL,
            "src/routes/files.js",
            20,
            31,
            "GET /api/files/download",
            "PATH-FILE-DOWNLOAD",
            "Traversal name=../private_keys/master_seed.txt reads outside storage/public",
            "f003",
        ),
        (
            "C-F005",
            VulnerabilityClass.INJECTION,
            "src/routes/search.js",
            12,
            28,
            "GET /api/search/logs",
            "INJ-LOG-CMD",
            "Shell metacharacters in keyword execute injected command via execSync",
            "f005",
        ),
        (
            "C-F007",
            VulnerabilityClass.MISSING_AUTH,
            "src/routes/admin.js",
            13,
            15,
            "GET /api/admin/audit-log",
            "AUTH-ADMIN-AUDIT",
            "Unauthenticated GET /api/admin/audit-log returns HTTP 200",
            "f007",
        ),
    ]

    pass_count = 0
    for cid, vclass, rel_file, s_line, e_line, route, inv_id, exp_fail, prefix in cases:
        cand = Candidate(
            id=cid,
            vulnerability_class=vclass,
            file=rel_file,
            start_line=s_line,
            end_line=e_line,
            route=route,
            reason=exp_fail,
            evidence=f"{rel_file}:{s_line}",
            confidence=0.9,
            expected_security_failure=exp_fail,
            invariant_id=inv_id,
        )
        slug = cid.lower().replace("-", "_")
        ver = VerificationResult(
            candidate_id=cid,
            test_path=f"tests/generated/{slug}.security.test.js",
            companion_test_path=f"tests/generated/{slug}.companion.test.js",
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
            companion_test_path=f"tests/generated/{slug}.companion.test.js",
            baseline_failure_summary=f"Matched SECURITY_INVARIANT_VIOLATED:{inv_id}",
        )
        sec_code = (REPRO_DIR / f"{prefix}.security.test.js").read_text(encoding="utf-8")
        comp_code = (REPRO_DIR / f"{prefix}.companion.test.js").read_text(encoding="utf-8")

        res = remediate_verified_finding(
            run_id=f"run-s9-{cid}",
            verified_finding=vf,
            security_test_code=sec_code,
            companion_test_code=comp_code,
            source_workspace=ws,
            sandbox=sandbox,
            llm=llm,
        )
        if res.final_status == FinalPatchStatus.PASS:
            assert res.guards_passed is True
            assert res.patched_security_exit_code == 0
            assert res.companion_after_exit_code == 0
            assert res.full_suite_exit_code == 0
            pass_count += 1

    assert pass_count >= 3, f"Expected >=3 end-to-end PASS patches, got {pass_count}"
