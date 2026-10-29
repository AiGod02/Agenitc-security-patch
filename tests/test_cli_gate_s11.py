# Tests patch-hash approval, tamper invalidation, designated-branch git apply, and CLI gate exit codes (Slice S11).
import hashlib
import shutil
import subprocess
from pathlib import Path

import pytest

from agent.cli import run_cli_gate
from agent.evidence import (
    ApprovalError,
    apply_approved_patch_to_branch,
    approve_finding_patch,
    write_evidence_bundle,
)
from agent.sandbox import DockerSandbox
from agent.tools.dispatcher import resolve_workspace_path
from agent.tools.patch_applier import apply_unified_diff_to_workspace
from contracts import (
    Candidate,
    CLIExitCode,
    FinalPatchStatus,
    GuardCheckResult,
    MatchReason,
    PatchResult,
    VerificationResult,
    VerificationStatus,
    VerifiedFinding,
    VulnerabilityClass,
)

ROOT = Path(__file__).resolve().parent.parent
FIXTURE_DIR = ROOT / "fixture" / "express-fixture"
REPRO_DIR = ROOT / "fixture" / "reproducers"


F007_DIFF = """--- a/src/routes/admin.js
+++ b/src/routes/admin.js
@@ -12,4 +12,4 @@
   // Retrieve recent administrative audit trail entries
-  router.get("/audit-log", (_req, res) => {
+  router.get("/audit-log", requireAuth, requireAdmin, (_req, res) => {
     return res.json({ entries: store.getAuditLog() });
   });
"""


def _build_f007_bundle(run_dir: Path) -> tuple[Path, str]:
    cand = Candidate(
        id="C-007",
        vulnerability_class=VulnerabilityClass.MISSING_AUTH,
        file="src/routes/admin.js",
        start_line=13,
        end_line=15,
        route="GET /api/admin/audit-log",
        reason="Missing auth on audit-log",
        evidence='router.get("/audit-log", ...)',
        confidence=0.95,
        expected_security_failure="Unauthenticated access returns 200",
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
    sha = hashlib.sha256(F007_DIFF.encode("utf-8")).hexdigest()
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
        candidate_id="C-007",
        unified_diff=F007_DIFF,
        patch_sha256=sha,
        attempts=1,
        patched_security_exit_code=0,
        companion_after_exit_code=0,
        full_suite_exit_code=0,
        guards=guards,
        guards_passed=True,
        final_status=FinalPatchStatus.PASS,
    )
    sec_code = (REPRO_DIR / "f007.security.test.js").read_text(encoding="utf-8")
    comp_code = (REPRO_DIR / "f007.companion.test.js").read_text(encoding="utf-8")
    bundle_dir = write_evidence_bundle(run_dir, vf, sec_code, comp_code, '{"numFailedTests":1}', pr)
    return bundle_dir, sha


def test_approval_hash_binding_tamper_rejection_and_git_branch_apply(tmp_path: Path):
    # Initialize an isolated git repo containing the Express fixture
    repo = tmp_path / "repo"
    shutil.copytree(FIXTURE_DIR, repo, ignore=shutil.ignore_patterns("node_modules"))
    subprocess.run(["git", "init", "-b", "main"], cwd=repo, check=True, capture_output=True)
    subprocess.run(["git", "config", "user.name", "Reviewer"], cwd=repo, check=True)
    subprocess.run(["git", "config", "user.email", "reviewer@local"], cwd=repo, check=True)
    subprocess.run(["git", "add", "."], cwd=repo, check=True)
    subprocess.run(["git", "commit", "-m", "baseline"], cwd=repo, check=True, capture_output=True)

    bundle_dir, sha = _build_f007_bundle(tmp_path / "runs" / "r1")

    # 1. Wrong hash rejected
    with pytest.raises(ApprovalError):
        approve_finding_patch(bundle_dir, "alice", "0" * 64, "psa/fix-c-007")

    # 2. Protected 'main' branch rejected
    with pytest.raises(ApprovalError):
        approve_finding_patch(bundle_dir, "alice", sha, "main")

    # 3. Exact hash approved
    rec = approve_finding_patch(bundle_dir, "alice", sha, "psa/fix-c-007")
    assert rec.patch_sha256 == sha

    # 4. Tamper with patch.diff by 1 byte after approval -> apply MUST block!
    orig_diff = (bundle_dir / "patch.diff").read_text(encoding="utf-8")
    (bundle_dir / "patch.diff").write_text(orig_diff + "\n", encoding="utf-8")
    with pytest.raises(ApprovalError):
        apply_approved_patch_to_branch(repo, bundle_dir)

    # Restore exact approved diff -> apply succeeds onto psa/fix-c-007 while leaving main untouched!
    (bundle_dir / "patch.diff").write_text(orig_diff, encoding="utf-8")
    applied = apply_approved_patch_to_branch(repo, bundle_dir)
    assert applied["branch"] == "psa/fix-c-007"
    assert applied["patched_files"] == ["src/routes/admin.js"]

    # Verify main branch working tree was NOT modified (no auto-merge!)
    main_admin = (repo / "src" / "routes" / "admin.js").read_text(encoding="utf-8")
    assert 'router.get("/audit-log", (_req, res) => {' in main_admin

    # Verify designated branch commit has the fix
    branch_admin = subprocess.run(
        ["git", "show", "psa/fix-c-007:src/routes/admin.js"],
        cwd=repo,
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    assert 'router.get("/audit-log", requireAuth, requireAdmin, (_req, res) => {' in branch_admin


def test_cli_gate_blocks_vulnerable_and_passes_patched_fixture(tmp_path: Path):
    sandbox = DockerSandbox(image="psa-sandbox:latest", agent_tag="s11gate")

    # Prepare reproducers folder with F-007 security & companion tests
    repro_subset = tmp_path / "repro_f007"
    repro_subset.mkdir()
    shutil.copy2(REPRO_DIR / "f007.security.test.js", repro_subset / "f007.security.test.js")
    shutil.copy2(REPRO_DIR / "f007.companion.test.js", repro_subset / "f007.companion.test.js")

    # 1. Vulnerable fixture -> CLI gate MUST fail with exit code 1
    vuln_ws = tmp_path / "vuln"
    shutil.copytree(FIXTURE_DIR, vuln_ws, ignore=shutil.ignore_patterns("node_modules"))
    code_vuln, _ = run_cli_gate(vuln_ws, reproducers_dir=repro_subset, sandbox=sandbox)
    assert code_vuln == CLIExitCode.VULNERABLE_OR_UNVERIFIED

    # 2. Missing target -> CLI gate MUST fail with exit code 2
    code_err, _ = run_cli_gate(tmp_path / "does_not_exist", reproducers_dir=repro_subset, sandbox=sandbox)
    assert code_err == CLIExitCode.INCONCLUSIVE_OR_ERROR

    # 3. Patched fixture -> CLI gate MUST pass with exit code 0
    patched_ws = tmp_path / "patched"
    shutil.copytree(FIXTURE_DIR, patched_ws, ignore=shutil.ignore_patterns("node_modules"))
    apply_unified_diff_to_workspace(
        patched_ws,
        F007_DIFF,
        lambda rel: resolve_workspace_path(patched_ws, rel),
    )
    code_pass, payload_pass = run_cli_gate(patched_ws, reproducers_dir=repro_subset, sandbox=sandbox)
    assert code_pass == CLIExitCode.PASS
    assert payload_pass["status"] == "PASS"
