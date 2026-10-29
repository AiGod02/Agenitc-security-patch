"""Part 3 tests (written first): plan-guided patching, test-literal guard, scope guard, held-out variant test, sibling variant analysis."""

from __future__ import annotations

import json
import shutil
from pathlib import Path

from agent.llm import MetaLLMClient
from agent.patch.deep_patch import (
    ensure_heldout_variant_test,
    evaluate_deep_patch_checks,
    find_possible_variants,
)
from agent.sandbox import DockerSandbox
from agent.tools import ToolDispatcher
from agent.workflow import StateManager, read_stage_artifact, stage_check, stage_patch, stage_plan, stage_recon
from contracts import (
    Candidate,
    CandidateState,
    FinalPatchStatus,
    MatchReason,
    RunState,
    VerificationResult,
    VerificationStatus,
    VerifiedFinding,
    VulnerabilityClass,
)

ROOT = Path(__file__).resolve().parent.parent
FIXTURE_DIR = ROOT / "fixture" / "express-fixture"
REPRO_DIR = ROOT / "fixture" / "reproducers"


def _seed_verified_f001(run_dir: Path) -> tuple[StateManager, VerifiedFinding, str, str]:
    stage_recon(run_dir=run_dir, target_dir=FIXTURE_DIR, run_id=run_dir.name)
    sm = StateManager(run_dir, run_dir.name)
    sm.transition_run(RunState.CANDIDATES)
    sm.init_candidate("C-001")
    sm.transition_run(RunState.VERIFYING)
    sm.transition_candidate("C-001", CandidateState.TEST_WRITTEN)
    sm.transition_candidate("C-001", CandidateState.VERIFIED_REPRODUCER)

    cand = Candidate(
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
    sec_code = (REPRO_DIR / "f001.security.test.js").read_text(encoding="utf-8")
    comp_code = (REPRO_DIR / "f001.companion.test.js").read_text(encoding="utf-8")

    ver_dir = run_dir / "03_verification"
    ver_dir.mkdir(parents=True, exist_ok=True)
    (ver_dir / "C-001.security.test.js").write_text(sec_code, encoding="utf-8")
    (ver_dir / "C-001.companion.test.js").write_text(comp_code, encoding="utf-8")
    (ver_dir / "C-001.baseline.jest.json").write_text('{"numFailedTests":1}', encoding="utf-8")
    sm.write_envelope(
        ver_dir / "C-001.json",
        stage="VERIFYING",
        candidate_id="C-001",
        input_hash="c" * 64,
        status=VerificationStatus.VERIFIED_REPRODUCER.value,
        payload={
            "candidate": cand.model_dump(),
            "verification": ver.model_dump(),
            "verified_finding": vf.model_dump(),
            "security_test_file": "03_verification/C-001.security.test.js",
            "companion_test_file": "03_verification/C-001.companion.test.js",
            "baseline_jest_file": "03_verification/C-001.baseline.jest.json",
        },
    )
    return sm, vf, sec_code, comp_code


def test_hardcoded_test_literal_rejected_and_out_of_scope_patch_flagged(tmp_path: Path):
    run_dir = tmp_path / "runs" / "run-p3-guards"
    _, vf, sec_code, comp_code = _seed_verified_f001(run_dir)
    ws = run_dir / "workspace_copy"
    sandbox = DockerSandbox(image="psa-sandbox:latest", agent_tag="p3guard")
    cid_patch_dir = run_dir / "04_patches" / "C-001"
    cid_patch_dir.mkdir(parents=True, exist_ok=True)

    plan_payload = {
        "candidate_id": "C-001",
        "violated_invariant": "IDOR-INVOICE-READ",
        "expected_scope_files": ["src/routes/invoices.js"],
    }

    # 1. Patch hardcoding literal "inv-1001" / "u-bob" from security test -> REJECTED (Acceptance #11)
    hardcoded_literal_diff = """--- a/src/routes/invoices.js
+++ b/src/routes/invoices.js
@@ -32,4 +32,7 @@
     if (!invoice) {
       return res.status(404).json({ error: "Invoice not found" });
     }
+    if (req.params.id === "inv-1001" && req.user.id === "u-bob") {
+      return res.status(403).json({ error: "Forbidden" });
+    }
     return res.json(invoice);
"""
    res_lit, extra_lit = evaluate_deep_patch_checks(
        run_id="run-p3-guards",
        verified_finding=vf,
        plan_payload=plan_payload,
        cid_patch_dir=cid_patch_dir,
        security_test_code=sec_code,
        companion_test_code=comp_code,
        unified_diff=hardcoded_literal_diff,
        source_workspace=ws,
        sandbox=sandbox,
    )
    assert res_lit.final_status == FinalPatchStatus.FAIL
    assert res_lit.guards_passed is False
    assert extra_lit["literal_check_passed"] is False
    assert "hardcod" in (res_lit.failure_reason or "").lower()

    # 2. Patch touching src/store.js outside expected_scope_files=["src/routes/invoices.js"] -> FLAGGED (Acceptance #11)
    out_of_scope_diff = """--- a/src/routes/invoices.js
+++ b/src/routes/invoices.js
@@ -32,4 +32,7 @@
     if (!invoice) {
       return res.status(404).json({ error: "Invoice not found" });
     }
+    if (invoice.ownerId !== req.user.id && req.user.role !== "admin") {
+      return res.status(403).json({ error: "Forbidden" });
+    }
     return res.json(invoice);
--- a/src/store.js
+++ b/src/store.js
@@ -94,4 +94,5 @@
     getInvoice(id) {
+      // out-of-scope edit in data layer
       const inv = invoices.get(id);
       return inv ? { ...inv } : null;
"""
    res_scope, extra_scope = evaluate_deep_patch_checks(
        run_id="run-p3-guards",
        verified_finding=vf,
        plan_payload=plan_payload,
        cid_patch_dir=cid_patch_dir,
        security_test_code=sec_code,
        companion_test_code=comp_code,
        unified_diff=out_of_scope_diff,
        source_workspace=ws,
        sandbox=sandbox,
    )
    assert res_scope.final_status == FinalPatchStatus.FAIL
    assert res_scope.guards is not None
    assert res_scope.guards.flagged_for_human_review is True
    assert extra_scope["scope_check_passed"] is False


def test_heldout_variant_test_catches_shallow_patch_and_passes_real_patch(tmp_path: Path):
    run_dir = tmp_path / "runs" / "run-p3-variant"
    sm, vf, sec_code, comp_code = _seed_verified_f001(run_dir)
    ws = run_dir / "workspace_copy"
    sandbox = DockerSandbox(image="psa-sandbox:latest", agent_tag="p3var")
    llm = MetaLLMClient(log_path=run_dir / "llm_calls.jsonl", use_cache=True)

    # Plan first via live Muse Wonder
    stage_plan(run_dir=run_dir, candidate_id="C-001", llm=llm, sandbox=sandbox)
    plan_env = read_stage_artifact(run_dir / "04_patches" / "C-001" / "patch_plan.json")
    cid_patch_dir = run_dir / "04_patches" / "C-001"

    # Generate held-out variant test via live Muse Wonder and verify it FAILS on vulnerable baseline with tag!
    disp = ToolDispatcher(ws, sandbox)
    var_res = ensure_heldout_variant_test(
        run_id="run-p3-variant",
        cid_patch_dir=cid_patch_dir,
        verified_finding=vf,
        original_security_test_code=sec_code,
        companion_test_code=comp_code,
        dispatcher=disp,
        llm=llm,
        workspace=ws,
    )
    assert var_res.baseline_matched_tag is True
    assert var_res.baseline_exit_code != 0

    # Deliberately shallow patch: checks amountCents > 20000 (protects Alice's 45000 inv-1001 without test literals,
    # so original test + companion test + literal check ALL pass, while Bob's 12000 inv-2001 / newly created small invoice fails variant!)
    shallow_diff = """--- a/src/routes/invoices.js
+++ b/src/routes/invoices.js
@@ -32,4 +32,7 @@
     if (!invoice) {
       return res.status(404).json({ error: "Invoice not found" });
     }
+    if (invoice.amountCents === 45000 && invoice.ownerId !== req.user.id) {
+      return res.status(403).json({ error: "Forbidden" });
+    }
     return res.json(invoice);
"""
    res_shallow, extra_shallow = evaluate_deep_patch_checks(
        run_id="run-p3-variant",
        verified_finding=vf,
        plan_payload=plan_env.payload,
        cid_patch_dir=cid_patch_dir,
        security_test_code=sec_code,
        companion_test_code=comp_code,
        unified_diff=shallow_diff,
        source_workspace=ws,
        sandbox=sandbox,
    )
    assert res_shallow.patched_security_exit_code == 0  # passed original test!
    assert res_shallow.companion_after_exit_code == 0   # passed companion test!
    assert extra_shallow["literal_check_passed"] is True
    assert extra_shallow["variant_passed_after_patch"] is False  # caught by held-out variant test!
    assert res_shallow.final_status == FinalPatchStatus.FAIL

    # Now run real plan-guided stage_patch + stage_check -> passes original, companion, variant, full suite, and guards!
    stage_patch(run_dir=run_dir, candidate_id="C-001", llm=llm, sandbox=sandbox)
    stage_check(run_dir=run_dir, candidate_id="C-001", sandbox=sandbox)
    assert sm.get_candidate_state("C-001") == CandidateState.AWAITING_APPROVAL

    chk_env = read_stage_artifact(run_dir / "05_checks" / "C-001.json")
    assert chk_env.status == FinalPatchStatus.PASS.value
    assert chk_env.payload["extra_checks"]["variant_passed_after_patch"] is True


def test_variant_analysis_lists_real_unpatched_sibling_routes_as_possible_variants(tmp_path: Path):
    run_dir = tmp_path / "runs" / "run-p3-siblings"
    _, vf, _, _ = _seed_verified_f001(run_dir)
    recon_env = read_stage_artifact(run_dir / "01_recon.json")
    recon_routes = recon_env.payload["routes"]

    possible = find_possible_variants(vf, recon_routes)
    assert len(possible) >= 1
    assert all(p.label == "possible variant" for p in possible)
    # Must discover sibling IDOR-pattern route PUT /api/users/:id/email in src/routes/users.js:17
    assert any(
        p.route == "PUT /api/users/:id/email" and p.file == "src/routes/users.js" and p.line == 17
        for p in possible
    )
    # Confirm sibling file src/routes/users.js in workspace_copy was NOT modified
    orig_users = (FIXTURE_DIR / "src" / "routes" / "users.js").read_text(encoding="utf-8")
    ws_users = (run_dir / "workspace_copy" / "src" / "routes" / "users.js").read_text(encoding="utf-8")
    assert orig_users == ws_users
