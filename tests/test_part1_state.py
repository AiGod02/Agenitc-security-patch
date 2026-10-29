"""Part 1 tests (written first): multi-stage state machine, envelopes, corruption redo, resume, void approval, CLI stages."""

from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
from pathlib import Path

import pytest

from agent.cli import main as cli_main
from agent.evidence import ApprovalError
from agent.workflow.pipeline import (
    stage_apply,
    stage_approve,
    stage_check,
    stage_detect,
    stage_patch,
    stage_plan,
    stage_recon,
    stage_verify,
)
from agent.workflow.state import (
    CorruptedArtifactError,
    IllegalStateTransitionError,
    StateManager,
    ensure_synced_state,
    read_stage_artifact,
    rebuild_state_from_events,
)
from contracts import CandidateState, RunState

ROOT = Path(__file__).resolve().parent.parent
FIXTURE_DIR = ROOT / "fixture" / "express-fixture"


def test_illegal_transition_rejected_and_logged_and_no_global_repair_state(tmp_path: Path):
    run_a = tmp_path / "runs" / "run-a"
    run_b = tmp_path / "runs" / "run-b"
    sm_a = StateManager(run_a, "run-a")
    sm_b = StateManager(run_b, "run-b")

    sm_a.transition_run(RunState.RECON)
    sm_a.transition_run(RunState.CANDIDATES)
    sm_a.init_candidate("C-001")

    # Illegal jump PROPOSED -> APPLIED must raise and log reason in events.jsonl (Acceptance #4)
    with pytest.raises(IllegalStateTransitionError, match="PROPOSED -> APPLIED"):
        sm_a.transition_candidate("C-001", CandidateState.APPLIED, reason="skip_gates")

    events_raw = (run_a / "events.jsonl").read_text(encoding="utf-8")
    assert "Illegal candidate transition" in events_raw
    assert "PROPOSED -> APPLIED" in events_raw
    assert sm_a.get_candidate_state("C-001") == CandidateState.PROPOSED

    # Valid path + per-candidate repair history isolated to run_a (not leaked into run_b)
    sm_a.transition_candidate("C-001", CandidateState.TEST_WRITTEN)
    sm_a.transition_candidate("C-001", CandidateState.VERIFIED_REPRODUCER)
    sm_a.transition_candidate("C-001", CandidateState.PLANNED)
    sm_a.transition_candidate("C-001", CandidateState.PATCH_PROPOSED)
    sm_a.record_candidate_repair_failure("C-001", "sig_hash_1", "guard failed")
    sm_a.transition_candidate("C-001", CandidateState.GUARD_REJECTED, reason="guard failed")

    sm_b.init_candidate("C-001")
    assert sm_a.get_candidate_repair_info("C-001")["repair_count"] == 1
    assert sm_b.get_candidate_repair_info("C-001")["repair_count"] == 0


def test_delete_or_tamper_state_json_rebuilds_from_events_jsonl(tmp_path: Path):
    run_dir = tmp_path / "runs" / "run-rebuild"
    sm = StateManager(run_dir, "run-rebuild")
    sm.transition_run(RunState.RECON)
    sm.transition_run(RunState.CANDIDATES)
    sm.init_candidate("C-007")
    sm.transition_candidate("C-007", CandidateState.TEST_WRITTEN)
    sm.transition_candidate("C-007", CandidateState.VERIFIED_REPRODUCER)

    original = json.loads((run_dir / "state.json").read_text(encoding="utf-8"))

    # 1. Delete state.json -> rebuild_state_from_events produces identical state (Acceptance #5)
    (run_dir / "state.json").unlink()
    assert not (run_dir / "state.json").exists()
    rebuilt = rebuild_state_from_events(run_dir)
    assert rebuilt["run_state"] == original["run_state"] == RunState.CANDIDATES.value
    assert rebuilt["candidates"]["C-007"]["state"] == CandidateState.VERIFIED_REPRODUCER.value
    assert (run_dir / "state.json").exists()

    # 2. Tamper with state.json -> ensure_synced_state detects disagreement, events.jsonl wins
    tampered = dict(rebuilt)
    tampered["run_state"] = RunState.APPLIED.value
    (run_dir / "state.json").write_text(json.dumps(tampered, indent=2), encoding="utf-8")

    synced = ensure_synced_state(run_dir)
    assert synced["run_state"] == RunState.CANDIDATES.value
    on_disk = json.loads((run_dir / "state.json").read_text(encoding="utf-8"))
    assert on_disk["run_state"] == RunState.CANDIDATES.value


def test_corrupted_artifact_detected_and_stage_redone(tmp_path: Path):
    run_dir = tmp_path / "runs" / "run-corrupt"
    recon_path = stage_recon(run_dir=run_dir, target_dir=FIXTURE_DIR, run_id="run-corrupt")
    assert recon_path == run_dir / "01_recon.json"

    env_ok = read_stage_artifact(recon_path)
    assert env_ok.run_id == "run-corrupt"
    assert env_ok.stage == "RECON"
    assert env_ok.status == "OK"
    assert len(env_ok.payload["routes"]) == 18

    # Corrupt payload inside 01_recon.json without updating payload_sha256 (Acceptance #7)
    corrupted_doc = json.loads(recon_path.read_text(encoding="utf-8"))
    corrupted_doc["payload"]["routes"] = []
    recon_path.write_text(json.dumps(corrupted_doc, indent=2), encoding="utf-8")

    with pytest.raises(CorruptedArtifactError):
        read_stage_artifact(recon_path)

    # Re-running stage_recon detects corruption, logs it in events.jsonl, and redoes the stage
    stage_recon(run_dir=run_dir, target_dir=FIXTURE_DIR, run_id="run-corrupt")
    restored = read_stage_artifact(recon_path)
    assert len(restored.payload["routes"]) == 18
    events_txt = (run_dir / "events.jsonl").read_text(encoding="utf-8")
    assert "artifact_corrupted" in events_txt


def test_patch_change_after_approval_voids_approval_and_returns_to_checks_passed(tmp_path: Path):
    # Initialize isolated git repo so stage_apply can also be tested against tamper
    repo = tmp_path / "repo"
    shutil.copytree(FIXTURE_DIR, repo, ignore=shutil.ignore_patterns("node_modules"))
    subprocess.run(["git", "init", "-b", "main"], cwd=repo, check=True, capture_output=True)
    subprocess.run(["git", "config", "user.name", "Reviewer"], cwd=repo, check=True)
    subprocess.run(["git", "config", "user.email", "reviewer@local"], cwd=repo, check=True)
    subprocess.run(["git", "add", "."], cwd=repo, check=True)
    subprocess.run(["git", "commit", "-m", "init"], cwd=repo, check=True, capture_output=True)

    run_dir = tmp_path / "runs" / "run-void"
    stage_recon(run_dir=run_dir, target_dir=repo, run_id="run-void")

    # Seed candidate C-007 through state machine to CHECKS_PASSED -> AWAITING_APPROVAL with a real patch
    sm = StateManager(run_dir, "run-void")
    sm.transition_run(RunState.CANDIDATES)
    sm.init_candidate("C-007")
    sm.transition_run(RunState.VERIFYING)
    sm.transition_candidate("C-007", CandidateState.TEST_WRITTEN)
    sm.transition_candidate("C-007", CandidateState.VERIFIED_REPRODUCER)
    sm.transition_run(RunState.PATCHING)
    sm.transition_candidate("C-007", CandidateState.PLANNED)
    sm.transition_candidate("C-007", CandidateState.PATCH_PROPOSED)
    sm.transition_run(RunState.CHECKING)
    sm.transition_candidate("C-007", CandidateState.CHECKS_PASSED)
    sm.transition_run(RunState.AWAITING_APPROVAL)
    sm.transition_candidate("C-007", CandidateState.AWAITING_APPROVAL)

    diff_text = (
        "--- a/src/routes/admin.js\n"
        "+++ b/src/routes/admin.js\n"
        "@@ -12,4 +12,4 @@\n"
        "   // Retrieve recent administrative audit trail entries\n"
        '-  router.get("/audit-log", (_req, res) => {\n'
        '+  router.get("/audit-log", requireAuth, requireAdmin, (_req, res) => {\n'
        "     return res.json({ entries: store.getAuditLog() });\n"
        "   });\n"
    )
    sha = hashlib.sha256(diff_text.encode("utf-8")).hexdigest()

    patch_cid_dir = run_dir / "04_patches" / "C-007"
    patch_cid_dir.mkdir(parents=True, exist_ok=True)
    (patch_cid_dir / "patch.diff").write_text(diff_text, encoding="utf-8")
    (patch_cid_dir / "patch.sha256").write_text(sha + "\n", encoding="utf-8")

    ev_cid_dir = run_dir / "06_evidence" / "C-007"
    ev_cid_dir.mkdir(parents=True, exist_ok=True)
    (ev_cid_dir / "patch.diff").write_text(diff_text, encoding="utf-8")
    (ev_cid_dir / "patch.sha256").write_text(sha + "\n", encoding="utf-8")
    (ev_cid_dir / "finding.json").write_text(
        json.dumps(
            {
                "candidate": {"id": "C-007"},
                "patch_result": {"final_status": "PASS", "patch_sha256": sha},
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    sm.write_envelope(
        run_dir / "05_checks" / "C-007.json",
        stage="CHECK",
        candidate_id="C-007",
        input_hash=sha,
        status="PASS",
        payload={"final_status": "PASS", "patch_sha256": sha, "guards_passed": True},
    )

    rec = stage_approve(
        run_dir=run_dir,
        candidate_id="C-007",
        reviewer="alice",
        expected_patch_sha256=sha,
        target_branch="psa/fix-c-007",
    )
    assert rec.patch_sha256 == sha
    assert sm.get_candidate_state("C-007") == CandidateState.APPROVED

    # Modify patch.diff after approval -> apply MUST void approval and revert candidate to CHECKS_PASSED!
    (patch_cid_dir / "patch.diff").write_text(diff_text + "\n", encoding="utf-8")
    with pytest.raises(ApprovalError, match="void"):
        stage_apply(run_dir=run_dir, repo_dir=repo, candidate_id="C-007", target_branch="psa/fix-c-007")

    synced = ensure_synced_state(run_dir)
    assert synced["candidates"]["C-007"]["state"] == CandidateState.CHECKS_PASSED.value
    approval_doc = json.loads((ev_cid_dir / "approval.json").read_text(encoding="utf-8"))
    assert approval_doc.get("voided") is True


def test_resumable_verify_and_standalone_cli_subcommands(tmp_path: Path):
    run_dir = tmp_path / "runs" / "run-cli-stages"

    # 1. Standalone CLI 'recon'
    assert cli_main(["recon", "--target", str(FIXTURE_DIR), "--run-dir", str(run_dir)]) == 0
    assert (run_dir / "01_recon.json").exists()

    # 2. Standalone CLI 'detect'
    assert cli_main(["detect", "--run-dir", str(run_dir)]) == 0
    cand_env = read_stage_artifact(run_dir / "02_candidates.json")
    first_cid = cand_env.payload["accepted"][0]["id"]
    second_cid = cand_env.payload["accepted"][1]["id"]

    # 3. Simulate mid-VERIFYING interruption by verifying ONLY candidate #1 first (--candidate first_cid)
    assert cli_main(["verify", "--run-dir", str(run_dir), "--candidate", first_cid]) == 0
    assert (run_dir / "03_verification" / f"{first_cid}.json").exists()
    assert not (run_dir / "03_verification" / f"{second_cid}.json").exists()

    # Count model_call events before resuming
    events_before = [
        json.loads(ln)
        for ln in (run_dir / "events.jsonl").read_text(encoding="utf-8").splitlines()
        if ln.strip()
    ]
    model_calls_for_first_before = [
        e for e in events_before if e["event_type"] == "model_call"
    ]

    # 4. Resume 'verify --max-candidates 2' -> first_cid MUST be skipped via artifact input_hash without new model calls for first_cid!
    assert cli_main(["verify", "--run-dir", str(run_dir), "--max-candidates", "2"]) == 0
    assert (run_dir / "03_verification" / f"{second_cid}.json").exists()

    events_after = [
        json.loads(ln)
        for ln in (run_dir / "events.jsonl").read_text(encoding="utf-8").splitlines()
        if ln.strip()
    ]
    skipped_events = [
        e
        for e in events_after
        if e["event_type"] == "artifact_event"
        and e["args"].get("action") == "stage_skipped_resumed"
        and e["args"].get("candidate_id") == first_cid
    ]
    assert len(skipped_events) == 1
    assert len(model_calls_for_first_before) >= 1

