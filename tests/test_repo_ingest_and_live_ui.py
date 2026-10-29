"""Tests (written first) for Git repo URL/path ingestion, auto-invariant helper setup, live UI scan launcher, real-time progress API, and 1-click branch apply."""

from __future__ import annotations

import asyncio
import json
import shutil
import subprocess
import time
from pathlib import Path

import httpx

from agent.api import create_review_api
from agent.ingest import prepare_ingested_target

ROOT = Path(__file__).resolve().parent.parent
FIXTURE_DIR = ROOT / "fixture" / "express-fixture"
GROUND_TRUTH = ROOT / "ground_truth.json"


def _create_git_repo_from_dir(src_dir: Path, repo_dir: Path, remove_invariant_helper: bool = False) -> str:
    shutil.copytree(src_dir, repo_dir, ignore=shutil.ignore_patterns("node_modules", ".git"))
    if remove_invariant_helper:
        inv_fp = repo_dir / "tests" / "helpers" / "invariant.js"
        if inv_fp.exists():
            inv_fp.unlink()
    subprocess.run(["git", "init", "-b", "main"], cwd=repo_dir, check=True, capture_output=True)
    subprocess.run(["git", "config", "user.name", "Judge Repo Owner"], cwd=repo_dir, check=True, capture_output=True)
    subprocess.run(["git", "config", "user.email", "judge@example.com"], cwd=repo_dir, check=True, capture_output=True)
    subprocess.run(["git", "add", "."], cwd=repo_dir, check=True, capture_output=True)
    subprocess.run(["git", "commit", "-m", "initial commit"], cwd=repo_dir, check=True, capture_output=True)
    head = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=repo_dir, text=True).strip()
    return head


def test_prepare_ingested_target_clones_git_repo_and_injects_invariant_and_test_script(tmp_path: Path):
    # Create a minimal Express git repo missing tests/helpers/invariant.js and missing a real "test" script
    ext_repo = tmp_path / "judge-express-app"
    ext_repo.mkdir(parents=True)
    (ext_repo / "package.json").write_text(
        json.dumps(
            {
                "name": "judge-express-app",
                "version": "1.0.0",
                "scripts": {"test": 'echo "Error: no test specified" && exit 1'},
                "dependencies": {"express": "^4.19.2"},
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    (ext_repo / "app.js").write_text(
        'const express = require("express");\n'
        "const app = express();\n"
        'app.get("/health", (req, res) => res.json({ ok: true }));\n'
        "module.exports = { app };\n",
        encoding="utf-8",
    )
    expected_commit = _create_git_repo_from_dir(ext_repo, tmp_path / "remote-judge-git")

    run_dir = tmp_path / "runs" / "ingest-01"
    meta = prepare_ingested_target(
        repo_source=str(tmp_path / "remote-judge-git"),
        run_dir=run_dir,
        build_custom_image=False,
    )

    assert meta["cloned_commit"] == expected_commit
    prepared = Path(meta["prepared_target"])
    assert (prepared / "tests" / "helpers" / "invariant.js").exists()
    assert "SECURITY_INVARIANT_VIOLATED" in (prepared / "tests" / "helpers" / "invariant.js").read_text(encoding="utf-8")

    pkg = json.loads((prepared / "package.json").read_text(encoding="utf-8"))
    assert "jest" in pkg["scripts"]["test"]
    assert (run_dir / "ingest_meta.json").exists()


def test_ui_repo_scan_launcher_live_progress_and_branch_apply(tmp_path: Path):
    # Simulate a judge pasting a git URL/path to an Express repo that doesn't even have invariant.js yet
    judge_git_remote = tmp_path / "judge-fixture-remote.git"
    _create_git_repo_from_dir(FIXTURE_DIR, judge_git_remote, remove_invariant_helper=True)

    runs_root = tmp_path / "runs"
    api = create_review_api(runs_root=runs_root, ground_truth_path=GROUND_TRUTH)

    async def exercise_full_judge_ui_flow() -> None:
        transport = httpx.ASGITransport(app=api)
        async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
            # 1. Verify UI HTML includes repo URL input, stage stepper, and side-by-side advisory
            ui_resp = await client.get("/")
            assert ui_resp.status_code == 200
            assert "Verified Security Patch Agent" in ui_resp.text
            assert "advisory_markdown" in ui_resp.text
            assert "/api/runs/start" in ui_resp.text

            # 2. Judge submits repository URL/path from UI
            start_resp = await client.post(
                "/api/runs/start",
                json={
                    "repo_source": str(judge_git_remote),
                    "run_id": "judge-live-01",
                    "max_candidates": 1,
                    "use_cache": True,
                },
            )
            assert start_resp.status_code == 200
            start_data = start_resp.json()
            assert start_data["run_id"] == "judge-live-01"

            # 3. Poll /api/runs/judge-live-01/live just like the browser UI does until AWAITING_APPROVAL
            deadline = time.monotonic() + 240.0
            final_live: dict = {}
            while time.monotonic() < deadline:
                live_resp = await client.get("/api/runs/judge-live-01/live")
                assert live_resp.status_code == 200
                final_live = live_resp.json()
                if final_live["job_status"] in ("AWAITING_APPROVAL", "COMPLETED", "FAILED"):
                    break
                await asyncio.sleep(1.0)

            assert final_live.get("job_status") in ("AWAITING_APPROVAL", "COMPLETED"), f"Unexpected live status: {final_live}"
            assert final_live["routes_discovered"] == 18
            assert len(final_live["candidates"]) >= 1

            # 4. Fetch full detail, verify C-001 has diff + 9-section advisory before approval
            detail_resp = await client.get("/api/runs/judge-live-01")
            assert detail_resp.status_code == 200
            detail = detail_resp.json()
            c001 = next(f for f in detail["findings"] if f["candidate"]["id"] == "C-001")
            sha = c001["patch_result"]["patch_sha256"]
            assert "## 1. Summary" in (c001["advisory_markdown"] or "")

            # 5. Judge clicks Approve Exact SHA-256 in UI
            app_resp = await client.post(
                "/api/runs/judge-live-01/bundles/C-001/approve",
                json={"reviewer": "hackathon-judge", "patch_sha256": sha, "target_branch": "psa/fix-c001"},
            )
            assert app_resp.status_code == 200

            # 6. Judge clicks Apply to Branch in UI (no manual repo_dir needed; uses cloned source_repo automatically!)
            apply_resp = await client.post(
                "/api/runs/judge-live-01/bundles/C-001/apply",
                json={"repo_dir": "", "target_branch": "psa/fix-c001"},
            )
            assert apply_resp.status_code == 200
            applied_out = apply_resp.json()
            assert applied_out["branch"] == "psa/fix-c001"
            assert len(applied_out["commit"]) == 40

    asyncio.run(exercise_full_judge_ui_flow())

