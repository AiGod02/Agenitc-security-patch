import json
import os
import shutil
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
FIXTURE_DIR = ROOT / "fixture" / "express-fixture"
GROUND_TRUTH = ROOT / "ground_truth.json"


def _run_jest(work: Path, extra_args: list[str] | None = None) -> subprocess.CompletedProcess[str]:
    jest_bin = FIXTURE_DIR / "node_modules" / "jest" / "bin" / "jest.js"
    env = os.environ.copy()
    env["NODE_PATH"] = str(FIXTURE_DIR / "node_modules")
    cmd = ["node", str(jest_bin), "--runInBand", "--json"]
    if extra_args:
        cmd.extend(extra_args)
    return subprocess.run(
        cmd,
        cwd=work,
        env=env,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=60,
    )


def test_ground_truth_and_all_flaws_red_green(tmp_path: Path):
    gt = json.loads(GROUND_TRUTH.read_text(encoding="utf-8"))
    assert len(gt["flaws"]) == 12

    work = tmp_path / "express-fixture"
    shutil.copytree(
        FIXTURE_DIR,
        work,
        ignore=shutil.ignore_patterns("node_modules"),
    )

    # 1. Baseline suite must be 100% green
    base_res = _run_jest(work)
    assert base_res.returncode == 0, f"Baseline suite failed:\n{base_res.stderr}\n{base_res.stdout}"
    base_report = json.loads(base_res.stdout)
    assert base_report["numFailedTests"] == 0
    assert base_report["numPassedTests"] == 6

    # 2. Copy all 12 security & companion tests into tests/reproducers/ and run Jest --json
    repro_dst = work / "tests" / "reproducers"
    repro_dst.mkdir(parents=True, exist_ok=True)
    for flaw in gt["flaws"]:
        sec_src = ROOT / flaw["reproducer_test_path"]
        comp_src = ROOT / flaw["companion_test_path"]
        shutil.copy2(sec_src, repro_dst / sec_src.name)
        shutil.copy2(comp_src, repro_dst / comp_src.name)

    repro_res = _run_jest(work, ["tests/reproducers"])
    assert repro_res.returncode != 0
    report = json.loads(repro_res.stdout)
    by_name = {Path(tr["name"]).name: tr for tr in report["testResults"]}

    for flaw in gt["flaws"]:
        sec_name = Path(flaw["reproducer_test_path"]).name
        comp_name = Path(flaw["companion_test_path"]).name
        assert sec_name in by_name, f"Missing result for {sec_name}"
        assert comp_name in by_name, f"Missing result for {comp_name}"

        sec_tr = by_name[sec_name]
        comp_tr = by_name[comp_name]

        assert sec_tr["status"] == "failed", f"Expected {sec_name} to fail on vulnerable code"
        msgs = "\n".join(
            msg for ar in sec_tr["assertionResults"] for msg in ar.get("failureMessages", [])
        )
        assert flaw["expected_invariant_text"] in msgs, (
            f"Expected tag {flaw['expected_invariant_text']} in {sec_name}, got:\n{msgs}"
        )
        assert comp_tr["status"] == "passed", (
            f"Expected companion {comp_name} to pass on baseline, got:\n{comp_tr}"
        )
