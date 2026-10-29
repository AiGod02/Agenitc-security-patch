"""CLI evaluation runner executing >=1 real workflow runs and computing Section 11 metrics (Slice S12)."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import argparse
import json
from pathlib import Path

from agent.workflow import run_security_workflow
from eval.report import format_evaluation_markdown, score_single_run


def _run_and_score_one(
    idx: int,
    target_dir: Path,
    ground_truth_path: Path,
    runs_root: Path,
    use_cache: bool,
) -> tuple[int, dict]:
    run_id = f"eval-run-{idx:02d}"
    print(f"[eval] starting {run_id} (use_cache={use_cache})...", flush=True)
    wf = run_security_workflow(
        target_dir=target_dir,
        runs_root=runs_root,
        run_id=run_id,
        use_cache=use_cache,
    )
    metrics = score_single_run(wf.run_dir, ground_truth_path)
    ov = metrics["overall"]
    print(
        f"[eval] finished {run_id} in {wf.duration_ms}ms: "
        f"candidates={ov['candidates']} verified_tp={ov['verified_planted_tp']}/{ov['planted']} "
        f"patches_passed={ov['patches_passed']}",
        flush=True,
    )
    return idx, metrics


def run_evaluation(
    target_dir: Path,
    ground_truth_path: Path,
    runs_root: Path,
    num_runs: int = 3,
    use_cache: bool = False,
    max_workers: int = 3,
) -> tuple[list[dict], str]:
    workers = 1 if use_cache else max(1, min(max_workers, num_runs))
    indexed_results: list[tuple[int, dict]] = []
    if workers == 1:
        for idx in range(1, num_runs + 1):
            indexed_results.append(
                _run_and_score_one(idx, target_dir, ground_truth_path, runs_root, use_cache)
            )
    else:
        with ThreadPoolExecutor(max_workers=workers) as pool:
            futures = [
                pool.submit(_run_and_score_one, idx, target_dir, ground_truth_path, runs_root, use_cache)
                for idx in range(1, num_runs + 1)
            ]
            for fut in futures:
                indexed_results.append(fut.result())

    indexed_results.sort(key=lambda pair: pair[0])
    scored = [m for _, m in indexed_results]

    md = format_evaluation_markdown(scored)
    runs_root.mkdir(parents=True, exist_ok=True)
    (runs_root / "evaluation_metrics.json").write_text(json.dumps(scored, indent=2), encoding="utf-8")
    (runs_root / "evaluation_report.md").write_text(md, encoding="utf-8")
    return scored, md


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run empirical evaluation and generate Section 11 report")
    parser.add_argument("--target", default=Path("fixture/express-fixture"), type=Path)
    parser.add_argument("--ground-truth", default=Path("ground_truth.json"), type=Path)
    parser.add_argument("--runs-dir", default=Path("runs/eval"), type=Path)
    parser.add_argument("--num-runs", default=3, type=int)
    parser.add_argument("--use-cache", action="store_true")
    parser.add_argument("--score-existing", nargs="*", type=Path, help="Score existing run directories instead of launching new runs")
    args = parser.parse_args(argv)

    if args.score_existing:
        scored = [score_single_run(p, args.ground_truth) for p in args.score_existing]
        md = format_evaluation_markdown(scored)
        args.runs_dir.mkdir(parents=True, exist_ok=True)
        (args.runs_dir / "evaluation_metrics.json").write_text(json.dumps(scored, indent=2), encoding="utf-8")
        (args.runs_dir / "evaluation_report.md").write_text(md, encoding="utf-8")
        print(md)
        return 0

    _, md = run_evaluation(
        target_dir=args.target,
        ground_truth_path=args.ground_truth,
        runs_root=args.runs_dir,
        num_runs=args.num_runs,
        use_cache=args.use_cache,
    )
    print(md)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

