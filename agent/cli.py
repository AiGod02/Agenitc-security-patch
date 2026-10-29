"""Primary CLI entrypoint and pre-merge security gate (Slice S11, Sections 4 & 9)."""

from __future__ import annotations

import argparse
import json
import shutil
import sys
import tempfile
from pathlib import Path

from agent.evidence import (
    ApprovalError,
    apply_approved_patch_to_branch,
    approve_finding_patch,
    replay_run,
)
from agent.llm import LLMClientError, MetaLLMClient
from agent.sandbox import DockerSandbox
from agent.verify.matcher import extract_jest_json
from agent.workflow import run_security_workflow
from contracts import CLIExitCode, SandboxRunner, VerificationStatus


def run_cli_gate(
    target_dir: Path,
    reproducers_dir: Path | None = None,
    sandbox: SandboxRunner | None = None,
    runs_root: Path | None = None,
) -> tuple[CLIExitCode, dict]:
    """Evaluate target_dir and return Section 12A CLI exit code (0 pass, 1 vulnerable/unverified, 2 inconclusive/error)."""
    if not target_dir.exists() or not target_dir.is_dir():
        return CLIExitCode.INCONCLUSIVE_OR_ERROR, {"error": f"Target directory does not exist: {target_dir}"}

    effective_sandbox = sandbox or DockerSandbox(image="psa-sandbox:latest", agent_tag="gate")

    with tempfile.TemporaryDirectory(prefix="psa-gate-") as tmp_dir:
        ws = Path(tmp_dir) / "ws"
        shutil.copytree(
            target_dir.resolve(),
            ws,
            ignore=shutil.ignore_patterns("node_modules", ".git", "runs"),
        )

        # 1. Baseline functional suite must exist and pass
        tests_folder = ws / "tests"
        if not tests_folder.exists():
            return CLIExitCode.INCONCLUSIVE_OR_ERROR, {"error": "Missing tests/ directory in target"}

        base_run = effective_sandbox.run(ws, ["jest", "--runInBand", "--json"], timeout_s=45.0)
        if base_run.timed_out:
            return CLIExitCode.INCONCLUSIVE_OR_ERROR, {"error": "Baseline test suite timed out"}
        base_report = extract_jest_json(base_run.stdout)
        if base_report is None or int(base_report.get("numTotalTests") or 0) == 0:
            return CLIExitCode.INCONCLUSIVE_OR_ERROR, {"error": "Baseline suite produced no valid Jest test report"}
        if base_run.exit_code != 0 or int(base_report.get("numFailedTests") or 0) > 0:
            return CLIExitCode.VULNERABLE_OR_UNVERIFIED, {
                "reason": "Baseline or embedded security tests failed",
                "numFailedTests": base_report.get("numFailedTests"),
            }

        # 2. If explicit reproducers/bundle tests directory is supplied, verify all security + companion tests pass
        if reproducers_dir is not None:
            if not reproducers_dir.exists():
                return CLIExitCode.INCONCLUSIVE_OR_ERROR, {"error": f"Reproducers directory missing: {reproducers_dir}"}
            sec_files = sorted(reproducers_dir.glob("*.security.test.js")) + sorted(reproducers_dir.glob("security.test.js"))
            comp_files = sorted(reproducers_dir.glob("*.companion.test.js")) + sorted(reproducers_dir.glob("companion.test.js"))
            if not sec_files:
                return CLIExitCode.INCONCLUSIVE_OR_ERROR, {"error": f"No security tests found in {reproducers_dir}"}

            gate_dst = ws / "tests" / "gate_checks"
            gate_dst.mkdir(parents=True, exist_ok=True)
            rel_targets: list[str] = []
            for idx, fp in enumerate([*sec_files, *comp_files]):
                dst_name = f"g{idx:03d}_{fp.name}"
                shutil.copy2(fp, gate_dst / dst_name)
                rel_targets.append(f"tests/gate_checks/{dst_name}")

            gate_run = effective_sandbox.run(
                ws,
                ["jest", "--runInBand", "--json", "--runTestsByPath", *rel_targets],
                timeout_s=60.0,
            )
            if gate_run.timed_out:
                return CLIExitCode.INCONCLUSIVE_OR_ERROR, {"error": "Gate security test run timed out"}
            gate_report = extract_jest_json(gate_run.stdout)
            if gate_report is None or int(gate_report.get("numTotalTests") or 0) == 0:
                return CLIExitCode.INCONCLUSIVE_OR_ERROR, {"error": "Gate tests produced invalid Jest report"}
            if gate_run.exit_code != 0 or int(gate_report.get("numFailedTests") or 0) > 0:
                return CLIExitCode.VULNERABLE_OR_UNVERIFIED, {
                    "reason": "Security invariant or companion test failed on target",
                    "numFailedTests": gate_report.get("numFailedTests"),
                    "numPassedTests": gate_report.get("numPassedTests"),
                }
            return CLIExitCode.PASS, {
                "status": "PASS",
                "baselinePassedTests": base_report.get("numPassedTests"),
                "gatePassedTests": gate_report.get("numPassedTests"),
            }

        # 3. Full live scan gate when no pre-existing reproducers_dir is supplied
        try:
            llm = MetaLLMClient(use_cache=True)
        except LLMClientError as exc:
            return CLIExitCode.INCONCLUSIVE_OR_ERROR, {"error": str(exc)}

        effective_runs = runs_root or (Path.cwd() / "runs" / "gate")
        wf = run_security_workflow(
            target_dir=target_dir,
            runs_root=effective_runs,
            sandbox=effective_sandbox,
            llm=llm,
            skip_patch=True,
        )
        verified_cnt = sum(1 for v in wf.verifications if v.status == VerificationStatus.VERIFIED_REPRODUCER)
        inconclusive_cnt = sum(1 for v in wf.verifications if v.status == VerificationStatus.INCONCLUSIVE)
        if verified_cnt > 0:
            return CLIExitCode.VULNERABLE_OR_UNVERIFIED, {
                "reason": f"Detected {verified_cnt} verified reproducible vulnerabilities",
                "run_id": wf.run_id,
            }
        if inconclusive_cnt > 0:
            return CLIExitCode.INCONCLUSIVE_OR_ERROR, {
                "reason": f"{inconclusive_cnt} candidate checks were INCONCLUSIVE",
                "run_id": wf.run_id,
            }
        return CLIExitCode.PASS, {"status": "PASS", "run_id": wf.run_id}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="psa", description="Verified Security Patch Agent CLI")
    sub = parser.add_subparsers(dest="command", required=True)

    p_run = sub.add_parser("run", help="Run full detection, verification, patching, and evidence bundle pipeline")
    p_run.add_argument("--target", required=True, type=Path, help="Path to owned Node/Express app")
    p_run.add_argument("--runs-dir", default=Path("runs"), type=Path, help="Output directory for run artifacts")
    p_run.add_argument("--run-id", default=None, help="Explicit run identifier")
    p_run.add_argument("--no-cache", action="store_true", help="Disable LLM response cache")
    p_run.add_argument("--max-candidates", type=int, default=None, help="Optional cap on candidates evaluated")

    p_gate = sub.add_parser("gate", help="Run pre-merge security gate (exit 0 pass, 1 vulnerable, 2 error/inconclusive)")
    p_gate.add_argument("--target", required=True, type=Path, help="Path to Node/Express app to gate")
    p_gate.add_argument("--reproducers", default=None, type=Path, help="Directory of security & companion tests")
    p_gate.add_argument("--runs-dir", default=Path("runs/gate"), type=Path, help="Directory for live gate artifacts")

    p_replay = sub.add_parser("replay", help="Deterministically replay recorded run events without live execution")
    p_replay.add_argument("--run-dir", required=True, type=Path, help="Path to runs/<run_id> folder")

    p_approve = sub.add_parser("approve", help="Record human approval bound to exact patch SHA-256")
    p_approve.add_argument("--bundle", required=True, type=Path, help="Path to finding evidence bundle directory")
    p_approve.add_argument("--reviewer", required=True, help="Human reviewer identifier")
    p_approve.add_argument("--sha256", required=True, help="Exact SHA-256 of patch.diff being approved")
    p_approve.add_argument("--branch", required=True, help="Designated non-main git branch for apply")
    p_approve.add_argument("--notes", default="", help="Optional review notes")

    p_apply = sub.add_parser("apply", help="Apply an approved finding patch onto its designated git branch")
    p_apply.add_argument("--repo", required=True, type=Path, help="Git repository root")
    p_apply.add_argument("--bundle", required=True, type=Path, help="Approved evidence bundle directory")
    p_apply.add_argument("--branch", default=None, help="Designated git branch (must match approval)")
    p_apply.add_argument("--subdir", default="", help="Subdirectory of Express app within git repo if nested")

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        if args.command == "run":
            artifacts = run_security_workflow(
                target_dir=args.target,
                runs_root=args.runs_dir,
                run_id=args.run_id,
                use_cache=not args.no_cache,
                max_candidates=args.max_candidates,
            )
            summary = json.loads((artifacts.run_dir / "run_summary.json").read_text(encoding="utf-8"))
            print(json.dumps(summary, indent=2))
            return int(CLIExitCode.PASS)

        if args.command == "gate":
            code, payload = run_cli_gate(
                target_dir=args.target,
                reproducers_dir=args.reproducers,
                runs_root=args.runs_dir,
            )
            print(json.dumps({"exit_code": int(code), **payload}, indent=2))
            return int(code)

        if args.command == "replay":
            report = replay_run(args.run_dir)
            print(report.format_text())
            return int(CLIExitCode.PASS)

        if args.command == "approve":
            rec = approve_finding_patch(
                bundle_dir=args.bundle,
                reviewer=args.reviewer,
                expected_patch_sha256=args.sha256,
                target_branch=args.branch,
                notes=args.notes,
            )
            print(rec.model_dump_json(indent=2))
            return int(CLIExitCode.PASS)

        if args.command == "apply":
            applied = apply_approved_patch_to_branch(
                repo_dir=args.repo,
                bundle_dir=args.bundle,
                target_branch=args.branch,
                subdir_in_repo=args.subdir,
            )
            print(json.dumps(applied, indent=2))
            return int(CLIExitCode.PASS)

    except ApprovalError as exc:
        print(json.dumps({"error": str(exc)}), file=sys.stderr)
        return int(CLIExitCode.VULNERABLE_OR_UNVERIFIED)
    except Exception as exc:
        print(json.dumps({"error": str(exc)}), file=sys.stderr)
        return int(CLIExitCode.INCONCLUSIVE_OR_ERROR)

    return int(CLIExitCode.INCONCLUSIVE_OR_ERROR)


if __name__ == "__main__":
    sys.exit(main())
