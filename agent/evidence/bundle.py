"""Evidence bundle writer per verified finding (Slice S10, Section 9)."""

from __future__ import annotations

import json
from pathlib import Path

from contracts import PatchResult, VerifiedFinding


def write_evidence_bundle(
    run_dir: Path,
    verified_finding: VerifiedFinding,
    security_test_code: str,
    companion_test_code: str,
    baseline_stdout: str,
    patch_result: PatchResult | None,
) -> Path:
    """Write a complete, self-contained reviewer evidence bundle folder for a verified finding."""
    cand = verified_finding.candidate
    bundle_dir = run_dir / "bundles" / cand.id
    bundle_dir.mkdir(parents=True, exist_ok=True)

    (bundle_dir / "security.test.js").write_text(security_test_code, encoding="utf-8")
    (bundle_dir / "companion.test.js").write_text(companion_test_code, encoding="utf-8")
    (bundle_dir / "baseline_failure_jest.json").write_text(baseline_stdout, encoding="utf-8")

    ver_updated = verified_finding.verification.model_copy()
    if patch_result is not None:
        ver_updated.patched_security_exit_code = patch_result.patched_security_exit_code
        ver_updated.companion_after_exit_code = patch_result.companion_after_exit_code
        ver_updated.full_suite_exit_code = patch_result.full_suite_exit_code
        ver_updated.guards_passed = patch_result.guards_passed
        ver_updated.final_status = patch_result.final_status

    finding_payload = {
        "candidate": cand.model_dump(),
        "verification": ver_updated.model_dump(),
        "baseline_failure_summary": verified_finding.baseline_failure_summary,
        "patch_result": patch_result.model_dump() if patch_result else None,
    }
    (bundle_dir / "finding.json").write_text(json.dumps(finding_payload, indent=2), encoding="utf-8")

    if patch_result is not None:
        (bundle_dir / "patch.diff").write_text(patch_result.unified_diff, encoding="utf-8")
        (bundle_dir / "patch.sha256").write_text(patch_result.patch_sha256 + "\n", encoding="utf-8")
        if patch_result.guards is not None:
            (bundle_dir / "guards.json").write_text(
                patch_result.guards.model_dump_json(indent=2),
                encoding="utf-8",
            )

    summary_lines = [
        f"# Evidence Bundle: {cand.id} ({cand.vulnerability_class})",
        "",
        f"- **Route**: `{cand.route}`",
        f"- **Location**: `{cand.file}:{cand.start_line}-{cand.end_line}`",
        f"- **Invariant ID**: `{cand.invariant_id}`",
        f"- **Expected Security Failure**: {cand.expected_security_failure}",
        f"- **Baseline Match**: `{verified_finding.baseline_failure_summary}` (exit `{ver_updated.baseline_exit_code}`, rerun `{ver_updated.rerun_exit_code}`)",
        f"- **Companion Baseline Exit**: `{ver_updated.companion_baseline_exit_code}`",
    ]
    if patch_result is not None:
        summary_lines.extend(
            [
                "",
                "## Remediation & Guard Results",
                f"- **Final Patch Status**: `{patch_result.final_status}`",
                f"- **Patch SHA-256**: `{patch_result.patch_sha256}`",
                f"- **Repair Attempts**: `{patch_result.attempts}`",
                f"- **Patched Security Test Exit**: `{patch_result.patched_security_exit_code}`",
                f"- **Patched Companion Test Exit**: `{patch_result.companion_after_exit_code}`",
                f"- **Full Suite Exit**: `{patch_result.full_suite_exit_code}`",
                f"- **Anti-Vandalism Guards Passed**: `{patch_result.guards_passed}`",
                f"- **Failure Reason**: `{patch_result.failure_reason or 'None'}`",
                "",
                "## Unified Diff",
                "```diff",
                patch_result.unified_diff.rstrip(),
                "```",
            ]
        )
    (bundle_dir / "summary.md").write_text("\n".join(summary_lines) + "\n", encoding="utf-8")
    return bundle_dir
