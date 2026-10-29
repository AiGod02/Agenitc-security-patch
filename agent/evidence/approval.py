"""Human patch-hash approval and designated-branch git worktree apply (Slice S11, Section 9)."""

from __future__ import annotations

import hashlib
import json
import subprocess
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from agent.tools.dispatcher import resolve_workspace_path
from agent.tools.patch_applier import apply_unified_diff_to_workspace
from contracts import ApprovalRecord, FinalPatchStatus

PROTECTED_BRANCHES = {"main", "master", "HEAD"}


class ApprovalError(ValueError):
    """Raised when patch hash mismatches, patch did not PASS, or branch policy is violated."""


def compute_patch_file_sha256(bundle_dir: Path) -> str:
    patch_file = bundle_dir / "patch.diff"
    if not patch_file.exists():
        raise ApprovalError(f"Missing patch.diff in bundle: {bundle_dir}")
    diff_text = patch_file.read_text(encoding="utf-8")
    return hashlib.sha256(diff_text.encode("utf-8")).hexdigest()


def approve_finding_patch(
    bundle_dir: Path,
    reviewer: str,
    expected_patch_sha256: str,
    target_branch: str,
    notes: str = "",
) -> ApprovalRecord:
    """Bind human approval to the exact SHA-256 of patch.diff after verifying PASS status."""
    if target_branch in PROTECTED_BRANCHES:
        raise ApprovalError(f"Cannot approve direct apply onto protected branch '{target_branch}'")

    finding_file = bundle_dir / "finding.json"
    if not finding_file.exists():
        raise ApprovalError(f"Missing finding.json in {bundle_dir}")
    finding_data = json.loads(finding_file.read_text(encoding="utf-8"))
    patch_res = finding_data.get("patch_result") or {}
    if patch_res.get("final_status") != FinalPatchStatus.PASS:
        raise ApprovalError(
            f"Cannot approve non-PASS patch (status={patch_res.get('final_status')})"
        )

    actual_sha = compute_patch_file_sha256(bundle_dir)
    if actual_sha != expected_patch_sha256.strip().lower():
        raise ApprovalError(
            f"Approval SHA-256 mismatch: expected {expected_patch_sha256}, actual patch.diff is {actual_sha}"
        )

    record = ApprovalRecord(
        finding_id=str(finding_data["candidate"]["id"]),
        reviewer=reviewer.strip(),
        approved_at=datetime.now(timezone.utc).isoformat(),
        patch_sha256=actual_sha,
        target_branch=target_branch.strip(),
        notes=notes,
    )
    (bundle_dir / "approval.json").write_text(record.model_dump_json(indent=2), encoding="utf-8")
    return record


def apply_approved_patch_to_branch(
    repo_dir: Path,
    bundle_dir: Path,
    target_branch: str | None = None,
    subdir_in_repo: str = "",
) -> dict[str, str | list[str]]:
    """Apply an approved patch onto a designated branch via temporary git worktree (no merge, no push)."""
    approval_file = bundle_dir / "approval.json"
    if not approval_file.exists():
        raise ApprovalError("Missing approval.json; human approval is required before apply")

    approval = ApprovalRecord.model_validate_json(approval_file.read_text(encoding="utf-8"))
    branch = (target_branch or approval.target_branch).strip()
    if branch in PROTECTED_BRANCHES:
        raise ApprovalError(f"Refusing to apply patch to protected branch '{branch}'")
    if branch != approval.target_branch:
        raise ApprovalError(
            f"Target branch '{branch}' does not match approved branch '{approval.target_branch}'"
        )

    # Re-verify exact patch SHA-256 right before applying — any 1-byte edit invalidates approval
    current_sha = compute_patch_file_sha256(bundle_dir)
    if current_sha != approval.patch_sha256:
        raise ApprovalError(
            f"Patch hash changed since approval ({approval.patch_sha256} -> {current_sha}); approval invalidated"
        )

    diff_text = (bundle_dir / "patch.diff").read_text(encoding="utf-8")

    with tempfile.TemporaryDirectory(prefix="psa-apply-wt-") as wt_parent:
        wt_dir = Path(wt_parent) / "worktree"
        add_proc = subprocess.run(
            ["git", "worktree", "add", "-B", branch, str(wt_dir), "HEAD"],
            cwd=repo_dir,
            capture_output=True,
            text=True,
            encoding="utf-8",
            timeout=30,
        )
        if add_proc.returncode != 0:
            raise RuntimeError(f"git worktree add failed: {add_proc.stderr}")

        try:
            app_root = (wt_dir / subdir_in_repo).resolve() if subdir_in_repo else wt_dir.resolve()
            touched = apply_unified_diff_to_workspace(
                app_root,
                diff_text,
                lambda rel: resolve_workspace_path(app_root, rel),
            )
            stage_paths = [
                f"{subdir_in_repo.strip('/')}/{p}" if subdir_in_repo else p
                for p in touched
            ]
            subprocess.run(["git", "add", "--", *stage_paths], cwd=wt_dir, check=True, capture_output=True, text=True)
            commit_msg = (
                f"security({approval.finding_id}): apply verified patch {approval.patch_sha256[:12]}\n\n"
                f"Approved-by: {approval.reviewer}\n"
                f"Patch-SHA256: {approval.patch_sha256}"
            )
            subprocess.run(["git", "commit", "-m", commit_msg], cwd=wt_dir, check=True, capture_output=True, text=True)
            rev = subprocess.run(
                ["git", "rev-parse", "HEAD"],
                cwd=wt_dir,
                check=True,
                capture_output=True,
                text=True,
            ).stdout.strip()
        finally:
            subprocess.run(
                ["git", "worktree", "remove", "--force", str(wt_dir)],
                cwd=repo_dir,
                capture_output=True,
                text=True,
            )

    return {
        "finding_id": approval.finding_id,
        "branch": branch,
        "commit": rev,
        "patch_sha256": approval.patch_sha256,
        "patched_files": touched,
    }
