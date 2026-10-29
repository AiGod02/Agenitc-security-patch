from agent.patch.guards import (
    WorkspaceBaselineSnapshot,
    capture_pre_patch_snapshot,
    evaluate_patch_guards,
    normalize_failure_signature,
)
from agent.patch.loop import remediate_verified_finding, validate_candidate_diff_on_workspace

__all__ = [
    "WorkspaceBaselineSnapshot",
    "capture_pre_patch_snapshot",
    "evaluate_patch_guards",
    "normalize_failure_signature",
    "remediate_verified_finding",
    "validate_candidate_diff_on_workspace",
]
