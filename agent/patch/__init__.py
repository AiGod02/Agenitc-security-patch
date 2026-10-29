from agent.patch.guards import (
    WorkspaceBaselineSnapshot,
    capture_pre_patch_snapshot,
    check_expected_scope,
    check_test_literal_hardcoding,
    evaluate_patch_guards,
    extract_test_specific_literals,
    normalize_failure_signature,
)
from agent.patch.loop import remediate_verified_finding, validate_candidate_diff_on_workspace
from agent.patch.deep_patch import (
    ensure_heldout_variant_test,
    evaluate_deep_patch_checks,
    find_possible_variants,
)

__all__ = [
    "WorkspaceBaselineSnapshot",
    "capture_pre_patch_snapshot",
    "check_expected_scope",
    "check_test_literal_hardcoding",
    "ensure_heldout_variant_test",
    "evaluate_deep_patch_checks",
    "evaluate_patch_guards",
    "extract_test_specific_literals",
    "find_possible_variants",
    "normalize_failure_signature",
    "remediate_verified_finding",
    "validate_candidate_diff_on_workspace",
]
