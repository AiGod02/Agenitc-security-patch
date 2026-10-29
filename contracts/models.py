"""Frozen Pydantic data contracts and runtime protocols for the Verified Security Patch Agent."""

from __future__ import annotations

from enum import IntEnum, StrEnum
from pathlib import Path
from typing import Any, Literal, Protocol, runtime_checkable

from pydantic import BaseModel, ConfigDict, Field, model_validator


class VulnerabilityClass(StrEnum):
    IDOR = "IDOR"
    PATH_TRAVERSAL = "PATH_TRAVERSAL"
    INJECTION = "INJECTION"
    MISSING_AUTH = "MISSING_AUTH"
    HARDCODED_SECRET = "HARDCODED_SECRET"
    PERMISSIVE_CORS = "PERMISSIVE_CORS"


class RouteEntry(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    method: str = Field(min_length=1)
    path: str = Field(min_length=1)
    file: str = Field(min_length=1)
    line: int = Field(ge=1)


class RichRouteEntry(RouteEntry):
    model_config = ConfigDict(extra="forbid", frozen=True)

    middleware_chain: list[str] = Field(default_factory=list)
    has_auth_check: bool = False
    sinks_reached: list[dict[str, Any]] = Field(default_factory=list)
    identity_fields: list[str] = Field(default_factory=list)
    ownership_comparisons: list[str] = Field(default_factory=list)


class RunState(StrEnum):
    CREATED = "CREATED"
    RECON = "RECON"
    CANDIDATES = "CANDIDATES"
    VERIFYING = "VERIFYING"
    PATCHING = "PATCHING"
    CHECKING = "CHECKING"
    AWAITING_APPROVAL = "AWAITING_APPROVAL"
    APPROVED = "APPROVED"
    APPLIED = "APPLIED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"


class CandidateState(StrEnum):
    PROPOSED = "PROPOSED"
    INVALID = "INVALID"
    TEST_WRITTEN = "TEST_WRITTEN"
    VERIFIED_REPRODUCER = "VERIFIED_REPRODUCER"
    NOT_REPRODUCED = "NOT_REPRODUCED"
    INCONCLUSIVE = "INCONCLUSIVE"
    PLANNED = "PLANNED"
    PATCH_PROPOSED = "PATCH_PROPOSED"
    GUARD_REJECTED = "GUARD_REJECTED"
    PATCH_FAILED = "PATCH_FAILED"
    CHECKS_PASSED = "CHECKS_PASSED"
    REGRESSION = "REGRESSION"
    AWAITING_APPROVAL = "AWAITING_APPROVAL"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"
    APPLIED = "APPLIED"


class ArtifactEnvelope(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    run_id: str = Field(min_length=1)
    stage: str = Field(min_length=1)
    candidate_id: str | None = None
    input_hash: str = Field(min_length=1)
    created_at: str = Field(min_length=1)
    status: str = Field(min_length=1)
    payload_sha256: str = Field(min_length=64, max_length=64)
    payload: dict[str, Any]


class FileLineCitation(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    file: str = Field(min_length=1)
    line: int = Field(ge=1)
    snippet: str = Field(min_length=1)


class PatchOption(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    option_id: str = Field(min_length=1)
    summary: str = Field(min_length=1)
    layer: Literal["handler", "shared_middleware", "data_access"]
    pros_and_cons: str = Field(min_length=1)


class PatchPlan(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    candidate_id: str = Field(min_length=1)
    violated_invariant: str = Field(min_length=1)
    root_cause: str = Field(min_length=1)
    root_cause_evidence: list[FileLineCitation] = Field(min_length=1)
    context_read: list[str] = Field(min_length=1)
    candidate_fixes: list[PatchOption] = Field(min_length=2)
    chosen_option_id: str = Field(min_length=1)
    chosen_rationale: str = Field(min_length=1)
    fix_layer: Literal["handler", "shared_middleware", "data_access"]
    fix_layer_justification: str = Field(min_length=1)
    helper_reuse_note: str = Field(min_length=1)
    behavioral_risks: str = Field(min_length=1)
    protecting_companion_test: str = Field(min_length=1)
    expected_scope_files: list[str] = Field(min_length=1)
    expected_approx_lines: int = Field(ge=1)


class VariantTestResult(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    candidate_id: str = Field(min_length=1)
    invariant_id: str = Field(min_length=1)
    variant_test_path: str = Field(min_length=1)
    baseline_exit_code: int
    baseline_matched_tag: bool
    baseline_match_reason: MatchReason
    post_patch_exit_code: int | None = None
    post_patch_passed: bool | None = None


class PossibleVariant(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    label: Literal["possible variant"] = "possible variant"
    route: str = Field(min_length=1)
    file: str = Field(min_length=1)
    line: int = Field(ge=1)
    pattern_reason: str = Field(min_length=1)


class Candidate(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    id: str = Field(min_length=1)
    vulnerability_class: VulnerabilityClass
    file: str = Field(min_length=1)
    start_line: int = Field(ge=1)
    end_line: int = Field(ge=1)
    route: str = Field(min_length=1)
    reason: str = Field(min_length=1)
    evidence: str = Field(min_length=1)
    confidence: float = Field(ge=0.0, le=1.0)
    expected_security_failure: str = Field(min_length=1)
    invariant_id: str = Field(min_length=1, pattern=r"^[A-Za-z0-9_-]+$")

    @model_validator(mode="after")
    def validate_line_range(self) -> Candidate:
        if self.end_line < self.start_line:
            raise ValueError(f"end_line ({self.end_line}) must be >= start_line ({self.start_line})")
        return self


class MatchReason(StrEnum):
    TAG_MATCHED = "TAG_MATCHED"
    PASSED = "PASSED"
    NO_TAG = "NO_TAG"
    WRONG_TAG = "WRONG_TAG"
    SETUP_ERROR = "SETUP_ERROR"
    TIMEOUT = "TIMEOUT"


class MatchResult(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    matched: bool
    reason: MatchReason
    detail: str = ""

    @model_validator(mode="after")
    def validate_consistency(self) -> MatchResult:
        if self.matched and self.reason != MatchReason.TAG_MATCHED:
            raise ValueError("matched=True requires reason=TAG_MATCHED")
        if not self.matched and self.reason == MatchReason.TAG_MATCHED:
            raise ValueError("reason=TAG_MATCHED requires matched=True")
        return self


class VerificationStatus(StrEnum):
    VERIFIED_REPRODUCER = "VERIFIED_REPRODUCER"
    NOT_REPRODUCED = "NOT_REPRODUCED"
    INCONCLUSIVE = "INCONCLUSIVE"


class FinalPatchStatus(StrEnum):
    PASS = "PASS"
    FAIL = "FAIL"
    INCONCLUSIVE = "INCONCLUSIVE"


class VerificationResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    candidate_id: str = Field(min_length=1)
    test_path: str = Field(min_length=1)
    companion_test_path: str | None = None
    baseline_exit_code: int
    rerun_exit_code: int | None = None
    timed_out: bool
    tagged_assertion_matched: bool
    match_reason: MatchReason
    companion_baseline_exit_code: int | None = None
    status: VerificationStatus

    # Post-patch fields (populated during remediation / S9)
    patched_security_exit_code: int | None = None
    companion_after_exit_code: int | None = None
    full_suite_exit_code: int | None = None
    guards_passed: bool | None = None
    final_status: FinalPatchStatus | None = None


class VerifiedFinding(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    candidate: Candidate
    verification: VerificationResult
    security_test_path: str = Field(min_length=1)
    companion_test_path: str = Field(min_length=1)
    baseline_failure_summary: str = Field(min_length=1)

    @model_validator(mode="after")
    def require_verified_reproducer(self) -> VerifiedFinding:
        if self.verification.status != VerificationStatus.VERIFIED_REPRODUCER:
            raise ValueError(
                f"VerifiedFinding requires status=VERIFIED_REPRODUCER, got {self.verification.status}"
            )
        if not self.verification.tagged_assertion_matched:
            raise ValueError("VerifiedFinding requires tagged_assertion_matched=True")
        if self.verification.companion_baseline_exit_code != 0:
            raise ValueError("VerifiedFinding requires companion_baseline_exit_code == 0")
        return self


class GuardCheckResult(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    passed: bool
    test_count_before: int = Field(ge=0)
    test_count_after: int = Field(ge=0)
    skipped_tests_after: int = Field(ge=0)
    test_files_untouched: bool
    routes_identical: bool
    exports_intact: bool
    forbidden_files_untouched: bool
    changed_lines: int = Field(ge=0)
    line_cap: int = Field(default=40, ge=1)
    flagged_for_human_review: bool = False
    reasons: list[str] = Field(default_factory=list)


class PatchResult(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    candidate_id: str = Field(min_length=1)
    unified_diff: str
    patch_sha256: str = Field(min_length=64, max_length=64)
    attempts: int = Field(ge=1)
    patched_security_exit_code: int | None = None
    companion_after_exit_code: int | None = None
    full_suite_exit_code: int | None = None
    guards: GuardCheckResult | None = None
    guards_passed: bool
    final_status: FinalPatchStatus
    failure_reason: str | None = None


class RunResult(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    exit_code: int
    stdout: str
    stderr: str
    timed_out: bool
    duration_ms: int = Field(ge=0)


class ModelRole(StrEnum):
    FAST = "fast"
    REASONING = "reasoning"


class LLMCaps(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    max_output_tokens: int | None = Field(default=None, ge=1)
    timeout_s: float = Field(default=90.0, gt=0.0)
    max_retries: int = Field(default=2, ge=0)
    reasoning_effort: Literal["low", "medium", "high", "max"] | None = None


class LLMResult(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, protected_namespaces=())

    parsed: dict[str, Any] | None = None
    text: str
    usage: dict[str, Any] | None = None
    latency_ms: int = Field(ge=0)
    cache_hit: bool
    model_id: str = Field(min_length=1)
    request_hash: str = Field(min_length=64, max_length=64)


class ToolName(StrEnum):
    LIST_FILES = "list_files"
    READ_FILE = "read_file"
    GREP = "grep"
    WRITE_FILE = "write_file"
    APPLY_PATCH = "apply_patch"
    RUN_TESTS = "run_tests"
    RUN_COMMAND = "run_command"
    HTTP_LOCAL = "http_local"


class ToolResult(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    ok: bool
    tool_name: str = Field(min_length=1)
    output: Any = None
    exit_code: int | None = None
    duration_ms: int = Field(default=0, ge=0)
    truncated: bool = False
    rejection_reason: str | None = None


class Event(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    seq: int = Field(ge=1)
    run_id: str = Field(min_length=1)
    timestamp: str = Field(min_length=1)
    stage: str = Field(min_length=1)
    event_type: Literal[
        "model_call",
        "tool_call",
        "stage_transition",
        "state_transition",
        "artifact_event",
        "approval",
    ]
    input_hash: str = Field(min_length=1)
    args: dict[str, Any] = Field(default_factory=dict)
    result_ref: str | None = None
    exit_code: int | None = None
    duration_ms: int = Field(ge=0)
    error: str | None = None


class ApprovalRecord(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    finding_id: str = Field(min_length=1)
    reviewer: str = Field(min_length=1)
    approved_at: str = Field(min_length=1)
    patch_sha256: str = Field(min_length=64, max_length=64)
    target_branch: str = Field(min_length=1)
    notes: str = ""


class CLIExitCode(IntEnum):
    PASS = 0
    VULNERABLE_OR_UNVERIFIED = 1
    INCONCLUSIVE_OR_ERROR = 2


@runtime_checkable
class SandboxRunner(Protocol):
    def run(self, workspace: Path, command: list[str], timeout_s: float = 30.0) -> RunResult:
        """Execute an allowlisted command list inside the isolated sandbox."""


@runtime_checkable
class LLMClient(Protocol):
    def call(
        self,
        role: ModelRole,
        system: str,
        user: str,
        schema: dict[str, Any] | None = None,
        caps: LLMCaps | None = None,
    ) -> LLMResult:
        """Execute a live or cached Meta Model API call with optional strict JSON schema."""


@runtime_checkable
class DispatcherProtocol(Protocol):
    def call(self, run_id: str, tool_name: str, args: dict[str, Any]) -> ToolResult:
        """Validate and dispatch a restricted tool call within the workspace."""
