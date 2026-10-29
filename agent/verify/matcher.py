"""Deterministic Jest JSON failure-reason matcher (Slice S3, Section 6.2)."""

from __future__ import annotations

import json
import re
from typing import Any

from contracts import MatchReason, MatchResult

SETUP_ERROR_SIGNATURES: tuple[str, ...] = (
    "ECONNREFUSED",
    "MODULE_NOT_FOUND",
    "Cannot find module",
    "ReferenceError",
    "SyntaxError",
    "EADDRINUSE",
)

JEST_TIMEOUT_SIGNATURES: tuple[str, ...] = (
    "Exceeded timeout of",
    "Timeout - Async callback was not invoked within the",
)

TAG_REGEX = re.compile(r"SECURITY_INVARIANT_VIOLATED:([A-Za-z0-9_-]+):")


def extract_jest_json(raw_output: str) -> dict[str, Any] | None:
    """Extract the Jest --json report object from stdout without regexing console prose."""
    stripped = raw_output.strip()
    if not stripped:
        return None
    try:
        parsed = json.loads(stripped)
        if isinstance(parsed, dict) and "testResults" in parsed:
            return parsed
    except json.JSONDecodeError:
        parsed = None

    # If Node emitted lines prior to Jest's final JSON object, scan from '{' positions
    idx = stripped.find('{"numFailedTestSuites"')
    if idx == -1:
        idx = stripped.find("{")
    while idx != -1:
        candidate = stripped[idx:]
        try:
            parsed = json.loads(candidate)
            if isinstance(parsed, dict) and "testResults" in parsed:
                return parsed
        except json.JSONDecodeError:
            parsed = None
        idx = stripped.find("{", idx + 1)
    return None


def _has_setup_error(text: str) -> str | None:
    for sig in SETUP_ERROR_SIGNATURES:
        if sig in text:
            return sig
    if "TypeError:" in text and "SECURITY_INVARIANT_VIOLATED:" not in text:
        return "TypeError"
    return None


def _has_jest_timeout(text: str) -> str | None:
    for sig in JEST_TIMEOUT_SIGNATURES:
        if sig in text:
            return sig
    return None


def match_jest_output(
    raw_stdout: str,
    invariant_id: str,
    timed_out: bool = False,
) -> MatchResult:
    """Evaluate Jest --json output against Section 6.2 verification criteria."""
    if timed_out:
        return MatchResult(
            matched=False,
            reason=MatchReason.TIMEOUT,
            detail="Sandbox process timed out",
        )

    report = extract_jest_json(raw_stdout)
    if report is None:
        return MatchResult(
            matched=False,
            reason=MatchReason.SETUP_ERROR,
            detail="Output did not contain a valid Jest JSON report",
        )

    test_results = report.get("testResults") or []
    if not isinstance(test_results, list) or len(test_results) == 0:
        return MatchResult(
            matched=False,
            reason=MatchReason.SETUP_ERROR,
            detail="Jest JSON report contained zero testResults",
        )

    all_failure_messages: list[str] = []
    suite_level_messages: list[str] = []

    for suite in test_results:
        suite_msg = suite.get("message") or ""
        if suite_msg:
            suite_level_messages.append(suite_msg)
        assertions = suite.get("assertionResults") or []
        if suite.get("status") == "failed" and len(assertions) == 0:
            # Suite crashed before executing any test() block (e.g., missing module or syntax error)
            combined = suite_msg
            timeout_sig = _has_jest_timeout(combined)
            if timeout_sig:
                return MatchResult(matched=False, reason=MatchReason.TIMEOUT, detail=timeout_sig)
            return MatchResult(
                matched=False,
                reason=MatchReason.SETUP_ERROR,
                detail=f"Test suite failed prior to assertions: {combined[:240]}",
            )
        for assertion in assertions:
            for msg in assertion.get("failureMessages") or []:
                all_failure_messages.append(msg)

    combined_failures = "\n".join([*suite_level_messages, *all_failure_messages])

    # Check timeout signatures inside Jest failureMessages first
    timeout_hit = _has_jest_timeout(combined_failures)
    if timeout_hit:
        return MatchResult(
            matched=False,
            reason=MatchReason.TIMEOUT,
            detail=f"Jest test timeout: {timeout_hit}",
        )

    # Check setup error signatures across suite & assertion failureMessages
    setup_hit = _has_setup_error(combined_failures)
    if setup_hit:
        return MatchResult(
            matched=False,
            reason=MatchReason.SETUP_ERROR,
            detail=f"Setup/runtime error signature detected: {setup_hit}",
        )

    num_total = int(report.get("numTotalTests") or 0)
    num_failed = int(report.get("numFailedTests") or 0)
    if num_total == 0:
        return MatchResult(
            matched=False,
            reason=MatchReason.SETUP_ERROR,
            detail="Zero tests executed",
        )

    if num_failed == 0 and bool(report.get("success", False)):
        return MatchResult(
            matched=False,
            reason=MatchReason.PASSED,
            detail="All tests passed on baseline (vulnerability not reproduced)",
        )

    # Inspect failureMessages from assertions only for SECURITY_INVARIANT_VIOLATED:<id>:
    assertion_blob = "\n".join(all_failure_messages)
    found_tags = TAG_REGEX.findall(assertion_blob)
    if invariant_id in found_tags:
        return MatchResult(
            matched=True,
            reason=MatchReason.TAG_MATCHED,
            detail=f"Matched SECURITY_INVARIANT_VIOLATED:{invariant_id}",
        )
    if found_tags:
        return MatchResult(
            matched=False,
            reason=MatchReason.WRONG_TAG,
            detail=f"Expected tag {invariant_id}, observed tags {sorted(set(found_tags))}",
        )
    return MatchResult(
        matched=False,
        reason=MatchReason.NO_TAG,
        detail="Test failed without SECURITY_INVARIANT_VIOLATED tag",
    )
