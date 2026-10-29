"""Mechanical anti-vandalism guards for patch verification (Slice S9, Section 6.3)."""

from __future__ import annotations

import hashlib
import os
import re
from dataclasses import dataclass
from pathlib import Path

from agent.recon import build_route_inventory, extract_exported_symbols
from agent.tools.patch_applier import PatchApplyError, count_changed_lines, parse_unified_diff
from contracts import DispatcherProtocol, GuardCheckResult


@dataclass
class WorkspaceBaselineSnapshot:
    test_file_hashes: dict[str, str]
    protected_file_hashes: dict[str, str]
    routes_set: set[tuple[str, str, str]]
    exports_map: dict[str, list[str]]
    test_count_before: int
    passing_test_names_before: set[str]


def _sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def hash_directory_tree(root: Path, rel_prefix: str) -> dict[str, str]:
    target = root / rel_prefix
    hashes: dict[str, str] = {}
    if not target.exists():
        return hashes
    for dirpath, dirnames, filenames in os.walk(target, followlinks=False):
        dirnames.sort()
        for fname in sorted(filenames):
            fp = Path(dirpath) / fname
            if fp.is_file() and not fp.is_symlink():
                rel = fp.relative_to(root).as_posix()
                hashes[rel] = _sha256_file(fp)
    return hashes


def hash_protected_files(workspace: Path) -> dict[str, str]:
    hashes: dict[str, str] = {}
    for rel in ("package.json", "package-lock.json"):
        fp = workspace / rel
        if fp.exists() and fp.is_file():
            hashes[rel] = _sha256_file(fp)
    hashes.update(hash_directory_tree(workspace, "storage"))
    return hashes


def capture_pre_patch_snapshot(
    run_id: str,
    workspace: Path,
    dispatcher: DispatcherProtocol,
    pre_suite_report: dict | None,
) -> WorkspaceBaselineSnapshot:
    routes = build_route_inventory(run_id, dispatcher)
    routes_set = {(r.method, r.path, r.file) for r in routes}
    exports_map = extract_exported_symbols(run_id, dispatcher)
    test_hashes = hash_directory_tree(workspace, "tests")
    protected_hashes = hash_protected_files(workspace)

    test_count_before = 0
    passing_names: set[str] = set()
    if pre_suite_report:
        test_count_before = int(pre_suite_report.get("numTotalTests") or 0)
        for suite in pre_suite_report.get("testResults") or []:
            for ar in suite.get("assertionResults") or []:
                if ar.get("status") == "passed" and ar.get("fullName"):
                    passing_names.add(str(ar["fullName"]))

    return WorkspaceBaselineSnapshot(
        test_file_hashes=test_hashes,
        protected_file_hashes=protected_hashes,
        routes_set=routes_set,
        exports_map=exports_map,
        test_count_before=test_count_before,
        passing_test_names_before=passing_names,
    )


def evaluate_patch_guards(
    run_id: str,
    workspace: Path,
    dispatcher: DispatcherProtocol,
    unified_diff: str,
    snapshot: WorkspaceBaselineSnapshot,
    post_suite_report: dict | None,
    line_cap: int = 40,
) -> GuardCheckResult:
    reasons: list[str] = []

    # 1. Inspect unified diff paths & changed line count
    try:
        file_diffs = parse_unified_diff(unified_diff)
        changed_lines = count_changed_lines(unified_diff)
    except PatchApplyError as exc:
        return GuardCheckResult(
            passed=False,
            test_count_before=snapshot.test_count_before,
            test_count_after=0,
            skipped_tests_after=0,
            test_files_untouched=False,
            routes_identical=False,
            exports_intact=False,
            forbidden_files_untouched=False,
            changed_lines=0,
            line_cap=line_cap,
            flagged_for_human_review=False,
            reasons=[f"Invalid unified diff: {exc}"],
        )

    diff_touched_tests = any(
        fd.new_path.startswith("tests/") or fd.old_path.startswith("tests/") or fd.new_path.endswith(".test.js")
        for fd in file_diffs
    )

    # 2. Byte-identical hash check across all of tests/
    after_test_hashes = hash_directory_tree(workspace, "tests")
    test_files_untouched = (not diff_touched_tests) and (after_test_hashes == snapshot.test_file_hashes)
    if not test_files_untouched:
        reasons.append("Patch modified, added, or deleted files under tests/")

    # 3. Protected config, lockfile, and storage check
    after_protected_hashes = hash_protected_files(workspace)
    forbidden_files_untouched = after_protected_hashes == snapshot.protected_file_hashes
    if not forbidden_files_untouched:
        reasons.append("Patch modified protected config, lockfile, or storage files")

    # 4. Route inventory preservation check
    routes_after = {(r.method, r.path, r.file) for r in build_route_inventory(run_id, dispatcher)}
    routes_identical = routes_after == snapshot.routes_set
    if not routes_identical:
        missing_routes = sorted(snapshot.routes_set - routes_after)
        added_routes = sorted(routes_after - snapshot.routes_set)
        reasons.append(f"Route inventory changed: removed={missing_routes}, added={added_routes}")

    # 5. Exported handlers preservation check
    exports_after = extract_exported_symbols(run_id, dispatcher)
    exports_intact = True
    for rel_file, prev_syms in snapshot.exports_map.items():
        cur_syms = set(exports_after.get(rel_file, []))
        removed_syms = set(prev_syms) - cur_syms
        if removed_syms:
            exports_intact = False
            reasons.append(f"Exported symbols removed from {rel_file}: {sorted(removed_syms)}")

    # 6. Full suite counts, skip/todo detection, and previously passing test regression check
    test_count_after = 0
    skipped_after = 0
    if post_suite_report is None:
        reasons.append("Full test suite did not produce a valid Jest JSON report")
    else:
        test_count_after = int(post_suite_report.get("numTotalTests") or 0)
        skipped_after = int(post_suite_report.get("numPendingTests") or 0) + int(
            post_suite_report.get("numTodoTests") or 0
        )
        if test_count_after < snapshot.test_count_before:
            reasons.append(
                f"Total test count dropped from {snapshot.test_count_before} to {test_count_after}"
            )
        if skipped_after > 0:
            reasons.append(f"Skipped/pending/todo tests detected after patch: {skipped_after}")

        after_passing: set[str] = set()
        for suite in post_suite_report.get("testResults") or []:
            for ar in suite.get("assertionResults") or []:
                status = ar.get("status")
                if status in ("pending", "skipped", "todo", "disabled"):
                    skipped_after += 1
                if status == "passed" and ar.get("fullName"):
                    after_passing.add(str(ar["fullName"]))
        regressed = sorted(snapshot.passing_test_names_before - after_passing)
        if regressed:
            reasons.append(f"Previously passing tests turned red: {regressed}")

    # 7. Changed-line cap (Section 6.3: above cap -> flagged for explicit human review, never auto-passed)
    flagged_for_size = changed_lines > line_cap
    if flagged_for_size:
        reasons.append(
            f"Changed-line count {changed_lines} exceeds cap {line_cap}; flagged for explicit human review"
        )

    passed = (
        len(reasons) == 0
        and test_files_untouched
        and forbidden_files_untouched
        and routes_identical
        and exports_intact
        and post_suite_report is not None
        and test_count_after >= snapshot.test_count_before
        and skipped_after == 0
        and not flagged_for_size
    )

    return GuardCheckResult(
        passed=passed,
        test_count_before=snapshot.test_count_before,
        test_count_after=test_count_after,
        skipped_tests_after=skipped_after,
        test_files_untouched=test_files_untouched,
        routes_identical=routes_identical,
        exports_intact=exports_intact,
        forbidden_files_untouched=forbidden_files_untouched,
        changed_lines=changed_lines,
        line_cap=line_cap,
        flagged_for_human_review=flagged_for_size,
        reasons=reasons,
    )


def normalize_failure_signature(failure_text: str) -> str:
    """Fingerprint failure reason per-run to stop repeated-error repair loops (Section 6.3 #5)."""
    cleaned = re.sub(r"\b\d+\s*ms\b", "<ms>", failure_text)
    cleaned = re.sub(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}[^\s]*", "<ts>", cleaned)
    cleaned = " ".join(cleaned.lower().split())
    return hashlib.sha256(cleaned.encode("utf-8")).hexdigest()


GENERIC_FRAMEWORK_LITERALS: frozenset[str] = frozenset(
    {
        "get",
        "post",
        "put",
        "delete",
        "patch",
        "options",
        "authorization",
        "bearer",
        "origin",
        "host",
        "cookie",
        "x-webhook-key",
        "content-type",
        "application/json",
        "admin",
        "user",
        "utf8",
        "utf-8",
        "true",
        "false",
        "error",
        "forbidden",
        "unauthorized",
        "access-control-allow-origin",
        "access-control-allow-credentials",
        "https://app.internal.example",
        "auth_token_secret",
        "webhook_api_key",
        "allowed_origin",
    }
)

QUOTED_LITERAL_RE = re.compile(r"""(['"`])((?:\\.|(?!\1)[^\\\r\n])+)\1""")


def extract_test_specific_literals(
    security_test_code: str,
    existing_source_text: str = "",
) -> set[str]:
    """Extract attack/identity/resource literals from a security test to guard against patch overfitting (Part 3b)."""
    # Strip require(...), test("title", ...), describe("title", ...), and invariant(...) lines before scanning literals
    filtered_lines: list[str] = []
    skip_invariant = False
    for raw_line in security_test_code.splitlines():
        s = raw_line.strip()
        if "require(" in s or s.startswith(("test(", "it(", "describe(")):
            continue
        if "invariant(" in s:
            skip_invariant = True
        if skip_invariant:
            if ");" in s:
                skip_invariant = False
            continue
        filtered_lines.append(raw_line)

    body = "\n".join(filtered_lines)
    candidates: set[str] = set()
    for m in QUOTED_LITERAL_RE.finditer(body):
        lit = m.group(2).strip()
        if "${" in lit:
            # Template literal like `Bearer ${token}` -> skip interpolation wrapper
            continue
        if len(lit) < 3:
            continue
        if lit.lower() in GENERIC_FRAMEWORK_LITERALS:
            continue
        if existing_source_text and lit in existing_source_text:
            continue
        candidates.add(lit)
        # Also extract trailing resource IDs or filenames from route/traversal strings (e.g. /api/invoices/inv-1001 -> inv-1001)
        if "/" in lit:
            tail = lit.rsplit("/", 1)[-1].strip()
            if len(tail) >= 4 and tail.lower() not in GENERIC_FRAMEWORK_LITERALS:
                if not existing_source_text or tail not in existing_source_text:
                    candidates.add(tail)
    return candidates


def check_test_literal_hardcoding(
    unified_diff: str,
    security_test_code: str,
    existing_source_text: str = "",
) -> list[str]:
    """Return violation reasons if added lines in unified_diff hardcode literals from security_test_code (Part 3b)."""
    forbidden_literals = extract_test_specific_literals(security_test_code, existing_source_text)
    if not forbidden_literals:
        return []
    try:
        file_diffs = parse_unified_diff(unified_diff)
    except PatchApplyError:
        return []

    added_lines: list[str] = []
    for fd in file_diffs:
        for hunk in fd.hunks:
            for hl in hunk.lines:
                if hl.startswith("+"):
                    added_lines.append(hl[1:])

    added_blob = "\n".join(added_lines)
    added_quoted = {m.group(2).strip() for m in QUOTED_LITERAL_RE.finditer(added_blob)}

    hits: list[str] = []
    for lit in sorted(forbidden_literals):
        if lit in added_quoted or f'"{lit}"' in added_blob or f"'{lit}'" in added_blob:
            hits.append(f"Patch hardcodes literal '{lit}' taken from security test")
    return hits


def check_expected_scope(unified_diff: str, expected_scope_files: list[str]) -> list[str]:
    """Check whether unified_diff touches files outside patch_plan.expected_scope_files (Part 3c)."""
    if not expected_scope_files:
        return []
    try:
        file_diffs = parse_unified_diff(unified_diff)
    except PatchApplyError:
        return []

    allowed = {p.strip().replace("\\", "/") for p in expected_scope_files}
    touched = {fd.new_path.strip().replace("\\", "/") for fd in file_diffs}
    outside = sorted(touched - allowed)
    if outside:
        return [
            f"Patch touches file(s) {outside} outside plan expected_scope {sorted(allowed)}; flagged for explicit human review"
        ]
    return []
