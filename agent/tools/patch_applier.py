"""Safe, atomic unified diff parser and applier with path containment checks."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

HUNK_HEADER_RE = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")


class PatchApplyError(ValueError):
    """Raised when a unified diff is malformed, unsafe, or does not match file contents."""


@dataclass
class DiffHunk:
    old_start: int
    old_count: int
    new_start: int
    new_count: int
    lines: list[str]


@dataclass
class FileDiff:
    old_path: str
    new_path: str
    hunks: list[DiffHunk]


def _clean_diff_path(raw: str) -> str:
    token = raw.split("\t")[0].strip()
    if token.startswith("a/") or token.startswith("b/"):
        token = token[2:]
    return token.replace("\\", "/")


def parse_unified_diff(diff_text: str) -> list[FileDiff]:
    raw_lines = diff_text.splitlines()
    file_diffs: list[FileDiff] = []
    idx = 0
    n = len(raw_lines)

    while idx < n:
        line = raw_lines[idx]
        if line.startswith("--- "):
            if idx + 1 >= n or not raw_lines[idx + 1].startswith("+++ "):
                raise PatchApplyError("Malformed unified diff: '---' not followed by '+++'")
            old_path = _clean_diff_path(line[4:])
            new_path = _clean_diff_path(raw_lines[idx + 1][4:])
            idx += 2
            hunks: list[DiffHunk] = []
            while idx < n and not raw_lines[idx].startswith("--- ") and not raw_lines[idx].startswith("diff --git "):
                hline = raw_lines[idx]
                if not hline.strip():
                    idx += 1
                    continue
                m = HUNK_HEADER_RE.match(hline)
                if not m:
                    raise PatchApplyError(f"Unexpected line outside hunk: {hline[:120]}")
                old_start = int(m.group(1))
                old_count = int(m.group(2)) if m.group(2) is not None else 1
                new_start = int(m.group(3))
                new_count = int(m.group(4)) if m.group(4) is not None else 1
                idx += 1
                hunk_lines: list[str] = []
                while idx < n:
                    cur = raw_lines[idx]
                    if cur.startswith(("@@ ", "--- ", "diff --git ")):
                        break
                    if cur.startswith("\\ No newline at end of file"):
                        idx += 1
                        continue
                    if cur == "":
                        # Treat empty line inside hunk as blank context line
                        hunk_lines.append(" ")
                    elif cur[0] in (" ", "+", "-"):
                        hunk_lines.append(cur)
                    else:
                        break
                    idx += 1
                hunks.append(
                    DiffHunk(
                        old_start=old_start,
                        old_count=old_count,
                        new_start=new_start,
                        new_count=new_count,
                        lines=hunk_lines,
                    )
                )
            if not hunks:
                raise PatchApplyError(f"File diff for {new_path} contains zero hunks")
            file_diffs.append(FileDiff(old_path=old_path, new_path=new_path, hunks=hunks))
        else:
            idx += 1

    if not file_diffs:
        raise PatchApplyError("Unified diff contained no file headers ('--- '/'+++ ')")
    return file_diffs


def count_changed_lines(diff_text: str) -> int:
    """Count total added + removed lines across all hunks in a unified diff."""
    file_diffs = parse_unified_diff(diff_text)
    changed = 0
    for fd in file_diffs:
        for hunk in fd.hunks:
            for hline in hunk.lines:
                if hline.startswith(("+", "-")):
                    changed += 1
    return changed


def _find_subsequence(haystack: list[str], needle: list[str], preferred_idx: int) -> int:
    if not needle:
        return max(0, min(preferred_idx, len(haystack)))
    m = len(needle)
    # Check exact preferred index first
    if 0 <= preferred_idx <= len(haystack) - m and haystack[preferred_idx : preferred_idx + m] == needle:
        return preferred_idx
    # Search nearby within +/- 30 lines, requiring a unique match if offset
    matches: list[int] = []
    lo = max(0, preferred_idx - 30)
    hi = min(len(haystack) - m, preferred_idx + 30)
    for pos in range(lo, hi + 1):
        if haystack[pos : pos + m] == needle:
            matches.append(pos)
    if len(matches) == 1:
        return matches[0]
    if len(matches) > 1:
        raise PatchApplyError("Ambiguous hunk context match")
    raise PatchApplyError("Hunk context did not match target file contents")


def apply_unified_diff_to_workspace(
    workspace: Path,
    diff_text: str,
    resolve_safe_path,
) -> list[str]:
    """Validate and atomically apply a unified diff inside workspace; returns touched relative paths."""
    file_diffs = parse_unified_diff(diff_text)
    staged_writes: list[tuple[Path, str, str]] = []

    for fd in file_diffs:
        if fd.old_path == "/dev/null" or fd.new_path == "/dev/null":
            raise PatchApplyError("Creating or deleting whole files via /dev/null is not permitted in patches")
        if fd.old_path != fd.new_path:
            raise PatchApplyError("Renaming files is not permitted in patches")

        target_path = resolve_safe_path(fd.new_path)
        if not target_path.exists() or not target_path.is_file():
            raise PatchApplyError(f"Target file does not exist: {fd.new_path}")

        raw_bytes = target_path.read_bytes()
        newline = "\r\n" if b"\r\n" in raw_bytes else "\n"
        raw_text = raw_bytes.decode("utf-8")
        had_trailing_nl = raw_text.endswith(("\n", "\r\n"))
        cur_lines = raw_text.splitlines()

        offset = 0
        for hunk in fd.hunks:
            expected_old = [hl[1:] for hl in hunk.lines if hl[0] in (" ", "-")]
            replacement = [hl[1:] for hl in hunk.lines if hl[0] in (" ", "+")]
            preferred = max(0, hunk.old_start - 1 + offset)
            pos = _find_subsequence(cur_lines, expected_old, preferred)
            cur_lines = cur_lines[:pos] + replacement + cur_lines[pos + len(expected_old) :]
            offset = (pos - (hunk.old_start - 1)) + (len(replacement) - len(expected_old))

        updated_text = newline.join(cur_lines)
        if had_trailing_nl and cur_lines:
            updated_text += newline
        staged_writes.append((target_path, fd.new_path, updated_text))

    touched: list[str] = []
    for target_path, rel_path, updated_text in staged_writes:
        target_path.write_bytes(updated_text.encode("utf-8"))
        touched.append(rel_path)
    return touched
