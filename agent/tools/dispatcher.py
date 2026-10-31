"""Restricted tool dispatcher enforcing Section 8 safety boundaries (Slice S5)."""

from __future__ import annotations

import json
import os
import re
import subprocess
import time
from pathlib import Path
from typing import Any

from agent.tools.patch_applier import PatchApplyError, apply_unified_diff_to_workspace
from contracts import SandboxRunner, ToolName, ToolResult

IGNORED_DIRS = {"node_modules", ".git", "__pycache__", ".pytest_cache"}


class PathContainmentError(ValueError):
    """Raised when a path argument attempts traversal, absolute access, or symlink escape."""


def resolve_workspace_path(workspace: Path, rel_path: str) -> Path:
    """Resolve a workspace-relative path while blocking absolute paths, '..', and symlink escapes."""
    if not isinstance(rel_path, str) or not rel_path.strip():
        raise PathContainmentError("Path must be a non-empty string")
    cleaned = rel_path.strip()
    if cleaned.startswith(("/", "\\")) or re.match(r"^[A-Za-z]:", cleaned):
        raise PathContainmentError(f"Absolute path blocked: {rel_path}")

    norm_parts = cleaned.replace("\\", "/").split("/")
    if any(part == ".." for part in norm_parts):
        raise PathContainmentError(f"Parent traversal ('..') blocked: {rel_path}")

    ws_root = workspace.resolve()
    candidate = ws_root.joinpath(*[p for p in norm_parts if p and p != "."])

    # Walk existing ancestors and final target to detect symlink escape outside ws_root
    probe = ws_root
    for part in [p for p in norm_parts if p and p != "."]:
        probe = probe / part
        if probe.exists() or probe.is_symlink():
            resolved_probe = probe.resolve()
            try:
                resolved_probe.relative_to(ws_root)
            except ValueError as exc:
                raise PathContainmentError(f"Symlink escape outside workspace blocked: {rel_path}") from exc

    resolved_final = candidate.resolve()
    try:
        resolved_final.relative_to(ws_root)
    except ValueError as exc:
        raise PathContainmentError(f"Resolved path escapes workspace: {rel_path}") from exc

    return candidate


class ToolDispatcher:
    """Validates and executes the 8 restricted tools defined in Section 8."""

    def __init__(
        self,
        workspace: Path,
        sandbox: SandboxRunner,
        max_output_bytes: int = 32_768,
        max_calls: int = 200,
        default_timeout_s: float = 30.0,
    ) -> None:
        self.workspace = workspace.resolve()
        self.sandbox = sandbox
        self.max_output_bytes = max_output_bytes
        self.max_calls = max_calls
        self.default_timeout_s = default_timeout_s
        self.call_count = 0

    def _truncate_str(self, text: str) -> tuple[str, bool]:
        encoded = text.encode("utf-8", errors="replace")
        if len(encoded) <= self.max_output_bytes:
            return text, False
        clipped = encoded[: self.max_output_bytes].decode("utf-8", errors="ignore")
        return clipped, True

    def _reject(self, tool_name: str, reason: str, start: float) -> ToolResult:
        return ToolResult(
            ok=False,
            tool_name=tool_name,
            duration_ms=int((time.perf_counter() - start) * 1000),
            rejection_reason=reason,
        )

    def call(self, run_id: str, tool_name: str, args: dict[str, Any]) -> ToolResult:
        start = time.perf_counter()
        if not run_id or not isinstance(run_id, str):
            return self._reject(str(tool_name), "run_id must be a non-empty string", start)
        if not isinstance(args, dict):
            return self._reject(str(tool_name), "args must be a JSON object", start)

        self.call_count += 1
        if self.call_count > self.max_calls:
            return self._reject(str(tool_name), f"Exceeded tool call cap ({self.max_calls})", start)

        valid_names = {t.value for t in ToolName}
        if tool_name not in valid_names:
            return self._reject(str(tool_name), f"Disallowed tool '{tool_name}'", start)

        try:
            if tool_name == ToolName.LIST_FILES:
                return self._handle_list_files(args, start)
            if tool_name == ToolName.READ_FILE:
                return self._handle_read_file(args, start)
            if tool_name == ToolName.GREP:
                return self._handle_grep(args, start)
            if tool_name == ToolName.WRITE_FILE:
                return self._handle_write_file(args, start)
            if tool_name == ToolName.APPLY_PATCH:
                return self._handle_apply_patch(args, start)
            if tool_name == ToolName.RUN_TESTS:
                return self._handle_run_tests(args, start)
            if tool_name == ToolName.RUN_COMMAND:
                return self._handle_run_command(args, start)
            if tool_name == ToolName.HTTP_LOCAL:
                return self._handle_http_local(args, start)
        except PathContainmentError as exc:
            return self._reject(tool_name, str(exc), start)
        except PatchApplyError as exc:
            return self._reject(tool_name, f"Patch rejected: {exc}", start)

        return self._reject(tool_name, "Unhandled tool", start)

    def _handle_list_files(self, args: dict[str, Any], start: float) -> ToolResult:
        allowed_keys = {"subdir"}
        if set(args.keys()) - allowed_keys:
            return self._reject("list_files", f"Unexpected args: {sorted(set(args.keys()) - allowed_keys)}", start)
        subdir = args.get("subdir", ".")
        target_dir = self.workspace if subdir in (".", "") else resolve_workspace_path(self.workspace, subdir)
        if not target_dir.exists() or not target_dir.is_dir():
            return self._reject("list_files", f"Directory not found: {subdir}", start)

        results: list[str] = []
        for root, dirs, files in os.walk(target_dir, followlinks=False):
            dirs[:] = sorted(d for d in dirs if d not in IGNORED_DIRS and not (Path(root) / d).is_symlink())
            for fname in sorted(files):
                fpath = Path(root) / fname
                if fpath.is_symlink():
                    continue
                rel = fpath.relative_to(self.workspace).as_posix()
                results.append(rel)

        joined = "\n".join(results)
        clipped, truncated = self._truncate_str(joined)
        out_list = [line for line in clipped.splitlines() if line]
        return ToolResult(
            ok=True,
            tool_name="list_files",
            output=out_list,
            exit_code=0,
            duration_ms=int((time.perf_counter() - start) * 1000),
            truncated=truncated,
        )

    def _handle_read_file(self, args: dict[str, Any], start: float) -> ToolResult:
        allowed_keys = {"path", "start_line", "end_line"}
        if "path" not in args or (set(args.keys()) - allowed_keys):
            return self._reject("read_file", "read_file requires 'path' and optional 'start_line', 'end_line'", start)
        fpath = resolve_workspace_path(self.workspace, args["path"])
        if not fpath.exists() or not fpath.is_file():
            return self._reject("read_file", f"File not found: {args['path']}", start)

        lines = fpath.read_text(encoding="utf-8", errors="replace").splitlines()
        start_line = int(args.get("start_line") or 1)
        end_line = int(args.get("end_line") or max(1, len(lines)))
        if start_line < 1 or end_line < start_line:
            return self._reject("read_file", f"Invalid line range: {start_line}..{end_line}", start)

        selected = lines[start_line - 1 : end_line]
        numbered = "\n".join(f"{start_line + idx}: {line}" for idx, line in enumerate(selected))
        clipped, truncated = self._truncate_str(numbered)
        return ToolResult(
            ok=True,
            tool_name="read_file",
            output=clipped,
            exit_code=0,
            duration_ms=int((time.perf_counter() - start) * 1000),
            truncated=truncated,
        )

    def _handle_grep(self, args: dict[str, Any], start: float) -> ToolResult:
        allowed_keys = {"pattern", "subdir"}
        if "pattern" not in args or not isinstance(args["pattern"], str) or not args["pattern"]:
            return self._reject("grep", "grep requires non-empty string 'pattern'", start)
        if set(args.keys()) - allowed_keys:
            return self._reject("grep", f"Unexpected args: {sorted(set(args.keys()) - allowed_keys)}", start)

        try:
            regex = re.compile(args["pattern"])
        except re.error as exc:
            return self._reject("grep", f"Invalid regex pattern: {exc}", start)

        subdir = args.get("subdir", ".")
        target_dir = self.workspace if subdir in (".", "") else resolve_workspace_path(self.workspace, subdir)
        if not target_dir.exists():
            return self._reject("grep", f"Path not found: {subdir}", start)

        hits: list[str] = []
        max_hits = 200
        files_to_scan: list[Path] = []
        if target_dir.is_file():
            files_to_scan.append(target_dir)
        else:
            for root, dirs, files in os.walk(target_dir, followlinks=False):
                dirs[:] = sorted(d for d in dirs if d not in IGNORED_DIRS and not (Path(root) / d).is_symlink())
                for fname in sorted(files):
                    fp = Path(root) / fname
                    if not fp.is_symlink():
                        files_to_scan.append(fp)

        truncated_hits = False
        for fp in files_to_scan:
            rel = fp.relative_to(self.workspace).as_posix()
            for lineno, line in enumerate(fp.read_text(encoding="utf-8", errors="replace").splitlines(), start=1):
                if regex.search(line):
                    hits.append(f"{rel}:{lineno}: {line}")
                    if len(hits) >= max_hits:
                        truncated_hits = True
                        break
            if truncated_hits:
                break

        joined = "\n".join(hits)
        clipped, truncated_bytes = self._truncate_str(joined)
        return ToolResult(
            ok=True,
            tool_name="grep",
            output=clipped,
            exit_code=0,
            duration_ms=int((time.perf_counter() - start) * 1000),
            truncated=truncated_hits or truncated_bytes,
        )

    def _handle_write_file(self, args: dict[str, Any], start: float) -> ToolResult:
        allowed_keys = {"path", "content"}
        if set(args.keys()) != allowed_keys or not isinstance(args.get("content"), str):
            return self._reject("write_file", "write_file requires 'path' and string 'content'", start)
        fpath = resolve_workspace_path(self.workspace, args["path"])
        fpath.parent.mkdir(parents=True, exist_ok=True)
        fpath.write_text(args["content"], encoding="utf-8")
        return ToolResult(
            ok=True,
            tool_name="write_file",
            output={"written": fpath.relative_to(self.workspace).as_posix(), "bytes": len(args["content"].encode("utf-8"))},
            exit_code=0,
            duration_ms=int((time.perf_counter() - start) * 1000),
        )

    def _handle_apply_patch(self, args: dict[str, Any], start: float) -> ToolResult:
        allowed_keys = {"diff"}
        if set(args.keys()) != allowed_keys or not isinstance(args.get("diff"), str) or not args["diff"].strip():
            return self._reject("apply_patch", "apply_patch requires non-empty 'diff' string", start)
        touched = apply_unified_diff_to_workspace(
            self.workspace,
            args["diff"],
            lambda rel: resolve_workspace_path(self.workspace, rel),
        )
        return ToolResult(
            ok=True,
            tool_name="apply_patch",
            output={"patched_files": touched},
            exit_code=0,
            duration_ms=int((time.perf_counter() - start) * 1000),
        )

    def _handle_run_tests(self, args: dict[str, Any], start: float) -> ToolResult:
        allowed_keys = {"test_paths", "timeout_s"}
        if set(args.keys()) - allowed_keys:
            return self._reject("run_tests", f"Unexpected args: {sorted(set(args.keys()) - allowed_keys)}", start)

        test_paths = args.get("test_paths") or []
        if not isinstance(test_paths, list) or not all(isinstance(p, str) for p in test_paths):
            return self._reject("run_tests", "'test_paths' must be a list of relative path strings", start)

        normalized_paths: list[str] = []
        for p in test_paths:
            resolved = resolve_workspace_path(self.workspace, p)
            if not resolved.exists():
                return self._reject("run_tests", f"Test path does not exist: {p}", start)
            normalized_paths.append(resolved.relative_to(self.workspace).as_posix())

        timeout_s = float(args.get("timeout_s") or self.default_timeout_s)
        cmd = ["jest", "--runInBand", "--json", "--runTestsByPath", *normalized_paths]
        run_res = self.sandbox.run(self.workspace, cmd, timeout_s=timeout_s)
        stdout_clipped, trunc_out = self._truncate_str(run_res.stdout)
        stderr_clipped, trunc_err = self._truncate_str(run_res.stderr)
        return ToolResult(
            ok=not run_res.timed_out,
            tool_name="run_tests",
            output={
                "stdout": stdout_clipped,
                "stderr": stderr_clipped,
                "timed_out": run_res.timed_out,
            },
            exit_code=run_res.exit_code,
            duration_ms=run_res.duration_ms,
            truncated=trunc_out or trunc_err,
            rejection_reason="Test execution timed out" if run_res.timed_out else None,
        )

    def _handle_run_command(self, args: dict[str, Any], start: float) -> ToolResult:
        allowed_keys = {"argv", "timeout_s"}
        if "argv" not in args or (set(args.keys()) - allowed_keys):
            return self._reject("run_command", "run_command requires 'argv' list and optional 'timeout_s'", start)
        argv = args["argv"]
        if not isinstance(argv, list) or not argv or not all(isinstance(x, str) and x for x in argv):
            return self._reject("run_command", "'argv' must be a non-empty list of strings", start)

        # Strict Section 8 allowlist: 'node <workspace_file>', 'npm test', 'git diff'
        if argv == ["npm", "test"]:
            run_res = self.sandbox.run(self.workspace, ["npm", "test"], timeout_s=float(args.get("timeout_s") or self.default_timeout_s))
        elif argv[0] == "node":
            if len(argv) < 2 or argv[1].startswith("-"):
                return self._reject("run_command", "Only 'node <workspace_script>' is allowlisted (eval flags blocked)", start)
            script_resolved = resolve_workspace_path(self.workspace, argv[1])
            if not script_resolved.exists():
                return self._reject("run_command", f"Script not found: {argv[1]}", start)
            rel_script = script_resolved.relative_to(self.workspace).as_posix()
            run_res = self.sandbox.run(
                self.workspace,
                ["node", rel_script, *argv[2:]],
                timeout_s=float(args.get("timeout_s") or self.default_timeout_s),
            )
        elif len(argv) >= 2 and argv[0] == "git" and argv[1] == "diff":
            for extra in argv[2:]:
                if not extra.startswith("-"):
                    resolve_workspace_path(self.workspace, extra)
            proc = subprocess.run(
                argv,
                cwd=self.workspace,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=15,
            )
            stdout_clipped, trunc = self._truncate_str(proc.stdout)
            return ToolResult(
                ok=proc.returncode == 0,
                tool_name="run_command",
                output={"stdout": stdout_clipped, "stderr": proc.stderr},
                exit_code=proc.returncode,
                duration_ms=int((time.perf_counter() - start) * 1000),
                truncated=trunc,
            )
        else:
            return self._reject(
                "run_command",
                f"Command rejected by strict allowlist (allowed: 'node <script>', 'npm test', 'git diff'): {argv}",
                start,
            )

        stdout_clipped, trunc_out = self._truncate_str(run_res.stdout)
        stderr_clipped, trunc_err = self._truncate_str(run_res.stderr)
        return ToolResult(
            ok=not run_res.timed_out,
            tool_name="run_command",
            output={"stdout": stdout_clipped, "stderr": stderr_clipped, "timed_out": run_res.timed_out},
            exit_code=run_res.exit_code,
            duration_ms=run_res.duration_ms,
            truncated=trunc_out or trunc_err,
        )

    def _handle_http_local(self, args: dict[str, Any], start: float) -> ToolResult:
        allowed_keys = {"method", "path", "headers", "body", "host"}
        if "path" not in args or (set(args.keys()) - allowed_keys):
            return self._reject("http_local", "http_local requires 'path' and optional 'method', 'headers', 'body', 'host'", start)

        host = str(args.get("host") or "127.0.0.1")
        if host not in ("127.0.0.1", "localhost"):
            return self._reject("http_local", f"Non-loopback host rejected: {host}", start)

        req_path = str(args["path"])
        if not req_path.startswith("/") or "://" in req_path:
            return self._reject("http_local", f"Path must be a relative route starting with '/': {req_path}", start)

        method = str(args.get("method") or "GET").upper()
        headers = args.get("headers") or {}
        if not isinstance(headers, dict):
            return self._reject("http_local", "'headers' must be an object", start)
        body = args.get("body")

        probe_payload = json.dumps({"method": method, "path": req_path, "headers": headers, "body": body})
        probe_script = (
            "const { createApp } = require('./src/app');"
            f"const spec = {probe_payload};"
            "const app = createApp();"
            "const srv = app.listen(0, '127.0.0.1', async () => {"
            "  const port = srv.address().port;"
            "  try {"
            "    const init = { method: spec.method, headers: { ...spec.headers } };"
            "    if (spec.body !== undefined && spec.body !== null) {"
            "      init.body = typeof spec.body === 'string' ? spec.body : JSON.stringify(spec.body);"
            "      if (!init.headers['content-type'] && !init.headers['Content-Type']) init.headers['content-type'] = 'application/json';"
            "    }"
            "    const resp = await fetch(`http://127.0.0.1:${port}${spec.path}`, init);"
            "    const text = await resp.text();"
            "    const hdrs = {}; resp.headers.forEach((v, k) => { hdrs[k] = v; });"
            "    console.log(JSON.stringify({ status: resp.status, headers: hdrs, body: text }));"
            "  } finally { srv.close(); }"
            "});"
        )
        probe_rel = ".psa_http_probe.js"
        probe_file = self.workspace / probe_rel
        try:
            probe_file.write_text(probe_script, encoding="utf-8")
            run_res = self.sandbox.run(self.workspace, ["node", probe_rel], timeout_s=15.0)
        finally:
            if probe_file.exists():
                probe_file.unlink()

        if run_res.exit_code != 0:
            return self._reject("http_local", f"Loopback request failed: {run_res.stderr[:240]}", start)

        clipped, trunc = self._truncate_str(run_res.stdout.strip())
        try:
            parsed = json.loads(clipped) if not trunc else clipped
        except json.JSONDecodeError:
            parsed = clipped
        return ToolResult(
            ok=True,
            tool_name="http_local",
            output=parsed,
            exit_code=0,
            duration_ms=run_res.duration_ms,
            truncated=trunc,
        )
