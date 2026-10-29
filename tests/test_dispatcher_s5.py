# Unit and boundary tests for ToolDispatcher (Slice S5); Docker container isolation is tested separately in test_sandbox_s2.py.
import os
import shutil
import subprocess
import time
from pathlib import Path

from agent.tools import ToolDispatcher
from contracts import RunResult

ROOT = Path(__file__).resolve().parent.parent
FIXTURE_DIR = ROOT / "fixture" / "express-fixture"


class LocalNodeSandboxForDispatcherTest:
    """Executes allowlisted argv locally with fixture NODE_PATH solely for testing ToolDispatcher validation."""

    def run(self, workspace: Path, command: list[str], timeout_s: float = 30.0) -> RunResult:
        env = os.environ.copy()
        node_modules = FIXTURE_DIR / "node_modules"
        env["NODE_PATH"] = str(node_modules)
        actual_cmd = list(command)
        if actual_cmd[0] == "jest":
            actual_cmd = ["node", str(node_modules / "jest" / "bin" / "jest.js"), *actual_cmd[1:]]
        start = time.perf_counter()
        proc = subprocess.run(
            actual_cmd,
            cwd=workspace,
            env=env,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout_s,
        )
        return RunResult(
            exit_code=proc.returncode,
            stdout=proc.stdout,
            stderr=proc.stderr,
            timed_out=False,
            duration_ms=int((time.perf_counter() - start) * 1000),
        )


def _make_ws(tmp_path: Path) -> Path:
    ws = tmp_path / "ws"
    shutil.copytree(FIXTURE_DIR, ws, ignore=shutil.ignore_patterns("node_modules"))
    return ws


def test_dispatcher_rejects_traversal_absolute_and_symlink_escape(tmp_path: Path):
    ws = _make_ws(tmp_path)
    outside_secret = tmp_path / "outside_secret.txt"
    outside_secret.write_text("TOP_SECRET_HOST_FILE", encoding="utf-8")

    disp = ToolDispatcher(ws, LocalNodeSandboxForDispatcherTest())

    # 1. Parent traversal '..' blocked
    r_trav = disp.call("run-1", "read_file", {"path": "../outside_secret.txt"})
    assert r_trav.ok is False
    assert "blocked" in (r_trav.rejection_reason or "").lower()

    # 2. Absolute path blocked (POSIX & Windows styles)
    r_abs1 = disp.call("run-1", "read_file", {"path": "/etc/passwd"})
    assert r_abs1.ok is False
    r_abs2 = disp.call("run-1", "write_file", {"path": str(outside_secret), "content": "x"})
    assert r_abs2.ok is False

    # 3. Symlink escape blocked if OS permits creating symlink in tmp_path
    link_path = ws / "escape_link.txt"
    symlink_created = False
    try:
        link_path.symlink_to(outside_secret)
        symlink_created = True
    except OSError:
        symlink_created = False

    if symlink_created:
        r_sym = disp.call("run-1", "read_file", {"path": "escape_link.txt"})
        assert r_sym.ok is False
        assert "escape" in (r_sym.rejection_reason or "").lower()


def test_dispatcher_rejects_disallowed_commands_tools_and_external_http(tmp_path: Path):
    ws = _make_ws(tmp_path)
    disp = ToolDispatcher(ws, LocalNodeSandboxForDispatcherTest())

    # Unknown tool
    r_unknown = disp.call("run-1", "exec_shell", {"cmd": "whoami"})
    assert r_unknown.ok is False

    # Disallowed commands in run_command
    for forbidden_argv in [
        ["sh", "-c", "id"],
        ["curl", "https://example.com"],
        ["node", "-e", "console.log(1)"],
        ["git", "push"],
        ["npm", "install"],
    ]:
        res = disp.call("run-1", "run_command", {"argv": forbidden_argv})
        assert res.ok is False, f"Expected {forbidden_argv} to be rejected"

    # External host in http_local rejected
    r_http_ext = disp.call("run-1", "http_local", {"host": "example.com", "path": "/"})
    assert r_http_ext.ok is False


def test_dispatcher_truncates_oversize_output_and_enforces_call_cap(tmp_path: Path):
    ws = _make_ws(tmp_path)
    big_content = "\n".join(f"line-{i}-" + ("X" * 80) for i in range(100))
    (ws / "big.txt").write_text(big_content, encoding="utf-8")

    disp = ToolDispatcher(ws, LocalNodeSandboxForDispatcherTest(), max_output_bytes=512, max_calls=3)
    r_read = disp.call("run-1", "read_file", {"path": "big.txt"})
    assert r_read.ok is True
    assert r_read.truncated is True
    assert len(r_read.output.encode("utf-8")) <= 512

    assert disp.call("run-1", "list_files", {}).ok is True
    assert disp.call("run-1", "list_files", {}).ok is True
    # 4th call exceeds max_calls=3
    r_cap = disp.call("run-1", "list_files", {})
    assert r_cap.ok is False
    assert "cap" in (r_cap.rejection_reason or "").lower()


def test_dispatcher_accepts_allowed_tools_and_apply_patch(tmp_path: Path):
    ws = _make_ws(tmp_path)
    disp = ToolDispatcher(ws, LocalNodeSandboxForDispatcherTest())

    r_list = disp.call("run-1", "list_files", {})
    assert r_list.ok is True
    assert "src/app.js" in r_list.output

    r_grep = disp.call("run-1", "grep", {"pattern": "createInvoicesRouter", "subdir": "src"})
    assert r_grep.ok is True
    assert "src/app.js" in r_grep.output

    # Test apply_patch on src/routes/admin.js
    diff = """--- a/src/routes/admin.js
+++ b/src/routes/admin.js
@@ -12,4 +12,4 @@
   // Retrieve recent administrative audit trail entries
-  router.get("/audit-log", (_req, res) => {
+  router.get("/audit-log", requireAuth, requireAdmin, (_req, res) => {
     return res.json({ entries: store.getAuditLog() });
   });
"""
    r_patch = disp.call("run-1", "apply_patch", {"diff": diff})
    assert r_patch.ok is True
    assert r_patch.output == {"patched_files": ["src/routes/admin.js"]}

    # Test http_local loopback health check
    r_http = disp.call("run-1", "http_local", {"method": "GET", "path": "/api/health"})
    assert r_http.ok is True
    assert r_http.output["status"] == 200

    # Test run_tests on baseline.test.js
    r_tests = disp.call("run-1", "run_tests", {"test_paths": ["tests/baseline.test.js"]})
    assert r_tests.ok is True
    assert r_tests.exit_code == 0
