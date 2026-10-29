# Tests deterministic Express route inventory (Slice S6) against hand-made list for fixture.
import shutil
from pathlib import Path

from agent.recon import build_route_inventory, extract_exported_symbols
from agent.tools import ToolDispatcher
from contracts import RunResult

ROOT = Path(__file__).resolve().parent.parent
FIXTURE_DIR = ROOT / "fixture" / "express-fixture"


class UnusedSandbox:
    """Recon must never invoke the container sandbox or model; fails if called."""

    def run(self, workspace: Path, command: list[str], timeout_s: float = 30.0) -> RunResult:
        raise AssertionError("Recon route inventory should only read files via ToolDispatcher")


HAND_MADE_FIXTURE_ROUTES = [
    ("GET", "/api/health", "src/app.js", 27),
    ("GET", "/api/admin/stats", "src/routes/admin.js", 8),
    ("GET", "/api/admin/audit-log", "src/routes/admin.js", 13),
    ("POST", "/api/admin/users/:id/deactivate", "src/routes/admin.js", 18),
    ("GET", "/api/auth/session", "src/routes/auth.js", 10),
    ("GET", "/api/auth/tokens", "src/routes/auth.js", 24),
    ("GET", "/api/exports/summary", "src/routes/exports.js", 8),
    ("GET", "/api/files/list", "src/routes/files.js", 14),
    ("GET", "/api/files/download", "src/routes/files.js", 20),
    ("GET", "/api/files/report", "src/routes/files.js", 34),
    ("GET", "/api/invoices", "src/routes/invoices.js", 8),
    ("POST", "/api/invoices", "src/routes/invoices.js", 14),
    ("GET", "/api/invoices/:id", "src/routes/invoices.js", 30),
    ("GET", "/api/search/logs", "src/routes/search.js", 12),
    ("GET", "/api/search/users", "src/routes/search.js", 31),
    ("GET", "/api/users/me", "src/routes/users.js", 8),
    ("PUT", "/api/users/:id/email", "src/routes/users.js", 17),
    ("POST", "/api/webhooks/payment", "src/routes/webhooks.js", 9),
]


def test_recon_route_inventory_matches_hand_made_list(tmp_path: Path):
    ws = tmp_path / "ws"
    shutil.copytree(FIXTURE_DIR, ws, ignore=shutil.ignore_patterns("node_modules"))
    disp = ToolDispatcher(ws, UnusedSandbox())

    routes = build_route_inventory("run-s6", disp)
    actual = [(r.method, r.path, r.file, r.line) for r in routes]
    assert actual == HAND_MADE_FIXTURE_ROUTES

    exports = extract_exported_symbols("run-s6", disp)
    assert "createApp" in exports["src/app.js"]
    assert "createInvoicesRouter" in exports["src/routes/invoices.js"]
