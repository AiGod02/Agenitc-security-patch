# Fake model client used ONLY in test_verify_setup_error_is_inconclusive to test setup-error state transitions; live MetaLLMClient + DockerSandbox used for real verification tests.
import shutil
from pathlib import Path
from typing import Any

from agent.detect import generate_candidates
from agent.llm import MetaLLMClient
from agent.recon import build_route_inventory
from agent.sandbox import DockerSandbox
from agent.tools import ToolDispatcher
from agent.verify import verify_candidate
from contracts import (
    Candidate,
    LLMCaps,
    LLMResult,
    ModelRole,
    VerificationStatus,
    VulnerabilityClass,
)

ROOT = Path(__file__).resolve().parent.parent
FIXTURE_DIR = ROOT / "fixture" / "express-fixture"


class BrokenImportFakeLLMForUnitTestOnly:
    """Used strictly in unit test below whose subject is verify_candidate's INCONCLUSIVE handling on setup errors."""

    def call(
        self,
        role: ModelRole,
        system: str,
        user: str,
        schema: dict[str, Any] | None = None,
        caps: LLMCaps | None = None,
    ) -> LLMResult:
        bad_pair = {
            "security_test_code": "const missing = require('./nonexistent-dep'); test('x', () => {});",
            "companion_test_code": "test('ok', () => { expect(1).toBe(1); });",
        }
        return LLMResult(
            parsed=bad_pair,
            text='{"security_test_code":"...","companion_test_code":"..."}',
            usage=None,
            latency_ms=1,
            cache_hit=False,
            model_id="unit-test-fake",
            request_hash="0" * 64,
        )


def test_verify_setup_error_is_inconclusive(tmp_path: Path):
    ws = tmp_path / "ws"
    shutil.copytree(FIXTURE_DIR, ws, ignore=shutil.ignore_patterns("node_modules"))
    sandbox = DockerSandbox(image="psa-sandbox:latest", agent_tag="s8setup")
    disp = ToolDispatcher(ws, sandbox)

    cand = Candidate(
        id="C-SETUP",
        vulnerability_class=VulnerabilityClass.IDOR,
        file="src/routes/invoices.js",
        start_line=30,
        end_line=36,
        route="GET /api/invoices/:id",
        reason="Missing owner check",
        evidence="store.getInvoice(req.params.id)",
        confidence=0.8,
        expected_security_failure="Bob reads Alice invoice",
        invariant_id="IDOR-SETUP-CHECK",
    )
    outcome = verify_candidate("run-s8-setup", cand, disp, BrokenImportFakeLLMForUnitTestOnly())
    assert outcome.verification.status == VerificationStatus.INCONCLUSIVE
    assert outcome.verified_finding is None


def test_verify_clean_route_is_not_reproduced(tmp_path: Path):
    ws = tmp_path / "ws"
    shutil.copytree(FIXTURE_DIR, ws, ignore=shutil.ignore_patterns("node_modules"))
    sandbox = DockerSandbox(image="psa-sandbox:latest", agent_tag="s8clean")
    disp = ToolDispatcher(ws, sandbox)
    llm = MetaLLMClient(use_cache=True)

    # False-positive candidate pointing at a CLEAN route (GET /api/admin/stats already has requireAuth + requireAdmin)
    clean_cand = Candidate(
        id="C-FP01",
        vulnerability_class=VulnerabilityClass.MISSING_AUTH,
        file="src/routes/admin.js",
        start_line=8,
        end_line=10,
        route="GET /api/admin/stats",
        reason="Suspected missing authentication on /api/admin/stats",
        evidence="router.get('/stats', ...)",
        confidence=0.4,
        expected_security_failure="Unauthenticated GET /api/admin/stats returns HTTP 200 instead of 401/403",
        invariant_id="FP-ADMIN-STATS-AUTH",
    )
    outcome = verify_candidate("run-s8-clean", clean_cand, disp, llm)
    assert outcome.verification.status == VerificationStatus.NOT_REPRODUCED
    assert outcome.verified_finding is None


def test_live_verify_loop_reaches_hard_checkpoint_of_at_least_four_flaws(tmp_path: Path):
    ws = tmp_path / "ws"
    shutil.copytree(FIXTURE_DIR, ws, ignore=shutil.ignore_patterns("node_modules"))
    sandbox = DockerSandbox(image="psa-sandbox:latest", agent_tag="s8live")
    disp = ToolDispatcher(ws, sandbox)
    llm = MetaLLMClient(use_cache=True)

    routes = build_route_inventory("run-s8-live", disp)
    batch = generate_candidates("run-s8-live", disp, llm, routes)

    # Verify first 6 detected candidates end-to-end in real Docker sandbox
    verified_count = 0
    for cand in batch.accepted[:6]:
        outcome = verify_candidate("run-s8-live", cand, disp, llm)
        if outcome.verification.status == VerificationStatus.VERIFIED_REPRODUCER:
            assert outcome.verified_finding is not None
            verified_count += 1
            # Remove verified test files between independent single-candidate checks in this loop
            for rel in (outcome.verification.test_path, outcome.verification.companion_test_path):
                if rel and (ws / rel).exists():
                    (ws / rel).unlink()

    assert verified_count >= 4, f"Hard checkpoint requires >=4 VERIFIED_REPRODUCER, got {verified_count}"
