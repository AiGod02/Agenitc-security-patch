import json
import shutil
from pathlib import Path

from agent.sandbox import DockerSandbox

ROOT = Path(__file__).resolve().parent.parent
FIXTURE_DIR = ROOT / "fixture" / "express-fixture"


def test_sandbox_runs_fixture_suite(tmp_path: Path):
    work = tmp_path / "ws"
    shutil.copytree(FIXTURE_DIR, work, ignore=shutil.ignore_patterns("node_modules"))

    sandbox = DockerSandbox(image="psa-sandbox:latest", agent_tag="s2test")
    res = sandbox.run(work, ["jest", "--runInBand", "--json"], timeout_s=45.0)
    assert not res.timed_out
    assert res.exit_code == 0, f"Sandbox Jest failed:\n{res.stderr}\n{res.stdout}"
    report = json.loads(res.stdout)
    assert report["numFailedTests"] == 0
    assert report["numPassedTests"] == 6


def test_sandbox_blocks_network_egress(tmp_path: Path):
    work = tmp_path / "ws"
    work.mkdir()
    probe_js = (
        "fetch('https://1.1.1.1')"
        ".then(() => { console.log('EGRESS_SUCCEEDED'); process.exit(0); })"
        ".catch((err) => { console.error('EGRESS_BLOCKED:' + (err.cause ? err.cause.code : err.message)); process.exit(42); });"
    )
    (work / "egress_probe.js").write_text(probe_js, encoding="utf-8")

    sandbox = DockerSandbox(image="psa-sandbox:latest", agent_tag="s2net")
    res = sandbox.run(work, ["node", "egress_probe.js"], timeout_s=15.0)
    assert not res.timed_out
    assert res.exit_code == 42
    assert "EGRESS_BLOCKED:" in res.stderr
    assert "EGRESS_SUCCEEDED" not in res.stdout


def test_sandbox_blocks_write_outside_workspace(tmp_path: Path):
    work = tmp_path / "ws"
    work.mkdir()
    escape_js = (
        "const fs = require('fs');"
        "try { fs.writeFileSync('/etc/escape_probe', 'x'); process.exit(0); }"
        "catch (e) { console.error('WRITE_BLOCKED:' + e.code); process.exit(43); }"
    )
    (work / "write_probe.js").write_text(escape_js, encoding="utf-8")

    sandbox = DockerSandbox(image="psa-sandbox:latest", agent_tag="s2fs")
    res = sandbox.run(work, ["node", "write_probe.js"], timeout_s=15.0)
    assert not res.timed_out
    assert res.exit_code == 43
    assert "WRITE_BLOCKED:" in res.stderr


def test_sandbox_enforces_hard_timeout(tmp_path: Path):
    work = tmp_path / "ws"
    work.mkdir()
    (work / "hang.js").write_text("setInterval(() => {}, 1000);\n", encoding="utf-8")

    sandbox = DockerSandbox(image="psa-sandbox:latest", agent_tag="s2timeout")
    res = sandbox.run(work, ["node", "hang.js"], timeout_s=3.0)
    assert res.timed_out is True
    assert res.exit_code == 124
