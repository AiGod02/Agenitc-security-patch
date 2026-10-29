"""Host-side Git repository ingestion and offline sandbox image preparation for arbitrary Express targets."""

from __future__ import annotations

import hashlib
import json
import re
import shutil
import subprocess
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from agent.workflow.state import atomic_write_json

ROOT_DIR = Path(__file__).resolve().parent.parent
DEFAULT_FIXTURE_PKG = ROOT_DIR / "fixture" / "express-fixture" / "package.json"

INVARIANT_HELPER_JS = """function invariant(id, condition, detail) {
  if (!condition) {
    throw new Error(`SECURITY_INVARIANT_VIOLATED:${id}: ${detail}`);
  }
}

module.exports = { invariant };
"""

_GITHUB_TREE_RE = re.compile(
    r"^(https://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+?)(?:\.git)?/tree/([^/]+)(?:/(.*))?$"
)
_ALLOWED_GIT_URL_RE = re.compile(r"^https://[A-Za-z0-9_./:@-]+$")


def parse_repo_source(repo_source: str, explicit_subdir: str = "") -> tuple[str, str | None, str]:
    """Parse GitHub repo/tree URLs or local paths into (clone_or_path, branch_or_none, subdir)."""
    cleaned = repo_source.strip()
    sub = explicit_subdir.strip().strip("/\\")
    m_tree = _GITHUB_TREE_RE.match(cleaned)
    if m_tree:
        base_url = m_tree.group(1) + ".git"
        branch = m_tree.group(2)
        url_sub = (m_tree.group(3) or "").strip("/")
        effective_sub = f"{url_sub}/{sub}".strip("/") if (url_sub and sub) else (sub or url_sub)
        return base_url, branch, effective_sub
    return cleaned, None, sub


def _is_remote_url(source: str) -> bool:
    return source.startswith(("https://", "http://"))


def _ensure_custom_sandbox_image(pkg_json_path: Path, lock_path: Path | None) -> str:
    """Reuse psa-sandbox:latest when package.json matches fixture; otherwise build cached psa-sandbox:<hash12>."""
    pkg_bytes = pkg_json_path.read_bytes()
    if DEFAULT_FIXTURE_PKG.exists():
        try:
            fix_deps = json.loads(DEFAULT_FIXTURE_PKG.read_text(encoding="utf-8")).get("dependencies", {})
            cur_deps = json.loads(pkg_bytes.decode("utf-8")).get("dependencies", {})
            if set(cur_deps.keys()).issubset(set(fix_deps.keys())):
                return "psa-sandbox:latest"
        except Exception:
            pass

    hasher = hashlib.sha256(pkg_bytes)
    if lock_path and lock_path.exists():
        hasher.update(lock_path.read_bytes())
    tag = f"psa-sandbox:{hasher.hexdigest()[:12]}"

    insp = subprocess.run(["docker", "image", "inspect", tag], capture_output=True, text=True)
    if insp.returncode == 0:
        return tag

    dockerfile_text = """FROM psa-sandbox:latest
USER root
WORKDIR /opt/psa-deps
COPY package.json package-lock.json* ./
RUN (npm install --legacy-peer-deps --no-audit --no-fund || npm install --no-audit --no-fund || true) \\
    && chown -R node:node /opt/psa-deps
USER node
WORKDIR /workspace
"""
    with tempfile.TemporaryDirectory(prefix="psa-img-build-") as tmp_ctx:
        ctx = Path(tmp_ctx)
        shutil.copy2(pkg_json_path, ctx / "package.json")
        if lock_path and lock_path.exists():
            shutil.copy2(lock_path, ctx / "package-lock.json")
        (ctx / "Dockerfile").write_text(dockerfile_text, encoding="utf-8")
        res = subprocess.run(
            ["docker", "build", "-t", tag, "-f", str(ctx / "Dockerfile"), str(ctx)],
            capture_output=True,
            text=True,
            timeout=300,
        )
        if res.returncode != 0:
            return "psa-sandbox:latest"
    return tag


def prepare_ingested_target(
    repo_source: str,
    run_dir: Path,
    subdir: str = "",
    build_custom_image: bool = True,
) -> dict[str, Any]:
    """Clone or copy target repository, inject invariant.js if absent, ensure Jest script, and resolve sandbox image."""
    run_dir.mkdir(parents=True, exist_ok=True)
    parsed_source, branch, effective_subdir = parse_repo_source(repo_source, subdir)

    source_repo_dir = run_dir / "source_repo"
    cloned_commit: str | None = None
    apply_repo_dir: str = ""
    apply_subdir: str = effective_subdir

    is_builtin_fixture = False
    if _is_remote_url(parsed_source):
        if not _ALLOWED_GIT_URL_RE.match(parsed_source):
            raise ValueError(f"Unsupported or unsafe repository URL: {parsed_source}")
        if source_repo_dir.exists():
            shutil.rmtree(source_repo_dir)
        clone_cmd = ["git", "clone", "--depth", "1"]
        if branch:
            clone_cmd.extend(["--branch", branch])
        clone_cmd.extend([parsed_source, str(source_repo_dir)])
        res = subprocess.run(clone_cmd, capture_output=True, text=True, timeout=180)
        if res.returncode != 0:
            raise RuntimeError(f"git clone failed: {res.stderr.strip() or res.stdout.strip()}")
        subprocess.run(["git", "config", "user.name", "PSA Security Reviewer"], cwd=source_repo_dir, capture_output=True)
        subprocess.run(["git", "config", "user.email", "psa@local.invalid"], cwd=source_repo_dir, capture_output=True)
        cloned_commit = subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=source_repo_dir, text=True
        ).strip()
        base_target = source_repo_dir
        apply_repo_dir = str(source_repo_dir.resolve())
    else:
        local_candidate = Path(parsed_source)
        if not local_candidate.is_absolute():
            local_candidate = (ROOT_DIR / local_candidate).resolve()
        else:
            local_candidate = local_candidate.resolve()
        if not local_candidate.exists() or not local_candidate.is_dir():
            raise ValueError(f"Repository path does not exist: {parsed_source}")

        check_sub = (local_candidate / effective_subdir).resolve() if effective_subdir else local_candidate
        is_builtin_fixture = check_sub == (ROOT_DIR / "fixture" / "express-fixture").resolve()

        if source_repo_dir.exists():
            shutil.rmtree(source_repo_dir)
        if (local_candidate / ".git").exists():
            res = subprocess.run(
                ["git", "clone", str(local_candidate), str(source_repo_dir)],
                capture_output=True,
                text=True,
                timeout=120,
            )
            if res.returncode == 0:
                subprocess.run(["git", "config", "user.name", "PSA Security Reviewer"], cwd=source_repo_dir, capture_output=True)
                subprocess.run(["git", "config", "user.email", "psa@local.invalid"], cwd=source_repo_dir, capture_output=True)
                cloned_commit = subprocess.check_output(
                    ["git", "rev-parse", "HEAD"], cwd=source_repo_dir, text=True
                ).strip()
                base_target = source_repo_dir
                apply_repo_dir = str(source_repo_dir.resolve())
            else:
                base_target = local_candidate
        else:
            shutil.copytree(local_candidate, source_repo_dir, ignore=shutil.ignore_patterns("node_modules", ".git"))
            subprocess.run(["git", "init", "-b", "main"], cwd=source_repo_dir, check=True, capture_output=True)
            subprocess.run(["git", "config", "user.name", "PSA Security Reviewer"], cwd=source_repo_dir, check=True, capture_output=True)
            subprocess.run(["git", "config", "user.email", "psa@local.invalid"], cwd=source_repo_dir, check=True, capture_output=True)
            subprocess.run(["git", "add", "."], cwd=source_repo_dir, check=True, capture_output=True)
            subprocess.run(["git", "commit", "-m", "baseline target snapshot"], cwd=source_repo_dir, check=True, capture_output=True)
            cloned_commit = subprocess.check_output(
                ["git", "rev-parse", "HEAD"], cwd=source_repo_dir, text=True
            ).strip()
            base_target = source_repo_dir
            apply_repo_dir = str(source_repo_dir.resolve())

    app_src = (base_target / effective_subdir).resolve() if effective_subdir else base_target.resolve()
    try:
        app_src.relative_to(base_target.resolve())
    except ValueError as exc:
        raise ValueError("Invalid subdirectory traversal") from exc

    if not app_src.exists() or not (app_src / "package.json").exists():
        raise ValueError(f"No Node.js package.json found in target {app_src}")

    prepared_dir = run_dir / "prepared_target"
    if prepared_dir.exists():
        shutil.rmtree(prepared_dir)
    shutil.copytree(app_src, prepared_dir, ignore=shutil.ignore_patterns("node_modules", ".git"))

    # 1. Auto-seed tests/helpers/invariant.js if the repo doesn't already include it
    inv_path = prepared_dir / "tests" / "helpers" / "invariant.js"
    injected_invariant = False
    if not inv_path.exists():
        inv_path.parent.mkdir(parents=True, exist_ok=True)
        inv_path.write_text(INVARIANT_HELPER_JS, encoding="utf-8")
        injected_invariant = True

    # 2. Ensure package.json has a runnable Jest test script if missing or npm's default placeholder
    pkg_path = prepared_dir / "package.json"
    pkg_doc = json.loads(pkg_path.read_text(encoding="utf-8"))
    scripts = dict(pkg_doc.get("scripts") or {})
    cur_test_script = str(scripts.get("test") or "").strip()
    updated_test_script = False
    if not cur_test_script or "no test specified" in cur_test_script.lower():
        scripts["test"] = "jest --runInBand"
        pkg_doc["scripts"] = scripts
        pkg_path.write_text(json.dumps(pkg_doc, indent=2) + "\n", encoding="utf-8")
        updated_test_script = True

    # 3. Ensure at least one baseline smoke test exists if the repo had zero test files (so test_count_before >= 1)
    existing_tests = list(prepared_dir.rglob("*.test.js")) + list(prepared_dir.rglob("*.spec.js"))
    if not existing_tests:
        smoke_path = prepared_dir / "tests" / "psa_baseline_smoke.test.js"
        smoke_path.parent.mkdir(parents=True, exist_ok=True)
        smoke_path.write_text(
            'test("baseline package.json loads", () => {\n'
            '  const pkg = require("../package.json");\n'
            '  expect(typeof pkg.name).toBe("string");\n'
            "});\n",
            encoding="utf-8",
        )

    # 4. Resolve or build offline Docker sandbox image with target's dependencies pre-baked
    sandbox_image = "psa-sandbox:latest"
    if build_custom_image:
        lock_fp = prepared_dir / "package-lock.json"
        sandbox_image = _ensure_custom_sandbox_image(pkg_path, lock_fp if lock_fp.exists() else None)

    meta = {
        "repo_source": repo_source,
        "parsed_source": parsed_source,
        "branch": branch,
        "subdir": effective_subdir,
        "cloned_commit": cloned_commit,
        "prepared_target": str(prepared_dir.resolve()),
        "apply_repo_dir": apply_repo_dir,
        "apply_subdir": apply_subdir,
        "sandbox_image": sandbox_image,
        "injected_invariant_helper": injected_invariant,
        "updated_test_script": updated_test_script,
        "is_builtin_fixture": is_builtin_fixture,
        "ingested_at": datetime.now(timezone.utc).isoformat(),
    }
    atomic_write_json(run_dir / "ingest_meta.json", meta)
    return meta
