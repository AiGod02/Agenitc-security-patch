# Verified Security Patch Agent

Proof-carrying security detection, verification, and minimal remediation agent for owned Node.js/Express repositories, powered by Meta Muse models (`muse-spark-1.3` and `muse-wonder-1.0`) and isolated Docker execution (`--network none`, `--read-only`, `--cap-drop ALL`).

## What It Guarantees (and What It Does Not)

1. **No Finding Without Execution Proof**: Every proposed candidate in six classes (`IDOR`, `PATH_TRAVERSAL`, `INJECTION`, `MISSING_AUTH`, `HARDCODED_SECRET`, `PERMISSIVE_CORS`) must state its expected failure upfront, fail deterministically twice on the vulnerable baseline with an exact `SECURITY_INVARIANT_VIOLATED:<invariant_id>` assertion tag in Jest `--json` output, have zero setup/runtime error signatures, and pass a companion positive test on the baseline.
2. **No Patch Without Anti-Vandalism Verification**: Candidate unified diffs are accepted (`PASS`) only if the demonstrating security test passes, the companion positive test still passes, the full test suite passes with zero regressions, and mechanical guards verify byte-identical `tests/` hashes, unchanged route inventory, preserved exports, untouched config/lockfiles, and `<= 40` changed lines.
3. **Human Hash-Bound Approval Only**: Nothing is auto-merged or pushed. Approvals bind cryptographically to the exact `patch.diff` SHA-256 and apply only to a designated review branch via `git worktree`.
4. **Honest Scope**: Evaluated on an owned 12-flaw + 6-clean-route + 1-prompt-injection Express fixture (`fixture/express-fixture`). Static analyzers like Semgrep catch many syntactic patterns more cheaply; the value demonstrated here is deterministic reproduction proof, companion behavioral preservation, and explicit false-positive denominators.

---

## Quickstart (Clean Machine)

### Prerequisites
- Python `>= 3.11`
- Node.js `>= 18` & `npm`
- Docker (Linux containers enabled)
- Meta Model API key (`https://api.meta.ai/v1`)

### 1. Configure Environment & Dependencies
```bash
cp .env.example .env
# Edit .env and set MODEL_API_KEY=<your_meta_api_key>

pip install -e ".[dev]"
cd fixture/express-fixture && npm install && cd ../..
docker build -t psa-sandbox:latest -f docker/Dockerfile .
```

### 2. Interactive Web Dashboard for Hackathon Judges (Paste Any Git Repo URL)
```bash
uvicorn agent.api.app:app --host 127.0.0.1 --port 8000
```
Open `http://127.0.0.1:8000` in your browser:
1. **Paste Any GitHub HTTPS Repo URL** (e.g. `https://github.com/owner/express-repo` or `https://github.com/owner/monorepo/tree/main/packages/api`) or click the 1-click **Built-in Vulnerable Express Fixture** preset, then click **Scan & Verify Repository**.
2. **Automatic Host Prep + Offline Sandbox**: The host clones the repo into `runs/<run_id>/source_repo`, auto-injects `tests/helpers/invariant.js` if missing, pre-bakes target dependencies + Jest + Supertest into a cached offline Docker image (`psa-sandbox:<hash12>`), and runs every verification & patch check inside `--network none --read-only --cap-drop ALL`.
3. **Live 6-Stage Stepper & Candidate Matrix**: Watch real-time progress across Static Recon -> Candidate Detect -> Verify Reproducer -> Deep Logic Plan -> Held-Out Variant & Patch -> Mechanical Guards & 9-Section Advisory.
4. **Side-by-Side Diff + Advisory, SHA-256 Approval & 1-Click Branch Commit**: Review the unified diff alongside `06_evidence/<cid>/advisory.md`, click **1. Approve Exact SHA-256**, and click **2. Apply Patch to Git Branch** to create an isolated review branch (`psa/fix-<cid>`) without auto-merging.

### 3. Run the Pre-Merge CLI Gate on the Vulnerable Fixture (Blocks with Exit Code `1`)
```bash
python -m agent.cli gate --target fixture/express-fixture --reproducers fixture/reproducers
```

### 3. Run the Full End-to-End Agent Pipeline
```bash
python -m agent.cli run --target fixture/express-fixture --run-id demo-run-01
```
Run outputs and per-finding evidence bundles are written to `runs/demo-run-01/`.

### 4. Inspect Deterministic Replay (No Live Model or Container Execution)
```bash
python -m agent.cli replay --run-dir runs/demo-run-01
```

### 5. Human Approval & Designated-Branch Apply
```bash
# Inspect runs/demo-run-01/bundles/C-001/summary.md and patch.sha256, then approve:
python -m agent.cli approve \
  --bundle runs/demo-run-01/bundles/C-001 \
  --reviewer alice \
  --sha256 <EXACT_SHA256_FROM_PATCH_SHA256> \
  --branch psa/fix-c-001

# Apply onto designated branch via git worktree (leaves main untouched):
python -m agent.cli apply \
  --repo . \
  --bundle runs/demo-run-01/bundles/C-001 \
  --branch psa/fix-c-001 \
  --subdir fixture/express-fixture
```

### 6. Run Multi-Run Evaluation & Generate Honest Metrics Table
```bash
python -m eval.run_eval --num-runs 3 --runs-dir runs/eval
```

### 7. Optional Minimal Human Review UI (FastAPI)
```bash
uvicorn agent.api.app:app --host 127.0.0.1 --port 8000
```

### 8. Run Full Automated Test Suite (`S0` – `S14`)
```bash
pytest -v
```

