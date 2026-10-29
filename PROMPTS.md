# Development Prompts Log (`PROMPTS.md`)

Per Section 1.5 of `implmentation.md`, this file records the user prompts and internal model system prompts used to construct and operate each slice of the Verified Security Patch Agent.

## 1. User Development Prompts (2026-10-29)

1. `go throug @[c:\Users\sooja\Downloads\MetaAI\Security_patch_agent\implmentation.md] and start building this`
   - Produced Wave 0 (`contracts/`, `docs/verified_facts.md`, `docs/threat_model.md`, `pyproject.toml`, `.gitignore`, `.env.example`, `CREDITS.md`), Wave 1 (`fixture/`, `ground_truth.json`, `docker/Dockerfile`, `agent/sandbox/`, `agent/verify/matcher.py`, `tests/data/`, `agent/llm/`), Wave 2 (`agent/tools/`, `agent/recon/`, `agent/detect/`, `agent/verify/loop.py`), and Wave 3 (`agent/patch/`, `agent/evidence/`, `agent/workflow/`, `agent/cli.py`).
2. `continue`
   - Resumed Docker verification after session restart and produced Wave 4 (`eval/report.py`, `eval/run_eval.py`, `agent/advisory.py`, `agent/api/app.py`, `ui/index.html`, `README.md`, and `tests/test_eval_and_api_s12_s14.py`).
3. `continue and run script agai i have opened the docker`
   - Executed live Docker sandbox verification suites (`S2`, `S8`, `S9`, `S10`, `S11`), full end-to-end pytest regression check, 3-run empirical evaluation (`eval/run_eval.py`), CLI gate demonstration, and final checklist audit.

## 2. Runtime Agent Prompts Sent to Meta Muse Models

- **Detection (`agent/detect/candidates.py`, `DETECT_SYSTEM_PROMPT`)**: Frames all repository source code inside `<untrusted_source_file>` tags as passive untrusted data to defeat prompt injection, enforces strict JSON Schema output (`CANDIDATE_LIST_SCHEMA`) over `muse-spark-1.3`, and requires concrete `expected_security_failure` + `invariant_id` per route.
- **Verification Test Generation (`agent/verify/loop.py`, `VERIFY_SYSTEM_PROMPT`)**: Generates paired CommonJS Jest + supertest `security_test_code` (invoking `invariant(id, condition, detail)`) and `companion_test_code` (proving legitimate route behavior) using `muse-spark-1.3` on initial pass and `muse-wonder-1.0` on single feedback retry.
- **Minimal Unified Diff Remediation (`agent/patch/loop.py`, `PATCH_SYSTEM_PROMPT`)**: Uses `muse-wonder-1.0` (`ModelRole.REASONING`) to synthesize minimal `<= 40`-line unified diffs strictly outside `tests/`, preserving routes and exports.
- **Post-Fix Architecture Advisory (`agent/advisory.py`, `ADVISORY_SYSTEM_PROMPT`)**: Uses `muse-spark-1.3` after a verified `PASS` patch to separate empirical `observed_facts` from defense-in-depth `recommendations`.
