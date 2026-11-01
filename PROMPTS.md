# Development Prompts Log (`PROMPTS.md`)

This file records the user prompts and internal model system prompts used to construct and operate each slice of the Verified Security Patch Agent.

## 1. User Development Prompts (2026-10-29)

1. `Initial Build Request`
   - Produced Wave 0 (`contracts/`, `docs/verified_facts.md`, `docs/threat_model.md`, `pyproject.toml`, `.gitignore`, `.env.example`, `CREDITS.md`), Wave 1 (`fixture/`, `ground_truth.json`, `docker/Dockerfile`, `agent/sandbox/`, `agent/verify/matcher.py`, `tests/data/`, `agent/llm/`), Wave 2 (`agent/tools/`, `agent/recon/`, `agent/detect/`, `agent/verify/loop.py`), and Wave 3 (`agent/patch/`, `agent/evidence/`, `agent/workflow/`, `agent/cli.py`).
2. `continue`
   - Resumed Docker verification after session restart and produced Wave 4 (`eval/report.py`, `eval/run_eval.py`, `agent/advisory.py`, `agent/api/app.py`, `ui/index.html`, `README.md`, and `tests/test_eval_and_api_s12_s14.py`).
3. `continue and run script agai i have opened the docker`
   - Executed live Docker sandbox verification suites (`S2`, `S8`, `S9`, `S10`, `S11`) and baseline verification.
4. `Extend the existing verified security patch agent with four parts, built in order: (1) multi-stage state management, (2) deep logic planning, (3) deep logic patching, (4) a comprehensive advisory report.`
   - Built on branch `feat/deep-logic-staged-pipeline`: Part 1 (`agent/workflow/state.py`, `agent/workflow/pipeline.py`, CLI stage subcommands), Part 2 (`agent/recon/inventory.py` rich static route/sink/ownership inventory, `agent/plan/planner.py` mechanically validated `patch_plan.json`), Part 3 (`agent/patch/deep_patch.py` held-out variant security test, `agent/patch/guards.py` test-literal & expected-scope guards, report-only sibling variant analysis), and Part 4 (`agent/advisory_report.py` 9-section comprehensive advisory with mechanical `file:line`/snippet check and aggregate `runs/<run_id>/report.md`).

## 2. Runtime Agent Prompts Sent to Meta Muse Models

- **Detection (`agent/detect/candidates.py`, `DETECT_SYSTEM_PROMPT`)**: Frames all repository source code inside `<untrusted_source_file>` tags as passive untrusted data to defeat prompt injection, enforces strict JSON Schema output (`CANDIDATE_LIST_SCHEMA`) over `muse-spark-1.3`, and requires concrete `expected_security_failure` + `invariant_id` per route.
- **Verification Test Generation (`agent/verify/loop.py`, `VERIFY_SYSTEM_PROMPT`)**: Generates paired CommonJS Jest + supertest `security_test_code` (invoking `invariant(id, condition, detail)`) and `companion_test_code` (proving legitimate route behavior) using `muse-spark-1.3` on initial pass and `muse-wonder-1.0` on single feedback retry.
- **Deep Logic Patch Planning (`agent/plan/planner.py`, `PLAN_SYSTEM_PROMPT`)**: Uses `muse-wonder-1.0` (`ModelRole.REASONING`) over `<untrusted_source_file>` blocks and rich recon slices to produce `patch_plan.json` (`>= 2` options, chosen layer, verbatim `file:line` root-cause snippets verified mechanically).
- **Held-Out Variant Security Test (`agent/patch/deep_patch.py`, `VARIANT_TEST_SYSTEM_PROMPT`)**: Uses `muse-wonder-1.0` before patching (never shown to the patch model) to generate a distinct reproducer test with different identities/resources/inputs that must fail on baseline with `SECURITY_INVARIANT_VIOLATED:<id>` and pass after patching.
- **Minimal Unified Diff Remediation (`agent/patch/loop.py`, `PATCH_SYSTEM_PROMPT`)**: Uses `muse-wonder-1.0` (`ModelRole.REASONING`) guided by `patch_plan.json` to synthesize minimal `<= 40`-line unified diffs strictly within `expected_scope_files`, reusing existing project helpers and forbidding test literals.
- **Post-Fix Architecture Advisory (`agent/advisory.py` & `agent/advisory_report.py`, `COMPREHENSIVE_ADVISORY_SYSTEM_PROMPT`)**: Uses `muse-spark-1.3` strictly over saved evidence artifacts after a verified `PASS` check to populate the 9-section `06_evidence/<cid>/advisory.md`, with mechanical `file:line`/snippet validation and explicit separation of AI recommendations from empirical facts.
