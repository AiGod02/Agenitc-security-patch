# Verified Security Patch Agent: Final Implementation Plan

Meta Global AI Developer Hackathon. Team of 3 (AI, backend, frontend). Internal deadline: **Wed 4 Nov 2026, 6 PM IST**. Official cutoff on the public listing: 5 Nov 2026, 6:30 AM IST (re-check in the official rules).

This file is written to be handed to AI coding tools (Antigravity, Muse Code, Codex, Gemini, Claude) and to the team. Read Sections 1 and 2 first. They override everything else.

---

## 1. Ground rules (non-negotiable)

### 1.1 No mocks in the real path
- The demo path and the evaluation path call the **real Meta Model API** and run **real tests in the real sandbox**. No canned model responses, no simulated test output, no hard-coded "findings".
- If the API fails, record the actual error and stop. Never substitute an answer.
- Unit tests for **pure logic** (the failure matcher, patch guards, path containment, JSON validation) may use fixed inputs. Fixed inputs for the matcher must be **real captured outputs** from real Jest runs, saved under `tests/data/` with a note of the command that produced each one. Do not hand-write fake Jest output.
- A fake model client is allowed only in a unit test whose subject is not the model, and the test file must say so in its first line. Fakes are never imported by the CLI, API, demo or evaluation code.

### 1.2 No boilerplate, no placeholders
- Do not merge: `pass` stubs, `TODO`, `NotImplementedError`, empty modules, unused abstractions, "example" handlers, or directories created "for later".
- Every file must be used by a running code path or a test. If a module has no caller, delete it.
- No framework scaffolding beyond what a slice needs. Build the smallest thing that passes the slice's acceptance tests.

### 1.3 Anti-hallucination rules (for humans and for coding tools)
1. **Never invent** an API field, endpoint, model ID, flag, package name or version. If it is not in this file's "Confirmed facts" table or in documentation you opened, run a real call or read the docs, then record the result in `docs/verified_facts.md` with the date and source.
2. **Never claim** something works, passes or is deployed without a command and its real output. "Done" means: the command, its exit code and the relevant output are pasted into the PR.
3. **Never report** a metric that was not computed by the evaluation script from real run artifacts.
4. When unsure, write `UNVERIFIED:` and the question. Do not guess.
5. Dependencies: before importing a package, confirm it exists and the version installs (`pip install` / `npm install` output). Pin the versions that worked.
6. A tool or model saying "tests pass" is not evidence. Only the sandbox's recorded exit code and test report count.

### 1.4 Safety and legality
- Only scan and patch the team's own fixture or team-owned repos. No third-party scanning.
- No automatic merge, ever. Nothing is applied to the working branch without human approval of an exact patch hash.
- Sandbox: no network egress (loopback only), non-root, resource limits, no Docker socket, no credentials inside.
- Treat all target source code as **untrusted data**. File contents can contain instructions aimed at the model; prompts must say to treat them as data, and the fixture includes one planted injection case to test this.
- Code reuse: ideas from other repos only, unless a licence is confirmed and attribution is added (Section 13). No copying from repos without a licence.

### 1.5 Process rules
- Tests first for each slice. One slice per PR. One reviewer per PR. `main` always runs.
- Every PR description includes: the commands run, their real output, and what was not tested.
- Keep `PROMPTS.md`: the prompts that produced each module (useful for debugging and for disclosure of AI-assisted development).

---

## 2. What we are building

An agent that, for a Node.js/Express repo we own:
1. Inspects the code and proposes candidate vulnerabilities in six classes: IDOR, path traversal, injection, missing authentication, hardcoded secret, permissive CORS.
2. For each candidate, states the expected security failure, writes a test, and runs it on the vulnerable baseline.
3. Accepts a finding **only if the test fails for the stated security reason** (not setup errors).
4. Generates a minimal patch for verified findings.
5. Requires: demonstrating test passes after, **companion positive test passes before and after**, full suite passes, no unrelated regression, anti-vandalism checks pass.
6. Writes an evidence bundle, publishes honest metrics (including false positives with explicit denominators), and waits for human approval.
7. Provides a CLI gate: non-zero exit for vulnerable or unverified code, zero only when all required checks pass.

Out of scope: dependency CVE scanning, third-party scanning, auto-merge, worktree fan-out, multi-agent swarms, RAG, a polished dashboard, any claim of universal detection.

---

## 3. Confirmed facts, unverified facts, and what to verify first

### 3.1 Checked on 29 Oct 2026 (with source)
| Fact | Status | Source |
|---|---|---|
| Meta Model API base URL `https://api.meta.ai/v1` | Consistent across sources seen | LiteLLM Meta provider docs |
| Endpoints listed there: `/chat/completions`, `/responses`, `/v1/messages` | Seen on a third-party page only | LiteLLM Meta provider docs |
| `muse-spark-1.1` listed with function calling, structured outputs, prompt caching, `reasoning_effort` | Seen on a third-party page only | LiteLLM Meta provider docs |
| Public hackathon page: tracks listed as indie and startup; submission deadline 5 Nov 2026 6:30 AM IST; originality rules not shown | Seen | Internshala listing |
| OpenHands vulnerability-fixer licence: MIT (React UI, Trivy-based scanning, TypeScript SDK) | Seen | OpenHands blog |
| cve-coder licence | **Conflicting**: PyPI shows "MIT License (Apache License)" with an MIT classifier | PyPI |
| cve-coder verify idea: regression test must fail on buggy checkout and pass on fixed; outcomes EFFECTIVE / FIX_FAILED / INCONCLUSIVE / NO_TESTS | Seen | PyPI |
| Samarth1980/patchbot: no LICENSE file in a shallow clone | Seen | local clone |

### 3.2 UNVERIFIED (verify on the first day with real calls; record in `docs/verified_facts.md`)
- Exact model IDs for Muse Spark and Muse Wonder (the earlier plan used `muse-spark-1.3` and `muse-wonder-1.0`; the third-party page lists `muse-spark-1.1`). Read the official model list or call the API.
- Whether `/responses` or `/chat/completions` is better for tool calling and structured output, and the exact request and response shapes.
- Which models support tool calling and JSON schema output; rate limits; credits; region availability.
- Whether Muse Code is a model, a harness or a coding agent, and whether it has an event log, replay or approval steps. **Do not rely on any of these.** The plan implements its own.
- Official hackathon rules: originality and prior code, AI coding tools, allowed implementation languages, judging rubric, which track is the security-patch track, required use of Meta models. The public listing does not show these. Read the official rules page and ask in office hours if unclear.
- PrismorSec/patchbot licence (the repo is mainly dependency remediation; not needed for MVP).

### 3.3 Day-1 gate (blocks everything else)
Run with a real key. All outputs go in `docs/verified_facts.md`.
```bash
curl --fail-with-body -sS -X POST "https://api.meta.ai/v1/responses" \
  -H "Authorization: Bearer ${MODEL_API_KEY}" -H "Content-Type: application/json" \
  -d '{"model":"<MODEL_ID_FROM_OFFICIAL_DOCS>","input":"Reply with the single word: ready"}'
```
Gate passes only when: one real call succeeds for each of Spark and Wonder, the model IDs are recorded, the usage fields in the response are recorded (or recorded as absent), and one real call proves structured JSON output works (or records that it does not and the plan falls back to JSON-in-text with strict validation). If an ID fails, find the correct ID in official docs. Never guess a replacement.

---

## 4. Architecture and the Python/Node boundary

Python owns the agent. Node.js/Express is the target application that is inspected, tested and patched inside a container. Confirm with organizers that a Python agent is allowed; if only Node is allowed, the same slices apply in Node.

```
CLI (primary)  <->  FastAPI (thin layer over the same functions)
          |
   Workflow runner (plain Python state machine, or LangGraph if the team prefers)
   RECON -> CANDIDATES -> EXPECTED_FAILURE -> TEST_GEN -> VERIFY
         -> PATCH -> CHECKS -> EVIDENCE -> AWAITING_APPROVAL -> APPROVED -> APPLIED
          |
   Tool dispatcher (validates every call)  ->  Sandbox (Docker, no network)
          |
   Fixture: Node/Express app + Jest + supertest
```

Build the CLI path first. FastAPI and the UI wrap it later; they add nothing the CLI cannot do.

Suggested layout (create each file only when its slice needs it):
```
agent/        llm/ (client, cache, cost log), tools/, sandbox/, verify/, patch/, evidence/, workflow/, cli.py
fixture/      express-fixture/ (app, tests, helpers, Dockerfile deps baked in)
ground_truth.json
eval/         run_eval.py, report.py
tests/        unit tests, tests/data/ (real captured outputs)
docs/         verified_facts.md, threat_model.md
runs/         (gitignored)
```

---

## 5. Data contracts (validate with Pydantic; treat model output as untrusted)

**Candidate**
```json
{
  "id": "C-001",
  "vulnerability_class": "IDOR",
  "file": "routes/invoices.js",
  "start_line": 42,
  "end_line": 55,
  "route": "GET /invoices/:id",
  "reason": "...",
  "evidence": "quoted lines from the file",
  "confidence": 0.72,
  "expected_security_failure": "Bob receives Alice's invoice body with HTTP 200",
  "invariant_id": "IDOR-INVOICE-OWNER"
}
```
Classes: `IDOR, PATH_TRAVERSAL, INJECTION, MISSING_AUTH, HARDCODED_SECRET, PERMISSIVE_CORS`. Reject candidates whose file does not exist, whose lines are out of range, or whose route is not in the inventory. Deduplicate overlapping candidates.

**Verification result**: `candidate_id, test_path, baseline_exit_code, timed_out, tagged_assertion_matched (bool), companion_baseline_exit_code, status` where status is one of `VERIFIED_REPRODUCER, NOT_REPRODUCED, INCONCLUSIVE`. Post-patch fields: `patched_security_exit_code, companion_after_exit_code, full_suite_exit_code, guards_passed, final_status` (`PASS, FAIL, INCONCLUSIVE`).

---

## 6. Verification specification (the core)

### 6.1 Tagged invariant helper
The fixture ships `tests/helpers/invariant.js`:
```js
function invariant(id, condition, detail) {
  if (!condition) throw new Error(`SECURITY_INVARIANT_VIOLATED:${id}: ${detail}`);
}
module.exports = { invariant };
```
Every generated security test must reach an `invariant(...)` call that encodes the stated expected failure. Run Jest with `--json` and read `failureMessages` from the JSON, not console text.

### 6.2 A candidate is `VERIFIED_REPRODUCER` only if all hold
1. The security test **failed** on the vulnerable baseline.
2. The failing test's `failureMessages` contains `SECURITY_INVARIANT_VIOLATED:<this candidate's invariant_id>`.
3. No setup-error signature appears in the failure: `ECONNREFUSED`, `MODULE_NOT_FOUND`, `Cannot find module`, `ReferenceError`, `SyntaxError`, `EADDRINUSE`, test timeout, `TypeError` raised outside an `invariant` call.
4. The companion positive test **passes on the baseline** (it proves the feature works for the legitimate case, so a later fix cannot pass by breaking the feature).
5. Re-running the security test once gives the same failure (determinism check).

Otherwise: test passed on baseline means `NOT_REPRODUCED` (counted, see Section 11); any setup error or missing tag means `INCONCLUSIVE` (one retry with the failure fed back, then final).

### 6.3 Patch acceptance (all required)
1. Demonstrating test now passes.
2. Companion test still passes.
3. Full suite passes; no previously passing test turned red.
4. **Anti-vandalism guards**, each a mechanical check:
   - total test count did not drop and no test is skipped or deleted
   - the security and companion test files are byte-identical after the patch (hash check); patches may not edit `tests/`
   - route inventory before and after is identical (no route removed or disabled)
   - no exported handler removed; no config, lockfile or secret-file changes unless the finding requires it
   - changed-line count within the cap (default 40); above it, the finding is flagged for explicit human review, never auto-passed
5. Repair attempts: at most 2 retries; stop if the normalized failure signature repeats.

### 6.4 Per-class guidance (for test authors)
| Class | Failing assertion (on vulnerable code) | Companion test |
|---|---|---|
| IDOR | Bob requests Alice's resource, expects 403/404, gets 200 and her data | Alice gets her own resource |
| Path traversal | `../` request returns content outside the allowed root | A legitimate file in the root still downloads |
| Injection | Crafted input changes query result or runs a command (harmless marker only) | Normal input returns correct results |
| Missing auth | Unauthenticated request to a protected route succeeds | Authenticated user still succeeds |
| Hardcoded secret | Secret literal is present in source and accepted for signing/auth | Auth still works with the secret from environment |
| Permissive CORS | Response echoes an arbitrary origin with credentials allowed | Allowed origin still gets headers |

Classes 5 and 6 are lowest priority. The cut ladder (Section 12) drops them before anything else.

---

## 7. Sandbox specification

- One Docker image with Node, Jest, supertest and **all dependencies pre-installed at build time**. The sandbox has no network, so `npm install` inside it must never be needed. Build the image with network, run it without.
- Run flags (adjust to what actually works, and record the final command in `docs/verified_facts.md`): `--network none`, `--read-only` with a tmpfs for temp, `--cap-drop ALL`, `--pids-limit`, `--memory`, `--cpus`, non-root user, workspace mounted as the only writable path, hard wall-clock timeout enforced by the runner.
- Loopback HTTP works inside the container: start the Express app and run supertest in the same container.
- Prove no egress with a real command inside the container (for example a request to a public host must fail) and save the output. Prove no write outside the workspace the same way.
- The original repo is never modified before approval; work in a disposable copy.
- No Docker socket, no host credentials, no API keys in the container. `MODEL_API_KEY` lives only in the orchestrator.

---

## 8. Tool surface (restricted dispatcher)

Exact names: `list_files`, `read_file` (line ranges), `grep` (bounded output), `write_file` (workspace only), `apply_patch` (workspace only), `run_tests` (fixed command, hard timeout, truncated output), `run_command` (strict allowlist: `node`, `npm test`, `git diff`; everything else rejected), `http_local` (loopback only).

The model may request a tool; the dispatcher decides. Validate tool name, argument schema, path containment (block absolute paths, `..`, symlink escape), output size, execution time and call count. Never pass model output to a shell string.

---

## 9. Platform logging, cache, replay, approval, CLI gate

- **Event log**: append-only JSONL, one event per model call and per tool call, with sequence number, run id, stage, input hash, sanitized arguments, result reference, exit code, timing, error status. No raw secrets.
- **Replay**: a command that replays recorded tool outcomes and recorded model outputs for inspection without re-executing destructive actions or re-calling the model. Replay output is labeled as replay, never presented as a live run.
- **Model call log and cost**: log model ID, prompt hash, latency, retries, provider-reported token usage. Compute cost only from verified pricing; otherwise record "unknown". Never estimate silently.
- **Cache**: key = model ID + hash of normalized request (including schema and tool context). Store hit/miss. Metrics report cache hits separately so live numbers are not inflated.
- **Caps**: per-candidate token and time limits, per-run limits, max 2 repair retries.
- **Approval**: reviewer sees finding, expected invariant, baseline failure, diff, patched security result, companion result, full-suite result, guard results. Approval binds to the SHA-256 of the exact patch; any change invalidates it. Apply writes to a designated branch only; no push, no merge.
- **CLI gate**: exit 0 only when all required checks pass on the patched code; non-zero on vulnerable, unverified, timed-out, missing-test, missing-credential or inconclusive states. Demonstrate it as a local pre-merge hook that blocks the vulnerable fixture and passes the verified patched fixture.

---

## 10. Fixture and ground truth

- Build a small original Express app (users, invoices, file download, search, a few admin routes) with Jest and supertest tests and a healthy baseline suite.
- 12 planted flaws across the six classes (two each), plus **one planted prompt-injection comment** in a source file to test that the agent treats code as data, plus a few **clean, non-vulnerable routes** so false positives are measurable.
- `ground_truth.json` per flaw: id, class, file, line range, route, invariant id, expected invariant text, reproducer test path, companion test path, expected patch outcome. Written before the agent is run, and committed.
- Order: first six flaws (IDOR, path traversal, injection) first; each has a hand-verified failing test and a companion test **before** any model is involved (run them yourself and see them go red/green).
- Optional later: a licensed third-party vulnerable app (for example OWASP NodeGoat) only if time remains and its licence permits; otherwise skip.

---

## 11. Evaluation and metrics (computed by script from run artifacts only)

Per class and overall, report counts and explicit denominators:
- Planted flaws: `n`. Candidates produced: `n`.
- Verified reproducers; matched to a ground-truth flaw (true positives); **missed planted flaws** (recall = verified planted / planted).
- `NOT_REPRODUCED` candidates, split by whether they map to a clean route (false positive) or to a planted flaw (weak test or miss).
- `INCONCLUSIVE` candidates reported separately, never counted as verified.
- Verified findings **not** in ground truth: listed for manual review, never silently counted as wins or errors.
- Patch success among verified findings; regressions caught; guard rejections.
- False-positive rate = false-positive candidates / all evaluated candidates (denominator shown).
- Latency, token usage (provider-reported), cache hit rate, cost only if pricing is verified.

Run the full evaluation at least 3 times and report the range, because model output varies. State the fixture size and that results do not prove universal detection. Never round up or omit a bad class.

Honest comparison: static tools such as Semgrep already find many of these patterns cheaply; the value here is the proof (failing test, companion test, regression checks) and the measured false-positive rate. Say so.

---

## 12. Build slices (the unit of work; Section 12A assigns them to parallel agents)

Each slice: tests first, no stubs, real commands in the PR. Order matters.

| # | Slice | Acceptance (all real commands) |
|---|---|---|
| S0 | Verified facts and API smoke test | Real call to Spark and Wonder succeeds; `docs/verified_facts.md` filled with IDs, response shape, usage fields |
| S1 | Fixture first six flaws + hand-written tests | Each security test fails with the tagged message; each companion passes; suite green otherwise |
| S2 | Sandbox runner | Real run of the fixture suite in the container; egress blocked proof; write-escape blocked proof; timeout kills a runaway test |
| S3 | Failure-reason matcher | Unit tests over real captured Jest JSON: true failure accepted; passing test, missing module, timeout, port in use, wrong tag all rejected |
| S4 | Meta client + cache + cost log | One live integration test; cache hit on repeat; usage fields logged as returned |
| S5 | Tool dispatcher | Rejects `..`, absolute paths, symlink escape, disallowed command, oversize output; accepts allowed calls |
| S6 | Recon (route inventory) | Prints method, path, file, line for every fixture route; compare with a hand-made list |
| S7 | Candidate generation | Real Spark calls; schema-valid JSON; invalid file/line rejected; compare against `ground_truth.json` |
| S8 | Verify loop | At least 4 planted flaws reach `VERIFIED_REPRODUCER`; clean routes produce `NOT_REPRODUCED`; setup errors yield `INCONCLUSIVE` |
| S9 | Patch loop + guards | At least 3 end-to-end PASS patches; a deliberately vandalizing patch (deletes the route) is rejected by the guards |
| S10 | Evidence bundle + event log + replay | Bundle folder per finding; replay reproduces the recorded sequence |
| S11 | Approval + apply + CLI gate | Gate fails on vulnerable fixture, passes on patched fixture; approval hash mismatch blocks apply |
| S12 | Evaluation script and report | Table generated from artifacts; 3 runs; per-class FP counts |
| S13 | Thin FastAPI, then minimal review UI | Only after S1 to S12 work; endpoints wrap existing functions |
| S14 | Architecture advisory | Only after a verified fix; separates observed facts from recommendations |

**Hard checkpoint (end of Day 3 of the build)**: if fewer than four planted flaws reach `VERIFIED_REPRODUCER`, stop patch work and fix the verifier. Fallback scope: IDOR, path traversal, injection, missing authentication.

**Cut ladder** (in order): NodeGoat integration, worktree fan-out, report UI polish, S14, FastAPI/UI (keep CLI), classes 5 and 6, then fixture below 12 flaws (disclose). Never cut: expected-reason failing tests, companion tests, human approval, false-positive reporting.

---

## 12A. Parallel agent execution (Antigravity)

The slices in Section 12 are split across eight agents that work at the same time. The split is by **file ownership**, so agents never edit the same files, and by **contracts**, so an agent can build against an interface before the code behind it exists.

### Rules for every agent
1. **Ownership.** Edit only the paths your agent owns (table below). Anything else needs a human-approved PR to the owning agent or to `contracts/`.
2. **Branch per agent**: `agent/<n>-<name>`. If Antigravity does not isolate each agent's workspace, give each its own checkout with `git worktree add ../wt-<n> -b agent/<n>-<name>`. Every change goes through a PR into `main`. One human reviewer checks `git diff --name-only` against the ownership table and checks the PR's real command output.
3. **Depend on contracts, not on unmerged code.** If a dependency is not merged yet, build and test only what can be tested with real data now. Write the integration test and mark it `blocked_on:<agent>`; run it once the dependency merges. Never stub or fake the dependency to make a test pass.
4. **Shared resources.** Name containers `psa-<agent>-<run>`. Tests use ephemeral ports (port 0), never fixed ports. Each agent writes run output only under `runs/<agent>/`.
5. **Live model calls** go only through Agent 3's client, with the cache on. Rate limits and credits are unknown until the smoke test: ask the human for a per-agent call budget and stop and report when it is spent.
6. **Every PR contains**: the commands run, their real output, what was not tested, and the files touched.
7. **Unverified facts.** If a task needs a fact that is not in Section 3.1 or in `docs/verified_facts.md`, write `UNVERIFIED:` in the PR and ask a human. Do not guess.
8. Sections 1 and 2 of this file apply to every agent without exception (no mocks in the real path, no stubs, no invented APIs).

### Contracts (Wave 0, written by humans, frozen after merge)
Put these in `contracts/` as Pydantic models plus a short `contracts/README.md`. A change after the freeze needs an explicit human-approved PR and a message to every agent.

| Contract | Shape |
|---|---|
| `RunResult` | `exit_code, stdout, stderr, timed_out, duration_ms` |
| `Sandbox.run(workspace, command, timeout_s) -> RunResult` | command is a list, never a shell string |
| `LLM.call(role, system, user, schema, caps) -> LLMResult` | role is `fast` or `reasoning`; result has `parsed or text, usage (or None), latency_ms, cache_hit, model_id, request_hash` |
| `Dispatcher.call(run_id, tool_name, args) -> ToolResult` | the eight tools in Section 8; rejects invalid calls with a reason |
| `Candidate`, `VerificationResult`, `VerifiedFinding`, `PatchResult` | Section 5 fields |
| `Event` | `seq, run_id, stage, input_hash, args, result_ref, exit_code, duration_ms, error` |
| `MatchResult` | `matched: bool, reason` where reason is one of `TAG_MATCHED, PASSED, NO_TAG, WRONG_TAG, SETUP_ERROR, TIMEOUT` |
| CLI exit codes | `0` all required checks pass; `1` vulnerable or unverified; `2` inconclusive or error. Never `0` on any failure, timeout, missing test or missing credential |

### Agents and ownership

| # | Agent | Owns (only these paths) | Slices | Depends on | Human reviewer |
|---|---|---|---|---|---|
| 1 | Sandbox and Tools | `agent/sandbox/`, `agent/tools/`, `docker/` | S2, S5 | contracts; Agent 2's `package.json` (first PR) | Backend |
| 2 | Fixture and Ground Truth | `fixture/`, `ground_truth.json` | S1 | contracts | Frontend |
| 3 | Model Layer | `agent/llm/`, model section of `docs/verified_facts.md` | S0, S4 | contracts; the human's API key | AI dev (you) |
| 4 | Detection | `agent/recon/`, `agent/detect/` | S6, S7 | Agents 1, 2, 3 | AI dev (you) |
| 5 | Verification | `agent/verify/`, `tests/data/` | S3, S8 | Agents 1, 2, 3, 4 | AI dev (you) |
| 6 | Remediation | `agent/patch/` | S9 | Agents 1, 2, 3, 5 | Frontend |
| 7 | Evidence, Approval, Gate, Workflow | `agent/evidence/`, `agent/workflow/`, `agent/cli.py` | S10, S11 | all contracts; Agents 5, 6 for wiring | Backend |
| 8 | Evaluation and Surfaces | `eval/`, `agent/api/`, `ui/` | S12, S13, S14 | all | Frontend |

### Waves (what runs in parallel, and the gate to start the next wave)

**Wave 0, humans only (Thu 29 Oct, morning).** Run the S0 smoke test with the real key. Write and merge `contracts/`, the project skeleton (`pyproject`, `.gitignore`, `.env.example`), and `docs/verified_facts.md`. Read the official hackathon rules and note the answers. **Gate:** one real call to each model works and the model IDs are recorded; contracts are merged.

**Wave 1, parallel (Thu 29 Oct).**
- Agent 1: sandbox run policy and runner, with the no-egress and no-write-escape proofs and a timeout kill test (on a plain Node image until Agent 2's `package.json` lands, then the baked-dependency image).
- Agent 2: `package.json` and lockfile first (so Agent 1 can build the image), then the first six flaws with hand-run red and green tests.
- Agent 3: Meta client, structured-output validation, cache, cost and latency log, caps, retries, one live integration test.
- Agent 5: failure-reason matcher only, tested on real captured Jest JSON. It builds its own tiny Node project under `tests/data/capture/` with a capture script that runs real Jest and saves the output for each case: tagged failure, passing test, missing module, timeout, port in use, wrong tag.
- Agent 7: event log, replay reader, evidence bundle writer and patch-hash approval logic. These are pure logic and are tested with real files.

**Gate:** sandbox runs the fixture suite with proofs saved; six flaws hand-verified red and green; a live model call works and repeats as a cache hit; matcher tests pass on real captures.

**Wave 2, parallel (Fri 30 Oct).**
- Agent 1: tool dispatcher with all rejection tests.
- Agent 4: route inventory and candidate generation against the fixture.
- Agent 5: the verify loop (needs Agents 1 to 4).
- Agent 2: flaws 7 to 12, the clean routes, and the planted prompt-injection comment.

**Gate (hard checkpoint):** at least four planted flaws reach `VERIFIED_REPRODUCER`. If fewer, all agents stop new work and help Agent 5 fix the verifier. Fallback scope is IDOR, path traversal, injection, missing auth.

**Wave 3, parallel (Sat 31 Oct to Sun 1 Nov).**
- Agent 6: patch loop and anti-vandalism guards, including a test that a deliberately vandalizing patch is rejected.
- Agent 7: workflow wiring, replay command, approval and apply, CLI gate.
- Agent 8: scoring code against `ground_truth.json`, run on real artifacts.

**Gate:** at least three end-to-end PASS patches; the gate blocks the vulnerable fixture and passes the patched one; replay works.

**Wave 4 (Mon 2 to Tue 3 Nov).** Integration and false-positive hardening, three full evaluation runs (Agent 8), thin FastAPI, then the minimal review UI, then the advisory only if everything else is green. Feature freeze Monday night.

### Brief to paste into every agent first
> You are building one part of a verified security patch agent, in parallel with other agents. Read `FINAL_IMPLEMENTATION_PLAN.md` Sections 1 to 11 and 12A, `contracts/`, and `docs/verified_facts.md` before writing code. Edit only the paths your agent owns. Follow the ground rules: no mocks in the real path, no stubs or placeholders, no invented APIs or model IDs, and never claim something works without pasting the command and its real output. Read the reference repositories in Section 12B for ideas, then close them and write your own code. Do not copy code from them. Write tests first. Open one PR per task. If you need something that is not verified or not yours, write `UNVERIFIED:` or `NEEDS-OWNER:` in the PR and stop.

### Agent briefs (task, acceptance, must not)

**Agent 1: Sandbox and Tools.** Build `Sandbox.run` (Docker, no network, read-only root with tmpfs, non-root, cpu, memory and pids limits, hard timeout) and the `Dispatcher` with the eight tools of Section 8. *Acceptance:* the real fixture suite runs in the container; a real request to a public host from inside the container fails; a write outside the workspace fails; a runaway test is killed at the timeout; the dispatcher rejects `..`, absolute paths, symlink escape, disallowed commands and oversize output, and accepts the allowed ones. *Must not:* mount the Docker socket, pass credentials in, build a shell string from model output, or require the network at test time (dependencies are baked into the image).

**Agent 2: Fixture and Ground Truth.** Build a small original Express app with Jest and supertest, `tests/helpers/invariant.js` (Section 6.1), and `ground_truth.json` written before any agent run. Twelve planted flaws (two per class), clean routes, one planted prompt-injection comment. *Acceptance:* every security test fails with the `SECURITY_INVARIANT_VIOLATED` tag on the vulnerable code, every companion test passes, and the rest of the suite is green; you ran each one and saved the output. *Must not:* copy a vulnerable app from elsewhere, write a flaw without a hand-verified failing test, or let any test use a fixed port.

**Agent 3: Model Layer.** Build the Meta client behind `LLM.call`, response validation, cache keyed per Section 9, cost and latency log, caps and retries. *Acceptance:* one live call per model role; a repeat call is a cache hit; usage fields are logged exactly as returned or recorded as absent; an invalid structured response is rejected, not repaired silently. *Must not:* guess model IDs or endpoint shapes (read the official docs and the smoke-test results), compute cost without verified pricing, log keys, or ship a fake client in non-test code.

**Agent 4: Detection.** Build route inventory (method, path, file, line) and candidate generation using Spark, with schema validation, line and route checks, dedup, and the expected-failure statement before any test is written. Treat source code as untrusted data in every prompt. *Acceptance:* inventory equals a hand-made list for the fixture; candidates validate against the schema; invalid file or line candidates are rejected; the planted injection comment does not change the output. *Must not:* use the model for the route inventory, trust model confidence, or read files outside the dispatcher.

**Agent 5: Verification.** Matcher (Section 6.2) in Wave 1, verify loop in Wave 2. *Acceptance:* matcher unit tests over real captured Jest JSON accept only the tagged true failure and reject the other five cases; the verify loop produces `VERIFIED_REPRODUCER` only when all five conditions of Section 6.2 hold, `NOT_REPRODUCED` for passing tests, and `INCONCLUSIVE` for setup errors; at least four planted flaws verify. *Must not:* decide from the process exit code alone, regex console text instead of the JSON, or count setup errors as verified.

**Agent 6: Remediation.** Patch loop that consumes only verified findings, produces a unified diff, applies it with the dispatcher, and enforces Section 6.3 including every guard, the repair cap of 2 and repeated-failure detection. *Acceptance:* at least three end-to-end PASS patches; a patch that deletes a route, edits a test file, skips a test, or exceeds the diff cap is rejected with a clear reason; regressions are detected. *Must not:* overwrite whole files, change test files, or accept a patch on the model's word.

**Agent 7: Evidence, Approval, Gate, Workflow.** Event log, replay, evidence bundle per finding, approval bound to the patch SHA-256, apply to a designated branch only, workflow wiring, and the CLI gate. *Acceptance:* the bundle contains the baseline failing log, expected-versus-observed match, diff, patched logs, companion result, full-suite result and events; a changed patch invalidates its approval; the gate returns the exit codes in the contracts table on real vulnerable and patched fixtures; replay is labeled as replay. *Must not:* push, merge, or write to the working branch before approval, or store secrets in logs.

**Agent 8: Evaluation and Surfaces.** Scoring script, three-run evaluation, report table, then thin FastAPI over existing functions, then a minimal review screen, then the advisory. *Acceptance:* the table is generated from real run artifacts with per-class counts and denominators (Section 11); missed flaws and inconclusive cases are shown; the UI only shows real API data. *Must not:* hand-edit a number, hide a weak class, or start the UI before the CLI path produces a real evidence bundle.

### Merge order and conflict control
Merge in dependency order: contracts, then Agents 2, 1, 3 and 5's matcher and 7's pure logic, then 4, then 5's verify loop, then 6, then 7's wiring, then 8. If two agents need to change the same file, the owner makes the change and the other agent waits. The human integrator runs the full suite on `main` after every merge; a red `main` stops all agents until fixed.

---

## 12B. Reference repositories (read for ideas, then close and write your own code)

These are the two repositories the agents must read during implementation. They are references, not code sources.

### 1. Samarth1980/patchbot
https://github.com/Samarth1980/patchbot (Python, LangGraph, Docker, Gemini)

**Licence: none found.** The repo had no LICENSE file when cloned on 28 Oct 2026, so copying or adapting its code is not permitted without the author's written permission. Read it for structure only.

Read and take as an **idea**:
- `agent_brain/graph.py`: the router that fingerprints repeated error output and stops loops, plus a step budget. Our version hashes a normalized failure signature, stored per run in the run's own state (not a module-level global).
- `agent_brain/evaluator.py`: gating on the real process exit code before asking any model. Our version also requires the tagged assertion and the companion and guard checks, and never uses a model to judge pass or fail.
- `mcp_sandbox/docker_client.py`: the lifecycle of a disposable git worktree plus a container, with cleanup. Ours disables the network and pre-bakes dependencies.
- `agent_brain/telemetry.py`: latency and token tracking (not reviewed in detail by us; read it before relying on it).

Do **not** take: whole-file overwrite as the patch format (ours is a minimal unified diff), bridge networking in the container, automatic force-push and PR creation in `agent_brain/pr_gate.py`, the made-up trace link in its PR body, the hard-coded repository slug, or its README performance numbers.

### 2. digital-duck/cve-coder
https://github.com/digital-duck/cve-coder (Python CLI; PyPI package `cve-coder`)

**Licence: conflicting.** PyPI shows "MIT License (Apache License)" with an MIT classifier. Read the repo's LICENSE file and record the answer in `docs/verified_facts.md` before reusing any text or prompts. Until then, ideas only.

Read and take as an **idea**:
- The stage structure (spec, detect, patch, verify, pipeline) with a separate saved artifact per stage, so each stage is inspectable.
- The verify rule: a regression test must **fail on the vulnerable checkout and pass on the fixed one**, run against both. This is the same principle as our Sections 6.2 and 6.3.
- The outcome vocabulary: EFFECTIVE, FIX_FAILED (test passed on both), INCONCLUSIVE (test did not separate the two), NO_TESTS. Ours maps to `PASS`, `FAIL`, `INCONCLUSIVE`.
- The detect-stage prompts in its skills directory (`common/SKILL.md`, per-language skills) for prompt-design ideas only.
- Where to look: its README, the CLI in `cve_coder/cve_coder.py`, and the saved per-CVE outputs described there.

Do **not** take: the dependence on NVD CVE IDs (ours finds flaws in source with no CVE), its Claude CLI agent backend, or any prompt text verbatim.

### Optional references
- OpenHands/vulnerability-fixer (MIT per OpenHands' blog post; React UI, scanner-driven): https://github.com/OpenHands/vulnerability-fixer. For Agent 8 only, for the review-screen flow. It targets known-vulnerability scanning, which is out of our scope.
- PrismorSec/patchbot (mainly dependency remediation; licence not verified): https://github.com/PrismorSec/patchbot. For Agent 7 only, for report shape and explicit failure reasons.

### How agents should use them
1. Open the repo, read the files named above, and write down the idea in your own words in the PR (two or three sentences).
2. Close the repo. Write your own implementation from this plan and the contracts.
3. If a human decides to reuse licensed code later, follow Section 13 (credits, licence notices, disclosure) first.
4. If an agent cannot browse GitHub, a human pastes the named files into the task. Do not let an agent reconstruct them from memory.

---

## 13. Reuse and attribution

- **Ideas adopted (no code copied):**
  - cve-coder: stage artifacts, same test on baseline and patched copy, outcomes EFFECTIVE / FIX_FAILED / INCONCLUSIVE.
  - Samarth1980/patchbot: disposable container, exit-code gates, repeated-error detection, latency and token logging.
  - OpenHands vulnerability-fixer: review flow (inspect finding, review diff and evidence, approve or reject).
  - PrismorSec/patchbot: report shape and explicit failure reasons.
- Samarth1980/patchbot has no licence file. Do not copy its code. If you want to reuse it, ask the author for written permission or an open licence first.
- If any licensed code (MIT, Apache-2.0) is copied: add a `CREDITS.md` with repo, licence, what was used, and keep the licence notices. Mention it in the README and the submission form. Check the official rules on pre-existing code before doing so.
- State AI-assisted development honestly if the rules ask for it.

---

## 14. Schedule (today is Thu 29 Oct; compress if Day 1 gate is already done)

When building with parallel agents, follow the wave plan in Section 12A; the dates below are the same calendar.

| Date | Goal |
|---|---|
| Thu 29 Oct | S0 gate, rules read, S1 fixture (6 flaws), S2 sandbox, S3 matcher |
| Fri 30 Oct | S4 client, S5 dispatcher, S6 recon, S7 candidates, start S8 verify (pair AI + backend) |
| Sat 31 Oct | S8 checkpoint (4 verified), S9 patch loop and guards |
| Sun 1 Nov | S10 evidence/replay, S11 approval and gate, first full evaluation |
| Mon 2 Nov | False-positive hardening, remaining fixture flaws to 12, feature freeze at night |
| Tue 3 Nov | Clean-machine README test, rehearse demo twice, optional UI/advisor if everything is green |
| Wed 4 Nov | Final recording, final evaluation, submit by 6 PM IST |

If behind, cut by the ladder in Section 12 rather than extending.

---

## 15. Demo script (all real)

1. Run the CLI gate on the vulnerable fixture: it blocks.
2. Start a run; show the real model call, the candidate and the stated expected failure.
3. Show the real failing test output containing the `SECURITY_INVARIANT_VIOLATED` tag.
4. Show the minimal diff, the passing demonstrating test, the passing companion test (before and after) and the full suite.
5. Show a vandalizing patch being rejected by the guards.
6. Approve the exact patch hash; apply to a branch.
7. Run the gate on the patched fixture: it passes.
8. Show the metrics table with per-class false positives and denominators, and say what was missed.

If anything fails live, show the real failure and the recorded run; never swap in a fake.

---

## 16. Submission checklist

- [ ] Official rules read; Python-agent, pre-existing-code, AI-tool and Meta-model requirements confirmed or asked about
- [ ] `docs/verified_facts.md` complete (model IDs, API shapes, sandbox command)
- [ ] Demo uses real API calls and real test output; no mocks in the demo or evaluation path
- [ ] Matcher unit tests use real captured outputs
- [ ] Guards reject a vandalizing patch
- [ ] Approval bound to patch hash; no auto-merge
- [ ] Metrics from script, 3 runs, per-class counts and denominators, misses disclosed
- [ ] README quickstart works on a clean machine
- [ ] `CREDITS.md` and disclosures complete
- [ ] No secrets in the repo or logs
- [ ] Submitted before 6 PM IST on 4 Nov