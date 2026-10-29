# Credits and Attribution

## Ideas Adopted (No Code Copied)

Per Section 13 of `implmentation.md`, no source code or prompt text was copied from third-party repositories. Only high-level architectural ideas were adopted and implemented from scratch:

1. **digital-duck/cve-coder** (`https://github.com/digital-duck/cve-coder`)
   - Idea adopted: stage-separated run artifacts and the core verification principle that a security regression test must fail on the vulnerable baseline and pass on the patched checkout, with explicit status outcomes (`PASS`, `FAIL`, `INCONCLUSIVE`).
2. **Samarth1980/patchbot** (`https://github.com/Samarth1980/patchbot`)
   - Idea adopted: disposable workspace copy + isolated container lifecycle, gating strictly on real process exit codes rather than model claims, normalized failure-signature loop breaking per run, and latency/token telemetry. (Licence not present in upstream repo; zero code copied.)
3. **OpenHands/vulnerability-fixer** (`https://github.com/OpenHands/vulnerability-fixer`, MIT)
   - Idea adopted: human-in-the-loop review flow (inspect finding, review diff and verification evidence, approve or reject).
4. **PrismorSec/patchbot** (`https://github.com/PrismorSec/patchbot`)
   - Idea adopted: structured evidence reports with explicit failure reasons.

## AI-Assisted Development Disclosure

This repository was developed with AI coding assistance (Google Antigravity) guided by `implmentation.md`, with all claims verified against real Meta Model API calls and real sandboxed/local Jest executions.
