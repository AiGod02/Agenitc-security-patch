# Threat Model (`docs/threat_model.md`)

## 1. Assets Protected
1. **Host system & credentials**: `MODEL_API_KEY`, host filesystem outside the disposable workspace, and host network/services.
2. **Target repository integrity**: Working branches of the owned repository must never be modified automatically or without human approval bound to an exact patch SHA-256.
3. **Verification integrity**: Tests, route inventory, and anti-vandalism guards must prevent false claims of vulnerability remediation or silent feature deletion.

## 2. Trust Boundaries & Untrusted Inputs
- **Target source code is untrusted data**: Source files, comments, and test outputs may contain prompt-injection instructions aimed at subverting the LLM (e.g., instructing the model to ignore vulnerabilities, exfiltrate secrets, or emit destructive patches). Every model prompt explicitly frames source files as untrusted data, and all model outputs are validated through strict Pydantic schemas and deterministic guards.
- **Model outputs are untrusted**:
  - Candidate file paths, line ranges, and routes are cross-checked against real workspace files and deterministic route inventory.
  - Tool invocations pass through the restricted `Dispatcher` (blocking `..`, absolute paths, symlink escapes, shell interpolation, and non-allowlisted commands).
  - Generated tests run inside an isolated Docker container (`--network none`, `--read-only` rootfs with `tmpfs`, `--cap-drop ALL`, `--pids-limit`, `--memory`, `--cpus`, non-root user, workspace mounted as the sole writable directory, hard wall-clock timeout).
  - Patches are never judged by an LLM: acceptance requires deterministic Jest JSON verification (`SECURITY_INVARIANT_VIOLATED:<id>` failing before and passing after), passing companion positive test before and after, passing full test suite, and passing mechanical anti-vandalism guards (test file byte-hash lock, route inventory preservation, export preservation, forbidden-file lock, and changed-line cap).

## 3. Out-of-Scope Threats
- Scanning third-party or unowned external systems (prohibited).
- Dependency/CVE advisories (`npm audit` / lockfile upgrades).
- Kernel/hypervisor zero-days escaping Docker/WSL2 container isolation.
