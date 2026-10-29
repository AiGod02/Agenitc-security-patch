# Frozen Data Contracts (`contracts/`)

This package defines the shared Pydantic models, enums, exit codes, and runtime protocols used across all slices of the Verified Security Patch Agent (per Sections 5, 6, 8, 9, and 12A of `implmentation.md`).

## Key Invariants Enforced at Schema Boundary
- **`Candidate`**: Enforces valid `VulnerabilityClass` (`IDOR`, `PATH_TRAVERSAL`, `INJECTION`, `MISSING_AUTH`, `HARDCODED_SECRET`, `PERMISSIVE_CORS`), `end_line >= start_line >= 1`, `0.0 <= confidence <= 1.0`, and alphanumeric/dash/underscore `invariant_id`.
- **`MatchResult`**: Enforces `matched=True` iff `reason == MatchReason.TAG_MATCHED`.
- **`VerifiedFinding`**: Rejects any finding whose `verification.status != VERIFIED_REPRODUCER`, `tagged_assertion_matched != True`, or `companion_baseline_exit_code != 0`.
- **`PatchResult` / `ApprovalRecord`**: Binds patches and human approvals to exact 64-hex-character SHA-256 hashes.
- **`CLIExitCode`**: `0` (`PASS`), `1` (`VULNERABLE_OR_UNVERIFIED`), `2` (`INCONCLUSIVE_OR_ERROR`).
