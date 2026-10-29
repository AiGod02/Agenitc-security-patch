"""Comprehensive 9-section evidence-only security advisory and run aggregate report generator (Part 4)."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from agent.plan.planner import _verify_single_citation
from agent.tools.dispatcher import PathContainmentError, resolve_workspace_path
from agent.workflow.state import atomic_write_json, atomic_write_text, read_stage_artifact
from contracts import FinalPatchStatus, LLMCaps, LLMClient, ModelRole
from eval.report import format_evaluation_markdown, score_single_run


class AdvisoryValidationError(ValueError):
    """Raised when an advisory cannot be generated or fails mechanical file:line/snippet verification."""


COMPREHENSIVE_ADVISORY_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "summary_prose": {"type": "string"},
        "minimality_explanation": {"type": "string"},
        "architectural_observations": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "observation": {"type": "string"},
                    "file": {"type": "string"},
                    "line": {"type": "integer"},
                    "snippet": {"type": "string"},
                    "artifact_ref": {"type": "string"},
                },
                "required": ["observation", "file", "line", "snippet", "artifact_ref"],
                "additionalProperties": False,
            },
        },
        "recommended_follow_ups": {
            "type": "array",
            "items": {"type": "string"},
        },
        "residual_risks_and_untested": {
            "type": "array",
            "items": {"type": "string"},
        },
    },
    "required": [
        "summary_prose",
        "minimality_explanation",
        "architectural_observations",
        "recommended_follow_ups",
        "residual_risks_and_untested",
    ],
    "additionalProperties": False,
}

COMPREHENSIVE_ADVISORY_SYSTEM_PROMPT = """You are a senior application security engineer writing structured sections for an evidence-backed post-patch advisory (`advisory.md`).
STRICT EVIDENCE & HONESTY RULES:
1. Rely ONLY on the saved evidence artifacts provided in the prompt (finding, baseline failure log, patch_plan, unified diff, check results, guard results, held-out variant test results, and possible variants).
2. NEVER claim a fix is universally safe, 100% secure, or bug-free beyond what the executed checks empirically showed.
3. Do NOT embed raw `file.js:123` line citations inside free-form prose strings (`summary_prose`, `minimality_explanation`, `recommended_follow_ups`, `residual_risks_and_untested`) unless they match exact citations in `patch_plan.root_cause_evidence`.
4. For `architectural_observations`: include ONLY observations directly supported by the code/artifacts. Each item MUST either:
   - copy an exact `{file, line, snippet}` from `patch_plan.root_cause_evidence` (with `artifact_ref` set to `""`), OR
   - reference a concrete artifact path such as `04_patches/<cid>/patch_plan.json` or `05_checks/<cid>.json` in `artifact_ref` (with `file=""`, `line=0`, `snippet=""`).
5. Keep `recommended_follow_ups` clearly framed as optional future engineering improvements (separate from observed facts).
6. In `residual_risks_and_untested`, state concrete limitations of what the test suite did NOT exercise (e.g., concurrency, multi-step state mutations, unpatched sibling routes, production secret rotation).
"""

_FORBIDDEN_OVERCLAIMS = (
    "100% secure",
    "guaranteed vulnerability-free",
    "completely immune to all",
    "proves universal security",
    "proves the application has no bugs",
    "completely safe against all attacks",
)

_FILE_LINE_RE = re.compile(
    r"(?<!://)`?([A-Za-z0-9_./-]+\.(?:js|cjs|mjs|ts|json|sql|md)):(\d+)(?:-(\d+))?`?"
)
_VERBATIM_SNIPPET_RE = re.compile(
    r"`([A-Za-z0-9_./-]+\.(?:js|cjs|mjs|ts|json|sql|md)):(\d+)(?:-(\d+))?`\s*\(verbatim snippet:\s*`([^`]+)`\)"
)
_ARTIFACT_REF_RE = re.compile(r"\(artifact:\s*`([^`]+)`\)")


def _strip_fenced_code_blocks(markdown_text: str) -> str:
    out_lines: list[str] = []
    in_fence = False
    for line in markdown_text.splitlines():
        if line.strip().startswith("```"):
            in_fence = not in_fence
            continue
        if not in_fence:
            out_lines.append(line)
    return "\n".join(out_lines)


def _resolve_existing_file(rel_path: str, workspace: Path, run_dir: Path | None) -> Path | None:
    try:
        wp = resolve_workspace_path(workspace, rel_path)
        if wp.exists() and wp.is_file():
            return wp
    except PathContainmentError:
        pass
    if run_dir is not None:
        try:
            rp = resolve_workspace_path(run_dir, rel_path)
            if rp.exists() and rp.is_file():
                return rp
        except PathContainmentError:
            pass
    return None


def validate_advisory_markdown_references(
    markdown_text: str,
    workspace: Path,
    run_dir: Path | None = None,
) -> tuple[bool, list[str]]:
    """Mechanically check every file:line, verbatim snippet, artifact reference, and safety-claim boundary in advisory.md (Part 4b)."""
    errors: list[str] = []
    prose_only = _strip_fenced_code_blocks(markdown_text)

    lowered = prose_only.lower()
    for phrase in _FORBIDDEN_OVERCLAIMS:
        if phrase in lowered:
            errors.append(f"Forbidden overclaiming phrase in advisory: {phrase!r}")

    # 1. Check every file:line or file:start-end citation in non-fenced text
    for m in _FILE_LINE_RE.finditer(prose_only):
        rel_path = m.group(1)
        start_line = int(m.group(2))
        end_line = int(m.group(3)) if m.group(3) else start_line

        resolved = _resolve_existing_file(rel_path, workspace, run_dir)
        if resolved is None:
            errors.append(f"Referenced file does not exist: {rel_path}:{start_line}")
            continue

        lines = resolved.read_text(encoding="utf-8", errors="replace").splitlines()
        total = len(lines)
        if start_line < 1 or start_line > total:
            errors.append(f"Referenced line {start_line} out of range for {rel_path} (1..{total})")
        elif end_line < start_line or end_line > total:
            errors.append(f"Referenced end line {end_line} out of range for {rel_path} ({start_line}..{total})")

    # 2. Check every `(verbatim snippet: `...`)` attached to a `file:line` citation
    for m in _VERBATIM_SNIPPET_RE.finditer(prose_only):
        rel_path = m.group(1)
        line_no = int(m.group(2))
        snip = m.group(4)
        ok, err = _verify_single_citation(workspace, rel_path, line_no, snip)
        if not ok:
            errors.append(f"Verbatim snippet check failed at {rel_path}:{line_no}: {err}")

    # 3. Check every `(artifact: `...`)` reference against run_dir when provided
    if run_dir is not None:
        for m in _ARTIFACT_REF_RE.finditer(prose_only):
            art_rel = m.group(1)
            try:
                art_fp = resolve_workspace_path(run_dir, art_rel)
            except PathContainmentError as exc:
                errors.append(f"Invalid artifact path '{art_rel}': {exc}")
                continue
            if not art_fp.exists():
                errors.append(f"Referenced artifact does not exist in run_dir: {art_rel}")

    return len(errors) == 0, errors


def _read_single_line_snippet(workspace: Path, rel_path: str, line_no: int) -> str:
    fp = _resolve_existing_file(rel_path, workspace, None)
    if fp is None:
        return ""
    lines = fp.read_text(encoding="utf-8", errors="replace").splitlines()
    if 1 <= line_no <= len(lines):
        return lines[line_no - 1].strip().replace("`", "'")
    return ""


def _scrub_unverified_inline_file_lines(text: str, workspace: Path, run_dir: Path | None) -> str:
    """Remove any accidental inline file:line token in free-form LLM prose if its line number fails verification."""

    def _replace(match: re.Match[str]) -> str:
        rel_path = match.group(1)
        start_line = int(match.group(2))
        end_line = int(match.group(3)) if match.group(3) else start_line
        resolved = _resolve_existing_file(rel_path, workspace, run_dir)
        if resolved is None:
            return f"`{rel_path}`"
        total = len(resolved.read_text(encoding="utf-8", errors="replace").splitlines())
        if start_line < 1 or start_line > total or end_line < start_line or end_line > total:
            return f"`{rel_path}`"
        return match.group(0)

    cleaned = _FILE_LINE_RE.sub(_replace, text)
    for phrase in _FORBIDDEN_OVERCLAIMS:
        cleaned = re.sub(re.escape(phrase), "verified within tested scope", cleaned, flags=re.IGNORECASE)
    return cleaned


def generate_comprehensive_advisory(
    run_dir: Path,
    candidate_id: str,
    workspace: Path,
    llm: LLMClient,
) -> Path:
    """Generate 06_evidence/<cid>/advisory.md strictly from saved evidence artifacts after CHECKS_PASSED (Part 4a/4b/4d)."""
    check_path = run_dir / "05_checks" / f"{candidate_id}.json"
    if not check_path.exists():
        raise AdvisoryValidationError(f"Missing check artifact {check_path}; refusing to generate advisory")

    check_env = read_stage_artifact(check_path)
    if check_env.status != FinalPatchStatus.PASS.value:
        raise AdvisoryValidationError(
            f"Candidate {candidate_id} check status is {check_env.status} (must be PASS); refusing to generate advisory"
        )

    patch_res = dict(check_env.payload.get("patch_result") or {})
    if patch_res.get("final_status") != FinalPatchStatus.PASS.value:
        raise AdvisoryValidationError(f"Candidate {candidate_id} patch_result.final_status != PASS")
    extra_checks = dict(check_env.payload.get("extra_checks") or {})

    ev_dir = run_dir / "06_evidence" / candidate_id
    finding_path = ev_dir / "finding.json"
    guards_path = ev_dir / "guards.json"
    baseline_log_path = ev_dir / "baseline_failure_jest.json"
    plan_path = run_dir / "04_patches" / candidate_id / "patch_plan.json"
    diff_path = run_dir / "04_patches" / candidate_id / "patch.diff"
    ver_path = run_dir / "03_verification" / f"{candidate_id}.json"

    for req_file in (finding_path, guards_path, plan_path, diff_path, ver_path):
        if not req_file.exists():
            raise AdvisoryValidationError(f"Missing required evidence artifact: {req_file}")

    finding_doc = json.loads(finding_path.read_text(encoding="utf-8"))
    guards_doc = json.loads(guards_path.read_text(encoding="utf-8"))
    plan_env = read_stage_artifact(plan_path)
    plan_doc = dict(plan_env.payload)
    ver_env = read_stage_artifact(ver_path)
    ver_doc = dict((ver_env.payload or {}).get("verification") or {})
    diff_text = diff_path.read_text(encoding="utf-8")

    variant_meta_path = run_dir / "04_patches" / candidate_id / "variant_test_results.json"
    variant_meta: dict[str, Any] = {}
    if variant_meta_path.exists():
        try:
            variant_meta = json.loads(variant_meta_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            variant_meta = {}

    possible_variants_path = run_dir / "04_patches" / candidate_id / "possible_variants.json"
    possible_variants: list[dict[str, Any]] = list(extra_checks.get("possible_variants") or [])
    if not possible_variants and possible_variants_path.exists():
        try:
            possible_variants = json.loads(possible_variants_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            possible_variants = []

    cand = finding_doc["candidate"]
    cid = str(cand["id"])

    # Mechanically verify core citations from patch_plan.root_cause_evidence BEFORE calling LLM / rendering
    verified_plan_citations: list[dict[str, Any]] = []
    for raw_cit in plan_doc.get("root_cause_evidence") or []:
        c_file = str(raw_cit.get("file") or "")
        c_line = int(raw_cit.get("line") or 0)
        c_snip = str(raw_cit.get("snippet") or "").strip().replace("`", "'")
        ok, err = _verify_single_citation(workspace, c_file, c_line, c_snip)
        if not ok:
            raise AdvisoryValidationError(f"Core plan citation failed mechanical validation: {err}")
        verified_plan_citations.append({"file": c_file, "line": c_line, "snippet": c_snip})

    # Verify candidate file:start_line-end_line exists on disk
    cand_snip = _read_single_line_snippet(workspace, str(cand["file"]), int(cand["start_line"]))
    if not cand_snip:
        raise AdvisoryValidationError(
            f"Candidate source location {cand['file']}:{cand['start_line']} could not be verified on workspace"
        )

    evidence_packet = {
        "candidate": cand,
        "baseline_failure_summary": finding_doc.get("baseline_failure_summary"),
        "verification": ver_doc,
        "patch_plan": plan_doc,
        "patch_sha256": patch_res.get("patch_sha256"),
        "unified_diff": diff_text,
        "guards": guards_doc,
        "extra_checks": extra_checks,
        "variant_test_results": variant_meta,
        "possible_variants": possible_variants,
    }

    llm_res = llm.call(
        role=ModelRole.FAST,
        system=COMPREHENSIVE_ADVISORY_SYSTEM_PROMPT,
        user=json.dumps(evidence_packet, indent=2),
        schema=COMPREHENSIVE_ADVISORY_SCHEMA,
        caps=LLMCaps(reasoning_effort="low", timeout_s=90.0),
    )
    parsed = llm_res.parsed or {}

    summary_prose = _scrub_unverified_inline_file_lines(
        str(parsed.get("summary_prose") or "").strip(), workspace, run_dir
    )
    if not summary_prose:
        summary_prose = (
            f"Verified `{cand['vulnerability_class']}` finding `{cid}` on `{cand['route']}` "
            f"(invariant `{cand['invariant_id']}`) was remediated and passed the demonstrating reproducer, "
            f"companion regression test, held-out variant test, full test suite, and mechanical guards."
        )

    minimality_prose = _scrub_unverified_inline_file_lines(
        str(parsed.get("minimality_explanation") or "").strip(), workspace, run_dir
    )
    if not minimality_prose:
        minimality_prose = str(plan_doc.get("chosen_rationale") or "Minimal localized fix enforcing the violated invariant.")

    # Filter architectural_observations mechanically (4b: failed reference removes the claim)
    valid_arch_bullets: list[str] = []
    for obs_item in parsed.get("architectural_observations") or []:
        obs_text = _scrub_unverified_inline_file_lines(
            str(obs_item.get("observation") or "").strip(), workspace, run_dir
        )
        if not obs_text:
            continue
        o_file = str(obs_item.get("file") or "").strip()
        o_line = int(obs_item.get("line") or 0)
        o_snip = str(obs_item.get("snippet") or "").strip().replace("`", "'")
        o_art = str(obs_item.get("artifact_ref") or "").strip()

        if o_file and o_line > 0 and o_snip:
            ok, _ = _verify_single_citation(workspace, o_file, o_line, o_snip)
            if ok:
                valid_arch_bullets.append(
                    f"- {obs_text} — `{o_file}:{o_line}` (verbatim snippet: `{o_snip}`)"
                )
                continue
        if o_art:
            try:
                art_fp = resolve_workspace_path(run_dir, o_art)
                if art_fp.exists():
                    valid_arch_bullets.append(f"- {obs_text} (artifact: `{o_art}`)")
            except PathContainmentError:
                pass

    if not valid_arch_bullets:
        primary_cit = verified_plan_citations[0] if verified_plan_citations else {
            "file": cand["file"],
            "line": cand["start_line"],
            "snippet": cand_snip,
        }
        valid_arch_bullets.append(
            f"- Fix placement in `{plan_doc.get('fix_layer', 'handler')}` layer: "
            f"{_scrub_unverified_inline_file_lines(str(plan_doc.get('fix_layer_justification') or 'Localized enforcement at route boundary.'), workspace, run_dir)} "
            f"— `{primary_cit['file']}:{primary_cit['line']}` (verbatim snippet: `{primary_cit['snippet']}`)"
        )

    # Build Section 2 Observed Facts with strict file:line or artifact citations
    observed_fact_lines = [
        f"- Route `{cand['route']}` in `{cand['file']}:{cand['start_line']}-{cand['end_line']}` failed baseline security invariant `{cand['invariant_id']}` with `{finding_doc.get('baseline_failure_summary')}` (artifact: `03_verification/{cid}.json`).",
        f"- Baseline source at `{cand['file']}:{cand['start_line']}` (verbatim snippet: `{cand_snip}`) executed before remediation.",
    ]
    if baseline_log_path.exists():
        observed_fact_lines.append(
            f"- Deterministic baseline Jest run exited with code `{ver_doc.get('baseline_exit_code')}` and rerun exit code `{ver_doc.get('rerun_exit_code')}` (artifact: `06_evidence/{cid}/baseline_failure_jest.json`)."
        )
    observed_fact_lines.extend(
        [
            f"- Approved patch SHA-256 `{patch_res.get('patch_sha256')}` modified `{guards_doc.get('changed_lines')}` line(s) within expected scope `{plan_doc.get('expected_scope_files')}` (artifact: `04_patches/{cid}/patch.diff`).",
            f"- Post-patch checks recorded `patched_security_exit_code={patch_res.get('patched_security_exit_code')}`, `companion_after_exit_code={patch_res.get('companion_after_exit_code')}`, `full_suite_exit_code={patch_res.get('full_suite_exit_code')}`, and `guards_passed={patch_res.get('guards_passed')}` (artifact: `05_checks/{cid}.json`).",
        ]
    )

    # Build Section 3 Root Cause
    root_cause_lines = [
        f"- **Violated Invariant**: `{plan_doc.get('violated_invariant', cand['invariant_id'])}` (artifact: `04_patches/{cid}/patch_plan.json`)",
        f"- **Root Cause**: {_scrub_unverified_inline_file_lines(str(plan_doc.get('root_cause') or cand['reason']), workspace, run_dir)}",
    ]
    ctx_items = [str(x) for x in (plan_doc.get("context_read") or []) if str(x).strip()]
    if ctx_items:
        root_cause_lines.append(
            f"- **Context Examined**: {_scrub_unverified_inline_file_lines('; '.join(ctx_items), workspace, run_dir)} (artifact: `04_patches/{cid}/patch_plan.json`)"
        )
    for cit in verified_plan_citations:
        root_cause_lines.append(
            f"- **Code Evidence**: `{cit['file']}:{cit['line']}` (verbatim snippet: `{cit['snippet']}`)"
        )

    # Build Section 4 What Changed and Why It Is Minimal
    options_lines: list[str] = []
    chosen_id = str(plan_doc.get("chosen_option_id") or "")
    for opt in plan_doc.get("candidate_fixes") or []:
        oid = str(opt.get("option_id") or "")
        marker = "SELECTED" if oid == chosen_id else "ALTERNATIVE"
        options_lines.append(
            f"  - `[{marker}]` **{oid}** (`{opt.get('layer')}`): "
            f"{_scrub_unverified_inline_file_lines(str(opt.get('summary') or ''), workspace, run_dir)} "
            f"({_scrub_unverified_inline_file_lines(str(opt.get('pros_and_cons') or ''), workspace, run_dir)})"
        )

    what_changed_lines = [
        f"- **Chosen Fix Option (`{chosen_id}` in `{plan_doc.get('fix_layer')}` layer)**: {minimality_prose} (artifact: `04_patches/{cid}/patch_plan.json`)",
        f"- **Helper / Pattern Reuse**: {_scrub_unverified_inline_file_lines(str(plan_doc.get('helper_reuse_note') or 'Reused existing Express route conventions.'), workspace, run_dir)}",
        f"- **Diff Footprint**: `{guards_doc.get('changed_lines')}` changed line(s) across `{plan_doc.get('expected_scope_files')}`, SHA-256 `{patch_res.get('patch_sha256')}` (artifact: `04_patches/{cid}/patch.diff`).",
        "- **Evaluated Options**:",
        *options_lines,
        "",
        "```diff",
        diff_text.rstrip("\n"),
        "```",
    ]

    # Build Section 5 Verification Evidence
    var_base_code = variant_meta.get("baseline_exit_code", "N/A")
    var_base_tag = variant_meta.get("baseline_matched_tag", False)
    var_post_code = extra_checks.get("variant_post_patch_exit_code", "N/A")
    var_passed = extra_checks.get("variant_passed_after_patch", False)
    ver_evidence_lines = [
        f"- **Baseline Failure (Demonstrating Test)**: `exit_code={ver_doc.get('baseline_exit_code')}`, `rerun_exit_code={ver_doc.get('rerun_exit_code')}`, `match_reason={ver_doc.get('match_reason')}`, `tagged_assertion_matched={ver_doc.get('tagged_assertion_matched')}` (artifact: `03_verification/{cid}.json`).",
        f"- **Patched Result (Demonstrating Test)**: `exit_code={patch_res.get('patched_security_exit_code')}` (artifact: `05_checks/{cid}.json`).",
        f"- **Companion Positive Test (Before & After)**: `before_exit_code={ver_doc.get('companion_baseline_exit_code')}`, `after_exit_code={patch_res.get('companion_after_exit_code')}` (artifact: `05_checks/{cid}.json`).",
        f"- **Held-Out Variant Security Test**: `baseline_exit_code={var_base_code}`, `baseline_matched_tag={var_base_tag}`, `post_patch_exit_code={var_post_code}`, `passed_after_patch={var_passed}` (artifact: `05_checks/{cid}.json`).",
        f"- **Full Regression Suite**: `exit_code={patch_res.get('full_suite_exit_code')}`, `test_count_before={guards_doc.get('test_count_before')}`, `test_count_after={guards_doc.get('test_count_after')}`, `skipped_tests_after={guards_doc.get('skipped_tests_after')}` (artifact: `06_evidence/{cid}/guards.json`).",
        f"- **Mechanical & Anti-Overfitting Guards**: `guards_passed={guards_doc.get('passed')}`, `test_files_untouched={guards_doc.get('test_files_untouched')}`, `routes_identical={guards_doc.get('routes_identical')}`, `exports_intact={guards_doc.get('exports_intact')}`, `forbidden_files_untouched={guards_doc.get('forbidden_files_untouched')}`, `literal_check_passed={extra_checks.get('literal_check_passed', True)}`, `scope_check_passed={extra_checks.get('scope_check_passed', True)}`, `flagged_for_human_review={guards_doc.get('flagged_for_human_review', False)}` (artifact: `06_evidence/{cid}/guards.json`).",
    ]

    # Build Section 7 Possible Variants (from 3d — report-only, never called vulnerable, unpatched)
    possible_variant_lines: list[str] = []
    for pv in possible_variants:
        pv_file = str(pv.get("file") or "")
        pv_line = int(pv.get("line") or 0)
        pv_snip = _read_single_line_snippet(workspace, pv_file, pv_line)
        if not pv_snip:
            # Drop unverified sibling reference per 4b
            continue
        possible_variant_lines.append(
            f"- **[possible variant — unverified, unpatched]** `{pv.get('route')}` at `{pv_file}:{pv_line}` "
            f"(verbatim snippet: `{pv_snip}`) — {_scrub_unverified_inline_file_lines(str(pv.get('pattern_reason') or ''), workspace, run_dir)}. "
            f"Not confirmed vulnerable and not modified by this patch; must be evaluated as a separate candidate with its own failing reproducer test."
        )
    if not possible_variant_lines:
        possible_variant_lines.append(
            "- No unpatched sibling routes matching this structural sink/ownership pattern were flagged in `01_recon.json` (artifact: `01_recon.json`)."
        )

    # Build Section 8 Recommended Follow-Ups (clearly labeled AI recommendations, separate from facts)
    follow_ups_raw = [
        _scrub_unverified_inline_file_lines(str(item).strip(), workspace, run_dir)
        for item in (parsed.get("recommended_follow_ups") or [])
        if str(item).strip()
    ]
    if not follow_ups_raw:
        follow_ups_raw = [
            "Consider centralizing resource-level authorization/validation checks into shared middleware or data-access helpers for sibling routes.",
            "Keep the generated demonstrating and held-out variant tests in CI regression gates after human review and merge.",
        ]
    follow_up_lines = [
        "> **AI Recommendations (Separate from Observed Empirical Facts):** The items below are optional defense-in-depth engineering suggestions generated by the AI model, not verified findings.",
        "",
        *[f"- **[AI Recommendation]** {item}" for item in follow_ups_raw],
    ]

    # Build Section 9 Residual Risks and What Was Not Tested
    risks_raw = [
        _scrub_unverified_inline_file_lines(str(item).strip(), workspace, run_dir)
        for item in (parsed.get("residual_risks_and_untested") or [])
        if str(item).strip()
    ]
    plan_risk = _scrub_unverified_inline_file_lines(str(plan_doc.get("behavioral_risks") or "").strip(), workspace, run_dir)
    if plan_risk:
        risks_raw.insert(
            0,
            f"Behavioral risk noted in plan (protected by `{plan_doc.get('protecting_companion_test')}`): {plan_risk}",
        )
    risk_lines = [
        "- **Scope Boundary of Proof**: These checks prove only that the demonstrating security test, held-out variant test, companion positive test, and existing Jest regression suite passed for the inputs exercised in the isolated sandbox. They do **not** prove the route or application is free of other vulnerabilities.",
        *[f"- {r}" for r in risks_raw],
    ]

    md_sections = [
        f"# Security Patch Advisory: `{cid}` (`{cand['vulnerability_class']}` on `{cand['route']}`)",
        "",
        "## 1. Summary",
        summary_prose,
        "",
        "## 2. Observed Facts",
        *observed_fact_lines,
        "",
        "## 3. Root Cause",
        *root_cause_lines,
        "",
        "## 4. What Changed and Why It Is Minimal",
        *what_changed_lines,
        "",
        "## 5. Verification Evidence",
        *ver_evidence_lines,
        "",
        "## 6. Architectural Observations",
        *valid_arch_bullets,
        "",
        "## 7. Possible Variants",
        *possible_variant_lines,
        "",
        "## 8. Recommended Follow-Ups",
        *follow_up_lines,
        "",
        "## 9. Residual Risks and What Was Not Tested",
        *risk_lines,
        "",
    ]
    final_md = "\n".join(md_sections)

    ok_refs, ref_errors = validate_advisory_markdown_references(final_md, workspace=workspace, run_dir=run_dir)
    if not ok_refs:
        raise AdvisoryValidationError(
            f"Generated advisory failed mechanical reference check: {'; '.join(ref_errors)}"
        )

    out_md_path = ev_dir / "advisory.md"
    atomic_write_text(out_md_path, final_md)
    atomic_write_json(
        ev_dir / "advisory_metadata.json",
        {
            "candidate_id": cid,
            "patch_sha256": patch_res.get("patch_sha256"),
            "reference_validation_passed": True,
            "possible_variants_count": len(possible_variants),
        },
    )
    return out_md_path


def generate_run_aggregate_report(run_dir: Path, ground_truth_path: Path) -> Path:
    """Produce runs/<run_id>/report.md aggregating findings and the deterministic metrics table from eval/report.py (Part 4c)."""
    scored = score_single_run(run_dir, ground_truth_path)
    eval_md = format_evaluation_markdown([scored]).rstrip("\n")

    state_doc: dict[str, Any] = {}
    state_file = run_dir / "state.json"
    if state_file.exists():
        state_doc = json.loads(state_file.read_text(encoding="utf-8"))

    cand_rows: list[str] = [
        "",
        "## Staged Pipeline Candidate Summary",
        "",
        "| Candidate | Class | Route | State | Check Status | Patch SHA-256 (prefix) | Advisory |",
        "|---|---|---|---|---|---|---|",
    ]

    candidates_list: list[dict[str, Any]] = []
    if (run_dir / "02_candidates.json").exists():
        c_env = read_stage_artifact(run_dir / "02_candidates.json")
        candidates_list = list(c_env.payload.get("accepted") or [])
    elif (run_dir / "candidates.json").exists():
        candidates_list = list(json.loads((run_dir / "candidates.json").read_text(encoding="utf-8")).get("accepted") or [])

    cand_states = state_doc.get("candidates") or {}
    for c in candidates_list:
        cid = str(c["id"])
        cstate = str((cand_states.get(cid) or {}).get("state") or "UNKNOWN")
        chk_status = "N/A"
        sha_prefix = "N/A"
        chk_file = run_dir / "05_checks" / f"{cid}.json"
        if chk_file.exists():
            chk_env = read_stage_artifact(chk_file)
            chk_status = chk_env.status
            full_sha = str((chk_env.payload.get("patch_result") or {}).get("patch_sha256") or "")
            if full_sha and set(full_sha) != {"0"}:
                sha_prefix = f"`{full_sha[:12]}`"
        adv_file = run_dir / "06_evidence" / cid / "advisory.md"
        adv_cell = f"`06_evidence/{cid}/advisory.md`" if adv_file.exists() else "None"
        cand_rows.append(
            f"| `{cid}` | `{c['vulnerability_class']}` | `{c['route']}` | `{cstate}` | `{chk_status}` | {sha_prefix} | {adv_cell} |"
        )

    full_report = eval_md + "\n" + "\n".join(cand_rows) + "\n"
    out_path = run_dir / "report.md"
    atomic_write_text(out_path, full_report)
    return out_path
