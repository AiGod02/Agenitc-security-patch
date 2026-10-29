"""Post-remediation architecture advisory separating observed facts from recommendations (Slice S14)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from contracts import FinalPatchStatus, LLMCaps, LLMClient, ModelRole

ADVISORY_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "observed_facts": {
            "type": "array",
            "items": {"type": "string"},
        },
        "recommendations": {
            "type": "array",
            "items": {"type": "string"},
        },
    },
    "required": ["observed_facts", "recommendations"],
    "additionalProperties": False,
}

ADVISORY_SYSTEM_PROMPT = """You produce a concise post-fix security architecture advisory ONLY for an already-verified and patched finding.
Strictly separate:
1. `observed_facts`: ONLY concrete empirical facts directly present in the provided finding JSON and unified diff (file, route, invariant tag, verified exit codes, and exact code change). Never speculate here.
2. `recommendations`: Defense-in-depth engineering recommendations (e.g., centralized authorization helpers, shared path-containment utility, CI security gates) clearly framed as optional future improvements.
"""


def generate_architecture_advisory(bundle_dir: Path, llm: LLMClient) -> dict[str, Any]:
    """Generate advisory only after a verified PASS patch; writes advisory.json and advisory.md."""
    finding_path = bundle_dir / "finding.json"
    if not finding_path.exists():
        raise ValueError(f"Missing finding.json in {bundle_dir}")

    finding_data = json.loads(finding_path.read_text(encoding="utf-8"))
    patch_res = finding_data.get("patch_result") or {}
    if patch_res.get("final_status") != FinalPatchStatus.PASS.value:
        raise ValueError("Architecture advisory requires a verified PASS patch first")

    res = llm.call(
        role=ModelRole.FAST,
        system=ADVISORY_SYSTEM_PROMPT,
        user=json.dumps(finding_data, indent=2),
        schema=ADVISORY_SCHEMA,
        caps=LLMCaps(reasoning_effort="low", timeout_s=60.0),
    )
    parsed = res.parsed or {"observed_facts": [], "recommendations": []}
    (bundle_dir / "advisory.json").write_text(json.dumps(parsed, indent=2), encoding="utf-8")

    md_lines = [
        f"# Architecture Advisory: {finding_data['candidate']['id']}",
        "",
        "## Observed Empirical Facts",
        *[f"- {fact}" for fact in parsed["observed_facts"]],
        "",
        "## Defense-in-Depth Recommendations",
        *[f"- {rec}" for rec in parsed["recommendations"]],
    ]
    (bundle_dir / "advisory.md").write_text("\n".join(md_lines) + "\n", encoding="utf-8")
    return parsed

