"""Deterministic evaluation scorer and Markdown report generator over real run artifacts (Slice S12, Section 11)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from contracts import FinalPatchStatus, VerificationStatus, VulnerabilityClass


def _load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def score_single_run(run_dir: Path, ground_truth_path: Path) -> dict[str, Any]:
    """Compute per-class and overall metrics strictly from saved run_dir artifacts and ground_truth.json."""
    gt = _load_json(ground_truth_path)
    flaws: list[dict[str, Any]] = gt["flaws"]
    clean_routes: set[str] = {c["route"] for c in gt.get("clean_routes", [])}

    cand_doc = _load_json(run_dir / "candidates.json")
    candidates: list[dict[str, Any]] = cand_doc.get("accepted", [])
    verifications: list[dict[str, Any]] = _load_json(run_dir / "verifications.json")
    patches: list[dict[str, Any]] = _load_json(run_dir / "patches.json")
    summary_doc = _load_json(run_dir / "run_summary.json")

    ver_by_id = {v["candidate_id"]: v for v in verifications}
    patch_by_id = {p["candidate_id"]: p for p in patches}

    # Index ground-truth flaws by (class, route)
    gt_by_key: dict[tuple[str, str], dict[str, Any]] = {
        (f["vulnerability_class"], f["route"]): f for f in flaws
    }
    gt_routes_any_class: set[str] = {f["route"] for f in flaws}

    classes = [c.value for c in VulnerabilityClass]
    per_class: dict[str, dict[str, Any]] = {}
    for cls in classes:
        planted_for_cls = [f for f in flaws if f["vulnerability_class"] == cls]
        per_class[cls] = {
            "planted": len(planted_for_cls),
            "candidates": 0,
            "verified_reproducers": 0,
            "true_positives": 0,
            "missed_flaw_ids": [],
            "not_reproduced_false_positive": 0,
            "not_reproduced_weak_test": 0,
            "inconclusive": 0,
            "verified_not_in_ground_truth": [],
            "patches_passed": 0,
            "guard_rejections": 0,
        }

    matched_gt_ids: set[str] = set()
    verified_outside_gt: list[dict[str, Any]] = []

    for cand in candidates:
        cid = cand["id"]
        cls = cand["vulnerability_class"]
        route = cand["route"]
        ver = ver_by_id.get(cid)
        patch = patch_by_id.get(cid)
        bucket = per_class[cls]
        bucket["candidates"] += 1

        gt_match = gt_by_key.get((cls, route))
        status = ver["status"] if ver else VerificationStatus.INCONCLUSIVE.value

        if status == VerificationStatus.VERIFIED_REPRODUCER.value:
            bucket["verified_reproducers"] += 1
            if gt_match is not None:
                bucket["true_positives"] += 1
                matched_gt_ids.add(gt_match["id"])
            else:
                entry = {"candidate_id": cid, "class": cls, "route": route, "file": cand["file"]}
                bucket["verified_not_in_ground_truth"].append(entry)
                verified_outside_gt.append(entry)

            if patch is not None:
                if patch.get("final_status") == FinalPatchStatus.PASS.value:
                    bucket["patches_passed"] += 1
                if patch.get("guards_passed") is False:
                    bucket["guard_rejections"] += 1

        elif status == VerificationStatus.NOT_REPRODUCED.value:
            if gt_match is not None or route in gt_routes_any_class and route not in clean_routes:
                bucket["not_reproduced_weak_test"] += 1
            else:
                bucket["not_reproduced_false_positive"] += 1
        else:
            bucket["inconclusive"] += 1

    for f in flaws:
        if f["id"] not in matched_gt_ids:
            per_class[f["vulnerability_class"]]["missed_flaw_ids"].append(f["id"])

    # Compute explicit denominators per class
    for cls, b in per_class.items():
        b["recall_ratio"] = f"{b['true_positives']}/{b['planted']}"
        b["fp_ratio"] = f"{b['not_reproduced_false_positive']}/{b['candidates']}"
        b["patch_pass_ratio"] = f"{b['patches_passed']}/{b['verified_reproducers']}"

    # Telemetry from llm_calls.jsonl
    llm_log_path = run_dir / "llm_calls.jsonl"
    live_calls = 0
    cache_hits = 0
    live_tokens = 0
    llm_latency_ms = 0
    if llm_log_path.exists():
        for raw_line in llm_log_path.read_text(encoding="utf-8").splitlines():
            if not raw_line.strip():
                continue
            rec = json.loads(raw_line)
            if rec.get("cache_hit"):
                cache_hits += 1
            else:
                live_calls += 1
                llm_latency_ms += int(rec.get("latency_ms") or 0)
                usage = rec.get("usage") or {}
                if isinstance(usage.get("total_tokens"), int):
                    live_tokens += usage["total_tokens"]

    total_planted = len(flaws)
    total_candidates = len(candidates)
    total_verified = sum(b["verified_reproducers"] for b in per_class.values())
    total_tp = len(matched_gt_ids)
    total_fp = sum(b["not_reproduced_false_positive"] for b in per_class.values())
    total_weak = sum(b["not_reproduced_weak_test"] for b in per_class.values())
    total_inconc = sum(b["inconclusive"] for b in per_class.values())
    total_patches_passed = sum(b["patches_passed"] for b in per_class.values())
    total_guard_rej = sum(b["guard_rejections"] for b in per_class.values())
    missed_all = [f["id"] for f in flaws if f["id"] not in matched_gt_ids]

    total_llm_requests = live_calls + cache_hits

    return {
        "run_id": summary_doc.get("run_id", run_dir.name),
        "duration_ms": int(summary_doc.get("duration_ms") or 0),
        "overall": {
            "planted_flaws": total_planted,
            "clean_routes": len(clean_routes),
            "candidates_produced": total_candidates,
            "verified_reproducers": total_verified,
            "true_positives": total_tp,
            "recall_denominator": f"{total_tp}/{total_planted}",
            "missed_flaw_ids": missed_all,
            "not_reproduced_false_positives": total_fp,
            "not_reproduced_weak_tests": total_weak,
            "false_positive_rate_denominator": f"{total_fp}/{total_candidates}",
            "inconclusive": total_inconc,
            "verified_not_in_ground_truth": verified_outside_gt,
            "patches_passed": total_patches_passed,
            "patch_success_denominator": f"{total_patches_passed}/{total_verified}",
            "guard_rejections": total_guard_rej,
        },
        "telemetry": {
            "live_model_calls": live_calls,
            "cache_hits": cache_hits,
            "cache_hit_denominator": f"{cache_hits}/{total_llm_requests}",
            "provider_reported_live_tokens": live_tokens,
            "live_llm_latency_ms": llm_latency_ms,
            "cost_usd": "unknown",
        },
        "per_class": per_class,
    }


def format_evaluation_markdown(scored_runs: list[dict[str, Any]]) -> str:
    """Render honest per-class and multi-run range Markdown report per Section 11."""
    if not scored_runs:
        raise ValueError("scored_runs must be non-empty")

    latest = scored_runs[-1]
    ov = latest["overall"]
    tel = latest["telemetry"]

    tps = [r["overall"]["true_positives"] for r in scored_runs]
    fps = [r["overall"]["not_reproduced_false_positives"] for r in scored_runs]
    cands = [r["overall"]["candidates_produced"] for r in scored_runs]
    patches = [r["overall"]["patches_passed"] for r in scored_runs]
    planted = ov["planted_flaws"]

    lines = [
        "# Verified Security Patch Agent — Empirical Evaluation Report",
        "",
        "## Scope & Honest Limitations Disclosure",
        f"- **Fixture size**: `{planted}` planted flaws across 6 classes (2 per class), `{ov['clean_routes']}` clean routes, and `1` planted prompt-injection comment in `fixture/express-fixture`.",
        f"- **Runs evaluated**: `{len(scored_runs)}` real run(s). Results on this owned Express fixture measure verification precision and patch safety on this target only and **do not prove universal vulnerability detection**.",
        "- **Comparison with static analyzers**: Lightweight static tools (such as Semgrep) already flag many syntactic patterns in these classes more cheaply. The contribution measured here is **execution-backed proof** (deterministic tagged failing test on baseline, passing companion positive test before and after, full regression suite, and mechanical anti-vandalism guards) alongside an explicit false-positive denominator.",
        "",
        f"## Multi-Run Range Summary (`n = {len(scored_runs)}` runs)",
        "",
        "| Metric | Min .. Max Across Runs | Latest Run (`" + latest["run_id"] + "`) |",
        "|---|---|---|",
        f"| Candidates Produced | `{min(cands)} .. {max(cands)}` | `{ov['candidates_produced']}` |",
        f"| Verified True Positives (Recall) | `{min(tps)}/{planted} .. {max(tps)}/{planted}` | `{ov['recall_denominator']}` |",
        f"| False Positives on Clean Routes | `{min(fps)} .. {max(fps)}` | `{ov['false_positive_rate_denominator']}` |",
        f"| Verified Patches Passed (`PASS`) | `{min(patches)} .. {max(patches)}` | `{ov['patch_success_denominator']}` |",
        "",
        f"## Per-Class Breakdown (Run `{latest['run_id']}`)",
        "",
        "| Vulnerability Class | Planted | Candidates | Verified TP (Recall) | Clean-Route FP (FP / Cand) | Weak Test (`NOT_REPRODUCED` on Flaw) | `INCONCLUSIVE` | Patches `PASS` | Guard Rejections | Missed Flaws |",
        "|---|---:|---:|---:|---:|---:|---:|---:|---:|---|",
    ]

    for cls, b in latest["per_class"].items():
        missed_str = ", ".join(b["missed_flaw_ids"]) if b["missed_flaw_ids"] else "None"
        lines.append(
            f"| `{cls}` | {b['planted']} | {b['candidates']} | `{b['recall_ratio']}` | `{b['fp_ratio']}` | {b['not_reproduced_weak_test']} | {b['inconclusive']} | `{b['patch_pass_ratio']}` | {b['guard_rejections']} | {missed_str} |"
        )

    outside_gt = ov["verified_not_in_ground_truth"]
    lines.extend(
        [
            "",
            "## Telemetry & Cost (`llm_calls.jsonl`)",
            f"- **Wall-Clock Run Duration**: `{latest['duration_ms']} ms`",
            f"- **Live Model Calls**: `{tel['live_model_calls']}`",
            f"- **Cache Hits**: `{tel['cache_hit_denominator']}` (reported separately so live latency/token figures are never inflated)",
            f"- **Provider-Reported Live Tokens**: `{tel['provider_reported_live_tokens']}`",
            f"- **Cumulative Live Model Latency**: `{tel['live_llm_latency_ms']} ms`",
            f"- **Estimated Cost (USD)**: `{tel['cost_usd']}` *(per Section 9: pricing unverified, never estimated silently)*",
            "",
            "## Manual Review Queue (Verified Findings Outside `ground_truth.json`)",
            f"- Count: `{len(outside_gt)}`",
        ]
    )
    for item in outside_gt:
        lines.append(f"  - `{item['candidate_id']}` (`{item['class']}` on `{item['route']}` in `{item['file']}`)")

    return "\n".join(lines) + "\n"

