"""Apply the documented Cyber360 TLS scoring policy to normalized controls."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


POLICY_PATH = Path(__file__).with_name("scoring-policy.json")


def load_policy() -> dict[str, Any]:
    return json.loads(POLICY_PATH.read_text(encoding="utf-8"))


def grade_for_score(score: int, policy: dict[str, Any]) -> str:
    for threshold in policy["grades"]:
        if score >= threshold["minimum"]:
            return threshold["grade"]
    return "F"


def score_controls(
    controls: list[dict[str, Any]], policy: dict[str, Any] | None = None
) -> dict[str, Any]:
    """Return evidence-aware component scores and an overall grade.

    Control status must be pass, confirmed, unknown or not_applicable. Unknown
    controls reduce coverage; they are never silently treated as passes.
    """
    policy = policy or load_policy()
    components: list[dict[str, Any]] = []
    applicable_total = 0
    assessed_total = 0
    component_scores: dict[str, int] = {}
    any_unknown = False

    for component, weight in policy["weights"].items():
        selected = [item for item in controls if item.get("component") == component]
        applicable = [item for item in selected if item.get("status") != "not_applicable"]
        assessed = [item for item in applicable if item.get("status") in {"pass", "confirmed"}]
        unknowns = [item for item in applicable if item.get("status") == "unknown"]
        any_unknown = any_unknown or bool(unknowns)
        applicable_total += len(applicable)
        assessed_total += len(assessed)
        deductions = sum(
            int(policy["deductions"].get(item.get("rule_id"), 0))
            for item in assessed
            if item.get("status") == "confirmed"
        )
        observed_score = max(0, 100 - deductions) if assessed else 0
        coverage = round(100 * len(assessed) / len(applicable)) if applicable else 100
        component_scores[component] = observed_score
        components.append(
            {
                "name": f"{component.replace('_', ' ').title()} ({coverage}% coverage)",
                "score": observed_score,
                "weight": weight,
                "coverage": coverage,
            }
        )

    coverage = round(100 * assessed_total / applicable_total) if applicable_total else 0
    weighted = round(
        sum(component_scores[name] * weight for name, weight in policy["weights"].items())
        / sum(policy["weights"].values())
    )

    caps: list[str] = []
    confirmed = [item for item in controls if item.get("status") == "confirmed"]
    for severity in ("critical", "high", "medium"):
        if any(item.get("severity") == severity for item in confirmed):
            cap = int(policy["severity_score_caps"][severity])
            if weighted > cap:
                weighted = cap
                caps.append(f"{severity} finding cap {cap}")
            break

    minimum_coverage = int(policy["minimum_coverage_for_grade"])
    if coverage < minimum_coverage:
        grade = "N/A"
        published_score = None
        caps.append(f"coverage {coverage}% below {minimum_coverage}% grading threshold")
    else:
        if any_unknown and weighted > int(policy["unknown_grade_max_score"]):
            weighted = int(policy["unknown_grade_max_score"])
            caps.append("unknown-control grade cap")
        published_score = weighted
        grade = grade_for_score(weighted, policy)

    basis = (
        f"{policy['id']} applied to {assessed_total}/{applicable_total} applicable controls "
        f"({coverage}% evidence coverage)"
    )
    if caps:
        basis += "; " + "; ".join(caps)

    result: dict[str, Any] = {
        "grade": grade,
        "grade_basis": basis,
        "score_components": [
            {"name": item["name"], "score": item["score"]} for item in components
        ],
        "coverage": coverage,
        "policy_id": policy["id"],
    }
    if published_score is not None:
        result["score"] = published_score
    return result

