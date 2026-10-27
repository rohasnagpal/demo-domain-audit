#!/usr/bin/env python3
"""Expand control results into detailed, evidence-specific findings from an agent's knowledge base."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
KNOWLEDGE_PATHS = {
    "h1": ROOT / "agents" / "hacking" / "reconnaissance" / "references" / "knowledge.json",
    "s11": ROOT / "agents" / "security" / "tls-security" / "references" / "knowledge.json",
    "s18": ROOT / "agents" / "security" / "email-domain-security" / "references" / "knowledge.json",
}
PLACEHOLDER = re.compile(r"\{([a-z][a-z0-9_]*)\}")


def load(agent: str) -> dict[str, Any]:
    return json.loads(KNOWLEDGE_PATHS[agent].read_text(encoding="utf-8"))


def fill(value: Any, context: dict[str, Any]) -> Any:
    """Replace {placeholders} with context values; unknown placeholders stay visible rather than guessed."""
    if isinstance(value, str):
        return PLACEHOLDER.sub(lambda m: str(context[m.group(1)]) if m.group(1) in context and context[m.group(1)] not in (None, "") else m.group(0), value)
    if isinstance(value, list):
        return [fill(item, context) for item in value]
    if isinstance(value, dict):
        return {key: fill(item, context) for key, item in value.items()}
    return value


def entry_for(knowledge: dict[str, Any], rule_id: str) -> dict[str, Any]:
    return knowledge.get("controls", {}).get(rule_id, {})


def explain_control(knowledge: dict[str, Any], item: dict[str, Any], context: dict[str, Any]) -> dict[str, Any]:
    """Add category, about and an outcome explanation to a control result of any status."""
    entry = entry_for(knowledge, item["rule_id"])
    ctx = {**context, **item.get("facts", {}), "observed": item.get("detail", "")}
    explained = {**item, "category": entry.get("category", ""), "about": fill(entry.get("about", ""), ctx)}
    status = item["status"]
    if status == "pass":
        explained["explanation"] = fill(entry.get("pass", item.get("detail", "")), ctx)
    elif status == "unknown":
        help_text = entry.get("unknown_help")
        explained["explanation"] = fill(help_text, ctx) if help_text else item.get("detail", "")
    else:
        explained["explanation"] = item.get("detail", "")
    return explained


def build_finding(
    knowledge: dict[str, Any],
    item: dict[str, Any],
    context: dict[str, Any],
    finding_id: str,
    evidence: list[dict[str, Any]],
    title: str | None = None,
    authority: str | None = None,
) -> dict[str, Any]:
    """Turn a confirmed control into a detailed finding."""
    entry = entry_for(knowledge, item["rule_id"])
    findings = entry.get("findings", {})
    text = findings.get(item.get("variant", "default")) or findings.get("default") or next(iter(findings.values()), {})
    ctx = {**context, **item.get("facts", {}), "observed": item.get("detail", "")}
    detail = fill(text, ctx)
    return {
        "finding_id": finding_id,
        "rule_id": item["rule_id"],
        "status": "confirmed",
        "severity": item.get("severity", "informational"),
        "title": title or entry.get("title") or item["rule_id"],
        "category": entry.get("category", ""),
        "about": fill(entry.get("about", ""), ctx),
        "analysis": item.get("detail", ""),
        "what_we_found": detail.get("what", item.get("detail", "")),
        "why_it_matters": [paragraph for paragraph in detail.get("why", []) if paragraph and "{" not in paragraph],
        "attack_scenario": detail.get("attack", ""),
        "severity_rationale": detail.get("severity_rationale", ""),
        "fix_steps": [step for step in detail.get("fix", []) if step and not (isinstance(step, str) and step.startswith("{"))],
        "rollback": detail.get("rollback", ""),
        "verify": detail.get("verify", {}),
        "references": fill(entry.get("references", []), ctx),
        "authority": authority,
        "remediation": detail.get("fix", [""])[0] if isinstance(detail.get("fix", [""])[0], str) else detail.get("fix", [{}])[0].get("text", ""),
        "evidence": evidence,
        "verification": "not_started",
    }


def command_purposes(knowledge: dict[str, Any]) -> dict[str, str]:
    return knowledge.get("commands", {})


def glossary(knowledge: dict[str, Any]) -> list[list[str]]:
    return knowledge.get("glossary", [])
