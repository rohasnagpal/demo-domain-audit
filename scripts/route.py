#!/usr/bin/env python3
"""Route a request to implemented Cyber360 specialists without granting execution authority."""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_REGISTRY = ROOT / "orchestrator" / "agent-registry.json"


def load_registry(path: Path) -> dict:
    with path.open(encoding="utf-8") as handle:
        registry = json.load(handle)
    if not isinstance(registry.get("agents"), list):
        raise ValueError("registry agents must be a list")
    return registry


def signal_matches(text: str, signal: str) -> bool:
    pattern = rf"(?<![a-z0-9]){re.escape(signal.casefold())}(?![a-z0-9])"
    return re.search(pattern, text) is not None


DOMAIN_PATTERN = re.compile(r"(?<![a-z0-9.@-])((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63})(?![a-z0-9-])")


def extract_domain(text: str) -> str | None:
    """Return the single domain named in a request, or None when there is not exactly one."""
    found = sorted(set(DOMAIN_PATTERN.findall(text.casefold())))
    return found[0] if len(found) == 1 else None


def match_workflow(registry: dict, text: str) -> dict | None:
    available = {agent["id"] for agent in registry["agents"] if agent.get("status") == "available"}
    for workflow in registry.get("workflows", []):
        trigger = next((t for t in workflow.get("triggers", []) if signal_matches(text, t)), None)
        if trigger and all(agent_id in available for agent_id in workflow["agents"]):
            return {**workflow, "matched_trigger": trigger}
    return None


def route(registry: dict, request: str, stage: str | None = None, explicit_agent: str | None = None) -> dict:
    text = request.casefold()
    selected = []
    workflow = match_workflow(registry, text)

    for agent in registry["agents"]:
        if agent.get("status") != "available":
            continue

        reasons = []
        if explicit_agent and agent.get("id", "").casefold() == explicit_agent.casefold():
            reasons.append(f"explicit-agent:{agent['id']}")
        if workflow and agent["id"] in workflow["agents"]:
            reasons.append(f"workflow:{workflow['id']}")

        matched_signals = sorted({signal for signal in agent.get("signals", []) if signal_matches(text, signal)})
        reasons.extend(f"signal:{signal}" for signal in matched_signals)

        if reasons:
            selected.append(
                {
                    "id": agent["id"],
                    "name": agent["name"],
                    "entry_skill_path": agent["entry_skill_path"],
                    "agent_path": agent["agent_path"],
                    "reasons": reasons,
                    "stage_supported": stage is None or stage.casefold() in agent.get("stages", []),
                    "network_authority_required": bool(agent.get("network_authority_required")),
                }
            )

    if explicit_agent and not any(item["id"].casefold() == explicit_agent.casefold() for item in selected):
        status = "requested_agent_unavailable"
    elif selected:
        status = "routed"
    else:
        status = "no_available_specialist"

    result = {
        "status": status,
        "request": request,
        "stage": stage,
        "chief": registry["chief"],
        "selected": selected,
        "authority_note": "Routing does not authorise network access, tool execution, remediation or external disclosure.",
        "coverage_note": (
            f"This installation implements {registry['catalog']['implemented_count']} of "
            f"{registry['catalog']['specialist_count']} catalogued specialists."
        ),
    }
    if workflow:
        result["workflow"] = {
            "id": workflow["id"],
            "name": workflow["name"],
            "path": workflow["path"],
            "entry_skill_path": workflow["entry_skill_path"],
            "agents": workflow["agents"],
            "matched_trigger": workflow["matched_trigger"],
            "target": extract_domain(request),
        }
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--request", default="", help="Natural-language cybersecurity request")
    parser.add_argument("--stage", choices=("build", "hack", "investigate", "secure", "audit", "repeat"))
    parser.add_argument("--agent", help="Explicit specialist ID, such as s11")
    parser.add_argument("--registry", type=Path, default=DEFAULT_REGISTRY)
    parser.add_argument("--list", action="store_true", help="List implemented specialists")
    args = parser.parse_args(argv)

    try:
        registry = load_registry(args.registry)
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        parser.error(f"cannot load registry: {exc}")

    if args.list:
        output = {
            "chief": registry["chief"],
            "catalog": registry["catalog"],
            "available_agents": [agent for agent in registry["agents"] if agent.get("status") == "available"],
        }
    else:
        if not args.request and not args.agent:
            parser.error("provide --request, --agent or --list")
        output = route(registry, args.request, args.stage, args.agent)

    print(json.dumps(output, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
