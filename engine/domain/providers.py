#!/usr/bin/env python3
"""Identify DNS, mail, registrar and certificate providers from observed records."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
PROVIDERS_PATH = ROOT / "agents" / "security" / "email-domain-security" / "references" / "providers.json"


def load_providers() -> dict[str, Any]:
    return json.loads(PROVIDERS_PATH.read_text(encoding="utf-8"))


def _match(entries: list[dict[str, Any]], default: dict[str, Any], values: list[str]) -> dict[str, Any]:
    lowered = [value.lower() for value in values if value]
    for entry in entries:
        if any(pattern in value for pattern in entry["match"] for value in lowered):
            return entry
    return default


def dns_provider(nameservers: list[str], data: dict[str, Any] | None = None) -> dict[str, Any]:
    data = data or load_providers()
    return _match(data["dns_providers"], data["default_dns_provider"], nameservers)


def mail_provider(mx_hosts: list[str], data: dict[str, Any] | None = None) -> dict[str, Any]:
    data = data or load_providers()
    return _match(data["mail_providers"], data["default_mail_provider"], mx_hosts)


def registrar(name: str | None, data: dict[str, Any] | None = None) -> dict[str, Any]:
    data = data or load_providers()
    entry = _match(data["registrars"], data["default_registrar"], [name or ""])
    if entry["id"] == "unknown" and name:
        return {**entry, "name": name}
    return entry


def ca_domain(issuer: str | None, data: dict[str, Any] | None = None) -> str | None:
    if not issuer:
        return None
    data = data or load_providers()
    lowered = issuer.lower()
    for name, domain in data["certificate_authorities"].items():
        if name in lowered:
            return domain
    return None


def third_party_services(
    txt_values: list[str], mx_hosts: list[str], nameservers: list[str], data: dict[str, Any] | None = None
) -> list[str]:
    """Describe the services that public DNS reveals, most significant first."""
    data = data or load_providers()
    services: list[str] = []
    mail = mail_provider(mx_hosts, data)
    if mx_hosts:
        services.append(f"Email: {mail['name']} (MX {', '.join(mx_hosts)})")
    dns = dns_provider(nameservers, data)
    if nameservers:
        services.append(f"DNS hosting: {dns['name']} (NS {', '.join(nameservers)})")
    for value in txt_values:
        lowered = value.lower()
        if lowered.startswith("v=spf1"):
            for term in value.split():
                if term.lower().startswith("include:"):
                    target = term.split(":", 1)[1]
                    label = data["spf_include_services"].get(target.lower(), "unrecognised sender")
                    services.append(f"Authorised email sender: {label} (SPF include:{target})")
            continue
        for token, label in data["txt_token_services"].items():
            if lowered.startswith(token):
                services.append(f"{label} (TXT {value[:60]}{'…' if len(value) > 60 else ''})")
                break
    return services
