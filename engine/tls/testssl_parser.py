"""Normalize testssl.sh pretty JSON into Cyber360 TLS report data."""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any


PROTOCOL_NAMES = {
    "SSLv2": "SSL 2.0",
    "SSLv3": "SSL 3.0",
    "TLS1": "TLS 1.0",
    "TLS1_1": "TLS 1.1",
    "TLS1_2": "TLS 1.2",
    "TLS1_3": "TLS 1.3",
    "NPN": "NPN/SPDY",
    "ALPN": "ALPN/HTTP2",
}

CONTROL_DEFINITIONS = {
    "TLS-PROTO-001": ("Deprecated TLS protocol accepted", "protocols", "high", "RFC8996", "Disable TLS 1.0 and TLS 1.1."),
    "TLS-PROTO-002": ("No currently acceptable TLS protocol demonstrated", "protocols", "critical", "RFC8996", "Enable TLS 1.2 or TLS 1.3."),
    "TLS-PROTO-003": ("SSL 2.0 or SSL 3.0 accepted", "protocols", "critical", "RFC8996", "Disable SSL 2.0 and SSL 3.0."),
    "TLS-CERT-001": ("Certificate expired", "certificate", "high", "CABF-BR", "Replace the expired certificate and verify renewal automation."),
    "TLS-CERT-002": ("Certificate not yet valid", "certificate", "high", "CABF-BR", "Deploy a certificate valid at the time of use."),
    "TLS-CERT-003": ("Certificate identity mismatch", "certificate", "high", "CABF-IP", "Deploy a certificate containing the requested DNS or IP SAN."),
    "TLS-CERT-004": ("Certificate chain validation failed", "certificate", "high", "RFC9325", "Deploy a complete chain trusted by the intended clients."),
    "TLS-CERT-005": ("Certificate uses an unrecognised trust anchor", "certificate", "medium", "RFC9325", "Use an appropriate trust anchor or document and distribute the private CA."),
    "TLS-CERT-006": ("Certificate nearing expiry", "certificate", "low", "local-policy", "Renew and deploy the replacement certificate before expiry."),
    "TLS-KEY-001": ("RSA certificate key is below 2048 bits", "certificate", "high", "RFC9325", "Replace the certificate and key with an approved key type and strength."),
    "TLS-SIG-001": ("Certificate uses an MD5 or SHA-1 signature", "certificate", "high", "RFC9325", "Reissue the certificate with an approved signature algorithm."),
    "TLS-CIPHER-001": ("Prohibited cipher suite accepted", "cipher_strength", "critical", "RFC9325", "Remove NULL, anonymous, export, RC4 and other prohibited suites."),
    "TLS-CIPHER-002": ("Static RSA key transport accepted", "key_exchange", "medium", "RFC9325", "Remove static RSA key transport and prefer forward-secret suites."),
    "TLS-CIPHER-003": ("64-bit block cipher accepted", "cipher_strength", "medium", "RFC9325", "Remove 3DES, IDEA and other 64-bit block ciphers."),
    "TLS-CIPHER-004": ("Obsolete CBC cipher accepted", "cipher_strength", "low", "RFC9325", "Prefer authenticated encryption and remove obsolete CBC suites after compatibility review."),
    "TLS-FS-001": ("Forward secrecy not demonstrated", "key_exchange", "medium", "RFC9325", "Enable ECDHE or DHE suites and prefer TLS 1.3."),
}


def _index(items: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    return {str(item.get("id")): item for item in items}


def _status_from_finding(finding: str) -> str:
    lowered = finding.lower()
    if "not offered" in lowered or "not supported" in lowered:
        return "not_supported"
    if "offered" in lowered or "supported" in lowered:
        return "supported"
    return "unknown"


def _control(rule_id: str, status: str, evidence_id: str, detail: str = "") -> dict[str, Any]:
    title, component, severity, authority, remediation = CONTROL_DEFINITIONS[rule_id]
    return {
        "rule_id": rule_id,
        "title": title,
        "component": component,
        "status": status,
        "severity": severity,
        "authority": authority,
        "remediation": remediation,
        "evidence_ids": [evidence_id],
        "detail": detail,
    }


def _parse_cipher(row: dict[str, Any]) -> dict[str, Any] | None:
    parts = re.split(r"\s{2,}", str(row.get("finding", "")).strip())
    if len(parts) < 6:
        return None
    try:
        strength = int(parts[5])
    except ValueError:
        strength = 0
    return {
        "protocol": parts[0],
        "name": parts[2],
        "strength_bits": strength,
        "key_exchange": parts[3],
        "status": "accepted",
    }


def _client_name(identifier: str) -> str:
    value = identifier.removeprefix("clientsimulation-").replace("_", " ")
    replacements = {
        "android": "Android", "chrome": "Chrome", "chromium": "Chromium",
        "firefox": "Firefox", "safari": "Safari", "java": "Java", "edge": "Edge",
        "openssl": "OpenSSL", "libressl": "LibreSSL", "apple mail": "Apple Mail",
        "thunderbird": "Thunderbird", " win": " Windows ", " osx": " macOS ",
    }
    for source, replacement in replacements.items():
        value = value.replace(source, replacement)
    return " ".join(value.split())


def _parse_client(row: dict[str, Any]) -> dict[str, Any]:
    finding = str(row.get("finding", ""))
    if finding.lower().startswith("no connection"):
        return {"client": _client_name(str(row.get("id", "client"))), "result": "fail"}
    parts = finding.split(maxsplit=1)
    return {
        "client": _client_name(str(row.get("id", "client"))),
        "result": "success" if len(parts) == 2 else "unknown",
        "protocol": parts[0] if parts else "",
        "cipher": parts[1] if len(parts) == 2 else "",
    }


def normalize_testssl(
    document: dict[str, Any], evidence_id: str = "E-testssl"
) -> dict[str, Any]:
    scans = document.get("scanResult") or []
    if len(scans) != 1:
        raise ValueError("testssl JSON must contain exactly one scanResult target")
    scan = scans[0]
    protocol_rows = scan.get("protocols") or []
    protocol_index = _index(protocol_rows)
    protocols = [
        {
            "name": PROTOCOL_NAMES.get(str(row.get("id")), str(row.get("id"))),
            "status": _status_from_finding(str(row.get("finding", ""))),
            "evidence_id": evidence_id,
        }
        for row in protocol_rows
    ]
    cipher_suites = [item for row in scan.get("cipherTests", []) if (item := _parse_cipher(row))]
    clients = [_parse_client(row) for row in scan.get("browserSimulations", [])]
    defaults = _index(scan.get("serverDefaults") or [])
    fs = _index(scan.get("fs") or [])
    categories = _index(scan.get("ciphers") or [])

    certificates: list[dict[str, Any]] = []
    if defaults:
        sans = str(defaults.get("cert_subjectAltName", {}).get("finding", "")).split()
        chain = defaults.get("cert_chain_of_trust", {})
        identity = defaults.get("cert_trust", {})
        certificate_status = "pass"
        if str(chain.get("severity", "")).upper() in {"CRITICAL", "HIGH", "MEDIUM"}:
            certificate_status = "finding"
        certificates.append(
            {
                "position": "leaf",
                "subject": str(defaults.get("cert_commonName", {}).get("finding", "")),
                "issuer": str(defaults.get("cert_caIssuers", {}).get("finding", "")),
                "status": certificate_status,
                "serial_number": str(defaults.get("cert_serialNumber", {}).get("finding", "")),
                "subject_alternative_names": sans,
                "not_before": str(defaults.get("cert_notBefore", {}).get("finding", "")),
                "not_after": str(defaults.get("cert_notAfter", {}).get("finding", "")),
                "public_key": str(defaults.get("cert_keySize", {}).get("finding", "")),
                "signature_algorithm": str(defaults.get("cert_signatureAlgorithm", {}).get("finding", "")),
                "sha256_fingerprint": str(defaults.get("cert_fingerprintSHA256", {}).get("finding", "")),
                "trust_result": str(chain.get("finding", "")),
                "identity_result": str(identity.get("finding", "")),
            }
        )

    controls: list[dict[str, Any]] = []

    old_statuses = [_status_from_finding(str(protocol_index.get(key, {}).get("finding", ""))) for key in ("TLS1", "TLS1_1")]
    if all(status == "not_supported" for status in old_statuses):
        controls.append(_control("TLS-PROTO-001", "pass", evidence_id, "TLS 1.0 and TLS 1.1 not offered"))
    elif any(status == "supported" for status in old_statuses):
        controls.append(_control("TLS-PROTO-001", "confirmed", evidence_id, "TLS 1.0 or TLS 1.1 offered"))
    else:
        controls.append(_control("TLS-PROTO-001", "unknown", evidence_id, "Deprecated protocol result incomplete"))

    modern_statuses = [_status_from_finding(str(protocol_index.get(key, {}).get("finding", ""))) for key in ("TLS1_2", "TLS1_3")]
    if any(status == "supported" for status in modern_statuses):
        controls.append(_control("TLS-PROTO-002", "pass", evidence_id, "TLS 1.2 or TLS 1.3 offered"))
    elif all(status == "not_supported" for status in modern_statuses):
        controls.append(_control("TLS-PROTO-002", "confirmed", evidence_id, "Neither TLS 1.2 nor TLS 1.3 offered"))
    else:
        controls.append(_control("TLS-PROTO-002", "unknown", evidence_id, "Modern protocol result incomplete"))

    ssl_statuses = [_status_from_finding(str(protocol_index.get(key, {}).get("finding", ""))) for key in ("SSLv2", "SSLv3")]
    if all(status == "not_supported" for status in ssl_statuses):
        controls.append(_control("TLS-PROTO-003", "pass", evidence_id, "SSL 2.0 and SSL 3.0 not offered"))
    elif any(status == "supported" for status in ssl_statuses):
        controls.append(_control("TLS-PROTO-003", "confirmed", evidence_id, "SSL 2.0 or SSL 3.0 offered"))
    else:
        controls.append(_control("TLS-PROTO-003", "unknown", evidence_id, "SSL protocol result incomplete"))

    expiration = str(defaults.get("cert_expirationStatus", {}).get("finding", ""))
    controls.append(_control("TLS-CERT-001", "confirmed" if "expired" in expiration.lower() else ("pass" if expiration else "unknown"), evidence_id, expiration))
    controls.append(_control("TLS-CERT-002", "confirmed" if "not yet valid" in expiration.lower() else ("pass" if expiration else "unknown"), evidence_id, expiration))
    controls.append(_control("TLS-CERT-006", "confirmed" if re.search(r"expires\s*<\s*30 days", expiration, re.I) else ("pass" if expiration else "unknown"), evidence_id, expiration))

    identity = defaults.get("cert_trust", {})
    identity_finding = str(identity.get("finding", ""))
    identity_ok = str(identity.get("severity", "")).upper() == "OK"
    controls.append(_control("TLS-CERT-003", "pass" if identity_ok else ("confirmed" if identity_finding else "unknown"), evidence_id, identity_finding))

    chain = defaults.get("cert_chain_of_trust", {})
    chain_finding = str(chain.get("finding", ""))
    chain_ok = str(chain.get("severity", "")).upper() == "OK"
    controls.append(_control("TLS-CERT-004", "pass" if chain_ok else ("confirmed" if chain_finding else "unknown"), evidence_id, chain_finding))
    private_anchor = bool(re.search(r"self.?signed|private", chain_finding, re.I))
    controls.append(_control("TLS-CERT-005", "confirmed" if private_anchor else ("not_applicable" if chain_ok else "unknown"), evidence_id, chain_finding))

    key_finding = str(defaults.get("cert_keySize", {}).get("finding", ""))
    key_match = re.search(r"RSA\s+(\d+)\s+bits", key_finding, re.I)
    controls.append(_control("TLS-KEY-001", "confirmed" if key_match and int(key_match.group(1)) < 2048 else ("pass" if key_finding else "unknown"), evidence_id, key_finding))
    signature = str(defaults.get("cert_signatureAlgorithm", {}).get("finding", ""))
    controls.append(_control("TLS-SIG-001", "confirmed" if re.search(r"\b(?:MD5|SHA-?1)\b", signature, re.I) else ("pass" if signature else "unknown"), evidence_id, signature))

    prohibited_ids = ("cipherlist_NULL", "cipherlist_aNULL", "cipherlist_EXPORT", "cipherlist_LOW")
    prohibited = [categories.get(key, {}) for key in prohibited_ids]
    prohibited_statuses = [_status_from_finding(str(item.get("finding", ""))) for item in prohibited]
    controls.append(_control("TLS-CIPHER-001", "confirmed" if "supported" in prohibited_statuses else ("pass" if prohibited and all(status == "not_supported" for status in prohibited_statuses) else "unknown"), evidence_id, "; ".join(str(item.get("finding", "")) for item in prohibited)))

    static_rsa = [item for item in cipher_suites if str(item.get("key_exchange", "")).upper() == "RSA"]
    controls.append(_control("TLS-CIPHER-002", "confirmed" if static_rsa else ("pass" if cipher_suites else "unknown"), evidence_id, f"{len(static_rsa)} static RSA suites accepted" if cipher_suites else "Cipher enumeration unavailable"))
    triple = categories.get("cipherlist_3DES_IDEA", {})
    triple_status = _status_from_finding(str(triple.get("finding", "")))
    controls.append(_control("TLS-CIPHER-003", "confirmed" if triple_status == "supported" else ("pass" if triple_status == "not_supported" else "unknown"), evidence_id, str(triple.get("finding", ""))))
    obsolete = categories.get("cipherlist_OBSOLETED", {})
    obsolete_status = _status_from_finding(str(obsolete.get("finding", "")))
    controls.append(_control("TLS-CIPHER-004", "confirmed" if obsolete_status == "supported" else ("pass" if obsolete_status == "not_supported" else "unknown"), evidence_id, str(obsolete.get("finding", ""))))
    fs_status = _status_from_finding(str(fs.get("FS", {}).get("finding", "")))
    controls.append(_control("TLS-FS-001", "pass" if fs_status == "supported" else ("confirmed" if fs_status == "not_supported" else "unknown"), evidence_id, str(fs.get("FS", {}).get("finding", ""))))

    excluded_defaults = {"cert", "cert_commonName", "cert_caIssuers", "cert_subjectAltName", "cert_serialNumber", "cert_notBefore", "cert_notAfter", "cert_keySize", "cert_signatureAlgorithm", "cert_fingerprintSHA256", "cert_trust", "cert_chain_of_trust"}
    server_features = [
        {
            "name": key.replace("_", " "),
            "status": "finding" if str(row.get("severity", "")).upper() in {"CRITICAL", "HIGH", "MEDIUM", "LOW"} else "observed",
            "details": str(row.get("finding", "")),
        }
        for key, row in {**defaults, **fs, **_index(scan.get("vulnerabilities") or [])}.items()
        if key not in excluded_defaults and key != "FS_ciphers"
    ]

    passed_controls = [
        {"rule_id": item["rule_id"], "title": item["title"], "evidence_ids": item["evidence_ids"]}
        for item in controls if item["status"] == "pass"
    ]
    return {
        "target": {"host": scan.get("targetHost"), "ip": scan.get("ip"), "port": scan.get("port"), "service": scan.get("service")},
        "tool": {"name": "testssl.sh", "version": str(document.get("version", "")).strip(), "openssl": document.get("openssl")},
        "technical": {
            "certificates": certificates,
            "protocols": protocols,
            "cipher_suites": cipher_suites,
            "client_simulations": clients,
            "server_features": server_features,
            "passed_controls": passed_controls,
        },
        "controls": controls,
    }

