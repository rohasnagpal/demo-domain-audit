#!/usr/bin/env python3
"""Run one authorised Cyber360 S11 TLS assessment and produce JSON + HTML."""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import re
import shlex
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

try:
    from ..reporting.output_store import create_report_directory
    from ..reporting.render_tls_report import render_report
    from .enrichment import enrich_s11_report
    from .scoring import score_controls
    from .testssl_parser import normalize_testssl
except ImportError:
    import sys

    ROOT = Path(__file__).resolve().parents[2]
    sys.path.insert(0, str(ROOT))
    from engine.reporting.output_store import create_report_directory
    from engine.reporting.render_tls_report import render_report
    from engine.tls.enrichment import enrich_s11_report
    from engine.tls.scoring import score_controls
    from engine.tls.testssl_parser import normalize_testssl


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def portable_path(path: Path) -> str:
    try:
        return path.resolve().relative_to(Path.cwd().resolve()).as_posix()
    except ValueError:
        return path.resolve().as_posix()


def readable_evidence(payload: dict[str, Any]) -> str:
    """Render one evidence record as plain text that opens cleanly in a browser tab."""
    command = " ".join(shlex.quote(part) for part in payload["command"])
    rule = "=" * 78
    return (
        f"Cyber360 evidence {payload['evidence_id']}\n{rule}\n"
        f"Command:      {command}\n"
        f"Started:      {payload['started_at']}\n"
        f"Completed:    {payload['completed_at']}\n"
        f"Exit status:  {payload['exit_status']}\n"
        f"{rule}\n\n--- stdout ---\n{payload['stdout'] or '(empty)'}\n\n--- stderr ---\n{payload['stderr'] or '(empty)'}\n"
    )


class EvidenceStore:
    def __init__(self, report_directory: Path):
        self.directory = report_directory / "evidence"
        self.records: list[dict[str, Any]] = []

    def run(self, evidence_id: str, argv: list[str], timeout: int) -> tuple[subprocess.CompletedProcess[bytes], dict[str, Any]]:
        started = utc_now()
        try:
            completed = subprocess.run(
                argv,
                input=b"",
                capture_output=True,
                check=False,
                timeout=timeout,
            )
        except subprocess.TimeoutExpired as exc:
            completed = subprocess.CompletedProcess(
                argv,
                124,
                stdout=exc.stdout or b"",
                stderr=(exc.stderr or b"") + f"\nTimed out after {timeout} seconds".encode(),
            )
        completed_at = utc_now()
        payload = {
            "evidence_id": evidence_id,
            "command": argv,
            "started_at": started,
            "completed_at": completed_at,
            "exit_status": completed.returncode,
            "stdout": completed.stdout.decode("utf-8", errors="replace"),
            "stderr": completed.stderr.decode("utf-8", errors="replace"),
        }
        json_path = self.directory / f"{evidence_id}.json"
        json_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        path = self.directory / f"{evidence_id}.txt"
        path.write_text(readable_evidence(payload), encoding="utf-8")
        record = {
            "evidence_id": evidence_id,
            "command": argv,
            "captured_at": started,
            "completed_at": completed_at,
            "exit_status": completed.returncode,
            "path": portable_path(path),
            "json_path": portable_path(json_path),
            "sha256": sha256_file(path),
            "excerpt": (payload["stdout"] + "\n" + payload["stderr"]).strip()[:1200],
        }
        self.records.append(record)
        return completed, record

    def register_file(
        self,
        evidence_id: str,
        path: Path,
        command: list[str],
        exit_status: int,
        captured_at: str | None = None,
    ) -> dict[str, Any]:
        record = {
            "evidence_id": evidence_id,
            "command": command,
            "captured_at": captured_at or utc_now(),
            "exit_status": exit_status,
            "path": portable_path(path),
            "sha256": sha256_file(path),
        }
        self.records.append(record)
        return record

    def write_manifest(self) -> Path:
        path = self.directory / "manifest.json"
        path.write_text(json.dumps({"evidence": self.records}, indent=2), encoding="utf-8")
        return path


def validate_target(value: str) -> tuple[str, str]:
    target = value.strip()
    if not target or "://" in target or "/" in target:
        raise ValueError("target must be one hostname or IP address, not a URL or range")
    try:
        address = ipaddress.ip_address(target)
        return str(address), "ip"
    except ValueError:
        ascii_target = target.encode("idna").decode("ascii").rstrip(".")
        if len(ascii_target) > 253 or not all(
            re.fullmatch(r"(?!-)[A-Za-z0-9-]{1,63}(?<!-)", label)
            for label in ascii_target.split(".")
        ):
            raise ValueError("target is not a valid DNS hostname or IP address")
        return ascii_target, "hostname"


def connect_address(target: str, port: int, identifier_type: str) -> str:
    if identifier_type == "ip" and ipaddress.ip_address(target).version == 6:
        return f"[{target}]:{port}"
    return f"{target}:{port}"


def extract_leaf(pem_output: bytes, destination: Path) -> bool:
    match = re.search(
        rb"-----BEGIN CERTIFICATE-----\r?\n.*?-----END CERTIFICATE-----\r?\n?",
        pem_output,
        re.S,
    )
    if not match:
        return False
    destination.write_bytes(match.group(0))
    return True


def finding_evidence(record: dict[str, Any]) -> dict[str, Any]:
    return {
        key: record[key]
        for key in ("evidence_id", "command", "captured_at", "exit_status", "path", "sha256", "excerpt")
        if key in record
    }


def build_report(
    normalized: dict[str, Any],
    scoring: dict[str, Any],
    *,
    report_id: str,
    target: str,
    port: int,
    identifier_type: str,
    authority: str,
    started_at: str,
    completed_at: str,
    tooling: list[dict[str, str]],
    evidence_by_id: dict[str, dict[str, Any]],
    profile: str,
    extra_limitations: list[str] | None = None,
) -> dict[str, Any]:
    confirmed = [item for item in normalized["controls"] if item["status"] == "confirmed"]
    unknown_controls = [item for item in normalized["controls"] if item["status"] == "unknown"]
    findings = []
    for index, item in enumerate(confirmed, 1):
        evidence = [
            finding_evidence(evidence_by_id[evidence_id])
            for evidence_id in item["evidence_ids"]
            if evidence_id in evidence_by_id
        ]
        if not evidence:
            continue
        findings.append(
            {
                "finding_id": f"S11-{index:03d}",
                "rule_id": item["rule_id"],
                "status": "confirmed",
                "severity": item["severity"],
                "title": item["title"],
                "analysis": item["detail"] or item["title"],
                "evidence": evidence,
                "authority": item["authority"],
                "remediation": item["remediation"],
                "verification": "not_started",
            }
        )
    unknowns = [
        {
            "rule_id": item["rule_id"],
            "reason": item["detail"] or "The structured evidence did not establish pass or failure.",
            "evidence_needed": f"A conclusive test for {item['title'].lower()} against this exact endpoint.",
        }
        for item in unknown_controls
    ]
    grade = scoring["grade"]
    score_text = f"{scoring['score']}/100" if "score" in scoring else "not scored"
    assessment = (
        f"Cyber360 evidence grade {grade} ({score_text}) with {scoring['coverage']}% control coverage. "
        f"{len(findings)} confirmed finding(s) and {len(unknowns)} unknown control(s)."
    )
    technical = dict(normalized["technical"])
    technical.update(
        {
            "grade": scoring["grade"],
            "grade_basis": scoring["grade_basis"],
            "score_components": scoring["score_components"],
            "coverage": scoring["coverage"],
            "policy_id": scoring["policy_id"],
        }
    )
    if "score" in scoring:
        technical["score"] = scoring["score"]
    limitations = [
        "Point-in-time observation from one client and network path.",
        "Client simulations describe modeled handshakes, not tests from physical client devices.",
    ]
    if profile == "standard":
        limitations.append("HTTP header and dedicated TLS vulnerability checks were outside the standard profile.")
    limitations.extend(extra_limitations or [])
    return {
        "report_id": report_id,
        "agent_id": "s11",
        "generated_at": completed_at,
        "scope": {
            "target": target,
            "port": port,
            "identifier_type": identifier_type,
            "authority": authority,
            "started_at": started_at,
            "completed_at": completed_at,
            "exclusions": ["All other hosts and ports", "Credential testing", "Exploitation", "Configuration changes"],
        },
        "tooling": tooling,
        "summary": {
            "overall_assessment": assessment,
            "confirmed_findings": len(findings),
            "unknown_controls": len(unknowns),
        },
        "findings": findings,
        "unknowns": unknowns,
        "assumptions": [
            "The observed endpoint is the intended TLS termination point.",
            "The local trust store represents the intended client trust context unless the authority statement says otherwise.",
        ],
        "limitations": limitations,
        "technical": technical,
    }


def run_assessment(
    target: str,
    port: int,
    authority: str,
    profile: str = "standard",
    timeout: int = 600,
    report_directory: Path | None = None,
) -> tuple[Path, Path]:
    target, identifier_type = validate_target(target)
    if not authority.strip():
        raise ValueError("an explicit authority statement is required before connecting")
    if not 1 <= port <= 65535:
        raise ValueError("port must be between 1 and 65535")
    if profile not in {"standard", "extended"}:
        raise ValueError("profile must be standard or extended")
    missing = [name for name in ("openssl", "testssl.sh") if not shutil.which(name)]
    if missing:
        raise RuntimeError(f"missing required classroom tools: {', '.join(missing)}")

    started_at = utc_now()
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    safe_target = re.sub(r"[^A-Za-z0-9.-]+", "-", target)
    report_id = f"S11-{safe_target}-{port}-{timestamp}"
    if report_directory is None:
        report_directory = create_report_directory(report_id)
    else:
        (report_directory / "evidence").mkdir(parents=True, exist_ok=True)
    evidence = EvidenceStore(report_directory)
    address = connect_address(target, port, identifier_type)

    openssl_version, _ = evidence.run("E01-openssl-version", ["openssl", "version"], 20)
    testssl_version, _ = evidence.run("E02-testssl-version", ["testssl.sh", "--version"], 20)

    chain_argv = ["openssl", "s_client", "-connect", address]
    if identifier_type == "hostname":
        chain_argv += ["-servername", target]
    chain_argv.append("-showcerts")
    chain, _ = evidence.run("E03-presented-chain", chain_argv, 30)

    leaf_path = report_directory / "evidence" / "leaf.pem"
    if extract_leaf(chain.stdout, leaf_path):
        evidence.register_file("E04-leaf-certificate", leaf_path, chain_argv, chain.returncode)
        evidence.run(
            "E05-certificate-inspection",
            [
                "openssl", "x509", "-in", str(leaf_path), "-noout", "-subject", "-issuer",
                "-serial", "-dates", "-fingerprint", "-sha256", "-text",
            ],
            30,
        )

    verify_argv = ["openssl", "s_client", "-connect", address]
    if identifier_type == "hostname":
        verify_argv += ["-servername", target, "-verify_hostname", target]
    else:
        verify_argv += ["-verify_ip", target]
    verify_argv += ["-verify_return_error", "-brief"]
    evidence.run("E06-identity-and-trust", verify_argv, 30)

    structured_path = report_directory / "evidence" / "testssl-pretty.json"
    testssl_argv = [
        "testssl.sh", "--quiet", "--warnings", "batch", "--color", "0", "--mapping", "iana",
        "--server-defaults", "--server-preference", "--protocols", "--categories",
        "--forward-secrecy", "--cipher-per-proto", "--client-simulation",
    ]
    if profile == "extended":
        testssl_argv += ["--vulnerable", "--headers"]
    testssl_argv += ["--jsonfile-pretty", str(structured_path), "--overwrite", address]
    testssl_run, raw_record = evidence.run("E07-testssl-raw", testssl_argv, timeout)

    extra_limitations: list[str] = []
    if structured_path.is_file():
        structured_record = evidence.register_file(
            "E08-testssl-structured", structured_path, testssl_argv, testssl_run.returncode
        )
        try:
            testssl_document = json.loads(structured_path.read_text(encoding="utf-8"))
            normalized = normalize_testssl(testssl_document, structured_record["evidence_id"])
        except (json.JSONDecodeError, ValueError) as exc:
            extra_limitations.append(f"Structured testssl output could not be normalized: {exc}")
            normalized = normalize_testssl({"scanResult": [{}]}, raw_record["evidence_id"])
    else:
        extra_limitations.append("testssl.sh did not produce structured output; technical controls remain unknown.")
        normalized = normalize_testssl({"scanResult": [{}]}, raw_record["evidence_id"])

    scoring = score_controls(normalized["controls"])
    completed_at = utc_now()
    tooling = [
        {"name": "OpenSSL", "version": openssl_version.stdout.decode(errors="replace").strip().splitlines()[0]},
        {"name": "testssl.sh", "version": next((line.strip() for line in testssl_version.stdout.decode(errors="replace").splitlines() if "testssl.sh" in line and "version" in line), "unknown")},
    ]
    records = {item["evidence_id"]: item for item in evidence.records}
    report = build_report(
        normalized,
        scoring,
        report_id=report_id,
        target=target,
        port=port,
        identifier_type=identifier_type,
        authority=authority.strip(),
        started_at=started_at,
        completed_at=completed_at,
        tooling=tooling,
        evidence_by_id=records,
        profile=profile,
        extra_limitations=extra_limitations,
    )
    report["raw_controls"] = normalized["controls"]
    report["evidence"] = evidence.records
    enrich_s11_report(report)
    leaf = (report.get("technical", {}).get("certificates") or [{}])[0]
    report["chart_data"] = {"timeline": [["TLS certificate", leaf.get("not_before"), leaf.get("not_after")]] if leaf.get("not_after") else []}
    json_path = report_directory / "report.json"
    html_path = report_directory / "report.html"
    json_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    html_path.write_text(render_report(report), encoding="utf-8")
    evidence.write_manifest()
    return json_path, html_path


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("target", help="One authorised DNS hostname, IPv4 address or IPv6 address")
    parser.add_argument("--port", type=int, default=443)
    parser.add_argument("--authority", required=True, help="User-provided authority statement recorded in the report")
    parser.add_argument("--profile", choices=("standard", "extended"), default="standard")
    parser.add_argument("--timeout", type=int, default=600, help="Maximum seconds for testssl.sh")
    args = parser.parse_args()
    try:
        json_path, html_path = run_assessment(
            args.target, args.port, args.authority, args.profile, args.timeout
        )
    except (ValueError, RuntimeError) as exc:
        parser.error(str(exc))
    print(json_path.resolve())
    print(html_path.resolve())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

