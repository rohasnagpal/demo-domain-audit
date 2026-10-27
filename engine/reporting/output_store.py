#!/usr/bin/env python3
"""Create and validate paths inside the Cyber360 reports folder."""

from __future__ import annotations

import argparse
import re
from pathlib import Path


REPORTS_FOLDER = "cyber360-reports"


def reports_root(base: Path | None = None) -> Path:
    """Return the only permitted Cyber360 output root for this working directory."""
    return ((base or Path.cwd()) / REPORTS_FOLDER).resolve()


def safe_report_id(report_id: str) -> str:
    value = re.sub(r"[^A-Za-z0-9._-]+", "-", report_id.strip()).strip("-.")
    if not value:
        raise ValueError("report_id does not contain a usable path component")
    return value[:160]


def require_managed_path(path: Path, base: Path | None = None) -> Path:
    """Resolve path and reject it unless it is below cyber360-reports/."""
    root = reports_root(base)
    resolved = path.resolve()
    try:
        resolved.relative_to(root)
    except ValueError as exc:
        raise ValueError(f"Cyber360 outputs must be stored below {root}") from exc
    return resolved


def create_report_directory(report_id: str, base: Path | None = None) -> Path:
    directory = reports_root(base) / safe_report_id(report_id)
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "evidence").mkdir(exist_ok=True)
    return directory


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("report_id", help="Unique report or engagement identifier")
    args = parser.parse_args()
    print(create_report_directory(args.report_id))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

