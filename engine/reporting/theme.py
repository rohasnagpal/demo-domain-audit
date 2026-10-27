#!/usr/bin/env python3
"""Load the report theme: tokens.css and report.css, inlined into each report so it stays self-contained."""

from __future__ import annotations

import os
import re
from pathlib import Path

THEMES_DIR = Path(__file__).with_name("themes")
BASE_THEME = "default"  # always loaded first; other themes override it
DEFAULT_THEME = "assurance"  # used when CYBER360_THEME is not set


def theme_name(name: str | None = None) -> str:
    value = name or os.environ.get("CYBER360_THEME") or DEFAULT_THEME
    if not re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,63}", value) or not (THEMES_DIR / value).is_dir():
        raise ValueError(f"unknown report theme: {value!r}")
    return value


def stylesheet(name: str | None = None) -> str:
    """The base theme, then the selected theme's tokens.css and report.css as overrides."""
    chosen = theme_name(name)
    files = [THEMES_DIR / BASE_THEME / "tokens.css", THEMES_DIR / BASE_THEME / "report.css"]
    if chosen != BASE_THEME:
        files += [path for path in (THEMES_DIR / chosen / "tokens.css", THEMES_DIR / chosen / "report.css") if path.is_file()]
    return "\n".join(path.read_text(encoding="utf-8") for path in files)
