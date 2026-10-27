---
name: setup-tools
description: Check or install the local command-line tools required by currently implemented Cyber360 agents. Use for Cyber360 setup, missing tool errors, classroom preparation or dependency verification.
---

# Set Up Cyber360 Tools

Use the bundled `../../scripts/setup-tools.sh` rather than inventing package commands.

1. Run `../../scripts/setup-tools.sh --check` and report the detected executable paths, versions and missing tools.
2. Explain the exact package-manager command proposed by `--install` before allowing a system change.
3. Require the user's explicit authorisation to install packages. Plugin installation alone is not package-install authority.
4. After authorisation, run `../../scripts/setup-tools.sh --install --yes` through the host's approval mechanism.
5. Report the final `--check` result. Do not claim readiness if any implemented agent's tool remains missing.

The script currently supports Homebrew and `apt-get`. If neither is available, stop and provide the script's unsupported-platform result; do not download executables from arbitrary URLs or silently introduce another package manager.

