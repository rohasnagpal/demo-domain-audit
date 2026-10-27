#!/usr/bin/env bash

set -u

usage() {
  cat <<'EOF'
Cyber360 tool setup

Usage:
  ./scripts/setup-tools.sh --check
  ./scripts/setup-tools.sh --install [--yes]

Options:
  --check    Report whether tools for currently implemented agents are ready.
  --install  Install missing tools with a supported system package manager.
  --yes      Skip the script's confirmation prompt. Use only after the user has
             explicitly authorised package installation.
  -h, --help Show this help.

Currently provisioned agent tools:
  S11 TLS & Cryptography Security: OpenSSL and testssl.sh
  H1 Reconnaissance: dig, host, whois, ping, traceroute, curl and nc
  S18 Email & Domain Security: dig, whois, curl and OpenSSL

Supported package managers:
  Homebrew (macOS or Linux), apt-get (Debian or Ubuntu)
EOF
}

mode=""
assume_yes=0

while (($#)); do
  case "$1" in
    --check|--install)
      if [[ -n "$mode" ]]; then
        echo "ERROR: choose exactly one of --check or --install" >&2
        exit 2
      fi
      mode="$1"
      ;;
    --yes)
      assume_yes=1
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "ERROR: unknown argument: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
  shift
done

if [[ -z "$mode" ]]; then
  echo "ERROR: choose --check or --install" >&2
  usage >&2
  exit 2
fi

tool_status() {
  local label="$1"
  local executable="$2"
  local version_arg="$3"
  if command -v "$executable" >/dev/null 2>&1; then
    local location version
    location="$(command -v "$executable")"
    if [[ -z "$version_arg" ]]; then
      version=""
    elif [[ "$executable" == "testssl.sh" ]]; then
      version="$($executable "$version_arg" 2>&1 | awk '/testssl\.sh.*version/ { print; exit }')"
    else
      version="$($executable "$version_arg" 2>&1 | awk 'NF { print; exit }')"
    fi
    printf 'READY   %-12s %s\n' "$label" "$location"
    [[ -n "$version" ]] && printf '        %s\n' "$version"
    return 0
  fi
  printf 'MISSING %-12s executable `%s` was not found on PATH\n' "$label" "$executable"
  return 1
}

# label executable version-argument brew-package apt-package
TOOLS=(
  "OpenSSL|openssl|version|openssl@4|openssl"
  "testssl.sh|testssl.sh|--version|testssl|testssl.sh"
  "dig|dig|-v|bind|dnsutils"
  "host|host||bind|dnsutils"
  "whois|whois||whois|whois"
  "curl|curl|--version|curl|curl"
  "nc|nc||netcat|netcat-openbsd"
  "ping|ping|||iputils-ping"
  "traceroute|traceroute|||traceroute"
)

check_tools() {
  local missing=0 entry label executable version_arg
  for entry in "${TOOLS[@]}"; do
    IFS='|' read -r label executable version_arg _ _ <<<"$entry"
    tool_status "$label" "$executable" "$version_arg" || missing=1
  done
  return "$missing"
}

if [[ "$mode" == "--check" ]]; then
  if check_tools; then
    echo "Cyber360 tool check passed."
    exit 0
  fi
  echo "Cyber360 tool check failed: install the missing tools before the class exercise." >&2
  exit 1
fi

declare -a missing_tools=()
for entry in "${TOOLS[@]}"; do
  IFS='|' read -r label executable _ _ _ <<<"$entry"
  command -v "$executable" >/dev/null 2>&1 || missing_tools+=("$entry")
done

if ((${#missing_tools[@]} == 0)); then
  check_tools
  echo "Nothing to install."
  exit 0
fi

package_manager=""
package_field=0
declare -a install_command
if command -v brew >/dev/null 2>&1; then
  package_manager="Homebrew"
  install_command=(brew install)
  package_field=4
elif command -v apt-get >/dev/null 2>&1; then
  package_manager="apt-get"
  install_command=(sudo apt-get install -y)
  package_field=5
else
  echo "ERROR: no supported package manager found." >&2
  echo "Install the missing tools with your operating system's trusted package manager, then rerun --check." >&2
  exit 1
fi

declare -a packages=()
for entry in "${missing_tools[@]}"; do
  IFS='|' read -r label _ _ brew_package apt_package <<<"$entry"
  package="$brew_package"
  ((package_field == 5)) && package="$apt_package"
  if [[ -z "$package" ]]; then
    echo "NOTE: install $label with your operating system; $package_manager does not provide it." >&2
    continue
  fi
  case " ${packages[*]-} " in
    *" $package "*) ;;
    *) packages+=("$package") ;;
  esac
done

if ((${#packages[@]} == 0)); then
  check_tools
  exit 1
fi
install_command+=("${packages[@]}")

echo "Cyber360 will use $package_manager to run:"
printf '  '
printf '%q ' "${install_command[@]}"
printf '\n'

if ((assume_yes == 0)); then
  if [[ ! -t 0 ]]; then
    echo "ERROR: confirmation requires an interactive terminal; rerun with --yes only after explicit authorisation." >&2
    exit 2
  fi
  read -r -p "Install these packages? [y/N] " reply
  case "$reply" in
    y|Y|yes|YES) ;;
    *)
      echo "Installation cancelled."
      exit 1
      ;;
  esac
fi

if [[ "$package_manager" == "apt-get" ]]; then
  sudo apt-get update
fi
"${install_command[@]}"

echo
check_tools

