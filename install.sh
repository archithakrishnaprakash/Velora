#!/usr/bin/env bash
# Velora installer for Kali Linux / Debian-based systems.
# Authorized security assessment tooling. Installs into an isolated virtualenv.
set -euo pipefail

APP="Velora"
VENV="${VELORA_VENV:-$HOME/.local/share/velora/venv}"
BINLINK="${VELORA_BIN:-$HOME/.local/bin/velora}"
PYQ="${PYTHON:-python3}"

say()  { printf '\033[1;34m[*]\033[0m %s\n' "$1"; }
ok()   { printf '\033[1;32m[✓]\033[0m %s\n' "$1"; }
err()  { printf '\033[1;31m[✗]\033[0m %s\n' "$1" >&2; }

# 1. Verify Python version (3.11+).
say "Checking Python version"
if ! "$PYQ" -c 'import sys; raise SystemExit(0 if sys.version_info>=(3,11) else 1)'; then
  err "Python 3.11+ is required. Install it (e.g. apt install python3) and re-run."
  exit 1
fi
ok "Python $("$PYQ" -c 'import sys;print("%d.%d.%d"%sys.version_info[:3])')"

# 2. Verify venv module.
say "Checking python venv support"
"$PYQ" -c 'import venv' 2>/dev/null || { err "python3-venv missing (apt install python3-venv)"; exit 1; }
ok "venv available"

# 3. Create virtual environment.
say "Creating virtualenv at $VENV"
mkdir -p "$(dirname "$VENV")"
"$PYQ" -m venv "$VENV"
# shellcheck disable=SC1091
source "$VENV/bin/activate"
pip install --upgrade pip wheel >/dev/null
ok "virtualenv ready"

# 4. Install the package (from the directory containing this script).
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
say "Installing $APP from $SCRIPT_DIR"
pip install "$SCRIPT_DIR" >/dev/null
ok "package installed"

# 5. Initialize database + config.
say "Initializing configuration and database"
"$VENV/bin/velora" init || true
ok "initialized"

# 6. Link the CLI onto PATH.
say "Linking CLI -> $BINLINK"
mkdir -p "$(dirname "$BINLINK")"
ln -sf "$VENV/bin/velora" "$BINLINK"
case ":$PATH:" in
  *":$(dirname "$BINLINK"):"*) ok "CLI on PATH" ;;
  *) err "Add $(dirname "$BINLINK") to your PATH (e.g. echo 'export PATH=\$PATH:$(dirname "$BINLINK")' >> ~/.bashrc)";;
esac

# 7. Optional desktop entry.
if [ "${VELORA_DESKTOP:-0}" = "1" ] && [ -d "$HOME/.local/share/applications" ]; then
  cat > "$HOME/.local/share/applications/velora.desktop" <<DESKTOP
[Desktop Entry]
Name=Velora
Comment=Authorized web vulnerability assessment
Exec=x-terminal-emulator -e "$BINLINK dashboard"
Terminal=true
Type=Application
Categories=Security;
DESKTOP
  ok "desktop entry created"
fi

# 8. Run doctor.
say "Running velora doctor"
"$VENV/bin/velora" doctor || true

echo
ok "$APP installed. Try: velora --help  |  velora doctor  |  velora dashboard"
echo "Reminder: only test systems you are explicitly authorized to assess."
