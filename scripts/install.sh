#!/usr/bin/env bash
# =============================================================================
# install.sh: Local Collection and Extraction Pipeline Installation Script
# =============================================================================
#
# What this script does:
#   1. Checks for Python 3.
#   2. Creates a virtual environment at collection/.venv.
#   3. Installs the pinned dependencies from requirements.txt.
#   4. Generates this node's Ed25519 signing key pair, if one doesn't
#      already exist.
#   5. Prints the resolved paths this component will use.
#
# Usage:
#   bash scripts/install.sh
# =============================================================================

set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
info()    { echo -e "${CYAN}[INFO]${NC}  $*"; }
success() { echo -e "${GREEN}[OK]${NC}    $*"; }
warn()    { echo -e "${YELLOW}[WARN]${NC}  $*"; }
error()   { echo -e "${RED}[ERROR]${NC} $*" >&2; exit 1; }

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VENV_DIR="$REPO_ROOT/collection/.venv"

command -v python3 >/dev/null 2>&1 || error "python3 not found. Install Python 3 first."
info "Using $(python3 --version)"

if [ ! -d "$VENV_DIR" ]; then
    info "Creating virtual environment at $VENV_DIR"
    python3 -m venv "$VENV_DIR"
else
    info "Virtual environment already exists at $VENV_DIR"
fi

info "Installing dependencies from requirements.txt"
"$VENV_DIR/bin/pip" install --quiet --upgrade pip
"$VENV_DIR/bin/pip" install --quiet -r "$REPO_ROOT/requirements.txt"
success "Dependencies installed"

info "Generating this node's signing key, if needed"
PYTHONPATH="$REPO_ROOT" "$VENV_DIR/bin/python" -c "
from collection.keys import load_or_create_node_key, node_fingerprint
key = load_or_create_node_key()
print('Node fingerprint:', node_fingerprint(key))
"
success "Signing key ready"

info "Resolved configuration:"
PYTHONPATH="$REPO_ROOT" "$VENV_DIR/bin/python" -c "
from collection.config import ConfigNotFoundError, resolve_flod_db_path, resolve_key_dir, resolve_sink_path
checks = [
    ('FLOD database', resolve_flod_db_path),
    ('Observation sink', resolve_sink_path),
    ('Key directory', resolve_key_dir),
]
for name, resolver in checks:
    try:
        resolved = resolver()
        print(f'  {name}: {resolved.value} ({resolved.source})')
    except ConfigNotFoundError as e:
        print(f'  {name}: not found ({e})')
"

success "Install complete"
