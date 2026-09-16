#!/usr/bin/env bash
# =============================================================================
# uninstall.sh: Local Collection and Extraction Pipeline Uninstall Script
# =============================================================================
#
# Removes collection/.venv. Leaves this node's signing key pair and any
# already-written observations in place unless --remove-keys is passed,
# since a node's signing identity is not something to delete by accident.
#
# Usage:
#   bash scripts/uninstall.sh [--remove-keys]
# =============================================================================

set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
info()    { echo -e "${CYAN}[INFO]${NC}  $*"; }
success() { echo -e "${GREEN}[OK]${NC}    $*"; }
warn()    { echo -e "${YELLOW}[WARN]${NC}  $*"; }
error()   { echo -e "${RED}[ERROR]${NC} $*" >&2; exit 1; }

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VENV_DIR="$REPO_ROOT/collection/.venv"

REMOVE_KEYS=false
for arg in "$@"; do
    case "$arg" in
        --remove-keys) REMOVE_KEYS=true ;;
        *) error "Unknown option: $arg" ;;
    esac
done

if [ -d "$VENV_DIR" ]; then
    rm -rf "$VENV_DIR"
    success "Removed $VENV_DIR"
else
    info "No virtual environment found at $VENV_DIR, nothing to remove"
fi

if [ "$REMOVE_KEYS" = true ]; then
    KEY_DIR="$(PYTHONPATH="$REPO_ROOT" python3 -c "
from collection.config import resolve_key_dir
print(resolve_key_dir().value)
")"
    if [ -n "$KEY_DIR" ] && [ -d "$KEY_DIR" ]; then
        rm -rf "$KEY_DIR"
        warn "Removed $KEY_DIR. This node will generate a new identity next run."
    else
        info "No key directory found at $KEY_DIR, nothing to remove"
    fi
else
    info "Leaving the signing key and any written observations in place"
    info "Pass --remove-keys to also delete this node's signing identity"
fi

success "Uninstall complete"
