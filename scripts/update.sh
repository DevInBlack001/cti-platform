#!/usr/bin/env bash
# =============================================================================
# update.sh: Local Collection and Extraction Pipeline Update Script
# =============================================================================
#
# Reinstalls dependencies from requirements.txt into the existing virtual
# environment. Does not touch keys, config, or already-written output.
#
# Usage:
#   bash scripts/update.sh
# =============================================================================

set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
info()    { echo -e "${CYAN}[INFO]${NC}  $*"; }
success() { echo -e "${GREEN}[OK]${NC}    $*"; }
warn()    { echo -e "${YELLOW}[WARN]${NC}  $*"; }
error()   { echo -e "${RED}[ERROR]${NC} $*" >&2; exit 1; }

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VENV_DIR="$REPO_ROOT/collection/.venv"

[ -d "$VENV_DIR" ] || error "No virtual environment found at $VENV_DIR. Run scripts/install.sh first."

info "Updating dependencies from requirements.txt"
"$VENV_DIR/bin/pip" install --quiet --upgrade -r "$REPO_ROOT/requirements.txt"
success "Update complete"
