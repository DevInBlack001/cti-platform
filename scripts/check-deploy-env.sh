#!/usr/bin/env bash
# =============================================================================
# check-deploy-env.sh: Refuses to start the OpenCTI deployment with
# leftover placeholder credentials from deploy/.env.example still in
# deploy/.env.
#
# What this script does:
#   1. Confirms deploy/.env exists.
#   2. Scans it for every value deploy/.env.example ships as a
#      placeholder ("changeme", "ChangeMe...") and lists which
#      variables still carry one.
#   3. Exits non-zero with a clear message if any are found, exits 0
#      if every placeholder has been replaced.
#
# Usage:
#   bash scripts/check-deploy-env.sh
# =============================================================================

set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; CYAN='\033[0;36m'; NC='\033[0m'
info()    { echo -e "${CYAN}[INFO]${NC}  $*"; }
success() { echo -e "${GREEN}[OK]${NC}    $*"; }
error()   { echo -e "${RED}[ERROR]${NC} $*" >&2; }

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ENV_FILE="$REPO_ROOT/deploy/.env"

[ -f "$ENV_FILE" ] || {
    error "$ENV_FILE not found. Copy deploy/.env.example to deploy/.env and fill in real values first."
    exit 1
}

info "Checking $ENV_FILE for leftover placeholder values"

# Every variable deploy/.env.example ships with a "changeme"-style
# placeholder, checked here by its exact variable name, so only these
# specific variables ever get flagged, keeping any other value
# elsewhere in the file that happens to contain the word "change" out
# of scope.
PLACEHOLDER_VARS=(
    MINIO_ROOT_PASSWORD
    RABBITMQ_DEFAULT_PASS
    OPENCTI_ADMIN_PASSWORD
    OPENCTI_ADMIN_TOKEN
    OPENCTI_HEALTHCHECK_ACCESS_KEY
    OPENCTI_ENCRYPTION_KEY
)

found_placeholder=0
for var in "${PLACEHOLDER_VARS[@]}"; do
    value="$(grep -E "^${var}=" "$ENV_FILE" 2>/dev/null | cut -d= -f2- || true)"
    if [ -z "$value" ] || [[ "$value" == *"changeme"* ]] || [[ "$value" == *"ChangeMe"* ]]; then
        error "$var is still a placeholder value in $ENV_FILE"
        found_placeholder=1
    fi
done

if [ "$found_placeholder" -ne 0 ]; then
    error "Generate real values for every variable listed above before running docker compose up. See deploy/.env.example's own comments for how to generate each one."
    exit 1
fi

success "No placeholder credentials found in $ENV_FILE"
