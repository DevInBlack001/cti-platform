#!/usr/bin/env bash
# =============================================================================
# check-deploy-env.sh: Refuses to start the OpenCTI deployment with
# leftover placeholder credentials, or with a widened network exposure
# that isn't also using TLS, in deploy/.env.
#
# What this script does:
#   1. Confirms deploy/.env exists.
#   2. Scans it for every value deploy/.env.example ships as a
#      placeholder ("changeme", "ChangeMe...") and lists which
#      variables still carry one.
#   3. If OPENCTI_BIND_ADDRESS has been widened past its safe loopback
#      default, requires OPENCTI_EXTERNAL_SCHEME to be https, since a
#      wider bind address without TLS means administrative traffic
#      (including OPENCTI_ADMIN_TOKEN itself) travels in plaintext to
#      whatever network that bind address now reaches.
#   4. Exits non-zero with a clear message if any check fails, exits 0
#      if every check passes.
#
# Usage:
#   bash scripts/check-deploy-env.sh
# =============================================================================

set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
info()    { echo -e "${CYAN}[INFO]${NC}  $*"; }
success() { echo -e "${GREEN}[OK]${NC}    $*"; }
warn()    { echo -e "${YELLOW}[WARN]${NC}  $*"; }
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

bind_address="$(grep -E "^OPENCTI_BIND_ADDRESS=" "$ENV_FILE" 2>/dev/null | cut -d= -f2- || true)"
bind_address="${bind_address:-127.0.0.1}"

if [ "$bind_address" != "127.0.0.1" ] && [ "$bind_address" != "localhost" ]; then
    scheme="$(grep -E "^OPENCTI_EXTERNAL_SCHEME=" "$ENV_FILE" 2>/dev/null | cut -d= -f2- || true)"
    acknowledged="$(grep -E "^OPENCTI_ACKNOWLEDGE_HTTP_EXPOSURE=" "$ENV_FILE" 2>/dev/null | cut -d= -f2- || true)"
    if [ "$scheme" != "https" ]; then
        if [ "$acknowledged" = "yes" ]; then
            warn "OPENCTI_BIND_ADDRESS is $bind_address over plaintext HTTP; proceeding because OPENCTI_ACKNOWLEDGE_HTTP_EXPOSURE=yes was set explicitly."
        else
            error "OPENCTI_BIND_ADDRESS is set to $bind_address (reachable beyond this host); OPENCTI_EXTERNAL_SCHEME is '$scheme', it needs to be https."
            error "Set OPENCTI_EXTERNAL_SCHEME=https, with a real certificate configured in front of OpenCTI, before widening the bind address, so OPENCTI_ADMIN_TOKEN and every other credential stay off plaintext HTTP. For a bind address confined to a trusted, already-isolated network (this project's own QEMU test VM, reachable only through its own host-only port forward), set OPENCTI_ACKNOWLEDGE_HTTP_EXPOSURE=yes to proceed on that basis."
            exit 1
        fi
    fi
    success "OPENCTI_BIND_ADDRESS is widened to $bind_address"
else
    success "OPENCTI_BIND_ADDRESS stays at its safe loopback default"
fi
