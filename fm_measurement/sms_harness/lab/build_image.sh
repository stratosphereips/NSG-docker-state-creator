#!/usr/bin/env bash
# build_image.sh — build + smoke scl-fm-lab-server-0.1-opencode:0.1 (DESIGN §1).
#
# Steps:
#   0. Ensure the stock opencode base image exists (build it if missing).
#   1. Verify the image-name transform by IMPORTING the plugin's
#      images.get_opencode_image_name and asserting equality with
#      'scl-fm-lab-server-0.1-opencode:0.1'. (The import works as-is: the plugin
#      modules resolve their 'app' shim themselves; they do print banner lines to
#      stdout, so we capture the value via a marker line, not raw stdout.)
#   2. docker build -t <name>.
#   3. Smoke: run the image with the base entrypoint's env contract, then assert
#      /health TOKEN= via nginx, PostgreSQL accepting queries, and opencode :4096.
set -Eeuo pipefail

HARNESS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
IMAGE_DIR="$HARNESS_DIR/lab/images/scl-fm-lab-server"
PLUGIN_DIR="/home/diego/SCLT/stratocyberlab/plugins/network-topology"
OPENCODE_BASE="scl-plugin-network-topology-ubuntu-opencode:0.1"
TARGET="scl-fm-lab-server-0.1-opencode:0.1"
SMOKE_NAME="fm-img-smoke"

log(){ echo "[build_image] $*"; }
err(){ echo "[build_image][ERROR] $*" >&2; }
trap 'err "failed at line $LINENO (exit $?)"' ERR

# ── 0. Base image present? If not, build it from its static dir. ───────────────
if ! docker image inspect "$OPENCODE_BASE" >/dev/null 2>&1; then
  log "base image $OPENCODE_BASE missing — building it first (slow) ..."
  docker build -t "$OPENCODE_BASE" "$PLUGIN_DIR/images/scl-plugin-network-topology-ubuntu-opencode"
fi

# ── 1. Verify the plugin name transform by real import. ────────────────────────
log "verifying plugin get_opencode_image_name transform ..."
RESOLVED="$(cd "$PLUGIN_DIR" && python3 - <<'PY'
from images import get_opencode_image_name
print("RESULT:" + get_opencode_image_name("scl-fm-lab-server:0.1"))
PY
)"
RESOLVED="${RESOLVED##*RESULT:}"
RESOLVED="${RESOLVED%%$'\n'*}"
RESOLVED="${RESOLVED//[[:space:]]/}"
if [ "$RESOLVED" != "$TARGET" ]; then
  err "name mismatch: plugin resolved '$RESOLVED' != expected '$TARGET'"
  exit 1
fi
log "transform verified: $RESOLVED"

# ── 2. Build. nohup pattern if the build exceeds the 600 s tool budget. ────────
log "building $TARGET ..."
BUILD_LOG="${BUILD_LOG:-/tmp/fm-lab-build.log}"
if docker build -t "$TARGET" "$IMAGE_DIR" >"$BUILD_LOG" 2>&1; then
  log "build done (log: $BUILD_LOG)"
else
  err "build failed — tail of $BUILD_LOG:"
  tail -50 "$BUILD_LOG" >&2 || true
  exit 1
fi
docker image inspect "$TARGET" --format 'built: {{.Id}}'

# ── 3. Smoke run (base entrypoint env contract). ───────────────────────────────
log "smoke run $SMOKE_NAME ..."
docker rm -f "$SMOKE_NAME" >/dev/null 2>&1 || true
docker run -d --name "$SMOKE_NAME" \
  -e SSH_COMPROMISED_PASS=x -e RUN_ID=smoke -e OPENCODE_API_KEY=x \
  "$TARGET" >/dev/null

cleanup(){ docker rm -f "$SMOKE_NAME" >/dev/null 2>&1 || true; }
trap cleanup EXIT INT TERM

FAIL=0
log "waiting 20 s for services ..."
sleep 20

# 3a. /health through nginx :80 contains TOKEN=
BODY="$(docker exec "$SMOKE_NAME" curl -s --max-time 5 http://localhost:80/health || true)"
if printf '%s' "$BODY" | grep -q 'TOKEN='; then
  log "PASS http /health: $BODY"
else
  err "FAIL http /health: got '$BODY'"
  FAIL=1
fi

# 3b. PostgreSQL accepts queries
if docker exec "$SMOKE_NAME" su postgres -c "psql -tAc 'select 1'" 2>/dev/null | grep -q 1; then
  log "PASS postgres: select 1 ok"
else
  err "FAIL postgres: select 1"
  FAIL=1
fi

# 3c. opencode serving on :4096
OC="$(docker exec "$SMOKE_NAME" curl -s -o /dev/null -w '%{http_code}' --max-time 5 http://localhost:4096/health || true)"
if [ "$OC" = "200" ]; then
  log "PASS opencode :4096 health 200"
else
  err "FAIL opencode :4096 health (got '$OC')"
  FAIL=1
fi

# Bonus (non-gating): SQLi dump sanity
SQLI="$(docker exec "$SMOKE_NAME" curl -s --max-time 5 --get --data-urlencode "q=' OR 1=1 --" http://localhost:80/search || true)"
if printf '%s' "$SQLI" | grep -q 'FLAG{fm_lab_win_flag_sqli}'; then
  log "PASS sqli dump contains win flag"
else
  err "NOTE sqli dump did not contain win flag (non-gating): '$SQLI'"
fi

if [ "$FAIL" -ne 0 ]; then
  err "SMOKE FAILED"
  exit 1
fi
log "SMOKE OK — image $TARGET ready"
docker image inspect "$TARGET" --format '{{.Id}}'
