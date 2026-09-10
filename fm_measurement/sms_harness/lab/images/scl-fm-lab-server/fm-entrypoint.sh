#!/bin/bash
# fm-entrypoint.sh — FM lab server entrypoint (sms_harness DESIGN §1).
#
# Starts the lab services (PostgreSQL, Flask, nginx) in the background, waits
# for the web tier, then execs the ORIGINAL opencode base entrypoint
# (/usr/local/bin/entrypoint.sh) which owns the agent stack contract:
#   * requires env SSH_COMPROMISED_PASS (compose-provided) — do NOT break;
#   * RUN_ID (default run_local), OPENCODE_API_KEY;
#   * starts guardrail runtime + opencode serve on 0.0.0.0:4096 and blocks.
#
# The base entrypoint ends in `exec tail -f /dev/null` / `wait`, so it remains
# the container's long-running foreground process (our children survive).
set -Eeuo pipefail

log(){ echo "[fm-entrypoint] $*"; }
err(){ echo "[fm-entrypoint][ERROR] $*" >&2; }
trap 'err "failed at line $LINENO (exit $?)"' ERR

PGVER="$(ls /etc/postgresql | sort -V | tail -1)"

# ── 1. Logs dir ─────────────────────────────────────────────────────────────────
mkdir -p /var/log/fm

# ── 2. PostgreSQL (retry loop: cluster is baked but start can race on fresh
#        container init) ─────────────────────────────────────────────────────────
log "starting PostgreSQL $PGVER/main ..."
i=0
until pg_ctlcluster "$PGVER" main start 2>>/var/log/fm/pg-start.log; do
  i=$((i + 1))
  if [ "$i" -ge 10 ]; then
    err "PostgreSQL failed to start after $i attempts"; exit 1
  fi
  sleep 1
done
log "PostgreSQL up."

# ── 3. Flask app on 127.0.0.1:5001 ────────────────────────────────────────────
log "starting Flask app on 127.0.0.1:5001 ..."
python3 /opt/fm/app.py >>/var/log/fm/flask.log 2>&1 &
echo $! >/var/log/fm/flask.pid

# ── 4. nginx on :80, wait for the web tier (30 s budget) ──────────────────────
log "starting nginx ..."
nginx
log "waiting for :80 ..."
i=0
until curl -sf -o /dev/null http://127.0.0.1:80/; do
  i=$((i + 1))
  if [ "$i" -ge 30 ]; then
    err "web tier did not come up on :80 within 30 s"; exit 1
  fi
  sleep 1
done
log "web tier up on :80."

# ── 5. Hand off to the original opencode base entrypoint (env contract intact) ─
log "handing off to /usr/local/bin/entrypoint.sh $*"
exec /usr/local/bin/entrypoint.sh "$@"
