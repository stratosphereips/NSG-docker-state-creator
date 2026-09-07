#!/usr/bin/env bash
set -eu

mkdir -p /tmp/nsg-observer-demo
printf 'created at %s\n' "$(date --iso-8601=seconds)" > /tmp/nsg-observer-demo/example.txt
mv /tmp/nsg-observer-demo/example.txt /tmp/nsg-observer-demo/renamed.txt
chmod 640 /tmp/nsg-observer-demo/renamed.txt
timeout 5 getent hosts example.com >/dev/null || true
curl --max-time 10 -fsS https://example.com/ >/tmp/nsg-observer-demo/example.html || true
python3 -m http.server 18080 --directory /tmp/nsg-observer-demo >/tmp/nsg-demo-http.log 2>&1 &
server_pid=$!
sleep 1
curl --max-time 3 -fsS http://127.0.0.1:18080/renamed.txt >/dev/null || true
kill "$server_pid"
wait "$server_pid" 2>/dev/null || true
rm -f /tmp/nsg-observer-demo/renamed.txt
sleep "${DEMO_HOLD_SECONDS:-20}"
