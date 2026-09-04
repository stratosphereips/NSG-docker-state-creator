#!/usr/bin/env bash
set -euo pipefail

image=${IMAGE_NAME:-nsg-observer:test}
container=${CONTAINER_NAME:-nsg-observer-smoke}
volume=${VOLUME_NAME:-nsg-observer-smoke-data}
build_network=${DOCKER_BUILD_NETWORK:-default}
skip_build=${SKIP_BUILD:-0}
tmpdir=

cleanup() {
    docker rm -f "$container" >/dev/null 2>&1 || true
    docker volume rm "$volume" >/dev/null 2>&1 || true
    if [[ -n "$tmpdir" && -d "$tmpdir" ]]; then
        docker run --rm --entrypoint chown -v "$tmpdir:/result" "$image" \
            -R "$(id -u):$(id -g)" /result >/dev/null 2>&1 || true
        rm -rf "$tmpdir"
    fi
}
trap cleanup EXIT

if [[ "$skip_build" != 1 ]]; then
    docker build --network="$build_network" -t "$image" .
fi
docker volume create "$volume" >/dev/null
docker run --name "$container" \
    --privileged \
    --security-opt seccomp=unconfined \
    -e OBS_SNAPSHOT_INTERVAL=2 \
    -e OBS_HASH_MAX_BYTES=65536 \
    -e OBS_EXCLUDE_PATHS=/usr:/opt/zeek \
    -e DEMO_HOLD_SECONDS=8 \
    -v "$volume:/observation" \
    -v /lib/modules:/lib/modules:ro \
    -v /usr/src:/usr/src:ro \
    "$image" /opt/nsg-observer/examples/demo-workload.sh

tmpdir=$(mktemp -d)
docker run --rm -v "$volume:/source:ro" -v "$tmpdir:/result" ubuntu:24.04 \
    bash -c 'cp -a /source/. /result/'

test -s "$tmpdir/supervisor.jsonl"
test -s "$tmpdir/processes.jsonl"
test -s "$tmpdir/files/events.jsonl"
test -s "$tmpdir/files/reconciliation.jsonl"
test -s "$tmpdir/sockets/sockets.jsonl"
test -s "$tmpdir/bcc/status.jsonl"
test -n "$(find "$tmpdir/syscalls" -type f -size +0c -print -quit)"
test -n "$(find "$tmpdir/pcap" -type f -size +24c -print -quit)"
test -n "$(find "$tmpdir/zeek" -type f -name '*.log' -size +0c -print -quit)"

grep -q 'workload_started' "$tmpdir/supervisor.jsonl"
grep -q 'nsg-observer-demo' "$tmpdir/files/events.jsonl"
grep -q 'process_seen' "$tmpdir/processes.jsonl"
grep -q 'cgroup_filter_ready' "$tmpdir/bcc/status.jsonl"

echo "Smoke test passed. Captured artifacts:"
find "$tmpdir" -maxdepth 3 -type f -printf '%P %s bytes\n' | sort
