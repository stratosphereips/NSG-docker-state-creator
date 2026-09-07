#!/usr/bin/env bash
set -euo pipefail

image=${IMAGE_NAME:-nsg-observer:test}
container=${CONTAINER_NAME:-nsg-observer-smoke}
volume=${VOLUME_NAME:-nsg-observer-smoke-data}
build_network=${DOCKER_BUILD_NETWORK:-default}
skip_build=${SKIP_BUILD:-0}
mount_local_observer=${MOUNT_LOCAL_OBSERVER:-0}
tmpdir=
observer_mount_args=()
workload=/opt/nsg-observer/examples/demo-workload.sh

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
if [[ "$mount_local_observer" == 1 ]]; then
    observer_mount_args=(-v "$(pwd)/observer:/opt/nsg-observer:ro" -v "$(pwd)/examples:/nsg-observer-examples:ro")
    workload=/nsg-observer-examples/demo-workload.sh
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
    "${observer_mount_args[@]}" \
    "$image" "$workload"

tmpdir=$(mktemp -d)
docker run --rm -v "$volume:/source:ro" -v "$tmpdir:/result" ubuntu:24.04 \
    bash -c 'cp -a /source/. /result/'

test -s "$tmpdir/supervisor.jsonl"
test -s "$tmpdir/processes.jsonl"
test -s "$tmpdir/files/events.jsonl"
test -s "$tmpdir/files/reconciliation.jsonl"
test -s "$tmpdir/sockets/sockets.jsonl"
test -s "$tmpdir/network/topology.jsonl"
test -s "$tmpdir/bcc/status.jsonl"
test -s "$tmpdir/state/graph.json"
test -s "$tmpdir/state/summary.json"
test -s "$tmpdir/state/embedding.jsonl"
test -s "$tmpdir/trajectory/sequence.jsonl"
test -s "$tmpdir/trajectory/current.json"
test -n "$(find "$tmpdir/trajectory/actions" -type f -name '*.json' -size +0c -print -quit)"
test -n "$(find "$tmpdir/trajectory/states" -type f -name manifest.json -size +0c -print -quit)"
test -n "$(find "$tmpdir/syscalls" -type f -size +0c -print -quit)"
test -n "$(find "$tmpdir/pcap" -type f -size +24c -print -quit)"
test -n "$(find "$tmpdir/zeek" -type f -name '*.log' -size +0c -print -quit)"

grep -q 'workload_started' "$tmpdir/supervisor.jsonl"
grep -q 'nsg-observer-demo' "$tmpdir/files/events.jsonl"
grep -q 'process_seen' "$tmpdir/processes.jsonl"
grep -q 'bpf_filter_ready' "$tmpdir/bcc/status.jsonl"
! grep -q '"event":"unparsed"' "$tmpdir/files/events.jsonl"
! grep -q '"event":"tool_exited"' "$tmpdir/bcc/status.jsonl"
python3 -c 'import json,sys
s=json.load(open(sys.argv[1], encoding="utf-8"))["summary"]
required=("known_networks","known_hosts","controlled_hosts","known_data","known_services","known_blocks")
assert all(key in s for key in required)
assert s["counts"]["known_networks"] >= 1
assert s["counts"]["controlled_hosts"] >= 1' "$tmpdir/state/graph.json"
python3 -c 'import json,sys
from pathlib import Path
root=Path(sys.argv[1])
sequence=[json.loads(line) for line in (root/"sequence.jsonl").read_text().splitlines()]
assert sequence and sequence[0]["kind"] == "state"
actions=[item for item in sequence if item["kind"] == "action"]
assert actions
for item in actions:
    assert item["started_at"] and item["ended_at"]
    assert item["state_before"] and item["state_after"]
    record=json.loads((root/item["record"]).read_text())
    assert record["command"]["shell_text"]
assert json.loads((root/"current.json").read_text())["id"].startswith("state-")' \
    "$tmpdir/trajectory"

echo "Smoke test passed. Captured artifacts:"
find "$tmpdir" -maxdepth 3 -type f -printf '%P %s bytes\n' | sort
