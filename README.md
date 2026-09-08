# NSG Docker State Creator

NSG Docker State Creator turns an Ubuntu-based image into a self-observing
container. The workload and all collectors run in the **same container**. It
records processes, syscalls, file activity and state, sockets, ports, packets,
Zeek protocol logs, interactive shell history, and an agent-readable state
graph inferred from those observations. It also passively builds an immutable
`state, action, state, ...` trajectory without modifying or launching the
observed agent.

This project intentionally does not collect CPU or memory utilization.

## What is captured

| Area | Capture mechanism | Output |
|---|---|---|
| Workload syscalls | `strace -ff` with timestamps, durations, paths and file descriptors | `syscalls/trace.*` |
| All visible processes | `/proc` lifecycle polling; libbpf/BCC `execsnoop` when available | `processes.jsonl`, `bcc/` |
| File events | Recursive inotify create/write/move/delete/attribute events | `files/events.jsonl` |
| File state | Periodic metadata and SHA-256 reconciliation | `files/reconciliation.jsonl` |
| Connections and ports | Repeated `ss` connection/listener inventory in the container network namespace | `sockets/sockets.jsonl` |
| Network knowledge | Interfaces, addresses, routes, neighbors, iptables and nftables snapshots | `network/topology.jsonl` |
| Network protocols | Zeek on the container network namespace | `zeek/*.log` |
| Packets | Bounded rotating `tcpdump` ring | `pcap/traffic.pcap*` |
| Interactive commands | `script` TTY input/output, persistent Bash history, command exit status | `tty/` |
| Supervisor state | Lifecycle and health records | `supervisor.jsonl`, `health.json` |
| Inferred world state | Confidence-bearing property graph, compact summary, embedding documents | `state/graph.json`, `state/summary.json`, `state/embedding.jsonl` |
| Passive actions and state transitions | Bash boundaries, process trees, exec events, and syscall activity correlated with material graph changes | `trajectory/sequence.jsonl`, `trajectory/actions/`, `trajectory/states/`, `trajectory/deltas/` |

The observation directory itself is excluded from file monitoring; otherwise
recording a file event would recursively generate another file event.

## Quick start

Step 1: build the image once:

```bash
docker build --network=host -t nsg-observer:local .
```

The `--network=host` option is only for the build step. It helps Docker reach
Ubuntu package mirrors when Docker's isolated build DNS is unreliable.

Step 2: choose one run mode.

Use this for a detached monitored Ubuntu container that you can enter with
`docker exec` and run commands by hand. This example writes directly into the
repo folder `observation/manual-run`:

```bash
docker network inspect nsg-observer-internet >/dev/null 2>&1 || \
  docker network create nsg-observer-internet
mkdir -p observation/manual-run

docker run -d \
  --name nsg-observer-manual \
  --network nsg-observer-internet \
  --privileged \
  --security-opt seccomp=unconfined \
  -v "$(pwd)/observation/manual-run:/observation" \
  -v /lib/modules:/lib/modules:ro \
  -v /usr/src:/usr/src:ro \
  nsg-observer:local sleep infinity
```

The dedicated user-defined bridge keeps the container in its own network
namespace while Docker provides outbound NAT and DNS. It is not host networking.
This also avoids relying on Docker's legacy default `bridge`, whose NAT rules may
be missing or overridden on hosts that run firewall or network-lab software.

Enter the running container and create some file, process, and internet
activity:

```bash
docker exec -it nsg-observer-manual bash
```

Inside the container, try:

```bash
hostname
id
mkdir -p /tmp/nsg-demo
echo "hello from monitored docker" > /tmp/nsg-demo/hello.txt
curl -I https://example.com
getent hosts example.com
ping -c 1 1.1.1.1
ss -tuna
exit
```

Or use Compose instead for the bundled automated demo workload:

```bash
docker compose up --build --abort-on-container-exit
```

Do not run both unless you intentionally want two separate demonstrations.
`docker run` is for your manual session. `docker compose up` is only a shortcut
that builds the same image and runs `examples/demo-workload.sh`.

Step 3: inspect the result without adding tools to the observed container:

```bash
find observation/manual-run -maxdepth 3 -type f -ls
```

Read the live state and action sequence from outside the container:

```bash
jq . observation/manual-run/state/summary.json
tail -n 20 observation/manual-run/trajectory/sequence.jsonl
jq . observation/manual-run/trajectory/current.json
```

Read the same state and action sequence from inside the container:

```bash
docker exec -it nsg-observer-manual bash
jq . /observation/state/summary.json
tail -n 20 /observation/trajectory/sequence.jsonl
jq . /observation/trajectory/current.json
exit
```

Stop the manual example when finished:

```bash
docker rm -f nsg-observer-manual
```

To verify internet access independently of the observer:

```bash
docker exec nsg-observer-manual ip route
docker exec nsg-observer-manual getent hosts example.com
docker exec nsg-observer-manual curl -I --max-time 10 https://example.com
```

If DNS resolves but HTTPS times out, inspect the host's `DOCKER-USER` firewall
chain and Docker NAT rules. Those host rules are outside the image and can block
outbound container traffic even when the container configuration is correct.

## Agent state graph

`state-builder` continuously turns the raw observations into a directed
property graph. Its central node is `agent:observed`; it links to everything
the agent can reasonably be said to know and distinguishes observation from
inference. Every output, even the smallest level, contains:

- known networks;
- known hosts;
- controlled hosts;
- known data, indexed by host;
- known services, indexed by host;
- known or suspected blocks.

Select one of three detail levels with `OBS_STATE_LEVEL`:

| Level | Intended use |
|---|---|
| `forensic` | Process instances, flows, all selected data, full source records in evidence |
| `operational` | Programs, aggregate flows, configured data filters, bounded evidence references (default) |
| `strategic` | Only compact topology, access, important data, services, and block conclusions |

### Use state inside the monitored Docker

The default entrypoint starts `state-builder --watch` in the same Docker as the
workload. An agent running in that Docker reads the latest atomically-written
state directly; it does not need a network API or another container:

```bash
jq '.known_networks' /observation/state/summary.json
jq '.nodes[] | select(.type == "host")' /observation/state/graph.json
```

Set `OBS_STATE_LEVEL=strategic` when the in-container agent only needs the six
core state categories.

### Build or replay state outside the monitored Docker

An external controller uses the same `state-builder` binary and the same
observation directory. This is useful for a forensic rebuild after a run, or
for a second graph detail level:

```bash
docker run --rm \
  --entrypoint state-builder \
  -v "$(pwd)/observation/manual-run:/observation" \
  nsg-observer:local \
  --input /observation --output /observation/state-forensic --level forensic
```

The embedded builder owns `/observation/state`. External builds must write to a
different directory such as `/observation/state-forensic` or
`/observation/state-external`; do not run two writers against the same output
directory.

The JSONL embedding view is not an embedding itself. It is a stable stream of
short node and edge documents ready to send to a future embedding model. See
[State graph](docs/STATE_GRAPH.md) for schema, inference rules, custom file
filters, assertions, and examples.

## Passive state/action trajectory

`trajectory-monitor` runs beside the other collectors. It does not wrap,
instrument, call, or require cooperation from the agent. It infers actions
from these already-collected signals:

- exact start/completion boundaries for an interactive Bash command;
- a new child process launched by a persistent program or shell;
- cgroup-filtered eBPF exec events as a fallback for very short processes;
- grouped network connects and file mutations made inside a long-running
  process without spawning a command.

Every action is stored, including actions which do not change the selected
state. By default, only a semantic change to one of the six core graph domains
creates a new immutable state. This yields a sequence such as:

```json
{"sequence":0,"kind":"state","id":"state-000000"}
{"sequence":1,"kind":"action","action_type":"generic_command","state_before":"state-000000","state_after":"state-000000","state_changed":false}
{"sequence":2,"kind":"action","action_type":"network_scan","state_before":"state-000000","state_after":"state-000001","state_changed":true}
{"sequence":3,"kind":"state","id":"state-000001","trigger_action_ids":["action:process:..."]}
```

Use `/observation/trajectory/sequence.jsonl` as the ordered index. It points to
complete action records and immutable state graph snapshots. An agent inside
the observed container can read it directly:

```bash
tail -n 10 /observation/trajectory/sequence.jsonl
jq . /observation/trajectory/current.json
```

An external controller reads the same files through the evidence volume. It
can also run a separate live monitor, using a different output directory:

```bash
docker run --rm \
  --entrypoint trajectory-monitor \
  -v "$(pwd)/observation/manual-run:/observation" \
  nsg-observer:local \
  --input /observation --output /observation/trajectory-external \
  --level operational --sensitivity material --watch
```

Do not have two trajectory monitors write to the same output path. The
embedded monitor owns `/observation/trajectory`. See
[Passive action trajectories](docs/ACTIONS_TRAJECTORY.md) for the complete
format, inference rules, timing model, sensitivity configuration, and limits.

## Add observation to another image

For another Ubuntu 24.04 image, rebuild this Dockerfile on top of it:

```bash
docker build \
  --build-arg BASE_IMAGE=other-owner/their-image:tag \
  -t their-image-observed:tag \
  .
```

Run the derived image using the original image's command:

```bash
mkdir -p observation/their-run

docker run --rm \
  --privileged \
  --security-opt seccomp=unconfined \
  -v "$(pwd)/observation/their-run:/observation" \
  -v /lib/modules:/lib/modules:ro \
  -v /usr/src:/usr/src:ro \
  their-image-observed:tag \
  /path/to/original-program --original-argument
```

The command after the image name is important: this project replaces the
original entrypoint so it can start observation before the workload. See
[Integrating other images](docs/INTEGRATION.md) for Compose, non-root users,
Ubuntu versions, and entrypoint handling.

## Configuration

All switches are environment variables:

| Variable | Default | Meaning |
|---|---:|---|
| `OBS_OUTPUT_DIR` | `/observation` | Persistent output directory |
| `OBS_ENABLE_STRACE` | `1` | Trace every syscall of the launched workload tree |
| `OBS_ENABLE_BCC` | `1` | Capture eBPF exec/open events for the container cgroup |
| `OBS_ENABLE_FILE_EVENTS` | `1` | Enable recursive inotify events |
| `OBS_ENABLE_STATE_RECONCILIATION` | `1` | Periodically hash filesystem state |
| `OBS_SNAPSHOT_INTERVAL` | `30` | Seconds between reconciliation scans |
| `OBS_HASH_MAX_BYTES` | `0` | Largest file to hash; zero means unlimited |
| `OBS_ARCHIVE_CHANGED_FILES` | `0` | Copy changed contents into SHA-256 object storage |
| `OBS_ENABLE_ZEEK` | `1` | Enable live Zeek analysis |
| `OBS_ENABLE_PCAP` | `1` | Enable rotating packet capture |
| `OBS_ENABLE_NETWORK_TOPOLOGY` | `1` | Snapshot addresses, routes, neighbors, and firewall policy |
| `OBS_NETWORK_INTERVAL` | `10` | Seconds between topology snapshots; unchanged snapshots are not repeated |
| `OBS_INTERFACE` | `any` | Interface used by Zeek and tcpdump |
| `OBS_PCAP_FILE_MB` | `100` | Size of each rotating PCAP segment |
| `OBS_PCAP_FILE_COUNT` | `10` | Number of PCAP segments retained |
| `OBS_ENABLE_TTY_RECORDING` | `1` | Record the initial interactive terminal |
| `OBS_ENABLE_STATE_GRAPH` | `1` | Continuously compile the inferred graph |
| `OBS_STATE_LEVEL` | `operational` | `forensic`, `operational`, or `strategic` graph detail |
| `OBS_STATE_INTERVAL` | `10` | Seconds between graph rebuilds |
| `OBS_ENABLE_TRAJECTORY` | `1` | Build the passive state/action/state sequence |
| `OBS_TRAJECTORY_SENSITIVITY` | `material` | `always`, `material`, or `critical` snapshot policy |
| `OBS_TRAJECTORY_SETTLE_SECONDS` | `2` | Wait after an action for resulting evidence to arrive |
| `OBS_TRAJECTORY_POLL_INTERVAL` | `0.2` | Seconds between action-source polls |
| `OBS_EXCLUDE_PATHS` | empty | Additional colon-separated filesystem exclusions |
| `OBS_WORKLOAD_USER` | empty | Run the workload as `user`, `uid`, `user:group`, or `uid:gid` while keeping collectors privileged |

Set a switch to `0` to disable that collector.

## Test

The smoke test builds the image, runs process/file/network activity, and checks
that all principal artifacts were produced:

```bash
bash tests/smoke.sh
```

Run the deterministic graph extraction tests without Docker:

```bash
make state-test
```

Or, on a minimal host without `make`:

```bash
python3 -m unittest -v tests/test_state_graph.py tests/test_trajectory.py
```

If Docker's isolated build network cannot resolve package mirrors, use:

```bash
DOCKER_BUILD_NETWORK=host bash tests/smoke.sh
```

If a dependency image was already built and you only need to test the current
working tree code, run:

```bash
SKIP_BUILD=1 MOUNT_LOCAL_OBSERVER=1 bash tests/smoke.sh
```

## Accuracy boundary

The launched workload and its descendants receive full syscall tracing.
Processes injected later with `docker exec` are visible to the process poller
and, when BCC is supported by the host kernel, to the cgroup-filtered BCC
or libbpf probes. Their entire syscall stream is not attached to the original `strace`
tree. Likewise, inotify reports paths and operations but not the responsible
PID; the syscall/BCC streams provide that attribution by time correlation.
File reads and opens are captured by `strace` and BCC `opensnoop`; the inotify
stream focuses on file changes to avoid self-generated read noise from the
reconciliation scanner.

Encrypted application payloads remain encrypted in PCAP and Zeek output.
Short-lived events may be lost if the kernel, BPF, packet, or inotify queues
overflow. File-state reconciliation and explicit health records make those
gaps detectable rather than silently claiming perfect capture.

See [Architecture](docs/ARCHITECTURE.md) for the detailed design and operational
limitations.

# About

This tool was developed at the Stratosphere Laboratory at the Czech Technical
University in Prague.
