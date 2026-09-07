# NSG Docker State Creator

NSG Docker State Creator turns an Ubuntu-based image into a self-observing
container. The workload and all collectors run in the **same container**. It
records processes, syscalls, file activity and state, sockets, ports, packets,
Zeek protocol logs, interactive shell history, and an agent-readable state
graph inferred from those observations.

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

The observation directory itself is excluded from file monitoring; otherwise
recording a file event would recursively generate another file event.

## Quick start

Build the image:

```bash
docker build -t nsg-observer:local .
```

Run a command inside the observed container:

```bash
docker volume create nsg-observation

docker run --rm -it \
  --privileged \
  --security-opt seccomp=unconfined \
  -v nsg-observation:/observation \
  -v /lib/modules:/lib/modules:ro \
  -v /usr/src:/usr/src:ro \
  nsg-observer:local bash
```

Run the bundled demonstration with Compose:

```bash
docker compose up --build --abort-on-container-exit
```

Inspect the result without adding tools to the observed container:

```bash
docker run --rm -it \
  -v nsg-observation:/observation:ro \
  ubuntu:24.04 find /observation -maxdepth 3 -type f -ls
```

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

Build any level again from an existing observation directory:

```bash
docker run --rm \
  --entrypoint state-builder \
  -v nsg-observation:/observation \
  nsg-observer:local \
  --input /observation --output /observation/state-forensic --level forensic
```

The JSONL embedding view is not an embedding itself. It is a stable stream of
short node and edge documents ready to send to a future embedding model. See
[State graph](docs/STATE_GRAPH.md) for schema, inference rules, custom file
filters, assertions, and examples.

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
docker run --rm \
  --privileged \
  --security-opt seccomp=unconfined \
  -v their-observation:/observation \
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
python3 -m unittest -v tests/test_state_graph.py
```

If Docker's isolated build network cannot resolve package mirrors, use:

```bash
DOCKER_BUILD_NETWORK=host bash tests/smoke.sh
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
