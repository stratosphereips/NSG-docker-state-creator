# Architecture

## Runtime model

`observe-entrypoint` becomes PID 1. It creates the output tree, starts every
enabled collector, waits for a short warm-up period, and only then executes the
requested workload. Signals are forwarded to process groups and collectors are
given time to flush when the workload exits.

`network-monitor` snapshots network configuration and `state-builder` compiles
all available observations into a fresh graph at a configurable interval. The
compiler also runs once when it receives a shutdown signal, subject to the
supervisor's flush deadline.

`trajectory-monitor` independently tails the append-only observations. It
identifies action boundaries, waits briefly for delayed Zeek, socket, file, and
process evidence, recompiles the graph, and records the action between its
before and after state identifiers. It never controls the workload.

The implementation deliberately stays in one container and uses that
container's mount, PID, user and network namespaces. The eBPF/BCC components
interact with the shared Linux kernel, but their pinned cgroup map filters
events to the current container's cgroup.

## Event sources

### Syscalls

The workload is launched under:

```text
strace -ff -ttt -T -yy -s 4096 -o /observation/syscalls/trace -- WORKLOAD
```

`-ff` follows forks and creates one trace file per traced PID. Absolute epoch
timestamps permit correlation with JSON and Zeek records. File-descriptor path
decoding and syscall duration are enabled.

### Processes

`process-monitor` scans the container's `/proc` every 100 ms by default. A
process identity consists of PID plus kernel start ticks, preventing PID reuse
from joining unrelated processes. It records credentials, capabilities,
security settings, command line, executable, working directory, controlling
TTY, cgroup, login UID and lifecycle.

The BCC monitor creates a pinned BPF hash containing the current cgroup ID,
then runs filtered eBPF helpers. It prefers Ubuntu's libbpf CO-RE `execsnoop`
for process execution and uses BCC `opensnoop-bpfcc` for cgroup-filtered file
opens. Network activity is captured in the container network namespace by
`ss`, Zeek and tcpdump rather than by unfiltered host-wide TCP BPF tools.
These probes are supplementary: they may require
matching host kernel headers under `/lib/modules` and `/usr/src`, BTF support,
and a writable BPF filesystem. A failure is written to `bcc/status.jsonl`; it
does not prevent the other collectors or workload from running.

### Files

`filesystem-monitor` recursively watches every top-level directory except:

- `/proc`
- `/sys`
- `/dev`
- `/run`
- the configured observation directory
- paths in `OBS_EXCLUDE_PATHS`

It emits create, modify, close-write, attribute, move and delete events.
Directories created inside a watched tree are automatically watched by inotify.
File reads and opens are covered by `strace` and BCC `opensnoop`; they are not
enabled in inotify because the reconciliation scanner would otherwise generate
continuous observer-caused read noise.

`state-reconciler` independently walks the same filesystem, records metadata,
and hashes regular files. It produces added, changed and deleted records. With
`OBS_ARCHIVE_CHANGED_FILES=1`, changed regular files are copied to:

```text
/observation/snapshots/objects/SHA256_PREFIX/SHA256
```

The archive is content-addressed and de-duplicated.

### Network

Zeek and tcpdump both capture from `OBS_INTERFACE`, which defaults to Linux's
`any` pseudo-interface. Because they run in the workload container's network
namespace, they observe that namespace's Ethernet and loopback traffic.

Zeek writes JSON protocol logs. Tcpdump writes a rotating PCAP ring bounded by
`OBS_PCAP_FILE_MB * OBS_PCAP_FILE_COUNT`. `socket-monitor` records connections
and listeners reported by `ss`, including process information where the kernel
permits it.

`network-monitor` records `ip -j` interface, route, and neighbor output. It also
records IPv4/IPv6 iptables-save output and the nftables JSON ruleset. A SHA-256
of each complete snapshot suppresses identical repetitions.

### Commands and sessions

When the container is started interactively, the requested command is wrapped
with util-linux `script`, producing separate input, output and timing streams.
Interactive Bash instances source `bash-observer.sh`, which writes unlimited,
timestamped history immediately after every prompt. A silent `PS0` hook writes
`action_started` immediately before Bash executes a command; `PROMPT_COMMAND`
writes the matching `command_completed`, working directory, and exit status.
The stable action ID joins both boundaries. This is shell-wide configuration,
not a wrapper around an individual user or agent. A successful `ssh`, `scp`,
or `sftp` command can therefore support a controlled-host inference.

Do not place secrets directly in command-line arguments. They will appear in
the syscall, process and history logs. TTY recordings may also contain secrets
entered while terminal echo is enabled.

## State graph

The compiler uses a directed property graph with stable IDs. The observed agent
is linked to known entities using `KNOWS_HOST`, `KNOWS_NETWORK`, `KNOWS_DATA`,
`KNOWS_SERVICE`, and `KNOWS_BLOCK`. Host-indexed facts use `STORES_DATA` and
`HOSTS_SERVICE`; control is represented explicitly with `CONTROLS`.

Each entity and relation has a confidence, observation count, source-file set,
and first/last timestamps when supplied by the source. Detail profiles decide
whether evidence contains full records, file/line references, or only counts.
Raw claims never silently become facts: network timeouts and unanswered Zeek
flows are block hypotheses, while an iptables DROP rule is near-certain local
policy evidence. See [State graph](STATE_GRAPH.md).

## Passive action trajectory

Action detection is deliberately multi-source. Bash supplies exact human
command text and exit status. The process collector identifies child commands
of persistent agent roots. Strace attaches their network and file effects and
also groups direct syscalls from long-running agents into inferred actions.
Cgroup-filtered execsnoop is used only when container/host PID mapping is
available and the structured process stream missed an exec.

Actions can overlap. Each record has an actor identity, start/end event time,
detection and recording time, concurrent action IDs, evidence references, and
before/after state IDs. When overlapping actions precede one graph update, the
delta names every contributing action and marks causal isolation false.

The semantic change detector projects only configured graph domains, removes
volatile timestamps and evidence counters, and buckets confidence. Therefore
collecting another copy of identical evidence does not create a fake new
state. See [Passive action trajectories](ACTIONS_TRAJECTORY.md).

## Output durability

Use a named volume or bind mount for `/observation`. Without one, Docker removes
the evidence when a `--rm` container exits. The software does not currently
send data to an external service; copying or shipping this directory is the
operator's responsibility.

## Known limitations

- Docker uses the host kernel. Kernel-level collection therefore requires a
  native Linux Docker host and elevated capabilities.
- `strace` follows the initial workload tree, not unrelated processes injected
  later through the Docker API.
- `/proc` and socket polling can miss processes or connections whose complete
  lifetime is shorter than the polling interval; BCC reduces this gap.
- Passive inference cannot always recover application-level intent. A direct
  syscall action has lower confidence than an exact Bash command, and
  overlapping actions may share a resulting state delta.
- Inotify queues can overflow. File hash reconciliation identifies end-state
  differences but cannot reconstruct every intermediate state.
- Memory-mapped writes can be observed by state reconciliation and syscalls
  surrounding the mapping, but not as one syscall per changed byte.
- Zeek and PCAP cannot decrypt TLS without authorized session keys or TLS
  termination.
- A successful TCP connection does not prove remote control. Automatic control
  requires stronger evidence such as Zeek `auth_success`, a successful audited
  SSH-family command, or an explicit assertion.
- A no-reply flow is only a block hypothesis. Packet loss, a down host, routing,
  or a closed application can produce similar symptoms.
- A process may write a filename containing a newline. Inotify's textual output
  cannot represent that path as one unambiguous line; reconciliation still
  observes the resulting file state.
- The observation path is necessarily excluded to prevent recursive event
  generation.
