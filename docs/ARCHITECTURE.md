# Architecture

## Runtime model

`observe-entrypoint` becomes PID 1. It creates the output tree, starts every
enabled collector, waits for a short warm-up period, and only then executes the
requested workload. Signals are forwarded to process groups and collectors are
given time to flush when the workload exits.

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

The BCC monitor creates a pinned BPF hash containing the current cgroup ID and
runs cgroup-filtered `execsnoop`, `opensnoop`, `tcpconnect`, and `tcpaccept`.
BCC is supplementary: it may require matching host kernel headers under
`/lib/modules` and `/usr/src`, BTF support, and a writable BPF filesystem. A failure is written
to `bcc/status.jsonl`; it does not prevent the other collectors or workload
from running.

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

### Commands and sessions

When the container is started interactively, the requested command is wrapped
with util-linux `script`, producing separate input, output and timing streams.
Interactive Bash instances source `bash-observer.sh`, which writes unlimited,
timestamped history immediately after every prompt.

Do not place secrets directly in command-line arguments. They will appear in
the syscall, process and history logs. TTY recordings may also contain secrets
entered while terminal echo is enabled.

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
- Inotify queues can overflow. File hash reconciliation identifies end-state
  differences but cannot reconstruct every intermediate state.
- Memory-mapped writes can be observed by state reconciliation and syscalls
  surrounding the mapping, but not as one syscall per changed byte.
- Zeek and PCAP cannot decrypt TLS without authorized session keys or TLS
  termination.
- A process may write a filename containing a newline. Inotify's textual output
  cannot represent that path as one unambiguous line; reconciliation still
  observes the resulting file state.
- The observation path is necessarily excluded to prevent recursive event
  generation.
