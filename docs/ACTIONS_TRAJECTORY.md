# Passive action and state trajectories

## Purpose

The trajectory layer converts the collector's continuous observations into an
ordered sequence for decision agents:

```text
state-000000 -> action A -> state-000000 -> action B -> state-000001
```

Action A is still recorded even though it did not materially alter the state.
Its `state_before` and `state_after` both refer to `state-000000`. The sequence
does not insert a duplicate state record. Action B caused or coincided with a
semantic state change, so the immutable `state-000001` snapshot follows it.

The observed human or program is not started by this component and does not
call an SDK. `trajectory-monitor` is a silent sibling process that consumes
the existing observation logs.

## What counts as an action

The monitor combines four passive signals, in descending attribution quality:

| Signal | What it detects | Typical confidence |
|---|---|---:|
| Bash `action_started` and `command_completed` | Exact interactive command, start, completion, working directory, user, TTY and exit status | 0.995 |
| Process lifecycle | A child command launched by a persistent shell or program, such as `nmap`, `curl`, or a helper script | 0.94 |
| eBPF exec fallback | A successful, very short exec missed by `/proc` polling | 0.80 |
| Syscall grouping | Network connects or file mutations performed directly by a long-running process | 0.75 |

The command rules in `observer/etc/state-graph.json` classify common tools as
`network_scan`, `network_probe`, `remote_access`, `network_request`,
`file_change`, `data_access`, or `package_change`. Unmatched commands are still
stored as `generic_command`. Rules affect labels, not whether an action is
retained.

Syscall-only activity has no command boundary. Events are grouped by actor and
kind until `inferred_idle_seconds` elapses. Such records explicitly contain
`"inference": true`; consumers should preserve that uncertainty.

Observer processes are excluded using `observer_process_regex`. The BCC
fallback is used only after host and container PIDs can be mapped, preventing
host-wide or observer commands from being guessed as workload actions.

## When a new state is created

`OBS_TRAJECTORY_SENSITIVITY` selects the snapshot policy:

| Policy | Immutable state condition |
|---|---|
| `always` | Every settled action batch gets a state, even if its semantic content is identical |
| `material` | Any configured core domain changes: networks, hosts, controlled hosts, data, services, or blocks (default) |
| `critical` | Only networks, hosts, controlled hosts, or blocks change |

The policy is independent of graph detail. `OBS_STATE_LEVEL` controls how much
each stored graph contains: `forensic`, `operational`, or `strategic`.

Material comparison ignores volatile values such as `generated_at`,
`first_seen`, `last_seen`, evidence arrays/counts, and observation counters.
Confidence is quantized into configurable buckets. A repeated observation of
the same host therefore does not create a state simply because its timestamp
or evidence count increased.

Edit the `trajectory` object in `observer/etc/state-graph.json` to configure:

- `watched_domains` and `critical_domains`;
- `ignore_fields` and `confidence_bucket`;
- action classification `command_rules`;
- polling, settle, inference-idle, batch, and maximum-action windows;
- `use_bcc_exec_fallback`.

The settle window lets file reconciliation, Zeek, sockets, and topology logs
land after a command ends. Actions that complete close together are evaluated
as one batch. This is important when multiple agents act concurrently.

## Output layout

```text
/observation/trajectory/
  sequence.jsonl
  current.json
  runtime-cursor.json
  actions/<hash>.json
  actors/<actor-hash>.jsonl
  deltas/<hash>.json
  states/state-000000/
    manifest.json
    graph.json
    summary.json
    embedding.jsonl
```

`sequence.jsonl` is the append-only ordered index. Each line is either:

```json
{"sequence":0,"kind":"state","id":"state-000000","recorded_at":"2026-09-07T10:00:00.000000Z","manifest":"states/state-000000/manifest.json","graph":"states/state-000000/graph.json"}
```

or:

```json
{"sequence":1,"kind":"action","id":"action:process:...","actor_id":"actor:process:...","action_type":"network_scan","started_at":"2026-09-07T10:00:03.100000Z","ended_at":"2026-09-07T10:00:04.900000Z","state_before":"state-000000","state_after":"state-000001","state_changed":true,"record":"actions/abc123.json"}
```

The action file contains the complete command (`executable`, `argv`, and shell
text), actor/process identity, targets, paths, effects, start/end/detection/
recording times, completion reason, exit status when known, evidence pointers,
children, concurrency, and state references.

When state changes, the corresponding delta contains added, removed, and
changed node/edge IDs plus `changed_domains`. It also contains:

- `contributing_action_ids`, because several actions may settle together;
- `causal_isolation`, which is false when another action overlaps the action.

Do not interpret a shared delta as proof that each concurrent action caused
every graph change.

Each state directory contains exactly the same graph, summary, and
embedding-ready JSONL forms documented in [State graph](STATE_GRAPH.md), plus a
manifest with hashes, policy, timestamp, and trigger action IDs. Files already
referenced by the sequence are immutable.

## Run inside the observed container

This is the default and the recommended mode for correct temporal states.
`observe-entrypoint` starts the monitor before starting the workload:

```bash
mkdir -p observation/manual-run

docker run --rm --privileged --security-opt seccomp=unconfined \
  -e OBS_ENABLE_TRAJECTORY=1 \
  -e OBS_TRAJECTORY_SENSITIVITY=material \
  -e OBS_STATE_LEVEL=operational \
  -v "$(pwd)/observation/manual-run:/observation" \
  nsg-observer:local /path/to/agent
```

Programs inside that container may read the output as ordinary files, but no
agent integration is required:

```bash
tail -n 1 /observation/trajectory/sequence.jsonl
jq . /observation/trajectory/current.json
```

## Run or consume outside the observed container

An external program can consume the named volume read-only at any time. To run
the monitor itself outside, mount the evidence volume and choose a distinct
output directory:

```bash
docker run --rm --entrypoint trajectory-monitor \
  -v "$(pwd)/observation/manual-run:/observation" \
  nsg-observer:local \
  --input /observation \
  --output /observation/trajectory-external \
  --level operational --sensitivity material --watch
```

Only one process may write each trajectory directory. Disable the embedded
instance with `OBS_ENABLE_TRAJECTORY=0` if the outside process should own the
canonical output, or retain both using separate paths.

For faithful `state_before` and `state_after`, the monitor must run live before
actions occur. A command without `--watch` processes available records once;
on completed historical logs it can recover actions, but all graph compilation
sees the already-completed evidence set and cannot manufacture state cutoffs
that were never recorded.

## Time and recovery semantics

Event times (`started_at`, `ended_at`) come from source observations.
`detected_at` records when the monitor recognized an action and `recorded_at`
when it committed it. All timestamps are UTC ISO 8601 and also have nanosecond
integer fields where applicable.

`runtime-cursor.json` stores byte offsets only after complete lines. On restart,
the monitor recovers state/action IDs from `sequence.jsonl`, resumes tailing,
and avoids rewriting committed actions. An unfinished command is finalized as
`monitor-shutdown`; a process disappearance, syscall exit, shell prompt, idle
window, or maximum duration records the corresponding completion reason.

## Accuracy boundary

- Passive observation can identify behavior, but not always the actor's intent.
- `/proc` polling can miss extremely short commands; working eBPF support
  reduces but does not eliminate this risk.
- Processes injected with `docker exec` do not join the initial strace tree;
  process and BCC events still expose execs, but their direct syscall effects
  have less attribution detail.
- Shell command text and terminal streams can contain secrets. Protect the
  evidence volume as sensitive data.
- State changes are correlated to actions, not proven causal. Concurrent
  actions are represented explicitly instead of inventing a single cause.
