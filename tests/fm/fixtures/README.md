# Fixture format (tests/fm/fixtures)

Every fixture case is a plain directory that mimics one `/observation`
evidence directory, loaded with `load_observation(fixture_dir)` (exposed to
tests as `load_fixture(name)` from `tests/fm/conftest.py`). All fixtures are
synthetic — no live agent, no docker.

## Layout of one case

```
<case>/
  supervisor.jsonl                  observe-entrypoint lifecycle events
  processes.jsonl                   /proc census (process-monitor)
  files/events.jsonl                inotify events + monitor lifecycle
  files/reconciliation.jsonl        baseline/scans + file_added/changed/deleted
  sockets/sockets.jsonl             ss connection/listener inventory
  bcc/status.jsonl                  BCC tool lifecycle
  syscalls/trace.<PID>              strace -ff -ttt -T -yy -s 4096 text
  tty/bash-history-<uid>-<ppid>-<pid>.log   "<epoch> <command>" lines
  health.json                       final supervisor status snapshot
```

Any file may be omitted to simulate a missing stream (the loader flags
`stream_missing`, it never crashes). Unknown JSONL event names are kept with
`raw` set, corrupt lines are skipped and flagged `jsonl_corrupt`.

## Envelope

JSONL lines use the documented default envelope written by
`observer/lib/jsonlog.py`:

```json
{"event": "<event_name>", "source": "<collector>", "timestamp": <epoch float>, ...fields}
```

Keys are sorted by the writer. `DEFAULT_ENVELOPE_PINS` in
`analysis/observation.py` pins `event_key="event"`, `time_key="timestamp"`.
`fixtures/envelope/` holds the first lines of every stream in this shape —
currently generated with the reconstructed `jsonlog.py`; per the sequencing
plan it must be re-pinned from one LIVE image run (build the image, run one
workload, copy the first ~20 lines of every stream) before any detector
conclusions are trusted.

## Record shapes to copy

See `analysis/records.py` (frozen dataclasses) and the collector sources in
`observer/bin/*` for exact field names. Notable invariants:

- processes: identity key is `(pid, start_ticks)` with `start_ticks` the RAW
  STRING of /proc stat field 22 — never int-coerce; `process_gone` carries
  only pid/start_ticks/name/cmdline/uid (ppid must come from the last
  seen/changed record).
- reconciliation `state`/`previous_state` are 7-element arrays
  `[mode, uid, gid, size, mtime_ns, ctime_ns, sha256_or_tag]`;
  `baseline_complete` carries only a file COUNT (no manifest).
- strace: `-ttt` epoch prefix on every line, `= -1 ENOENT (...)` results,
  `+++ exited with N +++` trailers, `...` argv truncation.

## Time discipline

Use one monotonic epoch base per fixture (e.g. 1757000000.0) with honest
ordering: sensors start before `workload_started` (supervisor warms up 2 s),
`workload_exited` precedes the `sensor_signal` teardown burst, trace tails
must reach within 2 s of `workload_exited` (else the integrity floor flags
`strace_tail_truncated`), and reconciliation scans must keep the declared
`interval_seconds` cadence.

## Existing cases

- `smoke/` — clean normal run of `bash -lc "touch /tmp/nsg-observer-demo;
  sleep 3"` under strace: every stream present, zero integrity flags, all
  SMOKE units PASS. Generated with the real `observer/lib/jsonlog.py`
  (scripted clock); treat it as the golden reference for envelope shape.
- `envelope/` — first lines of every stream (see Envelope above).
- `fm_2_3/`, `fm_4_2/`, `fm_4_5/` — owned by the respective detector
  implementers; sub-case directories follow the same format
  (e.g. `fm_4_2/fail_kill/`, `fm_4_2/benign_control/`), one case per
  battery arm: FAIL arm, benign control, degradation corpus, adversary
  controls, determinism.
