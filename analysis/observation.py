"""Loader for an /observation evidence directory.

All filesystem access for the analysis package lives here and nowhere else;
detectors receive an :class:`Observation` and are I/O-free, so tests build
Observation objects purely through ``load_observation(fixture_dir)``.

Envelope: every JSONL collector line is one object whose event-name and
timestamp keys are pinned by :class:`EnvelopePins`.  The observer's
observer/lib/jsonlog.py writes ``{"event": ..., "timestamp": ...,
"source": ..., **fields}``; if a live run is ever found to disagree, change
the pins — never the parser.  Records whose envelope timestamp is absent get
``ts=None`` and ordering falls back to ``seq`` (append order within one
single-writer file; cross-file ordering then needs the detector's own join
logic).

Missing streams, unreadable files, corrupt lines and degraded records become
StreamFlags — never exceptions, never a pass.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Iterator

from .integrity import StreamFlag, stream_integrity
from .records import (
    BccEvent,
    BashHistoryLine,
    ExecveLine,
    ExitTrailer,
    FileEvent,
    FileState,
    FilesysMonitorEvent,
    HealthFinal,
    ProcRecord,
    ReconEvent,
    SignalLine,
    SocketEvent,
    StraceLine,
    SupervisorEvent,
    SyscallLine,
)

# ---------------------------------------------------------------------------
# Stream names (used by StreamFlag.stream and Detector.DEPENDS_ON)
# ---------------------------------------------------------------------------

#: Canonical stream name -> location inside the observation directory.
#: filesystem_events and filesystem_monitor share one file (files/events.jsonl)
#: but are distinct logical streams with separate integrity identities.
STREAM_PATHS = {
    "supervisor": "supervisor.jsonl",
    "processes": "processes.jsonl",
    "filesystem_events": "files/events.jsonl",
    "filesystem_monitor": "files/events.jsonl",
    "reconciliation": "files/reconciliation.jsonl",
    "sockets": "sockets/sockets.jsonl",
    "bcc_status": "bcc/status.jsonl",
    "syscalls": "syscalls",
    "bash_history": "tty",
    "health": "health.json",
}

#: Streams whose records come from JSONL files (envelope-pinned).
JSONL_STREAMS = (
    "supervisor",
    "processes",
    "filesystem_events",
    "reconciliation",
    "sockets",
    "bcc_status",
)


@dataclass(frozen=True)
class EnvelopePins:
    """JSONL envelope key names (event name and epoch timestamp)."""

    event_key: str = "event"
    time_key: str = "timestamp"

    def to_dict(self) -> dict:
        return {"event_key": self.event_key, "time_key": self.time_key}


#: Default pins: the shape observer/lib/jsonlog.py writes.
DEFAULT_ENVELOPE_PINS = EnvelopePins()


@dataclass(frozen=True)
class Observation:
    """Parsed, typed view of one /observation directory.

    Every tuple is in stream (seq) order.  ``flags`` carries the loader flags
    (stream_missing, jsonl_corrupt, envelope_mismatch, record_degraded, ...)
    merged with the derived integrity floor (see analysis.integrity).
    """

    root: Path
    supervisor: tuple[SupervisorEvent, ...] = ()
    processes: tuple[ProcRecord, ...] = ()
    filesystem_events: tuple[FileEvent, ...] = ()
    filesystem_monitor: tuple[FilesysMonitorEvent, ...] = ()
    reconciliation: tuple[ReconEvent, ...] = ()
    sockets: tuple[SocketEvent, ...] = ()
    bcc_status: tuple[BccEvent, ...] = ()
    strace: tuple[StraceLine, ...] = ()
    strace_files: tuple[Path, ...] = ()
    bash_history: tuple[BashHistoryLine, ...] = ()
    health: HealthFinal | None = None
    flags: tuple[StreamFlag, ...] = ()
    pins: EnvelopePins = DEFAULT_ENVELOPE_PINS


# ---------------------------------------------------------------------------
# Coercion helpers (total: never raise on unexpected shapes)
# ---------------------------------------------------------------------------


def _as_str(value) -> str:
    return value if isinstance(value, str) else ("" if value is None else str(value))


def _as_opt_str(value) -> str | None:
    if value is None:
        return None
    return value if isinstance(value, str) else str(value)


def _as_int(value) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, float) and value.is_integer():
        return int(value)
    if isinstance(value, str):
        try:
            return int(value.strip())
        except ValueError:
            return None
    return None


def _as_float(value) -> float | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        try:
            return float(value.strip())
        except ValueError:
            return None
    return None


def _as_str_tuple(value) -> tuple[str, ...] | None:
    if value is None:
        return None
    if isinstance(value, (list, tuple)):
        return tuple(_as_str(item) for item in value)
    return None


def _ts(obj: dict, pins: EnvelopePins) -> float | None:
    return _as_float(obj.get(pins.time_key))


def _event(obj: dict, pins: EnvelopePins) -> str:
    value = obj.get(pins.event_key)
    return value if isinstance(value, str) else ""


# ---------------------------------------------------------------------------
# JSONL iteration
# ---------------------------------------------------------------------------


def iter_jsonl(
    path: Path, stream: str = "", flags: list[StreamFlag] | None = None
) -> Iterator[tuple[int, dict]]:
    """Yield (line_number, object) for each decodable JSON object.

    A JSON-decode failure appends ``jsonl_corrupt`` (with the line number) to
    ``flags`` and skips the line; a missing/unreadable file appends
    ``stream_missing`` and yields nothing.  Never raises, never hides loss.
    """
    name = stream or path.name
    try:
        handle = path.open("r", encoding="utf-8", errors="replace")
    except OSError:
        if flags is not None:
            flags.append(StreamFlag(name, "stream_missing", f"path={path}"))
        return
    with handle:
        for number, raw in enumerate(handle, start=1):
            stripped = raw.strip()
            if not stripped:
                continue
            try:
                obj = json.loads(stripped)
            except ValueError:
                if flags is not None:
                    flags.append(
                        StreamFlag(name, "jsonl_corrupt", f"line={number}"))
                continue
            if not isinstance(obj, dict):
                if flags is not None:
                    flags.append(StreamFlag(
                        name, "jsonl_corrupt",
                        f"line={number} non_object={type(obj).__name__}"))
                continue
            yield number, obj


# ---------------------------------------------------------------------------
# Per-stream record parsers (one per collector script)
# ---------------------------------------------------------------------------


def _parse_supervisor(seq: int, obj: dict, pins: EnvelopePins) -> SupervisorEvent:
    event = _event(obj, pins)
    argv = _as_str_tuple(obj.get("argv"))
    if event == "workload_started":
        argv = _as_str_tuple(obj.get("requested_argv"))
    return SupervisorEvent(
        seq=seq,
        ts=_ts(obj, pins),
        event=event,
        name=_as_opt_str(obj.get("name")),
        pid=_as_int(obj.get("pid")),
        argv=argv,
        returncode=_as_int(obj.get("returncode")),
        signal=_as_int(obj.get("signal")),
        error=_as_opt_str(obj.get("error")),
        effective_argv=_as_str_tuple(obj.get("effective_argv")),
    )


def _parse_process(
    seq: int, obj: dict, pins: EnvelopePins, flags: list[StreamFlag]
) -> ProcRecord:
    event = _event(obj, pins)
    pid = _as_int(obj.get("pid"))
    if pid is None and event != "monitor_started":
        flags.append(StreamFlag(
            "processes", "record_degraded", f"line={seq} event={event} no_pid"))
        pid = -1
    start_ticks = _as_str(obj.get("start_ticks"))
    if event in ("process_seen", "process_changed") and not start_ticks:
        flags.append(StreamFlag(
            "processes", "record_degraded",
            f"line={seq} event={event} no_start_ticks"))
    previous = None
    if event == "process_changed":
        prev = obj.get("previous")
        if isinstance(prev, dict):
            previous = _build_process_snapshot(0, prev)
    if event == "monitor_started":
        return ProcRecord(
            seq=seq, ts=_ts(obj, pins), event=event, pid=-1, start_ticks="")
    if event == "process_gone":
        uid = obj.get("uid")
        return ProcRecord(
            seq=seq,
            ts=_ts(obj, pins),
            event=event,
            pid=pid if pid is not None else -1,
            start_ticks=start_ticks,
            name=_as_str(obj.get("name")),
            cmdline=_as_str(obj.get("cmdline")),
            uid=tuple(_as_str(v) for v in uid) if isinstance(uid, (list, tuple)) else (),
        )
    return _build_process_snapshot(seq, obj, ts=_ts(obj, pins), event=event,
                                   previous=previous)


def _build_process_snapshot(
    seq: int, obj: dict, ts: float | None = None, event: str = "",
    previous: ProcRecord | None = None,
) -> ProcRecord:
    """Build a full-census ProcRecord from a process_info field dict."""
    uid = obj.get("uid")
    return ProcRecord(
        seq=seq,
        ts=ts,
        event=event,
        pid=_as_int(obj.get("pid")) or -1,
        start_ticks=_as_str(obj.get("start_ticks")),
        name=_as_str(obj.get("name")),
        state=_as_str(obj.get("state")),
        ppid=_as_int(obj.get("ppid")) if _as_int(obj.get("ppid")) is not None else -1,
        cmdline=_as_str(obj.get("cmdline")),
        uid=tuple(_as_str(v) for v in uid) if isinstance(uid, (list, tuple)) else (),
        username=_as_str(obj.get("username")),
        exe=_as_str(obj.get("exe")),
        cgroup=_as_str(obj.get("cgroup")),
        sessionid=_as_str(obj.get("sessionid")),
        tty_nr=_as_str(obj.get("tty_nr")),
        previous=previous,
    )


def _split_files_stream(
    seq: int, obj: dict, pins: EnvelopePins
) -> tuple[FileEvent | None, FilesysMonitorEvent | None]:
    """files/events.jsonl lines are either filesystem_event or monitor."""
    event = _event(obj, pins)
    ts = _ts(obj, pins)
    if event == "filesystem_event":
        operations = obj.get("operations")
        return FileEvent(
            seq=seq,
            ts=ts,
            kernel_time=_as_str(obj.get("kernel_time")),
            path=_as_str(obj.get("path")),
            operations=tuple(_as_str(v) for v in operations)
            if isinstance(operations, (list, tuple)) else (),
            move_cookie=_as_str(obj.get("move_cookie")),
        ), None
    if event in ("monitor_started", "monitor_exited", "monitor_failed", "unparsed"):
        roots = _as_str_tuple(obj.get("roots"))
        return None, FilesysMonitorEvent(
            seq=seq,
            ts=ts,
            event=event,
            returncode=_as_int(obj.get("returncode")),
            stderr=_as_opt_str(obj.get("stderr")),
            interval_seconds=_as_float(obj.get("interval_seconds")),
            roots=roots,
            raw=_as_opt_str(obj.get("raw")),
        )
    # Unknown event names are preserved (raw JSON) so no evidence is silently
    # dropped; they are not interpretable by the frozen record shapes.
    return None, FilesysMonitorEvent(
        seq=seq, ts=ts, event=event,
        raw=json.dumps(obj, sort_keys=True),
    )


def _parse_file_state(
    value, flags: list[StreamFlag], seq: int, kind: str
) -> FileState | None:
    if value is None:
        return None
    if not isinstance(value, (list, tuple)) or len(value) != 7:
        flags.append(StreamFlag(
            "reconciliation", "record_degraded",
            f"line={seq} {kind}_state_len="
            f"{len(value) if hasattr(value, '__len__') else 'n/a'}"))
        return None
    mode = _as_int(value[0])
    uid = _as_int(value[1])
    gid = _as_int(value[2])
    size = _as_int(value[3])
    mtime_ns = _as_int(value[4])
    ctime_ns = _as_int(value[5])
    if None in (mode, uid, gid, size, mtime_ns, ctime_ns):
        flags.append(StreamFlag(
            "reconciliation", "record_degraded", f"line={seq} {kind}_state_fields"))
        return None
    return FileState(
        mode=mode, uid=uid, gid=gid, size=size,
        mtime_ns=mtime_ns, ctime_ns=ctime_ns,
        checksum=_as_str(value[6]),
    )


def _parse_recon(seq: int, obj: dict, pins: EnvelopePins,
                 flags: list[StreamFlag]) -> ReconEvent:
    event = _event(obj, pins)
    return ReconEvent(
        seq=seq,
        ts=_ts(obj, pins),
        event=event,
        files=_as_int(obj.get("files")),
        duration_seconds=_as_float(obj.get("duration_seconds")),
        interval_seconds=_as_float(obj.get("interval_seconds")),
        path=_as_opt_str(obj.get("path")),
        state=_parse_file_state(obj.get("state"), flags, seq, ""),
        previous_state=_parse_file_state(obj.get("previous_state"), flags, seq,
                                         "previous"),
    )


def _parse_socket(seq: int, obj: dict, pins: EnvelopePins) -> SocketEvent:
    return SocketEvent(
        seq=seq,
        ts=_ts(obj, pins),
        kind=_event(obj, pins),
        socket=_as_str(obj.get("socket")),
    )


def _parse_bcc(seq: int, obj: dict, pins: EnvelopePins) -> BccEvent:
    return BccEvent(
        seq=seq,
        ts=_ts(obj, pins),
        event=_event(obj, pins),
        tool=_as_opt_str(obj.get("tool")),
        pid=_as_int(obj.get("pid")),
        returncode=_as_int(obj.get("returncode")),
        command=_as_str_tuple(obj.get("command")),
        error=_as_opt_str(obj.get("error")),
        cgroup_id=_as_int(obj.get("cgroup_id")),
    )


# ---------------------------------------------------------------------------
# bash history (tty/bash-history-<uid>-<ppid>-<pid>.log)
# ---------------------------------------------------------------------------

_BASH_HISTORY_NAME = re.compile(r"^bash-history-(?P<hint>.+)\.log$")
_HISTORY_EPOCH = re.compile(r"^(?P<epoch>\d+(?:\.\d+)?)\s+(?P<command>.*)$")


def parse_bash_history_dir(
    tty_dir: Path, flags: list[StreamFlag] | None = None
) -> tuple[BashHistoryLine, ...]:
    """Parse every tty/bash-history-*.log file (script(1) files ignored)."""
    records: list[BashHistoryLine] = []
    if not tty_dir.is_dir():
        if flags is not None:
            flags.append(StreamFlag("bash_history", "stream_missing",
                                    f"path={tty_dir}"))
        return ()
    for path in sorted(tty_dir.glob("bash-history-*.log"), key=lambda p: p.name):
        match = _BASH_HISTORY_NAME.match(path.name)
        owner_hint = match.group("hint") if match else path.name
        try:
            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            if flags is not None:
                flags.append(StreamFlag(
                    "bash_history", "stream_missing", f"path={path}"))
            continue
        for seq, raw in enumerate(lines, start=1):
            entry = _HISTORY_EPOCH.match(raw.strip())
            if entry:
                records.append(BashHistoryLine(
                    path=str(path), seq=seq,
                    epoch=float(entry.group("epoch")),
                    command=entry.group("command"), owner_hint=owner_hint))
            else:
                # Continuation line of a multi-line command (cmdhist).
                records.append(BashHistoryLine(
                    path=str(path), seq=seq, epoch=None,
                    command=raw, owner_hint=owner_hint))
    return tuple(records)


# ---------------------------------------------------------------------------
# health.json (final snapshot only)
# ---------------------------------------------------------------------------


def parse_health_file(
    path: Path, flags: list[StreamFlag] | None = None
) -> HealthFinal | None:
    try:
        obj = json.loads(path.read_text(encoding="utf-8"))
    except OSError:
        if flags is not None:
            flags.append(StreamFlag("health", "stream_missing", f"path={path}"))
        return None
    except ValueError:
        if flags is not None:
            flags.append(StreamFlag("health", "json_corrupt", f"path={path}"))
        return None
    if not isinstance(obj, dict):
        if flags is not None:
            flags.append(StreamFlag("health", "json_corrupt",
                                    f"path={path} non_object"))
        return None
    services = obj.get("services")
    parsed_services: list[tuple[str, int, bool, int | None]] = []
    if isinstance(services, dict):
        for name in sorted(services):
            info = services[name]
            if not isinstance(info, dict):
                continue
            running = info.get("running")
            parsed_services.append((
                _as_str(name),
                _as_int(info.get("pid")) or -1,
                running is True,
                _as_int(info.get("returncode")),
            ))
    return HealthFinal(
        state=_as_str(obj.get("state")),
        timestamp=_as_float(obj.get("timestamp")) or 0.0,
        workload_pid=_as_int(obj.get("workload_pid")),
        services=tuple(parsed_services),
    )


# ---------------------------------------------------------------------------
# strace -ff trace.PID files
# ---------------------------------------------------------------------------

#: kill-class syscalls that carry a signal-delivery edge.
SIGNAL_SYSCALLS = frozenset({"kill", "tgkill", "tkill", "ptrace"})

_TS_PREFIX = re.compile(r"^(?P<ts>\d{9,}\.\d+)\s*(?P<rest>.*)$")
_SYSCALL = re.compile(r"^(?P<name>[A-Za-z_][A-Za-z0-9_]*)\((?P<args>.*)\)\s*=\s*(?P<result>.+)$")
_DURATION = re.compile(r"^(?P<result>.*?)(?:\s+<(?P<duration>\d+(?:\.\d+)?)>)?$")
_EXITED_WITH = re.compile(r"^\+\+\+ exited with (?P<code>\d+) \+\+\+$")
_ARGV_ARRAY = re.compile(r"\[(?P<argv>.*)\]", re.DOTALL)
_QUOTED = re.compile(r'"((?:[^"\\]|\\.)*)"')
_ESCAPES = {"n": "\n", "t": "\t", "r": "\r", '"': '"', "\\": "\\"}


def _unquote(token: str) -> str:
    out: list[str] = []
    i = 0
    while i < len(token):
        char = token[i]
        if char == "\\" and i + 1 < len(token):
            nxt = token[i + 1]
            out.append(_ESCAPES.get(nxt, "\\" + nxt))
            i += 2
        else:
            out.append(char)
            i += 1
    return "".join(out)


def _parse_execve_argv(args_raw: str) -> tuple[tuple[str, ...] | None, bool]:
    """Extract the argv array from execve's argument text, or (None, False)."""
    match = _ARGV_ARRAY.search(args_raw)
    if match is None:
        return None, False
    body = match.group("argv")
    truncated = "..." in body
    argv = tuple(_unquote(m.group(1)) for m in _QUOTED.finditer(body))
    if not argv:
        return ((), truncated)
    return argv, truncated


def parse_strace_line(file_pid: int, seq: int, raw: str) -> StraceLine:
    """Parse one strace line into the typed hierarchy (total, never raises)."""
    line = raw.rstrip("\n")
    ts_match = _TS_PREFIX.match(line)
    ts = float(ts_match.group("ts")) if ts_match else None
    rest = ts_match.group("rest") if ts_match else line

    exit_match = _EXITED_WITH.match(rest)
    if exit_match:
        return ExitTrailer(file_pid=file_pid, seq=seq, raw=line, ts=ts,
                           code=int(exit_match.group("code")))

    call_match = _SYSCALL.match(rest)
    if call_match:
        name = call_match.group("name")
        args = call_match.group("args")
        result_full = call_match.group("result").strip()
        dur_match = _DURATION.match(result_full)
        result_raw = dur_match.group("result").strip()
        duration = _as_float(dur_match.group("duration")) if dur_match else None
        if name == "execve":
            argv, truncated = _parse_execve_argv(args)
            return ExecveLine(file_pid=file_pid, seq=seq, raw=line, ts=ts,
                              argv=argv, truncated=truncated,
                              result_raw=result_raw)
        if name in SIGNAL_SYSCALLS:
            return SignalLine(file_pid=file_pid, seq=seq, raw=line, ts=ts,
                              args_raw=args, result_raw=result_raw)
        return SyscallLine(file_pid=file_pid, seq=seq, raw=line, ts=ts,
                           name=name, args_raw=args, result_raw=result_raw,
                           duration_s=duration)

    return StraceLine(file_pid=file_pid, seq=seq, raw=line, ts=ts)


def parse_strace_dir(
    syscalls_dir: Path, flags: list[StreamFlag] | None = None
) -> tuple[tuple[StraceLine, ...], tuple[Path, ...]]:
    """Read every trace.PID file; return (lines sorted by (ts, pid, seq), paths).

    Lines lacking a timestamp sort last (ts None -> +inf).  A missing or empty
    directory yields ``stream_missing`` on the ``syscalls`` stream.
    """
    if not syscalls_dir.is_dir():
        if flags is not None:
            flags.append(StreamFlag("syscalls", "stream_missing",
                                    f"path={syscalls_dir}"))
        return (), ()
    files: list[Path] = []
    for path in sorted(syscalls_dir.iterdir(), key=lambda p: p.name):
        if not path.name.startswith("trace."):
            continue
        suffix = path.name[len("trace."):]
        if not suffix.isdigit():
            continue
        try:
            if path.stat().st_size == 0:
                continue
        except OSError:
            continue
        files.append(path)
    if not files:
        if flags is not None:
            flags.append(StreamFlag("syscalls", "stream_missing",
                                    f"path={syscalls_dir} no_trace_files"))
        return (), ()
    records: list[StraceLine] = []
    for path in files:
        file_pid = int(path.name[len("trace."):])
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            if flags is not None:
                flags.append(StreamFlag(
                    "syscalls", "stream_missing", f"path={path}"))
            continue
        for seq, raw in enumerate(text.splitlines(), start=1):
            if raw.strip():
                records.append(parse_strace_line(file_pid, seq, raw))
    records.sort(key=lambda r: (
        r.ts if r.ts is not None else float("inf"), r.file_pid, r.seq))
    return tuple(records), tuple(files)


# ---------------------------------------------------------------------------
# Top-level loader
# ---------------------------------------------------------------------------


def _load_jsonl_stream(
    path: Path, stream: str, pins: EnvelopePins, flags: list[StreamFlag],
) -> list[tuple[int, dict]]:
    """iter_jsonl plus the envelope_mismatch / timestamp checks."""
    objects: list[tuple[int, dict]] = []
    for seq, obj in iter_jsonl(path, stream=stream, flags=flags):
        objects.append((seq, obj))
    if objects:
        first = objects[0][1]
        if not isinstance(first.get(pins.event_key), str):
            flags.append(StreamFlag(
                stream, "envelope_mismatch",
                f"event_key={pins.event_key!r}"
                f" first_line_keys={sorted(str(k) for k in first.keys())}"))
        if all(_as_float(obj.get(pins.time_key)) is None for _, obj in objects):
            flags.append(StreamFlag(
                stream, "envelope_timestamp_missing",
                f"time_key={pins.time_key!r} lines={len(objects)}"))
    return objects


def load_observation(
    root: Path, pins: EnvelopePins = DEFAULT_ENVELOPE_PINS
) -> Observation:
    """Load one /observation directory into a typed, flagged Observation.

    Never raises on missing or corrupt evidence: every gap becomes a
    StreamFlag (see analysis.integrity for the frozen vocabulary) so no
    degraded unit can silently pass.
    """
    root = Path(root)
    flags: list[StreamFlag] = []

    supervisor = tuple(
        _parse_supervisor(seq, obj, pins)
        for seq, obj in _load_jsonl_stream(
            root / "supervisor.jsonl", "supervisor", pins, flags)
    )

    processes = tuple(
        _parse_process(seq, obj, pins, flags)
        for seq, obj in _load_jsonl_stream(
            root / "processes.jsonl", "processes", pins, flags)
    )

    file_events: list[FileEvent] = []
    file_monitor: list[FilesysMonitorEvent] = []
    for seq, obj in _load_jsonl_stream(
            root / "files" / "events.jsonl", "filesystem_events", pins, flags):
        event, monitor = _split_files_stream(seq, obj, pins)
        if event is not None:
            file_events.append(event)
        if monitor is not None:
            file_monitor.append(monitor)

    reconciliation = tuple(
        _parse_recon(seq, obj, pins, flags)
        for seq, obj in _load_jsonl_stream(
            root / "files" / "reconciliation.jsonl", "reconciliation",
            pins, flags)
    )

    sockets = tuple(
        _parse_socket(seq, obj, pins)
        for seq, obj in _load_jsonl_stream(
            root / "sockets" / "sockets.jsonl", "sockets", pins, flags)
    )

    bcc_status = tuple(
        _parse_bcc(seq, obj, pins)
        for seq, obj in _load_jsonl_stream(
            root / "bcc" / "status.jsonl", "bcc_status", pins, flags)
    )

    strace_lines, strace_files = parse_strace_dir(root / "syscalls", flags)
    bash_history = parse_bash_history_dir(root / "tty", flags)
    health = parse_health_file(root / "health.json", flags)

    observation = Observation(
        root=root,
        supervisor=supervisor,
        processes=processes,
        filesystem_events=tuple(file_events),
        filesystem_monitor=tuple(file_monitor),
        reconciliation=reconciliation,
        sockets=sockets,
        bcc_status=bcc_status,
        strace=strace_lines,
        strace_files=strace_files,
        bash_history=bash_history,
        health=health,
        flags=tuple(flags),
        pins=pins,
    )
    return replace(observation, flags=tuple(flags) + stream_integrity(observation))
