"""Frozen record dataclasses for every /observation stream.

This module is the frozen contract between the loader (analysis.observation)
and the detectors.  It performs zero I/O.  Every record carries ``seq`` (the
1-based line number of its record within its own single-writer stream file, so
ordering falls back to append order when the envelope carries no timestamp)
and ``ts`` (the envelope timestamp as epoch seconds, or ``None`` when absent).

Field vocabularies mirror the collector sources in observer/bin/* exactly;
anything a collector emits that has no frozen field here is dropped by the
loader (never crashes) — extend the loader-side raw capture, not these shapes,
if a detector needs more.
"""

from __future__ import annotations

from dataclasses import dataclass

# ---------------------------------------------------------------------------
# supervisor.jsonl (observer/bin/observe-entrypoint)
# ---------------------------------------------------------------------------

#: Supervisor event names (event vocabulary of observe-entrypoint).
SUPERVISOR_EVENTS = frozenset({
    "sensor_started",
    "sensor_start_failed",
    "sensor_exited",
    "sensor_signal",
    "supervisor_signal",
    "workload_started",
    "workload_exited",
})


@dataclass(frozen=True)
class SupervisorEvent:
    """One supervisor.jsonl line.

    Event-specific field use:
    - ``sensor_started``: name, pid, argv
    - ``sensor_start_failed``: name, argv, error
    - ``sensor_exited``: name, returncode
    - ``sensor_signal``: name, pid, signal
    - ``supervisor_signal``: signal
    - ``workload_started``: pid, argv (= requested_argv), effective_argv
    - ``workload_exited``: pid, returncode
    """

    seq: int
    ts: float | None
    event: str
    name: str | None = None
    pid: int | None = None
    argv: tuple[str, ...] | None = None
    returncode: int | None = None
    signal: int | None = None
    error: str | None = None
    effective_argv: tuple[str, ...] | None = None


# ---------------------------------------------------------------------------
# processes.jsonl (observer/bin/process-monitor)
# ---------------------------------------------------------------------------

#: Process census event names.
PROCESS_EVENTS = frozenset({
    "monitor_started",
    "process_seen",
    "process_changed",
    "process_gone",
})


@dataclass(frozen=True)
class ProcRecord:
    """One processes.jsonl census record, keyed by (pid, start_ticks).

    ``start_ticks`` is the RAW STRING of /proc/<pid>/stat field 22 (index 21)
    — compare by string equality only, never int-coerce (leading zeros /
    formatting would break identity).  ``process_gone`` records carry ONLY
    pid/start_ticks/name/cmdline/uid populated (that is all the collector
    emits); ppid closure must ride the last process_seen/process_changed
    record with the same key.  ``previous`` (process_changed only) is the
    prior snapshot re-typed; its ``event`` is ``""`` and its ``ts`` is
    ``None`` because the collector embeds a bare field dict.
    """

    seq: int
    ts: float | None
    event: str
    pid: int
    start_ticks: str
    name: str = ""
    state: str = ""
    ppid: int = -1
    cmdline: str = ""
    uid: tuple[str, ...] = ()
    username: str = ""
    exe: str = ""
    cgroup: str = ""
    sessionid: str = ""
    tty_nr: str = ""
    previous: "ProcRecord | None" = None


# ---------------------------------------------------------------------------
# files/events.jsonl (observer/bin/filesystem-monitor)
# ---------------------------------------------------------------------------

#: inotify operations emitted by filesystem-monitor.
FILE_EVENT_OPS = frozenset({
    "attrib", "close_write", "create", "delete", "delete_self",
    "modify", "move", "move_self",
})

#: Filesystem-monitor lifecycle event names.
FILESYSTEM_MONITOR_EVENTS = frozenset({
    "monitor_started",
    "monitor_exited",
    "monitor_failed",
    "unparsed",
})


@dataclass(frozen=True)
class FileEvent:
    """One inotify ``filesystem_event`` line (kernel_time is inotify's %s)."""

    seq: int
    ts: float | None
    kernel_time: str
    path: str
    operations: tuple[str, ...]
    move_cookie: str


@dataclass(frozen=True)
class FilesysMonitorEvent:
    """One filesystem-monitor lifecycle line (same stream as FileEvent)."""

    seq: int
    ts: float | None
    event: str
    returncode: int | None = None
    stderr: str | None = None
    interval_seconds: float | None = None
    roots: tuple[str, ...] | None = None
    raw: str | None = None


# ---------------------------------------------------------------------------
# files/reconciliation.jsonl (observer/bin/state-reconciler)
# ---------------------------------------------------------------------------

#: Reconciliation event names.
RECON_EVENTS = frozenset({
    "baseline_complete",
    "scan_complete",
    "file_added",
    "file_deleted",
    "file_changed",
})


@dataclass(frozen=True)
class FileState:
    """The reconciler's 7-tuple file state (checksum = sha256 hex or a tag).

    ``checksum`` is the hex sha256 of the content, or one of the tags
    ``size-limit``, ``link:<target>``, ``special``.
    """

    mode: int
    uid: int
    gid: int
    size: int
    mtime_ns: int
    ctime_ns: int
    checksum: str


@dataclass(frozen=True)
class ReconEvent:
    """One reconciliation line.

    ``baseline_complete`` carries ``files`` as a COUNT only — no golden
    manifest is ever dumped in-stream.  ``file_added`` carries ``state``;
    ``file_deleted`` carries ``previous_state``; ``file_changed`` carries
    both.
    """

    seq: int
    ts: float | None
    event: str
    files: int | None = None
    duration_seconds: float | None = None
    interval_seconds: float | None = None
    path: str | None = None
    state: FileState | None = None
    previous_state: FileState | None = None


# ---------------------------------------------------------------------------
# sockets/sockets.jsonl (observer/bin/socket-monitor)
# ---------------------------------------------------------------------------

#: Socket inventory event names.
SOCKET_EVENTS = frozenset({
    "monitor_started",
    "connection_seen",
    "connection_gone",
    "listener_seen",
    "listener_gone",
})


@dataclass(frozen=True)
class SocketEvent:
    """One socket-monitor line; ``socket`` is the VERBATIM ``ss`` line.

    Detectors needing address tuples parse the line with a frozen regex in
    their own module (the ss output format is not normalized by the loader).
    """

    seq: int
    ts: float | None
    kind: str
    socket: str


# ---------------------------------------------------------------------------
# bcc/status.jsonl (observer/bin/bcc-monitor)
# ---------------------------------------------------------------------------

#: BCC status event names.
BCC_EVENTS = frozenset({
    "tool_started",
    "tool_unavailable",
    "tool_exited",
    "tool_stopped",
    "cgroup_filter_ready",
    "cgroup_filter_failed",
    "cgroup_filter_removed",
    "cgroup_filter_remove_failed",
})


@dataclass(frozen=True)
class BccEvent:
    """One bcc/status.jsonl line."""

    seq: int
    ts: float | None
    event: str
    tool: str | None = None
    pid: int | None = None
    returncode: int | None = None
    command: tuple[str, ...] | None = None
    error: str | None = None
    cgroup_id: int | None = None


# ---------------------------------------------------------------------------
# tty/bash-history-*.log (observer/etc/bash-observer.sh)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class BashHistoryLine:
    """One bash history entry line: ``"<epoch> <command>"``.

    TIER: corroboration/join only, never deciding — the tty directory is
    chmod 1777, i.e. agent-writable testimony.  ``owner_hint`` is the
    ``<uid>-<ppid>-<pid>`` suffix of the file name.  Multi-line commands
    produce continuation lines whose epoch is ``None``.
    """

    path: str
    seq: int
    epoch: float | None
    command: str
    owner_hint: str


# ---------------------------------------------------------------------------
# health.json (supervisor status file, overwritten in place)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class HealthFinal:
    """The FINAL surviving health.json snapshot (earlier ones are lost).

    ``services`` is (name, pid, running, returncode) sorted by name.
    """

    state: str
    timestamp: float
    workload_pid: int | None
    services: tuple[tuple[str, int, bool, int | None], ...]


# ---------------------------------------------------------------------------
# syscalls/trace.PID (strace -ff -ttt -T -yy -s 4096)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class StraceLine:
    """Base strace line; ``raw`` preserves the full line verbatim.

    ``file_pid`` is the traced PID (the integer suffix of the trace.PID file
    name).  Unparsable lines stay this base type with everything but
    raw/ts/seq/file_pid defaulted.
    """

    file_pid: int
    seq: int
    raw: str
    ts: float | None = None


@dataclass(frozen=True)
class ExecveLine(StraceLine):
    """execve syscall line; ``argv`` is the parsed argv array (argv[1..] of
    the syscall, i.e. including argv[0]).  ``truncated`` marks strace's
    ``...`` elision (the -s limit was hit)."""

    argv: tuple[str, ...] | None = None
    truncated: bool = False
    result_raw: str = ""


@dataclass(frozen=True)
class SignalLine(StraceLine):
    """kill/tgkill/tkill/ptrace syscall line (arguments kept raw)."""

    args_raw: str = ""
    result_raw: str = ""


@dataclass(frozen=True)
class ExitTrailer(StraceLine):
    """``+++ exited with N +++`` trailer of a traced process."""

    code: int = 0


@dataclass(frozen=True)
class SyscallLine(StraceLine):
    """Any other parsed syscall line; ``result_raw`` is e.g.
    ``-1 ENOENT (No such file or directory)`` or ``0``; ``duration_s`` is
    strace's -T ``<...>`` suffix when present."""

    name: str = ""
    args_raw: str = ""
    result_raw: str = ""
    duration_s: float | None = None
