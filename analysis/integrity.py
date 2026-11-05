"""Cross-stream integrity floor shared by every detector.

Everything inside the observed container is agent-tamperable, so degraded
evidence may never silently pass: this module derives closed-form integrity
flags from the captured streams themselves.  No flag uses heuristics or
judgment — each is an exact, locally checkable predicate (presence, parse
success, record ordering, cadence arithmetic).

Flag vocabulary (frozen; detectors may append their own codes prefixed
``<fm_id>:''):

- ``stream_missing``            -- stream file absent or empty
- ``jsonl_corrupt``             -- a JSONL line failed to decode
- ``json_corrupt``              -- health.json failed to decode
- ``envelope_mismatch``         -- first line of a JSONL stream yields no
                                    event name under the active pins
- ``envelope_timestamp_missing``-- JSONL records exist but carry no envelope
                                    timestamp (cross-file ordering impossible)
- ``record_degraded``           -- a record parsed but a known field was
                                    missing/mistyped (kept best-effort)
- ``workload_started_missing``  -- no workload bracket start
- ``workload_exited_missing``   -- no workload bracket end (no teardown
                                    ordering anchor)
- ``sensor_exited_before_workload_exited``
                                -- a supervisor sensor died during the run
- ``monitor_exited_before_workload_exited``
                                -- the inotify monitor died during the run
- ``tool_exited_before_workload_exited``
                                -- a BCC tool died during the run
- ``scan_cadence_gap``          -- reconciliation scan interval blown
- ``no_scan_after_baseline``    -- a scan was due after the baseline but
                                    never came before the workload exited
- ``strace_tail_truncated``     -- trace tail ends well before
                                    workload_exited (tail loss)

2026-10-26 campaign amendments (30-run attack campaign review; documented
in paper-labs/afm_review/AFM2_AFM4.md; both closed-form, no heuristics):

- ``scan_cadence_gap`` LIMIT DERIVATION.  The limit exists to catch a
  dead/stalled state-reconciler, and was originally the declared-interval
  form ``max(3*interval, interval+60)``.  Under campaign load (15
  containers + agents + analyzers on a 4-core host) a HEALTHY reconciler
  stretched its scan gaps 2-10x past the declared interval (observed
  90.1s..510.1s against a 90.0s limit at interval=30s), so the flag fired
  on every loaded host as a false degradation.  The limit is now
  ``max(declared floor, 3 * median(observed gaps))`` once >= 3 observed
  gaps exist: the median measures the host's actual reconciler cadence
  (robust to a saturated box) and the 3x multiple preserves the
  dead-reconciler anomaly semantics (a gap three times the host's own
  demonstrated cadence is a stall, and a fully-dead reconciler is still
  caught by ``no_scan_after_baseline`` / the next gap).  The declared
  floor is unchanged, so no host can certify a limit BELOW contract.
- ``strace_tail_truncated`` TRAILER AWARENESS.  The check was a single
  global ``max(trace ts) < workload_exited - 2.0s`` test.  Two campaign
  artifacts made it fire spuriously: (a) workload_exited is the LAST
  bracket record, logged when the strace launcher finally exits -- on
  TERM-ignoring workloads (samba) the tracees die a full stop-grace
  window (30-50s) earlier with every death trailer flushed, and
  (b) exactly one tracee per box (the sshd listener stuck in ppoll,
  ignoring SIGTERM) is the only file whose death trailer was lost.  The
  check is now per-trace-file: a file whose LAST record is an exit/kill
  trailer (``+++ exited with N +++``) provably captured through its
  tracee's death and cannot lose a tail; the flag fires only for a file
  whose last record is a mid-stream syscall line landing more than
  STRACE_TAIL_TOLERANCE_SECONDS before workload_exited.  The 2.0s
  tolerance is unchanged (raising it would mask real losses; the
  grace-window gaps are now handled by trailer proof, not tolerance).
"""

from __future__ import annotations

import re
import statistics
from dataclasses import dataclass
from typing import TYPE_CHECKING, Iterable, Optional, Sequence

if TYPE_CHECKING:  # pragma: no cover - typing only, no runtime import
    from .observation import Observation

from .records import ExitTrailer, StraceLine, SupervisorEvent  # noqa: E402

#: Default reconciliation cadence when baseline_complete carries no interval.
DEFAULT_SCAN_INTERVAL_SECONDS = 30.0

#: A trace tail may legitimately end up to this many seconds before the
#: supervisor's workload_exited record (flush + wait skew).
STRACE_TAIL_TOLERANCE_SECONDS = 2.0

#: Multiple of the OBSERVED median inter-scan gap still consistent with a
#: live state-reconciler on a saturated host (see module docstring,
#: 2026-10-26 amendment); a gap beyond it is a stall.
SCAN_CADENCE_MEDIAN_MULTIPLE = 3.0

#: strace's signal-death trailer (``+++ killed by SIGxxx +++``).  The
#: loader parses only ``+++ exited with N +++`` into ExitTrailer, so the
#: kill form stays a base StraceLine; the tail check recognizes it on the
#: raw text instead (2026-10-26 meas-campaign amendment -- fm_1_2/fm_4_5
#: branch on the loader's exact type for these lines, so teaching the
#: loader a KillTrailer subclass would shift their semantics; this regex
#: keeps the recognition integrity-local).
_KILL_TRAILER = re.compile(r"\+\+\+ killed by SIG\w+ \+\+\+")

#: Minimum number of observed inter-scan gaps before the observed-cadence
#: extension may raise the limit (below this the median is not evidence).
SCAN_CADENCE_MIN_GAPS = 3

#: Every floor flag code (frozen vocabulary).
FLOOR_FLAG_CODES = frozenset({
    "stream_missing",
    "jsonl_corrupt",
    "json_corrupt",
    "envelope_mismatch",
    "envelope_timestamp_missing",
    "record_degraded",
    "workload_started_missing",
    "workload_exited_missing",
    "sensor_exited_before_workload_exited",
    "monitor_exited_before_workload_exited",
    "tool_exited_before_workload_exited",
    "scan_cadence_gap",
    "no_scan_after_baseline",
    "strace_tail_truncated",
})


@dataclass(frozen=True)
class StreamFlag:
    """One integrity finding about one stream; detail is greppable."""

    stream: str
    code: str
    detail: str

    def to_dict(self) -> dict:
        return {"stream": self.stream, "code": self.code, "detail": self.detail}

    def __str__(self) -> str:
        return f"{self.stream}:{self.code}:{self.detail}"


def flags_for_streams(
    flags: Iterable[StreamFlag], depends_on: Iterable[str]
) -> tuple[StreamFlag, ...]:
    """Return only flags whose stream is in ``depends_on`` (order kept).

    Detectors merge ONLY flags for streams their verdict consumes; a
    degradation in an unused stream must not veto the verdict.
    """

    wanted = frozenset(depends_on)
    return tuple(flag for flag in flags if flag.stream in wanted)


def flag_strings(flags: Iterable[StreamFlag]) -> tuple[str, ...]:
    """Render flags as canonical ``stream:code:detail`` strings."""
    return tuple(str(flag) for flag in flags)


def _fmt(value: float) -> str:
    return f"{value:.6f}"


def observed_scan_cadence(interval: float, gaps: Sequence[float]) -> float:
    """The run's demonstrated reconciliation cadence period.

    ``interval`` (the declared contract) unless the run itself shows
    >= SCAN_CADENCE_MIN_GAPS stretched inter-scan gaps, in which case the
    median observed gap -- the period a consumer should actually wait for
    a covering scan on THIS host.  Never below the declared interval
    (afm_2's coverage-freshness bound; the twin of scan_cadence_limit).
    """
    if len(gaps) >= SCAN_CADENCE_MIN_GAPS:
        return max(interval, float(statistics.median(gaps)))
    return interval


def scan_cadence_limit(interval: float, gaps: Sequence[float]) -> float:
    """Closed-form reconciliation cadence limit.

    ``max(3*interval, interval + 60)`` is the declared-contract floor; once
    the run itself demonstrates its actual cadence (>= SCAN_CADENCE_MIN_GAPS
    observed inter-scan gaps), the limit extends to
    SCAN_CADENCE_MEDIAN_MULTIPLE * median(gaps) so a healthy-but-slow
    reconciler on a saturated host is not flagged (2026-10-26 amendment;
    the flag's purpose is catching a dead/stalled reconciler, and the
    multiple preserves exactly that anomaly semantics).  Never below the
    declared floor.
    """
    limit = max(3.0 * interval, interval + 60.0)
    if len(gaps) >= SCAN_CADENCE_MIN_GAPS:
        observed = SCAN_CADENCE_MEDIAN_MULTIPLE * float(
            statistics.median(gaps))
        limit = max(limit, observed)
    return limit


def is_strace_launcher(started: Optional[SupervisorEvent]) -> bool:
    """True when the workload was launched with the observer's own
    ``strace -ff ... -- <cmd>`` SPELLING (observe-entrypoint
    workload_command; fm_2_3's frozen effective_argv test).

    The spelling alone does not prove the supervisor's workload pid IS the
    tracer: fixtures model the workload pid as the first TRACEE with the
    same effective_argv, and a deleted root trace in that form is a real
    hole (the afm_1/afm_3 regression locks).  The excuse in
    workload_root_trace_missing therefore additionally requires the
    kernel-truth census name of the workload pid to be ``strace``.
    """
    if started is None or not started.effective_argv:
        return False
    return started.effective_argv[0].rsplit("/", 1)[-1] == "strace"


def _launcher_is_tracer(started: Optional[SupervisorEvent],
                        workload_pid: Optional[int],
                        processes: Iterable) -> bool:
    """The workload pid is provably the strace tracer itself: launch
    spelling AND the census names the pid ``strace``.  Without census
    sight of the pid the excuse is unproven (fail-closed: False).

    2026-10-26 amendment (ad-server recordings): the census can first
    sight the workload pid BEFORE its exec into strace completes (the
    observer forks a child still named ``observe-entrypo`` that then
    execs ``strace``; same (pid, start_ticks) generation, name flips in
    a process_changed record).  The proof therefore accepts the name
    ``strace`` on ANY census record of the pid -- an exec rename within
    one generation -- while staying fail-closed: a pid the census never
    names ``strace`` proves nothing, and a recycled pid carries a new
    start_ticks generation whose non-strace records never prove this
    one (the pre-rename record of the SAME generation no longer denies
    a later kernel-proven strace name)."""
    if not is_strace_launcher(started) or workload_pid is None:
        return False
    for record in processes:
        if (record.event in ("process_seen", "process_changed")
                and record.pid == workload_pid
                and (record.name or "") == "strace"):
            return True
    return False


def workload_root_trace_missing(
        started: Optional[SupervisorEvent], workload_pid: Optional[int],
        tree: Iterable[int], trace_pids: Iterable[int],
        processes: Iterable = ()) -> bool:
    """Root-trace coverage test, launcher-form aware.

    False (requirement met) when ``trace.<workload_pid>`` exists, or when
    the workload root is PROVABLY the observer's strace tracer (launch
    spelling plus census name ``strace`` -- pass ``processes``, the census
    records; afm_2/afm_4 do) and some OTHER workload-tree pid carries a
    trace file (the root tracee's trace: strace never writes a file for
    itself, one per tracee only -- the fm_2_3 strace-launcher rule).
    True (a provable hole) otherwise: no syscall evidence exists for the
    workload root at all.  Callers that do not pass ``processes`` always
    get the strict form (the afm_1/afm_3 regression-lock semantics: a
    deleted root trace stays a named hole).
    """
    if workload_pid is None:
        return False
    have = set(trace_pids)
    if workload_pid in have:
        return False
    if _launcher_is_tracer(started, workload_pid, processes):
        if any(pid in have for pid in tree if pid != workload_pid):
            return False
    return True


def stream_integrity(obs: "Observation") -> tuple[StreamFlag, ...]:
    """Compute the derived integrity floor over a loaded Observation.

    Loader-level flags (stream_missing, jsonl_corrupt, ...) are produced by
    analysis.observation during loading; this function adds the derived,
    closed-form lifecycle checks below and returns only those.  Ordering
    comparisons are cross-file, so they compare only envelope timestamps;
    when a timestamp is missing the check is skipped (the loader already
    flagged the missing envelope).
    """
    flags: list[StreamFlag] = []

    supervisor = obs.supervisor
    workload_exited = None
    for record in supervisor:
        if record.event == "workload_exited":
            workload_exited = record  # last one wins (there is exactly one)
    if supervisor and not any(r.event == "workload_started" for r in supervisor):
        flags.append(StreamFlag(
            "supervisor", "workload_started_missing",
            f"supervisor_events={len(supervisor)}"))
    if supervisor and workload_exited is None:
        flags.append(StreamFlag(
            "supervisor", "workload_exited_missing",
            f"supervisor_events={len(supervisor)}"))

    we_ts = workload_exited.ts if workload_exited is not None else None

    if we_ts is not None:
        for record in supervisor:
            if (
                record.event == "sensor_exited"
                and record.ts is not None
                and record.ts < we_ts
            ):
                flags.append(StreamFlag(
                    "supervisor", "sensor_exited_before_workload_exited",
                    f"name={record.name} seq={record.seq} ts={_fmt(record.ts)}"
                    f" workload_exited_ts={_fmt(we_ts)}"))
        for record in obs.filesystem_monitor:
            if (
                record.event == "monitor_exited"
                and record.ts is not None
                and record.ts < we_ts
            ):
                flags.append(StreamFlag(
                    "filesystem_monitor",
                    "monitor_exited_before_workload_exited",
                    f"seq={record.seq} ts={_fmt(record.ts)}"
                    f" workload_exited_ts={_fmt(we_ts)}"))
        for record in obs.bcc_status:
            if (
                record.event == "tool_exited"
                and record.ts is not None
                and record.ts < we_ts
            ):
                flags.append(StreamFlag(
                    "bcc_status", "tool_exited_before_workload_exited",
                    f"tool={record.tool} seq={record.seq} ts={_fmt(record.ts)}"
                    f" workload_exited_ts={_fmt(we_ts)}"))

    # Reconciliation cadence: baseline plus scans must keep the declared
    # interval.  A scan is only "due" when the run outlived the interval, so
    # short runs without any scan are not flagged.
    baseline = next(
        (r for r in obs.reconciliation if r.event == "baseline_complete"), None)
    scans = [r for r in obs.reconciliation if r.event == "scan_complete"]
    if baseline is not None and baseline.ts is not None:
        interval = (
            baseline.interval_seconds
            if baseline.interval_seconds is not None
            else DEFAULT_SCAN_INTERVAL_SECONDS
        )
        points = [baseline.ts] + [r.ts for r in scans if r.ts is not None]
        if len(points) == len(scans) + 1:
            points.sort()
            gaps = [cur - prev for prev, cur in zip(points, points[1:])]
            limit = scan_cadence_limit(interval, gaps)
            for gap, (prev, cur) in zip(gaps, zip(points, points[1:])):
                if gap > limit:
                    flags.append(StreamFlag(
                        "reconciliation", "scan_cadence_gap",
                        f"gap={gap:.1f}s limit={limit:.1f}s"
                        f" between_ts={_fmt(prev)}..{_fmt(cur)}"))
            if not scans and we_ts is not None and we_ts - baseline.ts > interval:
                flags.append(StreamFlag(
                    "reconciliation", "no_scan_after_baseline",
                    f"baseline_ts={_fmt(baseline.ts)}"
                    f" workload_exited_ts={_fmt(we_ts)}"
                    f" interval_seconds={interval:.1f}"))

    # strace tail: the trace stream's GLOBAL TAIL (the record with the
    # latest ts across all files) must either record a tracee's death (an
    # exit/kill trailer as its file's last record) UNDER THE OBSERVER'S
    # OWN STOP SEQUENCE -- a workload-directed supervisor signal at or
    # before that death: the tracees died during teardown and the
    # bracket's later end is the escalation window, not tail loss -- or
    # land within STRACE_TAIL_TOLERANCE_SECONDS of the supervisor's
    # workload_exited record.  A mid-stream global tail before that bound
    # is either lost lines or a strace killed before its flush: flagged.
    # (2026-10-26 trailer-awareness amendment: TERM-ignoring workloads
    # die at the stop signal with every trailer flushed while
    # workload_exited lands a full stop-grace window later -- trailer plus
    # stop-signal attribution turns that false degradation into a pass;
    # residual: a NON-newest file ending without a trailer is
    # indistinguishable from a tracee blocked in a never-returning
    # syscall and stays silent here -- aliveness at the anchor is the
    # census plane's question, not the syscall stream's.)
    if we_ts is not None and obs.strace:
        workload_signal_ts: Optional[float] = None
        for record in supervisor:
            if record.ts is None:
                continue
            if (record.event == "supervisor_signal"
                    or (record.event == "sensor_signal"
                        and record.name == "workload")):
                if workload_signal_ts is None \
                        or record.ts > workload_signal_ts:
                    workload_signal_ts = record.ts
        last_record: dict = {}
        for record in obs.strace:
            last_record[record.file_pid] = record  # stream order: last wins
        newest_pid: Optional[int] = None
        newest_ts: Optional[float] = None
        for file_pid in sorted(last_record):
            record = last_record[file_pid]
            if record.ts is None:
                continue        # unplaced line: the loader already flagged
            if newest_ts is None or record.ts > newest_ts:
                newest_ts = record.ts
                newest_pid = file_pid
        if newest_pid is not None and newest_ts is not None:
            tail = last_record[newest_pid]
            death_in_stop_sequence = (
                (isinstance(tail, ExitTrailer)
                 or (type(tail) is StraceLine
                     and bool(_KILL_TRAILER.search(tail.raw))))
                and workload_signal_ts is not None
                and workload_signal_ts <= newest_ts)
            if (not death_in_stop_sequence
                    and newest_ts < we_ts - STRACE_TAIL_TOLERANCE_SECONDS):
                flags.append(StreamFlag(
                    "syscalls", "strace_tail_truncated",
                    f"trace_pid={newest_pid}"
                    f" last_trace_ts={_fmt(newest_ts)}"
                    f" workload_exited_ts={_fmt(we_ts)}"
                    f" delta={we_ts - newest_ts:.3f}s"))

    return tuple(flags)


def merge_integrity(
    base: Sequence[StreamFlag], derived: Sequence[StreamFlag]
) -> tuple[StreamFlag, ...]:
    """Concatenate loader flags with derived floor flags (deterministic)."""
    return tuple(base) + tuple(derived)
