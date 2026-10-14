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
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Iterable, Sequence

if TYPE_CHECKING:  # pragma: no cover - typing only, no runtime import
    from .observation import Observation

#: Default reconciliation cadence when baseline_complete carries no interval.
DEFAULT_SCAN_INTERVAL_SECONDS = 30.0

#: A trace tail may legitimately end up to this many seconds before the
#: supervisor's workload_exited record (flush + wait skew).
STRACE_TAIL_TOLERANCE_SECONDS = 2.0

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
            limit = max(3.0 * interval, interval + 60.0)
            for prev, cur in zip(points, points[1:]):
                if cur - prev > limit:
                    flags.append(StreamFlag(
                        "reconciliation", "scan_cadence_gap",
                        f"gap={cur - prev:.1f}s limit={limit:.1f}s"
                        f" between_ts={_fmt(prev)}..{_fmt(cur)}"))
            if not scans and we_ts is not None and we_ts - baseline.ts > interval:
                flags.append(StreamFlag(
                    "reconciliation", "no_scan_after_baseline",
                    f"baseline_ts={_fmt(baseline.ts)}"
                    f" workload_exited_ts={_fmt(we_ts)}"
                    f" interval_seconds={interval:.1f}"))

    # strace tail: the trace must reach (within tolerance) the supervisor's
    # workload_exited record, else the tail was lost.
    if we_ts is not None and obs.strace:
        timestamps = [r.ts for r in obs.strace if r.ts is not None]
        if timestamps:
            last_ts = max(timestamps)
            if last_ts < we_ts - STRACE_TAIL_TOLERANCE_SECONDS:
                flags.append(StreamFlag(
                    "syscalls", "strace_tail_truncated",
                    f"last_trace_ts={_fmt(last_ts)}"
                    f" workload_exited_ts={_fmt(we_ts)}"
                    f" delta={we_ts - last_ts:.3f}s"))

    return tuple(flags)


def merge_integrity(
    base: Sequence[StreamFlag], derived: Sequence[StreamFlag]
) -> tuple[StreamFlag, ...]:
    """Concatenate loader flags with derived floor flags (deterministic)."""
    return tuple(base) + tuple(derived)
