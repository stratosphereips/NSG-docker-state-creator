"""Kill-trailer tail lock (2026-10-26 meas campaign amendment).

The integrity strace-tail amendment's prose already counts an "exit/kill
trailer" as proof the file captured its tracee's death, but the loader
parses only ``+++ exited with N +++`` into ExitTrailer -- ``+++ killed by
SIGxxx +++`` stayed a base StraceLine, so the newest trace record being a
kill trailer under the observer's own stop sequence still flagged
strace_tail_truncated (observed: paper-l2-r1-20261026-171050 db-server,
trace.18 ends ``+++ killed by SIGTERM +++`` 30.001s before the bracket,
delta = the TERM grace + escalation window; every strace-consuming FM on
that host degraded to UNMEASURED).

This lock pins the closed-form fix: the tail check recognizes the
kill-trailer form on the newest record's raw text.  The loader's record
hierarchy is deliberately untouched -- fm_1_2/fm_4_5 branch on
``type(line) is StraceLine`` plus their own killed-by regex, and their
semantics must not shift.

Fail-closed stays fail-closed: a kill trailer WITHOUT the observer's
workload-directed stop signal behind it still flags, and a mid-stream
tail still flags.
"""

from __future__ import annotations

import sys
from pathlib import Path

TESTS_FM_DIR = Path(__file__).resolve().parent
REPO_ROOT = TESTS_FM_DIR.parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from analysis.integrity import stream_integrity  # noqa: E402
from analysis.observation import Observation  # noqa: E402
from analysis.records import (  # noqa: E402
    StraceLine,
    SupervisorEvent,
    SyscallLine,
)

B = 1790000000.0


def trace_line(seq, ts, pid, raw="getpid() = 1"):
    return SyscallLine(file_pid=pid, seq=seq, ts=ts, raw=raw,
                       name="getpid", args_raw="", result_raw="1")


def kill_trailer_line(seq, ts, pid, sig="SIGTERM"):
    # exactly the loader's output class for '+++ killed by ... +++':
    # a base StraceLine (NOT ExitTrailer), ts-prefixed raw text.
    return StraceLine(file_pid=pid, seq=seq, ts=ts,
                      raw=f"{ts:.6f} +++ killed by {sig} +++")


def workload_signal(seq, ts, signal_no=15, name="workload", pid=100):
    return SupervisorEvent(seq=seq, ts=ts, event="sensor_signal",
                           name=name, pid=pid, signal=signal_no)


def supervisor_bracket(ws=B, we=B + 600.0, pid=100, extra=()):
    events = [
        SupervisorEvent(seq=1, ts=ws, event="workload_started", pid=pid,
                        effective_argv=None),
        SupervisorEvent(seq=2, ts=we, event="workload_exited", pid=pid,
                        returncode=-9),
    ]
    return list(events) + list(extra)


def _tail_obs(strace_records, supervisor_records):
    return Observation(root=Path("."),
                       supervisor=tuple(supervisor_records),
                       strace=tuple(strace_records))


def test_tail_kill_trailer_in_stop_sequence_not_flagged():
    # meas-campaign shape (db-server): supervisor TERM at B+0.6, tracee
    # self-terminates at B+2.07 with the kill trailer flushed, the
    # escalation window carries workload_exited 30s later -> death under
    # the observer's own stop sequence, not tail loss.
    strace = [
        trace_line(1, B + 0.1, 101),
        kill_trailer_line(2, B + 2.07, 101),
    ]
    sup = supervisor_bracket(we=B + 32.0,
                             extra=[workload_signal(3, B + 0.6)])
    flags = stream_integrity(_tail_obs(strace, sup))
    assert not [f for f in flags if f.code == "strace_tail_truncated"]


def test_tail_kill_trailer_without_stop_signal_still_flagged():
    # kill trailer but NO workload-directed signal accounting for the gap:
    # unexplained silence before the bracket stays tail loss.
    strace = [
        trace_line(1, B + 0.1, 101),
        kill_trailer_line(2, B + 2.0, 101),
    ]
    sup = supervisor_bracket(we=B + 40.0)
    flags = [f for f in stream_integrity(_tail_obs(strace, sup))
             if f.code == "strace_tail_truncated"]
    assert len(flags) == 1
    assert "trace_pid=101" in flags[0].detail


def test_tail_kill_trailer_before_signal_still_flagged():
    # kill trailer landing BEFORE the workload-directed signal cannot be
    # attributed to the stop sequence (pre-stop death, tail must reach
    # the bracket): still tail loss.
    strace = [
        trace_line(1, B + 0.1, 101),
        kill_trailer_line(2, B + 0.5, 101),
    ]
    sup = supervisor_bracket(we=B + 40.0,
                             extra=[workload_signal(3, B + 30.0)])
    flags = [f for f in stream_integrity(_tail_obs(strace, sup))
             if f.code == "strace_tail_truncated"]
    assert len(flags) == 1


def test_tail_sigkill_trailer_in_stop_sequence_not_flagged():
    # the escalation path's SIGKILL deaths must prove equally.
    strace = [
        trace_line(1, B + 0.1, 101),
        kill_trailer_line(2, B + 12.0, 101, sig="SIGKILL"),
    ]
    sup = supervisor_bracket(we=B + 32.0,
                             extra=[workload_signal(3, B + 0.6)])
    flags = stream_integrity(_tail_obs(strace, sup))
    assert not [f for f in flags if f.code == "strace_tail_truncated"]


def test_loader_hierarchy_unchanged_for_kill_lines():
    # fm_1_2/fm_4_5 branch on type(line) is StraceLine + their own
    # killed-by regex: the loader must keep producing a base StraceLine
    # for kill trailers (the fix is integrity-local, not a new subclass).
    from analysis.observation import parse_strace_line
    line = parse_strace_line(
        18, 7, "1793035822.070704 +++ killed by SIGTERM +++")
    assert type(line) is StraceLine
