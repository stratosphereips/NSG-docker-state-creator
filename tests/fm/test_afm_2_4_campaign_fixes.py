"""Campaign-amendment locks for AFM2/AFM4 + the shared integrity floor.

Every lock here pins a 2026-10-26 campaign-review amendment (see
paper-labs/afm_review/AFM2_AFM4.md) to a closed-form test:

- integrity.scan_cadence_limit / observed_scan_cadence: the reconciliation
  cadence limit derives from the OBSERVED median inter-scan gap once the
  run demonstrates >= 3 gaps (a healthy reconciler stretched 2-10x under
  campaign load is not a dead one), never below the declared floor, and
  a genuine stall still flags.
- integrity.stream_integrity strace tail: a workload_exited trailing the
  newest tracee death by a stop-grace window is NOT tail loss when the
  newest trace record is a death trailer under the observer's own stop
  sequence (a workload-directed supervisor signal at/before it); without
  that attribution, or with a mid-stream tail, the flag stays.
- integrity.workload_root_trace_missing: the observer's strace-WRAPPER
  launch form (workload pid census-named ``strace``) carries the
  root-trace requirement on the root TRACEE's file; a traced-root form
  (or the strict 4-argument call afm_1/afm_3 use) keeps the hole flag.
- afm_4 r1 fork-ts exemption: a fork-proven tree child with no census
  identity whose every kernel-confirmed fork line is strictly AFTER the
  workload_exited anchor is post-teardown (never residue, never
  death-evidence-required); a fork line at/before the anchor, or without
  a ts, stays fail-closed.
- afm_4 post-exit census: the observer's final-sweep output (plain
  process_seen/process_gone records timestamped after the anchor, same
  schema) is recognized with zero format changes and lets the residue
  sweep decide instead of degrading AFM4:post_exit_census_missing.
"""

from __future__ import annotations

import sys
from pathlib import Path

TESTS_FM_DIR = Path(__file__).resolve().parent
REPO_ROOT = TESTS_FM_DIR.parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from analysis import integrity  # noqa: E402
from analysis.detectors import afm_4  # noqa: E402
from analysis.integrity import (  # noqa: E402
    observed_scan_cadence,
    scan_cadence_limit,
    stream_integrity,
    workload_root_trace_missing,
)
from analysis.observation import Observation  # noqa: E402
from analysis.records import (  # noqa: E402
    ExitTrailer,
    ProcRecord,
    ReconEvent,
    StraceLine,
    SupervisorEvent,
    SyscallLine,
)
from analysis.verdict import Outcome  # noqa: E402

B = 1790000000.0


# ---------------------------------------------------------------------------
# hand-built observations (pure data, no fixture dirs needed)
# ---------------------------------------------------------------------------


def supervisor_bracket(ws=B, we=B + 600.0, pid=100,
                       effective_argv=None, extra=()):
    events = [
        SupervisorEvent(seq=1, ts=ws, event="workload_started", pid=pid,
                        effective_argv=effective_argv),
        SupervisorEvent(seq=2, ts=we, event="workload_exited", pid=pid,
                        returncode=0),
    ]
    return list(events) + list(extra)


def recon_stream(baseline_ts, scan_ts, interval=30.0):
    records = [ReconEvent(seq=1, ts=baseline_ts,
                          event="baseline_complete", files=10,
                          interval_seconds=interval)]
    for index, ts in enumerate(scan_ts):
        records.append(ReconEvent(seq=2 + index, ts=ts,
                                  event="scan_complete", files=10))
    return records


def census_seen(seq, ts, pid, start_ticks="1", name="p", ppid=-1,
                cmdline=""):
    return ProcRecord(seq=seq, ts=ts, event="process_seen", pid=pid,
                      start_ticks=start_ticks, name=name, ppid=ppid,
                      cmdline=cmdline or name)


def census_gone(seq, ts, pid, start_ticks="1", name="p"):
    return ProcRecord(seq=seq, ts=ts, event="process_gone", pid=pid,
                      start_ticks=start_ticks, name=name)


def trace_line(seq, ts, pid, raw="getpid() = 1"):
    return SyscallLine(file_pid=pid, seq=seq, ts=ts, raw=raw,
                       name="getpid", args_raw="", result_raw="1")


def trailer(seq, ts, pid, code=0):
    return ExitTrailer(file_pid=pid, seq=seq, ts=ts, raw="+++ exited +++",
                       code=code)


def workload_signal(seq, ts, signal_no=15, name="workload", pid=100):
    return SupervisorEvent(seq=seq, ts=ts, event="sensor_signal",
                           name=name, pid=pid, signal=signal_no)


# ---------------------------------------------------------------------------
# cadence limit derivation
# ---------------------------------------------------------------------------


def test_cadence_limit_declared_floor_without_evidence():
    # no gaps / fewer than 3 gaps: the median is not evidence, the
    # declared contract floor max(3*interval, interval+60) governs.
    assert scan_cadence_limit(30.0, []) == 90.0
    assert scan_cadence_limit(30.0, [90.0, 95.0]) == 90.0
    assert scan_cadence_limit(45.0, []) == 135.0
    assert scan_cadence_limit(30.0, [10.0, 10.0]) == 90.0  # floor, not lower


def test_cadence_limit_stretches_with_observed_median():
    # campaign shape: a healthy reconciler at 3x the declared interval
    # under load (median gap 100s at interval 30s) -> limit 300s, so the
    # observed 90..290s gaps are not a dead reconciler.
    gaps = [100.0] * 9 + [289.0]
    assert scan_cadence_limit(30.0, gaps) == 300.0


def test_cadence_limit_still_catches_a_stall():
    # a genuine stall among healthy gaps: 3x the host's own demonstrated
    # median is still anomalous.
    gaps = [100.0] * 9 + [3000.0]
    assert scan_cadence_limit(30.0, gaps) == 300.0
    assert 3000.0 > scan_cadence_limit(30.0, gaps)


def test_observed_scan_cadence_never_below_declared():
    assert observed_scan_cadence(30.0, []) == 30.0
    assert observed_scan_cadence(30.0, [10.0] * 5) == 30.0
    assert observed_scan_cadence(30.0, [120.0] * 5) == 120.0


def test_stream_integrity_healthy_loaded_reconciler_not_flagged():
    # the exact campaign false degradation: interval=30, ten scans at
    # ~100s spacing (2-10x stretch under load) -> no scan_cadence_gap.
    scans = [B + 100.0 * (i + 1) for i in range(10)]
    obs = Observation(root=Path("."), reconciliation=recon_stream(B, scans))
    flags = stream_integrity(obs)
    assert not [f for f in flags if f.code == "scan_cadence_gap"]


def test_stream_integrity_stalled_reconciler_still_flagged():
    # healthy ~100s cadence, then one 3000s hole: the dead reconciler is
    # still named (the limit is 3x the host's own median, 300s).
    scans = [B + 100.0 * (i + 1) for i in range(9)]
    scans.append(scans[-1] + 3000.0)
    obs = Observation(root=Path("."), reconciliation=recon_stream(B, scans))
    flags = [f for f in stream_integrity(obs)
             if f.code == "scan_cadence_gap"]
    assert len(flags) == 1
    assert "gap=3000.0s" in flags[0].detail
    assert "limit=300.0s" in flags[0].detail


# ---------------------------------------------------------------------------
# strace tail: stop-sequence attribution
# ---------------------------------------------------------------------------


def _tail_obs(strace_records, supervisor_records):
    return Observation(root=Path("."),
                       supervisor=tuple(supervisor_records),
                       strace=tuple(strace_records))


def test_tail_death_trailer_in_stop_sequence_not_flagged():
    # campaign samba shape: TERM at B+0.6, tracees die at B+0.65 with the
    # death trailer flushed, workload_exited lands 50s later at the
    # escalation kill -> NOT tail loss.
    strace = [
        trace_line(1, B + 0.1, 101),
        trailer(2, B + 0.65, 101),
        trace_line(1, B + 0.2, 102),
        trailer(2, B + 0.63, 102),
    ]
    sup = supervisor_bracket(we=B + 50.9,
                             extra=[workload_signal(3, B + 0.6)])
    flags = stream_integrity(_tail_obs(strace, sup))
    assert not [f for f in flags if f.code == "strace_tail_truncated"]


def test_tail_trailer_without_stop_signal_still_flagged():
    # same late bracket with NO workload-directed signal accounting for
    # the gap: unexplained silence stays tail loss (the fm_4_5
    # degraded_strace_tail lock).
    strace = [trace_line(1, B + 83.5, 101), trailer(2, B + 83.6, 101)]
    sup = supervisor_bracket(we=B + 220.0)
    flags = [f for f in stream_integrity(_tail_obs(strace, sup))
             if f.code == "strace_tail_truncated"]
    assert len(flags) == 1
    assert "trace_pid=101" in flags[0].detail


def test_tail_mid_stream_without_trailer_still_flagged():
    # strace killed before flush: newest file ends mid-stream, no trailer.
    strace = [trace_line(1, B + 10.0, 101), trace_line(2, B + 20.0, 101)]
    sup = supervisor_bracket(we=B + 60.0,
                             extra=[workload_signal(3, B + 0.5)])
    flags = [f for f in stream_integrity(_tail_obs(strace, sup))
             if f.code == "strace_tail_truncated"]
    assert len(flags) == 1


def test_tail_within_tolerance_never_flagged():
    strace = [trace_line(1, B + 598.5, 101)]
    sup = supervisor_bracket(we=B + 600.0)
    flags = stream_integrity(_tail_obs(strace, sup))
    assert not [f for f in flags if f.code == "strace_tail_truncated"]


# ---------------------------------------------------------------------------
# workload root trace: launcher form
# ---------------------------------------------------------------------------


LAUNCHER_ARGV = ("strace", "-ff", "-ttt", "-T", "-yy", "-s", "4096",
                 "-o", "/observation/syscalls/trace", "--", "bash", "-lc",
                 "work")


def _started(effective_argv):
    return SupervisorEvent(seq=1, ts=B, event="workload_started", pid=15,
                           effective_argv=effective_argv)


def test_root_trace_present_never_missing():
    started = _started(None)
    assert workload_root_trace_missing(started, 100, {100, 101},
                                       {100}) is False


def test_root_trace_launcher_form_carried_by_root_tracee():
    # real observer capture: workload pid 15 IS the strace launcher
    # (census-named strace); trace.15 cannot exist, trace.18 (the root
    # tracee) does -> requirement met.
    started = _started(LAUNCHER_ARGV)
    census = (census_seen(1, B, 15, name="strace", ppid=1),
              census_seen(2, B, 18, name="sh", ppid=15))
    assert workload_root_trace_missing(
        started, 15, {15, 18}, {18}, processes=census) is False


def test_root_trace_launcher_form_without_any_tree_trace_is_a_hole():
    started = _started(LAUNCHER_ARGV)
    census = (census_seen(1, B, 15, name="strace", ppid=1),)
    assert workload_root_trace_missing(
        started, 15, {15}, set(), processes=census) is True


def test_root_trace_strict_without_census_proof():
    # the argv SPELLING alone does not excuse a missing root trace
    # (fixtures model the workload pid as the traced root with the same
    # effective_argv): without census proof the caller gets the strict
    # form -- the afm_1/afm_3 regression-lock semantics.
    started = _started(LAUNCHER_ARGV)
    assert workload_root_trace_missing(
        started, 100, {100, 101}, {101}) is True  # no processes passed
    bash_named = (census_seen(1, B, 100, name="bash", ppid=1),)
    assert workload_root_trace_missing(
        started, 100, {100, 101}, {101}, processes=bash_named) is True


# ---------------------------------------------------------------------------
# afm_4: r1 fork-ts exemption + final-sweep census recognition
# ---------------------------------------------------------------------------


CFG = {"contract_version": "2026-10-d"}


def _afm4_obs(processes, strace_records, supervisor_records):
    # strace_files must mirror the trace.PID files the records simulate
    # (the loader derives them from a directory listing).
    files = tuple(Path(f"syscalls/trace.{r.file_pid}")
                  for r in strace_records)
    return Observation(root=Path("."),
                       supervisor=tuple(supervisor_records),
                       processes=tuple(processes),
                       strace=tuple(strace_records),
                       strace_files=files)


def test_afm4_post_anchor_fork_child_is_not_death_evidence_required():
    # campaign shape (l2skill/r2 db-server): the workload root 100 is
    # census-named strace (launcher), a tree member 101 (census child,
    # traced) forks a helper 900 AFTER the anchor; 900 is never
    # census-sighted and its trace exits after the anchor.  r1: born
    # after workload_exited -> note, never AFM4:death_evidence_missing,
    # and the unit decides (PASS: everything else death-evidenced).
    sup = [
        SupervisorEvent(seq=1, ts=B, event="workload_started", pid=100,
                        effective_argv=LAUNCHER_ARGV),
        SupervisorEvent(seq=2, ts=B + 100.0, event="workload_exited",
                        pid=100, returncode=0),
    ]
    processes = [
        census_seen(1, B + 0.5, 100, "100", name="strace", ppid=1),
        census_seen(2, B + 1.0, 101, "201", name="sh", ppid=100),
        census_gone(3, B + 99.0, 101, "201", name="sh"),
    ]
    strace_records = [
        trailer(1, B + 99.5, 101),
        # the fork LINE itself is timestamped after the anchor (kernel
        # truth): the child never overlapped the engagement window
        SyscallLine(file_pid=101, seq=2, ts=B + 130.0,
                    raw="clone(...) = 900", name="clone",
                    args_raw="", result_raw="900"),
        trace_line(1, B + 130.5, 900, "getpid() = 900"),
        trailer(2, B + 131.0, 900),
    ]
    units = afm_4.detect(_afm4_obs(processes, strace_records, sup), CFG)
    unit = units[0]
    assert unit.unit_key == "AFM4/run"
    assert unit.outcome is Outcome.PASS, unit.integrity_flags
    assert not any("death_evidence_missing" in f
                   for f in unit.integrity_flags)
    assert any("tree_member_post_anchor" in r for r in unit.evidence)


def test_afm4_in_window_fork_child_still_death_evidence_required():
    # the same shape with the fork BEFORE the anchor stays fail-closed:
    # the census blind spot is genuinely undecidable.
    sup = [
        SupervisorEvent(seq=1, ts=B, event="workload_started", pid=100,
                        effective_argv=LAUNCHER_ARGV),
        SupervisorEvent(seq=2, ts=B + 100.0, event="workload_exited",
                        pid=100, returncode=0),
    ]
    processes = [
        census_seen(1, B + 0.5, 100, "100", name="strace", ppid=1),
        census_seen(2, B + 1.0, 101, "201", name="sh", ppid=100),
        census_gone(3, B + 99.0, 101, "201", name="sh"),
    ]
    strace_records = [
        # fork IN window at B+50: the child overlapped the engagement
        # window; its trailer lands after the anchor, so its fate at the
        # anchor is undecidable -> the fail-closed flag stays
        SyscallLine(file_pid=101, seq=1, ts=B + 50.0,
                    raw="clone(...) = 900", name="clone",
                    args_raw="", result_raw="900"),
        trailer(2, B + 99.5, 101),
        trailer(1, B + 110.0, 900),
    ]
    units = afm_4.detect(_afm4_obs(processes, strace_records, sup), CFG)
    unit = units[0]
    assert unit.outcome is Outcome.UNMEASURED
    assert any("AFM4:death_evidence_missing pid=900" in f
               for f in unit.integrity_flags)


def test_afm4_final_sweep_burst_decides_residue():
    # the observer's post-exit final census flush writes PLAIN
    # process_seen records timestamped after the anchor (same schema);
    # a surviving tree child sighted only by that burst is residue FAIL
    # -- zero format changes needed in the detector.
    sup = [
        SupervisorEvent(seq=1, ts=B, event="workload_started", pid=100,
                        effective_argv=LAUNCHER_ARGV),
        SupervisorEvent(seq=2, ts=B + 100.0, event="workload_exited",
                        pid=100, returncode=0),
    ]
    processes = [
        census_seen(1, B + 0.5, 100, "100", name="strace", ppid=1),
        census_seen(2, B + 1.0, 101, "201", name="sh", ppid=100),
        census_seen(3, B + 2.0, 102, "202", name="backdoor",
                    ppid=100, cmdline="backdoor --serve"),
        census_gone(4, B + 99.0, 101, "201", name="sh"),
        # final sweep at the anchor + 0.2s: 102 still alive
        census_seen(5, B + 100.2, 102, "202", name="backdoor",
                    ppid=100, cmdline="backdoor --serve"),
    ]
    strace_records = [
        SyscallLine(file_pid=101, seq=1, ts=B + 2.0,
                    raw="clone(...) = 102", name="clone",
                    args_raw="", result_raw="102"),
        trailer(2, B + 99.5, 101),
        trace_line(1, B + 90.0, 102, "accept(...) = 4"),
    ]
    units = afm_4.detect(_afm4_obs(processes, strace_records, sup), CFG)
    unit = units[0]
    assert unit.outcome is Outcome.FAIL, unit.integrity_flags
    assert any("residue_process pid=102" in e for e in unit.evidence)


def test_afm4_no_post_exit_tick_degrades():
    # without the flush (a census that stopped before the anchor) the
    # same surviving child is undecidable: AFM4:post_exit_census_missing.
    sup = [
        SupervisorEvent(seq=1, ts=B, event="workload_started", pid=100,
                        effective_argv=LAUNCHER_ARGV),
        SupervisorEvent(seq=2, ts=B + 100.0, event="workload_exited",
                        pid=100, returncode=0),
    ]
    processes = [
        census_seen(1, B + 0.5, 100, "100", name="strace", ppid=1),
        census_seen(2, B + 1.0, 101, "201", name="sh", ppid=100),
        census_seen(3, B + 2.0, 102, "202", name="backdoor",
                    ppid=100, cmdline="backdoor --serve"),
        census_gone(4, B + 99.0, 101, "201", name="sh"),
        census_gone(5, B + 99.5, 100, "100", name="strace"),
    ]
    strace_records = [
        SyscallLine(file_pid=101, seq=1, ts=B + 2.0,
                    raw="clone(...) = 102", name="clone",
                    args_raw="", result_raw="102"),
        trailer(2, B + 99.5, 101),
        trace_line(1, B + 90.0, 102, "accept(...) = 4"),
    ]
    units = afm_4.detect(_afm4_obs(processes, strace_records, sup), CFG)
    unit = units[0]
    assert unit.outcome is Outcome.UNMEASURED
    assert any("AFM4:post_exit_census_missing" in f
               for f in unit.integrity_flags)
