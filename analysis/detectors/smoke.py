"""Scaffold plumbing detector (NOT a failure-mode detector).

FM_ID is ``SMOKE``, not an FM id: this module exists so the
loader -> detector -> CLI path is exercised end-to-end by
tests/fm/test_scaffold.py and stays green for implementers.  It emits one
unit per always-on stream: PASS when the stream parsed with records and no
integrity flags touch it, UNMEASURED (with the merged flags) otherwise — the
same merge pattern (flags_for_streams + flag_strings) the FM detectors are
expected to copy.  ``bash_history`` is deliberately excluded: it is
corroboration-tier and legitimately absent in non-interactive runs.
"""

from __future__ import annotations

from typing import Any, Mapping

from ..integrity import flag_strings, flags_for_streams
from ..observation import Observation
from ..verdict import UnitResult

FM_ID = "SMOKE"

DEPENDS_ON = frozenset({
    "supervisor",
    "processes",
    "filesystem_events",
    "filesystem_monitor",
    "reconciliation",
    "sockets",
    "bcc_status",
    "syscalls",
    "health",
})

#: stream name -> record count accessor on Observation.
_STREAM_COUNTS = {
    "supervisor": lambda obs: len(obs.supervisor),
    "processes": lambda obs: len(obs.processes),
    "filesystem_events": lambda obs: len(obs.filesystem_events),
    "filesystem_monitor": lambda obs: len(obs.filesystem_monitor),
    "reconciliation": lambda obs: len(obs.reconciliation),
    "sockets": lambda obs: len(obs.sockets),
    "bcc_status": lambda obs: len(obs.bcc_status),
    "syscalls": lambda obs: len(obs.strace),
    "health": lambda obs: 1 if obs.health is not None else 0,
}


def detect(obs: Observation, cfg: Mapping[str, Any]) -> tuple[UnitResult, ...]:
    units: list[UnitResult] = []
    merged = flags_for_streams(obs.flags, DEPENDS_ON)
    for stream in sorted(_STREAM_COUNTS):
        count = _STREAM_COUNTS[stream](obs)
        stream_flags = flag_strings(
            flags_for_streams(merged, (stream,)))
        key = f"SMOKE/stream={stream}"
        if count > 0 and not stream_flags:
            units.append(UnitResult.passed(
                FM_ID, key, evidence=(f"records={count}",)))
        else:
            reasons = [f"records={count}"]
            flags = tuple(stream_flags) or (f"SMOKE:stream_missing",)
            units.append(UnitResult.unmeasured(
                FM_ID, key, reasons=reasons, integrity_flags=flags))
    return tuple(units)
