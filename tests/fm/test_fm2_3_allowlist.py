"""FM2.3 allowlist bookkeeping, re-run as part of the validation suite.

Closes the locked open item (tex appendix, FM2.1--FM2.4 row): "FM2.3
predicate re-pointed at environment monitoring: allowlist bookkeeping must
re-run in the validation suite."  The predicate's per-unit flag routing
rests on one hardcoded allowlist -- ``fm_2_3._SENSOR_OWNED_STREAMS``, the
environment-monitoring streams -> the sanctioned observer (sensor) whose
unit consumes each stream's flags.  Nothing in the detector re-derives
that map; a stale entry (phantom stream name, unsanctioned sensor, an
environment monitor missing from the map, or a floor code the routing
silently drops) fails OPEN at runtime -- degradation flags vanish and the
sabotaged unit PASSes.  Exactly that had happened (2026-10-18, fixed the
same day): loader structural codes on sensor-owned streams fell through
``_route_flag`` to ``[]``, and deleting files/events.jsonl flagged only
the ``filesystem_events`` spelling ``DEPENDS_ON`` did not name.

So this module re-runs the bookkeeping against its three sources of
truth, fail-closed, on every ``make test`` (same wiring discipline as
test_fm_registry.py's registry<->code reconciliation):

1. the observer collector sources (observer/bin/*): every sanctioned
   observer the entrypoint ``start()``s, and every evidence stream each
   monitor declares via ``JsonLog("<path>", "<sensor>")``;
2. the loader's stream vocabulary (analysis.observation.STREAM_PATHS):
   every allowlist key must be a real stream, both spellings of a shared
   file included;
3. the integrity floor's producer table (analysis.integrity): every
   (stream, code) pair the floor can emit on a consumed stream must have
   a non-empty routing destination.

Then the routing itself is re-run over the whole pinned fixture corpus:
no flag on a consumed stream may vanish -- each must land on some unit's
integrity flags unless the addressed sensor was never started in that run
(no unit, nothing to degrade).
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

TESTS_FM_DIR = Path(__file__).resolve().parent
REPO_ROOT = TESTS_FM_DIR.parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))
if str(TESTS_FM_DIR) not in sys.path:
    sys.path.insert(0, str(TESTS_FM_DIR))

from analysis.detectors import fm_2_3  # noqa: E402
from analysis.integrity import StreamFlag  # noqa: E402
from analysis.observation import STREAM_PATHS, load_observation  # noqa: E402
from analysis.verdict import Outcome  # noqa: E402

OBSERVER_BIN = REPO_ROOT / "observer" / "bin"
ENTRYPOINT = OBSERVER_BIN / "observe-entrypoint"
FIXTURES_FM_2_3 = TESTS_FM_DIR / "fixtures" / "fm_2_3"
#: the scaffold smoke fixture is fm_2_3-pinned too (test_fm2_3.py)
SMOKE = TESTS_FM_DIR / "fixtures" / "smoke"

#: observe-entrypoint start("<name>", ...) -- the sanctioned observer roster.
_START_CALL = re.compile(r'\bstart\(\s*"([a-z0-9][a-z0-9-]*)"')
#: JsonLog("<output path>", "<collector name>") in every collector script.
_JSONLOG = re.compile(r'JsonLog\(\s*"([^"]+)",\s*"([^"]+)"')
#: StreamFlag("<stream>", "<code>") pairs the integrity floor can emit.
_FLOOR_PAIR = re.compile(r'StreamFlag\(\s*"([a-z_]+)",\s*"([a-z_]+)"')

#: The supervisor (PID 1) owns supervisor.jsonl but is not a sensor unit;
#: its stream is routed structurally and excluded from the per-sensor map.
SUPERVISOR_NAME = "supervisor"


def _sanctioned_observers() -> set:
    """Every sensor name the observer entrypoint sanctions via start()."""
    return set(_START_CALL.findall(ENTRYPOINT.read_text(encoding="utf-8")))


def _streams_of_path(rel_path: str) -> set:
    """Canonical loader stream names whose STREAM_PATHS entry is rel_path."""
    return {stream for stream, path in STREAM_PATHS.items() if path == rel_path}


def _monitor_stream_ownership() -> dict:
    """sensor name -> set of loader streams it owns, re-derived from the
    collector sources' own JsonLog declarations (closed form: the first
    argument is the output path, the second the collector name)."""
    ownership: dict = {}
    for script in sorted(OBSERVER_BIN.iterdir()):
        if not script.is_file():
            continue
        for rel_path, name in _JSONLOG.findall(
                script.read_text(encoding="utf-8")):
            streams = _streams_of_path(rel_path)
            assert streams, (
                f"{script.name}: JsonLog path {rel_path!r} is not a loader "
                f"stream (STREAM_PATHS drift)")
            ownership.setdefault(name, set()).update(streams)
    return ownership


def _floor_pairs() -> set:
    """Every (stream, code) the integrity floor can emit, from its source."""
    return set(_FLOOR_PAIR.findall(
        (REPO_ROOT / "analysis" / "integrity.py").read_text(encoding="utf-8")))


def _corpus() -> list:
    return sorted(p for p in FIXTURES_FM_2_3.iterdir() if p.is_dir()) + [SMOKE]


# ---------------------------------------------------------------------------
# 1. the allowlist vs the observer collector sources
# ---------------------------------------------------------------------------


def test_allowlist_sensors_are_sanctioned_observers():
    """Every mapped sensor is a name the entrypoint actually starts -- a
    typo or a renamed monitor fails closed here instead of silently
    dropping that monitor's degradation flags at runtime."""
    roster = _sanctioned_observers()
    assert roster, "observe-entrypoint start() roster unexpectedly empty"
    for stream, sensor in fm_2_3._SENSOR_OWNED_STREAMS.items():
        assert sensor in roster, (
            f"allowlist stream {stream!r} names unsanctioned sensor "
            f"{sensor!r}; entrypoint roster={sorted(roster)}")


def test_every_sanctioned_monitor_stream_degrades_its_own_unit():
    """The bookkeeping oracle, one rule no exceptions: for every observer
    that owns a JSONL evidence stream, breaking that stream (the loader's
    stream_missing) must degrade that observer's own unit.  A monitor the
    allowlist forgot -- or a stream whose structural flag routing drops --
    fails here.  (This is the re-run that caught the 2026-10-18 fail-open
    hole: sockets/reconciliation/events deletion left the owning units
    PASSing.)"""
    by_name = _evidence_units(FIXTURES_FM_2_3 / "benign_control")
    for sensor, streams in sorted(_monitor_stream_ownership().items()):
        if sensor == SUPERVISOR_NAME:
            continue                    # PID 1: structural stream, no unit
        assert sensor in by_name, (
            f"sanctioned observer {sensor!r} owns {sorted(streams)} but "
            f"yields no unit in the pinned benign corpus")
        for stream in sorted(streams):
            assert stream in fm_2_3.DEPENDS_ON, (
                f"{sensor}'s stream {stream!r} is not a declared dependency")
            routed = fm_2_3._route_flag(
                StreamFlag(stream, "stream_missing", "allowlist_recheck"),
                by_name)
            assert sensor in routed, (
                f"breaking {stream!r} ({sensor}) routes to "
                f"{routed or 'NOTHING'} -- allowlist bookkeeping is stale "
                f"for this stream")


def _evidence_units(case: Path) -> dict:
    """name -> UnitEvidence for one fixture, built exactly by the module
    docstring's unit-enumeration rule (supervisor sensor_started units,
    bcc tool_started units, the strace launcher), so _route_flag gets the
    record shape it reads (.kind) from real corpus evidence."""
    obs = load_observation(case)
    units: dict = {}
    for record in obs.supervisor:
        if record.event == "sensor_started" and record.name:
            units.setdefault(record.name, fm_2_3.UnitEvidence(
                name=record.name, pid=record.pid, kind="sensor"))
    for record in obs.bcc_status:
        if record.event == "tool_started" and record.tool:
            units.setdefault(record.tool, fm_2_3.UnitEvidence(
                name=record.tool, pid=record.pid, kind="bcc_tool"))
    started = next((r for r in obs.supervisor
                    if r.event == "workload_started"), None)
    if (started is not None and started.effective_argv
            and started.effective_argv[0].rsplit("/", 1)[-1] == "strace"):
        units.setdefault("strace", fm_2_3.UnitEvidence(
            name="strace", pid=started.pid, kind="strace"))
    return units


def test_allowlist_streams_are_real_and_not_dead():
    """Every allowlist key is a loader stream vocabulary name (a phantom
    key can never match a flag) AND a stream some monitor actually writes
    (a key no monitor owns is dead bookkeeping)."""
    ownership = _monitor_stream_ownership()
    owned_streams = set().union(*ownership.values()) if ownership else set()
    for stream in fm_2_3._SENSOR_OWNED_STREAMS:
        assert stream in STREAM_PATHS, (
            f"allowlist key {stream!r} is not a loader stream name")
        assert stream in owned_streams, (
            f"allowlist key {stream!r} is owned by no collector -- dead "
            f"bookkeeping")


# ---------------------------------------------------------------------------
# 2. the allowlist vs the integrity floor's producer table
# ---------------------------------------------------------------------------


def test_every_floor_code_on_a_consumed_stream_routes_somewhere():
    """Re-derive every (stream, code) the floor can emit and prove the
    routing never drops it: structural codes on shared streams go to all
    units, lifecycle codes name a unit or ride the allowlist, and nothing
    on a DEPENDS_ON stream vanishes.  New floor vocabulary drifting past
    the detector's bookkeeping fails here closed."""
    by_name = _evidence_units(FIXTURES_FM_2_3 / "benign_control")
    pairs = _floor_pairs()
    assert pairs, "integrity.py producer table unexpectedly empty"
    assert (("supervisor", "sensor_exited_before_workload_exited") in pairs
            and ("reconciliation", "scan_cadence_gap") in pairs), (
        "producer-table derivation missed known floor emissions")
    for stream, code in sorted(pairs):
        if stream not in fm_2_3.DEPENDS_ON:
            continue                    # a stream this detector never consumes
        detail = "name=process-monitor" if code.startswith(
            "sensor_exited") else (
            "tool=execsnoop-bpfcc" if code.startswith("tool_exited") else "x")
        routed = fm_2_3._route_flag(
            StreamFlag(stream, code, detail), by_name)
        assert routed, (
            f"floor flag {stream}:{code} on a consumed stream routes to "
            f"NOTHING -- silent drop, fail-open")


def test_floor_lifecycle_codes_ride_the_allowlist():
    """The lifecycle codes (monitor_exited / scan cadence) must reach their
    owning sensor's unit through the allowlist, never by luck of a shared
    structural branch."""
    units = fm_2_3.detect(
        load_observation(FIXTURES_FM_2_3 / "benign_control"), {})
    by_name = _evidence_units(FIXTURES_FM_2_3 / "benign_control")
    assert by_name, "benign corpus yielded no units for the oracle"
    lifecycle = {"monitor_exited_before_workload_exited",
                 "scan_cadence_gap", "no_scan_after_baseline"}
    for stream, code in sorted(_floor_pairs()):
        if code not in lifecycle:
            continue
        assert stream in fm_2_3._SENSOR_OWNED_STREAMS, (
            f"lifecycle code {code} emitted on {stream!r} but the allowlist "
            f"does not own that stream")
        owner = fm_2_3._SENSOR_OWNED_STREAMS[stream]
        assert owner in by_name, (
            f"{stream}'s owner {owner!r} has no unit in the benign corpus")


# ---------------------------------------------------------------------------
# 3. re-run the bookkeeping over the pinned fixture corpus
# ---------------------------------------------------------------------------


def test_no_consumed_flag_vanishes_across_the_corpus():
    """The bookkeeping re-run: detect() over every pinned fm_2_3 fixture;
    each flag on a consumed stream must surface on some unit's integrity
    flags.  Two documented, legitimate non-renderings: an addressed sensor
    that was never started (no unit exists -- nothing to degrade), and a
    flag whose destination unit FAILed (sabotage-equals-fail conversion:
    a FAIL unit carries no integrity flags -- the floor flag stays visible
    document-wide via the CLI's integrity_flags, pinned in
    test_fm2_3.py::test_cli_end_to_end_fm_filter)."""
    problems = []
    for case in _corpus():
        obs = load_observation(case)
        results = fm_2_3.detect(obs, {})
        evidence = _evidence_units(case)
        rendered = {f for unit in results for f in unit.integrity_flags}
        failed = {u.unit_key[len("FM2.3/sensor="):] for u in results
                  if u.outcome is Outcome.FAIL}
        unit_names = {u.unit_key[len("FM2.3/sensor="):] for u in results}
        for flag in obs.flags:
            if flag.stream not in fm_2_3.DEPENDS_ON:
                continue
            if str(flag) in rendered:
                continue
            destinations = fm_2_3._route_flag(flag, evidence)
            if not destinations:
                owner = fm_2_3._SENSOR_OWNED_STREAMS.get(flag.stream)
                addressee = None
                if flag.code == "sensor_exited_before_workload_exited":
                    addressee = fm_2_3._field_of(flag.detail, "name")
                elif flag.code == "tool_exited_before_workload_exited":
                    addressee = fm_2_3._field_of(flag.detail, "tool")
                if owner is not None and owner not in unit_names:
                    continue    # sensor never started: no unit to degrade
                if addressee is not None and addressee not in unit_names:
                    continue
                problems.append(f"{case.name}: {flag} routed to NOTHING")
                continue
            if any(name in failed for name in destinations):
                continue    # absorbed by the FAIL conversion, not dropped
            problems.append(f"{case.name}: {flag} routed but never rendered")
    assert not problems, (
        "consumed-stream flags silently dropped (stale allowlist "
        f"bookkeeping): {problems}")


def test_corpus_has_the_three_environment_monitors_started():
    """Guard the oracle corpus itself: every pinned fixture that yields
    units at all starts the three environment monitors the allowlist is
    about, so the corpus re-run actually exercises their routing."""
    for case in _corpus():
        obs = load_observation(case)
        started = {r.name for r in obs.supervisor
                   if r.event == "sensor_started" and r.name}
        if not started:
            continue                # e.g. degraded_no_supervisor: sentinel run
        missing = ({"filesystem-monitor", "state-reconciler",
                    "socket-monitor"} - started)
        assert not missing, (
            f"{case.name}: corpus drifted -- environment monitors "
            f"{sorted(missing)} never started, allowlist unexercised")
