"""CLI over an /observation directory.

Usage::

    python3.12 -m analysis.analyze /path/to/observation \
        [--config DIR] [--fm FM4.2 ...] [--agent ID] [--per-host] [--json] \
        [--out verdicts.jsonl]

Detectors are auto-discovered from the ``analysis.detectors`` package via
pkgutil (each module must export ``FM_ID: str`` and
``detect(obs, cfg) -> tuple[UnitResult, ...]``); adding a detector module
requires no registration edit.  Config files are optional JSON looked up as
``DIR/<module_name>.json`` then ``DIR/<fm_id>.json`` (e.g. fm_4_2.json).

Per-agent default (HARD REQUIREMENT, 2026-11-11: "FMs should be given to
each AGENT, not to the hosts" — supersedes the opt-in design): without
flags, ALL agent trees across the observation's hosts are DISCOVERED
automatically (opencode-serve census pattern + supervisor workload
brackets, analysis/agents.py) and the full FM battery runs PER AGENT —
units keyed ``FM<id>/agent=<id>``, one verdict set per agent plus an
aggregate summary block.  Roles are human-declared in ``DIR/agents.json``
(minimal form ``{"roles": {"<host>": "attacker"|"defender"}}`` — the
campaign runner emits it per run — or the full per-agent form); no roles
map -> every agent role ``unknown``: only shared-surface FMs decide and
every role-scoped FM emits a run-level UNMEASURED with
``agents:role_undeclared`` (fail-closed, never guessed).  Estate hosts
with no agent tree contribute evidence only and get NO FM units; a
zero-agent observation yields ZERO FM units + ``agents:none_detected``.

CLI surface:
- default: per-agent auto (above);
- ``--agent ID``: restrict to one agent (registry-declared or discovered);
- ``--per-host``: explicitly-requested LEGACY/debug mode reproducing the
  pre-2026-11-11 per-host behavior byte-for-byte — without it, per-host
  output never appears;
- ``--fm`` filters within the agent scope.

Outputs:
- ``verdicts.jsonl`` (path from ``--out``): one header line, then one line
  per unit, in canonical JSON (per-agent runs carry the agent blocks +
  summary in the header).
- stdout: a human table with per-agent sections (or the canonical JSON
  document with ``--json``).

Exit codes: 0 on completion regardless of verdicts (verdicts are data),
2 on usage error.
"""

from __future__ import annotations

import argparse
import importlib
import json
import pkgutil
import sys
from pathlib import Path
from typing import Any, Mapping

from . import detectors as _detectors_pkg
from .integrity import StreamFlag
from .observation import DEFAULT_ENVELOPE_PINS, EnvelopePins, load_observation
from .verdict import UnitResult

DEFAULT_OUTPUT = "verdicts.jsonl"


def discover_detectors() -> list[Any]:
    """Import every analysis.detectors.* module exporting FM_ID + detect."""
    found: list[Any] = []
    for info in pkgutil.iter_modules(_detectors_pkg.__path__):
        module = importlib.import_module(f"analysis.detectors.{info.name}")
        if hasattr(module, "FM_ID") and hasattr(module, "detect"):
            found.append(module)
    return sorted(found, key=lambda m: str(m.FM_ID))


def load_config(config_dir: Path | None, module: Any) -> dict:
    """Load DIR/<module>.json, DIR/<fm_id>.json, or DIR/config.json.

    Precedence is module-specific first; the generic ``config.json`` name is
    a last resort so a single pre-registered manifest directory (and the
    test fixtures) work without renaming.  {} when absent/invalid.
    """
    if config_dir is None:
        return {}
    fm_id = str(module.FM_ID)
    candidates = [
        config_dir / f"{module.__name__.rsplit('.', 1)[-1]}.json",
        config_dir / f"{fm_id.lower()}.json",
        config_dir / "config.json",
    ]
    for path in candidates:
        if path.is_file():
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
            except ValueError:
                print(f"analyze: invalid config json: {path}", file=sys.stderr)
                return {}
            return data if isinstance(data, dict) else {}
    return {}


def run_analysis(
    observation_dir: Path,
    config_dir: Path | None = None,
    fm_filter: set[str] | None = None,
    pins: EnvelopePins = DEFAULT_ENVELOPE_PINS,
    detector_modules: list[Any] | None = None,
    agent: str | None = None,
    per_host: bool = True,
) -> dict:
    """Load, detect, and return the canonical analysis document.

    Mode selection: ``agent=<id>`` runs the single-agent-scoped battery
    (analysis.agents.run_agent_scoped — registry-declared or discovered);
    ``per_host=False`` with no agent runs the per-agent AUTO mode
    (analysis.agents.run_agents_auto — the CLI default since 2026-11-11:
    discovery + per-agent battery + ``agents:none_detected`` on empty);
    the LIBRARY default ``per_host=True`` keeps the legacy per-host mode
    so detector-level callers are unaffected (the CLI maps flags to
    modes: default per-agent, ``--per-host`` legacy).
    """
    if agent is not None:
        from .agents import run_agent_scoped
        return run_agent_scoped(
            Path(observation_dir), config_dir, fm_filter, agent,
            pins=pins, detector_modules=detector_modules)
    if not per_host:
        from .agents import run_agents_auto
        return run_agents_auto(
            Path(observation_dir), config_dir, fm_filter,
            pins=pins, detector_modules=detector_modules)
    modules = detector_modules if detector_modules is not None \
        else discover_detectors()
    if fm_filter is not None:
        modules = [m for m in modules if str(m.FM_ID) in fm_filter]
    obs = load_observation(Path(observation_dir), pins)
    results: dict[str, list[UnitResult]] = {}
    for module in modules:
        cfg: Mapping[str, Any] = load_config(config_dir, module)
        units = tuple(module.detect(obs, cfg))
        results[str(module.FM_ID)] = sorted(units, key=lambda u: u.unit_key)
    return canonical_document(obs, results)


def canonical_document(obs, results: Mapping[str, list[UnitResult]]) -> dict:
    """The canonical JSON document (stable shapes and ordering)."""
    return {
        "observation_dir": str(obs.root),
        "pins": obs.pins.to_dict(),
        "integrity_flags": [
            flag.to_dict() for flag in sorted(
                obs.flags, key=lambda f: (f.stream, f.code, f.detail))
        ],
        "detectors": {
            fm_id: [unit.to_dict() for unit in units]
            for fm_id, units in sorted(results.items())
        },
    }


def write_verdicts_jsonl(document: Mapping[str, Any], path: Path) -> None:
    """One header line + one line per unit; deterministic order."""
    with Path(path).open("w", encoding="utf-8") as handle:
        header = {
            "observation_dir": document["observation_dir"],
            "pins": document["pins"],
            "integrity_flags": document["integrity_flags"],
        }
        if "agent" in document:      # agent-scoped run: header carries it
            header["agent"] = document["agent"]
        if "mode" in document:       # per-agent auto run: header carries
            header["mode"] = document["mode"]       # the agent blocks and
            header["agents"] = document["agents"]   # the aggregate summary
            header["summary"] = document["summary"]
        handle.write(json.dumps(header, sort_keys=True) + "\n")
        for fm_id in sorted(document["detectors"]):
            for unit in document["detectors"][fm_id]:
                handle.write(json.dumps(unit, sort_keys=True) + "\n")


def _render_unit_rows(rows: list[Mapping[str, Any]]) -> tuple[
        list[str], dict[str, int]]:
    """The FM/UNIT/OUTCOME/EVIDENCE rows for one section of units."""
    lines: list[str] = []
    counts: dict[str, int] = {}
    for unit in rows:
        outcome = unit["outcome"]
        counts[outcome] = counts.get(outcome, 0) + 1
        evidence = " ".join(unit["evidence"][:3])
        if unit["integrity_flags"]:
            evidence = (evidence + " " if evidence else "") + \
                "flags=" + ",".join(unit["integrity_flags"][:2])
        lines.append(
            f"{unit['fm_id']:<10} {unit['unit_key']:<44.44} "
            f"{outcome:<11} {evidence}")
    return lines, counts


def _units_by_agent(document: Mapping[str, Any]) -> dict[str, list[dict]]:
    """Group the per-agent document's units by the agent id embedded in
    each unit key (``FM<id>/agent=<aid>[/...]``)."""
    grouped: dict[str, list[dict]] = {}
    for fm_id in sorted(document["detectors"]):
        for unit in document["detectors"][fm_id]:
            marker = "/agent="
            key = unit["unit_key"]
            agent_id = key[key.index(marker) + len(marker):].split("/", 1)[0] \
                if marker in key else "?"
            grouped.setdefault(agent_id, []).append(unit)
    return grouped


def render_table(document: Mapping[str, Any]) -> str:
    """Human-readable stdout table (per-agent sections in per-agent mode)."""
    lines: list[str] = []
    lines.append(f"observation: {document['observation_dir']}")
    agent = document.get("agent")
    if agent is not None:
        lines.append(
            f"agent: {agent['id']} role={agent['role']}"
            f" home_host={agent['home_host']}"
            f" surfaces={agent['surfaces']}"
            + (" FAIL_CLOSED" if agent.get("fail_closed") else ""))
    summary = document.get("summary")
    if document.get("mode") == "per_agent":
        lines.append(
            f"mode: per_agent agents={summary.get('agents', 0)}"
            f" hosts_evidence_only={summary.get('hosts_evidence_only', [])}")
    pins = document["pins"]
    lines.append(
        f"pins: event_key={pins['event_key']} time_key={pins['time_key']}")
    flags = document["integrity_flags"]
    lines.append(f"integrity flags: {len(flags)}")
    for flag in flags:
        lines.append(
            f"  {flag['stream']}:{flag['code']}:{flag['detail']}")

    if document.get("mode") == "per_agent":
        header = f"{'FM':<10} {'UNIT':<44} {'OUTCOME':<11} EVIDENCE"
        totals = {"PASS": 0, "FAIL": 0, "UNMEASURED": 0}
        grouped = _units_by_agent(document)
        for block in document.get("agents", []):
            lines.append("")
            lines.append(
                f"== agent {block['id']} role={block['role']}"
                f" home_host={block['home_host']}"
                + (" FAIL_CLOSED" if block.get("fail_closed") else ""))
            lines.append(header)
            lines.append("-" * len(header))
            rows, counts = _render_unit_rows(grouped.get(block["id"], []))
            lines.extend(rows)
            for key, value in counts.items():
                totals[key] = totals.get(key, 0) + value
        total = sum(totals.values())
        lines.append("")
        lines.append(
            f"summary: agents={summary.get('agents', 0)} units={total}"
            f" PASS={totals.get('PASS', 0)} FAIL={totals.get('FAIL', 0)}"
            f" UNMEASURED={totals.get('UNMEASURED', 0)}")
        return "\n".join(lines)

    lines.append("")
    header = f"{'FM':<10} {'UNIT':<44} {'OUTCOME':<11} EVIDENCE"
    lines.append(header)
    lines.append("-" * len(header))
    rows, counts = _render_unit_rows(
        [unit for fm_id in sorted(document["detectors"])
         for unit in document["detectors"][fm_id]])
    lines.extend(rows)
    total = sum(counts.values())
    lines.append("")
    lines.append(
        f"summary: units={total} PASS={counts.get('PASS', 0)}"
        f" FAIL={counts.get('FAIL', 0)}"
        f" UNMEASURED={counts.get('UNMEASURED', 0)}")
    return "\n".join(lines)


def _parse_args(argv: list[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="python3.12 -m analysis.analyze",
        description="Post-hoc failure-mode analysis over an /observation"
                    " evidence directory.")
    parser.add_argument("observation_dir", help="path to an /observation copy")
    parser.add_argument("--config", type=Path, default=None,
                        help="directory holding per-detector JSON configs"
                             " (DIR/<module>.json or DIR/<fm_id>.json)")
    parser.add_argument("--fm", action="append", default=None,
                        help="run only these FM ids (repeatable)")
    parser.add_argument("--agent", default=None,
                        help="restrict the per-agent battery to ONE agent"
                             " (registry-declared or auto-discovered id,"
                             " e.g. opencode@client-attacker)")
    parser.add_argument("--per-host", dest="per_host", action="store_true",
                        help="LEGACY/debug: the pre-2026-11-11 per-host"
                             " mode (one FM<id>/run unit set per host);"
                             " without it per-host output never appears"
                             " (the default is per-agent auto)")
    parser.add_argument("--json", action="store_true",
                        help="print the canonical JSON document to stdout")
    parser.add_argument("--out", type=Path, default=None,
                        help=f"verdicts.jsonl output path"
                             f" (default: {DEFAULT_OUTPUT})")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    observation_dir = Path(args.observation_dir)
    if not observation_dir.is_dir():
        print(f"analyze: not a directory: {observation_dir}", file=sys.stderr)
        return 2
    if args.agent is not None and args.per_host:
        print("analyze: --agent and --per-host are mutually exclusive"
              " (--per-host is the legacy per-host mode; --agent scopes to"
              " one agent)", file=sys.stderr)
        return 2
    # CLI default (2026-11-11 HARD REQUIREMENT): per-agent auto.  --per-host
    # restores the legacy per-host behavior; --agent restricts to one agent.
    document = run_analysis(
        observation_dir,
        config_dir=args.config,
        fm_filter=set(args.fm) if args.fm else None,
        agent=args.agent,
        per_host=args.per_host,
    )
    out_path = args.out if args.out is not None else Path(DEFAULT_OUTPUT)
    try:
        write_verdicts_jsonl(document, out_path)
    except OSError as error:
        print(f"analyze: cannot write {out_path}: {error}", file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps(document, sort_keys=True, indent=2))
    else:
        print(render_table(document))
        print(f"verdicts: {out_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
