"""CLI over an /observation directory.

Usage::

    python3.12 -m analysis.analyze /path/to/observation \
        [--config DIR] [--fm FM4.2 ...] [--json] [--out verdicts.jsonl]

Detectors are auto-discovered from the ``analysis.detectors`` package via
pkgutil (each module must export ``FM_ID: str`` and
``detect(obs, cfg) -> tuple[UnitResult, ...]``); adding a detector module
requires no registration edit.  Config files are optional JSON looked up as
``DIR/<module_name>.json`` then ``DIR/<fm_id>.json`` (e.g. fm_4_2.json).

Outputs:
- ``verdicts.jsonl`` (path from ``--out``): one header line, then one line
  per unit, in canonical JSON.
- stdout: a human table (or the canonical JSON document with ``--json``).

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
) -> dict:
    """Load, detect, and return the canonical analysis document."""
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
        handle.write(json.dumps(header, sort_keys=True) + "\n")
        for fm_id in sorted(document["detectors"]):
            for unit in document["detectors"][fm_id]:
                handle.write(json.dumps(unit, sort_keys=True) + "\n")


def render_table(document: Mapping[str, Any]) -> str:
    """Human-readable stdout table."""
    lines: list[str] = []
    lines.append(f"observation: {document['observation_dir']}")
    pins = document["pins"]
    lines.append(
        f"pins: event_key={pins['event_key']} time_key={pins['time_key']}")
    flags = document["integrity_flags"]
    lines.append(f"integrity flags: {len(flags)}")
    for flag in flags:
        lines.append(
            f"  {flag['stream']}:{flag['code']}:{flag['detail']}")
    lines.append("")
    header = f"{'FM':<10} {'UNIT':<44} {'OUTCOME':<11} EVIDENCE"
    lines.append(header)
    lines.append("-" * len(header))
    counts = {"PASS": 0, "FAIL": 0, "UNMEASURED": 0}
    for fm_id in sorted(document["detectors"]):
        for unit in document["detectors"][fm_id]:
            outcome = unit["outcome"]
            counts[outcome] = counts.get(outcome, 0) + 1
            evidence = " ".join(unit["evidence"][:3])
            if unit["integrity_flags"]:
                evidence = (evidence + " " if evidence else "") + \
                    "flags=" + ",".join(unit["integrity_flags"][:2])
            lines.append(
                f"{unit['fm_id']:<10} {unit['unit_key']:<44.44} "
                f"{outcome:<11} {evidence}")
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
    document = run_analysis(
        observation_dir,
        config_dir=args.config,
        fm_filter=set(args.fm) if args.fm else None,
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
