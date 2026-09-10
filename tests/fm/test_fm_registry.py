"""Unified FM registry consistency tests.

The registry (fm_measurement/registry/fm_registry.json) is the single map
of every failure mode in the taxonomy to every surface that implements it.
These tests make it impossible for the registry to drift from the code:

- bidirectional vs analysis/detectors/ (every detector claimed, every claim
  backed by a file, module name == normalized FM id),
- bidirectional vs the sms_harness analyzer set via the explicit module
  inventory (inventory must exactly match the sms/ directory),
- taxonomy counts and status vocabulary enforced.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
REGISTRY_PATH = REPO / "fm_measurement" / "registry" / "fm_registry.json"
DETECTORS_DIR = REPO / "analysis" / "detectors"
SMS_DIR = REPO / "fm_measurement" / "sms_harness" / "sms"

NON_DETECTOR_MODULES = {"smoke", "__init__"}

VALID_NSG_DSC = {"tested", "wip", "rejected", "folded", "absorbed_into_fm_4_1"}
VALID_SMS = {
    "measured",
    "implementation_removed_2026_08_27",
    "removed_from_playbook_2026_08_27",
}


def _load() -> dict:
    return json.loads(REGISTRY_PATH.read_text())


def _normalize(fm_id: str) -> str:
    # FM4.5 -> fm_4_5, AFM1 -> afm_1, SFM2 -> sfm_2
    return re.sub(r"^([A-Z]+)(\d)", r"\1_\2", fm_id).lower().replace(".", "_")


def _disk_detectors() -> set[str]:
    return {
        p.stem
        for p in DETECTORS_DIR.glob("*.py")
        if p.stem not in NON_DETECTOR_MODULES
    }


def _registry_nsg_dsc_modules(registry: dict) -> set[str]:
    modules: set[str] = set()
    for mode in registry["modes"]:
        entry = mode.get("nsg_dsc") or {}
        module = entry.get("module")
        if module:
            assert module == _normalize(mode["id"]), (
                f"{mode['id']}: module {module!r} violates the naming convention"
            )
            modules.add(module)
    return modules


def test_registry_loads_and_taxonomy_counts_add_up():
    registry = _load()
    modes = registry["modes"]
    roles = registry["taxonomy"]["roles"]
    assert len(modes) == registry["taxonomy"]["total"]
    by_role: dict[str, int] = {}
    for mode in modes:
        by_role[mode["role"]] = by_role.get(mode["role"], 0) + 1
    assert by_role == roles
    assert len({m["id"] for m in modes}) == len(modes), "duplicate FM ids"
    assert re.fullmatch(r"(FM|AFM|SFM)\d+(\.\d+)?", modes[0]["id"])


def test_nsg_dsc_modules_bidirectional_with_disk():
    registry = _load()
    claimed = _registry_nsg_dsc_modules(registry)
    disk = _disk_detectors()
    assert claimed == disk, (
        f"registry/detectors drift: unclaimed on disk={sorted(disk - claimed)}, "
        f"registered but missing={sorted(claimed - disk)}"
    )


def test_nsg_dsc_statuses_and_wip_discipline():
    registry = _load()
    wip = []
    for mode in registry["modes"]:
        entry = mode.get("nsg_dsc") or {}
        status = entry.get("status")
        assert status in VALID_NSG_DSC, f"{mode['id']}: bad nsg_dsc status {status!r}"
        if status == "wip":
            wip.append(mode["id"])
            assert entry.get("note"), f"{mode['id']}: wip requires an explanatory note"
        if status == "rejected":
            assert entry.get("reason"), f"{mode['id']}: rejection requires a reason"
    assert wip == ["FM1.3"], f"unexpected wip set: {wip}"


def test_sms_inventory_matches_directory_exactly():
    registry = _load()
    inventory = registry["sms_module_inventory"]
    listed = set(inventory["analyzers"]) | set(inventory["substrate"])
    disk = {p.name for p in SMS_DIR.glob("*.py")} - {"__init__.py"}
    assert listed == disk, (
        f"sms inventory drift: unlisted={sorted(disk - listed)}, "
        f"gone={sorted(listed - disk)}"
    )
    assert not (set(inventory["analyzers"]) & set(inventory["substrate"]))


def test_sms_analyzers_bidirectional_with_modes():
    registry = _load()
    claimed: set[str] = set()
    for mode in registry["modes"]:
        entry = mode.get("sms_harness")
        if not entry:
            continue
        status = entry.get("status")
        assert status in VALID_SMS, f"{mode['id']}: bad sms status {status!r}"
        module = entry.get("module")
        if module:
            assert (SMS_DIR / module).is_file(), f"{mode['id']}: {module} missing"
            claimed.add(module)
    analyzers = set(registry["sms_module_inventory"]["analyzers"])
    assert claimed == analyzers, (
        f"analyzer drift: unclaimed={sorted(analyzers - claimed)}, "
        f"not in inventory={sorted(claimed - analyzers)}"
    )


def test_measured_anywhere_count():
    registry = _load()
    measured = {
        m["id"]
        for m in registry["modes"]
        if (m.get("nsg_dsc") or {}).get("status") == "tested"
        or (m.get("sms_harness") or {}).get("status") == "measured"
        or (m.get("netsecgame") or {}).get("status") == "measured"
    }
    assert len(measured) == registry["taxonomy"]["measured_anywhere"]
