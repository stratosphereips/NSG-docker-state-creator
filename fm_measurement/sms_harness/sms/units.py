"""S3 units: scenario (test mode) or timeline (real mode) -> units.jsonl."""
import json
import os

from . import common

UNITS_PATH = "units.jsonl"
PLANNER_HEALTH_PATH = "planner_health.jsonl"

STATUSES = ("complete", "alert_only", "planner_only")


def _run_id(archive):
    mf = os.path.join(archive, "manifest.json")
    if os.path.exists(mf):
        return json.load(open(mf, "r", encoding="utf-8")).get(
            "run", os.path.basename(os.path.normpath(archive)))
    return os.path.basename(os.path.normpath(archive))


def from_scenario(archive, scenario):
    """scenario = {"units": [unit dicts (schema minus run)], "planner_health":
    [rows] optional}. Writes units.jsonl (+ planner_health.jsonl if given).
    Returns the unit records written."""
    units_in = scenario.get("units", scenario if isinstance(
        scenario, list) else [])
    run = _run_id(archive)
    out = []
    for u in units_in:
        rec = dict(u)
        rec.setdefault("run", run)
        rec.setdefault("status", "complete")
        rec.setdefault("integrity", [])
        assert rec["status"] in STATUSES, rec["status"]
        out.append(rec)
    with open(os.path.join(archive, UNITS_PATH), "w", encoding="utf-8") as fh:
        for rec in out:
            fh.write(json.dumps(rec, separators=(",", ":")) + "\n")
    ph = scenario.get("planner_health") if isinstance(scenario, dict) else None
    if ph:
        with open(os.path.join(archive, PLANNER_HEALTH_PATH), "w",
                  encoding="utf-8") as fh:
            for row in ph:
                fh.write(json.dumps(row, separators=(",", ":")) + "\n")
    return out


def from_timeline(archive, timeline_jsonl):
    """Real mode: group timeline rows by unit_id, aggregate t_* extremes,
    derive status. Returns unit records (also written to units.jsonl)."""
    rows = common.read_jsonl(timeline_jsonl) if isinstance(
        timeline_jsonl, str) else timeline_jsonl
    agg = {}
    order = []
    for r in rows:
        uid = r.get("unit_id")
        if uid not in agg:
            agg[uid] = {"unit_id": uid, "events": []}
            order.append(uid)
        agg[uid]["events"].append(r)
    run = _run_id(archive)
    out = []
    for uid in order:
        evs = sorted(agg[uid]["events"], key=lambda e: e.get("ts", 0))
        hosts = sorted({e.get("host") for e in evs if e.get("host")})
        first, last = evs[0], evs[-1]
        kinds = {e.get("kind") for e in evs}
        if "t_done" in kinds:
            status = "complete"
        elif "t_exec_start" in kinds:
            status = "planner_only"
        else:
            status = "alert_only"
        rec = {
            "unit_id": uid, "run": run, "hosts": hosts,
            "attacker_ip": first.get("attacker_ip", ""),
            "attack_type": first.get("attack_type", "unknown"),
            "t_alert": first.get("ts"),
            "t_plan": next((e["ts"] for e in evs if e.get("kind") == "t_plan"),
                           None),
            "t_exec_start": next((e["ts"] for e in evs
                                  if e.get("kind") == "t_exec_start"), None),
            "t_exec_end": next((e["ts"] for e in evs
                                if e.get("kind") == "t_exec_end"), None),
            "t_done": next((e["ts"] for e in evs if e.get("kind") == "t_done"),
                           None),
            "status": status, "integrity": [],
        }
        out.append(rec)
    with open(os.path.join(archive, UNITS_PATH), "w", encoding="utf-8") as fh:
        for rec in out:
            fh.write(json.dumps(rec, separators=(",", ":")) + "\n")
    return out
