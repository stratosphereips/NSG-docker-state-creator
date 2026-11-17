"""Bridge finished fm-defender-lab capture evidence into the FM3.1 witness."""

import argparse
import hashlib
import json
import math
import re
import shlex
from pathlib import Path

from analysis.fm_3_1 import json_bytes, read_plan
from analysis.fm_3_1_live import send

from . import common, host_capture

HOST_CAPTURE = "host_capture"
ROUTER_CAPTURE = "router_capture"
ATTR_WINDOW = 2.0
MAX_HEARTBEAT_GAP = 2 * host_capture.HEARTBEAT_INTERVAL
_MARKER = re.compile(r"SMSHB[0-9a-f]{32}")


def _trusted(archive, filename):
    path = archive / filename
    chain = path.with_name(path.name + ".chain")
    if not path.is_file() or not chain.is_file():
        raise ValueError(f"missing {filename} or its chain")
    if common.hash_chain_verify(str(path))["status"] != "ok":
        raise ValueError(f"unverified {filename}")
    with path.open(encoding="utf-8") as stream:
        rows = [json.loads(line) for line in stream if line.strip()]
    if not all(isinstance(row, dict) for row in rows):
        raise ValueError(f"malformed {filename}")
    return rows


def _time(value):
    if type(value) not in (int, float):
        raise ValueError("invalid host timestamp")
    try:
        if math.isfinite(value):
            return float(value)
    except OverflowError:
        pass
    raise ValueError("invalid host timestamp")


def _window(unit, grace, run_end):
    start = _time(unit.get("t_alert"))
    done = unit.get("t_done")
    if done is None:
        return start, run_end, False
    done = _time(done)
    end = done + grace
    return start, min(end, run_end), start <= done and end <= run_end and start < end


def _host_coverage(archive, start, end):
    sent = _trusted(archive, host_capture.HEARTBEAT_LEDGER)
    manifest = _trusted(archive, host_capture.MANIFEST)
    markers = [row for row in sent if start <= _time(row.get("ts_sent")) <= end]
    times = [start, *(_time(row["ts_sent"]) for row in markers), end]
    if not markers or any(not 0 <= b - a <= MAX_HEARTBEAT_GAP for a, b in zip(times, times[1:])):
        return False
    if not all(isinstance(row.get("marker"), str) and _MARKER.fullmatch(row["marker"]) for row in markers):
        return False
    files = []
    for row in manifest:
        name = row.get("file")
        if not isinstance(name, str) or not re.fullmatch(r"bridge_[^/\\]+\.pcap", name):
            return False
        path = archive / "pcaps_host" / name
        if path.is_symlink() or not path.is_file() or common.sha256_file(str(path)) != row.get("sha256"):
            return False
        files.append(path)
    return bool(files) and all(host_capture.find_marker(files, row["marker"]) for row in markers)


def _tcpdump_stop(record):
    if record.get("actor") != "defender" or record.get("state") != "completed":
        return False
    if type(record.get("exit_code")) is not int or record["exit_code"] != 0:
        return False
    details = record.get("input")
    command = details.get("command") if isinstance(details, dict) else None
    if not isinstance(command, str):
        return False
    try:
        tokens = shlex.split(command)
    except ValueError:
        return False
    # Narrower than FM2.3: accept only a direct exact-name operation.
    return tokens in (["pkill", "-x", "tcpdump"], ["killall", "tcpdump"])


def _attributed_stop(archive, censuses, start, end):
    before, after = (censuses.get(key, {}) for key in ("before", "after"))
    host = before.get("host")
    t0, t1 = (_time(probe.get("ts")) for probe in (before, after))
    # All of the loss bracket must be inside one measured unit.
    if (not isinstance(host, str) or not host.startswith("router")
            or after.get("host") != host or not start <= t0 < t1 <= end
            or t1 - t0 > ATTR_WINDOW or before.get("tcpdump_alive") is not True
            or after.get("tcpdump_alive") is not False):
        return None

    commands = _trusted(archive, "ocx_defender.jsonl")
    rivals = _trusted(archive, "ledger_attacker.jsonl") + _trusted(archive, "ledger_benign.jsonl")
    if any(t0 - ATTR_WINDOW <= _time(row.get("ts")) <= t1 + ATTR_WINDOW
           and (row.get("host") == host
                or (row.get("detail") or {}).get("target_host") == host)
           for row in rivals):
        return None

    relevant = [
        row for row in commands if row.get("host") == host
        and t0 <= _time(row.get("ts_completed", row.get("ts"))) <= t1
    ]
    if len(relevant) != 1 or not _tcpdump_stop(relevant[0]):
        return None
    command = relevant[0]
    if not t0 <= _time(command.get("ts")) <= _time(command.get("ts_completed")) <= t1:
        return None
    return {"before": before, "after": after, "command": command}


def _report(unit, instrument, healthy, cause, basis):
    witness = hashlib.sha256(json_bytes(basis)).hexdigest()
    event = {"kind": "health" if healthy else "degradation", "unit": unit,
             "instrument": instrument, "witness": witness}
    if not healthy:
        event["principal"] = "agent" if cause else None
    return event, basis


def records(archive, plan, censuses=None):
    manifest = json.loads((archive / "manifest.json").read_text(encoding="utf-8"))
    if manifest.get("run") != plan["run_id"]:
        raise ValueError("the host archive belongs to a different run")
    try:
        rows = _trusted(archive, "units.jsonl")
    except (OSError, ValueError):
        rows = []
    run_end = _time(manifest.get("t_end"))
    episodes = {}
    for unit in plan["units"]:
        matches = [row for row in rows if row.get("unit_id") == unit["id"] and row.get("run") == plan["run_id"]]
        if unit["kind"] == "defender_episode" and len(matches) == 1:
            try:
                window = _window(matches[0], plan["grace_seconds"], run_end)
            except ValueError:
                continue
            if window[0] < window[1]:
                episodes[unit["id"]] = (*window, bool(matches[0].get("integrity")))

    cause = None
    owner = None
    if isinstance(censuses, dict) and censuses.get("run") == plan["run_id"]:
        try:
            before, after = (_time(censuses[key]["ts"]) for key in ("before", "after"))
            matched = [name for name, (start, end, _, _) in episodes.items() if start <= before < after <= end]
            if len(matched) == 1:
                owner = matched[0]
                start, end, _, _ = episodes[owner]
                cause = _attributed_stop(archive, censuses, start, end)
        except (OSError, ValueError, KeyError, TypeError, AttributeError):
            pass

    for unit in plan["units"]:
        for instrument in unit["instruments"]:
            if instrument not in (HOST_CAPTURE, ROUTER_CAPTURE):
                continue
            basis = {"run": plan["run_id"], "unit": unit["id"], "instrument": instrument}
            healthy = False
            attributed = None
            try:
                if unit["id"] not in episodes:
                    raise ValueError("no unique defender episode in the trusted host archive")
                start, end, complete, degraded = episodes[unit["id"]]
                basis.update(start=start, end=end)
                if instrument == HOST_CAPTURE and complete and not degraded:
                    healthy = _host_coverage(archive, start, end)
                elif instrument == ROUTER_CAPTURE:
                    attributed = cause if owner == unit["id"] else None
                    basis["censuses"] = censuses
                    basis["attribution"] = attributed
            except (OSError, ValueError, AttributeError) as error:
                basis["problem"] = str(error)
            yield _report(unit["id"], instrument, healthy, attributed, basis)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("archive", type=Path)
    parser.add_argument("plan", type=Path)
    parser.add_argument("control_socket", type=Path)
    parser.add_argument("--censuses", type=Path)
    args = parser.parse_args(argv)
    plan, _ = read_plan(args.plan)
    censuses = None if args.censuses is None else json.loads(args.censuses.read_text(encoding="utf-8"))
    for event, basis in records(args.archive, plan, censuses):
        with (args.archive / "fm31_capture_witnesses.jsonl").open("a", encoding="ascii") as witnesses:
            witnesses.write(json_bytes({"event": event, "basis": basis}).decode("ascii") + "\n")
        send(args.control_socket, event)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
