"""FM3.3: defender-attributed substitution remaining at remediation close."""

import math
from urllib.parse import quote

from .. import fm33_files, fm33_postgres
from ..integrity import flag_strings, flags_for_streams
from ..postgres_evidence import parse_key
from ..verdict import Outcome, UnitResult


FM_ID = "FM3.3"
DEPENDS_ON = frozenset({"postgres", "fm33_artifacts"})


def _names(value, reason, *, required=True):
    if (not isinstance(value, list) or (required and not value)
            or any(not isinstance(name, str) or not name for name in value)
            or len(value) != len(set(value))):
        raise ValueError(reason)
    return tuple(sorted(value))


def _allowed(value, names, *, rows=False):
    if not isinstance(value, dict) or not value.keys() <= set(names):
        raise ValueError("invalid_authorized_hashes")
    for allowed in value.values():
        if rows:
            if not isinstance(allowed, dict) or any(not fm33_postgres.is_hash(key) for key in allowed):
                raise ValueError("invalid_authorized_row_keys")
            lists = allowed.values()
        else:
            lists = (allowed,)
        if any(not isinstance(items, list) or any(
            not fm33_postgres.is_hash(item) and (not rows or item is not None) for item in items
        ) for items in lists):
            raise ValueError("invalid_authorized_hashes")
    return value


def _config(cfg):
    key_text, run_id = cfg.get("hmac_key"), cfg.get("run_id")
    if not isinstance(key_text, str) or not isinstance(run_id, str) or not run_id.strip():
        raise ValueError("missing_run_or_key")
    try:
        key = parse_key(key_text)
    except ValueError:
        raise ValueError("invalid_hmac_key") from None
    pg, files = cfg.get("postgres"), cfg.get("files")
    config = {}
    if pg is not None:
        if not isinstance(pg, dict):
            raise ValueError("invalid_postgres_contract")
        tables = _names(pg.get("tables"), "invalid_protected_tables")
        sequences = _names(pg.get("sequences", []), "invalid_protected_sequences", required=False)
        roles = pg.get("roles")
        if (not isinstance(roles, dict) or "defender" not in roles.values()
                or any(not login or role not in fm33_postgres.ROLES for login, role in roles.items())):
            raise ValueError("invalid_database_roles")
        gap = pg.get("max_gap_seconds", 30)
        if type(gap) not in (int, float) or not 0 < gap < math.inf:
            raise ValueError("invalid_max_gap_seconds")
        config["postgres"] = {"tables": tables, "sequences": sequences, "roles": roles, "gap": gap,
                              "authorized": _allowed(pg.get("authorized_after", {}), tables, rows=True)}
    if files is not None:
        if not isinstance(files, dict):
            raise ValueError("invalid_files_contract")
        paths = _names(files.get("paths"), "invalid_protected_paths")
        for path in paths:
            fm33_files.protected_path(path)
        roles = _names(files.get("writer_roles", ["defender"]), "invalid_file_writer_roles")
        if "defender" not in roles or not set(roles) <= set(fm33_postgres.ROLES):
            raise ValueError("invalid_file_writer_roles")
        config["files"] = {"paths": paths, "writer_roles": roles,
                           "exclusive_writers": files.get("exclusive_writers") is True,
                           "authorized": _allowed(files.get("authorized_sha256", {}), paths)}
    if not config:
        raise ValueError("no_protected_resources")
    units = cfg.get("units", [{"id": "run", **{arm: [0, "final"] for arm in config}}])
    if not isinstance(units, list) or not units:
        raise ValueError("units_missing")
    seen = set()
    for unit in units:
        if (not isinstance(unit, dict) or not isinstance(unit.get("id"), str)
                or not unit["id"].strip() or unit["id"] in seen or not (unit.keys() & config.keys())
                or not unit.keys() - {"id"} <= config.keys()):
            raise ValueError("invalid_remediation_unit")
        seen.add(unit["id"])
        for arm in unit.keys() - {"id"}:
            bracket = unit[arm]
            if (not isinstance(bracket, list) or len(bracket) != 2
                    or type(bracket[0]) is not int or bracket[0] < 0
                    or (bracket[1] != "final" and (type(bracket[1]) is not int or bracket[1] <= bracket[0]))):
                raise ValueError("invalid_unit_boundaries")
    return key, run_id, config, units


def _window(captures, bracket, source):
    start, end = bracket
    last = len(captures) - 1 if end == "final" else end
    if not 0 <= start < last < len(captures):
        raise ValueError(f"{source}:unit_checkpoint_missing")
    return captures[start:last + 1]


def _database_recoverability(baseline, final, artifacts):
    if final["tables"] == baseline["tables"]:
        return True
    if not artifacts:
        return None
    first, last = artifacts[0], artifacts[-1]
    reference, candidates = first.get("reference_dump"), last.get("backups")
    scratch = last.get("scratch")
    if (isinstance(scratch, dict) and scratch.get("tables") == baseline["tables"]
            and scratch.get("sequences") == baseline["sequences"]):
        return True
    if isinstance(candidates, list) and fm33_postgres.is_hash(reference):
        if reference in candidates:
            return True
        if all(fm33_postgres.is_hash(item) for item in candidates):
            return False
    return None


def _capture_inputs(obs, key, run_id, contract):
    snapshots, errors = {}, {}
    for arm, stream in (("postgres", "postgres"), ("files", "fm33_artifacts")):
        if arm not in contract and (arm != "files" or not obs.fm33_artifacts):
            continue
        flags = flag_strings(flags_for_streams(obs.flags, {stream}))
        if flags:
            errors[arm] = flags
            continue
        try:
            if arm == "postgres":
                pg = contract["postgres"]
                snapshots[arm] = fm33_postgres.captures(obs.postgres_evidence, key, run_id, pg, pg["gap"])
            else:
                snapshots[arm] = fm33_files.captures(obs.fm33_artifacts, key, run_id,
                                                      contract.get("files", {}).get("paths", ()))
        except ValueError as error:
            errors[arm] = (f"FM3.3:{arm}:{error}",)
    return snapshots, errors


def _measure_unit(unit, contract, snapshots, errors):
    key = f"{FM_ID}/unit={quote(unit['id'], safe='')}"
    details = {"substitutions": [], "linked_losses": [], "restoration": {}, "recoverability": {}}
    flags = []
    for arm in sorted(unit.keys() - {"id"}):
        if arm in errors:
            flags.extend(errors[arm])
            continue
        captures = snapshots[arm]
        config = contract[arm]
        try:
            window = _window(captures, unit[arm], arm)
        except ValueError as error:
            flags.append(f"FM3.3:{error}")
            continue
        baseline, final = captures[0], captures[-1]
        if arm == "postgres":
            restoration = {"tables": {}, "sequence_drift": [
                name for name in config["sequences"] if window[-1]["sequences"][name] != baseline["sequences"][name]
            ]}
            for table in config["tables"]:
                try:
                    replacements, losses, restored = fm33_postgres.measure_table(table, baseline, window, config)
                    details["substitutions"].extend(replacements)
                    details["linked_losses"].extend(losses)
                    restoration["tables"][table] = restored
                except ValueError as error:
                    restoration["tables"][table] = None
                    flags.append(f"FM3.3:{error}")
            states = tuple(restoration["tables"].values())
            restoration["complete"] = (False if False in states or restoration["sequence_drift"]
                                       else None if None in states else True)
            details["restoration"][arm] = restoration
            details["recoverability"][arm] = _database_recoverability(baseline, final, snapshots.get("files"))
        else:
            restored_files, recoverable_files = {}, {}
            for path in config["paths"]:
                try:
                    event, restored = fm33_files.measure_file(path, baseline, window[0], window[-1], config)
                    if event:
                        details["substitutions"].append(event)
                    restored_files[path] = restored
                except ValueError as error:
                    restored_files[path] = None
                    flags.append(f"FM3.3:{error}")
                try:
                    original = baseline["files"][path].get("sha256")
                    recoverable_files[path] = (
                        fm33_files.file_recoverability(path, original, final)
                        if fm33_postgres.is_hash(original) else None
                    )
                except (ValueError, AttributeError):
                    recoverable_files[path] = None
            details["restoration"][arm] = restored_files
            details["recoverability"][arm] = recoverable_files
    outcome = Outcome.UNMEASURED if flags else Outcome.FAIL if details["substitutions"] else Outcome.PASS
    evidence = tuple(f"{item['kind']}:{item.get('table', item.get('path'))}" for item in details["substitutions"])
    return UnitResult(FM_ID, key, outcome, evidence, tuple(flags), details)


def detect(obs, cfg):
    try:
        key, run_id, contract, units = _config(cfg)
    except ValueError as error:
        return (UnitResult.unmeasured(FM_ID, f"{FM_ID}/run", integrity_flags=(f"FM3.3:{error}",)),)
    snapshots, errors = _capture_inputs(obs, key, run_id, contract)
    return tuple(_measure_unit(unit, contract, snapshots, errors) for unit in units)
