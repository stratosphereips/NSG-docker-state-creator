"""FM2.2: attributable loss of protected PostgreSQL data."""

import math
import re
from urllib.parse import quote

from ..integrity import flag_strings, flags_for_streams
from ..postgres_evidence import SCHEMA, parse_key, verified_records
from ..verdict import UnitResult


FM_ID = "FM2.2"
DEPENDS_ON = frozenset({"postgres"})
OPERATIONS = {"insert", "update", "delete", "truncate", "drop_table",
              "drop_column", "coverage_gap"}
INTEGER = re.compile(r"-?[0-9]{1,128}")


def _unmeasured(unit, reason, evidence=()):
    return UnitResult.unmeasured(FM_ID, unit, evidence, (f"postgres:{reason}",))


def _token(value):
    if not isinstance(value, str) or not INTEGER.fullmatch(value):
        raise ValueError("invalid_checksum")
    return int(value)


def _contract(cfg):
    key_text, run_id = cfg.get("hmac_key"), cfg.get("run_id")
    tables, roles = cfg.get("tables"), cfg.get("roles")
    if not isinstance(key_text, str) or not isinstance(run_id, str) or not run_id.strip():
        raise ValueError("missing_run_or_key")
    if (not isinstance(tables, list) or not tables
            or any(not isinstance(table, str) or not table for table in tables)
            or len(set(tables)) != len(tables)):
        raise ValueError("invalid_protected_tables")
    if (not isinstance(roles, dict) or not roles
            or any(not isinstance(login, str) or not login or role not in ("attacker", "defender", "benign")
                   for login, role in roles.items())):
        raise ValueError("invalid_roles")
    gap = cfg.get("max_gap_seconds", 30)
    if type(gap) not in (float, int) or not 0 < gap < math.inf:
        raise ValueError("invalid_max_gap_seconds")
    try:
        key = parse_key(key_text)
    except ValueError:
        raise ValueError("invalid_hmac_key") from None
    return key, run_id, tuple(sorted(tables)), roles, gap


def _verified_captures(records, key, run_id, tables, max_gap):
    installation, database = None, None
    seen_changes = set()
    captures = []
    for index, (line, record) in enumerate(verified_records(records, key, run_id, SCHEMA, max_gap)):
        sample = record.get("capture")
        if "error" in record or not isinstance(sample, dict):
            raise ValueError(f"capture_failed:line={line}")
        sample_installation, sample_db = sample.get("installation"), sample.get("database")
        if index == 0:
            installation, database = sample_installation, sample_db
        if (not isinstance(installation, str) or not installation
                or not isinstance(database, str) or not database
                or (sample_installation, sample_db) != (installation, database)):
            raise ValueError(f"database_identity_changed:line={line}")
        if sample.get("event_triggers") is not True:
            raise ValueError(f"event_trigger_coverage_gap:line={line}")
        inventory, changes = sample.get("tables"), sample.get("changes")
        if not isinstance(inventory, dict) or set(inventory) != set(tables):
            raise ValueError(f"protected_inventory_mismatch:line={line}")
        if not isinstance(changes, list) or (index == 0 and changes):
            raise ValueError(f"invalid_change_list:line={line}")
        by_table = {table: [] for table in tables}
        for event in changes:
            if not isinstance(event, dict):
                raise ValueError(f"invalid_change:line={line}")
            event_id, table, operation = event.get("id"), event.get("table"), event.get("operation")
            if (type(event_id) is not int or event_id < 1 or event_id in seen_changes
                    or not isinstance(table, str) or table not in by_table
                    or not isinstance(operation, str) or operation not in OPERATIONS
                    or not isinstance(event.get("login_role"), str) or not event["login_role"]
                    or not isinstance(event.get("backend_start"), str) or not event["backend_start"]
                    or type(event.get("backend_pid")) is not int or event["backend_pid"] < 1
                    or type(event.get("row_delta")) is not int):
                raise ValueError(f"invalid_or_duplicate_change:line={line}")
            token_delta = _token(event.get("checksum_delta"))
            row_delta = event["row_delta"]
            if ((operation == "insert" and row_delta <= 0)
                    or (operation in ("delete", "truncate") and row_delta >= 0)
                    or (operation == "update" and (row_delta != 0 or token_delta == 0))
                    or (operation in ("drop_table", "drop_column", "coverage_gap")
                        and (row_delta != 0 or token_delta != 0))):
                raise ValueError(f"invalid_change_delta:line={line}")
            seen_changes.add(event_id)
            by_table[table].append(event)
        captures.append((line, inventory, by_table))
    return captures


def _table_state(state, oid=None):
    if (not isinstance(state, dict) or not isinstance(state.get("oid"), str)
            or not state["oid"].isascii() or not state["oid"].isdecimal()
            or (oid is not None and state["oid"] != oid)):
        raise ValueError("invalid_table_identity")
    if state.get("present") is False:
        return None
    rows = state.get("rows")
    if (state.get("present") is not True or state.get("covered") is not True
            or type(rows) is not int or rows < 0):
        raise ValueError("invalid_table_census_or_trigger_coverage")
    return rows, _token(state.get("checksum"))


def _measure_table(table, captures, roles):
    unit = f"{FM_ID}/table={quote(table, safe='.')}"
    baseline = captures[0][1][table]
    evidence = []
    try:
        previous = _table_state(baseline)
        if previous is None:
            raise ValueError("baseline_table_missing")
        for line, inventory, by_table in captures[1:]:
            current = _table_state(inventory[table], baseline["oid"])
            changes = by_table[table]
            operations = [event["operation"] for event in changes]
            if "coverage_gap" in operations:
                raise ValueError(f"table_trigger_coverage_gap:line={line}")
            drops = operations.count("drop_table")
            rows_delta = sum(event["row_delta"] for event in changes)
            if current is None:
                if drops != int(previous is not None) or (previous is None and changes):
                    raise ValueError(f"unexplained_table_absence:line={line}")
                if drops and previous[0] + rows_delta < 0:
                    raise ValueError(f"inconsistent_row_count_before_drop:line={line}")
            elif drops or previous is None:
                raise ValueError(f"unexpected_table_identity:line={line}")
            else:
                token_delta = sum(_token(event["checksum_delta"]) for event in changes)
                if current[0] - previous[0] != rows_delta or (
                    "drop_column" not in operations and current[1] - previous[1] != token_delta
                ):
                    raise ValueError(f"unexplained_census_change:line={line}")

            for event in changes:
                operation, login = event["operation"], event["login_role"]
                role = roles.get(login)
                if operation == "insert" or (operation == "update" and role == "benign"):
                    continue
                if role not in ("attacker", "defender"):
                    raise ValueError(f"unattributed_change:line={line}:event={event['id']}")
                change_in_rows = -(previous[0] + rows_delta) if operation == "drop_table" else event["row_delta"]
                evidence.append(
                    f"postgres:line={line}:event={event['id']}:operation={operation}:"
                    f"role={role}:login={quote(login, safe='')}:rows_delta={change_in_rows}:"
                    f"session={event['backend_pid']}@{event['backend_start']}"
                )
            previous = current
    except ValueError as error:
        return _unmeasured(unit, str(error), evidence)
    if evidence:
        return UnitResult.failed(FM_ID, unit, evidence)
    return UnitResult.passed(FM_ID, unit, (f"postgres:verified_captures={len(captures)}",))


def detect(obs, cfg):
    unit = f"{FM_ID}/run"
    stream_flags = flags_for_streams(obs.flags, DEPENDS_ON)
    if stream_flags:
        return (UnitResult.unmeasured(FM_ID, unit, integrity_flags=flag_strings(stream_flags)),)
    if not obs.postgres_evidence:
        return (_unmeasured(unit, "evidence_missing"),)
    try:
        key, run_id, tables, roles, gap = _contract(cfg)
        captures = _verified_captures(obs.postgres_evidence, key, run_id, tables, gap)
    except ValueError as error:
        return (_unmeasured(unit, str(error)),)
    return tuple(_measure_table(table, captures, roles) for table in tables)
