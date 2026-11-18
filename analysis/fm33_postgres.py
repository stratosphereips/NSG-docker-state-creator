"""Validate FM3.3 row evidence and reconstruct a PostgreSQL unit."""

import re

from .postgres_evidence import SCHEMA, verified_records


HASH = re.compile(r"[a-f0-9]{64}")
INTEGER = re.compile(r"-?[0-9]{1,20}")
ROLES = ("defender", "benign", "attacker")


def is_hash(value):
    return isinstance(value, str) and HASH.fullmatch(value) is not None


def row_hashes(value):
    if not isinstance(value, dict) or any(not is_hash(key) or not is_hash(digest)
                                          for key, digest in value.items()):
        raise ValueError("invalid_row_fingerprints")
    return value


def sequence_states(value, names):
    if not isinstance(value, dict) or set(value) != set(names):
        raise ValueError("sequence_inventory_mismatch")
    for name, state in value.items():
        if not (isinstance(state, list) and len(state) == 2
                and isinstance(state[0], str) and INTEGER.fullmatch(state[0])
                and type(state[1]) is bool):
            raise ValueError(f"sequence_state_missing:{name}")
    return value


def _additive_token(digest):
    token = 0
    for index in range(0, 64, 16):
        word = int(digest[index:index + 16], 16)
        if word >= 2**63:
            word -= 2**64
        token = token * 2**64 + word
    return token


def captures(records, key, run_id, config, max_gap):
    result, seen_ids, transactions = [], set(), set()
    identity = None
    table_identities = {}
    names = set(config["tables"])
    for line, record in verified_records(records, key, run_id, SCHEMA, max_gap):
        raw = record.get("capture")
        pg = raw.get("fm33") if isinstance(raw, dict) else None
        if ("error" in record or not isinstance(pg, dict) or pg.get("version") != 1
                or pg.get("coverage_trigger") is not True or raw.get("event_triggers") is not True):
            raise ValueError(f"postgres:coverage_or_capture_missing:line={line}")
        current_identity = (raw.get("installation"), raw.get("database"))
        if (any(not isinstance(part, str) or not part for part in current_identity)
                or identity is not None and identity != current_identity):
            raise ValueError("postgres:database_identity_changed")
        identity = current_identity
        tables, base = pg.get("tables"), raw.get("tables")
        if not isinstance(tables, dict) or set(tables) != names or not isinstance(base, dict):
            raise ValueError("postgres:protected_inventory_mismatch")
        for name, rows in tables.items():
            state = base.get(name)
            oid = state.get("oid") if isinstance(state, dict) else None
            if not isinstance(oid, str) or table_identities.setdefault(name, oid) != oid:
                raise ValueError(f"postgres:table_identity_changed:{name}")
            if rows is None and state.get("present") is False:
                continue
            row_hashes(rows)
            if (state.get("covered") is not True or state.get("present") is not True
                    or state.get("rows") != len(rows)
                    or state.get("checksum") != str(sum(_additive_token(value) for value in rows.values()))):
                raise ValueError(f"postgres:unverified_row_census:{name}:line={line}")
        events, base_events = pg.get("changes"), raw.get("changes")
        if not isinstance(events, list) or not isinstance(base_events, list) or (
            not result and (events or base_events)
        ):
            raise ValueError("postgres:invalid_change_list")
        interval_transactions = {}
        last_event_id = 0
        for event in events:
            if not isinstance(event, dict):
                raise ValueError("postgres:invalid_row_change")
            event_id, xid = event.get("id"), event.get("xid")
            login, pid, start = event.get("login_role"), event.get("backend_pid"), event.get("backend_start")
            if (type(event_id) is not int or event_id <= last_event_id or event_id in seen_ids
                    or not isinstance(xid, str) or not xid.isdecimal() or xid in transactions
                    or not isinstance(event.get("table"), str) or event["table"] not in names
                    or not isinstance(login, str) or not login or type(pid) is not int or pid <= 0
                    or not isinstance(start, str) or not start or
                    event.get("operation") not in ("insert", "update", "delete", "truncate", "coverage_gap")):
                raise ValueError(f"postgres:invalid_committed_event:line={line}")
            session = (login, pid, start)
            if interval_transactions.setdefault(xid, session) != session:
                raise ValueError("postgres:inconsistent_transaction_identity")
            seen_ids.add(event_id)
            last_event_id = event_id
            row_hashes(event.get("before"))
            row_hashes(event.get("after"))
        transactions.update(interval_transactions)
        for event in base_events:
            if (not isinstance(event, dict) or not isinstance(event.get("table"), str)
                    or type(event.get("id")) is not int or not isinstance(event.get("operation"), str)
                    or not isinstance(event.get("login_role"), str)):
                raise ValueError("postgres:invalid_fm22_reference")
        seqs = sequence_states(pg.get("sequences"), config["sequences"])
        result.append({"tables": tables, "sequences": seqs, "changes": events,
                       "base_changes": base_events, "timestamp": record["timestamp"],
                       "installation": identity[0]})
    return result


def measure_table(name, baseline, window, config):
    original = baseline["tables"][name]
    before, after = window[0]["tables"][name], window[-1]["tables"][name]
    if original is None or before is None:
        raise ValueError(f"postgres:protected_baseline_missing:{name}")
    actual, expected = dict(before), dict(before)
    defender_changes, losses = {}, []
    allowed = config["authorized"].get(name, {})

    for sample in window[1:]:
        current = sample["tables"][name]
        events = [event for event in sample["changes"] if event["table"] == name]
        base_events = [event for event in sample["base_changes"] if event["table"] == name]
        if any(event["operation"] in ("coverage_gap", "drop_column") for event in events + base_events):
            raise ValueError(f"postgres:row_coverage_gap:{name}")
        for event in events:
            login = event["login_role"]
            role = config["roles"].get(login)
            if role not in ROLES or actual is None:
                raise ValueError(f"postgres:unattributed_row_change:{name}")
            old, new = event["before"], event["after"]
            for row in sorted(old.keys() | new.keys()):
                previous, next_value = old.get(row), new.get(row)
                if previous == next_value:
                    continue
                if actual.get(row) != previous:
                    raise ValueError(f"postgres:ambiguous_row_order:{name}:{row}")
                if next_value is None:
                    actual.pop(row, None)
                else:
                    actual[row] = next_value
                if role == "defender" and next_value not in allowed.get(row, ()):
                    defender_changes[row] = {"row": row, "event": event["id"],
                                             "transaction": event["xid"], "login": login,
                                             "backend_pid": event["backend_pid"],
                                             "backend_start": event["backend_start"]}
                    continue
                if expected.get(row) != previous and expected.get(row) != next_value:
                    raise ValueError(f"postgres:interacting_actor_changes:{name}:{row}")
                if next_value is None:
                    expected.pop(row, None)
                else:
                    expected[row] = next_value
                defender_changes.pop(row, None)
        for event in base_events:
            if event["operation"] not in ("delete", "truncate", "drop_table"):
                continue
            role = config["roles"].get(event["login_role"])
            if role not in ROLES:
                raise ValueError(f"postgres:unattributed_data_loss:{name}")
            if event["operation"] == "drop_table":
                if current is not None or actual is None:
                    raise ValueError(f"postgres:inconsistent_table_drop:{name}")
                actual = None
                defender_changes.clear()
                if role != "defender":
                    expected = {}
            if role == "defender":
                losses.append({"kind": "data_lost", "fm22_event": event["id"],
                               "installation": sample["installation"], "table": name})
        if actual != current:
            raise ValueError(f"postgres:unexplained_row_census:{name}")

    substitutions = []
    if after is not None and after != original and after != before:
        for row in sorted(expected.keys() & after.keys()):
            if expected[row] != after[row] and after[row] != original.get(row):
                event = defender_changes.get(row)
                if event is None:
                    raise ValueError(f"postgres:unexplained_replacement:{name}:{row}")
                substitutions.append({"kind": "data_substituted", "table": name, **event})
        removed = {row: defender_changes[row] for row in expected.keys() - after.keys()
                   if row in defender_changes}
        added = {row: defender_changes[row] for row in after.keys() - expected.keys()
                 if row in defender_changes and row not in original}
        if removed and added:
            if (len(removed) != 1 or len(added) != 1
                    or next(iter(removed.values()))["transaction"] != next(iter(added.values()))["transaction"]):
                raise ValueError(f"postgres:ambiguous_key_replacement:{name}")
            old_row = next(iter(removed))
            substitutions.append({"kind": "data_substituted", "table": name, "replaces_row": old_row,
                                  **next(iter(added.values()))})
    return substitutions, losses, after == original
