"""Wire formats and authentication for the host-side evidence streams."""

import hashlib
import hmac
import json
import re


STREAM_PATH = "postgres/evidence.jsonl"
SCHEMA = "nsg-postgres/1"
ARTIFACTS_PATH = "fm33/artifacts.jsonl"
ARTIFACTS_SCHEMA = "nsg-fm33-artifacts/1"
GENESIS = "0" * 64
HEX_MAC = re.compile(r"[0-9a-f]{64}")


def canonical_json(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)


def evidence_mac(key, payload):
    return hmac.new(key, canonical_json(payload).encode("ascii"), hashlib.sha256).hexdigest()


def parse_key(text):
    key = bytes.fromhex(text)
    if len(key) < 32:
        raise ValueError("the evidence key must contain at least 32 bytes in hex")
    return key


def verified_records(records, key, run_id, schema, max_gap=None, *, closed=True):
    """Authenticate a complete baseline/sample/final chain, retaining line references."""
    if len(records) < (2 if closed else 1):
        raise ValueError("incomplete_capture")
    previous_mac, previous_time = GENESIS, None
    for index, (line, record) in enumerate(records):
        signed = {name: value for name, value in record.items() if name != "mac"}
        mac = record.get("mac")
        if not isinstance(mac, str) or not HEX_MAC.fullmatch(mac):
            raise ValueError(f"invalid_mac:line={line}")
        try:
            expected = evidence_mac(key, signed)
        except (ValueError, TypeError, RecursionError):
            raise ValueError(f"invalid_record:line={line}") from None
        if not hmac.compare_digest(mac, expected) or record.get("previous_mac") != previous_mac:
            raise ValueError(f"signature_or_chain_mismatch:line={line}")
        kind = ("baseline" if index == 0
                else "final" if closed and index == len(records) - 1 else "sample")
        ts = record.get("timestamp")
        if (record.get("schema") != schema or record.get("run_id") != run_id
                or type(record.get("seq")) is not int or record["seq"] != index
                or record.get("kind") != kind or type(ts) is not int or not 0 < ts < 2**63):
            raise ValueError(f"invalid_run_bracket_or_sequence:line={line}")
        if previous_time is not None:
            gap = (ts - previous_time) / 1_000_000_000
            if gap <= 0 or (max_gap is not None and gap > max_gap):
                raise ValueError(f"capture_cadence_gap:line={line}")
        yield line, record
        previous_time, previous_mac = ts, mac
