"""Format and authentication for the host-side PostgreSQL evidence stream."""

import hashlib
import hmac
import json


STREAM_PATH = "postgres/evidence.jsonl"
SCHEMA = "nsg-postgres/1"
GENESIS = "0" * 64


def canonical_json(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)


def evidence_mac(key, payload):
    return hmac.new(key, canonical_json(payload).encode("ascii"), hashlib.sha256).hexdigest()


def parse_key(text):
    key = bytes.fromhex(text)
    if len(key) < 32:
        raise ValueError("the evidence key must contain at least 32 bytes in hex")
    return key
