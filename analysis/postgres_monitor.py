"""Capture and sign PostgreSQL FM2.2 evidence from the trusted Docker host."""

import argparse
import json
import math
import os
from pathlib import Path
import signal
import subprocess
import sys
import threading
import time

from .postgres_evidence import (
    GENESIS, SCHEMA, STREAM_PATH, canonical_json, evidence_mac, parse_key,
)


def capture(previous, timeout):
    sql = """
BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY;
SET LOCAL statement_timeout = :'timeout';
SELECT nsg_fm22.capture(NULLIF(:'previous', '')::pg_snapshot);
COMMIT;
"""
    result = subprocess.run(
        ["psql", "-XqAtw", "-v", "ON_ERROR_STOP=1", "-v", f"previous={previous}",
         "-v", f"timeout={math.ceil(timeout * 1000)}ms"],
        input=sql, text=True, encoding="utf-8", capture_output=True, timeout=timeout,
        env={**os.environ, "PGCLIENTENCODING": "UTF8"},
    )
    result.check_returncode()
    data = json.loads(result.stdout)
    if not isinstance(data, dict) or not isinstance(data.get("snapshot"), str):
        raise ValueError("invalid capture response")
    return data


def collect(archive, args, key, stopped):
    previous, previous_mac, sequence = "", GENESIS, 0

    def sample(kind):
        nonlocal previous, previous_mac, sequence
        record = {"schema": SCHEMA, "run_id": args.run_id, "seq": sequence,
                  "kind": kind, "timestamp": time.time_ns(), "previous_mac": previous_mac}
        try:
            data = capture(previous, args.timeout)
            previous = data["snapshot"]
            record["capture"] = data
        except (OSError, subprocess.SubprocessError, ValueError) as error:
            record["error"] = type(error).__name__
            print(f"postgres-monitor: {kind} capture failed: {record['error']}", file=sys.stderr)
            if isinstance(error, subprocess.CalledProcessError) and error.stderr:
                print(error.stderr.rstrip(), file=sys.stderr)
        previous_mac = evidence_mac(key, record)
        archive.write(canonical_json({**record, "mac": previous_mac}) + "\n")
        archive.flush()
        os.fsync(archive.fileno())
        sequence += 1
        return "capture" in record

    started = time.monotonic()
    if not sample("baseline"):
        return 1
    print("postgres-monitor: baseline ready", flush=True)
    while not stopped.wait(max(0, started + args.interval - time.monotonic())):
        started = time.monotonic()
        sample("sample")
    return 0 if sample("final") else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True, help="observation directory")
    parser.add_argument("--key-file", type=Path, required=True, help="host-side hex HMAC key")
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--interval", type=float, default=10)
    parser.add_argument("--timeout", type=float, default=5)
    args = parser.parse_args()
    if not args.run_id.strip() or not all(
        math.isfinite(value) and value > 0 for value in (args.interval, args.timeout)
    ):
        parser.error("run-id must be non-empty and interval and timeout must be positive and finite")
    try:
        key = parse_key(args.key_file.read_text(encoding="ascii"))
        path = args.output / STREAM_PATH
        path.parent.mkdir(parents=True, exist_ok=True)
        stopped = threading.Event()
        for signum in (signal.SIGINT, signal.SIGTERM):
            signal.signal(signum, lambda *_: stopped.set())
        with path.open("x", encoding="ascii") as archive:
            return collect(archive, args, key, stopped)
    except (OSError, ValueError) as error:
        print(f"postgres-monitor: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
