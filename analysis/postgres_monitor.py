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


def capture(previous, timeout, fm33=False):
    function = "nsg_fm33.capture" if fm33 else "nsg_fm22.capture"
    # Catalog changes can be newer than a repeatable-read data snapshot.
    # Lock the protected relations before taking that snapshot.
    sql = rf"""
SELECT coalesce(
    'LOCK TABLE ' || string_agg(format('ONLY %I.%I', n.nspname, c.relname), ', ' ORDER BY c.oid)
        || ' IN ACCESS SHARE MODE',
    'SET LOCAL lock_timeout = DEFAULT'
) AS protected_locks
FROM nsg_fm22.protected_tables AS p
JOIN pg_catalog.pg_class AS c ON c.oid = p.relation
JOIN pg_catalog.pg_namespace AS n ON n.oid = c.relnamespace
\gset
BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY;
SET LOCAL statement_timeout = :'timeout';
:protected_locks;
SELECT CASE WHEN EXISTS (
    SELECT FROM nsg_fm22.protected_tables AS p JOIN pg_catalog.pg_class AS c ON c.oid = p.relation
    WHERE NOT EXISTS (
        SELECT FROM pg_catalog.pg_locks AS l
        WHERE l.pid = pg_backend_pid() AND l.relation = p.relation AND l.granted
            AND l.locktype = 'relation' AND l.mode = 'AccessShareLock'
    )
) THEN jsonb_build_object('protected_inventory_changed', true)
ELSE {function}(NULLIF(:'previous', '')::pg_snapshot) END;
COMMIT;
"""
    deadline = time.monotonic() + timeout
    for attempt in range(3):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise subprocess.TimeoutExpired("psql", timeout)
        result = subprocess.run(
            ["psql", "-XqAtw", "-v", "ON_ERROR_STOP=1", "-v", "VERBOSITY=verbose",
             "-v", f"previous={previous}", "-v", f"timeout={math.ceil(remaining * 1000)}ms"],
            input=sql, text=True, encoding="utf-8", capture_output=True, timeout=remaining,
            env={**os.environ, "PGCLIENTENCODING": "UTF8"},
        )
        if result.returncode and " 42P01:" in result.stderr and attempt < 2:
            # A target can be renamed or dropped between discovery and LOCK.
            continue
        result.check_returncode()
        data = json.loads(result.stdout)
        if isinstance(data, dict) and data.get("protected_inventory_changed") is True:
            continue
        if not isinstance(data, dict) or not isinstance(data.get("snapshot"), str):
            raise ValueError("invalid capture response")
        return data
    raise ValueError("protected relation inventory changed during capture")


def collect(archive, args, key, stopped, checkpoint=None):
    previous, previous_mac, sequence = "", GENESIS, 0

    def sample(kind):
        nonlocal previous, previous_mac, sequence
        record = {"schema": SCHEMA, "run_id": args.run_id, "seq": sequence,
                  "kind": kind, "timestamp": time.time_ns(), "previous_mac": previous_mac}
        try:
            data = capture(previous, args.timeout, args.fm33)
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
    wake = checkpoint if checkpoint is not None else stopped
    while not stopped.is_set():
        wake.wait(max(0, started + args.interval - time.monotonic()))
        if stopped.is_set():
            break
        if checkpoint is not None:
            checkpoint.clear()
        started = time.monotonic()
        sample("sample")
        if args.fm33:
            print(f"postgres-monitor: FM3.3 checkpoint {sequence - 1}", flush=True)
    return 0 if sample("final") else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True, help="observation directory")
    parser.add_argument("--key-file", type=Path, required=True, help="host-side hex HMAC key")
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--interval", type=float, default=10)
    parser.add_argument("--timeout", type=float, default=5)
    parser.add_argument("--fm33", action="store_true", help="include enrolled FM3.3 rows and sequences")
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
        checkpoint = threading.Event() if args.fm33 else None

        def stop(*_):
            stopped.set()
            if checkpoint is not None:
                checkpoint.set()

        for signum in (signal.SIGINT, signal.SIGTERM):
            signal.signal(signum, stop)
        if checkpoint is not None:
            signal.signal(signal.SIGUSR1, lambda *_: checkpoint.set())
        with path.open("x", encoding="ascii") as archive:
            return collect(archive, args, key, stopped, checkpoint)
    except (OSError, ValueError) as error:
        print(f"postgres-monitor: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
