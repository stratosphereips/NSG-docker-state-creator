"""Seal trusted host checkpoints for FM3.3 files and recovery artifacts."""

import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import stat
import subprocess
import sys
import tarfile
import tempfile
import time

from .detectors.afm_2 import _collect_write_edges, _unparsed_write_lines
from .detectors.fm_2_1 import _mutation_edges
from .detectors.fm_2_3 import _strace_children, _workload_tree
from .detectors.fm_4_2 import FORK_SYSCALLS
from .fm33_files import protected_path
from .fm33_postgres import ROLES, is_hash
from .integrity import flags_for_streams
from .observation import EnvelopePins, iter_jsonl, load_observation
from .postgres_evidence import (
    ARTIFACTS_PATH, ARTIFACTS_SCHEMA, GENESIS, SCHEMA, STREAM_PATH,
    canonical_json, evidence_mac, parse_key, verified_records,
)
from .records import SyscallLine


def hash_regular(path, *, dir_fd=None):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=dir_fd)
    with os.fdopen(descriptor, "rb") as stream:
        before = os.fstat(stream.fileno())
        if not stat.S_ISREG(before.st_mode):
            raise ValueError("expected a regular file")
        digest = hashlib.sha256()
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
        after = os.fstat(stream.fileno())
        if (before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (
            after.st_size, after.st_mtime_ns, after.st_ctime_ns
        ):
            raise ValueError("file changed during capture")
        return digest.hexdigest()


def host_file(root, path):
    options = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    directory = os.open(root, options)
    try:
        for part in path.parts[1:-1]:
            child = os.open(part, options, dir_fd=directory)
            os.close(directory)
            directory = child
        return hash_regular(path.name, dir_fd=directory)
    finally:
        os.close(directory)


def container_id(container):
    if not container or container.startswith("-") or ":" in container:
        raise ValueError("invalid Docker container name")
    result = subprocess.run(["docker", "inspect", "--type", "container", "--format", "{{.Id}}", container],
                            check=True, text=True, capture_output=True, timeout=10)
    identifier = result.stdout.strip()
    if len(identifier) != 64 or any(char not in "0123456789abcdef" for char in identifier):
        raise ValueError("Docker did not return a container identity")
    return identifier


def container_file(container, path):
    with tempfile.TemporaryFile() as archive:
        result = subprocess.run(["docker", "cp", f"{container}:{path}", "-"], stdout=archive,
                                stderr=subprocess.PIPE, timeout=30)
        if result.returncode != 0:
            if b"Could not find the file" in result.stderr:
                raise FileNotFoundError(str(path))
            result.check_returncode()
        archive.seek(0)
        with tarfile.open(fileobj=archive, mode="r|*") as files:
            member = files.next()
            if member is None or not member.isreg() or member.name != path.name or member.pax_headers.get("path"):
                raise ValueError("Docker did not return a regular file at the expected path")
            stream = files.extractfile(member)
            if stream is None:
                raise ValueError("Docker file contents unavailable")
            digest = hashlib.sha256()
            while chunk := stream.read(1024 * 1024):
                digest.update(chunk)
            if files.next() is not None:
                raise ValueError("unexpected extra Docker archive members")
            return digest.hexdigest()


def snapshot_file(root, container, path):
    try:
        digest = container_file(container, path) if container else host_file(root, path)
        return {"status": "present", "sha256": digest}
    except FileNotFoundError:
        return {"status": "missing"}
    except (OSError, ValueError, tarfile.TarError, subprocess.SubprocessError):
        return {"status": "unavailable"}


def writer_witness(role, trace_root, paths):
    obs = load_observation(trace_root, EnvelopePins(time_key="ts"))
    errors = {flag.code for flag in flags_for_streams(obs.flags, {"supervisor", "processes", "syscalls"})}
    starts = [event for event in obs.supervisor if event.event == "workload_started"]
    ends = [event for event in obs.supervisor if event.event == "workload_exited"]
    if (len(starts) != 1 or len(ends) != 1 or not starts[0].pid
            or starts[0].pid != ends[0].pid or starts[0].ts is None or ends[0].ts is None
            or starts[0].ts >= ends[0].ts):
        return {"role": role, "complete": False, "events": []}
    start, end = starts[0], ends[0]
    tree = set(_workload_tree(obs.processes, start.pid))
    children = _strace_children(obs.strace)
    frontier = set(tree)
    while frontier:
        descendants = {child for parent in frontier for child in children.get(parent, ()) if child > 1}
        frontier = descendants - tree
        tree.update(frontier)
    tree = frozenset(tree)
    scoped = tuple(record for record in obs.strace if record.file_pid in tree)
    edges, truncated = _mutation_edges(scoped)
    write_errors = []
    writes, truncated_writes = _collect_write_edges(scoped, tree, write_errors)
    if truncated or truncated_writes or write_errors or _unparsed_write_lines(scoped):
        errors.add("unresolved_write")
    for record in scoped:
        if not isinstance(record, SyscallLine):
            continue
        if record.name in {"io_uring_setup", "io_uring_enter"} or (
            record.name in {"mmap", "mmap2"} and "MAP_SHARED" in record.args_raw
            and any(f"<{path}>" in record.args_raw for path in paths)
        ) or (record.name in {"copy_file_range", "splice", "sendfile"}
              and any(f"<{path}>" in record.args_raw for path in paths)):
            errors.add("unsupported_write_channel")
    # Include successful file writes and transformations, with the pathname
    # decided by the kernel trace. Opening a writable descriptor alone is insufficient.
    mutations = [edge for edge in edges if edge.success and (
        "destructive" in edge.classes or edge.syscall in {"link", "linkat", "symlink", "symlinkat"}
    )]
    mutations.extend(edge for edge in writes if edge.bytes_out > 0)
    starts_by_pid = {}
    for record in obs.processes:
        if record.pid in tree and record.start_ticks:
            starts_by_pid.setdefault(record.pid, set()).add(record.start_ticks)
    births = {}
    for record in scoped:
        if (isinstance(record, SyscallLine) and record.name in FORK_SYSCALLS
                and record.result_raw and record.result_raw.isdigit() and record.ts is not None):
            births.setdefault(int(record.result_raw), []).append(record)
    events = []
    for edge in mutations:
        if edge.path not in paths:
            continue
        identities = starts_by_pid.get(edge.actor_pid, set())
        fork_records = births.get(edge.actor_pid, [])
        if (edge.ts is None or not start.ts <= edge.ts <= end.ts or len(identities) > 1
                or len(fork_records) > 1 or (not identities and not fork_records)):
            errors.add("unresolved_writer_identity")
            continue
        identity = {"start_ticks": next(iter(identities))} if identities else {}
        if fork_records:
            fork = fork_records[0]
            if fork.ts > edge.ts:
                errors.add("unresolved_writer_identity")
                continue
            identity["birth"] = f"trace.{fork.file_pid}:{fork.seq}"
        events.append({"path": edge.path, "timestamp": round(edge.ts * 1_000_000_000),
                       "pid": edge.actor_pid, "syscall": edge.syscall, "line": edge.seq, **identity})
    # Syscalls outside the recorded process tree make the claimed writer
    # coverage unsafe if they can mutate any enrolled file.
    if any(record.file_pid not in tree for record in obs.strace):
        errors.add("unresolved_trace_process")
    recon = [
        {"path": record.path, "timestamp": round(record.ts * 1_000_000_000),
         "line": record.seq, "before": record.previous_state.checksum, "after": record.state.checksum}
        for record in obs.reconciliation
        if record.path in paths and record.event == "file_changed" and record.ts is not None
        and record.previous_state is not None and record.state is not None
        and is_hash(record.previous_state.checksum) and is_hash(record.state.checksum)
    ]
    return {"role": role, "complete": not errors, "errors": sorted(errors),
            "start": round(start.ts * 1_000_000_000), "end": round(end.ts * 1_000_000_000),
            "reconciliation": recon,
            "events": sorted(events, key=lambda event: (event["timestamp"], event["pid"], event["line"]))}


def _digest_or_none(path):
    try:
        return hash_regular(path)
    except (OSError, ValueError):
        return None


def read_scratch(root, run_id, key):
    flags = []
    source = list(iter_jsonl(root / STREAM_PATH, flags=flags))
    if flags:
        raise ValueError("scratch archive is unreadable")
    last = list(verified_records(source, key, run_id, SCHEMA))[-1][1]
    snapshot = last.get("capture", {}).get("fm33", {})
    if snapshot.get("version") != 1 or snapshot.get("coverage_trigger") is not True:
        raise ValueError("scratch archive lacks verified row and sequence evidence")
    return {"tables": snapshot["tables"], "sequences": snapshot["sequences"]}


def append_checkpoint(path, key, run_id, kind, captured, timestamp):
    path.parent.mkdir(parents=True, exist_ok=True)
    mode = "x" if kind == "baseline" else "r+"
    with path.open(mode, encoding="ascii") as archive:
        fcntl.flock(archive, fcntl.LOCK_EX)
        previous, seq = GENESIS, 0
        if kind != "baseline":
            flags = []
            records = list(iter_jsonl(path, flags=flags))
            if flags:
                raise ValueError("artifact archive is unreadable")
            verified = list(verified_records(records, key, run_id, ARTIFACTS_SCHEMA, closed=False))
            previous, seq = verified[-1][1]["mac"], len(verified)
            if timestamp <= verified[-1][1]["timestamp"]:
                raise ValueError("artifact checkpoint is out of order")
            archive.seek(0, os.SEEK_END)
        signed = {"schema": ARTIFACTS_SCHEMA, "run_id": run_id, "seq": seq, "kind": kind,
                  "timestamp": timestamp, "previous_mac": previous, "capture": captured}
        archive.write(canonical_json({**signed, "mac": evidence_mac(key, signed)}) + "\n")
        archive.flush()
        os.fsync(archive.fileno())
    return seq


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--key-file", type=Path, required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--kind", choices=("baseline", "sample", "final"), required=True)
    parser.add_argument("--path", action="append", default=[])
    source = parser.add_mutually_exclusive_group()
    source.add_argument("--root", type=Path)
    source.add_argument("--container")
    parser.add_argument("--trace", action="append", default=[], metavar="ROLE=TRUSTED_OBSERVATION")
    parser.add_argument("--reference-dump", type=Path)
    parser.add_argument("--backup", action="append", type=Path, default=[])
    parser.add_argument("--file-backup", action="append", default=[], metavar="PROTECTED_PATH=BACKUP_PATH")
    parser.add_argument("--probe-file", action="append", default=[], metavar="PROTECTED_PATH=HOST_RESPONSE")
    parser.add_argument("--scratch", type=Path)
    parser.add_argument("--scratch-run-id")
    args = parser.parse_args()
    try:
        key = parse_key(args.key_file.read_text(encoding="ascii"))
        paths = {str(protected_path(path)) for path in args.path}
        if paths and not (args.root or args.container):
            raise ValueError("protected paths require a host root or a Docker container")
        if bool(args.scratch) != bool(args.scratch_run_id):
            raise ValueError("scratch archive and its run ID must be provided together")
        root = args.root.resolve(strict=True) if args.root else None
        container = container_id(args.container) if args.container else None
        source_id = container
        if root:
            root_info = root.stat()
            source_id = f"{root_info.st_dev}:{root_info.st_ino}"
        files = {path: snapshot_file(root, container, PurePosixPath(path)) for path in sorted(paths)}
        timestamp = time.time_ns()
        witnesses = []
        for entry in args.trace:
            role, directory = entry.split("=", 1)
            if role not in ROLES:
                raise ValueError("invalid trace role")
            witnesses.append(writer_witness(role, Path(directory), paths))
        file_backups = {}
        for entry in args.file_backup:
            name, backup = entry.split("=", 1)
            file_backups.setdefault(str(protected_path(name)), []).append(_digest_or_none(Path(backup)))
        reference = hash_regular(args.reference_dump) if args.reference_dump else None
        probes = {}
        for entry in args.probe_file:
            name, response = entry.split("=", 1)
            name = str(protected_path(name))
            if name not in paths or name in probes:
                raise ValueError("each probe must refer to a distinct enrolled file")
            probes[name] = hash_regular(Path(response))
        captured = {"files": files, "source": source_id, "writers": witnesses, "reference_dump": reference,
                    "backups": [_digest_or_none(file) for file in args.backup],
                    "file_backups": file_backups, "probes": probes}
        if args.scratch:
            captured["scratch"] = read_scratch(args.scratch, args.scratch_run_id, key)
        sequence = append_checkpoint(args.output / ARTIFACTS_PATH, key, args.run_id,
                                     args.kind, captured, timestamp)
        print(f"FM3.3 checkpoint {sequence} ({args.kind})")
    except (OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
        print(f"fm33-artifacts: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
