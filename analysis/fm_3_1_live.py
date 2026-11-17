"""Collect and score exact-copy submissions on a trusted Linux host."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import secrets
import selectors
import socket
import struct
import sys
import tarfile
import tempfile
import time
from contextlib import ExitStack
from pathlib import Path

from .fm_3_1 import (MAX_UPLOAD, PRINCIPALS, Ledger, archive_manifest, evaluate,
                    identifier, json_bytes, read_key, read_plan)

_HEADER_LIMIT = 4096
_REQUEST_SECONDS = 5
_CONTROL = "control"


def _chunks(connection, deadline):
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("request deadline exceeded")
        connection.settimeout(remaining)
        chunk = connection.recv(64 * 1024)
        if not chunk:
            break
        yield chunk


def _request(chunks):
    pending = b""
    for chunk in chunks:
        pending += chunk
        header, separator, rest = pending.partition(b"\n")
        if len(header) > _HEADER_LIMIT:
            raise ValueError("request header too large")
        if separator:
            request = json.loads(header)
            if not isinstance(request, dict):
                raise ValueError("invalid request")
            return request, rest
    raise ValueError("incomplete request header")


def _peer_identity(connection):
    size = struct.calcsize("3i")
    pid, _, _ = struct.unpack("3i", connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, size))
    try:
        process_stat = Path(f"/proc/{pid}/stat").read_text()
        start_ticks = process_stat.rpartition(")")[2].split()[19]
    except (OSError, IndexError) as error:
        raise ValueError("cannot resolve submission peer identity") from error
    if pid <= 0 or not start_ticks.isascii() or not start_ticks.isdecimal():
        raise ValueError("invalid submission peer identity")
    return {"pid": pid, "start_ticks": start_ticks}


def _receive_archive(chunks, first, length, archive_directory):
    if type(length) is not int or not 0 < length <= MAX_UPLOAD:
        raise ValueError("invalid upload length")
    digest = hashlib.sha256()
    with tempfile.NamedTemporaryFile(dir=archive_directory) as destination:
        chunk = first
        remaining = length
        while True:
            if len(chunk) > remaining:
                raise ValueError("too much archive data")
            destination.write(chunk)
            digest.update(chunk)
            remaining -= len(chunk)
            if remaining == 0:
                break
            chunk = next(chunks, None)
            if chunk is None:
                raise ValueError("incomplete archive data")
        destination.flush()
        destination.seek(0)
        archive_manifest(destination)
        archive_id = digest.hexdigest()
        try:
            os.link(destination.name, archive_directory / f"{archive_id}.tar")
        except FileExistsError:
            pass
    return archive_id


class Witness:
    def __init__(self, plan, archive_directory, ledger):
        self.units = {unit["id"]: unit for unit in plan["units"]}
        self.archive_directory = archive_directory
        self.ledger = ledger
        self.open_units = set()
        self.closed_units = set()

    def submission(self, principal, request, chunks, first, connection):
        if set(request) != {"kind", "unit", "artifact", "size"} or request["kind"] != "submission":
            raise ValueError("the submission endpoint accepts only artifact uploads")
        unit, artifact = request["unit"], request["artifact"]
        if (not identifier(unit) or unit not in self.open_units
                or not identifier(artifact) or artifact not in self.units[unit]["artifacts"]):
            raise ValueError("unit or artifact is not open for submission")
        peer = _peer_identity(connection)
        digest = _receive_archive(chunks, first, request["size"], self.archive_directory)
        self.ledger.append({"kind": "submission", "unit": unit, "artifact": artifact,
                            "principal": principal, "peer": peer, "sha256": digest})

    def control(self, request):
        kind = request.get("kind")
        if kind == "seal" and set(request) == {"kind"}:
            self.ledger.append(request)
            return True
        unit = request.get("unit")
        if not identifier(unit) or unit not in self.units:
            raise ValueError("unknown unit")
        if kind in ("open", "close") and set(request) == {"kind", "unit"}:
            if kind == "open" and unit not in self.open_units | self.closed_units:
                self.open_units.add(unit)
            elif kind == "close" and unit in self.open_units:
                self.open_units.remove(unit)
                self.closed_units.add(unit)
            else:
                raise ValueError("invalid episode or task transition")
        elif kind in ("health", "degradation"):
            fields = {"kind", "unit", "instrument", "witness"}
            if kind == "degradation":
                fields.add("principal")
            principal = request.get("principal")
            if (set(request) != fields or unit not in self.open_units | self.closed_units
                    or request["instrument"] not in self.units[unit]["instruments"]
                    or not identifier(request["witness"])
                    or principal is not None and (not isinstance(principal, str) or principal not in PRINCIPALS)):
                raise ValueError("invalid integrity report")
        else:
            raise ValueError("invalid host control operation")
        self.ledger.append(request)
        return False


def _listen(stack, selector, path, principal):
    server = stack.enter_context(socket.socket(socket.AF_UNIX, socket.SOCK_STREAM))
    server.bind(str(path))
    stack.callback(path.unlink, missing_ok=True)
    path.chmod(0o600 if principal == _CONTROL else 0o666)
    server.listen()
    selector.register(server, selectors.EVENT_READ, principal)


def serve(plan_path, directory, sockets, principals):
    plan, digest = read_plan(plan_path)
    directory.mkdir(mode=0o700)
    archives = directory / "archives"
    archives.mkdir(mode=0o700)
    key = secrets.token_bytes(32)
    fd = os.open(directory / "witness.key", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as handle:
        handle.write(key)
    sockets.mkdir(mode=0o700)
    with ExitStack() as stack:
        ledger = Ledger(directory / "ledger.jsonl", key)
        stack.callback(ledger.close)
        ledger.append({"kind": "begin", "plan_sha256": digest})
        witness = Witness(plan, archives, ledger)
        selector = stack.enter_context(selectors.DefaultSelector())
        for principal in (*sorted(principals), _CONTROL):
            _listen(stack, selector, sockets / f"{principal}.sock", principal)
        while True:
            for listener, _ in selector.select():
                connection, _ = listener.fileobj.accept()
                with connection:
                    try:
                        chunks = _chunks(connection, time.monotonic() + _REQUEST_SECONDS)
                        request, first = _request(chunks)
                        if listener.data == _CONTROL:
                            if first:
                                raise ValueError("unexpected host control payload")
                            sealed = witness.control(request)
                        else:
                            witness.submission(listener.data, request, chunks, first, connection)
                            sealed = False
                        response = {"ok": True}
                    except (ValueError, TimeoutError, ConnectionError, tarfile.TarError) as error:
                        response = {"ok": False, "error": str(error)}
                        sealed = False
                    try:
                        connection.sendall(json_bytes(response) + b"\n")
                    except (ConnectionError, TimeoutError):
                        pass
                    if sealed:
                        return


def send(endpoint, request, payload=None):
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
        connection.settimeout(2 * _REQUEST_SECONDS)
        connection.connect(str(endpoint))
        connection.sendall(json_bytes(request) + b"\n")
        if payload is not None:
            while chunk := payload.read(64 * 1024):
                connection.sendall(chunk)
        with connection.makefile("rb") as response:
            result = json.loads(response.readline(_HEADER_LIMIT))
        if not result.get("ok"):
            raise ValueError(result.get("error", "witness rejected the request"))


def submit(endpoint, unit, artifact, source):
    with tempfile.TemporaryFile() as archive_file:
        with tarfile.open(fileobj=archive_file, mode="w", dereference=False) as archive:
            archive.add(source, arcname=".")
        size = archive_file.tell()
        if size > MAX_UPLOAD:
            raise ValueError("artifact exceeds the upload limit")
        archive_file.seek(0)
        send(endpoint, {"kind": "submission", "unit": unit, "artifact": artifact, "size": size}, archive_file)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    record = commands.add_parser("serve")
    record.add_argument("plan", type=Path)
    record.add_argument("directory", type=Path)
    record.add_argument("sockets", type=Path)
    record.add_argument("--principal", choices=sorted(PRINCIPALS - {"agent"}), action="append", default=[])

    control = commands.add_parser("control")
    control.add_argument("socket", type=Path)
    control.add_argument("event", help="trusted harness event as a JSON object")

    upload = commands.add_parser("submit")
    upload.add_argument("socket", type=Path)
    upload.add_argument("unit")
    upload.add_argument("artifact")
    upload.add_argument("source", type=Path)

    score = commands.add_parser("score")
    score.add_argument("plan", type=Path)
    score.add_argument("directory", type=Path)

    args = parser.parse_args(argv)
    try:
        if args.command == "serve":
            serve(args.plan, args.directory, args.sockets, {"agent", *args.principal})
        elif args.command == "control":
            send(args.socket, json.loads(args.event))
        elif args.command == "submit":
            submit(args.socket, args.unit, args.artifact, args.source)
        else:
            plan, digest = read_plan(args.plan)
            try:
                key = read_key(args.directory / "witness.key")
            except (OSError, ValueError):
                key = None
            verdicts = evaluate(plan, digest, args.directory, key)
            print(json.dumps([verdict.to_dict() for verdict in verdicts], sort_keys=True, indent=2))
    except (OSError, ValueError, tarfile.TarError) as error:
        print(f"FM3.1: {error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
