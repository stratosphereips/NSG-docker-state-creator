"""streamkit: the shared parser surface for wave-3+ detectors.

One import surface (``from analysis import streamkit``) with two halves.

DELEGATED (frozen, import-only)
    Proven helpers of the seven frozen detectors are re-exported BY REFERENCE
    — ``streamkit.workload_tree`` *is* ``fm_2_3._workload_tree`` — so there is
    zero behavior change and one implementation.  Nothing here refactors,
    wraps, or copies frozen code.  The frozen modules stay untouched; new
    detectors import them through this name (or directly — both are the same
    object) so fixes land in exactly one place.

    - workload-tree resolution: :func:`workload_tree` (fm_2_3 ppid-closure
      fork fixpoint), :func:`tree_pids` + :func:`census` (fm_4_5 pid-level
      descent over first-seen ppids).
    - trace-hole detection: :func:`missing_trace_pids` (fm_4_2: successful
      fork-class results naming trace.PID files absent from syscalls/) and
      :func:`strace_children` (fm_2_3 kernel-confirmed parentage map).
    - mutation-edge collector: :func:`mutation_edges` (+ :class:`MutEdge`,
      :func:`kernel_paths`, :func:`unparsed_destructive_lines`) from fm_2_1.
    - bind-edge collector: :func:`collect_bind_edges` (+ :class:`BindEdge`,
      :func:`listener_identity`, :func:`norm_addr`) from afm_4.
    - kill-edge collectors: :func:`collect_signal_edges` and
      :func:`collect_killcmd_edges` (+ :class:`KillEdge`) from fm_4_2.
    - shared proven tokenizers: :func:`split_args` (fm_4_2 top-level comma
      splitter), :func:`split_top_args` (afm_1 brace-aware splitter),
      :func:`parse_sockaddr` and :func:`msg_name_values` (afm_1).

NEW (fresh, implemented here; formats pinned to the collector sources in
observer/bin/* — never to examples in this docstring)

    (a) execveat argv: the loader types ``execveat`` as a plain SyscallLine
        (the known shared gap — only ``execve`` becomes an ExecveLine).
        :func:`parse_execveat` / :func:`execveat_lines` rebuild
        ExecveLine-equivalent records with argv parsed from the bracketed
        argv array; :func:`execveat_target` resolves the executed path from
        the literal filename or, for ``""`` + ``AT_EMPTY_PATH``, from the
        -yy dirfd annotation (strace execveat(2) shape:
        ``execveat(dirfd, filename, [argv], envp, flags) = result``).
    (b) zeek conn.log: the zeek sensor (observe-entrypoint, cwd
        /observation/zeek, policy/tuning/json-logs) writes one JSON object
        per line.  :func:`load_conn_log` / :func:`load_conn_dir` parse
        ts / id.orig_h / id.orig_p / id.resp_h / id.resp_p / proto /
        duration / service into :class:`ZeekConn` records.
    (c) ss lines: SocketEvent keeps the ``ss -H -n -p [-t -u]`` line
        verbatim.  :func:`parse_ss_line` / :func:`parse_socket_events`
        normalize family / state / queues / local / peer / owning processes
        into :class:`SsSocketRecord` (both spellings the collector can emit:
        with a leading Netid column, and state-first).
    (d) snapshots/objects: state-reconciler (OBS_ARCHIVE_CHANGED_FILES=1)
        archives every added/changed regular file content-addressed at
        ``snapshots/objects/<checksum[:2]>/<sha256>``.  :func:`load_object`,
        :func:`load_verified_object`, :func:`list_objects` read and verify
        them (a verified read fails closed on a name/content hash mismatch).
    (e) census CapEff deltas: process-monitor embeds a ``capabilities`` dict
        (including ``effective`` = /proc CapEff) in every process_seen /
        process_changed record and the prior snapshot in ``previous`` — but
        the frozen ProcRecord drops it.  :func:`cap_effective_changes` /
        :func:`load_cap_changes` derive :class:`CapDelta` records (raised /
        dropped capability NAMES) from raw processes.jsonl objects.

Trust rules carried over from the wave-1/2 contract: every loader is total
(missing / corrupt / degraded evidence becomes a named ``STREAMKIT:*`` flag
in the caller's flags list, never an exception, never a silent pass); no
heuristic or probabilistic judgment anywhere; tampering can only degrade a
verdict (the verified object read and the degraded CapDelta records are the
fail-closed halves).  This module is a parser surface, NOT a detector: it
deliberately exports no FM_ID/detect, so analyze.py auto-discovery never
picks it up.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any, Iterable, List, Mapping, Optional, Tuple

from .detectors.afm_1 import _msg_name_values, _parse_sockaddr, _split_top_args
from .detectors.afm_4 import (
    BindEdge,
    _collect_bind_edges,
    _listener_identity,
    _norm_addr,
)
from .detectors.fm_2_1 import (
    MutEdge,
    _kernel_paths,
    _mutation_edges,
    _unparsed_destructive_lines,
)
from .detectors.fm_2_3 import _strace_children, _workload_tree
from .detectors.fm_4_2 import (
    KillEdge,
    _split_args,
    collect_killcmd_edges,
    collect_signal_edges,
    missing_trace_pids,
)
from .detectors.fm_4_5 import Generation, _census, _tree_pids
from .observation import iter_jsonl
from .records import ExecveLine, SocketEvent, StraceLine, SyscallLine

__all__ = [
    # ---- delegated: workload tree / census -------------------------------
    "workload_tree", "tree_pids", "census", "Generation",
    # ---- delegated: trace holes ------------------------------------------
    "missing_trace_pids", "strace_children",
    # ---- delegated: mutation / bind / kill edge collectors ---------------
    "mutation_edges", "MutEdge", "kernel_paths",
    "unparsed_destructive_lines",
    "collect_bind_edges", "BindEdge", "listener_identity", "norm_addr",
    "collect_signal_edges", "collect_killcmd_edges", "KillEdge",
    # ---- delegated: shared tokenizers ------------------------------------
    "split_args", "split_top_args", "parse_sockaddr", "msg_name_values",
    "iter_jsonl",
    # ---- new: execveat ----------------------------------------------------
    "ExecveatTarget", "parse_execveat", "execveat_lines", "execveat_target",
    # ---- new: zeek conn.log ----------------------------------------------
    "ZeekConn", "parse_conn_object", "load_conn_log", "load_conn_dir",
    # ---- new: ss lines ----------------------------------------------------
    "SsEndpoint", "SsProcess", "SsSocketRecord",
    "parse_ss_line", "parse_socket_events",
    # ---- new: snapshots/objects -------------------------------------------
    "SnapshotObject", "object_path", "load_object", "object_text",
    "load_verified_object", "list_objects",
    # ---- new: census CapEff deltas ----------------------------------------
    "CAPABILITY_NAMES", "CapDelta", "capability_names",
    "cap_effective_changes", "load_cap_changes",
    # ---- surface self-description -----------------------------------------
    "DELEGATIONS",
]

#: Public name -> frozen origin (module.qualname).  Every entry is re-exported
#: BY REFERENCE; the import-surface tests assert object identity against the
#: origin so accidental copies cannot fork a frozen helper.
DELEGATIONS: Mapping[str, str] = {
    "workload_tree": "analysis.detectors.fm_2_3._workload_tree",
    "strace_children": "analysis.detectors.fm_2_3._strace_children",
    "census": "analysis.detectors.fm_4_5._census",
    "tree_pids": "analysis.detectors.fm_4_5._tree_pids",
    "Generation": "analysis.detectors.fm_4_5.Generation",
    "missing_trace_pids": "analysis.detectors.fm_4_2.missing_trace_pids",
    "collect_signal_edges": "analysis.detectors.fm_4_2.collect_signal_edges",
    "collect_killcmd_edges": "analysis.detectors.fm_4_2.collect_killcmd_edges",
    "KillEdge": "analysis.detectors.fm_4_2.KillEdge",
    "split_args": "analysis.detectors.fm_4_2._split_args",
    "mutation_edges": "analysis.detectors.fm_2_1._mutation_edges",
    "MutEdge": "analysis.detectors.fm_2_1.MutEdge",
    "kernel_paths": "analysis.detectors.fm_2_1._kernel_paths",
    "unparsed_destructive_lines":
        "analysis.detectors.fm_2_1._unparsed_destructive_lines",
    "collect_bind_edges": "analysis.detectors.afm_4._collect_bind_edges",
    "BindEdge": "analysis.detectors.afm_4.BindEdge",
    "listener_identity": "analysis.detectors.afm_4._listener_identity",
    "norm_addr": "analysis.detectors.afm_4._norm_addr",
    "split_top_args": "analysis.detectors.afm_1._split_top_args",
    "parse_sockaddr": "analysis.detectors.afm_1._parse_sockaddr",
    "msg_name_values": "analysis.detectors.afm_1._msg_name_values",
    "iter_jsonl": "analysis.observation.iter_jsonl",
}

# Public aliases (the imported private names above stay bound too, so both
# spellings resolve to the identical frozen function object).
tree_pids = _tree_pids
census = _census
workload_tree = _workload_tree
strace_children = _strace_children
mutation_edges = _mutation_edges
kernel_paths = _kernel_paths
unparsed_destructive_lines = _unparsed_destructive_lines
collect_bind_edges = _collect_bind_edges
listener_identity = _listener_identity
norm_addr = _norm_addr
split_args = _split_args
split_top_args = _split_top_args
parse_sockaddr = _parse_sockaddr
msg_name_values = _msg_name_values


# ---------------------------------------------------------------------------
# Small total coercers (local, 3.8-safe; same semantics as observation's)
# ---------------------------------------------------------------------------


def _opt_int(value: Any) -> Optional[int]:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, float) and value.is_integer():
        return int(value)
    if isinstance(value, str):
        try:
            return int(value.strip())
        except ValueError:
            return None
    return None


def _opt_float(value: Any) -> Optional[float]:
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        try:
            return float(value.strip())
        except ValueError:
            return None
    return None


def _opt_str(value: Any) -> Optional[str]:
    if value is None:
        return None
    return value if isinstance(value, str) else str(value)


# ---------------------------------------------------------------------------
# (a) execveat argv — the shared exec gap
# ---------------------------------------------------------------------------

_QUOTED = re.compile(r'"((?:[^"\\]|\\.)*)"')
_ESCAPES = {"n": "\n", "t": "\t", "r": "\r", '"': '"', "\\": "\\"}

#: -yy dirfd annotation: ``3</work>`` / ``AT_FDCWD</work>`` / the mount form
#: ``3</work</>`` (inner text up to the nested ``<`` is the fd's path).
_DIRFD_ANNOTATION = re.compile(r"^(?:AT_FDCWD|-?\d+)<(?P<inner>.*)>$")


def _unquote(token: str) -> str:
    out: List[str] = []
    i = 0
    while i < len(token):
        char = token[i]
        if char == "\\" and i + 1 < len(token):
            nxt = token[i + 1]
            out.append(_ESCAPES.get(nxt, "\\" + nxt))
            i += 2
        else:
            out.append(char)
            i += 1
    return "".join(out)


def _quoted_value(token: str) -> str:
    """The unescaped content of the FIRST quoted string in ``token`` (the
    token verbatim when it carries no quotes)."""
    match = _QUOTED.search(token)
    return _unquote(match.group(1)) if match else token.strip()


def _argv_array(token: str) -> Tuple[Optional[Tuple[str, ...]], bool]:
    """(argv, truncated) of one bracketed argv-array argument token.

    ``None`` argv = no array found (degraded); ``()`` = empty-but-parsed
    array; ``truncated`` marks strace's ``...`` elision inside the array.
    """
    text = token.strip()
    if len(text) < 2 or text[0] != "[" or text[-1] != "]":
        return None, False
    body = text[1:-1]
    truncated = "..." in body
    argv = tuple(_unquote(m.group(1)) for m in _QUOTED.finditer(body))
    return (argv, truncated) if argv else ((), truncated)


def parse_execveat(record: StraceLine) -> Optional[ExecveLine]:
    """Re-type one execveat SyscallLine as an ExecveLine with argv parsed.

    Total and side-effect free: a non-SyscallLine, or any syscall other than
    ``execveat``, returns ``None``; an argv argument that is not a bracketed
    array yields ``argv=None`` (degraded, caller must fail closed); strace's
    ``...`` elision sets ``truncated``.  ``raw``/``ts``/``seq``/``file_pid``/
    ``result_raw`` are carried over verbatim, so the record is
    indistinguishable from a loader-produced ExecveLine of the same line.
    """
    if not isinstance(record, SyscallLine) or record.name != "execveat":
        return None
    args = split_top_args(record.args_raw)
    argv: Optional[Tuple[str, ...]] = None
    truncated = False
    if len(args) >= 3:
        argv, truncated = _argv_array(args[2])
    return ExecveLine(
        file_pid=record.file_pid,
        seq=record.seq,
        raw=record.raw,
        ts=record.ts,
        argv=argv,
        truncated=truncated,
        result_raw=record.result_raw,
    )


def execveat_lines(strace: Iterable[StraceLine]) -> Tuple[ExecveLine, ...]:
    """Every execveat line of a trace tuple as an ExecveLine (in order)."""
    out: List[ExecveLine] = []
    for record in strace:
        parsed = parse_execveat(record)
        if parsed is not None:
            out.append(parsed)
    return tuple(out)


@dataclass(frozen=True)
class ExecveatTarget:
    """The kernel-resolved execution target of one execveat line.

    ``source`` is how the path was pinned: ``filename`` (the literal
    pathname argument — cwd-relative as the kernel sees it, kept verbatim),
    ``dirfd`` (empty filename + AT_EMPTY_PATH + a -yy dirfd annotation
    naming an absolute path), or ``unresolved`` (neither applies: the
    executed path is not derivable from the trace, and callers must treat
    it as missing evidence, never guess).
    """

    path: str
    source: str                    # "filename" | "dirfd" | "unresolved"
    dirfd_path: str = ""           # absolute path of the -yy dirfd annotation
    filename: str = ""             # unquoted filename argument ("" when empty)
    flags: Tuple[str, ...] = ()    # execveat(2) flag literals, split on "|"


def execveat_target(record: StraceLine) -> ExecveatTarget:
    """Resolve what one execveat line executed (closed form; no guessing)."""
    if not isinstance(record, SyscallLine) or record.name != "execveat":
        return ExecveatTarget(path="", source="unresolved")
    args = split_top_args(record.args_raw)
    dirfd_token = args[0].strip() if args else ""
    filename_token = args[1].strip() if len(args) > 1 else ""
    flags_token = args[4].strip() if len(args) > 4 else ""
    flags = tuple(part.strip() for part in flags_token.split("|")) \
        if flags_token else ()

    dirfd_path = ""
    match = _DIRFD_ANNOTATION.match(dirfd_token)
    if match is not None:
        inner = match.group("inner")
        if inner.endswith(" (deleted)"):
            inner = inner[: -len(" (deleted)")]
        if "<" in inner:               # -yy mount annotation: path<root>
            inner = inner.split("<", 1)[0]
        if inner.startswith("/"):
            dirfd_path = inner

    filename = _quoted_value(filename_token)
    if filename:
        return ExecveatTarget(path=filename, source="filename",
                              dirfd_path=dirfd_path, filename=filename,
                              flags=flags)
    if "AT_EMPTY_PATH" in flags and dirfd_path:
        # execveat(fd, "", ..., AT_EMPTY_PATH) executes the file open ON the
        # dirfd itself -- which the -yy annotation names.
        return ExecveatTarget(path=dirfd_path, source="dirfd",
                              dirfd_path=dirfd_path, filename="",
                              flags=flags)
    return ExecveatTarget(path="", source="unresolved",
                          dirfd_path=dirfd_path, filename="", flags=flags)


# ---------------------------------------------------------------------------
# (b) zeek conn.log (JSON lines; observe-entrypoint runs zeek with
#     policy/tuning/json-logs and cwd /observation/zeek)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ZeekConn:
    """One conn.log JSON line (only the flow-identity fields; ``raw`` keeps
    the line verbatim for evidence notes).

    Unset fields (absent from the JSON, or zeek's ``-`` unset marker) are
    ``None`` — never a guessed default.
    """

    seq: int                        # 1-based line number within its file
    file: str                       # file name the line came from
    ts: Optional[float] = None
    uid: str = ""
    orig_h: Optional[str] = None
    orig_p: Optional[int] = None
    resp_h: Optional[str] = None
    resp_p: Optional[int] = None
    proto: str = ""                 # "tcp" | "udp" | "icmp" ... verbatim
    duration: Optional[float] = None
    service: Optional[str] = None   # "-" and absent are both None
    conn_state: Optional[str] = None
    raw: str = ""


def _zeek_unset(value: Any) -> Optional[str]:
    text = _opt_str(value)
    return None if text == "-" else text


def parse_conn_object(seq: int, obj: Mapping[str, Any],
                      file: str = "", raw: str = "") -> ZeekConn:
    """One decoded conn.log JSON object -> ZeekConn (total, never raises)."""
    return ZeekConn(
        seq=seq,
        file=file,
        ts=_opt_float(obj.get("ts")),
        uid=_opt_str(obj.get("uid")) or "",
        orig_h=_opt_str(obj.get("id.orig_h")),
        orig_p=_opt_int(obj.get("id.orig_p")),
        resp_h=_opt_str(obj.get("id.resp_h")),
        resp_p=_opt_int(obj.get("id.resp_p")),
        proto=_opt_str(obj.get("proto")) or "",
        duration=_opt_float(obj.get("duration")),
        service=_zeek_unset(obj.get("service")),
        conn_state=_zeek_unset(obj.get("conn_state")),
        raw=raw,
    )


def load_conn_log(path: Path, flags: Optional[List[str]] = None
                  ) -> Tuple[ZeekConn, ...]:
    """Parse one conn.log JSON-lines file; corrupt lines become flags."""
    path = Path(path)
    records: List[ZeekConn] = []
    try:
        handle = path.open("r", encoding="utf-8", errors="replace")
    except OSError:
        if flags is not None:
            flags.append(f"STREAMKIT:conn_missing path={path}")
        return ()
    with handle:
        for number, raw in enumerate(handle, start=1):
            stripped = raw.strip()
            if not stripped:
                continue
            try:
                obj = json.loads(stripped)
            except ValueError:
                if flags is not None:
                    flags.append(
                        f"STREAMKIT:conn_corrupt file={path.name}"
                        f" line={number}")
                continue
            if not isinstance(obj, dict):
                if flags is not None:
                    flags.append(
                        f"STREAMKIT:conn_non_object file={path.name}"
                        f" line={number}")
                continue
            records.append(parse_conn_object(number, obj,
                                             file=path.name, raw=stripped))
    return tuple(records)


def load_conn_dir(zeek_dir: Path, flags: Optional[List[str]] = None
                  ) -> Tuple[ZeekConn, ...]:
    """Parse every conn*.log of the zeek output directory (conn.log plus
    rotated spellings) in sorted file order; ``zeek-console.log`` never
    matches the glob."""
    zeek_dir = Path(zeek_dir)
    if not zeek_dir.is_dir():
        if flags is not None:
            flags.append(f"STREAMKIT:conn_dir_missing path={zeek_dir}")
        return ()
    records: List[ZeekConn] = []
    for path in sorted(zeek_dir.glob("conn*.log"), key=lambda p: p.name):
        if not path.is_file():
            continue
        records.extend(load_conn_log(path, flags))
    return tuple(records)


# ---------------------------------------------------------------------------
# (c) normalized ss-line records (socket-monitor: ss -H -n -p -t -u ...)
# ---------------------------------------------------------------------------

#: Netid column spellings of `ss` (leading token when -t and -u combine).
_NETID_TOKENS = frozenset({
    "tcp", "tcp6", "udp", "udp6", "sctp", "sctp6", "raw", "vsock",
    "netlink", "unix", "p_dgr", "p_str", "p_raw", "i_uc", "i_nlg", "i_ucw",
})

#: One process entry of the ``users:(("name",pid=N,fd=M),...)`` column.
_SS_PROC = re.compile(r'\("([^"]*)",pid=(\d+)(?:,fd=(-?\d+))?\)')


@dataclass(frozen=True)
class SsEndpoint:
    """One endpoint column.  ``addr`` is verbatim with brackets stripped,
    wildcard spellings (``*``, ``0.0.0.0``, ``::``) normalized to ``*`` by
    the frozen afm_4 normalizer; ``port`` is None for ``*`` or non-inet
    spellings; ``raw`` keeps the token as ss printed it."""

    addr: str
    port: Optional[int]
    raw: str


@dataclass(frozen=True)
class SsProcess:
    """One owning-process entry of the users:(...) column."""

    name: str
    pid: int
    fd: Optional[int]


@dataclass(frozen=True)
class SsSocketRecord:
    """One normalized ss line (total: anything unparsable stays None and
    ``degraded`` is True — callers must treat a degraded record as missing
    evidence, never as a match).

    ``family`` is "tcp" | "udp" | "" (non-inet netid); state-first spellings
    derive udp from ``UNCONN`` exactly like the frozen afm_4 listener
    parser.  ``seq``/``ts``/``kind`` carry the SocketEvent census join when
    the record came from :func:`parse_socket_events`.
    """

    raw: str
    netid: str = ""
    family: str = ""
    state: str = ""
    recv_q: Optional[int] = None
    send_q: Optional[int] = None
    local: Optional[SsEndpoint] = None
    peer: Optional[SsEndpoint] = None
    processes: Tuple[SsProcess, ...] = ()
    pids: Tuple[int, ...] = ()
    degraded: bool = False
    seq: int = 0
    ts: Optional[float] = None
    kind: str = ""


def _ss_endpoint(token: str) -> Optional[SsEndpoint]:
    """Parse one endpoint column (bracketed v6, v4, wildcard, or bare)."""
    text = token.strip()
    if not text:
        return None
    addr = text
    port: Optional[int] = None
    if text.startswith("[") and "]" in text:
        close = text.index("]")
        addr = text[1:close]
        rest = text[close + 1:]
        if rest.startswith(":"):
            port_text = rest[1:]
            port = int(port_text) if port_text.isdigit() else None
        elif rest != "":
            return None                    # mangled bracketed token
    elif ":" in text:
        addr, _, port_text = text.rpartition(":")
        port = int(port_text) if port_text.isdigit() else None
    return SsEndpoint(addr=norm_addr(addr), port=port, raw=text)


def _ss_family(netid: str, state: str) -> str:
    if netid.startswith("tcp"):
        return "tcp"
    if netid.startswith("udp"):
        return "udp"
    if netid in ("", "tcp", "tcp6", "udp", "udp6"):
        # state-first spelling (the collector's combined -t -u output always
        # carries Netid, but the frozen fixtures and afm_4 accept both):
        # UNCONN is the udp state spelling, everything else tcp.
        return "udp" if state.upper() == "UNCONN" else "tcp"
    return ""                              # raw / vsock / netlink / unix


def parse_ss_line(line: str) -> Optional[SsSocketRecord]:
    """Normalize one verbatim ss line; None only for an empty line.

    Column model of ``ss -H -n -p [-t -u] (-a|-l)``:
    ``[Netid] State Recv-Q Send-Q Local Peer [users:...]``.
    """
    tokens = line.split()
    if not tokens:
        return None
    index = 0
    netid = ""
    if tokens[0].lower() in _NETID_TOKENS:
        netid = tokens[0].lower()
        index = 1
    if len(tokens) < index + 5:
        # Too few columns to carry endpoints: nothing is guessed (not even
        # a family), the line stays as a degraded record.
        return SsSocketRecord(raw=line, netid=netid, degraded=True)
    state = tokens[index]
    recv_q = _opt_int(tokens[index + 1])
    send_q = _opt_int(tokens[index + 2])
    local = _ss_endpoint(tokens[index + 3])
    peer = _ss_endpoint(tokens[index + 4])
    rest = " ".join(tokens[index + 5:])
    processes = tuple(
        SsProcess(name=m.group(1), pid=int(m.group(2)),
                  fd=_opt_int(m.group(3)))
        for m in _SS_PROC.finditer(rest)
    )
    pids = tuple(sorted({proc.pid for proc in processes}))
    return SsSocketRecord(
        raw=line,
        netid=netid,
        family=_ss_family(netid, state),
        state=state,
        recv_q=recv_q,
        send_q=send_q,
        local=local,
        peer=peer,
        processes=processes,
        pids=pids,
        degraded=local is None,
    )


def parse_socket_events(sockets: Iterable[SocketEvent],
                        flags: Optional[List[str]] = None
                        ) -> Tuple[SsSocketRecord, ...]:
    """Normalize every SocketEvent's verbatim ss line, keeping the census
    join (seq/ts/kind).  Unparsable or degraded lines stay as degraded
    records AND raise a named flag, so no inventory line ever vanishes and
    no degraded parse can masquerade as a clean one."""
    out: List[SsSocketRecord] = []
    for event in sockets:
        parsed = parse_ss_line(event.socket)
        if parsed is None or parsed.degraded:
            if flags is not None:
                flags.append(
                    f"STREAMKIT:ss_unparsed seq={event.seq}"
                    f" kind={event.kind}")
        if parsed is None:
            parsed = SsSocketRecord(raw=event.socket, degraded=True)
        out.append(replace(parsed, seq=event.seq, ts=event.ts,
                           kind=event.kind))
    return tuple(out)


# ---------------------------------------------------------------------------
# (d) snapshots/objects content-addressed archive (state-reconciler,
#     OBS_ARCHIVE_CHANGED_FILES=1: output/snapshots/objects/<cc>/<sha256>)
# ---------------------------------------------------------------------------

_SHA256_NAME = re.compile(r"^[0-9a-f]{64}$")


def object_path(objects_dir: Path, checksum: str) -> Path:
    """The content-addressed path of one archive object.

    Pure path algebra mirroring state-reconciler.archive_file exactly
    (``objects/<checksum[:2]>/<checksum>``); a malformed checksum raises
    ValueError (caller-contract violation, not missing evidence).
    """
    if not _SHA256_NAME.fullmatch(checksum or ""):
        raise ValueError(f"not a sha256 object name: {checksum!r}")
    return Path(objects_dir) / checksum[:2] / checksum


def _sha256_file(path: Path) -> Tuple[Optional[str], Optional[str]]:
    """(hex sha256, error) — (None, None) when unreadable."""
    digest = hashlib.sha256()
    try:
        with path.open("rb") as handle:
            while True:
                chunk = handle.read(1024 * 1024)
                if not chunk:
                    break
                digest.update(chunk)
        return digest.hexdigest(), None
    except OSError:
        return None, None


def load_object(objects_dir: Path, checksum: str,
                flags: Optional[List[str]] = None) -> Optional[bytes]:
    """Raw bytes of one archived object (no hash verification — use
    :func:`load_verified_object` for deciding evidence)."""
    path = object_path(objects_dir, checksum)
    try:
        return path.read_bytes()
    except OSError:
        if flags is not None:
            flags.append(f"STREAMKIT:object_missing checksum={checksum}")
        return None


def object_text(objects_dir: Path, checksum: str,
                flags: Optional[List[str]] = None) -> Optional[str]:
    """utf-8 (errors replaced) text of one archived object, or None."""
    data = load_object(objects_dir, checksum, flags)
    if data is None:
        return None
    return data.decode("utf-8", errors="replace")


def load_verified_object(objects_dir: Path, checksum: str,
                         flags: Optional[List[str]] = None) -> Optional[bytes]:
    """Bytes of one archived object, FAIL CLOSED on any mismatch.

    The archive is content-addressed, so ``sha256(content) != name`` is
    closed-form tampering/corruption: the read returns None with a named
    flag instead of handing the caller untrusted bytes.  A None here must
    surface as UNMEASURED downstream, never as an empty object."""
    data = load_object(objects_dir, checksum, flags)
    if data is None:
        return None
    actual = hashlib.sha256(data).hexdigest()
    if actual != checksum:
        if flags is not None:
            flags.append(
                f"STREAMKIT:object_corrupt checksum={checksum}"
                f" content={actual}")
        return None
    return data


@dataclass(frozen=True)
class SnapshotObject:
    """One object discovered by :func:`list_objects`.

    ``matches`` is True iff the content hashes to the object's name (the
    content-addressed invariant); None = unreadable content.
    """

    checksum: str
    path: Path
    size: Optional[int]
    content_sha256: Optional[str]
    matches: Optional[bool]


def list_objects(objects_dir: Path, flags: Optional[List[str]] = None,
                 verify: bool = True) -> Tuple[SnapshotObject, ...]:
    """Every object under objects/ in (prefix, name) order, verified.

    Layout discipline is flagged, never guessed: files not exactly two
    levels deep (``<cc>/<sha256>``), names that are not 64-hex, or a prefix
    directory that disagrees with the name's first two characters each
    become a named flag and the object is either reported with
    ``matches=False`` (present but misplaced/named) or skipped (not an
    object at all)."""
    objects_dir = Path(objects_dir)
    if not objects_dir.is_dir():
        if flags is not None:
            flags.append(f"STREAMKIT:object_dir_missing path={objects_dir}")
        return ()
    out: List[SnapshotObject] = []
    for entry in sorted(objects_dir.iterdir(), key=lambda p: p.name):
        if not entry.is_dir():
            if flags is not None:
                flags.append(
                    f"STREAMKIT:object_layout_bad path={entry.name}")
            continue
        for obj in sorted(entry.iterdir(), key=lambda p: p.name):
            name = obj.name
            if not obj.is_file() or not _SHA256_NAME.fullmatch(name):
                if flags is not None:
                    flags.append(
                        f"STREAMKIT:object_layout_bad path="
                        f"{entry.name}/{name}")
                continue
            size: Optional[int] = None
            try:
                size = obj.stat().st_size
            except OSError:
                pass
            if not verify:
                out.append(SnapshotObject(checksum=name, path=obj,
                                          size=size, content_sha256=None,
                                          matches=None))
                continue
            if entry.name != name[:2] and flags is not None:
                flags.append(
                    f"STREAMKIT:object_prefix_mismatch checksum={name}"
                    f" dir={entry.name}")
            content_sha: Optional[str]
            if size is None:
                content_sha = None
            else:
                content_sha, _error = _sha256_file(obj)
            matches: Optional[bool] = None
            if content_sha is not None:
                matches = content_sha == name
                if not matches and flags is not None:
                    flags.append(
                        f"STREAMKIT:object_corrupt checksum={name}"
                        f" content={content_sha}")
            out.append(SnapshotObject(checksum=name, path=obj, size=size,
                                      content_sha256=content_sha,
                                      matches=matches))
    return tuple(out)


# ---------------------------------------------------------------------------
# (e) census CapEff deltas (process-monitor embeds /proc CapEff in every
#     census record; ProcRecord drops it, so this reads the raw objects)
# ---------------------------------------------------------------------------

#: Linux capability names, index = capability number (CAP_* since 2.2; bits
#: 38-40 are perfmon/bpf/checkpoint_restore since kernels 5.8/5.19).  Frozen
#: closed-form table — extend only when the kernel vocabulary changes.
CAPABILITY_NAMES: Tuple[str, ...] = (
    "chown",              # 0
    "dac_override",       # 1
    "dac_read_search",    # 2
    "fowner",             # 3
    "fsetid",             # 4
    "kill",               # 5
    "setgid",             # 6
    "setuid",             # 7
    "setpcap",            # 8
    "linux_immutable",    # 9
    "net_bind_service",   # 10
    "net_broadcast",      # 11
    "net_admin",          # 12
    "net_raw",            # 13
    "ipc_lock",           # 14
    "ipc_owner",          # 15
    "sys_module",         # 16
    "sys_rawio",          # 17
    "sys_chroot",         # 18
    "sys_ptrace",         # 19
    "sys_pacct",          # 20
    "sys_admin",          # 21
    "sys_boot",           # 22
    "sys_nice",           # 23
    "sys_resource",       # 24
    "sys_time",           # 25
    "sys_tty_config",     # 26
    "mknod",              # 27
    "lease",              # 28
    "audit_write",        # 29
    "audit_control",      # 30
    "setfcap",            # 31
    "mac_override",       # 32
    "mac_admin",          # 33
    "syslog",             # 34
    "wake_alarm",         # 35
    "block_suspend",      # 36
    "audit_read",         # 37
    "perfmon",            # 38
    "bpf",                # 39
    "checkpoint_restore", # 40
)


def _mask_int(value: Any) -> Optional[int]:
    """A /proc status capability mask (16 hex digits, optional 0x) -> int."""
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if not isinstance(value, str):
        return None
    text = value.strip().lower()
    if text.startswith("0x"):
        text = text[2:]
    if not text or any(ch not in "0123456789abcdef" for ch in text):
        return None
    return int(text, 16)


def capability_names(mask: Any) -> Tuple[str, ...]:
    """Names of every set capability bit, ascending bit order.

    Accepts the raw census spelling (hex string) or an int; bits beyond the
    frozen table render as ``cap<N>``.  An unparsable mask yields ``()`` —
    callers must use :class:`CapDelta`'s ``degraded`` flag, not this, when
    the mask itself was unreadable.
    """
    value = _mask_int(mask)
    if value is None or value <= 0:
        return ()
    names: List[str] = []
    bit = 0
    remaining = value
    while remaining:
        if remaining & 1:
            names.append(
                CAPABILITY_NAMES[bit]
                if bit < len(CAPABILITY_NAMES) else f"cap{bit}")
        remaining >>= 1
        bit += 1
    return tuple(names)


@dataclass(frozen=True)
class CapDelta:
    """One census-observed effective-capability change of one identity.

    ``degraded`` is True when either mask was absent or unparsable — an
    attacker stripping the capabilities field cannot turn a change into a
    clean "no delta"; the degraded record is emitted so the caller fails
    closed (UNMEASURED), and ``raised``/``dropped`` stay empty.
    """

    seq: int
    ts: Optional[float]
    pid: Optional[int]
    start_ticks: str
    previous: str            # raw mask text as recorded ("" when absent)
    current: str             # raw mask text as recorded ("" when absent)
    raised: Tuple[str, ...] = ()
    dropped: Tuple[str, ...] = ()
    degraded: bool = False


def _cap_mask(record: Mapping[str, Any], field: str = "effective"
              ) -> Tuple[str, Optional[int]]:
    """(raw text, parsed int|None) of one snapshot's effective mask."""
    caps = record.get("capabilities")
    if not isinstance(caps, Mapping):
        return "", None
    raw = caps.get(field)
    text = raw if isinstance(raw, str) else ("" if raw is None else str(raw))
    return text, _mask_int(text)


def cap_effective_changes(records: Iterable[Any],
                          flags: Optional[List[str]] = None
                          ) -> Tuple[CapDelta, ...]:
    """Derive CapEff deltas from raw processes.jsonl objects.

    ``records`` is an iterable of ``(seq, obj)`` pairs (exactly what
    :func:`iter_jsonl` yields; bare dicts are accepted and numbered in
    order).  Only ``process_changed`` records carry a ``previous`` snapshot,
    so only they can yield deltas; equal masks yield nothing; absent or
    unparsable masks yield a ``degraded`` record plus a named flag."""
    out: List[CapDelta] = []
    position = 0
    for item in records:
        if isinstance(item, Mapping):
            position += 1
            seq, obj = position, item
        else:
            seq, obj = item[0], item[1]
        if not isinstance(obj, Mapping) or obj.get("event") != "process_changed":
            continue
        current_text, current_mask = _cap_mask(obj)
        previous_obj = obj.get("previous")
        if isinstance(previous_obj, Mapping):
            previous_text, previous_mask = _cap_mask(previous_obj)
        else:
            previous_text, previous_mask = "", None
        pid = _opt_int(obj.get("pid"))
        start_ticks = obj.get("start_ticks")
        base = dict(
            seq=seq,
            ts=_opt_float(obj.get("timestamp")),
            pid=pid,
            start_ticks=start_ticks if isinstance(start_ticks, str)
            else ("" if start_ticks is None else str(start_ticks)),
            previous=previous_text,
            current=current_text,
        )
        if current_mask is None or previous_mask is None:
            reason = ("cap_field_missing"
                      if (current_text == "" or previous_text == "")
                      else "cap_mask_unparsable")
            if flags is not None:
                flags.append(f"STREAMKIT:{reason} seq={seq}")
            out.append(CapDelta(degraded=True, **base))
            continue
        if current_mask == previous_mask:
            continue
        delta = CapDelta(
            raised=capability_names(current_mask & ~previous_mask),
            dropped=capability_names(previous_mask & ~current_mask),
            **base,
        )
        out.append(delta)
    return tuple(out)


def load_cap_changes(processes_jsonl: Path,
                     flags: Optional[List[str]] = None) -> Tuple[CapDelta, ...]:
    """iter_jsonl over processes.jsonl + :func:`cap_effective_changes`.

    A missing/unreadable file or corrupt line keeps its loader flag
    (surfaced here as a ``STREAMKIT:processes:<code>`` string) so a lost
    census can never masquerade as an empty delta set."""
    stream_flags: List[Any] = []
    records = list(iter_jsonl(Path(processes_jsonl), stream="processes",
                              flags=stream_flags))
    if flags is not None:
        for flag in stream_flags:
            flags.append(
                f"STREAMKIT:processes:{flag.code} {flag.detail}")
    return cap_effective_changes(records, flags)
