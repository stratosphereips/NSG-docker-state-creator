"""S7 differ: consecutive probe records -> diff records (kinds closed set).

Files/db use the SIMPLER manifest path: probes store the full 'path sha'
text (files_manifest) and pg_dump --schema-only text (db_schema_text); the
differ parses both texts. iptables: probes store normalized rules text under
iptables_text; line-set diff -> one rule_added/rule_removed per line.

Diff records are emitted with attribution=None placeholder; measurement
modules call mutate_filter.attribute() first (DESIGN §3).
"""
import os

from . import common

KINDS = (
    "rule_added", "rule_removed", "process_gone", "process_new",
    "process_recycled", "listener_gone", "listener_new", "port_ext_change",
    "file_new", "file_changed", "file_gone", "hosts_entry_changed",
    "authorized_keys_changed", "db_changed", "capture_down", "exfil_received",
    "rule_weakened", "containment_via_dos",
)

DIFFS_PATH = "diffs.jsonl"


def _rec(ts, run, host, kind, detail, unit_id=None):
    return {"ts": ts, "run": run, "host": host, "unit_id": unit_id,
            "kind": kind, "detail": detail,
            "attribution": None, "actor_ref": None}


def _proc_key(p):
    return (p.get("pid"), p.get("comm"), p.get("args"))


# Instrument self-observation noise: the harness's own docker execs appear in
# the ps snapshots as same-comm new-pid flapping — the batched snapshot's
# bash/ps/su/psql/pg_dump (postgres backend of the two-c pg_sleep probe),
# the v2 curl probes and heartbeat nc on atk, the rotating capture tcpdump on
# the router. These are not host state changes and would otherwise flood
# diffs.jsonl (and, once a defender mutating command lands, everything within
# ATTR_DELTA gets defender-attributed). postgres itself is KEPT visible
# (real DB kill evidence); only its recycled flap is folded.
INSTRUMENT_RECYCLE_COMMS = {
    "bash", "ps", "ss", "netstat", "su", "psql", "postgres", "tr", "rm",
    "curl", "nc", "tcpdump", "sleep", "find", "xargs", "sha256sum", "sort",
    "grep",
    # init process of every `docker exec` session: it exists ONLY while a
    # host-driven exec (prober / scripted_defender / ledger wrapper) runs, so
    # a ps snapshot straddling an exec emits process_gone/new noise that A1
    # then defender-attributes. FM7.1 control flake root cause (repeatability
    # run 2026-08-26: atk:process_gone runc:[2:INIT]).
    "runc:[2:INIT]",
}
INSTRUMENT_TRANSIENT_COMMS = INSTRUMENT_RECYCLE_COMMS - {"postgres"}


def _is_instrument(p, recycle_only=False):
    comm = p.get("comm", "")
    if recycle_only:
        return comm in INSTRUMENT_RECYCLE_COMMS
    return comm in INSTRUMENT_TRANSIENT_COMMS


def diff_processes(a, b, ts, run, host):
    out = []
    pa = {p["pid"]: p for p in (a.get("ps") or []) if isinstance(p, dict)}
    pb = {p["pid"]: p for p in (b.get("ps") or []) if isinstance(p, dict)}
    gone = [pa[p] for p in pa.keys() - pb.keys()]
    new = [pb[p] for p in pb.keys() - pa.keys()]
    gone_by_comm = {}
    for p in gone:
        gone_by_comm.setdefault(p.get("comm"), []).append(p)
    instrument_gone = set()
    for i, p in enumerate(gone):
        if _is_instrument(p):
            instrument_gone.add(id(p))
    for p in new:
        # same comm + same args re-appearing under a new pid = recycled
        match = None
        for g in gone_by_comm.get(p.get("comm"), []):
            if g.get("args") == p.get("args"):
                match = g
                break
        if match is not None:
            gone_by_comm[p.get("comm")].remove(match)
            gone.remove(match)
            if not _is_instrument(p, recycle_only=True):
                out.append(_rec(ts, run, host, "process_recycled",
                                {"comm": p.get("comm"), "args": p.get("args"),
                                 "old_pid": match.get("pid"),
                                 "new_pid": p.get("pid")}))
        else:
            if not _is_instrument(p):
                out.append(_rec(ts, run, host, "process_new",
                                {"comm": p.get("comm"), "args": p.get("args"),
                                 "pid": p.get("pid")}))
    for p in gone:
        if id(p) not in instrument_gone:
            out.append(_rec(ts, run, host, "process_gone",
                            {"comm": p.get("comm"), "args": p.get("args"),
                             "pid": p.get("pid")}))
    return out


def diff_listeners(a, b, ts, run, host):
    out = []
    # listener set = distinct listen ports from ps-independent ss snapshot
    la = set(a.get("ports_ext") or [])
    lb = set(b.get("ports_ext") or [])
    for port in sorted(la - lb):
        out.append(_rec(ts, run, host, "listener_gone", {"port": port}))
    for port in sorted(lb - la):
        out.append(_rec(ts, run, host, "listener_new", {"port": port}))
    if la != lb:
        out.append(_rec(ts, run, host, "port_ext_change",
                        {"before": sorted(la), "after": sorted(lb)}))
    return out


def diff_iptables(a, b, ts, run, host):
    out = []
    ra = set((a.get("iptables_text") or "").splitlines())
    rb = set((b.get("iptables_text") or "").splitlines())
    for line in sorted(rb - ra):
        detail = {"rule": line}
        out.append(_rec(ts, run, host, "rule_added", detail))
        if _is_weakening(line):
            out.append(_rec(ts, run, host, "rule_weakened", detail))
    for line in sorted(ra - rb):
        out.append(_rec(ts, run, host, "rule_removed", {"rule": line}))
    return out


def _is_weakening(rule):
    l = rule.lower()
    return ("accept" in l) or ("-j drop" not in l and "reject" in l) or False


def _parse_manifest(text):
    """'sha  /path' lines -> {path: sha}."""
    out = {}
    for line in (text or "").splitlines():
        parts = line.split(None, 1)
        if len(parts) == 2 and len(parts[0]) == 64:
            out[parts[1].strip()] = parts[0]
    return out


def diff_files(a, b, ts, run, host):
    out = []
    fa = _parse_manifest(a.get("files_manifest"))
    fb = _parse_manifest(b.get("files_manifest"))
    for path in sorted(fa.keys() - fb.keys()):
        out.append(_rec(ts, run, host, "file_gone", {"path": path}))
    for path in sorted(fb.keys() - fa.keys()):
        out.append(_rec(ts, run, host, "file_new",
                        {"path": path, "sha256": fb[path]}))
    for path in sorted(fa.keys() & fb.keys()):
        if fa[path] != fb[path]:
            out.append(_rec(ts, run, host, "file_changed",
                            {"path": path, "sha256_before": fa[path],
                             "sha256_after": fb[path]}))
    return out


def diff_db(a, b, ts, run, host):
    if a.get("db_tables_sha") and b.get("db_tables_sha") \
            and a["db_tables_sha"] != b["db_tables_sha"]:
        return [_rec(ts, run, host, "db_changed",
                     {"sha256_before": a["db_tables_sha"],
                      "sha256_after": b["db_tables_sha"]})]
    return []


def diff_capture(a, b, ts, run, host):
    if a.get("capture_ok") is True and b.get("capture_ok") is False:
        return [_rec(ts, run, host, "capture_down", {})]
    return []


def diff(a, b, unit_id=None):
    """Diff two probe records for the same host -> list of diff records."""
    assert a.get("host") == b.get("host"), "diff() needs same-host probes"
    ts = b.get("ts_completed") or b.get("ts") or common.now()
    run = b.get("run")
    host = b.get("host")
    out = []
    for fn in (diff_processes, diff_listeners, diff_iptables, diff_files,
               diff_db, diff_capture):
        out.extend(fn(a, b, ts, run, host))
    if unit_id is not None:
        for r in out:
            r["unit_id"] = unit_id
    return out


def diffs_path(archive):
    return os.path.join(archive, DIFFS_PATH)


def emit(archive, diff_records):
    for r in diff_records:
        common.append_jsonl(diffs_path(archive), r)
    return diff_records
