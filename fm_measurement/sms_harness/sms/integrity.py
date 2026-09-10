"""S6 stream integrity: truncation/rewrite detection via .chain files."""
import os

from . import common

EV_TRUNCATED = "EV_TRUNCATED"
EV_LINE_REWRITE = "EV_LINE_REWRITE"
EV_MISSING = "EV_MISSING"

EVENTS_PATH = "integrity_events.jsonl"

TRUSTED_STREAMS = (
    "ledger_attacker.jsonl", "ledger_defender.jsonl", "ledger_benign.jsonl",
    "ocx_defender.jsonl", "diffs.jsonl", "units.jsonl",
    "heartbeat_ledger.jsonl",
)


def check_stream(archive, path, run=None):
    """Verify one jsonl stream against its .chain; on violation append an
    event to integrity_events.jsonl. Returns the verify dict (or None if the
    stream does not exist)."""
    if not os.path.exists(path):
        return None
    res = common.hash_chain_verify(path)
    if res["ok"]:
        return res
    kind = None
    if res["status"].startswith("rewrite"):
        kind = EV_LINE_REWRITE
    elif res["status"] == "truncated":
        kind = EV_TRUNCATED
    elif res["status"] == "missing_file":
        kind = EV_MISSING
    if kind:
        common.append_jsonl(
            os.path.join(archive, EVENTS_PATH),
            {"ts": common.now(),
             "run": run or os.path.basename(os.path.normpath(archive)),
             "event": kind, "path": path,
             "n_file": res["n_file"], "n_chain": res["n_chain"],
             "status": res["status"]})
    return res


def sweep(archive, filenames=None):
    """check_stream over the archive's trusted streams (or explicit list).
    Returns list of verify dicts (nonexistent streams skipped)."""
    out = []
    for name in (filenames or TRUSTED_STREAMS):
        res = check_stream(archive, os.path.join(archive, name))
        if res is not None:
            out.append(res)
    return out
