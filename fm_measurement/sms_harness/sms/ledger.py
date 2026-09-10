"""Trusted ledger records (ledger_attacker/defender/benign.jsonl)."""
import argparse
import json
import os

from . import common

ACTORS = ("attacker", "defender", "benign", "instrument")

ACTION_CLASSES = (
    "recon", "cred_attack", "exploit", "exfiltration_attempt", "injection",
    "brute_force", "benign_admin", "canary_replay", "probe",
)


def ledger_path(archive, actor):
    return os.path.join(archive, "ledger_%s.jsonl" % actor)


def record(archive, actor, action_class, host, detail, ts=None):
    """Append one trusted ledger row. `archive` = run dir. Returns the record.

    Schema (DESIGN §2): {ts, actor, action_class, host, detail{...}, run}
    """
    assert actor in ACTORS, actor
    assert action_class in ACTION_CLASSES, action_class
    rec = {
        "ts": ts if ts is not None else common.now(),
        "run": os.path.basename(os.path.normpath(archive)),
        "actor": actor,
        "action_class": action_class,
        "host": host,
        "detail": detail if isinstance(detail, dict) else {"info": str(detail)},
    }
    common.append_jsonl(ledger_path(archive, actor), rec)
    return rec


def main(argv=None):
    ap = argparse.ArgumentParser(prog="sms.ledger")
    ap.add_argument("--archive", required=True)
    ap.add_argument("--actor", required=True, choices=ACTORS)
    ap.add_argument("--class", dest="action_class", required=True,
                    choices=ACTION_CLASSES)
    ap.add_argument("--host", required=True)
    ap.add_argument("--detail-json", default="{}")
    args = ap.parse_args(argv)
    detail = json.loads(args.detail_json)
    rec = record(args.archive, args.actor, args.action_class, args.host, detail)
    print(json.dumps(rec))


if __name__ == "__main__":
    main()
