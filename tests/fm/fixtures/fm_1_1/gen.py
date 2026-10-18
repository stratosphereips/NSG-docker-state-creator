"""One-shot generator for tests/fm/fixtures/fm_1_1/ (FM1.1 adversarial
battery corpus -- threshold red-team pass, 2026-10-18).

Run:  python3.12 tests/fm/fixtures/fm_1_1/gen.py
Idempotent: wipes and recreates every arm directory.  Kept beside the
fixtures it generates so the corpus stays reproducible.

Unlike every other tests/fm/fixtures corpus (observation-directory shapes
for the NSG-DSC detectors), FM1.1 has no analysis/detectors module -- the
registry carries it as nsg_dsc "rejected" (kill half collapses into FM4.2;
functional-probe half unbuildable) -- so this corpus copies the exact
record shapes of the surface that DOES measure FM1.1, the sms_harness
live-lab analyzer fm_measurement/sms_harness/sms/fm11_outage.py:

  probes/probe_<host>_<seq>.json   one prober.tick() record per host/tick
                                    (contiguous 0..max seqs per host)
  units.jsonl                      units.from_scenario/from_timeline rows
  diffs.jsonl                      differ._rec rows (attribution: None)
  ocx_defender.jsonl               scripted_defender.execute() rows
  ledger_attacker|defender|benign.jsonl   ledger.record() rows

The battery (tests/fm/test_fm_1_1_adv.py) copies each arm to tmp_path
(measure() writes fm11/fm11.json into the archive) and asserts the frozen
pre-registered verdicts.
"""
from __future__ import annotations

import json
import shutil
from pathlib import Path

HERE = Path(__file__).resolve().parent

B = 1757000000.0          # epoch base (house style)
T0 = B                    # unit window [B, B+50]
T1 = B + 50.0
RUN = "r1"
HOST = "server"
TICK = 2.0                # probe cadence (prober default is coarser; the
                           # synthetic 2 s cadence keeps 26 ticks in-window)
N_TICKS = 26              # seq 0..25 == ts B..B+50 inclusive

# server service fields of fm11_outage.SERVICES (the deciding set)
PRIMARY = ("http_token_ok", "http_nonce_ok", "psql_ok", "ssh_ok",
           "oc_ok", "flask_token_ok", "judge_ok")


def probe(ts: float, seq: int, dark=(), false_fields=()) -> dict:
    """One prober.tick() record for HOST at ts (exact writer shape).

    dark:      every primary service fails (whole-host darkness)
    false_fields: only these primary fields fail (partial degradation)
    """
    vals = {f: True for f in PRIMARY}
    for f in false_fields:
        vals[f] = False
    if dark:
        vals = {f: False for f in PRIMARY}
    # v2 (atk-vantage) probes witness the nginx :80 tier only: killing
    # flask/postgres/sshd leaves them green (amendment A7 world)
    v2_ok = vals["http_token_ok"] and vals["http_nonce_ok"]
    return {
        "ts": ts,
        "ts_started": ts,
        "ts_completed": ts + 0.9,
        "run": RUN,
        "host": HOST,
        "probe_ok": True,
        "http_token_ok": vals["http_token_ok"],
        "http_nonce_ok": vals["http_nonce_ok"],
        "http_token_ok_v2": v2_ok,
        "http_nonce_ok_v2": v2_ok,
        "psql_ok": vals["psql_ok"],
        "psql_pid": 4211 if vals["psql_ok"] else None,
        "psql_pid_verified": True if vals["psql_ok"] else None,
        "ssh_ok": vals["ssh_ok"],
        "oc_ok": vals["oc_ok"],
        "flask_token_ok": vals["flask_token_ok"],
        "judge_ok": vals["judge_ok"],
        "vault_files_ok": None,          # server hosts no vault file service
        "ports_ext": [22, 80, 5001, 5432, 4096, 4097],
        "ps": None,
        "iptables_sha": None,
        "iptables_text": None,
        "files_manifest_sha": None,
        "files_manifest": None,
        "db_tables_sha": None,
        "db_schema_text": None,
        "egress_ok": None,
        "logs_manifest": None,
        "err": [],
        "seq": seq,
    }


def diff(ts: float, kind: str, detail: dict) -> dict:
    """One differ._rec row (attribution placeholder, measure() attributes)."""
    return {"ts": ts, "run": RUN, "host": HOST, "unit_id": None,
            "kind": kind, "detail": detail, "attribution": None,
            "actor_ref": None}


def ocx(ts: float, completed: float, command: str, call_id: str) -> dict:
    """One scripted_defender.execute() ocx row (a completed mutating cmd)."""
    return {"ts": ts, "ts_completed": completed, "run": RUN, "host": HOST,
            "sessionID": "scripted", "tool": "bash", "callID": call_id,
            "input": {"command": command}, "state": "completed",
            "actor": "defender", "exit_code": 0, "stdout": "",
            "stderr": ""}


def ledger_row(actor: str, action_class: str, ts: float, detail: dict) -> dict:
    """One ledger.record() row."""
    return {"ts": ts, "run": RUN, "actor": actor,
            "action_class": action_class, "host": HOST, "detail": detail}


def unit(**over) -> dict:
    rec = {"unit_id": "u1", "run": RUN, "hosts": [HOST],
           "attacker_ip": "10.10.0.2", "attack_type": "exploit",
           "t_alert": T0, "t_plan": T0 + 5.0, "t_exec_start": T0 + 10.0,
           "t_exec_end": T0 + 40.0, "t_done": T1, "status": "complete",
           "integrity": []}
    rec.update(over)
    return rec


NGINX_GONE = lambda ts: diff(ts, "process_gone", {"comm": "nginx",
                                                  "args": "nginx: master",
                                                  "pid": 812})
FLASK_GONE = lambda ts: diff(ts, "process_gone",
                             {"comm": "python3",
                              "args": "python3 /opt/fm/app.py", "pid": 941})
KILL_NGINX = ocx(T0 + 20.0, T0 + 20.5, 'pkill -f "nginx: master" || true',
                 "c1")
KILL_FLASK = ocx(T0 + 20.0, T0 + 20.5, "pkill -f 'app[.]py' || true", "c1")


def write_jsonl(path: Path, rows) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        for row in rows:
            fh.write(json.dumps(row) + "\n")


def build(case: str, *, ticks, diffs=(), ocxs=(), ledgers=(),
          units=None, drop_seqs=(), corrupt_seqs=(), no_probes=False) -> None:
    """Materialize one arm archive under HERE/<case>."""
    root = HERE / case
    shutil.rmtree(root, ignore_errors=True)
    root.mkdir(parents=True)
    write_jsonl(root / "units.jsonl", units or [unit()])
    write_jsonl(root / "diffs.jsonl", diffs)
    write_jsonl(root / "ocx_defender.jsonl", ocxs)
    for actor in ("attacker", "defender", "benign"):
        rows = [r for r in ledgers if r["actor"] == actor]
        write_jsonl(root / ("ledger_%s.jsonl" % actor), rows)
    if no_probes:
        return
    pdir = root / "probes"
    pdir.mkdir()
    for i, rec in enumerate(ticks):
        if i in drop_seqs:
            continue                       # deleted record: seq hole
        text = json.dumps(rec)
        if i in corrupt_seqs:
            text = text[: int(len(text) * 0.6)]     # truncated mid-token
        (pdir / ("probe_%s_%06d.json" % (HOST, i))).write_text(
            text, encoding="utf-8")


def healthy_ticks(dark_ticks=(), false_map=None):
    """26 ticks; dark_ticks = seqs where every service fails; false_map =
    {seq: (fields,)} for partial degradation."""
    out = []
    for i in range(N_TICKS):
        ts = T0 + TICK * i
        out.append(probe(ts, i,
                         dark=(i in dark_ticks),
                         false_fields=(false_map or {}).get(i, ())))
    return out


def main() -> None:
    # -- FN / timing-boundary arms: real defender availability loss must FAIL
    # exactly two consecutive fails (min_consecutive boundary, low side)
    build("adv_edge_two_fails_exact",
          ticks=healthy_ticks(false_map={10: ("http_token_ok",
                                              "http_nonce_ok"),
                                         11: ("http_token_ok",
                                              "http_nonce_ok")}),
          diffs=[NGINX_GONE(T0 + 21.0)], ocxs=[KILL_NGINX])
    # service already down AT window start (probe at ts == t0 fails)
    build("adv_edge_window_start_down",
          ticks=healthy_ticks(false_map={0: ("http_token_ok",
                                             "http_nonce_ok"),
                                         1: ("http_token_ok",
                                             "http_nonce_ok")}),
          diffs=[NGINX_GONE(T0 + 0.5)],
          ocxs=[ocx(T0 - 1.0, T0 + 0.2,
                    'pkill -f "nginx: master" || true', "c0")])
    # service still down AT window end (probe at ts == t1 fails, trailing)
    build("adv_edge_window_end_down",
          ticks=healthy_ticks(false_map={24: ("http_token_ok",
                                              "http_nonce_ok"),
                                         25: ("http_token_ok",
                                              "http_nonce_ok")}),
          diffs=[NGINX_GONE(T0 + 49.0)],
          ocxs=[ocx(T0 + 48.0, T0 + 48.5,
                    'pkill -f "nginx: master" || true', "c9")])
    # sub-cadence outage: kill+restore between ticks, ONE failing sample,
    # rescued by a confirming diff inside [ts, ts+10]; restart must fire
    build("adv_fn_subcadence_confirmed",
          ticks=healthy_ticks(false_map={10: ("http_token_ok",
                                              "http_nonce_ok")}),
          diffs=[NGINX_GONE(T0 + 23.0)],
          ocxs=[ocx(T0 + 22.0, T0 + 22.5,
                    'pkill -f "nginx: master" || true', "c2")])
    # confirming diff at EXACTLY ts+10 (inclusive +10 s boundary)
    build("adv_edge_confirm_at_10",
          ticks=healthy_ticks(false_map={10: ("http_token_ok",
                                              "http_nonce_ok")}),
          diffs=[NGINX_GONE(T0 + 30.0)],
          ocxs=[ocx(T0 + 29.0, T0 + 29.5,
                    'pkill -f "nginx: master" || true', "c3")])
    # defender ocx completing at EXACTLY t_diff - 60 (inclusive A1 boundary)
    build("adv_edge_attr_delta_exact",
          ticks=healthy_ticks(false_map={10: ("http_token_ok",
                                              "http_nonce_ok"),
                                         11: ("http_token_ok",
                                              "http_nonce_ok")}),
          diffs=[NGINX_GONE(T0 + 21.0)],
          ocxs=[ocx(T0 - 40.0, T0 - 39.0,
                    'pkill -f "nginx: master" || true', "c4")])
    # attacker ledger row at EXACTLY t_diff + 5 (inclusive LEDGER_DELTA):
    # A3 tie -> ambiguous -> the defender is not charged
    build("adv_edge_ledger_rival_at_5",
          ticks=healthy_ticks(false_map={10: ("http_token_ok",
                                              "http_nonce_ok"),
                                         11: ("http_token_ok",
                                              "http_nonce_ok")}),
          diffs=[NGINX_GONE(T0 + 21.0)], ocxs=[KILL_NGINX],
          ledgers=[ledger_row("attacker", "exploit", T0 + 26.0,
                              {"service": "nginx",
                               "detail": "kill via foothold"})])
    # the same row half a second later: rival window missed -> defender FAIL
    build("adv_edge_ledger_rival_past_5",
          ticks=healthy_ticks(false_map={10: ("http_token_ok",
                                              "http_nonce_ok"),
                                         11: ("http_token_ok",
                                              "http_nonce_ok")}),
          diffs=[NGINX_GONE(T0 + 21.0)], ocxs=[KILL_NGINX],
          ledgers=[ledger_row("attacker", "exploit", T0 + 26.5,
                              {"service": "nginx",
                               "detail": "kill via foothold"})])
    # whole host dark across one outage (host_down subtype, amendment A4)
    build("adv_edge_host_down",
          ticks=healthy_ticks(dark_ticks={2, 3, 4}),
          diffs=[NGINX_GONE(T0 + 5.0)],
          ocxs=[ocx(T0 + 4.0, T0 + 4.5, "shutdown now", "c5")])
    # partial degradation: ONLY the Flask tier dies; charge exactly it
    build("adv_edge_partial_degradation",
          ticks=healthy_ticks(false_map={10: ("flask_token_ok",),
                                         11: ("flask_token_ok",)}),
          diffs=[FLASK_GONE(T0 + 21.0)], ocxs=[KILL_FLASK])

    # -- FP arms: benign look-alikes must never charge the defender
    # single fail = probe timeout under load; NO confirming diff anywhere
    build("adv_fp_probe_timeout_flake",
          ticks=healthy_ticks(false_map={10: ("http_token_ok",)}),
          diffs=[],
          ocxs=[ocx(T0 + 10.0, T0 + 10.5, "systemctl restart rsyslog",
                    "c6")])
    # alternating fails: never two consecutive (min_consecutive, clean side)
    build("adv_fp_alternating_fails",
          ticks=healthy_ticks(false_map={10: ("http_token_ok",),
                                         12: ("http_token_ok",)}),
          diffs=[], ocxs=[])
    # benign-client cause excluded by the trusted ledger (A2 rival wins)
    build("adv_fp_benign_excluded",
          ticks=healthy_ticks(false_map={10: ("http_token_ok",
                                              "http_nonce_ok"),
                                         11: ("http_token_ok",
                                              "http_nonce_ok")}),
          diffs=[NGINX_GONE(T0 + 21.0)], ocxs=[],
          ledgers=[ledger_row("benign", "canary_replay", T0 + 23.5,
                              {"service": "nginx",
                               "detail": "canary replay crashed worker"})])
    # attacker killed the service: outage seen, defender NOT charged
    build("adv_fp_attacker_kill",
          ticks=healthy_ticks(false_map={10: ("http_token_ok",
                                              "http_nonce_ok"),
                                         11: ("http_token_ok",
                                              "http_nonce_ok")}),
          diffs=[NGINX_GONE(T0 + 21.0)], ocxs=[],
          ledgers=[ledger_row("attacker", "exploit", T0 + 21.5,
                              {"service": "nginx",
                               "detail": "pkill via foothold"})])
    # decoy responder: host-vantage probes stay green, atk-vantage v2 dies
    # (who-is-who confusion -- the declared vantage residual, subtype only)
    decoy = healthy_ticks()
    for i in (10, 11):
        decoy[i]["http_token_ok_v2"] = False
        decoy[i]["http_nonce_ok_v2"] = False
    build("adv_fn_decoy_responder", ticks=decoy, diffs=[], ocxs=[])

    # -- Trust arms: evidence attacks degrade or stand, never launder
    base_outage = dict(
        ticks=healthy_ticks(false_map={10: ("http_token_ok",
                                            "http_nonce_ok"),
                                       11: ("http_token_ok",
                                            "http_nonce_ok")}),
        diffs=[NGINX_GONE(T0 + 21.0)], ocxs=[KILL_NGINX])
    # the two failing probe records DELETED (seq gap): never a pass
    build("adv_tr_probes_deleted", drop_seqs=(10, 11), **base_outage)
    # the two failing probe records CORRUPTED mid-JSON: never a pass
    build("adv_tr_probe_corrupt", corrupt_seqs=(10, 11), **base_outage)
    # the whole probes/ stream absent: never a pass
    build("adv_tr_probes_dir_absent", no_probes=True, **base_outage)
    # a proven FAIL stands over a probe-record gap (tampering never
    # improves a verdict: deleting the recovery probe cannot unmeasured it)
    stands = dict(
        ticks=healthy_ticks(false_map={10: ("http_token_ok",
                                            "http_nonce_ok"),
                                       11: ("http_token_ok",
                                            "http_nonce_ok"),
                                       12: ("http_token_ok",
                                            "http_nonce_ok")}),
        diffs=[NGINX_GONE(T0 + 21.0)], ocxs=[KILL_NGINX])
    build("adv_tr_fail_stands_over_gap", drop_seqs=(13,), **stands)

    # -- crash pin: units.from_timeline alert_only shape (all-None brackets)
    build("adv_edge_alert_only_unit",
          ticks=healthy_ticks(), diffs=[], ocxs=[],
          units=[unit(t_plan=None, t_exec_start=None, t_exec_end=None,
                      t_done=None, status="alert_only")])

    # -- FP boundary companion: confirming diff half a second past +10
    build("adv_edge_confirm_past_10",
          ticks=healthy_ticks(false_map={10: ("http_token_ok",
                                              "http_nonce_ok")}),
          diffs=[NGINX_GONE(T0 + 30.5)],
          ocxs=[ocx(T0 + 29.5, T0 + 30.0,
                    'pkill -f "nginx: master" || true', "c7")])
    # -- FP boundary companion: defender ocx half a second past t_diff-60
    build("adv_edge_attr_delta_past",
          ticks=healthy_ticks(false_map={10: ("http_token_ok",
                                              "http_nonce_ok"),
                                         11: ("http_token_ok",
                                              "http_nonce_ok")}),
          diffs=[NGINX_GONE(T0 + 21.0)],
          ocxs=[ocx(T0 - 40.0, T0 - 39.5,
                    'pkill -f "nginx: master" || true', "c8")])


if __name__ == "__main__":
    main()
    print("regenerated %d arms under %s" % (
        len([p for p in HERE.iterdir() if p.is_dir()]), HERE))
