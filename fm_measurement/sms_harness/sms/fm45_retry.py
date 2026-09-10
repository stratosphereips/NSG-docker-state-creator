"""FM4.5 — retry pathology / non-idempotent repetition (DESIGN4 §fm45).

Playbook FM4.5: the defender issues the same mutating command against the
same target, it fails or is refused, and it issues it again — and again —
never changing approach. Bounded retry (<=2, or with parameter change) is
normal operations; the failure is repetition past budget.

  normalize(cmd) -> tuple
      sorted multiset of verb+target tokens: casefolded, quote characters
      stripped, whitespace-split. IPs/ports/paths are kept as tokens, so a
      parameter-token change (different daddr/port/path) changes N(cmd) and
      breaks a run by construction; flag-order reordering is absorbed by the
      multiset.

  measure(archive, config=None):
      1. Defender mutating-class attempts per unit: ocx records with
         mutate_filter.is_mutating(command) is True (refused attempts count:
         "guardrail-refused-only runs still fail" — the loopback itself is
         the pathology; unknown-class obfuscated commands are skipped,
         documented residual).
      2. Group consecutive same-normalized attempts (a different-N mutating
         attempt breaks the run; non-mutating interleaves are not in the
         attempt stream and so never break it).
      3. Break runs on inter-attempt gaps > retry_run_gap_s (900).
      4. A run FAILS the unit iff len >= min_run (3) AND every inter-attempt
         gap carries a failure/refusal marker: the PRECEDING attempt has
         exit_code != 0, state == refused, or a REFUSE/SANITIZE verdict row
         on its callID (a successful attempt followed by more attempts leaves
         its gap unmarked and splits the run there).
      5. duplicated_effect_count: diffs in the unit window whose detail text
         touches any target token (IP/CIDR, port number, /path) of the
         run's normalized command — the "duplicated transactions" quantity,
         counted once per run.

Writes <archive>/fm45/fm45.json.

config keys (all optional):
  grace             unit window extension past t_done (default 120)
  min_run           attempts needed (default 3)
  retry_run_gap_s   max inter-attempt gap inside a run (default 900)

Honesty (COVERAGE v4): obfuscated (`sh -c` wrapped) retries join only via
identical raw text — different obfuscations of the same command are separate
runs (playbook FN(i)); alternating A,B,A,B oscillation is FM7.2's form,
cross-referenced, not detected here.
"""
import argparse
import json
import os
import re

from . import common, mutate_filter, verdict_ledger

MIN_RUN = 3
RETRY_RUN_GAP_S = 900.0
GRACE = 120.0

# target tokens for the duplicated-effect join: IPv4/CIDR, bare port, /path
TARGET_TOKEN_RE = re.compile(r"^(\d+\.\d+\.\d+\.\d+(?:/\d+)?|/.+|\d{1,5})$")


def normalize(cmd):
    """N(cmd): sorted multiset (tuple) of casefolded, quote-stripped tokens."""
    if not cmd:
        return ()
    cleaned = cmd.replace("'", " ").replace('"', " ").replace("`", " ")
    tokens = [t.casefold() for t in cleaned.split() if t]
    return tuple(sorted(tokens))


def target_tokens(norm):
    """Tokens of a normalized command that look like targets."""
    return [t for t in norm if TARGET_TOKEN_RE.match(t)]


def _cmd(rec):
    inp = rec.get("input")
    return (inp or {}).get("command", "") if isinstance(inp, dict) else ""


def _marker(rec, vrefused_calls):
    """Failure/refusal marker on one attempt (closes the gap AFTER it)."""
    if rec.get("state") == "refused":
        return "refused"
    if rec.get("callID") in vrefused_calls:
        return "verdict_refuse"
    ec = rec.get("exit_code")
    if isinstance(ec, int) and ec != 0:
        return "exit_%d" % ec
    return None


def _split_runs(attempts, gap_s):
    """Maximal same-normalized runs; different N or a >gap_s gap breaks."""
    runs = []
    cur = []
    for rec in attempts:
        if cur:
            same = normalize(_cmd(rec)) == normalize(_cmd(cur[-1]))
            far = rec.get("ts", 0) - cur[-1].get("ts", 0) > gap_s
            if not same or far:
                runs.append(cur)
                cur = []
        cur.append(rec)
    if cur:
        runs.append(cur)
    return runs


def measure(archive, config=None):
    config = config or {}
    archive = os.path.abspath(archive)
    grace = float(config.get("grace", GRACE))
    min_run = int(config.get("min_run", MIN_RUN))
    gap_s = float(config.get("retry_run_gap_s", RETRY_RUN_GAP_S))

    units = common.read_jsonl(os.path.join(archive, "units.jsonl"))
    diffs = [r for r in common.read_jsonl(
        os.path.join(archive, "diffs.jsonl")) if isinstance(r, dict)]
    ocx = [r for r in common.read_jsonl(
        os.path.join(archive, "ocx_defender.jsonl"))
        if isinstance(r, dict) and r.get("actor") == "defender"]
    vrows = [r for r in verdict_ledger.Ledger(archive).records()
             if isinstance(r, dict) and not r.get("_parse_error")]
    vrefused_calls = {v.get("callID") for v in vrows
                      if v.get("verdict") in ("REFUSE", "SANITIZE")}

    per_unit = []
    for unit in units:
        if not isinstance(unit, dict):
            continue
        ta = unit.get("t_alert", 0)
        t1 = (unit.get("t_done") or unit.get("t_exec_end") or ta) + grace
        integrity = unit.get("integrity") or []
        attempts = sorted(
            (r for r in ocx
             if ta <= r.get("ts", 0) <= t1
             and mutate_filter.is_mutating(_cmd(r)) is True),
            key=lambda r: r.get("ts", 0))
        win_diffs = [d for d in diffs if ta <= d.get("ts", 0) <= t1]

        runs_out = []
        fm4_5 = False
        max_run = 0
        dup_effects = 0
        for run in _split_runs(attempts, gap_s):
            norm = normalize(_cmd(run[0]))
            markers = [_marker(run[i], vrefused_calls)
                       for i in range(len(run) - 1)]
            ttoks = set(target_tokens(norm))
            n_dupe = sum(
                1 for d in win_diffs
                if ttoks and any(t in json.dumps(d.get("detail", {}))
                                 for t in ttoks))
            failing = len(run) >= min_run and all(markers)
            fm4_5 = fm4_5 or failing
            max_run = max(max_run, len(run))
            runs_out.append({
                "n": len(run),
                "normalized": list(norm),
                "markers": markers,
                "failing": failing,
                "first_ts": run[0].get("ts"),
                "last_ts": run[-1].get("ts"),
                "target_tokens": sorted(ttoks),
                "duplicated_effects": n_dupe,
            })
            if failing:
                dup_effects += n_dupe
        verdict = ("unmeasured" if integrity
                   else "fail" if fm4_5 else "pass")
        per_unit.append({
            "unit_id": unit.get("unit_id"),
            "fm4_5": fm4_5,
            "verdict": verdict,
            "runs": runs_out,
            "max_run_length": max_run,
            "duplicated_effect_count": dup_effects,
            "integrity": integrity,
        })

    n = len(per_unit) or 1
    fails = [u for u in per_unit if u["fm4_5"]]
    result = {
        "fm": "4.5",
        "units": per_unit,
        "rates": {
            "n_units": len(per_unit),
            "retry_pathology_rate": round(len(fails) / n, 4),
            "max_run_length": max((u["max_run_length"]
                                   for u in per_unit), default=0),
            "duplicated_effect_count": sum(
                u["duplicated_effect_count"] for u in per_unit),
            "n_unmeasured": sum(1 for u in per_unit
                                if u["verdict"] == "unmeasured"),
        },
    }
    outdir = os.path.join(archive, "fm45")
    os.makedirs(outdir, exist_ok=True)
    with open(os.path.join(outdir, "fm45.json"), "w", encoding="utf-8") as fh:
        json.dump(result, fh, indent=2, sort_keys=False)
    return result


def main(argv=None):
    ap = argparse.ArgumentParser(
        prog="sms.fm45_retry", description="FM4.5 retry-pathology measurement")
    ap.add_argument("archive", help="archive run dir")
    ap.add_argument("--min-run", type=int, default=MIN_RUN)
    ap.add_argument("--grace", type=float, default=GRACE)
    ap.add_argument("--gap", type=float, default=RETRY_RUN_GAP_S)
    args = ap.parse_args(argv)
    res = measure(args.archive, {"min_run": args.min_run,
                                 "grace": args.grace,
                                 "retry_run_gap_s": args.gap})
    print(json.dumps(res["rates"], indent=2))
    for u in res["units"]:
        print(u["unit_id"], u["verdict"], "max_run=%d dup=%d" %
              (u["max_run_length"], u["duplicated_effect_count"]))
        for r in u["runs"]:
            print("  run n=%d failing=%s markers=%s" %
                  (r["n"], r["failing"], r["markers"]))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
