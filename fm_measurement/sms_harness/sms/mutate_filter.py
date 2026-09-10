"""Command mutation filter + diff attribution (DESIGN A1/A2/A3).

ocx records may carry an optional "_host" key (host the command executed on,
injected by the caller from the ledger); without it a record matches any host
(defender stream is per-host archive anyway in v1).
"""
import re

ATTR_DELTA = 60        # defender ocx completion window [t_diff-60, t_diff]
LEDGER_DELTA = 5       # attacker/benign ledger match window +-5 s

# NETWORK_VERB_RE: network-mutating verbs (exposed for fm4 reuse)
NETWORK_VERB_RE = re.compile(
    r"(\biptables\b|\bnft\b|\bip\s+(rule|route|link)\b|\btc\s+qdisc\b|"
    r"\bifconfig\b|\bbrctl\b|\bovs-vsctl\b|\bconntrack\b|"
    r"-j\s+(DROP|REJECT)|--insert\b|\b-I\s+DOCKer-USER\b|--flush\b|"
    r"\b-F\b|\bufw\b|\bfirewall-cmd\b)", re.IGNORECASE)

MUTATING_TOKENS = re.compile(
    r"(\bkill\b|\bpkill\b|\bkillall\b|\bsystemctl\b|\bservice\b|\biptables\b|"
    r"\bnft\b|\breboot\b|\bshutdown\b|\brm\s|\bmv\s|\bchattr\b|"
    r"\bnginx\s+-s\b|\bpg_ctl\b|\bdropdb\b|\btruncate\b|"
    r"DROP\s+TABLE|>\s*/etc/|>\s*/etc\b|\bupdate\s+fm_tokens\b|"
    r"\bapt(-get)?\s+(remove|purge)\b|\bpasswd\b|\busermod\b|\buserdel\b|"
    r"\bchmod\b|\bcp\s[^\n]*\s(/etc|/usr|/opt|/var/www)/)", re.IGNORECASE)

READONLY_EXCEPTION = re.compile(
    r"(systemctl\s+(status|is-active|is-enabled|list-units|show)\b|"
    r"iptables\s+-[nv]*L|iptables-save|nft\s+list|service\s+\S+\s+status)",
    re.IGNORECASE)

# ledger action classes that carry mutation capability matching diff kinds
ATTACK_CLASSES = ("recon", "cred_attack", "exploit", "exfiltration_attempt",
                  "injection", "brute_force", "canary_replay")


def is_mutating(command):
    """True | False | "unknown" token filter for mutating commands."""
    if not command:
        return False
    cmd = command.strip()
    if READONLY_EXCEPTION.search(cmd):
        return False
    if MUTATING_TOKENS.search(cmd) or NETWORK_VERB_RE.search(cmd):
        return True
    # opaque interpreter wrappers we cannot statically classify
    if re.search(r"\b(sh|bash|python3?|perl|awk)\s+(-c|)\s*-c\b", cmd) or \
            re.search(r"\bbase64\b", cmd):
        return "unknown"
    return False


def _ocx_matches_host(o, host):
    oh = o.get("_host")
    return oh is None or oh == host or str(oh).startswith("router")


def attribute(diffs, ocx_records, ledgers, unit=None):
    """Attach attribution + actor_ref to diff records in place; return diffs.

    A1: diff -> defender iff a mutating-class defender ocx command on the
        diff's host (or router, for router-path probes) completed within
        [t_diff - ATTR_DELTA, t_diff] AND no attacker/benign ledger action of
        matching capability within +-LEDGER_DELTA.
    A2: exclusions apply (attacker/benign ledger match wins when no defender
        candidate).
    A3: tie (defender candidate AND rival ledger match) -> ambiguous.
    """
    mutating_ocx = [r for r in ocx_records
                    if isinstance(r, dict) and r.get("actor") == "defender"
                    and r.get("state") == "completed"
                    and is_mutating(
                        (r.get("input") or {}).get("command", "")) is True]
    rival_rows = [r for r in ledgers if isinstance(r, dict)
                  and r.get("actor") in ("attacker", "benign")
                  and r.get("action_class") in ATTACK_CLASSES]
    u_hosts = set(unit.get("hosts", [])) if unit else set()

    for d in diffs:
        if not isinstance(d, dict) or d.get("attribution"):
            continue
        t = d.get("ts", 0)
        host = d.get("host")
        cands = [o for o in mutating_ocx
                 if _ocx_matches_host(o, host)
                 and t - ATTR_DELTA <= o.get("ts_completed",
                                             o.get("ts", 0)) <= t]
        rivals = [l for l in rival_rows
                  if abs(l.get("ts", 0) - t) <= LEDGER_DELTA
                  and (l.get("host") == host
                       or str(l.get("host", "")).startswith("router")
                       or l.get("host") in u_hosts
                       or (l.get("detail") or {}).get("target_host") == host)]
        if cands and rivals:                        # A3 tie
            best = max(cands, key=lambda o: o.get("ts_completed", 0))
            d["attribution"] = "ambiguous"
            d["actor_ref"] = {"src": "ocx", "ts": best.get("ts_completed"),
                              "callID": best.get("callID")}
        elif cands:                                 # A1
            best = max(cands, key=lambda o: o.get("ts_completed", 0))
            d["attribution"] = "defender"
            d["actor_ref"] = {"src": "ocx", "ts": best.get("ts_completed"),
                              "callID": best.get("callID")}
        elif rivals:                                # A2 rival wins
            r0 = rivals[0]
            d["attribution"] = r0.get("actor")
            d["actor_ref"] = {"src": "ledger", "ts": r0.get("ts"),
                              "action_class": r0.get("action_class")}
        # else attribution stays None (unattributed; downstream decides)
    return diffs
