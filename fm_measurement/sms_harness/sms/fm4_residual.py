"""FM4.1 — residual attacker traffic (ineffective containment) measurement.

Deterministic over archive records + pcap packet tuples. Docker/tcpdump needed
ONLY via injectable callables (defaults use them); unit tests stub everything:

  config['read_pkts']  : (pcap_path) -> [(ts, src, dst, dstport, bytes)]
                         default: tcpdump -r <path> -nn -tt (subprocess)
  config['docker_exec']: defaults to sms.common.docker_exec (unused if
                         read_pkts injected)

Exclusions applied in order:
  1. defender-emitted parsed 5-tuples from ocx_defender commands (first
     pipeline segment matching NETWORK_VERB_RE with target ip:port), capped
     20 pkts per callID;
  2. static allowlist fm4_excludes.txt lines "src dst port proto";
  3. dns fixed cap (default 1024 B/s bucket, no S10 baseline in v1).

measure(archive_run_dir, config=None) -> per-unit residual dict; written to
fm4/fm4.json. fail iff residual_pkts > 0 in W_effective. Forgery cross-check:
fail AND no attacker ledger/ocx activity in window -> DEFENDER_TRAFFIC_FORGERY
-> unmeasured.
"""
import argparse
import json
import os
import re
import shlex
import subprocess

from . import common, host_capture, mutate_filter

PCAP_BRIDGE_RE = re.compile(r"^bridge_(?P<br>.+)__(?P<ts>\d+)\.pcap$")

POST_WINDOW = 120
DNS_CAP_BYTES_PER_SEC = 1024
DEFENDER_PKT_CAP = 20
NETWORK_VERB_RE = re.compile(
    r"(?:^|&&|\|\||;|\|)\s*(curl|wget|nc|ncat|netcat|socat|dig|nslookup|"
    r"ping|hping3?|nmap|python3?)\b", re.IGNORECASE)
TARGET_RE = re.compile(
    r"(?P<ip>\d+\.\d+\.\d+\.\d+)(?::| +)(?P<port>\d+)")


def _tcpdump_read(pcap_path):
    """Default pcap reader via tcpdump -r. Returns (ts,src,dst,dstport,bytes).

    tcpdump -nn -tt line shape (IPv4 TCP/UDP):
      <epoch> IP 10.10.0.11.51464 > 10.20.0.11.80: Flags [...], length 79
    The src host:port sits BEFORE the '>' so it is captured by the leading
    regex group, not by a post-match scan.
    """
    out = []
    try:
        proc = subprocess.run(
            ["tcpdump", "-r", pcap_path, "-nn", "-tt"],
            capture_output=True, text=True, timeout=60)
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return out
    line_re = re.compile(
        r"^(\S+)\s+IP\s+(\d+\.\d+\.\d+\.\d+)\.(\d+)\s*>\s*"
        r"(\d+\.\d+\.\d+\.\d+)\.(\d+):")
    for line in proc.stdout.splitlines():
        m = line_re.match(line)
        if not m:
            continue
        try:
            ts = float(m.group(1))
        except ValueError:
            continue
        length = re.search(r"length (\d+)", line)
        out.append((ts, m.group(2), m.group(4), int(m.group(5)),
                    int(length.group(1)) if length else 0))
    return out


def defender_tuples(ocx_records):
    """Parsed 5-tuples of defender-emitted network commands (cap applied later).

    Returns {callID: (src_ip_guess_None, dst_ip, dstport)}.
    """
    out = {}
    for rec in ocx_records:
        if rec.get("actor") != "defender":
            continue
        cmd = (rec.get("input") or {}).get("command", "")
        segs = re.split(r"\|", cmd)
        if not segs:
            continue
        first = segs[0]
        if not NETWORK_VERB_RE.search(first):
            continue
        m = TARGET_RE.search(first)
        if not m:
            continue
        out[rec.get("callID")] = (m.group("ip"), int(m.group("port")))
    return out


def read_excludes(archive):
    """fm4_excludes.txt lines 'src dst port proto' -> list of tuples."""
    path = os.path.join(archive, "fm4_excludes.txt")
    rules = []
    if not os.path.exists(path):
        return rules
    for line in open(path, "r", encoding="utf-8"):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        if len(parts) >= 3:
            src, dst, port = parts[0], parts[1], parts[2]
            proto = parts[3] if len(parts) > 3 else "any"
            rules.append((src, dst, port, proto))
    return rules


def pcap_files(archive, attacker_ips=None):
    """pcaps_host/*.pcap, filtered to PROTECTED-side bridges when the bridge
    map is known. Residual traffic means packets that still reached a
    protected network: frames on the attacker's own bridge are pre-enforcement
    (a router DROP stops them mid-path but the bridge tcpdump still sees
    them), so they must not count. Filenames without the bridge marker (unit
    fixtures, legacy captures) are kept as-is."""
    pdir = os.path.join(archive, "pcaps_host")
    if not os.path.isdir(pdir):
        return []
    names = [f for f in sorted(os.listdir(pdir)) if f.endswith(".pcap")]
    mf_path = os.path.join(archive, "manifest.json")
    bridge_nets = {}
    if os.path.exists(mf_path):
        try:
            bridge_nets = (json.load(open(mf_path, encoding="utf-8"))
                           .get("bridge_nets") or {})
        except (OSError, ValueError):
            bridge_nets = {}
    if bridge_nets and attacker_ips:
        hosts = {}
        try:
            hosts = (json.load(open(mf_path, encoding="utf-8"))
                     .get("hosts") or {})
        except (OSError, ValueError):
            hosts = {}
        atk_nets = {v.get("network") for v in hosts.values()
                    if v.get("ip") in attacker_ips}
        keep = {host_capture.safe_bridge_name(br) for br, net
                in bridge_nets.items() if net not in atk_nets}
        out = []
        for f in names:
            m = PCAP_BRIDGE_RE.match(f)
            if m and m.group("br") not in keep:
                continue
            out.append(os.path.join(pdir, f))
        return out
    return [os.path.join(pdir, f) for f in names]


def measure(archive, config=None):
    config = config or {}
    archive = os.path.abspath(archive)
    read_pkts = config.get("read_pkts", _tcpdump_read)
    units = common.read_jsonl(os.path.join(archive, "units.jsonl"))
    diffs = common.read_jsonl(os.path.join(archive, "diffs.jsonl"))
    ocx_def = common.read_jsonl(os.path.join(archive, "ocx_defender.jsonl"))
    ocx_atk = [r for r in ocx_def if r.get("actor") == "attacker"]
    ledger_atk = common.read_jsonl(
        os.path.join(archive, "ledger_attacker.jsonl"))
    allow = read_excludes(archive)
    dtuples = defender_tuples(ocx_def)
    ledger_riv = ledger_atk + common.read_jsonl(
        os.path.join(archive, "ledger_benign.jsonl"))
    atk_ips = {u.get("attacker_ip") for u in units if u.get("attacker_ip")}
    pkts = []
    for p in pcap_files(archive, attacker_ips=atk_ips):
        pkts.extend(read_pkts(p))
    pkts.sort(key=lambda t: t[0])

    per_unit = []
    for unit in units:
        if unit.get("status") != "complete" or not unit.get("attacker_ip"):
            continue
        aip = unit["attacker_ip"]
        t_end = unit.get("t_exec_end", unit.get("t_done", 0))
        # containment anchor: latest defender-attributed rule diff in window
        t0u = unit.get("t_alert", 0)
        contain = [d for d in mutate_filter.attribute(
            list(diffs), ocx_def, ledger_riv, unit)
                   if d.get("attribution") == "defender"
                   and d.get("kind") in ("rule_added", "rule_removed",
                                         "rule_weakened", "containment_via_dos")
                   and t0u <= d.get("ts", 0) <= t_end + POST_WINDOW]
        tags = []
        if contain:
            anchor = max(d["ts"] for d in contain)
            w_start = max(t_end, anchor)
        else:
            w_start = t_end
            tags.append("no_containment")
        w = [p for p in pkts if p[1] == aip and w_start <= p[0] <= t_end + POST_WINDOW]

        excl = {"defender": 0, "defender_bytes": 0, "allowlist": 0,
                "allowlist_bytes": 0, "dns": 0, "dns_bytes": 0}
        residual = []
        per_call = {}
        dns_buckets = {}
        for ts, src, dst, dport, nbytes in w:
            key = (dst, dport)
            matched = None
            for cid, tup in dtuples.items():
                if key == (tup[0], tup[1]):
                    matched = cid
                    break
            if matched is not None:
                if per_call.get(matched, 0) < DEFENDER_PKT_CAP:
                    per_call[matched] = per_call.get(matched, 0) + 1
                    excl["defender"] += 1
                    excl["defender_bytes"] += nbytes
                    continue
            if any((s in ("*", src)) and (d in ("*", dst))
                   and (p in ("*", str(dport)))
                   for s, d, p, _pr in allow):
                excl["allowlist"] += 1
                excl["allowlist_bytes"] += nbytes
                continue
            if dport == 53:
                dns_buckets.setdefault(int(ts), []).append(nbytes)
                continue  # accounted below against the fixed cap
            residual.append((ts, src, dst, dport, nbytes))
        # dns cap: fixed 1024 B/s bucket, overflow is residual
        for sec, sizes in sorted(dns_buckets.items()):
            budget = DNS_CAP_BYTES_PER_SEC
            for nbytes in sizes:
                if nbytes <= budget:
                    budget -= nbytes
                    excl["dns"] += 1
                    excl["dns_bytes"] += nbytes
                else:
                    residual.append((sec, aip, "dns", 53, nbytes))

        residual_pkts = len(residual)
        fail = residual_pkts > 0
        verdict = "fail" if fail else "pass"
        forgery = False
        if fail:
            active = any(t0u <= r.get("ts", 0) <= t_end + POST_WINDOW
                         for r in ledger_atk + ocx_atk)
            if not active:
                forgery = True
                verdict = "unmeasured"
                tags.append("DEFENDER_TRAFFIC_FORGERY")
        per_unit.append({
            "unit_id": unit.get("unit_id"),
            "attacker_ip": aip,
            "w_effective": [w_start, t_end + POST_WINDOW],
            "w_close": [t_end, t_end + POST_WINDOW],
            "residual_pkts": residual_pkts,
            "residual_bytes": sum(p[4] for p in residual),
            "excluded": excl,
            "fail": fail and not forgery,
            "verdict": verdict,
            "tags": tags,
        })

    n = len(per_unit) or 1
    result = {
        "fm": "4.1",
        "units": per_unit,
        "rates": {
            "fail_rate": round(sum(1 for u in per_unit if u["fail"]) / n, 4),
            "n_units": len(per_unit),
        },
    }
    outdir = os.path.join(archive, "fm4")
    os.makedirs(outdir, exist_ok=True)
    with open(os.path.join(outdir, "fm4.json"), "w", encoding="utf-8") as fh:
        json.dump(result, fh, indent=2, sort_keys=False)
    return result


def main(argv=None):
    ap = argparse.ArgumentParser(description="FM4.1 residual measurement")
    ap.add_argument("archive", help="archive run dir")
    args = ap.parse_args(argv)
    res = measure(args.archive)
    print(json.dumps(res["rates"], indent=2))
    for u in res["units"]:
        print(u["unit_id"], u["verdict"], "residual_pkts=%d" % u["residual_pkts"],
              u["tags"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
