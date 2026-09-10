"""Run controller CLI: start/stop/status for one measurement run.

start: manifest (topology, docker_ps snapshot, tokens, t0, bridges),
baselines/, prober thread (@2 s; --fastpoll 0.5 s), host capture + heartbeat.
stop: final probe tick, stop capture, integrity sweep, manifest.t_end.
All state lives in the archive dir; thread-based, one process, Ctrl-C safe.
"""
import argparse
import json
import os
import signal
import subprocess
import sys
import threading
import time

from . import common, host_capture, integrity, prober

CONTROL = "_control.json"


def _write_control(archive, state):
    with open(os.path.join(archive, CONTROL), "w", encoding="utf-8") as fh:
        json.dump(state, fh, indent=2)


def _read_control(archive):
    p = os.path.join(archive, CONTROL)
    return json.load(open(p, "r", encoding="utf-8")) if os.path.exists(p) else {}


def _read_manifest(archive):
    return json.load(open(os.path.join(archive, "manifest.json"),
                          encoding="utf-8"))


def baseline(archive, hosts_cfg, run_cfg):
    """Write baselines/<host>.json = first probe record per host."""
    os.makedirs(os.path.join(archive, "baselines"), exist_ok=True)
    recs = prober.tick(archive, hosts_cfg, run_cfg)
    for host, rec in recs.items():
        with open(os.path.join(archive, "baselines", "%s.json" % host),
                  "w", encoding="utf-8") as fh:
            json.dump(rec, fh)
    return recs


def start(archive, topology, interval=2.0):
    os.makedirs(archive, exist_ok=True)
    ps = common.docker_ps(topology)
    # Only real topology hosts: labeled hosts carry scl.host.type; routers are
    # keyed router_*. Unlabeled sidecar containers (slips-sensor, capture
    # helpers) fall through to their container id — probing them only adds
    # churn to diffs.jsonl.
    hosts = {k: v for k, v in ps.items()
             if v.get("ip") and (k.startswith("router_") or v.get("type"))}
    # v3 (DESIGN3 §shared): router's server-net IP (10.20.0.x), resolved live
    # (never hardcoded) — feeds the prober's ===EGRESS arm + the FM1.3 roles.
    router_srv_ip = None
    try:
        router_srv_ip = prober.resolve_router_srv_ip(topology, hosts)
    except Exception as exc:  # noqa: BLE001 — egress arm degrades to off
        sys.stderr.write("router_srv_ip resolve failed (%s)\n" % exc)
    manifest = {
        "run": os.path.basename(os.path.normpath(archive)),
        "topology": topology,
        "t0": common.now(),
        "t_end": None,
        "hosts": {h: {"ip": v["ip"], "container": v["container"],
                      "network": v["network"]}
                  for h, v in hosts.items()},
        "tokens": {"http": None},
        "probe_interval": interval,
        "router_srv_ip": router_srv_ip,
    }
    with open(os.path.join(archive, "manifest.json"), "w",
              encoding="utf-8") as fh:
        json.dump(manifest, fh, indent=2)
    # Fresh run-scoped content-probe token (playbook FM1.1): rotate the DB
    # value so manifest and corp.fm_tokens always agree. Falls back to the
    # current DB value when the container is unreachable (offline archives).
    token = ""
    try:
        token = prober.rotate_token(archive) or ""
    except Exception as exc:  # noqa: BLE001
        sys.stderr.write("rotate_token failed (%s); falling back to read\n"
                         % exc)
        try:
            token = prober.read_token(archive) or ""
        except Exception:  # noqa: BLE001
            token = ""
    manifest["tokens"]["http"] = token
    with open(os.path.join(archive, "manifest.json"), "w",
              encoding="utf-8") as fh:
        json.dump(manifest, fh, indent=2)
    run_cfg = {"run": manifest["run"], "topology": topology,
               "tokens": {"http": token}, "atk": "atk",
               "psql_host": "server", "router_srv_ip": router_srv_ip}
    # chain-init the trusted streams so the integrity sweep is meaningful
    for name in integrity.TRUSTED_STREAMS:
        p = os.path.join(archive, name)
        open(p, "a", encoding="utf-8").close()
        common.hash_chain_init(p)
    baseline(archive, hosts, run_cfg)
    # capture + heartbeat
    router_ip = next((v["ip"] for k, v in hosts.items()
                      if k.startswith("router_")), "")
    nets = sorted({v["network"] for v in hosts.values() if v["network"]})
    # bridge per network (pcap filenames carry the bridge id); mapping kept in
    # the manifest so FM4.1 can read only the protected-side bridges
    bridge_nets = {}
    for net in nets:
        brs = host_capture.bridge_names(topology, [net])
        for br in brs:
            bridge_nets[br] = net
    bridges = sorted(bridge_nets)
    manifest["bridges"] = bridges
    manifest["bridge_nets"] = bridge_nets
    with open(os.path.join(archive, "manifest.json"), "w",
              encoding="utf-8") as fh:
        json.dump(manifest, fh, indent=2)
    cap = host_capture.HostCapture(
        archive, topology, bridges, router_ip,
        atk_ip=hosts.get("atk", {}).get("ip")).start()
    # prober loop thread; each tick diffs consecutive same-host probe records
    # (S7) into diffs.jsonl so FM measurement modules have diff evidence
    stop_evt = threading.Event()

    def probe_loop():
        from . import differ  # noqa: PLC0415
        last = {}
        while not stop_evt.is_set():
            try:
                recs = prober.tick(archive, hosts, run_cfg)
                for host, rec in recs.items():
                    if host in last:
                        try:
                            differ.emit(archive, differ.diff(last[host], rec))
                        except Exception as exc:  # noqa: BLE001
                            sys.stderr.write("differ error (%s): %s\n"
                                             % (host, exc))
                    last[host] = rec
            except Exception as exc:  # noqa: BLE001
                sys.stderr.write("prober tick error: %s\n" % exc)
            stop_evt.wait(interval)

    th = threading.Thread(target=probe_loop, daemon=True)
    th.start()
    _write_control(archive, {"started": True, "pid": os.getpid(),
                             "t0": manifest["t0"], "topology": topology})
    return {"manifest": manifest, "threads": [th],
            "stop": lambda: (stop_evt.set(), cap.stop())}


def stop(archive):
    # kill the host-capture helper container if the controller died without
    # running its own teardown
    try:
        prefix = "sms-capture-%s" % os.path.basename(os.path.normpath(archive))
        out = subprocess.run(["docker", "ps", "-a", "--format", "{{.Names}}"],
                             capture_output=True, text=True, timeout=20).stdout
        for cname in out.split():
            if cname == prefix or cname.startswith(prefix + "-"):
                subprocess.run(["docker", "rm", "-f", cname],
                               capture_output=True, timeout=20)
    except Exception:  # noqa: BLE001
        pass
    ctl = _read_control(archive)
    mf = _read_manifest(archive)
    topology = mf.get("topology")
    ps = common.docker_ps(topology) if topology else {}
    ps = {k: v for k, v in ps.items()
          if v.get("ip") and (k.startswith("router_") or v.get("type"))}
    run_cfg = {"run": mf.get("run"), "topology": topology,
               "tokens": mf.get("tokens", {}), "atk": "atk",
               "psql_host": "server", "router_srv_ip": mf.get("router_srv_ip")}
    try:
        prober.tick(archive, ps, run_cfg)  # final tick
    except Exception as exc:  # noqa: BLE001
        sys.stderr.write("final tick error: %s\n" % exc)
    mf["t_end"] = common.now()
    with open(os.path.join(archive, "manifest.json"), "w",
              encoding="utf-8") as fh:
        json.dump(mf, fh, indent=2)
    # chain-append everything that grew, then sweep
    for name in integrity.TRUSTED_STREAMS + ("pcap_host_manifest.jsonl",):
        p = os.path.join(archive, name)
        if os.path.exists(p):
            lines = [l for l in open(p, encoding="utf-8") if l.strip()]
            while common.chain_len(p) < len(lines):
                idx = common.chain_len(p)
                common.hash_chain_append(p, lines[idx].rstrip("\n"))
    results = integrity.sweep(archive)
    _write_control(archive, dict(ctl, started=False, stopped=True,
                                 t_end=mf["t_end"]))
    return {"t_end": mf["t_end"], "integrity": results}


def status(archive):
    ctl = _read_control(archive)
    mf = _read_manifest(archive) if os.path.exists(
        os.path.join(archive, "manifest.json")) else {}
    n_probes = len(os.listdir(os.path.join(archive, "probes"))) \
        if os.path.isdir(os.path.join(archive, "probes")) else 0
    return {"archive": archive, "control": ctl,
            "t0": mf.get("t0"), "t_end": mf.get("t_end"),
            "probe_files": n_probes}


def main(argv=None):
    ap = argparse.ArgumentParser(prog="sms.run_controller")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sp = sub.add_parser("start")
    sp.add_argument("--archive", required=True)
    sp.add_argument("--topology", required=True)
    sp.add_argument("--fastpoll", action="store_true")
    sub.add_parser("stop").add_argument("--archive", required=True)
    sub.add_parser("status").add_argument("--archive", required=True)
    args = ap.parse_args(argv)
    if args.cmd == "start":
        interval = 0.5 if args.fastpoll else 2.0
        handles = start(args.archive, args.topology, interval)
        stop_fns = handles["stop"]
        trig = threading.Event()
        signal.signal(signal.SIGTERM, lambda *a: trig.set())
        signal.signal(signal.SIGINT, lambda *a: trig.set())
        print("run started: %s" % args.archive, flush=True)
        try:
            while not trig.is_set():
                time.sleep(0.5)
        finally:
            stop_fns()
            stop(args.archive)
            print("run stopped: %s" % args.archive)
    elif args.cmd == "stop":
        print(json.dumps(stop(args.archive)))
    else:
        print(json.dumps(status(args.archive), indent=2))


if __name__ == "__main__":
    main()
