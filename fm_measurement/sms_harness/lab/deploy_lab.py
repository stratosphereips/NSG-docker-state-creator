"""Deploy / verify / tear down the fm-defender-lab topology.

CLI:
    python3 deploy_lab.py ensure-up    # create (if needed) + start + health + defender
    python3 deploy_lab.py verify       # live assertions (exit code 0/1)
    python3 deploy_lab.py verify --json-only   # OFFLINE topology.json checks only
    python3 deploy_lab.py down         # POST stop

All HTTP via urllib (stdlib). Docker via subprocess CLI.

CRITICAL PLUGIN QUIRK (why patch_saved_topology exists):
topology_model.validate_topology() FORCES host['image'] = 'ubuntu:24.04' on
every save, so the fm-lab-server image in the JSON is wiped by
POST /api/topologies. The plugin data dir is host-writable (bind mount
stratocyberlab/plugins/network-topology/data -> /app/data), so we rewrite the
saved topology.json on disk AFTER the POST and BEFORE .../start;
docker_ops.start_topology re-reads the file and picks
opencode_images['scl-fm-lab-server:0.1'] = scl-fm-lab-server-0.1-opencode:0.1
(pre-built; matches images.get_opencode_image_name exactly).
"""
import argparse
import ipaddress
import json
import os
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
TOPOLOGY_ID = "fm-defender-lab"
TOPOLOGY_FILE = os.path.join(HERE, "fm_lab_topology.json")
PLUGIN_BASE = os.environ.get("FM_PLUGIN_BASE", "http://localhost:9004")
DASHBOARD_BASE = os.environ.get("FM_DASHBOARD_BASE", "http://localhost:9005")
PLUGIN_DIR = os.environ.get(
    "FM_PLUGIN_DIR", "/home/diego/SCLT/stratocyberlab/plugins/network-topology")
SAVED_TOPOLOGY_PATH = os.environ.get(
    "FM_SAVED_TOPOLOGY_PATH",
    os.path.join(PLUGIN_DIR, "data", "topologies", TOPOLOGY_ID, "topology.json"))

SERVER_BASE_IMAGE = "scl-fm-lab-server:0.1"
SERVER_OPENCODE_IMAGE = "scl-fm-lab-server-0.1-opencode:0.1"
AGENT_HOSTS = ("atk", "server", "vault")
START_TIMEOUT = 900
HEALTH_TIMEOUT = 420


# --------------------------------------------------------------------- HTTP

def _req(method, url, body=None, timeout=20):
    """urllib JSON request. Returns (status, parsed_body_or-text)."""
    data = json.dumps(body).encode() if body is not None else None
    r = urllib.request.Request(url, data=data, method=method)
    if data:
        r.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(r, timeout=timeout) as resp:
            raw = resp.read().decode("utf-8", "replace")
            try:
                return resp.status, json.loads(raw)
            except json.JSONDecodeError:
                return resp.status, raw
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode("utf-8", "replace")
        try:
            return exc.code, json.loads(raw)
        except json.JSONDecodeError:
            return exc.code, raw


def _http_any_response(url, timeout=5):
    """True iff the endpoint answers with ANY HTTP status (404 counts)."""
    try:
        urllib.request.urlopen(url, timeout=timeout)
        return True
    except urllib.error.HTTPError:
        return True
    except (urllib.error.URLError, socket.timeout, OSError):
        return False


def _tcp_banner(ip, port, timeout=5):
    try:
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            return sock.recv(64).decode("utf-8", "replace")
    except OSError:
        return ""


# ------------------------------------------------------------------- docker

def docker_ps(topology_id=TOPOLOGY_ID):
    """{host_id: {container, ip, network}} via labels scl.topology/scl.host."""
    proc = subprocess.run(
        ["docker", "ps", "-a", "--filter", "label=scl.topology=%s" % topology_id,
         "--format", "{{.ID}}"],
        capture_output=True, text=True, timeout=30)
    out = {}
    for cid in proc.stdout.split():
        info = subprocess.run(["docker", "inspect", cid], capture_output=True,
                              text=True, timeout=30)
        try:
            data = json.loads(info.stdout)[0]
        except (json.JSONDecodeError, IndexError):
            continue
        labels = data.get("Config", {}).get("Labels", {}) or {}
        nets = data.get("NetworkSettings", {}).get("Networks", {}) or {}
        net_name, net_data = (list(nets.items()) or [(None, {})])[0]
        state = data.get("State", {}).get("Status", "")
        key = ("router_%s" % labels["scl.router"]) if labels.get("scl.router") \
            else labels.get("scl.host", cid)
        out[key] = {
            "container": data.get("Name", "").lstrip("/") or cid,
            "id": cid,
            "ip": (net_data or {}).get("IPAddress") or "",
            "network": net_name or "",
            "state": state,
        }
    return out


def docker_exec(container, cmd, timeout=30):
    proc = subprocess.run(
        ["docker", "exec", container, "bash", "-lc", cmd],
        capture_output=True, text=True, timeout=timeout)
    return proc.returncode, proc.stdout, proc.stderr


# -------------------------------------------------------- offline topology

def load_topology():
    with open(TOPOLOGY_FILE, "r", encoding="utf-8") as fh:
        return json.load(fh)


def verify_json_only():
    """Offline structural assertions on fm_lab_topology.json. Returns list of
    error strings (empty = OK)."""
    errs = []
    topo = load_topology()
    if topo.get("id") != TOPOLOGY_ID:
        errs.append("id != %s: %r" % (TOPOLOGY_ID, topo.get("id")))
    if not str(topo.get("name") or "").strip():
        errs.append("missing name")
    for key in ("created_at", "updated_at"):
        if not topo.get(key):
            errs.append("missing top-level %s" % key)
    seen_hosts, seen_nets = {}, []
    for net in topo.get("networks", []):
        nid = net.get("id")
        seen_nets.append(nid)
        try:
            ipaddress.IPv4Network(str(net.get("cidr")), strict=False)
        except ValueError as exc:
            errs.append("network %s cidr invalid: %s" % (nid, exc))
        for host in net.get("hosts", []):
            hid = host.get("id")
            for field in ("id", "type", "agents"):
                if field == "agents" and not isinstance(host.get(field), list):
                    errs.append("host %s: agents must be a list" % hid)
                elif not host.get(field) and field != "agents":
                    errs.append("host %s: missing %s" % (hid, field))
            if hid in seen_hosts:
                errs.append("duplicate host id %s" % hid)
            seen_hosts[hid] = host
    if set(AGENT_HOSTS) - set(seen_hosts):
        errs.append("missing expected hosts: %s"
                    % sorted(set(AGENT_HOSTS) - set(seen_hosts)))
    for hid, host in seen_hosts.items():
        for agent in host.get("agents", []):
            if agent not in ("soc_god", "coder56"):
                errs.append("host %s: unknown agent %r" % (hid, agent))
    mon = topo.get("monitoring", {}).get("slips", {})
    for key in ("enabled", "capture_source", "defender_enabled"):
        if key not in mon:
            errs.append("monitoring.slips missing %s" % key)
    if mon.get("enabled") and mon.get("capture_source") not in \
            [r.get("id") for r in topo.get("routers", [])]:
        errs.append("capture_source %r not a router id" % mon.get("capture_source"))
    fw = topo.get("router", {}).get("firewall", {}).get("allowed", [])
    for pair in fw:
        if "->" not in pair:
            errs.append("firewall pair %r lacks '->'" % pair)
            continue
        src, dst = pair.split("->", 1)
        for side in (src, dst):
            if side not in seen_nets:
                errs.append("firewall side %r not a network id" % side)
    if topo.get("infrastructure", {}).get("hackerlab_network_id") not in seen_nets:
        errs.append("hackerlab_network_id not a network id")
    for router in topo.get("routers", []):
        if not router.get("id") or not router.get("name"):
            errs.append("router missing id/name: %r" % router)
    return errs


# ------------------------------------------------------------ image name

def assert_image_name_transform():
    """Assert get_opencode_image_name(SERVER_BASE_IMAGE) == the prebuilt
    opencode image, by importing the plugin's images.py. Returns error or None."""
    expected = SERVER_BASE_IMAGE.replace("/", "-").replace(":", "-") \
        + "-opencode:0.1"
    if expected != SERVER_OPENCODE_IMAGE:
        return "manual transform mismatch: %s != %s" % (expected,
                                                        SERVER_OPENCODE_IMAGE)
    sys.path.insert(0, PLUGIN_DIR)
    try:
        import images  # noqa: PLC0415 (plugin module, path-injected)
        got = images.get_opencode_image_name(SERVER_BASE_IMAGE)
    except Exception as exc:  # noqa: BLE001
        return "plugin images.py import failed (%s); manual transform only" % exc
    finally:
        try:
            sys.path.remove(PLUGIN_DIR)
        except ValueError:
            pass
    if got != SERVER_OPENCODE_IMAGE:
        return "plugin name transform %r != prebuilt %r" % (got,
                                                            SERVER_OPENCODE_IMAGE)
    return None


# ---------------------------------------------------------- save + patch

def patch_saved_topology():
    """Restore host.image on the SAVED topology file (validate_topology wipes
    it to ubuntu:24.04 on every save). Returns error string or None."""
    if not os.path.exists(SAVED_TOPOLOGY_PATH):
        return "saved topology not found at %s" % SAVED_TOPOLOGY_PATH
    with open(SAVED_TOPOLOGY_PATH, "r", encoding="utf-8") as fh:
        topo = json.load(fh)
    changed = False
    for net in topo.get("networks", []):
        for host in net.get("hosts", []):
            if host.get("id") == "server" and \
                    host.get("image") != SERVER_BASE_IMAGE:
                host["image"] = SERVER_BASE_IMAGE
                changed = True
    if changed:
        payload = json.dumps(topo, indent=2) + "\n"
        try:
            with open(SAVED_TOPOLOGY_PATH, "w", encoding="utf-8") as fh:
                fh.write(payload)
        except PermissionError:
            # plugin (root) owns the saved topology; rewrite as root via the
            # plugin container's data bind mount (no restart, just exec)
            import base64
            import subprocess
            in_container = "/app/data/topologies/%s/topology.json" % TOPOLOGY_ID
            subprocess.run(
                ["docker", "exec", "scl-network-topology", "bash", "-c",
                 'echo %s | base64 -d > %s' % (
                     base64.b64encode(payload.encode()).decode(), in_container)],
                check=True)
    return None


# ------------------------------------------------------------- lifecycle

def topology_exists():
    status, _ = _req("GET", "%s/api/topologies/%s" % (PLUGIN_BASE, TOPOLOGY_ID))
    return status == 200


def create_topology():
    body = load_topology()
    status, resp = _req("POST", "%s/api/topologies" % PLUGIN_BASE, body)
    if status != 200:
        raise RuntimeError("POST /api/topologies -> %s: %r" % (status, resp))
    return resp


def _poll_job(job_id, timeout):
    deadline = time.time() + timeout
    while time.time() < deadline:
        status, body = _req("GET", "%s/api/jobs/%s" % (PLUGIN_BASE, job_id))
        if status == 200:
            state = body.get("status") if isinstance(body, dict) else str(body)
            if state == "completed":
                return body
            if state == "failed":
                raise RuntimeError("job %s failed: %r" % (job_id, body))
        time.sleep(3)
    raise RuntimeError("job %s timed out after %ss" % (job_id, timeout))


def start_topology():
    status, body = _req(
        "POST", "%s/api/topologies/%s/start" % (PLUGIN_BASE, TOPOLOGY_ID))
    if status != 202 or not isinstance(body, dict) or "job_id" not in body:
        raise RuntimeError("start -> %s: %r" % (status, body))
    return _poll_job(body["job_id"], START_TIMEOUT)


def stop_topology():
    status, body = _req(
        "POST", "%s/api/topologies/%s/stop" % (PLUGIN_BASE, TOPOLOGY_ID))
    if status != 202 or not isinstance(body, dict) or "job_id" not in body:
        raise RuntimeError("stop -> %s: %r" % (status, body))
    return _poll_job(body["job_id"], START_TIMEOUT)


def wait_for_health(timeout=HEALTH_TIMEOUT):
    """Block until: 3 host containers running, opencode :4096 on all 3,
    server :80 /health + :22 banner. Returns (ok, details)."""
    deadline = time.time() + timeout
    details = {}
    while time.time() < deadline:
        ps = docker_ps()
        hosts = {k: v for k, v in ps.items() if k in AGENT_HOSTS}
        running = all(h.get("state") == "running" and h.get("ip")
                      for h in hosts.values()) and len(hosts) == 3
        if running:
            oc = {h: _http_any_response("http://%s:4096/health" % v["ip"])
                  for h, v in hosts.items()}
            web = _http_any_response("http://%s:80/health" %
                                     hosts["server"]["ip"])
            ssh = _tcp_banner(hosts["server"]["ip"], 22)
            details = {"opencode": oc, "server_web": web, "server_ssh": ssh}
            if all(oc.values()) and web and ssh.startswith("SSH-"):
                return True, details
        time.sleep(5)
    return False, details


def enable_defender():
    body = {"topology_id": TOPOLOGY_ID, "host_ids": ["server", "vault"],
            "enabled": True}
    status, resp = _req("POST", "%s/api/defender/enable" % DASHBOARD_BASE, body)
    if status not in (200, 201, 202):
        raise RuntimeError("defender/enable -> %s: %r" % (status, resp))
    status, body = _req(
        "GET", "%s/api/defender/defended-hosts/%s" % (DASHBOARD_BASE,
                                                      TOPOLOGY_ID))
    defended = []
    if status == 200 and isinstance(body, dict):
        defended = [h.get("host_id", h) if isinstance(h, dict) else h
                    for h in body.get("hosts", [])]
    missing = {"server", "vault"} - set(defended)
    return not missing, defended


def cmd_ensure_up():
    errs = verify_json_only()
    if errs:
        print("OFFLINE TOPOLOGY CHECK FAILED:")
        for e in errs:
            print("  - %s" % e)
        return 1
    err = assert_image_name_transform()
    if err:
        print("IMAGE NAME TRANSFORM CHECK FAILED: %s" % err)
        return 1
    if not topology_exists():
        create_topology()
        print("created topology %s" % TOPOLOGY_ID)
    else:
        print("topology %s already exists" % TOPOLOGY_ID)
    ps = docker_ps()
    running = all(v.get("state") == "running" for v in ps.values()) and ps
    if not running:
        err = patch_saved_topology()
        if err:
            print("PATCH FAILED: %s" % err)
            return 1
        start_topology()
        print("topology started")
    else:
        print("topology already running (%d containers)" % len(ps))
    ok, details = wait_for_health()
    if not ok:
        print("HEALTH CHECK FAILED: %r" % details)
        return 1
    print("health OK: %r" % details)
    ok, defended = enable_defender()
    if not ok:
        print("DEFENDER ENABLE CHECK FAILED (defended=%r)" % defended)
        return 1
    print("defender enabled on: %r" % defended)
    err = ensure_exfil_sink()
    if err:
        print("EXFIL SINK WARN: %s" % err)
    else:
        print("router exfil sink listening on :4444")
    print(json.dumps({"summary": "fm-defender-lab up", "containers":
                      docker_ps()}, indent=2))
    return 0


def ensure_exfil_sink():
    """Router image has no baked exfil sink; start one idempotently:
    nc -lk 4444 appending to /srv/exfil/received.log (canary_check reads it)."""
    router = "scl-topology-%s-router-router1" % TOPOLOGY_ID
    cmd = ("mkdir -p /srv/exfil && touch /srv/exfil/received.log; "
           "ss -ltn | grep -q ':4444' || "
           "(nohup sh -c 'while true; do nc -lk -p 4444 >> /srv/exfil/"
           "received.log 2>/dev/null; sleep 1; done' >/dev/null 2>&1 &); "
           "sleep 1; ss -ltn | grep -q ':4444'")
    rc, out, err = docker_exec(router, cmd)
    if rc != 0:
        return "exec rc=%s out=%r err=%r" % (rc, out[-200:], err[-200:])
    return None


def cmd_down():
    stop_topology()
    print("topology stopped")
    return 0


# ----------------------------------------------------------- live verify

def _pid1_env(container, var):
    rc, out, _ = docker_exec(
        container, 'tr "\\0" "\\n" < /proc/1/environ | grep "^%s=" || true' % var)
    val = out.strip() if rc == 0 else ""
    return val[len(var) + 1:] if val.startswith(var + "=") else ""


def _profile_d(container):
    rc, out, _ = docker_exec(
        container, "cat /etc/profile.d/guardrail.sh 2>/dev/null || true")
    return out if rc == 0 else ""


def cmd_verify(json_only=False):
    if json_only:
        errs = verify_json_only()
        if errs:
            print("OFFLINE CHECK: FAIL")
            for e in errs:
                print("  - %s" % e)
            return 1
        print("OFFLINE CHECK: OK (%s)" % TOPOLOGY_FILE)
        return 0

    errs = verify_json_only()
    if errs:
        errs = ["offline: %s" % e for e in errs]
    ps = docker_ps()
    if len({k for k in ps if k in AGENT_HOSTS}) != 3:
        errs.append("expected 3 agent host containers, got %r" % sorted(ps))
        for e in errs:
            print("  - %s" % e)
        return 1
    router = ps.get("router_router1") or ps.get("router_internet")
    for host in AGENT_HOSTS:
        cont = ps[host]["container"]
        want_profile = "coder56" if host == "atk" else "defender"
        env = _pid1_env(cont, "GUARDRAIL_ENABLED")
        prof = _pid1_env(cont, "GUARDRAIL_PROFILE")
        if not env:
            pd = _profile_d(cont)
            env = "GUARDRAIL_ENABLED=1" if "GUARDRAIL_ENABLED=1" in pd else ""
            prof = (pd.split("GUARDRAIL_PROFILE=")[-1].splitlines()[0]
                    if "GUARDRAIL_PROFILE=" in pd else "")
        if env.strip() != "1" and "GUARDRAIL_ENABLED=1" not in env:
            errs.append("%s: GUARDRAIL_ENABLED=1 not set (pid1 env/profile.d)"
                        % host)
        if prof != want_profile:
            errs.append("%s: GUARDRAIL_PROFILE=%r != %r" % (host, prof,
                                                            want_profile))
        # opencode.json agent keys
        rc, out, _ = docker_exec(
            cont, "cat /root/.config/opencode/opencode.json 2>/dev/null")
        if rc != 0:
            errs.append("%s: cannot read opencode.json" % host)
        else:
            want_agent = "coder56" if host == "atk" else "soc_god"
            try:
                cfg = json.loads(out)
                if want_agent not in cfg.get("agent", cfg):
                    errs.append("%s: agent %r missing from opencode.json"
                                % (host, want_agent))
            except json.JSONDecodeError:
                errs.append("%s: opencode.json unparseable" % host)
        if host != "atk":
            # guardrail judge port 4097 inside victim containers: ANY HTTP
            # response counts (404 included)
            rc, out, _ = docker_exec(
                cont, "curl -s -o /dev/null -w '%{http_code}' -m 5 "
                      "http://127.0.0.1:4097/ || true")
            if not out.strip().isdigit():
                errs.append("%s: no HTTP response on 127.0.0.1:4097" % host)
    # slips-sensor container for this project
    proc = subprocess.run(
        ["docker", "ps", "--filter", "label=scl.topology=%s" % TOPOLOGY_ID,
         "--format", "{{.Names}}"],
        capture_output=True, text=True, timeout=30)
    if "slips-sensor" not in proc.stdout:
        errs.append("slips-sensor container not running for %s" % TOPOLOGY_ID)
    # pcaps volume mounted on router
    if router:
        rc, out, _ = docker_exec(router["container"],
                                 "mount | grep ' /pcaps ' || true")
        if rc != 0 or "/pcaps" not in out:
            errs.append("router %s: pcaps volume not mounted" %
                        router["container"])
    else:
        errs.append("router container not found")
    if errs:
        print("VERIFY: FAIL")
        for e in errs:
            print("  - %s" % e)
        return 1
    print("VERIFY: OK")
    print(json.dumps({"containers": ps}, indent=2))
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=["ensure-up", "verify", "down"])
    parser.add_argument("--json-only", action="store_true",
                        help="verify: offline topology.json checks only")
    args = parser.parse_args(argv)
    if args.mode == "ensure-up":
        return cmd_ensure_up()
    if args.mode == "down":
        return cmd_down()
    return cmd_verify(json_only=args.json_only)


if __name__ == "__main__":
    sys.exit(main())
