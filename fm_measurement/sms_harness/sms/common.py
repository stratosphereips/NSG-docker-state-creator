"""Common primitives: time, jsonl IO, hash chains, docker CLI wrappers.

Python 3.12 stdlib only; docker is driven via the CLI (subprocess).
"""
import hashlib
import json
import os
import subprocess
import time

# Archive root (host-side, defender-unreachable). Env override supported.
ARCHIVE_ROOT = os.environ.get("SMS_ARCHIVE_ROOT", "/home/diego/SCLT/sms_archive")

DOCKER_TIMEOUT = 30


def now():
    """Epoch float timestamp."""
    return time.time()


def append_jsonl(path, record):
    """Append one JSON record as a line. Returns the line written."""
    line = json.dumps(record, separators=(",", ":"), sort_keys=False)
    os.makedirs(os.path.dirname(os.path.abspath(path)) or ".", exist_ok=True)
    with open(path, "a", encoding="utf-8") as fh:
        fh.write(line + "\n")
    return line


def read_jsonl(path):
    """Read a jsonl file into a list of dicts. Missing file -> []."""
    if not os.path.exists(path):
        return []
    out = []
    with open(path, "r", encoding="utf-8") as fh:
        for lineno, line in enumerate(fh, 1):
            line = line.strip()
            if not line:
                continue
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError:
                # salvage: keep raw line under a marker key (see audit memory:
                # missing-newline / garbage lines must not silently drop data)
                out.append({"_parse_error": True, "_lineno": lineno, "_raw": line})
    return out


def sha256_bytes(data):
    return hashlib.sha256(data).hexdigest()


def sha256_file(path):
    """sha256 hex of a file's bytes."""
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


# ---------------------------------------------------------------------------
# Hash chains: h_n = sha256(h_{n-1} || line). Chain file "<path>.chain" is a
# jsonl of per-line running hashes h_1..h_n (h_0 = 64 zeros) so that both
# truncation and mid-file rewrites are detectable exactly.
# ---------------------------------------------------------------------------

GENESIS = "0" * 64


def _chain_path(path):
    return path + ".chain"


def hash_chain_init(path):
    """(Re)initialize an empty chain file for `path`."""
    open(_chain_path(path), "w", encoding="utf-8").close()
    return _chain_path(path)


def hash_chain_append(path, line=None):
    """Append the chain hash for the LAST line of `path` to its .chain file.

    If `line` is given it must equal the last line (without trailing newline).
    Returns h_n.
    """
    with open(path, "r", encoding="utf-8") as fh:
        lines = [l.rstrip("\n") for l in fh]
    if not lines:
        return GENESIS
    last = line if line is not None else lines[-1]
    prev = chain_head(path)
    h = sha256_bytes((prev + last).encode("utf-8"))
    with open(_chain_path(path), "a", encoding="utf-8") as fh:
        fh.write(h + "\n")
    return h


def chain_head(path):
    """Latest chain hash h_n (GENESIS if empty)."""
    cp = _chain_path(path)
    if not os.path.exists(cp):
        return GENESIS
    h = GENESIS
    with open(cp, "r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                h = line
    return h


def chain_len(path):
    cp = _chain_path(path)
    if not os.path.exists(cp):
        return 0
    return sum(1 for l in open(cp, "r", encoding="utf-8") if l.strip())


def hash_chain_verify(path):
    """Verify `path` against its .chain file.

    Returns dict {ok, n_file, n_chain, status} where status is
    "ok" | "truncated" | "rewrite:<i>" | "un chained tail".
    Replays h_n over the file lines and compares index-by-index.
    """
    cp = _chain_path(path)
    chain = [l.strip() for l in open(cp, "r", encoding="utf-8")] if os.path.exists(cp) else []
    chain = [h for h in chain if h]
    if not os.path.exists(path):
        return {"ok": False, "n_file": 0, "n_chain": len(chain), "status": "missing_file"}
    with open(path, "r", encoding="utf-8") as fh:
        lines = [l.rstrip("\n") for l in fh if l.strip("\n") != ""]
    h = GENESIS
    for i, line in enumerate(lines):
        h = sha256_bytes((h + line).encode("utf-8"))
        if i < len(chain) and h != chain[i]:
            return {"ok": False, "n_file": len(lines), "n_chain": len(chain),
                    "status": "rewrite:%d" % i}
    if len(chain) > len(lines):
        return {"ok": False, "n_file": len(lines), "n_chain": len(chain),
                "status": "truncated"}
    if len(lines) > len(chain):
        # extra lines appended without chain update: prefix intact -> benign
        return {"ok": True, "n_file": len(lines), "n_chain": len(chain),
                "status": "unchained_tail"}
    return {"ok": True, "n_file": len(lines), "n_chain": len(chain), "status": "ok"}


# ---------------------------------------------------------------------------
# docker CLI wrappers
# ---------------------------------------------------------------------------

def docker_exec(container, cmd, timeout=DOCKER_TIMEOUT, topology=None, host=None):
    """Run `bash -lc cmd` inside a container.

    `container` is a container name; when `topology` + `host` are given the
    name is re-resolved via docker_ps on EVERY call (topologies restart and
    container names/ids change). Returns (rc, stdout, stderr).
    """
    if topology and host:
        ps = docker_ps(topology)
        entry = ps.get(host)
        if not entry:
            # container may have been recreated since the snapshot was cached
            ps = docker_ps(topology, refresh=True)
            entry = ps.get(host)
        if not entry:
            return (1, "", "unknown host %r in topology %r" % (host, topology))
        container = entry["container"]
    try:
        proc = subprocess.run(
            ["docker", "exec", container, "bash", "-lc", cmd],
            capture_output=True, text=True, timeout=timeout)
        return (proc.returncode, proc.stdout, proc.stderr)
    except subprocess.TimeoutExpired:
        return (124, "", "timeout after %ds" % timeout)
    except FileNotFoundError as exc:
        return (127, "", str(exc))


_PS_CACHE = {}          # topology_id -> (monotonic_ts, snapshot)
_PS_CACHE_TTL = 20.0    # seconds; names/IPs are stable during a live run


def docker_ps(topology_id, refresh=False):
    """Snapshot the topology's containers.

    Filters `docker ps -a` by label scl.topology=<id>, inspects each, and
    returns {host_id: {container, ip, network, type}}. A container carrying
    the `scl.router` label is keyed 'router_<router_id>'.

    Results are cached for _PS_CACHE_TTL seconds: the prober resolves host
    names per docker_exec and an un-cached snapshot costs ~8 docker CLI calls
    per exec (344 subprocesses, ~35 s per tick measured). refresh=True forces
    a re-scan (call after starting/stopping containers).
    """
    now_mono = time.monotonic()
    if not refresh:
        hit = _PS_CACHE.get(topology_id)
        if hit and (now_mono - hit[0]) < _PS_CACHE_TTL:
            return hit[1]
    proc = subprocess.run(
        ["docker", "ps", "-a", "--filter", "label=scl.topology=%s" % topology_id,
         "--format", "{{.ID}}"],
        capture_output=True, text=True, timeout=DOCKER_TIMEOUT)
    out = {}
    for cid in proc.stdout.split():
        info = subprocess.run(
            ["docker", "inspect", cid], capture_output=True, text=True,
            timeout=DOCKER_TIMEOUT)
        try:
            data = json.loads(info.stdout)[0]
        except (json.JSONDecodeError, IndexError):
            continue
        labels = data.get("Config", {}).get("Labels", {}) or {}
        nets = data.get("NetworkSettings", {}).get("Networks", {}) or {}
        net_name, net_data = (list(nets.items()) or [(None, {})])[0]
        entry = {
            "container": data.get("Name", "").lstrip("/") or cid,
            "id": cid,
            "ip": (net_data or {}).get("IPAddress") or "",
            "network": net_name or "",
            # SHARED-BUG FIX (2026-08-26, fm12 e2e bring-up): the plugin's
            # compose.py bakes the host-type label as `scl.host_type`
            # (underscore); the original `scl.host.type` (dot) read never
            # matched, so docker_ps returned type="" for every non-router
            # host and run_controller.start() silently probed ROUTERS ONLY
            # (no server/vault/atk probes -> every FM canary arm dead).
            # Read the real key first, keep the dot variant as fallback.
            "type": labels.get("scl.host_type") or labels.get("scl.host.type", ""),
            "router": labels.get("scl.router", ""),
        }
        key = "router_%s" % labels["scl.router"] if labels.get("scl.router") \
            else labels.get("scl.host", cid)
        out[key] = entry
    _PS_CACHE[topology_id] = (now_mono, out)
    return out


def normalize_iptables(text):
    """Normalize iptables-save output to a sorted list of rule lines.

    Strips [n:m] counters, comments and whitespace so that only the rule set
    semantics matter for rule_added/rule_removed diffs.
    """
    import re
    rules = []
    for line in (text or "").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        line = re.sub(r"\[[0-9]+:[0-9]+\] ", "", line)
        line = re.sub(r"\s+#\s*comment.*$", "", line)
        if line:
            rules.append(line)
    return sorted(rules)
