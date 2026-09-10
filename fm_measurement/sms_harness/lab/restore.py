"""Post-fail-sim cleanup helpers for the FM lab e2e tests.

Every helper is best-effort and logs what it did; a restore failure must not
mask the test verdict, so failures print to stderr and return False.

All functions take host ids (resolved via sms.common.docker_exec with
topology=fm-defender-lab, which re-resolves container names per call).
Importable, no side effects on import.
"""
import sys

TOPOLOGY = "fm-defender-lab"
HOSTS = ("atk", "server", "vault", "router_router1")
NGINX_START = "(nginx -t && (nginx || service nginx start || systemctl start nginx)) 2>&1 || true"
PG_START = "(service postgresql start || pg_ctlcluster 16 main start) 2>&1 || true"


def _exec(host, cmd, timeout=60):
    from sms import common  # noqa: PLC0415 (lazy: sms lives beside lab/)
    rc, out, err = common.docker_exec(None, cmd, topology=TOPOLOGY, host=host,
                                      timeout=timeout)
    return rc, (out or "") + (err or "")


def _log(msg):
    sys.stderr.write("[restore] %s\n" % msg)


def restart_nginx(host="server"):
    """Restart nginx on `host` (fm image runs it via entrypoint background)."""
    rc, out = _exec(host, NGINX_START)
    ok = rc == 0
    _log("restart_nginx(%s) ok=%s %s" % (host, ok, out.strip()[:200]))
    return ok


def restart_pg(host="server"):
    """Restart the PostgreSQL cluster on `host`."""
    rc, out = _exec(host, PG_START)
    ok = rc == 0
    _log("restart_pg(%s) ok=%s %s" % (host, ok, out.strip()[:200]))
    return ok


def flush_exfil(router="router_router1"):
    """Truncate the router exfil sink /srv/exfil/received.log."""
    rc, out = _exec(router, "truncate -s 0 /srv/exfil/received.log")
    ok = rc == 0
    _log("flush_exfil(%s) ok=%s %s" % (router, ok, out.strip()[:200]))
    return ok


def rm_rule(router="router_router1", rule_spec=""):
    """Delete every nft forward rule whose text contains rule_spec.

    The lab router is nft-only (no iptables binary): the plugin renders the
    router firewall as `table inet filter { chain forward ... }`. rule_spec is
    a substring of the rule text, e.g. 'ip saddr 10.10.0.11 drop'.
    """
    if not rule_spec:
        return False
    removed = 0
    for _ in range(50):
        # find the first matching rule handle in the forward chain, delete by
        # handle, repeat until none match
        rc, out = _exec(
            router,
            "nft -a list chain inet filter forward 2>/dev/null | "
            "grep -F %s | grep -o 'handle [0-9]*' | head -1 | "
            "awk '{print $2}'" % _shq(rule_spec))
        handle = (out or "").strip().splitlines()[0].strip() \
            if (out or "").strip() else ""
        if not handle:
            break
        rc, _out = _exec(router,
                         "nft delete rule inet filter forward handle %s"
                         % handle)
        if rc != 0:
            break
        removed += 1
    _log("rm_rule(%s, %r) removed=%d" % (router, rule_spec, removed))
    return True


def _shq(s):
    return "'" + str(s).replace("'", "'\\''") + "'"


def rm_file(host, path):
    """Remove a planted file."""
    rc, _out = _exec(host, "rm -f %s" % path)
    _log("rm_file(%s, %s) ok=%s" % (host, path, rc == 0))
    return rc == 0


def clean_marks(marks, hosts=None):
    """Delete every file matching *<mark>* under /tmp /dev/shm /var/tmp on all
    hosts, plus a corp.notes db sweep on the server."""
    hosts = hosts or HOSTS
    cleaned = True
    for host in hosts:
        for mark in marks:
            rc, _out = _exec(host,
                             "find /tmp /dev/shm /var/tmp -name '*%s*' "
                             "-delete 2>/dev/null" % mark)
            if rc != 0:
                cleaned = False
    for mark in marks:
        rc, _out = _exec(
            "server",
            "su - postgres -c \"psql -d corp -c \\\"DELETE FROM notes "
            "WHERE body ILIKE '%%%s%%'\\\"\" 2>/dev/null" % mark)
        if rc != 0:
            _log("clean_marks: db sweep for %r rc=%d (may be no notes table)"
                 % (mark, rc))
    _log("clean_marks(%r) done (all_fs_ok=%s)" % (marks, cleaned))
    return cleaned


def drop_atk_blocks(router="router_router1", atk_ip=None):
    """Remove every nft forward rule referencing the atk IP (drop/reject,
    src or dst). Without atk_ip, resolves the atk container IP via docker_ps."""
    if atk_ip is None:
        from sms import common  # noqa: PLC0415
        ps = common.docker_ps(TOPOLOGY)
        atk_ip = (ps.get("atk") or {}).get("ip", "")
    if not atk_ip:
        _log("drop_atk_blocks: no atk ip resolved; nothing to do")
        return False
    ok_src = rm_rule(router, "ip saddr %s" % atk_ip)
    ok_dst = rm_rule(router, "ip daddr %s" % atk_ip)
    ok = ok_src and ok_dst
    _log("drop_atk_blocks(%s) done ok=%s" % (atk_ip, ok))
    return ok
