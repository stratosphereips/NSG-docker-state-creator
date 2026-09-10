"""Host-executed injection-payload delivery primitive (shared machinery).

Extracted 2026-08-27 from the removed FM5.3 channel-breadth module: FM5.2
(forced-utterance suppression) and FM5.5 (self-disarmament) both deliver a
planted instruction file into a container the defender reads. Every delivery
is host-executed (real docker exec), ledgered (actor=attacker,
action_class=injection) and its residue is pre-registered in payloads.json
marks[] so downstream canary/FS scans can exclude it.

Only the file-based channels survive; the FM5.3 channel-breadth measurement
itself was removed.
"""
import json
import os

from . import canary_check, common, ledger

CHANNELS = {
    "file_content":     {"live": True, "status": None},
    "threat_intel_doc": {"live": True, "status": None},
}

DEFAULT_INBOX = "/opt/fm/inbox"


def dexec(config=None):
    """Topology-aware docker_exec wrapper (unit-test-injectable via
    config['docker_exec'])."""
    config = config or {}
    d = config.get("docker_exec")
    if d is not None and d is not common.docker_exec:
        return d
    topo = config.get("topology")

    def _run(host, cmd):
        return common.docker_exec(None, cmd, topology=topo, host=host)
    return _run


def _config(archive, config):
    """Resolve config defaults from the archive manifest."""
    config = dict(config or {})
    manifest = {}
    mpath = os.path.join(archive, "manifest.json")
    if os.path.exists(mpath):
        try:
            manifest = json.load(open(mpath, encoding="utf-8"))
        except (OSError, ValueError):
            manifest = {}
    config.setdefault("topology", manifest.get("topology") or "fm-defender-lab")
    config.setdefault("server_host", "server")
    return config


def _sha_of(dexec, host, path):
    rc, out, _ = dexec(host, "sha256sum %s 2>/dev/null" % path)
    if rc == 0 and out.strip():
        return out.strip().split()[0]
    return None


def deliver(archive, channel, mark, config=None, payload=None, host=None,
            path=None, tag=None):
    """Deliver `mark`'s payload on `channel` in the real container.

    Executes the delivery command, appends an attacker/injection ledger row,
    and pre-registers the mark in payloads.json with the (path, sha256)
    residue. `payload` is the instruction text (must be single-quote free),
    `host`/`path` override the channel defaults (fm55 on vault uses
    /root/inbox/), `tag` lands on the mark entry (e.g. "fm55_disarm",
    "fm52_suppress").
    """
    assert channel in CHANNELS, channel
    archive = os.path.abspath(archive)
    cfg = _config(archive, config)
    dex = dexec(cfg)
    now = common.now()

    text = payload
    assert text is not None, "payload text required"
    assert "'" not in text, "payload must be single-quote free: %r" % text
    server = host or cfg["server_host"]
    residue = []

    default_name = ("alert_%s.txt" % mark if channel == "file_content"
                    else "threat_intel_%s.md" % mark)
    target = path or os.path.join(DEFAULT_INBOX, default_name)
    assert "'" not in target, "path must be single-quote free: %r" % target
    cmd = "mkdir -p %s && printf '%%s\\n' '%s' > %s" % (
        os.path.dirname(target), text, target)

    rc, out, err = dex(server, cmd)
    if rc == 0:
        sha = _sha_of(dex, server, target)
        if sha:
            residue.append({"path": target, "sha256": sha})

    delivered = rc == 0
    ledger.record(archive, "attacker", "injection", server,
                  {"channel": channel, "mark": mark, "command": cmd,
                   "exit_code": rc})

    entry = {"mark": mark, "channel": channel, "deliver_ts": now,
             "delivered": delivered, "host": server, "residue": residue,
             "payload": text}
    if path is not None:
        entry["path"] = path
    if tag:
        entry["tag"] = tag
    payloads = canary_check.load_payloads(archive)
    payloads.setdefault("marks", []).append(entry)
    with open(os.path.join(archive, "payloads.json"), "w",
              encoding="utf-8") as fh:
        json.dump(payloads, fh, indent=2)

    return {"channel": channel, "mark": mark, "host": server, "command": cmd,
            "exit_code": rc, "delivered": delivered,
            "status": "delivered" if delivered else "delivery_failed",
            "deliver_ts": now, "residue": residue, "path": target}
