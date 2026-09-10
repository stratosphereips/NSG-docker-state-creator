"""S4 host bridge capture + S8 heartbeat markers + pcap trust windows.

- resolves the topology's bridge ifaces via docker network inspect
- runs root `tcpdump -i br-a -i br-b -U -G 15 -w pcaps_host/bridge_%s.pcap`
- manifest line per rotated pcap file (pcap_host_manifest.jsonl)
- heartbeat: every 5 s emit sequenced marker SMSHB<32hex> atk->router:4444,
  logged to heartbeat_ledger.jsonl; a pcap window is TRUSTED iff all expected
  markers appear as raw ASCII bytes in the pcap files.
"""
import glob
import json
import os
import secrets
import signal
import subprocess
import threading
import time

from . import common

MANIFEST = "pcap_host_manifest.jsonl"
HEARTBEAT_LEDGER = "heartbeat_ledger.jsonl"
HEARTBEAT_PORT = 4444
HEARTBEAT_INTERVAL = 5.0
MARKER_PREFIX = b"SMSHB"
CAPTURE_IMAGE = "scl-plugin-network-topology-ubuntu:0.1"  # has tcpdump


def safe_bridge_name(br):
    """Filesystem-safe pcap prefix for a bridge iface name."""
    return "".join(c if c.isalnum() or c in "._-" else "_" for c in br)


def bridge_names(topology_id, net_ids):
    """Resolve host bridge iface names for the topology's docker networks.

    net_ids entries are FULL docker network names (e.g.
    scl-topology-<topo>_<net> as returned by docker_ps(). If a short net id
    is passed, the scl-topology-<topo>_<net> form is tried too."""
    bridges = []
    for net in net_ids:
        names = [net]
        if not net.startswith("scl-topology-"):
            names.append("scl-topology-%s_%s" % (topology_id, net))
            names.append("scl-topology-%s_topo_%s" % (topology_id, net))
        out = ""
        for name in names:
            try:
                out = subprocess.run(
                    ["docker", "network", "inspect", "-f",
                     '{{index .Options "com.docker.network.bridge.name"}}',
                     name],
                    capture_output=True, text=True, timeout=10).stdout.strip()
            except subprocess.TimeoutExpired:
                out = ""
            if out:
                break
            try:
                nid = subprocess.run(
                    ["docker", "network", "inspect", "-f", "{{.Id}}", name],
                    capture_output=True, text=True, timeout=10).stdout.strip()
            except subprocess.TimeoutExpired:
                nid = ""
            if nid:
                out = "br-" + nid[:12]
                break
        if out:
            bridges.append(out)
    return sorted(set(bridges))


class HostCapture:
    """tcpdump on the topology bridges + manifest + heartbeat threads."""

    def __init__(self, archive, topology_id, bridges, router_ip,
                 atk_host="atk", atk_ip=None):
        self.archive = archive
        self.topology = topology_id
        self.bridges = bridges
        self.router_ip = router_ip
        self.atk_host = atk_host
        self.atk_ip = atk_ip
        self.pcap_dir = os.path.join(archive, "pcaps_host")
        os.makedirs(self.pcap_dir, exist_ok=True)
        self.tcpdump = None
        self._threads = []
        self._stop = threading.Event()
        self._hb_seq = 0

    # -- capture -----------------------------------------------------------
    def start(self):
        # tcpdump must see the HOST netns bridges; unprivileged users cannot
        # capture on them, so run tcpdump in a helper container with
        # --network host and the pcap dir bind-mounted.
        # ONE tcpdump PER BRIDGE, file prefix bridge_<bridge>__<ts>.pcap:
        # measurement (FM4.1) must distinguish packets on the attacker's
        # bridge (pre-enforcement, always visible) from packets that actually
        # reached a protected network's bridge (post-enforcement).
        name = "sms-capture-%s" % os.path.basename(self.archive)
        self.capture_container = name
        self.tcpdumps = []
        for br in self.bridges:
            safe = safe_bridge_name(br)
            cmd = ["docker", "run", "--rm", "--name", "%s-%s" % (name, safe),
                   "--network", "host", "--cap-add", "NET_ADMIN",
                   "-v", "%s:/cap" % self.pcap_dir,
                   CAPTURE_IMAGE, "tcpdump", "-U", "-G", "15", "-n", "-s", "0",
                   "-Z", "root",
                   "-i", br, "-w", "/cap/bridge_%s__%%s.pcap" % safe]
            self.tcpdumps.append(subprocess.Popen(
                cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))
        self.tcpdump = self.tcpdumps[0] if self.tcpdumps else None
        t = threading.Thread(target=self._manifest_loop, daemon=True)
        t.start()
        self._threads.append(t)
        hb = threading.Thread(target=self._heartbeat_loop, daemon=True)
        hb.start()
        self._threads.append(hb)
        return self

    def _manifest_loop(self):
        seen = set()
        while not self._stop.is_set():
            for path in sorted(glob.glob(
                    os.path.join(self.pcap_dir, "bridge_*.pcap"))):
                if path in seen or self._stop.is_set():
                    continue
                # wait until file stops growing (rotation moved on)
                try:
                    if self._file_growing(path):
                        continue
                    seen.add(path)
                    common.append_jsonl(
                        os.path.join(self.archive, MANIFEST),
                        {"ts": common.now(),
                         "file": os.path.basename(path),
                         "sha256": common.sha256_file(path),
                         "size": os.path.getsize(path),
                         "run": os.path.basename(self.archive)})
                except OSError:
                    continue
            self._stop.wait(2.0)

    @staticmethod
    def _file_growing(path):
        try:
            s1 = os.path.getsize(path)
            time.sleep(1.0)
            s2 = os.path.getsize(path)
            return s1 != s2
        except OSError:
            return True

    # -- heartbeat ---------------------------------------------------------
    def _heartbeat_loop(self):
        while not self._stop.is_set():
            marker = ("SMSHB" + secrets.token_hex(16))
            try:
                if self.router_ip:
                    common.docker_exec(
                        None,
                        "printf %%s '%s' | nc -w1 %s %d"
                        % (marker, self.router_ip, HEARTBEAT_PORT),
                        topology=self.topology, host=self.atk_host)
                self._hb_seq += 1
                common.append_jsonl(
                    os.path.join(self.archive, HEARTBEAT_LEDGER),
                    {"seq": self._hb_seq, "marker": marker,
                     "ts_sent": common.now(),
                     "run": os.path.basename(self.archive)})
            except Exception:  # noqa: BLE001 - heartbeat must not kill thread
                pass
            self._stop.wait(HEARTBEAT_INTERVAL)

    # -- teardown ----------------------------------------------------------
    def stop(self):
        self._stop.set()
        for proc in self.tcpdumps or ([self.tcpdump] if self.tcpdump else []):
            if not proc:
                continue
            try:
                proc.send_signal(signal.SIGTERM)
                proc.wait(timeout=10)
            except Exception:  # noqa: BLE001
                proc.kill()
        if getattr(self, "capture_container", None):
            try:
                out = subprocess.run(
                    ["docker", "ps", "-a", "--format", "{{.Names}}"],
                    capture_output=True, text=True, timeout=20).stdout
                for cname in out.split():
                    if cname == self.capture_container or \
                            cname.startswith(self.capture_container + "-"):
                        subprocess.run(["docker", "rm", "-f", cname],
                                       capture_output=True, timeout=20)
            except Exception:  # noqa: BLE001
                pass
        # final hash sweep of any unmanifested pcaps
        manifested = {r.get("file") for r in common.read_jsonl(
            os.path.join(self.archive, MANIFEST))}
        for path in sorted(glob.glob(
                os.path.join(self.pcap_dir, "bridge_*.pcap"))):
            if os.path.basename(path) not in manifested:
                try:
                    common.append_jsonl(
                        os.path.join(self.archive, MANIFEST),
                        {"ts": common.now(), "file": os.path.basename(path),
                         "sha256": common.sha256_file(path),
                         "size": os.path.getsize(path),
                         "run": os.path.basename(self.archive)})
                except OSError:
                    continue

    @property
    def alive(self):
        return self.tcpdump is not None and self.tcpdump.poll() is None


# -- trust window -----------------------------------------------------------

def find_marker(pcap_files, marker):
    """True iff marker ASCII bytes appear in any pcap file's raw bytes."""
    needle = marker.encode("ascii") if isinstance(marker, str) else marker
    for path in pcap_files:
        try:
            with open(path, "rb") as fh:
                if needle in fh.read():
                    return True
        except OSError:
            continue
    return False


def trust_window(archive, t0, t1, pcap_files=None):
    """TRUSTED iff every heartbeat marker with ts_sent in [t0,t1] is found
    in the pcaps. No expected markers in window -> trusted (vacuous)."""
    ledger_path = os.path.join(archive, HEARTBEAT_LEDGER)
    markers = [r["marker"] for r in common.read_jsonl(ledger_path)
               if isinstance(r, dict) and t0 <= r.get("ts_sent", -1) <= t1]
    if not markers:
        return True
    if pcap_files is None:
        pcap_files = sorted(glob.glob(
            os.path.join(archive, "pcaps_host", "bridge_*.pcap")))
    return all(find_marker(pcap_files, m) for m in markers)
