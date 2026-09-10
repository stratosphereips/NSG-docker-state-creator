"""Shared fixtures for the FM lab e2e tests (live topology, NO LLM).

DESIGN §4: fixture `lab` ensures the topology is up once per session, resolves
IPs, provides an archive factory per test, and start/stop helpers around
sms.run_controller. Scenario/defender/attacker_action helpers wrap the sms
modules so individual tests stay short.

Skips the whole module set when the topology is unreachable AND SMS_SKIP_E2E
is set (CI / laptop runs without docker).
"""
import json
import os
import subprocess
import sys
import time
import uuid

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", ".."))
LAB = os.path.join(ROOT, "lab")
for p in (ROOT, LAB):
    if p not in sys.path:
        sys.path.insert(0, p)

TOPOLOGY = "fm-defender-lab"


def _reachable():
    proc = subprocess.run(
        ["docker", "ps", "--filter", "label=scl.topology=%s" % TOPOLOGY,
         "--format", "{{.Names}}"],
        capture_output=True, text=True, timeout=30)
    return len(proc.stdout.split()) >= 3


class LabHandle:
    """Per-session live-lab handle."""

    topology = TOPOLOGY

    def ips(self):
        from sms import common  # noqa: PLC0415
        return common.docker_ps(TOPOLOGY)

    def atk_ip(self):
        return (self.ips().get("atk") or {}).get("ip", "")

    def archive(self, tmp_path):
        run = "run_%s" % uuid.uuid4().hex[:8]
        path = os.path.abspath(os.path.join(str(tmp_path), run))
        os.makedirs(path, exist_ok=True)
        return path

    def start_run(self, archive, interval=2.0):
        """Start the in-process run controller (baselines + prober thread +
        host capture + heartbeat). Returns the controller handle with .stop()."""
        from sms import run_controller  # noqa: PLC0415
        return run_controller.start(archive, TOPOLOGY, interval=interval)

    def stop_run(self, archive, handle=None):
        from sms import run_controller  # noqa: PLC0415
        if handle is not None:
            try:
                handle["stop"]()
            except Exception:  # noqa: BLE001
                pass
        return run_controller.stop(archive)


@pytest.fixture(scope="session")
def lab():
    if not _reachable():
        if os.environ.get("SMS_SKIP_E2E"):
            pytest.skip("topology unreachable and SMS_SKIP_E2E set")
        proc = subprocess.run(
            [sys.executable, os.path.join(LAB, "deploy_lab.py"), "ensure-up"],
            timeout=1200)
        if proc.returncode != 0 or not _reachable():
            pytest.fail("deploy_lab.py ensure-up failed (rc=%d); run it "
                        "manually for details" % proc.returncode)
    # the router exfil sink (:4444 -> /srv/exfil/received.log) is runtime
    # state, not baked in the image — ensure it for FM5.1 regardless of how
    # long ago the topology came up
    sys.path.insert(0, LAB)
    import deploy_lab  # noqa: PLC0415
    err = deploy_lab.ensure_exfil_sink()
    if err:  # returns None on success, an error string otherwise
        pytest.fail("router exfil sink not listening on :4444 (%s)" % err)
    return LabHandle()


@pytest.fixture()
def scenario(lab, tmp_path):
    """Write units (+ optional planner_health) into a fresh archive; returns
    (archive, unit_records)."""
    from sms import units  # noqa: PLC0415

    def build(units_in, planner_health=None):
        archive = lab.archive(tmp_path)
        payload = {"units": units_in}
        if planner_health:
            payload["planner_health"] = planner_health
        recs = units.from_scenario(archive, payload)
        return archive, recs

    return build


@pytest.fixture()
def defender(lab):
    """Bound scripted-defender executor: defender(archive, host, command)."""
    from sms import scripted_defender  # noqa: PLC0415
    return scripted_defender.execute


@pytest.fixture()
def attacker_action(lab):
    """Run a command on atk via docker exec + append an attacker ledger row.
    Returns (rc, stdout, stderr); ledger row is appended to the archive when
    given."""
    from sms import common, ledger  # noqa: PLC0415

    def run(cmd, archive=None, action_class="exploit", detail=None,
            timeout=60):
        rc, out, err = common.docker_exec(
            None, cmd, topology=TOPOLOGY, host="atk", timeout=timeout)
        if archive:
            ledger.record(archive, "attacker", action_class, "atk",
                          dict(detail or {}, command=cmd, exit_code=rc))
        return rc, out, err

    return run


@pytest.fixture()
def write_json():
    def write(path, obj):
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(obj, fh, indent=2)
        return path

    return write


def unit(unit_id, hosts, t_alert, t_done, status="complete",
         attack_type="exploit", attacker_ip="", t_plan=None,
         t_exec_start=None, t_exec_end=None):
    """Canonical unit-dict builder used by every e2e scenario."""
    return {
        "unit_id": unit_id,
        "hosts": hosts,
        "attacker_ip": attacker_ip,
        "attack_type": attack_type,
        "t_alert": t_alert,
        "t_plan": t_plan if t_plan is not None else t_alert + 1.0,
        "t_exec_start": t_exec_start if t_exec_start is not None else t_alert + 2.0,
        "t_exec_end": t_exec_end if t_exec_end is not None else t_done - 1.0,
        "t_done": t_done,
        "status": status,
        "integrity": [],
    }


def planner_ok(ts):
    return {"ts": ts, "ok": True, "detail": "test-mode planner healthy"}


# ---------------------------------------------------------------------------
# DESIGN4 LANE ISOLATION helpers (cross-lane noise on the shared live lab)
# ---------------------------------------------------------------------------

LANE_LOCK = "/tmp/sms_lane.lock"


class lane_lock:  # noqa: N801 (context-manager class)
    """Serialize a sensitive window across the parallel e2e lanes.

    DESIGN4 LANE ISOLATION: "serialize just that case via a lock file
    /tmp/sms_lane.lock (flock) around the sensitive window". Blocking
    (retries LOCK_NB until `timeout`, then raises TimeoutError).
    """

    def __init__(self, timeout=60.0, poll=0.5):
        self.timeout = timeout
        self.poll = poll
        self.fh = None

    def __enter__(self):
        import fcntl
        self.fh = open(LANE_LOCK, "a+")
        deadline = time.monotonic() + self.timeout
        while True:
            try:
                fcntl.flock(self.fh.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                return self
            except OSError:
                if time.monotonic() >= deadline:
                    self.fh.close()
                    raise TimeoutError(
                        "lane lock %s busy for >%.0fs (sibling lane holding a "
                        "sensitive window)" % (LANE_LOCK, self.timeout))
                time.sleep(self.poll)

    def __exit__(self, *exc):
        import fcntl
        try:
            fcntl.flock(self.fh.fileno(), fcntl.LOCK_UN)
        finally:
            self.fh.close()
        return False


def server_health_ok(lab, timeout=180.0, poll=3.0):
    """Server /health == 200 from the ATK vantage, retried over `timeout`.

    CROSS-LANE NOISE (2026-08-27, observed live in the combined LANE1 run):
    the atk->server path crosses the router, and LANE2's fm43/fm72 arms
    legitimately insert a transient `ip saddr <atk_ip> drop` forward rule
    (removed again in their finally). A single-shot curl from atk therefore
    false-fails LANE1 health asserts while such a rule is live. Retry under
    the shared lane lock instead of weakening the vantage: the assertion
    still requires a 200 observed from atk, just tolerant of the sibling
    lane's bounded rule lifetime.
    """
    from sms import common  # noqa: PLC0415
    ip = (lab.ips().get("server") or {}).get("ip", "")
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with lane_lock(timeout=60.0):
                rc, out, _ = common.docker_exec(
                    None,
                    "curl -s -m 3 -o /dev/null -w '%%{http_code}' "
                    "http://%s/health" % ip,
                    topology=TOPOLOGY, host="atk")
                if (out or "").strip() == "200":
                    return True
        except TimeoutError:
            pass  # sibling lane mid-sensitive-window; keep retrying
        time.sleep(poll)
    return False
