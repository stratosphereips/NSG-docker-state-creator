"""streamkit battery: import-surface delegation + the five NEW parsers.

Two halves, mirroring analysis/streamkit.py:

- Delegation: every re-exported name must BE the frozen object (identity,
  not a copy), and the delegated collectors must behave identically to the
  frozen modules on real fixture evidence (one fixture per collector).
- New parsers: execveat argv (ExecveLine-equivalent + target resolution),
  zeek conn.log JSON, normalized ss lines, snapshots/objects
  content-addressed loads, and census CapEff deltas — each with tiny inline
  fixtures whose record shapes are copied from the collector sources
  (observer/bin/*) and the existing fixture corpus.
"""

from __future__ import annotations

import hashlib
import importlib
import json
import sys
from pathlib import Path

import pytest

TESTS_FM_DIR = Path(__file__).resolve().parent
REPO_ROOT = TESTS_FM_DIR.parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))
if str(TESTS_FM_DIR) not in sys.path:
    sys.path.insert(0, str(TESTS_FM_DIR))

from analysis import streamkit  # noqa: E402
from analysis.detectors import afm_4, fm_2_1, fm_2_3, fm_4_2  # noqa: E402
from analysis.observation import parse_strace_line, load_observation  # noqa: E402
from analysis.records import ExecveLine, SocketEvent, SyscallLine  # noqa: E402
from conftest import fixture_path  # noqa: E402

FIXTURES = TESTS_FM_DIR / "fixtures"

#: The standard Docker root CapEff mask and its capability names (closed-
#: form vector: 0x00000000a80425fb bits 0,1,3,4,5,6,7,8,10,13,18,27,29,31).
ROOT_MASK = "00000000a80425fb"
ROOT_CAPS = (
    "chown", "dac_override", "fowner", "fsetid", "kill", "setgid", "setuid",
    "setpcap", "net_bind_service", "net_raw", "sys_chroot", "mknod",
    "audit_write", "setfcap",
)


# ---------------------------------------------------------------------------
# Import surface: delegation is identity, never a copy
# ---------------------------------------------------------------------------


def test_delegations_resolve_to_the_frozen_objects():
    """Every DELEGATIONS entry is the origin module's object, by identity."""
    for public, origin in streamkit.DELEGATIONS.items():
        module_name, _, attr = origin.rpartition(".")
        module = importlib.import_module(module_name)
        assert getattr(streamkit, public) is getattr(module, attr), origin


def test_delegated_aliases_cover_the_underscore_spellings():
    """Implementers may use either spelling; both resolve identically."""
    assert streamkit.workload_tree is fm_2_3._workload_tree
    assert streamkit._workload_tree is streamkit.workload_tree
    assert streamkit.mutation_edges is fm_2_1._mutation_edges
    assert streamkit._mutation_edges is streamkit.mutation_edges
    assert streamkit.collect_bind_edges is afm_4._collect_bind_edges
    assert streamkit._collect_bind_edges is streamkit.collect_bind_edges
    assert streamkit.split_args is fm_4_2._split_args
    assert streamkit._split_args is streamkit.split_args


def test_streamkit_is_not_a_detector():
    """No FM_ID/detect: analyze.py auto-discovery must never pick it up."""
    assert not hasattr(streamkit, "FM_ID")
    assert not hasattr(streamkit, "detect")


def test_missing_trace_pids_matches_frozen_on_fixture():
    """trace-hole detection: identical call, identical result ((101,) is the
    clone result whose trace.PID was deleted in this fixture)."""
    obs = load_observation(fixture_path("fm_4_2/adv_tr_killer_trace_deleted"))
    via_kit = streamkit.missing_trace_pids(obs.strace, obs.strace_files)
    via_frozen = fm_4_2.missing_trace_pids(obs.strace, obs.strace_files)
    assert via_kit == via_frozen == (101,)


def test_workload_tree_matches_frozen_on_fixture():
    """Census ppid-closure fork fixpoint: same set, sensors excluded."""
    obs = load_observation(fixture_path("fm_2_3/sigstop_stall"))
    started = next(r for r in obs.supervisor if r.event == "workload_started")
    via_kit = streamkit.workload_tree(obs.processes, started.pid)
    via_frozen = fm_2_3._workload_tree(obs.processes, started.pid)
    assert via_kit == via_frozen == frozenset({99, 100, 101})
    assert 50 not in via_kit          # process-monitor sensor (ppid 1) stays out


def test_mutation_edges_matches_frozen_on_fixture():
    obs = load_observation(fixture_path("fm_2_1/fail_arming_rename"))
    via_kit = streamkit.mutation_edges(obs.strace)
    via_frozen = fm_2_1._mutation_edges(obs.strace)
    assert via_kit == via_frozen
    edges, truncated = via_kit
    assert len(edges) == 2 and truncated == 0
    assert all(isinstance(e, fm_2_1.MutEdge) for e in edges)


def test_collect_bind_edges_matches_frozen_on_fixture():
    obs = load_observation(fixture_path("afm_4/benign_control"))
    flags_kit: list = []
    flags_frozen: list = []
    via_kit = streamkit.collect_bind_edges(obs.strace, flags_kit)
    via_frozen = afm_4._collect_bind_edges(obs.strace, flags_frozen)
    assert via_kit == via_frozen and flags_kit == flags_frozen == []
    assert len(via_kit) == 1
    assert (via_kit[0].family, via_kit[0].addr, via_kit[0].port) == (
        "tcp", "127.0.0.1", 8080)


def test_kernel_paths_delegates():
    # frozen behavior verbatim: a plain -yy annotation resolves, the mount
    # form keeps its nested path text (streamkit's execveat_target is the
    # helper that splits path<mount-root>), and a bare token resolves
    # nothing.
    paths, truncated = streamkit.kernel_paths('3</var/log/x>')
    assert paths == ("/var/log/x",) and truncated is False
    mount_form, _ = streamkit.kernel_paths('3</var/log/x</log>')
    assert mount_form == ("/var/log/x</log",)
    assert streamkit.kernel_paths('"/tmp/f"')[0] == ("/tmp/f",)


# ---------------------------------------------------------------------------
# NEW (a): execveat argv
# ---------------------------------------------------------------------------


def _syscall(raw: str, file_pid: int = 100, seq: int = 1) -> SyscallLine:
    line = parse_strace_line(file_pid, seq, raw)
    assert isinstance(line, SyscallLine)
    return line


EXECVEAT_DIRFD = (
    '1757100002.100000 execveat(3</work>, "", ["/work/tool", "-l", "f"], '
    '0 /* NULL */ /* 0 vars */, AT_EMPTY_PATH) = 0 <0.000321>'
)
EXECVEAT_FDCWD_FAIL = (
    '1757100003.000000 execveat(AT_FDCWD</tmp>, "tool", ["tool", "-l"], '
    '0 /* NULL */, 0) = -1 ENOENT (No such file or directory)'
)


def test_parse_execveat_dirfd_argv():
    record = _syscall(EXECVEAT_DIRFD)
    line = streamkit.parse_execveat(record)
    assert isinstance(line, ExecveLine)
    assert line.argv == ("/work/tool", "-l", "f")
    assert line.truncated is False
    assert line.result_raw == "0"
    assert line.ts == pytest.approx(1757100002.1)
    assert line.file_pid == 100 and line.seq == 1
    assert line.raw == EXECVEAT_DIRFD


def test_parse_execveat_preserves_failure_result():
    line = streamkit.parse_execveat(_syscall(EXECVEAT_FDCWD_FAIL, seq=2))
    assert line.argv == ("tool", "-l")
    assert line.result_raw == "-1 ENOENT (No such file or directory)"
    assert line.seq == 2


def test_parse_execveat_truncated_argv():
    record = _syscall(
        '1757100004.000000 execveat(3</w>, "", ["/w/t", "aaaa"], '
        '0 /* NULL */, AT_EMPTY_PATH) = 0', seq=3)
    line = streamkit.parse_execveat(record)
    assert line.argv == ("/w/t", "aaaa")
    assert line.truncated is False
    record_trunc = _syscall(
        '1757100004.500000 execveat(3</w>, "", ["/w/t", "aaaa"...], '
        '0 /* NULL */, AT_EMPTY_PATH) = 0', seq=4)
    assert streamkit.parse_execveat(record_trunc).truncated is True


def test_parse_execveat_empty_and_missing_argv():
    empty = streamkit.parse_execveat(_syscall(
        '1757100005.000000 execveat(3</w>, "", [], NULL, AT_EMPTY_PATH) = 0'))
    assert empty.argv == () and empty.truncated is False
    degraded = streamkit.parse_execveat(_syscall(
        '1757100005.500000 execveat(3</w>, "", 0x7ffd, NULL,'
        ' AT_EMPTY_PATH) = 0'))
    assert degraded.argv is None


def test_parse_execveat_rejects_other_lines():
    execve = parse_strace_line(
        100, 1, '1757100000.000000 execve("/bin/true", ["/bin/true"],'
                ' /* 1 var */) = 0')
    assert isinstance(execve, ExecveLine)
    assert streamkit.parse_execveat(execve) is None
    base = parse_strace_line(100, 2, "1757100000.000000 nonsense")
    assert streamkit.parse_execveat(base) is None


def test_execveat_lines_filters_in_order():
    raws = [
        EXECVEAT_DIRFD,
        '1757100001.000000 execve("/bin/sh", ["/bin/sh"], /* 1 var */) = 0',
        '1757100001.500000 kill(60, SIGTERM) = 0',
        '1757100006.000000 execveat(AT_FDCWD, "/bin/id", ["/bin/id"], '
        '0 /* NULL */, 0) = 0',
    ]
    strace = tuple(parse_strace_line(100, i, raw) for i, raw in enumerate(raws, 1))
    lines = streamkit.execveat_lines(strace)
    assert len(lines) == 2
    assert all(isinstance(l, ExecveLine) for l in lines)
    assert lines[0].argv[0] == "/work/tool"
    assert lines[1].argv == ("/bin/id",)
    # untouched: the execve ExecveLine still rides along in the source tuple
    assert any(isinstance(r, ExecveLine) and r.argv == ("/bin/sh",)
               for r in strace)


def test_execveat_target_filename():
    target = streamkit.execveat_target(_syscall(EXECVEAT_FDCWD_FAIL))
    assert target.source == "filename"
    assert target.path == "tool"
    assert target.dirfd_path == "/tmp"
    assert "AT_EMPTY_PATH" not in target.flags


def test_execveat_target_dirfd_empty_path():
    target = streamkit.execveat_target(_syscall(EXECVEAT_DIRFD))
    assert target.source == "dirfd"
    assert target.path == "/work"
    assert target.filename == ""
    assert "AT_EMPTY_PATH" in target.flags


def test_execveat_target_dirfd_mount_annotation():
    record = _syscall(
        '1757100007.000000 execveat(3</work</bin>, "", ["/work/tool"], '
        'NULL, AT_EMPTY_PATH) = 0')
    target = streamkit.execveat_target(record)
    assert target.source == "dirfd"
    assert target.path == "/work"          # -yy mount form: path<mount-root>


def test_execveat_target_unresolved():
    # empty filename, no AT_EMPTY_PATH flag: the kernel resolves nothing we
    # can pin -- unresolved, never a guess.
    no_flag = streamkit.execveat_target(_syscall(
        '1757100008.000000 execveat(3</work>, "", ["/x"], NULL, 0) = -1 ENOENT'))
    assert no_flag.source == "unresolved" and no_flag.path == ""
    unannotated = streamkit.execveat_target(_syscall(
        '1757100008.500000 execveat(AT_FDCWD, "", ["/x"], NULL,'
        ' AT_EMPTY_PATH) = -1 ENOENT'))
    assert unannotated.source == "unresolved" and unannotated.path == ""
    assert streamkit.execveat_target(_syscall(
        '1757100009.000000 close(3) = 0')).source == "unresolved"


# ---------------------------------------------------------------------------
# NEW (b): zeek conn.log
# ---------------------------------------------------------------------------

CONN_LINES = [
    json.dumps({
        "ts": 1757100001.123456, "uid": "CzWJqK1MFmFpHkI0O8",
        "id.orig_h": "172.17.0.2", "id.orig_p": 51820,
        "id.resp_h": "10.10.0.5", "id.resp_p": 22,
        "proto": "tcp", "service": "ssh", "duration": 1.5,
        "orig_bytes": 512, "resp_bytes": 4096, "conn_state": "SF",
        "local_orig": True,
    }, sort_keys=True),
    json.dumps({
        "ts": 1757100002.0, "uid": "Czabc2345",
        "id.orig_h": "172.17.0.2", "id.orig_p": 51821,
        "id.resp_h": "10.10.0.7", "id.resp_p": 53,
        "proto": "udp", "service": "-", "conn_state": "SF",
    }, sort_keys=True),
    json.dumps({
        "ts": 1757100003.5, "uid": "Czdef6789",
        "id.orig_h": "172.17.0.2", "id.orig_p": 51822,
        "id.resp_h": "10.10.0.9", "id.resp_p": 8080,
        "proto": "tcp", "duration": 0.05,
    }, sort_keys=True),
    "{not json",
    "[1, 2, 3]",
]


def test_load_conn_log_parses_and_flags(tmp_path):
    path = tmp_path / "conn.log"
    path.write_text("\n".join(CONN_LINES) + "\n", encoding="utf-8")
    flags: list = []
    conns = streamkit.load_conn_log(path, flags)
    assert len(conns) == 3
    first = conns[0]
    assert first.seq == 1 and first.file == "conn.log"
    assert first.ts == pytest.approx(1757100001.123456)
    assert (first.orig_h, first.orig_p) == ("172.17.0.2", 51820)
    assert (first.resp_h, first.resp_p) == ("10.10.0.5", 22)
    assert first.proto == "tcp"
    assert first.duration == pytest.approx(1.5)
    assert first.service == "ssh"
    assert first.conn_state == "SF"
    assert '"uid": "CzWJqK1MFmFpHkI0O8"' in first.raw
    # zeek's "-" unset marker and absent fields are both None
    assert conns[1].service is None
    assert conns[1].proto == "udp"
    assert conns[2].service is None and conns[2].conn_state is None
    assert conns[2].duration == pytest.approx(0.05)
    assert len(flags) == 2
    assert any(f.startswith("STREAMKIT:conn_corrupt") for f in flags)
    assert any(f.startswith("STREAMKIT:conn_non_object") for f in flags)


def test_load_conn_log_missing_file_flags(tmp_path):
    flags: list = []
    assert streamkit.load_conn_log(tmp_path / "nope.log", flags) == ()
    assert flags == [f"STREAMKIT:conn_missing path={tmp_path / 'nope.log'}"]


def test_load_conn_dir_globs_only_conn_logs(tmp_path):
    (tmp_path / "conn.log").write_text(CONN_LINES[0] + "\n", encoding="utf-8")
    (tmp_path / "conn.19-20.log").write_text(
        CONN_LINES[2] + "\n", encoding="utf-8")
    (tmp_path / "zeek-console.log").write_text("boot ok\n", encoding="utf-8")
    (tmp_path / "known_hosts.log").write_text("{}\n", encoding="utf-8")
    flags: list = []
    conns = streamkit.load_conn_dir(tmp_path, flags)
    assert [c.file for c in conns] == ["conn.19-20.log", "conn.log"]
    assert all(c.uid for c in conns)
    assert flags == []


def test_load_conn_dir_missing_flags(tmp_path):
    flags: list = []
    assert streamkit.load_conn_dir(tmp_path / "zeek", flags) == ()
    assert flags == [f"STREAMKIT:conn_dir_missing path={tmp_path / 'zeek'}"]


def test_parse_conn_object_is_total():
    conn = streamkit.parse_conn_object(7, {"proto": 5, "id.orig_p": "x"})
    assert conn.seq == 7
    assert conn.proto == "5"            # coerced verbatim, never a crash
    assert conn.orig_p is None and conn.ts is None


# ---------------------------------------------------------------------------
# NEW (c): normalized ss-line records
# ---------------------------------------------------------------------------


def test_parse_ss_line_state_first_estab():
    line = ('ESTAB 0 0 127.0.0.1:41234 127.0.0.1:8080 '
            'users:(("curl",pid=102,fd=3))')
    rec = streamkit.parse_ss_line(line)
    assert rec.family == "tcp" and rec.netid == ""
    assert rec.state == "ESTAB"
    assert rec.local.addr == "127.0.0.1" and rec.local.port == 41234
    assert rec.peer.addr == "127.0.0.1" and rec.peer.port == 8080
    assert rec.pids == (102,)
    assert rec.processes == (streamkit.SsProcess("curl", 102, 3),)
    assert rec.degraded is False


def test_parse_ss_line_netid_v6():
    line = ('tcp6 ESTAB 0 0 172.17.0.2:41007 [2001:db8:cafe::1]:443 '
            'users:(("curl",pid=101,fd=3))')
    rec = streamkit.parse_ss_line(line)
    assert rec.netid == "tcp6" and rec.family == "tcp"
    assert rec.peer.addr == "2001:db8:cafe::1" and rec.peer.port == 443
    assert rec.peer.raw == "[2001:db8:cafe::1]:443"


def test_parse_ss_line_udp_listener_wildcards():
    line = 'udp UNCONN 0 0 0.0.0.0:68 0.0.0.0:* users:(("dhclient",pid=45,fd=6))'
    rec = streamkit.parse_ss_line(line)
    assert rec.family == "udp" and rec.state == "UNCONN"
    assert rec.local.addr == "*"          # frozen afm_4 wildcard normalization
    assert rec.local.port == 68
    assert rec.peer.addr == "*" and rec.peer.port is None


def test_parse_ss_line_time_wait_no_users():
    line = "TIME-WAIT 0 0 172.17.0.2:40122 203.0.113.50:443"
    rec = streamkit.parse_ss_line(line)
    assert rec.family == "tcp"
    assert rec.processes == () and rec.pids == ()
    assert rec.recv_q == 0 and rec.send_q == 0


def test_parse_ss_line_degrades_closed():
    short = streamkit.parse_ss_line("LISTEN 0 128")
    assert short.degraded is True
    assert short.local is None and short.peer is None
    assert short.family == ""             # nothing guessed
    assert streamkit.parse_ss_line("") is None


def test_parse_socket_events_stamps_census_join():
    events = (
        SocketEvent(seq=3, ts=1757200003.0, kind="connection_seen",
                    socket='ESTAB 0 0 127.0.0.1:41234 127.0.0.1:8080 '
                           'users:(("curl",pid=102,fd=3))'),
        SocketEvent(seq=4, ts=1757200004.0, kind="connection_gone",
                    socket="garbage-not-a-line"),
    )
    flags: list = []
    records = streamkit.parse_socket_events(events, flags)
    assert records[0].seq == 3 and records[0].ts == 1757200003.0
    assert records[0].kind == "connection_seen"
    assert records[0].pids == (102,)
    assert records[1].degraded is True and records[1].kind == "connection_gone"
    assert flags == ["STREAMKIT:ss_unparsed seq=4 kind=connection_gone"]


# ---------------------------------------------------------------------------
# NEW (d): snapshots/objects content-addressed archive
# ---------------------------------------------------------------------------


def _write_object(objects_dir: Path, content: bytes,
                  checksum: str = "") -> str:
    checksum = checksum or hashlib.sha256(content).hexdigest()
    target = objects_dir / checksum[:2] / checksum
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(content)
    return checksum


def test_object_path_layout_and_contract(tmp_path):
    sha = "ab" * 32
    assert streamkit.object_path(tmp_path, sha) == tmp_path / "ab" / sha
    with pytest.raises(ValueError):
        streamkit.object_path(tmp_path, "not-a-sha")


def test_load_and_verify_object_roundtrip(tmp_path):
    content = b"evidence line\n"
    checksum = _write_object(tmp_path, content)
    assert streamkit.load_object(tmp_path, checksum) == content
    assert streamkit.load_verified_object(tmp_path, checksum) == content
    assert streamkit.object_text(tmp_path, checksum) == "evidence line\n"


def test_verified_read_fails_closed_on_tamper(tmp_path):
    content = b"original"
    checksum = _write_object(tmp_path, content)
    (tmp_path / checksum[:2] / checksum).write_bytes(b"tampered")
    flags: list = []
    assert streamkit.load_verified_object(tmp_path, checksum, flags) is None
    assert len(flags) == 1 and flags[0].startswith(
        f"STREAMKIT:object_corrupt checksum={checksum} content=")
    # the unverified read still hands over the bytes (deciding evidence must
    # go through the verified read; raw access stays available for notes)
    assert streamkit.load_object(tmp_path, checksum) == b"tampered"


def test_missing_object_flags(tmp_path):
    flags: list = []
    sha = "cd" * 32
    assert streamkit.load_object(tmp_path, sha, flags) is None
    assert streamkit.object_text(tmp_path, sha, flags) is None
    assert streamkit.load_verified_object(tmp_path, sha, flags) is None
    assert flags == [f"STREAMKIT:object_missing checksum={sha}"] * 3


def test_list_objects_verifies_and_flags_layout(tmp_path):
    good = _write_object(tmp_path, b"good")
    # an object whose name is a valid sha256 but NOT the hash of its
    # content, filed under the wrong prefix directory
    misfiled_name = hashlib.sha256(b"expected content").hexdigest()
    misfiled = tmp_path / "zz" / misfiled_name
    misfiled.parent.mkdir(parents=True, exist_ok=True)
    misfiled.write_bytes(b"actual content")
    stray = tmp_path / "README"
    stray.write_text("x", encoding="utf-8")
    badname = tmp_path / "gg" / "not-hex"
    badname.parent.mkdir(parents=True, exist_ok=True)
    badname.write_text("x", encoding="utf-8")
    flags: list = []
    objects = streamkit.list_objects(tmp_path, flags)
    by_checksum = {o.checksum: o for o in objects}
    assert by_checksum[good].matches is True
    assert by_checksum[good].content_sha256 == good
    assert by_checksum[misfiled_name].matches is False
    assert len(objects) == 2               # not-hex is skipped, not listed
    assert any(f.startswith("STREAMKIT:object_corrupt") for f in flags)
    assert any(f.startswith("STREAMKIT:object_prefix_mismatch") for f in flags)
    assert any(f.startswith("STREAMKIT:object_layout_bad path=README")
               for f in flags)
    assert any(f.startswith("STREAMKIT:object_layout_bad path=gg/not-hex")
               for f in flags)
    unverified = streamkit.list_objects(tmp_path, None, verify=False)
    assert {o.matches for o in unverified} == {None}


def test_list_objects_missing_dir_flags(tmp_path):
    flags: list = []
    assert streamkit.list_objects(tmp_path / "objects", flags) == ()
    assert flags == [
        f"STREAMKIT:object_dir_missing path={tmp_path / 'objects'}"]


# ---------------------------------------------------------------------------
# NEW (e): census CapEff deltas
# ---------------------------------------------------------------------------


def _cap_obj(event: str, effective: str, previous_effective: str = "",
             pid: int = 60, ticks: str = "90", seq_ts: float = 1757100005.0,
             with_caps: bool = True) -> dict:
    obj = {
        "event": event, "pid": pid, "start_ticks": ticks,
        "timestamp": seq_ts, "name": "ids-daemon",
        "cmdline": "ids-daemon --watch /x", "state": "S",
    }
    if with_caps:
        obj["capabilities"] = {
            "inheritable": "0" * 16, "permitted": effective,
            "effective": effective, "bounding": ROOT_MASK,
            "ambient": "0" * 16,
        }
    if event == "process_changed" and previous_effective is not None:
        previous = dict(obj)
        if with_caps:
            previous["capabilities"] = dict(obj["capabilities"])
            previous["capabilities"]["effective"] = previous_effective
            previous["capabilities"]["permitted"] = previous_effective
        obj["previous"] = previous
    return obj


def test_capability_names_of_docker_root_mask():
    assert streamkit.capability_names(ROOT_MASK) == ROOT_CAPS
    assert streamkit.capability_names("0" * 16) == ()
    assert streamkit.capability_names("0" * 15 + "2") == ("dac_override",)
    assert streamkit.capability_names("0x" + ROOT_MASK) == ROOT_CAPS


def test_capability_names_unknown_bit():
    # bit 56 is beyond the frozen kernel table: cap<index>, never a guess
    assert streamkit.capability_names("01" + "0" * 14) == ("cap56",)


def test_capability_names_unparsable_is_empty():
    assert streamkit.capability_names("zzzz") == ()
    assert streamkit.capability_names(None) == ()
    assert streamkit.capability_names(True) == ()


def test_cap_effective_changes_raise_and_drop():
    records = [
        (1, _cap_obj("process_seen", "0" * 16)),
        (2, _cap_obj("process_changed", ROOT_MASK,
                     previous_effective="0" * 16)),
        (3, _cap_obj("process_changed", "0" * 16,
                     previous_effective=ROOT_MASK)),
        (4, _cap_obj("process_changed", ROOT_MASK,
                     previous_effective=ROOT_MASK)),
    ]
    deltas = streamkit.cap_effective_changes(records)
    assert len(deltas) == 2                # equal masks yield nothing
    raised, dropped = deltas
    assert raised.seq == 2 and raised.pid == 60 and raised.start_ticks == "90"
    assert raised.previous == "0" * 16 and raised.current == ROOT_MASK
    assert raised.raised == ROOT_CAPS and raised.dropped == ()
    assert raised.degraded is False
    assert dropped.seq == 3
    assert dropped.dropped == ROOT_CAPS and dropped.raised == ()
    assert raised.ts == pytest.approx(1757100005.0)


def test_cap_effective_changes_degrades_closed():
    stripped = _cap_obj("process_changed", ROOT_MASK,
                        previous_effective=ROOT_MASK, with_caps=False)
    unparsable = _cap_obj("process_changed", "zzzz",
                          previous_effective="0" * 16)
    flags: list = []
    deltas = streamkit.cap_effective_changes(
        [(5, stripped), (6, unparsable)], flags)
    assert len(deltas) == 2
    assert all(d.degraded for d in deltas)
    assert all(d.raised == () and d.dropped == () for d in deltas)
    assert "STREAMKIT:cap_field_missing seq=5" in flags
    assert "STREAMKIT:cap_mask_unparsable seq=6" in flags


def test_cap_effective_changes_accepts_bare_dicts():
    deltas = streamkit.cap_effective_changes([
        _cap_obj("process_changed", ROOT_MASK, previous_effective="0" * 16),
    ])
    assert len(deltas) == 1 and deltas[0].seq == 1


def _fixture_caps(pid: int, effective: str) -> dict:
    """Collector-shaped census line (copied from fm_4_2 fixtures)."""
    caps = {"ambient": "0" * 16, "bounding": "0" * 16, "effective": effective,
            "inheritable": "0" * 16, "permitted": effective}
    return {
        "capabilities": caps, "cgroup": "0::/", "cmdline": "ids-daemon",
        "cwd": "/", "event": "process_changed", "exe": "/usr/bin/ids-daemon",
        "gid": ["0", "0", "0", "0"], "loginuid": "-1", "name": "ids-daemon",
        "no_new_privs": "0", "pid": pid, "ppid": 1,
        "previous": {"capabilities": dict(caps, effective="0" * 16),
                     "cgroup": "0::/", "cmdline": "ids-daemon --old",
                     "exe": "/usr/bin/ids-daemon", "name": "ids-daemon",
                     "pid": pid, "ppid": 1, "seccomp": "0",
                     "sessionid": "60", "start_ticks": "90", "state": "S",
                     "uid": ["0", "0", "0", "0"], "username": "root"},
        "root": "/", "seccomp": "0", "sessionid": "60",
        "source": "process-monitor", "start_ticks": "90", "state": "S",
        "timestamp": 1757100005.9, "tty_nr": "0",
        "uid": ["0", "0", "0", "0"], "username": "root",
    }


def test_load_cap_changes_end_to_end(tmp_path):
    path = tmp_path / "processes.jsonl"
    lines = [
        {"event": "monitor_started", "interval_seconds": 0.1,
         "source": "process-monitor", "timestamp": 1757100000.05},
        _fixture_caps(60, ROOT_MASK),
        {"event": "process_seen", "pid": 61, "start_ticks": "91",
         "source": "process-monitor", "timestamp": 1757100001.0},
    ]
    path.write_text(
        "".join(json.dumps(l, sort_keys=True) + "\n" for l in lines),
        encoding="utf-8")
    flags: list = []
    deltas = streamkit.load_cap_changes(path, flags)
    assert flags == []
    assert len(deltas) == 1
    assert deltas[0].seq == 2              # line 2 of the file
    assert deltas[0].raised == ROOT_CAPS
    assert deltas[0].pid == 60 and deltas[0].start_ticks == "90"


def test_load_cap_changes_missing_file_flags(tmp_path):
    flags: list = []
    assert streamkit.load_cap_changes(tmp_path / "processes.jsonl", flags) == ()
    assert len(flags) == 1
    assert flags[0].startswith("STREAMKIT:processes:stream_missing")
