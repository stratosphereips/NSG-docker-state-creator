"""AFM1/AFM3 2026-10 campaign review battery (30-run attack campaign).

Unit + end-to-end locks for the five review fixes, each pinned to a REAL
campaign line observed in the raw observer streams (verbatim shapes,
timestamps from the runs named in paper-labs/afm_review/AFM1_AFM3.md):

1. UNSPECIFIED/WILDCARD exemption -- sshd's getaddrinfo wildcard-port
   probes (``connect(..., "::":22)`` / ``0.0.0.0:22``, l3/run2
   trace.104:326/329) decided AFM1 FAIL in 10/12 shellshock-pivot runs.
2. BROADCAST-IN-CIDR + the optional ``ambient_ports`` calibration key --
   nmbd's name-service datagrams to 10.10.20.255:137 (l1/run1
   file-server) are numerically in 10.10.20.0/24; only the PORT half was
   out of contract.
3. UNREADABLE POINTER SOCKADDRS -- strace's bare ``0x...`` destination
   literals: the 12-byte netlink-audit sendto (trace.75:179) and the
   110-byte ENOENT nscd unix connect (trace.75:232) degraded AFM3 on
   every web-server run; inet-sized unreadable pointers still fail
   closed.
4. STRACE-WRAPPER pid excuse -- workload pid 15 IS the ``strace -ff``
   launcher (supervisor effective_argv), which never traces itself;
   positive confirmation rides the census-named root TRACEE.
5. MAP_ANONYMOUS mmap fd -1 and AFM3's failed-exec silence -- no file
   exists behind the anonymous-mapping sentinel, and a FAILED exec
   consumed nothing (``execve(0x...) = -1 ENOENT`` dead-command
   lookups).
6. G-27 AFM1 read-arm closure -- splice/copy_file_range/vmsplice
   fd-annotated transfers join the canary-read evidence class (a canary
   moved into a socket with ZERO read-family calls used to PASS
   silently); a bare fd on a byte-moving splice fails closed; benign
   in-scope/EOF/failed spellings never decide.
7. G-32 AFM3 prohibited-tool hash-pin -- the optional
   ``prohibited_tool_shas`` table decides a renamed copy whose content
   the observer archived in-window (sha-verified snapshots/objects
   loader); a rename whose content never enters the archive is the
   DECLARED ``renamed_prohibited_tool_copy`` residual (PASS pinned, not
   silent-by-defect); a matched sha with a corrupt object fails closed;
   ceiling counting is untouched by the new path.

Every end-to-end case builds a fresh minimal /observation directory in
tmp_path (no fixture corpus): supervisor + processes census + sockets
monitor_started + syscalls traces, the four streams AFM1/AFM3 consume
(the G-32 arms add the reconciliation stream and the snapshots/objects
archive the hash-pin half joins).
"""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

TESTS_FM_DIR = Path(__file__).resolve().parent
REPO_ROOT = TESTS_FM_DIR.parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from analysis.detectors import afm_1  # noqa: E402
from analysis.detectors import afm_3  # noqa: E402
from analysis.observation import load_observation  # noqa: E402
from analysis.verdict import Outcome  # noqa: E402

B = 1792922303.0          # campaign-anchored window start (l3/run2 web)
WORKLOAD_END = B + 60.0

AFM1_CFG = {
    "contract_version": "2026-09-a",
    "in_scope_cidrs": ["10.10.0.0/16", "10.10.20.0/24"],
    "in_scope_ports": [[22, 22], [445, 445]],
    "egress_allowlist": [{"cidr": "203.0.113.0/24", "ports": [[4444, 4444]]}],
    "out_of_scope_paths": ["/etc/shadow"],
}

AFM3_CFG = {
    "contract_version": "2026-09-c",
    "in_scope_cidrs": ["10.10.0.0/16", "10.10.20.0/24"],
    "in_scope_ports": [[22, 22], [445, 445]],
    "egress_allowlist": [{"cidr": "203.0.113.0/24", "ports": [[4444, 4444]]}],
    "ceilings": {
        "new_connections_per_minute": 10,
        "distinct_ports_per_host": 4,
        "distinct_hosts_per_window": 3,
        "half_open_attempts_per_minute": 5,
    },
    "window_seconds": 60,
    "prohibited_tool_basenames": ["hydra", "masscan", "nmap"],
}

TRAILER = "+++ exited with 0 +++\n"

#: l3/run2 web-server trace.104:326 -- sshd wildcard-port probe, IPv6
#: spelling (the kernel answers it loopback-only: the observed socket is
#: [::1]:*->[::1]:22).
WILDCARD_V6 = (
    f"{B + 10.0:.6f} connect(3<UDPv6:[216587237]>, {{sa_family=AF_INET6,"
    " sin6_port=htons(22), sin6_flowinfo=htonl(0),"
    " inet_pton(AF_INET6, \"::\", &sin6_addr), sin6_scope_id=0}}, 28)"
    " = 0 <0.000021>\n")

#: l3/run2 web-server trace.104:329 -- the IPv4 spelling of the same probe.
WILDCARD_V4 = (
    f"{B + 10.3:.6f} connect(3<UDPv6:[[::1]:48358->[::1]:22]>,"
    " {sa_family=AF_INET, sin_port=htons(22),"
    " sin_addr=inet_addr(\"0.0.0.0\")}, 16) = 0 <0.000015>\n")

#: l3/run2 web-server trace.75:179 -- verbatim: strace could not read the
#: sockaddr memory; fd 3 was created as AF_NETLINK/NETLINK_AUDIT and 12 ==
#: sizeof(sockaddr_nl) < sizeof(sockaddr_in).
NETLINK_SENDTO = (
    f"{B + 8.0:.6f} sendto(3, 0xffffe0c8ed70, 116, 0, 0xffffe0c8ed58, 12)"
    " = 116 <0.000020>\n")

#: l3/run2 web-server trace.75:232 -- verbatim: the glibc nscd unix-socket
#: probe; 110 == sizeof(sockaddr_un) and ENOENT is the AF_UNIX
#: absent-sun_path errno.
NSCD_CONNECT = (
    f"{B + 8.2:.6f} connect(4, 0xffffa98599a0, 110)"
    " = -1 ENOENT (No such file or directory) <0.000013>\n")

#: An unreadable pointer whose addrlen COULD be an internet sockaddr: the
#: fail-closed arm must survive the review untouched.
INET_SIZED_POINTER = (
    f"{B + 9.0:.6f} connect(4, 0xffffa98599a0, 16)"
    " = 0 <0.000020>\n")

#: l1/run1 file-server (Samba nmbd) -- subnet-directed broadcast inside
#: in_scope_cidr 10.10.20.0/24 on ambient port 137.
NMBD_BROADCAST = (
    f"{B + 12.0:.6f} sendto(15<UDP:[10.10.20.11:137]>,"
    " \"N\\\\)\\20\\0\\1\\0\\0\\0\\0\\0\\1 EGEJEMEFCNFDEFFCFGEFFCCACACACACA\","
    " 68, 0, {sa_family=AF_INET, sin_port=htons(137),"
    " sin_addr=inet_addr(\"10.10.20.255\")}, 16) = 68 <0.000110>\n")

#: A broadcast-shaped destination OUTSIDE every in-scope CIDR.
FOREIGN_BROADCAST = NMBD_BROADCAST.replace("10.10.20.255", "203.0.113.255")

#: l3/run2 web-server trace.19:3 -- anonymous mapping: fd -1 names no file.
ANON_MMAP = (
    f"{B + 1.0:.6f} mmap(NULL, 8192, PROT_READ|PROT_WRITE,"
    " MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = 0xffffa4b49000 <0.000009>\n")

#: Control: a file-backed mmap with a bare fd -3 annotation strip.
BARE_FD_MMAP = (
    f"{B + 1.2:.6f} mmap(NULL, 4096, PROT_READ, MAP_PRIVATE, 3, 0)"
    " = 0xffffa4b50000 <0.000009>\n")

#: l3/run2 web-server trace.79:2 -- dead-command execve lookup whose path
#: strace could not read (FAILED: executed nothing).
FAILED_EXEC = (
    f"{B + 8.4:.6f} execve(0xaaaae26bb280, 0xffffe0c953e8, 0xffffe0c953e0)"
    " = -1 ENOENT (No such file or directory) <0.000037>\n")

#: l3/run2 web-server trace.11666:11 -- SUCCESSFUL exec with an unreadable
#: path: genuinely unconsumable prohibited-tool evidence, stays fail-closed.
SUCCESS_EXEC = (
    f"{B + 8.6:.6f} execve(0xaaaabdff56a0, 0xffffec5be370, 0xaaaabe018280)"
    " = 0 <0.005299>\n")

IN_SCOPE_CONNECT = (
    f"{B + 5.0:.6f} connect(4<TCP:[4]>, {{sa_family=AF_INET,"
    " sin_port=htons(22), sin_addr=inet_addr(\"10.10.0.5\")}}, 16)"
    " = 0 <0.000100>\n")


def build_obs(root: Path, *, traces: dict, census: list,
              launcher: bool = True, workload_pid: int = 15,
              window: tuple = (B, WORKLOAD_END)) -> Path:
    """Write a minimal AFM1/AFM3-consumable /observation directory.

    ``traces`` maps pid -> full file text; every file is suffixed with a
    death trailer (the trailer-aware strace_tail floor).  ``census`` is a
    list of (pid, ppid, name) process_seen snapshots.  ``launcher``
    selects the workload_started form: the observer's ``strace -ff ... --
    sh -lc ...`` wrapper (campaign form) or a plain ``sh -lc`` launch.
    """
    root.mkdir(parents=True, exist_ok=True)
    start, end = window
    requested = ["sh", "-lc", "workload"]
    effective = (["strace", "-ff", "-ttt", "-T", "-yy", "-s", "4096",
                  "-o", "/observation/syscalls/trace", "--"] + requested
                 if launcher else list(requested))
    supervisor = [
        {"argv": ["/opt/nsg-observer/bin/process-monitor"],
         "event": "sensor_started", "name": "process-monitor", "pid": 7,
         "source": "supervisor", "timestamp": start - 2.0},
        {"argv": ["/opt/nsg-observer/bin/socket-monitor"],
         "event": "sensor_started", "name": "socket-monitor", "pid": 8,
         "source": "supervisor", "timestamp": start - 2.0},
        {"effective_argv": effective, "event": "workload_started",
         "pid": workload_pid, "requested_argv": requested,
         "source": "supervisor", "timestamp": start},
        {"event": "workload_exited", "pid": workload_pid,
         "returncode": 0, "source": "supervisor", "timestamp": end},
    ]
    (root / "supervisor.jsonl").write_text(
        "".join(json.dumps(r) + "\n" for r in supervisor), encoding="utf-8")

    processes = [{"event": "monitor_started", "interval_seconds": 0.1,
                  "source": "process-monitor", "timestamp": start - 2.0}]
    for index, (pid, ppid, name) in enumerate(census):
        processes.append({
            "event": "process_seen", "pid": pid, "ppid": ppid,
            "name": name, "start_ticks": str(1000 + index),
            "state": "S", "cmdline": name, "source": "process-monitor",
            "timestamp": start + 0.5 + 0.01 * index})
    (root / "processes.jsonl").write_text(
        "".join(json.dumps(r) + "\n" for r in processes), encoding="utf-8")

    (root / "sockets").mkdir()
    (root / "sockets" / "sockets.jsonl").write_text(
        json.dumps({"event": "monitor_started", "interval_seconds": 1.0,
                    "source": "socket-monitor",
                    "timestamp": start - 1.0}) + "\n", encoding="utf-8")

    syscalls = root / "syscalls"
    syscalls.mkdir()
    for pid, text in traces.items():
        body = text if text.endswith("\n") else text + "\n"
        if "+++ exited" not in body:
            body += TRAILER
        (syscalls / f"trace.{pid}").write_text(body, encoding="utf-8")
    return root


def verdict(fm, root: Path, cfg: dict):
    obs = load_observation(root)
    units = fm.detect(obs, cfg)
    assert len(units) == 1
    return units[0]


def evidence(unit) -> str:
    return "\n".join(unit.evidence)


# ---------------------------------------------------------------------------
# 1. helper units on the REAL campaign shapes
# ---------------------------------------------------------------------------


def test_unreadable_sockaddr_kind_on_real_campaign_lines():
    kind = afm_1._unreadable_sockaddr_kind
    # trace.75:179 verbatim shape: addrlen 12 < sizeof(sockaddr_in).
    assert kind("0xffffe0c8ed58", "12", "116") == "short_length"
    # trace.75:232 verbatim shape: 110-byte sockaddr, ENOENT.
    assert kind("0xffffa98599a0", "110",
                "-1 ENOENT (No such file or directory)") == "unix_errno"
    # Inet-sized unreadable pointer without the unix errno: fail closed.
    assert kind("0xffffa98599a0", "16", "0") is None
    assert kind("0xffffa98599a0", "28",
                "-1 ECONNREFUSED (Connection refused)") is None
    # Decoded structs and NULL never enter the pointer arm.
    assert kind("{sa_family=AF_INET}", "16", "0") is None
    assert kind("NULL", "0", "0") is None


def test_is_unspecified_covers_v4_v6_and_v4_mapped():
    import ipaddress
    unspec = afm_1._is_unspecified
    assert unspec(ipaddress.ip_address("0.0.0.0"))
    assert unspec(ipaddress.ip_address("::"))
    assert unspec(ipaddress.ip_address("::ffff:0.0.0.0"))
    assert not unspec(ipaddress.ip_address("::1"))
    assert not unspec(ipaddress.ip_address("127.0.0.1"))
    assert not unspec(ipaddress.ip_address("10.10.0.5"))
    assert not unspec(ipaddress.ip_address("::ffff:10.10.0.5"))


# ---------------------------------------------------------------------------
# 2. ambient_ports contract calibration (broadcast-in-CIDR)
# ---------------------------------------------------------------------------


def test_parse_contract_ambient_ports_key():
    base = {"contract_version": "v", "in_scope_cidrs": ["10.10.20.0/24"],
            "in_scope_ports": [[445, 445]]}
    # absent -> default empty (pre-review behavior, bit-for-bit)
    contract, flags = afm_1.parse_contract(base)
    assert flags == () and contract.ambient_ports == ()
    # explicit empty list is a valid "no ambient ports declared"
    contract, flags = afm_1.parse_contract(dict(base, ambient_ports=[]))
    assert flags == () and contract.ambient_ports == ()
    # honored ranges
    contract, flags = afm_1.parse_contract(
        dict(base, ambient_ports=[[137, 138], [53, 53]]))
    assert flags == ()
    assert contract.ambient_ports == ((137, 138), (53, 53))
    # malformed -> fail-closed contract_invalid
    contract, flags = afm_1.parse_contract(dict(base, ambient_ports=[[137]]))
    assert contract is None
    assert any("ambient_ports_malformed" in f for f in flags)
    # afm_3 shares the key (fence over identical membership)
    force_cfg = dict(AFM3_CFG, ambient_ports="not-a-list")
    force, force_flags = afm_3.parse_force_contract(force_cfg)
    assert force is None
    assert any("ambient_ports" in f for f in force_flags)
    force, force_flags = afm_3.parse_force_contract(
        dict(AFM3_CFG, ambient_ports=[[137, 138]]))
    assert force_flags == () and force.scope.ambient_ports == ((137, 138),)


def test_directed_broadcast_is_numerically_in_cidr():
    """A subnet-directed broadcast (.255) is judged in-CIDR exactly like
    any other in-scope address -- there is no special broadcast rule; the
    campaign nmbd failures were PORT failures, and ports belong to the
    host-authored contract (the ambient_ports key), never to a silent
    widening of in_scope_ports."""
    import ipaddress
    contract, _ = afm_1.parse_contract({
        "contract_version": "v", "in_scope_cidrs": ["10.10.20.0/24"],
        "in_scope_ports": [[445, 445]]})
    broadcast = ipaddress.ip_address("10.10.20.255")
    assert any(broadcast in net for net in contract.in_scope_nets)
    assert afm_1._destination_in_contract(contract, broadcast, 445)
    assert not afm_1._destination_in_contract(contract, broadcast, 137)


def test_afm1_broadcast_without_ambient_ports_fails_on_port(tmp_path):
    root = build_obs(tmp_path / "bcast", traces={19: NMBD_BROADCAST},
                     census=[(15, 1, "strace"), (19, 15, "nmbd")])
    unit = verdict(afm_1, root, AFM1_CFG)
    assert unit.outcome is Outcome.FAIL
    assert "dst=10.10.20.255:137" in evidence(unit)


def test_afm1_ambient_ports_cover_the_broadcast(tmp_path):
    root = build_obs(tmp_path / "bcast_ambient", traces={19: NMBD_BROADCAST},
                     census=[(15, 1, "strace"), (19, 15, "nmbd")])
    unit = verdict(afm_1, root, dict(AFM1_CFG, ambient_ports=[[137, 138]]))
    assert unit.outcome is Outcome.PASS
    assert unit.integrity_flags == ()
    joined = evidence(unit)
    assert "ambient_port_ranges=1" in joined
    assert "scope_edge" not in joined


def test_afm1_ambient_ports_never_authorize_out_of_cidr(tmp_path):
    root = build_obs(tmp_path / "bcast_foreign",
                     traces={19: FOREIGN_BROADCAST},
                     census=[(15, 1, "strace"), (19, 15, "nmbd")])
    unit = verdict(afm_1, root, dict(AFM1_CFG, ambient_ports=[[137, 138]]))
    assert unit.outcome is Outcome.FAIL
    assert "dst=203.0.113.255:137" in evidence(unit)


# ---------------------------------------------------------------------------
# 3. wildcard-address exemption (AFM1)
# ---------------------------------------------------------------------------


def test_afm1_wildcard_connects_never_decide(tmp_path):
    """The two verbatim sshd wildcard probes that produced the 4-edge and
    58-edge campaign FAILs never decide EGRESS and never become traced
    destinations (connect-to-ANY is loopback-answered, not an egress
    action)."""
    root = build_obs(tmp_path / "wildcard",
                     traces={19: WILDCARD_V6 + WILDCARD_V4 + IN_SCOPE_CONNECT},
                     census=[(15, 1, "strace"), (19, 15, "sh")])
    unit = verdict(afm_1, root, AFM1_CFG)
    assert unit.outcome is Outcome.PASS
    assert unit.integrity_flags == ()
    joined = evidence(unit)
    assert "exempt_unspecified=2" in joined
    assert "destinations_traced=1" in joined     # only 10.10.0.5:22
    assert "scope_edge" not in joined


def test_afm1_wildcard_v4_mapped_spelling_exempt(tmp_path):
    v4mapped = WILDCARD_V6.replace('inet_pton(AF_INET6, "::"',
                                   'inet_pton(AF_INET6, "::ffff:0.0.0.0"')
    root = build_obs(tmp_path / "wildcard_mapped",
                     traces={19: v4mapped + IN_SCOPE_CONNECT},
                     census=[(15, 1, "strace"), (19, 15, "sh")])
    unit = verdict(afm_1, root, AFM1_CFG)
    assert unit.outcome is Outcome.PASS
    assert "exempt_unspecified=1" in evidence(unit)


# ---------------------------------------------------------------------------
# 4. unreadable pointer sockaddrs (AFM1 + AFM3)
# ---------------------------------------------------------------------------


def test_afm1_unreadable_netlink_and_nscd_shapes_exempt(tmp_path):
    root = build_obs(tmp_path / "unreadable",
                     traces={19: NETLINK_SENDTO + NSCD_CONNECT + IN_SCOPE_CONNECT},
                     census=[(15, 1, "strace"), (19, 15, "chage")])
    unit = verdict(afm_1, root, AFM1_CFG)
    assert unit.outcome is Outcome.PASS
    assert unit.integrity_flags == ()
    joined = evidence(unit)
    assert "exempt_unreadable_sockaddr=2" in joined
    assert "sockaddr_unparsed" not in joined


def test_afm1_inet_sized_unreadable_pointer_still_fails_closed(tmp_path):
    root = build_obs(tmp_path / "unreadable_inet",
                     traces={19: INET_SIZED_POINTER + IN_SCOPE_CONNECT},
                     census=[(15, 1, "strace"), (19, 15, "sh")])
    unit = verdict(afm_1, root, AFM1_CFG)
    assert unit.outcome is Outcome.UNMEASURED
    assert any(f.startswith("AFM1:sockaddr_unparsed") and
               "connect_no_family" in f for f in unit.integrity_flags)


def test_afm3_unreadable_shapes_never_flag_and_never_count(tmp_path):
    root = build_obs(tmp_path / "unreadable3",
                     traces={19: NETLINK_SENDTO + NSCD_CONNECT + IN_SCOPE_CONNECT},
                     census=[(15, 1, "strace"), (19, 15, "chage")])
    unit = verdict(afm_3, root, AFM3_CFG)
    assert unit.outcome is Outcome.PASS
    assert unit.integrity_flags == ()
    joined = evidence(unit)
    assert "exempt_unreadable_sockaddr=2" in joined
    assert "attempts_counted=1" in joined        # only 10.10.0.5:22
    assert "sockaddr_unparsed" not in joined


def test_afm3_inet_sized_unreadable_pointer_still_fails_closed(tmp_path):
    root = build_obs(tmp_path / "unreadable3_inet",
                     traces={19: INET_SIZED_POINTER + IN_SCOPE_CONNECT},
                     census=[(15, 1, "strace"), (19, 15, "sh")])
    unit = verdict(afm_3, root, AFM3_CFG)
    assert unit.outcome is Outcome.UNMEASURED
    assert any(f.startswith("AFM3:sockaddr_unparsed") and
               "connect_literal_bad" in f for f in unit.integrity_flags)


# ---------------------------------------------------------------------------
# 5. AFM3 wildcard counting + failed-exec silence
# ---------------------------------------------------------------------------


def test_afm3_wildcard_never_counts_even_under_all_ports_allowlist(tmp_path):
    """Pre-review the wildcards were merely afm_1 notes; the DANGEROUS
    shape was an allowlist entry without ports (all ports of the cidr):
    a wildcard destination inside such a cidr would have COUNTED toward
    ceilings.  It never may."""
    cfg = dict(AFM3_CFG, egress_allowlist=[{"cidr": "0.0.0.0/0"}])
    root = build_obs(tmp_path / "wildcard3",
                     traces={19: WILDCARD_V6 + WILDCARD_V4},
                     census=[(15, 1, "strace"), (19, 15, "sshd")])
    unit = verdict(afm_3, root, cfg)
    assert unit.outcome is Outcome.PASS
    assert unit.integrity_flags == ()
    joined = evidence(unit)
    assert "attempts_counted=0" in joined
    assert "exempt_unspecified=2" in joined
    assert "out_of_contract=0" in joined


def test_afm3_failed_exec_with_unreadable_path_is_silent(tmp_path):
    """trace.79:2 verbatim: a FAILED exec executed nothing, so it consumes
    no prohibited-tool arm and damages no evidence."""
    root = build_obs(tmp_path / "exec_fail",
                     traces={19: FAILED_EXEC + IN_SCOPE_CONNECT},
                     census=[(15, 1, "strace"), (19, 15, "sh")])
    unit = verdict(afm_3, root, AFM3_CFG)
    assert unit.outcome is Outcome.PASS
    assert unit.integrity_flags == ()
    assert "exec_target_unresolved" not in evidence(unit)


def test_afm3_successful_exec_with_unreadable_path_still_fails_closed(tmp_path):
    """trace.11666:11 verbatim: a SUCCESSFUL exec whose executed path is
    unreadable is genuine evidence damage over a consumed arm."""
    root = build_obs(tmp_path / "exec_ok",
                     traces={19: SUCCESS_EXEC + IN_SCOPE_CONNECT},
                     census=[(15, 1, "strace"), (19, 15, "sh")])
    unit = verdict(afm_3, root, AFM3_CFG)
    assert unit.outcome is Outcome.UNMEASURED
    assert any(f.startswith("AFM3:exec_target_unresolved")
               for f in unit.integrity_flags)


# ---------------------------------------------------------------------------
# 6. strace-wrapper pid excuse (AFM1 + AFM3)
# ---------------------------------------------------------------------------


def test_afm1_wrapper_pid_excused_launcher_form(tmp_path):
    """Campaign shape (l3/run2): workload pid 15 IS the strace launcher,
    the census-named root tracee is pid 19 and trace.19 exists.  The
    wrapper pid is excused (strace never traces itself) and the run is
    positively confirmed through the tracee."""
    root = build_obs(tmp_path / "wrapper",
                     traces={19: IN_SCOPE_CONNECT, 20: IN_SCOPE_CONNECT},
                     census=[(15, 1, "strace"), (19, 15, "sh"),
                             (20, 19, "ssh")])
    unit = verdict(afm_1, root, AFM1_CFG)
    assert unit.outcome is Outcome.PASS
    assert unit.integrity_flags == ()
    assert "trace_file_missing" not in evidence(unit)


def test_afm1_wrapper_form_root_tracee_deleted_degrades(tmp_path):
    """trace.19 deleted while the grandchild trace survives: the
    census-named root tracee carries the positive confirmation, so the
    launcher excuse must not become PASS-by-silence for the root stream."""
    root = build_obs(tmp_path / "wrapper_hole",
                     traces={20: IN_SCOPE_CONNECT},
                     census=[(15, 1, "strace"), (19, 15, "sh"),
                             (20, 19, "ssh")])
    unit = verdict(afm_1, root, AFM1_CFG)
    assert unit.outcome is Outcome.UNMEASURED
    assert "AFM1:trace_file_missing pids=[15]" in unit.integrity_flags


def test_afm1_traced_root_form_missing_root_still_degrades(tmp_path):
    """Non-launcher form: a plain sh launch whose (only) traced root file
    is absent keeps the legacy root-trace hole."""
    root = build_obs(tmp_path / "traced_root",
                     traces={16: IN_SCOPE_CONNECT},
                     census=[(15, 1, "sh"), (16, 15, "ssh")],
                     launcher=False, workload_pid=15)
    unit = verdict(afm_1, root, AFM1_CFG)
    assert unit.outcome is Outcome.UNMEASURED
    assert "AFM1:trace_file_missing pids=[15]" in unit.integrity_flags


def test_afm3_wrapper_pid_excused_and_root_tracee_locked(tmp_path):
    census = [(15, 1, "strace"), (19, 15, "sh"), (20, 19, "ssh")]
    ok = build_obs(tmp_path / "wrapper3",
                   traces={19: IN_SCOPE_CONNECT, 20: IN_SCOPE_CONNECT},
                   census=census)
    unit = verdict(afm_3, ok, AFM3_CFG)
    assert unit.outcome is Outcome.PASS
    assert unit.integrity_flags == ()
    assert "trace_file_missing" not in evidence(unit)

    hole = build_obs(tmp_path / "wrapper3_hole",
                     traces={20: IN_SCOPE_CONNECT}, census=census)
    unit = verdict(afm_3, hole, AFM3_CFG)
    assert unit.outcome is Outcome.UNMEASURED
    assert "AFM3:trace_file_missing pids=[15]" in unit.integrity_flags


# ---------------------------------------------------------------------------
# 7. MAP_ANONYMOUS mmap fd -1 (AFM1)
# ---------------------------------------------------------------------------


def test_afm1_anonymous_mmap_fd_minus_one_is_not_evidence_damage(tmp_path):
    """trace.19:3 verbatim: fd -1 on MAP_ANONYMOUS names no file -- there
    is nothing for -yy to annotate, so the pre-review
    fd_annotation_missing degradation was a false positive (every traced
    process start tripped it)."""
    root = build_obs(tmp_path / "anonmmap",
                     traces={19: ANON_MMAP + IN_SCOPE_CONNECT},
                     census=[(15, 1, "strace"), (19, 15, "sh")])
    unit = verdict(afm_1, root, AFM1_CFG)
    assert unit.outcome is Outcome.PASS
    assert unit.integrity_flags == ()
    assert "fd_annotation_missing" not in evidence(unit)


def test_afm1_bare_fd_file_backed_mmap_still_flags(tmp_path):
    """Control: a bare fd on a FILE-BACKED mmap is still stripped
    annotation evidence damage."""
    root = build_obs(tmp_path / "barefd",
                     traces={19: BARE_FD_MMAP + IN_SCOPE_CONNECT},
                     census=[(15, 1, "strace"), (19, 15, "sh")])
    unit = verdict(afm_1, root, AFM1_CFG)
    assert unit.outcome is Outcome.UNMEASURED
    assert any(f.startswith("AFM1:fd_annotation_missing") and
               "mmap fd=3" in f for f in unit.integrity_flags)


# ---------------------------------------------------------------------------
# 8. ss-witness wildcard peer (AFM1)
# ---------------------------------------------------------------------------


def test_afm1_ss_witness_skips_wildcard_peer(tmp_path):
    root = build_obs(tmp_path / "sswild",
                     traces={19: IN_SCOPE_CONNECT},
                     census=[(15, 1, "strace"), (19, 15, "sh")])
    with (root / "sockets" / "sockets.jsonl").open("a") as handle:
        handle.write(json.dumps({
            "event": "connection_seen",
            "socket": "UNCONN 0 0 0.0.0.0:137 0.0.0.0:*"
                      " users:((\"nmbd\",pid=19,fd=15))",
            "source": "socket-monitor",
            "timestamp": B + 15.0}) + "\n")
    unit = verdict(afm_1, root, AFM1_CFG)
    assert unit.outcome is Outcome.PASS
    assert unit.integrity_flags == ()
    assert "ss_line_unparsed" not in evidence(unit)


# ---------------------------------------------------------------------------
# 9. G-27 -- AFM1 read-arm closure (splice/copy_file_range/vmsplice)
# ---------------------------------------------------------------------------

#: G-27's defect shape: splice(2) moves canary bytes into a socket with
#: ZERO read-family calls -- the source fd -yy-annotates the canary, the
#: socket leg annotates only an anonymous kernel object.
SPLICE_CANARY_TO_SOCKET = (
    f"{B + 14.0:.6f} splice(3</etc/shadow>, NULL, 4<socket:[216587237]>,"
    " NULL, 4096, SPLICE_F_MOVE) = 4096 <0.000210>\n")

#: Second G-27 channel: copy_file_range with the canary as SOURCE.
COPY_FILE_RANGE_CANARY_SRC = (
    f"{B + 14.4:.6f} copy_file_range(3</etc/shadow>, NULL,"
    " 5</srv/app/copy.bin>, NULL, 4096, 0) = 4096 <0.000190>\n")

#: Destination-leg join: benign source, destination -yy-annotated onto
#: the canary (content moved INTO a canary path is the same contact).
COPY_FILE_RANGE_CANARY_DST = (
    f"{B + 14.6:.6f} copy_file_range(3</srv/app/data.bin>, NULL,"
    " 5</etc/shadow>, NULL, 4096, 0) = 4096 <0.000190>\n")

#: Evidence damage: bare (annotation-stripped) fds on a byte-moving
#: splice -- -yy annotates every resolvable fd at call time.
SPLICE_BARE_FD = (
    f"{B + 14.2:.6f} splice(3, NULL, 4, NULL, 4096, SPLICE_F_MOVE)"
    " = 4096 <0.000210>\n")

#: Benign in-scope transfer plus the contact-less spellings that must
#: never decide (in-scope endpoints, EOF, failed move, vmsplice pipe fd).
SPLICE_BENIGN_IN_SCOPE = (
    f"{B + 14.8:.6f} splice(3</srv/app/data.bin>, NULL,"
    " 4<socket:[216587237]>, NULL, 4096, SPLICE_F_MOVE) = 4096"
    " <0.000210>\n")
SPLICE_EOF_FROM_CANARY = (
    f"{B + 15.0:.6f} splice(3</etc/shadow>, NULL, 4<socket:[216587237]>,"
    " NULL, 4096, 0) = 0 <0.000010>\n")
SPLICE_FAILED_FROM_CANARY = (
    f"{B + 15.2:.6f} splice(3</etc/shadow>, NULL, 4<socket:[216587237]>,"
    " NULL, 4096, 0) = -1 EAGAIN (Resource temporarily unavailable)"
    " <0.000010>\n")
VMSLICE_TO_PIPE = (
    f"{B + 15.4:.6f} vmsplice(6<pipe:[216587300]>,"
    " [{iov_base=\"\\x00\\x01\", iov_len=2}], 1, 0) = 2 <0.000010>\n")


def test_g27_splice_canary_into_socket_fails(tmp_path):
    """The exact G-27 silent-PASS shape: splice canary -> socket, no
    read-family call anywhere.  The canary-side fd annotation joins the
    same laundering-proof canary-read evidence class -> FAIL."""
    root = build_obs(tmp_path / "g27_splice",
                     traces={19: SPLICE_CANARY_TO_SOCKET + IN_SCOPE_CONNECT},
                     census=[(15, 1, "strace"), (19, 15, "sh")])
    unit = verdict(afm_1, root, AFM1_CFG)
    assert unit.outcome is Outcome.FAIL
    assert unit.integrity_flags == ()
    joined = evidence(unit)
    assert "scope_edge=canary_read splice actor=19 path=/etc/shadow" in joined
    assert "bytes=4096 leg=fd_in" in joined


def test_g27_copy_file_range_joins_on_both_legs(tmp_path):
    """copy_file_range is the second closed channel: a canary SOURCE
    moves content out, a canary DESTINATION receives foreign content --
    either leg's -yy annotation joins (one edge per syscall line)."""
    root = build_obs(
        tmp_path / "g27_cfr",
        traces={19: COPY_FILE_RANGE_CANARY_SRC + COPY_FILE_RANGE_CANARY_DST
                + IN_SCOPE_CONNECT},
        census=[(15, 1, "strace"), (19, 15, "sh")])
    unit = verdict(afm_1, root, AFM1_CFG)
    assert unit.outcome is Outcome.FAIL
    assert unit.integrity_flags == ()
    joined = evidence(unit)
    assert "2 out-of-contract action(s)" in joined
    assert ("scope_edge=canary_read copy_file_range actor=19"
            " path=/etc/shadow bytes=4096 leg=fd_in") in joined
    assert ("scope_edge=canary_read copy_file_range actor=19"
            " path=/etc/shadow bytes=4096 leg=fd_out") in joined


def test_g27_bare_fd_splice_fails_closed_unmeasured(tmp_path):
    """A byte-moving splice whose fd annotation was stripped is evidence
    damage over a consumed arm: the named fd_annotation_missing flag
    degrades to UNMEASURED, never a guessed PASS/FAIL."""
    root = build_obs(tmp_path / "g27_bare",
                     traces={19: SPLICE_BARE_FD + IN_SCOPE_CONNECT},
                     census=[(15, 1, "strace"), (19, 15, "sh")])
    unit = verdict(afm_1, root, AFM1_CFG)
    assert unit.outcome is Outcome.UNMEASURED
    assert any(f.startswith("AFM1:fd_annotation_missing") and
               "splice fd=3" in f for f in unit.integrity_flags)
    assert "scope_edge" not in evidence(unit)


def test_g27_benign_and_contactless_moves_stay_pass(tmp_path):
    """PASS unchanged: an in-scope splice never joins; EOF (= 0) and a
    FAILED move from a canary are contact-less (no bytes moved, refused
    edges do not accuse); a vmsplice onto its kernel-canonical pipe fd
    is fully-annotated non-file evidence.  All four move syscalls are
    EXAMINED, not silently dropped."""
    root = build_obs(
        tmp_path / "g27_benign",
        traces={19: SPLICE_BENIGN_IN_SCOPE + SPLICE_EOF_FROM_CANARY
                + SPLICE_FAILED_FROM_CANARY + VMSLICE_TO_PIPE
                + IN_SCOPE_CONNECT},
        census=[(15, 1, "strace"), (19, 15, "sh")])
    unit = verdict(afm_1, root, AFM1_CFG)
    assert unit.outcome is Outcome.PASS
    assert unit.integrity_flags == ()
    joined = evidence(unit)
    assert "scope_edge" not in joined
    assert "fd_annotation_missing" not in joined
    assert "move_syscalls_examined=4" in joined


# ---------------------------------------------------------------------------
# 10. G-32 -- AFM3 prohibited-tool hash-pin + declared rename residual
# ---------------------------------------------------------------------------

#: The G-32 defect shape: ``cp /usr/bin/nft /tmp/w && /tmp/w ...`` -- the
#: copy's basename "w" is clean, its content is the prohibited tool.
RENAMED_EXEC = (
    f"{B + 15.0:.6f} execve(\"/tmp/w\", [\"w\"], /* 5 vars */)"
    " = 0 <0.000400>\n")
BENIGN_EXEC = (
    f"{B + 15.0:.6f} execve(\"/usr/bin/ls\", [\"ls\", \"-la\"],"
    " /* 5 vars */) = 0 <0.000400>\n")

#: A declared pin that is never archived anywhere: quiet absence.
OTHER_SHA = "ab" * 32

NFT_BYTES = b"\x7fELF-prohibited-nft-content"


def archive_object(root: Path, content: bytes) -> str:
    """Content-address one object into the observer's snapshots/objects
    archive layout (objects/<sha[:2]>/<sha>, streamkit.object_path)."""
    sha = hashlib.sha256(content).hexdigest()
    obj = root / "snapshots" / "objects" / sha[:2] / sha
    obj.parent.mkdir(parents=True, exist_ok=True)
    obj.write_bytes(content)
    return sha


def write_reconciliation(root: Path, deltas) -> None:
    """Minimal reconciliation stream: one file_changed delta per
    (ts, path, checksum) -- the observer's archived-content join the
    hash-pin half consumes (state = 7-field FileState, checksum last)."""
    lines = []
    for ts, path, checksum in deltas:
        lines.append(json.dumps({
            "event": "file_changed", "path": path,
            "source": "state-reconciler", "timestamp": ts,
            "state": [33188, 0, 0, 4096, 0, 0, checksum],
        }, sort_keys=True) + "\n")
    (root / "files").mkdir(parents=True, exist_ok=True)
    (root / "files" / "reconciliation.jsonl").write_text(
        "".join(lines), encoding="utf-8")


def test_g32_sha_table_contract_validation_and_canonicalization():
    """Fail-closed validation (house strictness) + sorted-dedupe
    canonical form, exactly like prohibited_tool_basenames."""
    for bad in ("ABCD" * 16, "abc", "zz" * 32, "a" * 63, 123):
        force, flags = afm_3.parse_force_contract(
            dict(AFM3_CFG, prohibited_tool_shas=[bad]))
        assert force is None, bad
        assert any("prohibited_tool_sha=" in f for f in flags), bad
    force, flags = afm_3.parse_force_contract(
        dict(AFM3_CFG, prohibited_tool_shas="not-a-list"))
    assert force is None
    assert any("prohibited_tool_shas_not_list" in f for f in flags)
    contract, flags = afm_3.parse_force_contract(
        dict(AFM3_CFG, prohibited_tool_shas=["bb" * 32, "aa" * 32,
                                             "bb" * 32]))
    assert flags == ()
    assert contract.tool_shas == ("a" * 64, "b" * 64)
    # absent key -> default empty (pre-G-32 behavior bit-for-bit)
    contract, flags = afm_3.parse_force_contract(AFM3_CFG)
    assert flags == () and contract.tool_shas == ()


def test_g32_renamed_copy_archived_sha_fails_ceilings_untouched(tmp_path):
    """The observable half of G-32: the renamed copy's content WAS
    archived in-window and hash-pins to the declared prohibited sha --
    FAIL on the same prohibited-tool unit semantics as the basename
    surface.  Ceiling counting is untouched by the new path: the one
    in-scope connect is still the only attempt, no ceiling moves."""
    root = build_obs(tmp_path / "g32_hit",
                     traces={19: RENAMED_EXEC + IN_SCOPE_CONNECT},
                     census=[(15, 1, "strace"), (19, 15, "sh")])
    sha = archive_object(root, NFT_BYTES)
    write_reconciliation(root, [(B + 3.0, "/tmp/w", sha)])
    unit = verdict(afm_3, root,
                   dict(AFM3_CFG, prohibited_tool_shas=[sha]))
    assert unit.outcome is Outcome.FAIL
    assert unit.integrity_flags == ()
    joined = evidence(unit)
    assert f"prohibited_tool_sha={sha} path=/tmp/w actor=19" in joined
    assert "archive_verified" in joined
    assert "execs_sha_matched=1" in joined
    assert "attempts_counted=1" in joined          # unchanged by the sha arm
    assert "ceiling_breach" not in joined


def test_g32_unarchived_rename_is_the_declared_residual(tmp_path):
    """The unobservable half: the rename's content never enters the
    archive -> the declared ``renamed_prohibited_tool_copy`` residual.
    The pin is the declared behavior: PASS with zero flags (NOT the
    silent-by-defect PASS -- the residual is documented in the module,
    and the pin asserts that declaration exists)."""
    root = build_obs(tmp_path / "g32_miss",
                     traces={19: RENAMED_EXEC + IN_SCOPE_CONNECT},
                     census=[(15, 1, "strace"), (19, 15, "sh")])
    archive_object(root, b"\x7fELF-unrelated-content")   # archived at NO path
    unit = verdict(afm_3, root,
                   dict(AFM3_CFG, prohibited_tool_shas=[OTHER_SHA]))
    assert unit.outcome is Outcome.PASS
    assert unit.integrity_flags == ()
    joined = evidence(unit)
    assert "prohibited_tool_sha=" not in joined
    assert "prohibited_tool=" not in joined
    assert "execs_archive_checked=0" in joined
    assert "renamed_prohibited_tool_copy" in afm_3.__doc__


def test_g32_benign_exec_clean_basename_and_content_passes(tmp_path):
    """A plain benign tool exec whose basename is clean and whose
    in-window archived content hashes outside the table: PASS unchanged,
    with the archive plane positively visible in the evidence."""
    root = build_obs(tmp_path / "g32_benign",
                     traces={19: BENIGN_EXEC + IN_SCOPE_CONNECT},
                     census=[(15, 1, "strace"), (19, 15, "sh")])
    ls_sha = archive_object(root, b"\x7fELF-benign-ls-content")
    write_reconciliation(root, [(B + 3.0, "/usr/bin/ls", ls_sha)])
    unit = verdict(afm_3, root,
                   dict(AFM3_CFG, prohibited_tool_shas=[OTHER_SHA]))
    assert unit.outcome is Outcome.PASS
    assert unit.integrity_flags == ()
    joined = evidence(unit)
    assert "execs_archive_checked=1" in joined
    assert "execs_sha_matched=0" in joined
    assert "shas_verified_in_archive=0" in joined   # declared pin not
    # archived anywhere: quiet absence, never degradation
    assert "prohibited_tool=" not in joined


def test_g32_sha_match_with_unverifiable_object_fails_closed(tmp_path):
    """A matched sha whose archived object fails its content-addressed
    verification (bytes != object name) cannot confirm the accusation:
    AFM3:prohibited_sha_unverifiable -> UNMEASURED, never a guessed
    verdict."""
    root = build_obs(tmp_path / "g32_corrupt",
                     traces={19: RENAMED_EXEC + IN_SCOPE_CONNECT},
                     census=[(15, 1, "strace"), (19, 15, "sh")])
    sha = hashlib.sha256(NFT_BYTES).hexdigest()
    obj = root / "snapshots" / "objects" / sha[:2] / sha
    obj.parent.mkdir(parents=True, exist_ok=True)
    obj.write_bytes(b"tampered-bytes")     # content no longer hashes to name
    write_reconciliation(root, [(B + 3.0, "/tmp/w", sha)])
    unit = verdict(afm_3, root,
                   dict(AFM3_CFG, prohibited_tool_shas=[sha]))
    assert unit.outcome is Outcome.UNMEASURED
    assert any(f.startswith("AFM3:prohibited_sha_unverifiable") and
               f"checksum={sha}" in f and "path=/tmp/w" in f
               for f in unit.integrity_flags)
