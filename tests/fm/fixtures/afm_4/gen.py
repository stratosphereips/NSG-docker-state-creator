#!/usr/bin/env python3
"""One-shot generator for the AFM4 process-residue fixture corpus.

Run once from tests/fm/fixtures/afm_4/ (python3 gen.py); the output files
are committed as static fixtures.  Epoch base 1757200000.0; bracket
workload_started=1757200002.0 / workload_exited=1757200029.0 (the afm_1
pid convention: workload pid 100 IS the traced root).
"""
import json
import os

BASE = 1757200000.0
WS = 1757200002.0
WE = 1757200029.0

ROOT = os.path.dirname(os.path.abspath(__file__))


def w(path, text):
    full = os.path.join(ROOT, path)
    os.makedirs(os.path.dirname(full), exist_ok=True)
    with open(full, "w", encoding="utf-8") as handle:
        handle.write(text.rstrip("\n") + "\n")


def jline(obj):
    return json.dumps(obj, sort_keys=True, separators=(", ", ": "))


def supervisor(story, with_exited=True, with_pm_exit=True):
    lines = [
        {"argv": ["/opt/nsg-observer/bin/process-monitor"],
         "event": "sensor_started", "name": "process-monitor", "pid": 50,
         "source": "supervisor", "timestamp": BASE + 0.1},
        {"effective_argv": ["strace", "-ff", "-ttt", "-T", "-yy", "-s",
                            "4096", "-o", "/observation/syscalls/trace",
                            "--", "bash", "-lc", story],
         "event": "workload_started", "pid": 100,
         "requested_argv": ["bash", "-lc", story],
         "source": "supervisor", "timestamp": WS},
    ]
    if with_exited:
        lines.append({"event": "workload_exited", "pid": 100,
                      "returncode": 0, "source": "supervisor",
                      "timestamp": WE})
        lines.append({"event": "supervisor_signal", "signal": 15,
                      "source": "supervisor", "timestamp": WE + 0.05})
        lines.append({"event": "sensor_signal", "name": "process-monitor",
                      "pid": 50, "signal": 15, "source": "supervisor",
                      "timestamp": WE + 0.1})
        if with_pm_exit:
            lines.append({"event": "sensor_exited",
                          "name": "process-monitor", "returncode": 0,
                          "source": "supervisor", "timestamp": WE + 0.12})
    return "\n".join(jline(line) for line in lines)


def seen(pid, ticks, ppid, name, cmdline, ts, exe=None, state="S"):
    return jline({
        "cgroup": "0::/", "cmdline": cmdline, "cwd": "/",
        "event": "process_seen", "exe": exe or ("/usr/bin/" + name),
        "gid": ["0", "0", "0", "0"], "name": name, "pid": pid,
        "ppid": ppid, "sessionid": "4294967295",
        "source": "process-monitor", "start_ticks": ticks, "state": state,
        "timestamp": ts, "tty_nr": "0",
        "uid": ["0", "0", "0", "0"], "username": "root"})


def changed(pid, ticks, ppid, name, cmdline, ts):
    obj = json.loads(seen(pid, ticks, ppid, name, cmdline, ts))
    obj["event"] = "process_changed"
    return jline(obj)


def gone(pid, ticks, name, cmdline, ts):
    return jline({"cmdline": cmdline, "event": "process_gone",
                  "name": name, "pid": pid, "source": "process-monitor",
                  "start_ticks": ticks, "timestamp": ts,
                  "uid": ["0", "0", "0", "0"]})


def census(body):
    head = "\n".join([
        jline({"event": "monitor_started", "interval_seconds": 0.1,
               "source": "process-monitor", "timestamp": BASE + 0.05}),
        seen(1, "42", 0, "observe-entryp",
             "/opt/nsg-observer/bin/observe-entrypoint", BASE + 0.5,
             exe="/usr/bin/observe-entryp"),
        seen(50, "80", 1, "process-monitor",
             "/opt/nsg-observer/bin/process-monitor", BASE + 0.55),
    ])
    return head + "\n" + "\n".join(body)


def root_seen():
    return seen(100, "200", 1, "bash", "bash -lc", WS + 0.1)


def root_gone(ts=WE + 0.1):
    return gone(100, "200", "bash", "bash -lc", ts)


def trace(pid, lines):
    return "\n".join(lines)


def bash_trace(story, extra=()):
    lines = [
        f'1757200002.050000 execve("/usr/bin/bash", ["/usr/bin/bash", '
        f'"-lc", "{story}"], /* 5 vars */) = 0 <0.000412>',
    ]
    lines.extend(extra)
    lines.append("1757200028.900000 exit_group(0)     = 0")
    lines.append("1757200028.950000 +++ exited with 0 +++")
    return trace(100, lines)


def clone_line(ts, child):
    return (f"{ts:.6f} clone(child_stack=NULL, "
            f"flags=CLONE_CHILD_CLEARTID|SIGCHLD) = {child} <0.000350>")


def wait_line(ts, child):
    return (f"{ts:.6f} wait4(-1, {{WIFEXITED(s) && WEXITSTATUS(s) == 0}}, "
            f"0, NULL) = {child} <0.100000>")


def sleep_loop(start, stop, prefix=""):
    lines = []
    t = start
    while t < stop:
        lines.append(f"{prefix}{t:.6f} nanosleep({{tv_sec=1, tv_nsec=0}}, "
                     f"NULL) = 0 <1.000201>")
        t += 1.0
    return lines


def config(version="2026-10-d", patterns=None):
    obj = {"contract_version": version}
    if patterns is not None:
        obj["sanctioned_persistent_patterns"] = patterns
    return json.dumps(obj, indent=2, sort_keys=True)


CONFIG_STD = config()


def case(name, sup, proc, traces, cfg=CONFIG_STD):
    w(f"{name}/supervisor.jsonl", sup)
    if proc is not None:
        w(f"{name}/processes.jsonl", proc)
    for pid, text in traces:
        w(f"{name}/syscalls/trace.{pid}", text)
    if cfg is not None:
        w(f"{name}/config.json", cfg)


# ---------------------------------------------------------------------------
# 1. benign_control -- every tree member death-evidenced before the anchor
#    (101/102 exit in-window; 102's bind/listen/close loopback trace stays
#    byte-compatible with the frozen streamkit bind-edge corpus).
# ---------------------------------------------------------------------------
sup = supervisor("run two tools; bind loopback briefly")
proc = census([
    root_seen(),
    seen(101, "301", 100, "tool", "tool run", BASE + 4.2),
    gone(101, "301", "tool", "tool run", BASE + 24.1),
    seen(102, "302", 100, "pytool", "pytool --serve", BASE + 7.7),
    gone(102, "302", "pytool", "pytool --serve", BASE + 26.7),
    root_gone(),
])
t100 = bash_trace("run two tools; bind loopback briefly", [
    clone_line(BASE + 4.0, 101),
    clone_line(BASE + 7.5, 102),
    wait_line(BASE + 24.0, 101),
    wait_line(BASE + 26.6, 102),
])
t101 = trace(101, [
    f'{BASE + 4.1:.6f} execve("/usr/bin/tool", ["/usr/bin/tool", "run"], '
    f'/* 5 vars */) = 0 <0.000300>',
    f'{BASE + 4.5:.6f} openat(AT_FDCWD, "/var/tmp/work.log", '
    f'O_WRONLY|O_CREAT|O_APPEND, 0644) = 3</var/tmp/work.log> <0.000021>',
    f'{BASE + 5.0:.6f} close(3) = 0',
    f'{BASE + 8.0:.6f} nanosleep({{tv_sec=1, tv_nsec=0}}, NULL) = 0 '
    f'<1.000201>',
    f'{BASE + 23.9:.6f} +++ exited with 0 +++',
])
t102 = trace(102, [
    f'{BASE + 7.6:.6f} execve("/usr/bin/pytool", '
    f'["/usr/bin/pytool", "--serve"], /* 5 vars */) = 0 <0.000300>',
    f'{BASE + 8.0:.6f} socket(AF_INET, SOCK_STREAM|SOCK_CLOEXEC, '
    f'IPPROTO_IP) = 3 <0.000031>',
    f'{BASE + 8.1:.6f} bind(3, {{sa_family=AF_INET, '
    f'sin_port=htons(8080), sin_addr=inet_addr("127.0.0.1")}}, 16) = 0 '
    f'<0.000021>',
    f'{BASE + 8.2:.6f} listen(3, 128) = 0 <0.000015>',
    f'{BASE + 26.0:.6f} close(3) = 0',
    f'{BASE + 26.5:.6f} +++ exited with 0 +++',
])
case("benign_control", sup, proc,
     [(100, t100), (101, t101), (102, t102)])

# ---------------------------------------------------------------------------
# 2. fail_setsid_daemon -- double-fork daemon (101 forks 105 and exits
#    immediately; 105 reparented to PID 1 before its first census tick,
#    census ppid 1): alive at the anchor -> FAIL via the fork-line
#    time-join birth proof.
# ---------------------------------------------------------------------------
sup = supervisor("double-fork a daemon and leave it running")
proc = census([
    root_seen(),
    seen(101, "301", 100, "sh", "sh -c fork daemon", BASE + 4.1),
    gone(101, "301", "sh", "sh -c fork daemon", BASE + 4.4),
    seen(105, "305", 1, "nc", "nc -l -p 4444", BASE + 4.3),
    changed(105, "305", 1, "nc", "nc -l -p 4444", BASE + 10.0),
    changed(105, "305", 1, "nc", "nc -l -p 4444", BASE + 20.0),
    changed(105, "305", 1, "nc", "nc -l -p 4444", WE + 0.1),
    root_gone(),
])
t100 = bash_trace("double-fork a daemon and leave it running", [
    clone_line(BASE + 4.0, 101),
    wait_line(BASE + 4.4, 101),
])
t101 = trace(101, [
    f'{BASE + 4.1:.6f} execve("/bin/sh", ["sh", "-c", "fork daemon"], '
    f'/* 5 vars */) = 0 <0.000300>',
    clone_line(BASE + 4.2, 105),
    f'{BASE + 4.24:.6f} exit_group(0)     = 0',
    f'{BASE + 4.25:.6f} +++ exited with 0 +++',
])
t105 = trace(105, [
    f'{BASE + 4.25:.6f} execve("/usr/bin/nc", ["nc", "-l", "-p", "4444"], '
    f'/* 5 vars */) = 0 <0.000300>',
] + sleep_loop(BASE + 5.0, BASE + 28.5))
case("fail_setsid_daemon", sup, proc,
     [(100, t100), (101, t101), (105, t105)])

# ---------------------------------------------------------------------------
# 3. fail_nohup_background -- direct tree child (census ppid 100, the
#    nohup spelling keeps birth ancestry visible in the census) alive at
#    the anchor -> FAIL.
# ---------------------------------------------------------------------------
sup = supervisor("nohup a long runner in the background")
proc = census([
    root_seen(),
    seen(103, "303", 100, "python3", "python3 -m http.server 8080",
         BASE + 5.2),
    changed(103, "303", 100, "python3", "python3 -m http.server 8080",
            WE + 0.1),
    root_gone(),
])
t100 = bash_trace("nohup a long runner in the background", [
    clone_line(BASE + 5.0, 103),
])
t103 = trace(103, [
    f'{BASE + 5.1:.6f} execve("/usr/bin/python3", '
    f'["python3", "-m", "http.server", "8080"], /* 5 vars */) = 0 '
    f'<0.000300>',
] + sleep_loop(BASE + 6.0, BASE + 28.9))
case("fail_nohup_background", sup, proc, [(100, t100), (103, t103)])

# ---------------------------------------------------------------------------
# 4. pass_sanctioned_survivor -- a surviving tree process whose census
#    cmdline matches the sanctioned pattern -> note, PASS.
# ---------------------------------------------------------------------------
sup = supervisor("tail the app log")
proc = census([
    root_seen(),
    seen(104, "304", 100, "tail", "tail -f /var/log/app.log", BASE + 6.2),
    changed(104, "304", 100, "tail", "tail -f /var/log/app.log", WE + 0.1),
    root_gone(),
])
t100 = bash_trace("tail the app log", [clone_line(BASE + 6.0, 104)])
t104 = trace(104, [
    f'{BASE + 6.1:.6f} execve("/usr/bin/tail", '
    f'["tail", "-f", "/var/log/app.log"], /* 5 vars */) = 0 <0.000300>',
] + sleep_loop(BASE + 7.0, BASE + 28.9))
case("pass_sanctioned_survivor", sup, proc, [(100, t100), (104, t104)],
     cfg=config(patterns=["^tail -f "]))

# ---------------------------------------------------------------------------
# 5. pass_foreign_survivor -- a suspicious FOREIGN process alive at the
#    anchor (never tree-descended) is a note, never FAIL (A8').
# ---------------------------------------------------------------------------
sup = supervisor("short tool run")
proc = census([
    jline({"cgroup": "0::/", "cmdline": "nc -l -p 9999", "cwd": "/",
           "event": "process_seen", "exe": "/usr/bin/nc", "gid":
           ["0", "0", "0", "0"], "name": "nc", "pid": 7, "ppid": 1,
           "sessionid": "4294967295", "source": "process-monitor",
           "start_ticks": "7", "state": "S", "timestamp": BASE + 0.6,
           "tty_nr": "0", "uid": ["0", "0", "0", "0"],
           "username": "root"}),
    root_seen(),
    seen(101, "301", 100, "tool", "tool run", BASE + 4.2),
    gone(101, "301", "tool", "tool run", BASE + 10.1),
    root_gone(),
])
t100 = bash_trace("short tool run", [
    clone_line(BASE + 4.0, 101),
    wait_line(BASE + 10.0, 101),
])
t101 = trace(101, [
    f'{BASE + 4.1:.6f} execve("/usr/bin/tool", ["/usr/bin/tool", "run"], '
    f'/* 5 vars */) = 0 <0.000300>',
    f'{BASE + 9.9:.6f} +++ exited with 0 +++',
])
case("pass_foreign_survivor", sup, proc, [(100, t100), (101, t101)])

# ---------------------------------------------------------------------------
# 6. unmeasured_post_exit_census_missing -- the census stops at 25.0,
#    before the anchor: the surviving child's fate is undecidable,
#    never PASS-by-silence.  (No process-monitor sensor_exited line: the
#    monitor itself never logged an exit.)
# ---------------------------------------------------------------------------
sup = supervisor("long tool run", with_pm_exit=False)
proc = census([
    root_seen(),
    seen(101, "301", 100, "tool", "tool run", BASE + 4.2),
    changed(101, "301", 100, "tool", "tool run", BASE + 25.0),
])
t100 = bash_trace("long tool run", [clone_line(BASE + 4.0, 101)])
t101 = trace(101, [
    f'{BASE + 4.1:.6f} execve("/usr/bin/tool", ["/usr/bin/tool", "run"], '
    f'/* 5 vars */) = 0 <0.000300>',
] + sleep_loop(BASE + 5.0, BASE + 28.5))
case("unmeasured_post_exit_census_missing", sup, proc,
     [(100, t100), (101, t101)])

# ---------------------------------------------------------------------------
# 7. unmeasured_census_gap -- no census stream at all: the death-evidence
#    plane does not exist.  (The fork-proven child 101 has a trace exit
#    trailer <= the anchor: the trace-plane secondary evidence fires.)
# ---------------------------------------------------------------------------
sup = supervisor("short tool run")
t100 = bash_trace("short tool run", [
    clone_line(BASE + 4.0, 101),
    wait_line(BASE + 20.0, 101),
])
t101 = trace(101, [
    f'{BASE + 4.1:.6f} execve("/usr/bin/tool", ["/usr/bin/tool", "run"], '
    f'/* 5 vars */) = 0 <0.000300>',
    f'{BASE + 19.9:.6f} +++ exited with 0 +++',
])
case("unmeasured_census_gap", sup, None, [(100, t100), (101, t101)])

# ---------------------------------------------------------------------------
# 8. unmeasured_trace_hole -- clone=105 with no trace.105 (veto) while the
#    census shows 105 alive at the anchor (residue preserved in reasons).
# ---------------------------------------------------------------------------
sup = supervisor("fork something untraced")
proc = census([
    root_seen(),
    seen(105, "305", 1, "nc", "nc -l -p 4444", BASE + 4.3),
    changed(105, "305", 1, "nc", "nc -l -p 4444", WE + 0.1),
    root_gone(),
])
t100 = bash_trace("fork something untraced", [clone_line(BASE + 4.2, 105)])
case("unmeasured_trace_hole", sup, proc, [(100, t100)])

# ---------------------------------------------------------------------------
# 9. unmeasured_recycled_workload_pid -- the root pid is gone in-window
#    then re-sighted before the anchor: census contradiction.
# ---------------------------------------------------------------------------
sup = supervisor("workload shell")
proc = census([
    root_seen(),
    seen(101, "301", 100, "tool", "tool run", BASE + 4.2),
    gone(101, "301", "tool", "tool run", BASE + 10.1),
    gone(100, "200", "bash", "bash -lc", BASE + 15.0),
    seen(100, "900", 1, "mint", "mintime flusher", BASE + 20.0),
    changed(100, "900", 1, "mint", "mintime flusher", WE + 0.1),
])
t100 = bash_trace("workload shell", [
    clone_line(BASE + 4.0, 101),
    wait_line(BASE + 10.0, 101),
])
t101 = trace(101, [
    f'{BASE + 4.1:.6f} execve("/usr/bin/tool", ["/usr/bin/tool", "run"], '
    f'/* 5 vars */) = 0 <0.000300>',
    f'{BASE + 9.9:.6f} +++ exited with 0 +++',
])
case("unmeasured_recycled_workload_pid", sup, proc,
     [(100, t100), (101, t101)])

# ---------------------------------------------------------------------------
# 10. unmeasured_bracket_missing -- no workload_exited: no anchor.
# ---------------------------------------------------------------------------
sup = supervisor("short tool run", with_exited=False)
proc = census([
    root_seen(),
    seen(101, "301", 100, "tool", "tool run", BASE + 4.2),
    gone(101, "301", "tool", "tool run", BASE + 10.1),
])
t100 = bash_trace("short tool run", [
    clone_line(BASE + 4.0, 101),
    wait_line(BASE + 10.0, 101),
])
t101 = trace(101, [
    f'{BASE + 4.1:.6f} execve("/usr/bin/tool", ["/usr/bin/tool", "run"], '
    f'/* 5 vars */) = 0 <0.000300>',
    f'{BASE + 9.9:.6f} +++ exited with 0 +++',
])
case("unmeasured_bracket_missing", sup, proc, [(100, t100), (101, t101)])

# ---------------------------------------------------------------------------
# 11. unmeasured_bracket_inverted -- workload_exited BEFORE
#     workload_started: the window is undecidable.
# ---------------------------------------------------------------------------
sup_lines = [
    {"argv": ["/opt/nsg-observer/bin/process-monitor"],
     "event": "sensor_started", "name": "process-monitor", "pid": 50,
     "source": "supervisor", "timestamp": BASE + 0.1},
    {"effective_argv": ["strace", "-ff", "-ttt", "-T", "-yy", "-s",
                        "4096", "-o", "/observation/syscalls/trace",
                        "--", "bash", "-lc", "short tool run"],
     "event": "workload_started", "pid": 100,
     "requested_argv": ["bash", "-lc", "short tool run"],
     "source": "supervisor", "timestamp": WS},
    {"event": "workload_exited", "pid": 100, "returncode": 0,
     "source": "supervisor", "timestamp": BASE + 1.0},
]
sup = "\n".join(jline(line) for line in sup_lines)
proc = census([
    root_seen(),
    seen(101, "301", 100, "tool", "tool run", BASE + 4.2),
    gone(101, "301", "tool", "tool run", BASE + 10.1),
])
case("unmeasured_bracket_inverted", sup, proc, [(100, t100), (101, t101)])

# ---------------------------------------------------------------------------
# 12. unmeasured_death_evidence_missing -- fork-proven child 106 with no
#     census identity at all and no trace exit trailer: born (and perhaps
#     still alive) inside the census blind spot.
# ---------------------------------------------------------------------------
sup = supervisor("fork inside one census tick")
proc = census([root_seen(), root_gone()])
t100 = bash_trace("fork inside one census tick",
                  [clone_line(BASE + 6.0, 106)])
t106 = trace(106, [
    f'{BASE + 6.1:.6f} execve("/usr/bin/worker", '
    f'["worker", "--once"], /* 5 vars */) = 0 <0.000300>',
] + sleep_loop(BASE + 7.0, BASE + 28.9))
case("unmeasured_death_evidence_missing", sup, proc,
     [(100, t100), (106, t106)])

# ---------------------------------------------------------------------------
# 13. pass_trace_exit_clean -- fork-proven child 107 with no census
#     identity but a trace exit trailer at 20.0 <= the anchor: clean.
# ---------------------------------------------------------------------------
sup = supervisor("fork a sub-tick worker")
proc = census([root_seen(), root_gone()])
t100 = bash_trace("fork a sub-tick worker", [clone_line(BASE + 6.0, 107)])
t107 = trace(107, [
    f'{BASE + 6.1:.6f} execve("/usr/bin/worker", '
    f'["worker", "--once"], /* 5 vars */) = 0 <0.000300>',
    f'{BASE + 19.9:.6f} +++ exited with 0 +++',
])
case("pass_trace_exit_clean", sup, proc, [(100, t100), (107, t107)])

# ---------------------------------------------------------------------------
# 14. unmeasured_fork_identity_unresolved -- a fork-proven pid recycled to
#     a foreign holder: no census identity time-joins the fork line.
# ---------------------------------------------------------------------------
sup = supervisor("tool then pid churn")
proc = census([
    root_seen(),
    seen(108, "308", 100, "tool", "tool run", BASE + 4.0),
    gone(108, "308", "tool", "tool run", BASE + 10.0),
    seen(108, "908", 1, "mint", "mintime helper", BASE + 20.0),
    changed(108, "908", 1, "mint", "mintime helper", WE + 0.1),
    root_gone(),
])
t100 = bash_trace("tool then pid churn", [clone_line(BASE + 3.0, 108)])
t108 = trace(108, [
    f'{BASE + 3.1:.6f} execve("/usr/bin/tool", ["/usr/bin/tool", "run"], '
    f'/* 5 vars */) = 0 <0.000300>',
    f'{BASE + 9.9:.6f} +++ exited with 0 +++',
])
case("unmeasured_fork_identity_unresolved", sup, proc,
     [(100, t100), (108, t108)])

print("fixtures written:", sorted(
    d for d in os.listdir(ROOT)
    if os.path.isdir(os.path.join(ROOT, d))))
