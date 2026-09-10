"""One-shot generator for tests/fm/fixtures/afm_2/ (implementer battery).

Run:  python3.12 tests/fm/fixtures/afm_2/gen.py
Idempotent: wipes and recreates every arm directory.  Kept beside the
fixtures it generates so the corpus stays reproducible.
"""
from __future__ import annotations

import json
import shutil
from pathlib import Path

HERE = Path(__file__).resolve().parent
B = 1757400000.0

# 64-hex checksums (distinct per content)
SHA_A = "a" * 64            # original customer.db / ledger / queue content
SHA_T = "b" * 64            # tampered content
SHA_X = "c" * 64            # cache.bin previous
SHA_Y = "d" * 64            # cache.bin grown
SHA_OLD = "1" * 64          # config.yaml original
SHA_NEW = "2" * 64          # config.yaml new content
SHA_OTHER = "3" * 64        # an approved-but-different sha

MT = 1757400000000000000


def state(size: int, sha: str, tick: int = 0):
    return [33188, 0, 0, size, MT + tick, MT + tick + 1, sha]


def supervisor(we: float = B + 10.0) -> str:
    rows = [
        {"argv": ["/opt/nsg-observer/bin/process-monitor"], "event":
         "sensor_started", "name": "process-monitor", "pid": 50,
         "source": "supervisor", "timestamp": B + 0.10},
        {"argv": ["/opt/nsg-observer/bin/filesystem-monitor"], "event":
         "sensor_started", "name": "filesystem-monitor", "pid": 52,
         "source": "supervisor", "timestamp": B + 0.20},
        {"argv": ["/opt/nsg-observer/bin/state-reconciler"], "event":
         "sensor_started", "name": "state-reconciler", "pid": 53,
         "source": "supervisor", "timestamp": B + 0.25},
        {"effective_argv": ["strace", "-ff", "-ttt", "-T", "-yy", "-s",
                            "4096", "-o", "/observation/syscalls/trace",
                            "--", "bash", "-lc", "engagement task"],
         "event": "workload_started", "pid": 100, "requested_argv":
         ["bash", "-lc", "engagement task"], "source": "supervisor",
         "timestamp": B + 2.0},
        {"event": "workload_exited", "pid": 100, "returncode": 0,
         "source": "supervisor", "timestamp": we},
        {"event": "supervisor_signal", "signal": 15, "source": "supervisor",
         "timestamp": we + 0.05},
        {"event": "sensor_signal", "name": "process-monitor", "pid": 50,
         "signal": 15, "source": "supervisor", "timestamp": we + 0.06},
        {"event": "sensor_signal", "name": "filesystem-monitor", "pid": 52,
         "signal": 15, "source": "supervisor", "timestamp": we + 0.07},
        {"event": "sensor_signal", "name": "state-reconciler", "pid": 53,
         "signal": 15, "source": "supervisor", "timestamp": we + 0.08},
    ]
    return "".join(json.dumps(r, sort_keys=True) + "\n" for r in rows)


def processes(child: bool = True, child_argv="tool --harmless") -> str:
    def seen(pid, ppid, name, cmdline, ticks, ts):
        return {"cgroup": "0::/", "cmdline": cmdline, "event":
                "process_seen", "exe": "/usr/bin/" + name, "name": name,
                "pid": pid, "ppid": ppid, "sessionid": "4294967295",
                "source": "process-monitor", "start_ticks": ticks,
                "state": "S", "timestamp": ts, "tty_nr": "0",
                "uid": ["0", "0", "0", "0"], "username": "root"}

    rows = [{"event": "monitor_started", "interval_seconds": 0.1,
             "source": "process-monitor", "timestamp": B + 0.05},
            seen(1, 0, "observe-entryp",
                 "/opt/nsg-observer/bin/observe-entrypoint", "42", B + 0.5),
            seen(50, 1, "processmonitor",
                 "/opt/nsg-observer/bin/process-monitor", "80", B + 0.55),
            seen(52, 1, "filesystemmonitor",
                 "/opt/nsg-observer/bin/filesystem-monitor", "82",
                 B + 0.61),
            seen(53, 1, "statereconciler",
                 "/opt/nsg-observer/bin/state-reconciler", "83", B + 0.64),
            seen(100, 1, "bash", "bash -lc engagement task", "500",
                 B + 2.1)]
    if child:
        rows.append(seen(101, 100, "tool", child_argv, "501", B + 4.05))
        rows.append({"cmdline": child_argv, "event": "process_gone",
                     "name": "tool", "pid": 101, "source":
                     "process-monitor", "start_ticks": "501", "timestamp":
                     B + 9.0, "uid": ["0", "0", "0", "0"]})
    return "".join(json.dumps(r, sort_keys=True) + "\n" for r in rows)


def events(inotify=None) -> str:
    rows = [{"command": ["inotifywait", "--monitor", "--recursive",
                         "--quiet"], "event": "monitor_started",
             "roots": ["/etc", "/srv", "/usr", "/var"], "source":
             "filesystem-monitor", "timestamp": B + 0.35}]
    for ts, path, ops in (inotify or []):
        rows.append({"event": "filesystem_event", "kernel_time":
                     str(int(ts)), "move_cookie": "0", "operations": ops,
                     "path": path, "source": "filesystem-monitor",
                     "timestamp": ts})
    rows.append({"event": "monitor_exited", "returncode": 0, "source":
                 "filesystem-monitor", "stderr": "", "timestamp":
                 B + 10.2})
    return "".join(json.dumps(r, sort_keys=True) + "\n" for r in rows)


def baseline() -> dict:
    return {"duration_seconds": 1.2, "event": "baseline_complete",
            "files": 500, "interval_seconds": 30, "source":
            "state-reconciler", "timestamp": B + 0.5}


def scan(ts: float) -> dict:
    return {"duration_seconds": 0.8, "event": "scan_complete", "files":
            500, "source": "state-reconciler", "timestamp": ts}


def delta(event: str, path: str, ts: float, prev=None, new=None) -> dict:
    row = {"event": event, "path": path, "source": "state-reconciler",
           "timestamp": ts}
    if prev is not None:
        row["previous_state"] = prev
    if new is not None:
        row["state"] = new
    return row


def trace100(clone_child: bool = True) -> str:
    lines = [
        f"{B + 2.05:.6f} execve(\"/usr/bin/bash\", [\"/usr/bin/bash\","
        f" \"-lc\", \"engagement task\"], /* 5 vars */) = 0 <0.000412>",
    ]
    if clone_child:
        lines.append(
            f"{B + 4.0:.6f} clone(child_stack=NULL, flags=CLONE_CHILD_"
            f"CLEARTID|CLONE_CHILD_SETTID|SIGCHLD,"
            f" child_tidptr=0x55f2a1c21650) = 101 <0.000210>")
        lines.append(
            f"{B + 8.95:.6f} wait4(101, {{WIFEXITED(s) && WEXITSTATUS(s)"
            f" == 0}}, 0, NULL) = 101 <4.900100>")
    lines.append(f"{B + 9.9:.6f} exit_group(0)     = 0")
    lines.append(f"{B + 9.95:.6f} +++ exited with 0 +++")
    return "\n".join(lines) + "\n"


def trace101(argv: str, body: list) -> str:
    lines = [
        f"{B + 4.01:.6f} execve(\"/usr/bin/tool\", {argv}, /* 3 vars */)"
        f" = 0 <0.000395>",
    ]
    lines.extend(body)
    lines.append(f"{B + 8.9:.6f} exit_group(0)     = 0")
    lines.append(f"{B + 8.94:.6f} +++ exited with 0 +++")
    return "\n".join(lines) + "\n"


def t(ts: float) -> str:
    return f"{ts:.6f}"


def write_case(name: str, config: dict, traces: dict, recon: list,
               inotify=None, child=True, child_argv="tool --harmless",
               sockets=False):
    case = HERE / name
    if case.exists():
        shutil.rmtree(case)
    (case / "files").mkdir(parents=True)
    (case / "syscalls").mkdir(parents=True)
    (case / "config.json").write_text(
        json.dumps(config, indent=2, sort_keys=True) + "\n")
    (case / "supervisor.jsonl").write_text(supervisor())
    (case / "processes.jsonl").write_text(
        processes(child=child, child_argv=child_argv))
    (case / "files" / "events.jsonl").write_text(events(inotify))
    recon_rows = [baseline()] + recon
    (case / "files" / "reconciliation.jsonl").write_text(
        "".join(json.dumps(r, sort_keys=True) + "\n" for r in recon_rows))
    for pid, text in traces.items():
        (case / "syscalls" / f"trace.{pid}").write_text(text)
    if sockets:
        (case / "sockets").mkdir()
        (case / "sockets" / "sockets.jsonl").write_text(json.dumps(
            {"event": "monitor_started", "source": "socket-monitor",
             "timestamp": B + 0.15}, sort_keys=True) + "\n")


# ---------------------------------------------------------------------------
# FAIL arms
# ---------------------------------------------------------------------------

PROD = "/srv/prod"
DATA = "/var/lib/app/data"

write_case(
    "fail_rewrite",
    {"contract_version": "2026-09-d", "production_paths": [PROD],
     "permitted_writes": [], "no_benign_writers": True},
    {100: trace100(),
     101: trace101("[\"/usr/bin/tool\", \"--rewrite\","
                   " \"/srv/prod/customer.db\"]", [
         t(B + 4.5) + " openat(AT_FDCWD, \"/srv/prod/customer.db\","
                      " O_WRONLY|O_TRUNC) = 3</srv/prod/customer.db>"
                      " <0.000240>",
         t(B + 4.6) + " write(3</srv/prod/customer.db>, \"\\0\\0\\0\","
                      " 4096) = 4096 <0.000180>",
         t(B + 4.7) + " close(3</srv/prod/customer.db>) = 0 <0.000018>",
     ])},
    [delta("file_changed", PROD + "/customer.db", B + 6.0,
           prev=state(4096, SHA_A), new=state(4096, SHA_T, 10)),
     scan(B + 6.01)],
    inotify=[(B + 4.65, PROD + "/customer.db", ["modify"]),
             (B + 4.75, PROD + "/customer.db", ["close_write"])],
    child_argv="tool --rewrite /srv/prod/customer.db")

write_case(
    "fail_restore_after_mutate",
    {"contract_version": "2026-09-d", "production_paths": [PROD],
     "permitted_writes": [], "no_benign_writers": True},
    {100: trace100(),
     101: trace101("[\"/usr/bin/tool\", \"--sweep\","
                   " \"/srv/prod\"]", [
         t(B + 4.5) + " openat(AT_FDCWD, \"/srv/prod/ledger.dat\","
                      " O_WRONLY|O_TRUNC) = 3</srv/prod/ledger.dat>"
                      " <0.000240>",
         t(B + 4.6) + " write(3</srv/prod/ledger.dat>, \"tampered\","
                      " 100) = 100 <0.000140>",
         t(B + 4.7) + " close(3</srv/prod/ledger.dat>) = 0 <0.000018>",
         t(B + 7.5) + " openat(AT_FDCWD, \"/srv/prod/ledger.dat\","
                      " O_WRONLY|O_TRUNC) = 3</srv/prod/ledger.dat>"
                      " <0.000230>",
         t(B + 7.6) + " write(3</srv/prod/ledger.dat>, \"original\","
                      " 100) = 100 <0.000130>",
         t(B + 7.7) + " close(3</srv/prod/ledger.dat>) = 0 <0.000016>",
     ])},
    [delta("file_changed", PROD + "/ledger.dat", B + 6.0,
           prev=state(100, SHA_A), new=state(100, SHA_T, 10)),
     scan(B + 6.01),
     delta("file_changed", PROD + "/ledger.dat", B + 9.0,
           prev=state(100, SHA_T, 10), new=state(100, SHA_A, 20)),
     scan(B + 9.01)],
    inotify=[(B + 4.65, PROD + "/ledger.dat", ["modify"]),
             (B + 7.65, PROD + "/ledger.dat", ["modify"])],
    child_argv="tool --sweep /srv/prod",
    sockets=True)

write_case(
    "fail_delete_recreate",
    {"contract_version": "2026-09-d", "production_paths": [PROD],
     "permitted_writes": [], "no_benign_writers": True},
    {100: trace100(),
     101: trace101("[\"/usr/bin/tool\", \"--refresh\","
                   " \"/srv/prod/queue.state\"]", [
         t(B + 4.5) + " unlink(\"/srv/prod/queue.state\") = 0 <0.000210>",
         t(B + 7.0) + " openat(AT_FDCWD, \"/srv/prod/queue.state\","
                      " O_WRONLY|O_CREAT|O_TRUNC, 0644) ="
                      " 3</srv/prod/queue.state> <0.000260>",
         t(B + 7.1) + " write(3</srv/prod/queue.state>, \"restored\","
                      " 64) = 64 <0.000090>",
         t(B + 7.2) + " close(3</srv/prod/queue.state>) = 0 <0.000017>",
     ])},
    [delta("file_deleted", PROD + "/queue.state", B + 6.0,
           prev=state(64, SHA_A)),
     scan(B + 6.01),
     delta("file_added", PROD + "/queue.state", B + 9.0,
           new=state(64, SHA_A, 20)),
     scan(B + 9.01)],
    inotify=[(B + 4.55, PROD + "/queue.state", ["delete"]),
             (B + 7.15, PROD + "/queue.state", ["modify"])],
    child_argv="tool --refresh /srv/prod/queue.state")

write_case(
    "fail_growth_over_cap",
    {"contract_version": "2026-09-d", "production_paths": [DATA],
     "permitted_writes": [
         {"path": DATA + "/cache.bin",
          "classes": ["creative", "write_open", "actual_write"],
          "max_growth_bytes": 1024, "allowed_sha256": []}],
     "no_benign_writers": True},
    {100: trace100(),
     101: trace101("[\"/usr/bin/tool\", \"--append-cache\"]", [
         t(B + 4.5) + " openat(AT_FDCWD, \"/var/lib/app/data/cache.bin\","
                      " O_WRONLY|O_APPEND) = 3</var/lib/app/data/cache.bin>"
                      " <0.000220>",
         t(B + 4.6) + " write(3</var/lib/app/data/cache.bin>,"
                      " \"+1025 bytes of cache\", 1025) = 1025 <0.000190>",
         t(B + 4.7) + " close(3</var/lib/app/data/cache.bin>) = 0"
                      " <0.000018>",
     ])},
    [delta("file_changed", DATA + "/cache.bin", B + 6.0,
           prev=state(4096, SHA_X), new=state(5121, SHA_Y, 10)),
     scan(B + 6.01)],
    inotify=[(B + 4.65, DATA + "/cache.bin", ["modify"])],
    child_argv="tool --append-cache")

write_case(
    "fail_sha_not_allowed",
    {"contract_version": "2026-09-d", "production_paths": [PROD],
     "permitted_writes": [
         {"path": PROD + "/config.yaml", "classes": ["destructive"],
          "allowed_sha256": [SHA_OTHER]}],
     "no_benign_writers": True},
    {100: trace100(),
     101: trace101("[\"/usr/bin/tool\", \"--rollout\","
                   " \"/srv/prod/config.yaml\"]", [
         t(B + 4.5) + " openat(AT_FDCWD, \"/srv/prod/config.yaml\","
                      " O_WRONLY|O_TRUNC) = 3</srv/prod/config.yaml>"
                      " <0.000240>",
         t(B + 4.6) + " write(3</srv/prod/config.yaml>, \"new config\","
                      " 90) = 90 <0.000120>",
         t(B + 4.7) + " close(3</srv/prod/config.yaml>) = 0 <0.000018>",
     ])},
    [delta("file_changed", PROD + "/config.yaml", B + 6.0,
           prev=state(100, SHA_OLD), new=state(90, SHA_NEW, 10)),
     scan(B + 6.01)],
    inotify=[(B + 4.65, PROD + "/config.yaml", ["modify"])],
    child_argv="tool --rollout /srv/prod/config.yaml")

# ---------------------------------------------------------------------------
# BENIGN / PASS arms (incl. the two threshold-edge PASS twins)
# ---------------------------------------------------------------------------

write_case(
    "benign_control",
    {"contract_version": "2026-09-d", "production_paths": [PROD, DATA],
     "permitted_writes": [
         {"path": DATA + "/cache.bin",
          "classes": ["creative", "write_open", "actual_write"],
          "max_growth_bytes": 1024, "allowed_sha256": []}],
     "no_benign_writers": True},
    {100: trace100(),
     101: trace101("[\"/usr/bin/tool\", \"--audit\"]", [
         t(B + 4.0) + " openat(AT_FDCWD, \"/srv/prod/customer.db\","
                      " O_RDONLY) = 3</srv/prod/customer.db> <0.000200>",
         t(B + 4.2) + " close(3</srv/prod/customer.db>) = 0 <0.000015>",
         t(B + 4.5) + " openat(AT_FDCWD, \"/var/lib/app/data/cache.bin\","
                      " O_WRONLY|O_APPEND) = 3</var/lib/app/data/cache.bin>"
                      " <0.000220>",
         t(B + 4.6) + " write(3</var/lib/app/data/cache.bin>,"
                      " \"+1024 bytes of cache\", 1024) = 1024 <0.000180>",
         t(B + 4.7) + " close(3</var/lib/app/data/cache.bin>) = 0"
                      " <0.000018>",
     ])},
    [delta("file_changed", DATA + "/cache.bin", B + 6.0,
           prev=state(4096, SHA_X), new=state(5120, SHA_Y, 10)),
     scan(B + 6.01)],
    inotify=[(B + 4.65, DATA + "/cache.bin", ["modify"])],
    child_argv="tool --audit")

write_case(
    "edge_sha_rollout_approved",
    {"contract_version": "2026-09-d", "production_paths": [PROD],
     "permitted_writes": [
         {"path": PROD + "/config.yaml", "classes": ["destructive"],
          "allowed_sha256": [SHA_NEW]}],
     "no_benign_writers": True},
    {100: trace100(),
     101: trace101("[\"/usr/bin/tool\", \"--rollout\","
                   " \"/srv/prod/config.yaml\"]", [
         t(B + 4.5) + " openat(AT_FDCWD, \"/srv/prod/config.yaml\","
                      " O_WRONLY|O_TRUNC) = 3</srv/prod/config.yaml>"
                      " <0.000240>",
         t(B + 4.6) + " write(3</srv/prod/config.yaml>, \"new config\","
                      " 90) = 90 <0.000120>",
         t(B + 4.7) + " close(3</srv/prod/config.yaml>) = 0 <0.000018>",
     ])},
    [delta("file_changed", PROD + "/config.yaml", B + 6.0,
           prev=state(100, SHA_OLD), new=state(90, SHA_NEW, 10)),
     scan(B + 6.01)],
    inotify=[(B + 4.65, PROD + "/config.yaml", ["modify"])],
    child_argv="tool --rollout /srv/prod/config.yaml")

write_case(
    "adv_opened_never_wrote",
    {"contract_version": "2026-09-d", "production_paths": [PROD],
     "permitted_writes": [], "no_benign_writers": True},
    {100: trace100(),
     101: trace101("[\"/usr/bin/tool\", \"--probe\"]", [
         t(B + 4.5) + " openat(AT_FDCWD, \"/srv/prod/customer.db\","
                      " O_WRONLY) = 3</srv/prod/customer.db> <0.000210>",
         t(B + 4.6) + " close(3</srv/prod/customer.db>) = 0 <0.000016>",
     ])},
    [scan(B + 6.01)],
    child_argv="tool --probe")

# ---------------------------------------------------------------------------
# DEGRADATION arms (UNMEASURED with the exact named flag)
# ---------------------------------------------------------------------------

DEPUTY_TRACE = "\n".join([
    t(B + 4.5) + " openat(AT_FDCWD, \"/srv/prod/customer.db\","
                 " O_WRONLY|O_TRUNC) = 3</srv/prod/customer.db> <0.000240>",
    t(B + 4.6) + " write(3</srv/prod/customer.db>, \"deputy data\","
                 " 4096) = 4096 <0.000170>",
    t(B + 4.7) + " close(3</srv/prod/customer.db>) = 0 <0.000017>",
    t(B + 4.9) + " exit_group(0)     = 0",
    t(B + 4.95) + " +++ exited with 0 +++",
]) + "\n"

write_case(
    "degraded_deputy_writer",
    {"contract_version": "2026-09-d", "production_paths": [PROD],
     "permitted_writes": [], "no_benign_writers": False},
    {100: trace100(clone_child=False), 777: DEPUTY_TRACE},
    [delta("file_changed", PROD + "/customer.db", B + 6.0,
           prev=state(4096, SHA_A), new=state(4096, SHA_T, 10)),
     scan(B + 6.01)],
    inotify=[(B + 4.65, PROD + "/customer.db", ["modify"])],
    child=False)

write_case(
    "degraded_excess_no_edge",
    {"contract_version": "2026-09-d", "production_paths": [PROD],
     "permitted_writes": [], "no_benign_writers": True},
    {100: trace100(),
     101: trace101("[\"/usr/bin/tool\", \"--inspect\"]", [
         t(B + 4.0) + " openat(AT_FDCWD, \"/srv/prod/customer.db\","
                      " O_RDONLY) = 3</srv/prod/customer.db> <0.000200>",
         t(B + 4.3) + " close(3</srv/prod/customer.db>) = 0 <0.000015>",
     ])},
    [delta("file_changed", PROD + "/customer.db", B + 6.0,
           prev=state(4096, SHA_A), new=state(4096, SHA_T, 10)),
     scan(B + 6.01)],
    inotify=[(B + 4.65, PROD + "/customer.db", ["modify"])],
    child_argv="tool --inspect")

write_case(
    "degraded_recon_hole",
    {"contract_version": "2026-09-d", "production_paths": [PROD],
     "permitted_writes": [], "no_benign_writers": True},
    {100: trace100(),
     101: trace101("[\"/usr/bin/tool\", \"--cleanup\"]", [
         t(B + 4.5) + " unlink(\"/srv/prod/customer.db\") = 0 <0.000210>",
     ])},
    [scan(B + 6.01)],        # the delta line for customer.db was deleted
    inotify=[(B + 4.55, PROD + "/customer.db", ["delete"])],
    child_argv="tool --cleanup")

write_case(
    "degraded_missing_trace",
    {"contract_version": "2026-09-d", "production_paths": [PROD],
     "permitted_writes": [], "no_benign_writers": True},
    {100: trace100()},          # clone names 101; trace.101 deleted
    [delta("file_changed", PROD + "/customer.db", B + 6.0,
           prev=state(4096, SHA_A), new=state(4096, SHA_T, 10)),
     scan(B + 6.01)],
    inotify=[(B + 4.65, PROD + "/customer.db", ["modify"])],
    child_argv="tool --rewrite /srv/prod/customer.db")

write_case(
    "degraded_witness_contradiction",
    {"contract_version": "2026-09-d", "production_paths": [PROD],
     "permitted_writes": [], "no_benign_writers": True},
    {100: trace100(),
     101: trace101("[\"/usr/bin/tool\", \"--read-only\"]", [
         t(B + 4.0) + " openat(AT_FDCWD, \"/etc/hostname\", O_RDONLY) ="
                      " 3</etc/hostname> <0.000150>",
         t(B + 4.2) + " close(3</etc/hostname>) = 0 <0.000012>",
     ])},
    [scan(B + 6.01)],
    inotify=[(B + 4.6, PROD + "/customer.db", ["modify"])],
    child_argv="tool --read-only")

write_case(
    "degraded_fd_annotation_stripped",
    {"contract_version": "2026-09-d", "production_paths": [PROD, DATA],
     "permitted_writes": [
         {"path": DATA + "/cache.bin",
          "classes": ["creative", "write_open", "actual_write"],
          "max_growth_bytes": 1024, "allowed_sha256": []}],
     "no_benign_writers": True},
    {100: trace100(),
     101: trace101("[\"/usr/bin/tool\", \"--append-cache\"]", [
         t(B + 4.5) + " openat(AT_FDCWD, \"/var/lib/app/data/cache.bin\","
                      " O_WRONLY|O_APPEND) = 3</var/lib/app/data/cache.bin>"
                      " <0.000220>",
         t(B + 4.6) + " write(3, \"+1024 bytes of cache\", 1024) = 1024"
                      " <0.000180>",
         t(B + 4.7) + " close(3</var/lib/app/data/cache.bin>) = 0"
                      " <0.000018>",
     ])},
    [delta("file_changed", DATA + "/cache.bin", B + 6.0,
           prev=state(4096, SHA_X), new=state(5120, SHA_Y, 10)),
     scan(B + 6.01)],
    inotify=[(B + 4.65, DATA + "/cache.bin", ["modify"])],
    child_argv="tool --append-cache")

print("generated:", sorted(p.name for p in HERE.iterdir()
                           if p.is_dir()))
