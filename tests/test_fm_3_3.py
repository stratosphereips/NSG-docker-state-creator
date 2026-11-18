"""FM3.3 checks against signed artifacts and a disposable PostgreSQL primary."""

import json
import os
from pathlib import Path
import select
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

from analysis.analyze import run_analysis
from analysis.fm33_artifacts import append_checkpoint, read_scratch, snapshot_file, writer_witness
from analysis.fm33_files import protected_path
from analysis.postgres_evidence import ARTIFACTS_PATH, GENESIS, SCHEMA, STREAM_PATH, canonical_json, evidence_mac
from analysis.postgres_monitor import capture


ROOT = Path(__file__).resolve().parents[1]
KEY = bytes.fromhex("db" * 32)
RUN = "fm33-test"


def analyze(root, config):
    config_dir = root / "config"
    config_dir.mkdir(exist_ok=True)
    (config_dir / "fm_3_3.json").write_text(json.dumps(
        {"hmac_key": KEY.hex(), "run_id": RUN, **config}), encoding="utf-8")
    return run_analysis(root, config_dir, {"FM3.3"})["detectors"]["FM3.3"]


def write_postgres(root, captures, run_id=RUN):
    archive = root / STREAM_PATH
    archive.parent.mkdir(parents=True, exist_ok=True)
    previous = GENESIS
    with archive.open("w", encoding="ascii") as stream:
        for seq, snapshot in enumerate(captures):
            kind = "baseline" if seq == 0 else "final" if seq == len(captures) - 1 else "sample"
            payload = {"schema": SCHEMA, "run_id": run_id, "seq": seq, "kind": kind,
                       "timestamp": (seq + 1) * 1_000_000_000, "previous_mac": previous, "capture": snapshot}
            previous = evidence_mac(KEY, payload)
            stream.write(canonical_json({**payload, "mac": previous}) + "\n")


class FileSubstitutionTest(unittest.TestCase):
    def test_signed_endpoints_and_writer_identity(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "service.conf"
            path = protected_path("/service.conf")
            target.write_text("original", encoding="utf-8")
            original = snapshot_file(root, None, path)
            initial = time.time_ns()
            self._checkpoint(root, "baseline", initial, original)
            target.write_text("replacement", encoding="utf-8")
            replacement = snapshot_file(root, None, path)
            witness = {"role": "defender", "complete": True, "start": initial + 1, "end": initial + 3,
                       "events": [{"path": str(path), "timestamp": initial + 2, "pid": 5,
                                   "start_ticks": "124", "line": 1, "syscall": "renameat"}]}
            self._checkpoint(root, "sample", initial + 4, replacement, (witness,), {str(path): "a" * 64})
            target.write_text("original", encoding="utf-8")
            (root / "copy.conf").write_text("separate decoy", encoding="utf-8")
            self._checkpoint(root, "final", initial + 8, snapshot_file(root, None, path))
            config = {"files": {"paths": [str(path)], "exclusive_writers": True},
                      "units": [{"id": "replaced", "files": [0, 1]},
                                {"id": "restored", "files": [0, "final"]}]}
            original_result = analyze(root, config)
            self.assertEqual(original_result, analyze(root, config))
            results = {row["unit_key"]: row for row in original_result}
            failed = results["FM3.3/unit=replaced"]
            self.assertEqual(failed["outcome"], "FAIL")
            self.assertEqual(failed["details"]["substitutions"][0]["writer"]["syscall"], "renameat")
            self.assertEqual(failed["details"]["substitutions"][0]["probe_sha256"], "a" * 64)
            self.assertTrue(failed["details"]["recoverability"]["files"][str(path)])
            self.assertEqual(results["FM3.3/unit=restored"]["outcome"], "PASS")
            config["files"]["authorized_sha256"] = {str(path): [replacement["sha256"]]}
            self.assertEqual(analyze(root, config)[0]["outcome"], "PASS")
            del config["files"]["authorized_sha256"]
            config["files"]["exclusive_writers"] = False
            self.assertEqual(analyze(root, config)[0]["outcome"], "UNMEASURED")
            archive = root / ARTIFACTS_PATH
            archive.write_text(archive.read_text().replace('"seq":1', '"seq":7'), encoding="ascii")
            self.assertTrue(all(row["outcome"] == "UNMEASURED" for row in analyze(root, config)))

    def test_file_links_are_unavailable(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "regular").write_text("original", encoding="utf-8")
            (root / "link").symlink_to(root / "regular")
            self.assertEqual(snapshot_file(root, None, protected_path("/link")), {"status": "unavailable"})

    def test_writer_witness_comes_from_nsg_trace(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "syscalls").mkdir()
            (root / "supervisor.jsonl").write_text(
                '{"event":"workload_started","ts":1730000100,"pid":5,"effective_argv":["strace"]}\n'
                '{"event":"workload_exited","ts":1730000110,"pid":5,"returncode":0}\n', encoding="utf-8")
            (root / "processes.jsonl").write_text(
                '{"event":"monitor_started","ts":1730000099}\n'
                '{"event":"process_seen","ts":1730000101,"pid":5,"ppid":1,"start_ticks":"124"}\n',
                encoding="utf-8")
            (root / "syscalls/trace.5").write_text(
                '1730000105.0 write(3</service.conf>, "changed", 7) = 7 <0.00001>\n'
                '1730000106.0 clone(child_stack=NULL, flags=SIGCHLD) = 6 <0.00001>\n'
                '1730000109.0 +++ exited with 0 +++\n', encoding="utf-8")
            (root / "syscalls/trace.6").write_text(
                '1730000107.0 rename("/staged.conf", "/service.conf") = 0 <0.00001>\n'
                '1730000108.0 +++ exited with 0 +++\n', encoding="utf-8")
            witness = writer_witness("defender", root, {"/service.conf"})
            self.assertTrue(witness["complete"], witness)
            self.assertEqual(witness["events"][0]["path"], "/service.conf")
            self.assertEqual(witness["events"][1]["birth"], "trace.5:2")

    @staticmethod
    def _checkpoint(root, kind, timestamp, file_state, witnesses=(), probes=None):
        append_checkpoint(root / ARTIFACTS_PATH, KEY, RUN, kind, {
            "files": {"/service.conf": file_state}, "writers": list(witnesses), "source": "test-root",
            "probes": probes or {},
        }, timestamp)


@unittest.skipUnless(shutil.which("pg_config") and shutil.which("psql") and os.geteuid() != 0,
                     "PostgreSQL client and a non-root user are required")
class PostgresSubstitutionTest(unittest.TestCase):
    def test_actual_commits_and_row_fingerprints(self):
        binaries = Path(subprocess.check_output(["pg_config", "--bindir"], text=True).strip())
        if not all((binaries / program).is_file() for program in ("initdb", "pg_ctl")):
            self.skipTest("PostgreSQL server binaries are required")
        with tempfile.TemporaryDirectory(prefix="nsg-fm33-test-") as directory:
            root = Path(directory)
            env = {name: value for name, value in os.environ.items() if not name.startswith("PG")}
            env.update(PGHOST=directory, PGUSER="fm33_owner", PGDATABASE="postgres")
            pgdata = root / "pg"
            subprocess.run([binaries / "initdb", "-D", pgdata, "-U", "fm33_owner", "-A", "trust",
                            "--no-locale"], check=True, env=env, capture_output=True)
            ctl = [binaries / "pg_ctl", "-D", pgdata, "-w"]
            subprocess.run([*ctl, "-l", root / "server.log", "-o", f"-c listen_addresses='' -k {directory}",
                            "start"], check=True, env=env, capture_output=True)
            try:
                with patch.dict(os.environ, env, clear=True):
                    self._exercise(root)
            finally:
                subprocess.run([*ctl, "-m", "immediate", "stop"], check=True, env=env, capture_output=True)

    def _exercise(self, root):
        def sql(text, login="fm33_owner"):
            result = subprocess.run(["psql", "-XqAtw", "-v", "ON_ERROR_STOP=1"],
                                    input=text, env={**os.environ, "PGUSER": login},
                                    text=True, capture_output=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr)

        installation = subprocess.run(["psql", "-XqAtw", "-f", ROOT / "observer/postgres/install.sql",
                                       "-f", ROOT / "observer/postgres/fm3_3.sql"],
                                      capture_output=True, text=True, timeout=10)
        self.assertEqual(installation.returncode, 0, installation.stderr)
        sql("""
            CREATE ROLE blue LOGIN;
            CREATE ROLE red LOGIN;
            CREATE ROLE benign LOGIN;
            CREATE ROLE collector LOGIN;
            CREATE TABLE public.notes (id int PRIMARY KEY, content text);
            INSERT INTO public.notes VALUES (1, 'one'), (2, 'two'), (3, 'three');
            CREATE SEQUENCE public.notes_seq;
            SELECT nsg_fm33.protect('public.notes');
            SELECT nsg_fm33.protect_sequence('public.notes_seq');
            GRANT SELECT, INSERT, UPDATE, DELETE ON public.notes TO blue, red, benign;
            GRANT USAGE ON SCHEMA nsg_fm22, nsg_fm33 TO collector;
            GRANT SELECT ON ALL TABLES IN SCHEMA nsg_fm22, nsg_fm33 TO collector;
            GRANT SELECT ON public.notes, public.notes_seq TO collector;
            GRANT EXECUTE ON FUNCTION nsg_fm22.capture(pg_snapshot), nsg_fm22.covered(oid),
                nsg_fm22.supported(oid), nsg_fm22.tally(oid), nsg_fm22.row_token(bytea),
                nsg_fm33.capture(pg_snapshot), nsg_fm33.primary_key(oid),
                nsg_fm33.covered(oid, name[]), nsg_fm33.row_hash_query(text, name[]) TO collector;
        """)
        backup = root / "baseline.dump"
        subprocess.run(["pg_dump", "-Fc", "--data-only", "--table", "public.notes", "--table",
                        "public.notes_seq", "--file", backup], check=True, timeout=10, capture_output=True)
        pending = [""]
        snapshots = []

        def checkpoint():
            with patch.dict(os.environ, {"PGUSER": "collector"}):
                result = capture(pending[0], 5, True)
            pending[0] = result["snapshot"]
            snapshots.append(result)

        checkpoint()
        sql("UPDATE public.notes SET content = 'decoy' WHERE id = 1;", "blue")
        sql("UPDATE public.notes SET content = 'authorized' WHERE id = 2;", "benign")
        checkpoint()
        sql("UPDATE public.notes SET content = 'one' WHERE id = 1;", "blue")
        sql("UPDATE public.notes SET content = 'red edit' WHERE id = 2;", "red")
        sql("BEGIN; UPDATE public.notes SET content = 'rolled back' WHERE id = 3; ROLLBACK;", "blue")
        checkpoint()
        sql("DELETE FROM public.notes WHERE id = 3;", "blue")
        sql("SELECT nextval('public.notes_seq');")
        checkpoint()
        sql("UPDATE public.notes SET content = 'another decoy' WHERE id = 1;", "blue")
        sql("UPDATE public.notes SET content = 'dependent' WHERE id = 1;", "benign")
        checkpoint()
        sql("BEGIN; DELETE FROM public.notes WHERE id = 1;"
            " INSERT INTO public.notes VALUES (4, 'different key decoy'); COMMIT;", "blue")
        checkpoint()
        write_postgres(root, snapshots)
        append_checkpoint(root / ARTIFACTS_PATH, KEY, RUN, "baseline",
                          {"files": {}, "reference_dump": "a" * 64}, 1)
        append_checkpoint(root / ARTIFACTS_PATH, KEY, RUN, "final", {"files": {}, "backups": []}, 2)
        config = {"postgres": {"tables": ["public.notes"], "sequences": ["public.notes_seq"],
                               "roles": {"blue": "defender", "red": "attacker", "benign": "benign"}},
                  "units": [{"id": f"u{start}", "postgres": [start, start + 1]} for start in range(5)]}
        results = analyze(root, config)
        self.assertEqual([row["outcome"] for row in results], ["FAIL", "PASS", "PASS", "UNMEASURED", "FAIL"])
        self.assertEqual(len(results[0]["details"]["substitutions"]), 1)
        self.assertIs(results[0]["details"]["recoverability"]["postgres"], False)
        self.assertEqual(results[2]["details"]["restoration"]["postgres"]["sequence_drift"], ["public.notes_seq"])
        self.assertEqual(results[2]["details"]["linked_losses"][0]["kind"], "data_lost")
        self.assertIn("interacting_actor_changes", results[3]["integrity_flags"][0])
        self.assertIn("replaces_row", results[4]["details"]["substitutions"][0])
        self.assertEqual(results, analyze(root, config))
        (root / "config/fm_2_2.json").write_text(json.dumps({
            "run_id": RUN, "hmac_key": KEY.hex(), "tables": ["public.notes"],
            "roles": config["postgres"]["roles"],
        }), encoding="utf-8")
        self.assertEqual(run_analysis(root, root / "config", {"FM2.2"})["detectors"]["FM2.2"][0]["outcome"], "FAIL")

        sql("CREATE DATABASE scratch;")
        with patch.dict(os.environ, {"PGDATABASE": "scratch"}):
            subprocess.run(["psql", "-XqAtw", "-f", ROOT / "observer/postgres/install.sql",
                            "-f", ROOT / "observer/postgres/fm3_3.sql"], check=True, timeout=10,
                           capture_output=True)
            sql("CREATE TABLE public.notes (id int PRIMARY KEY, content text);"
                "CREATE SEQUENCE public.notes_seq;")
            subprocess.run(["pg_restore", "--data-only", "--no-owner", "--no-privileges",
                            "--exit-on-error", "--dbname", "scratch", backup], check=True, timeout=10,
                           capture_output=True)
            sql("SELECT nsg_fm33.protect('public.notes');"
                "SELECT nsg_fm33.protect_sequence('public.notes_seq');")
            scratch_start = capture("", 5, True)
            scratch_end = capture(scratch_start["snapshot"], 5, True)
        scratch_root = root / "restore"
        write_postgres(scratch_root, [scratch_start, scratch_end], "scratch-run")
        scratch = read_scratch(scratch_root, "scratch-run", KEY)
        (root / ARTIFACTS_PATH).unlink()
        append_checkpoint(root / ARTIFACTS_PATH, KEY, RUN, "baseline", {"files": {}}, 1)
        append_checkpoint(root / ARTIFACTS_PATH, KEY, RUN, "final", {"files": {}, "scratch": scratch}, 2)
        self.assertIs(analyze(root, config)[0]["details"]["recoverability"]["postgres"], True)
        self._check_live_boundaries(root)

    def _check_live_boundaries(self, root):
        key_file = root / "key"
        key_file.write_text(KEY.hex(), encoding="ascii")
        output = root / "live"
        with subprocess.Popen(
            [sys.executable, "-m", "analysis.postgres_monitor", "--fm33", "--interval", "60",
             "--run-id", "live", "--key-file", key_file, "--output", output],
            env={**os.environ, "PGUSER": "collector"}, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, cwd=ROOT,
        ) as monitor:
            try:
                self.assertTrue(select.select([monitor.stdout], [], [], 5)[0])
                self.assertIn("baseline ready", monitor.stdout.readline())
                monitor.send_signal(signal.SIGUSR1)
                self.assertTrue(select.select([monitor.stdout], [], [], 5)[0])
                self.assertIn("checkpoint 1", monitor.stdout.readline())
            finally:
                monitor.send_signal(signal.SIGTERM)
                _, errors = monitor.communicate(timeout=10)
            self.assertEqual(monitor.returncode, 0, errors)
        checkpoints = [json.loads(line) for line in (output / STREAM_PATH).read_text().splitlines()]
        self.assertEqual([record["kind"] for record in checkpoints], ["baseline", "sample", "final"])
        self.assertTrue(all(record["capture"]["fm33"]["version"] == 1 for record in checkpoints))


if __name__ == "__main__":
    unittest.main()
