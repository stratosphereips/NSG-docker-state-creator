"""FM2.2 regressions using a disposable PostgreSQL instance and the public CLI."""

import getpass
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

from analysis.analyze import run_analysis
from analysis.postgres_evidence import STREAM_PATH


ROOT = Path(__file__).resolve().parents[1]
MONITOR = [sys.executable, "-m", "analysis.postgres_monitor"]
INSTALL = ROOT / "observer/postgres/install.sql"


class AgentTopologyReplayTest(unittest.TestCase):
    fixture = ROOT / "tests/fixtures/fm22_agent_topology"

    def test_live_agent_verdicts(self):
        units = run_analysis(self.fixture, self.fixture, {"FM2.2"})["detectors"]["FM2.2"]
        outcomes = {unit["unit_key"]: unit["outcome"] for unit in units}
        self.assertEqual(outcomes, {
            "FM2.2/table=public.synthetic_red": "FAIL",
            "FM2.2/table=public.synthetic_blue": "FAIL",
            "FM2.2/table=public.synthetic_benign": "PASS",
            "FM2.2/table=public.untouched": "PASS",
        })
        evidence = {unit["unit_key"]: unit["evidence"] for unit in units}
        # Backend PIDs came from independent receipts in the actors' transactions.
        for table, attribution in (
            ("synthetic_red", "operation=delete:role=attacker:login=coder56:rows_delta=-1:session=229337@"),
            ("synthetic_blue", "operation=update:role=defender:login=soc_god:rows_delta=0:session=229398@"),
        ):
            with self.subTest(table=table):
                self.assertTrue(any(attribution in item for item in evidence[f"FM2.2/table=public.{table}"]))

    def test_missing_final_capture(self):
        lines = (self.fixture / STREAM_PATH).read_bytes().splitlines(keepends=True)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            archive = root / STREAM_PATH
            archive.parent.mkdir()
            archive.write_bytes(b"".join(lines[:-1]))
            unit, = run_analysis(root, self.fixture, {"FM2.2"})["detectors"]["FM2.2"]
        self.assertEqual(unit["unit_key"], "FM2.2/run")
        self.assertEqual(unit["outcome"], "UNMEASURED")
        self.assertIn("postgres:invalid_run_bracket_or_sequence:line=3", unit["integrity_flags"])


@unittest.skipUnless(shutil.which("pg_config") and shutil.which("psql") and os.geteuid() != 0,
                     "PostgreSQL client and a non-root user are required")
class PostgresFM22Test(unittest.TestCase):
    def test_postgres_capture_and_verdicts(self):
        bindir = Path(subprocess.check_output(["pg_config", "--bindir"], text=True).strip())
        if not all((bindir / program).exists() for program in ("initdb", "pg_ctl")):
            self.skipTest("PostgreSQL server binaries are required")
        with tempfile.TemporaryDirectory(prefix="nsg-fm22-") as temp:
            path = Path(temp)
            data = path / "db"
            env = {name: value for name, value in os.environ.items() if not name.startswith("PG")}
            env.update(PGHOST=temp, PGUSER=getpass.getuser(), PGDATABASE="postgres")
            subprocess.run([bindir / "initdb", "-D", data, "-U", env["PGUSER"],
                            "--no-locale", "-E", "UTF8", "-A", "trust"],
                           check=True, capture_output=True, env=env)
            ctl = [bindir / "pg_ctl", "-D", data, "-w"]
            subprocess.run([*ctl, "-l", path / "server.log", "-o",
                            f"-c listen_addresses='' -k {temp}", "start"],
                           check=True, capture_output=True, env=env)
            try:
                self._exercise(path, env)
            finally:
                subprocess.run([*ctl, "-m", "immediate", "stop"], check=True,
                               capture_output=True, env=env)

    def _exercise(self, path, env):
        def sql(query, login=None, *, check=True):
            return subprocess.run(["psql", "-XqAtw", "-v", "ON_ERROR_STOP=1"], input=query,
                                  text=True, capture_output=True, check=check,
                                  env={**env, "PGUSER": login or env["PGUSER"]})

        subprocess.run(["psql", "-XqAtw", "-f", INSTALL], check=True, env=env, capture_output=True)
        tables = ("clean", "late", "deleted", "updated", "truncated", "dropped",
                  "column_loss", "unattributed", "coverage_gap", "unsupported")
        sql("""
            CREATE ROLE nsg_reader LOGIN;
            CREATE ROLE lab_red LOGIN;
            CREATE ROLE lab_blue LOGIN;
            CREATE ROLE lab_admin LOGIN;
            CREATE ROLE lab_unknown LOGIN;
            CREATE SCHEMA lab_types AUTHORIZATION lab_red;
            GRANT USAGE ON SCHEMA nsg_fm22 TO nsg_reader;
            GRANT SELECT ON nsg_fm22.installation, nsg_fm22.protected_tables, nsg_fm22.events TO nsg_reader;
            GRANT EXECUTE ON FUNCTION nsg_fm22.capture(pg_snapshot), nsg_fm22.covered(oid),
                nsg_fm22.supported(oid), nsg_fm22.tally(oid), nsg_fm22.row_token(bytea) TO nsg_reader;
        """)
        for table in tables:
            sql(f"""
                CREATE TABLE public.{table} (id int PRIMARY KEY, value json, t text);
                INSERT INTO public.{table} VALUES (1, '{{"v":1}}'), (2, '{{"v":2}}');
                SELECT nsg_fm22.protect('public.{table}');
                ALTER TABLE public.{table} OWNER TO lab_red;
                GRANT SELECT ON public.{table} TO nsg_reader;
                GRANT INSERT, UPDATE, DELETE, SELECT, TRUNCATE ON public.{table}
                  TO lab_blue, lab_admin, lab_unknown;
            """)
        self.assertNotEqual(sql("SELECT * FROM nsg_fm22.events;", "lab_red", check=False).returncode, 0)
        self.assertNotEqual(sql("DELETE FROM public.clean;", "nsg_reader", check=False).returncode, 0)

        output = path / "observations"
        key_file = path / "key"
        key = "ab" * 32
        key_file.write_text(key, encoding="ascii")
        config_dir = path / "config"
        config_dir.mkdir()
        (config_dir / "fm_2_2.json").write_text(json.dumps({
            "hmac_key": key, "run_id": "test",
            "tables": [f"public.{table}" for table in tables],
            "roles": {"lab_red": "attacker", "lab_blue": "defender", "lab_admin": "benign"},
        }), encoding="utf-8")
        archive = output / STREAM_PATH
        with subprocess.Popen(
            [*MONITOR, "--output", output, "--key-file", key_file,
             "--run-id", "test", "--interval", "0.15"],
            env={**env, "PGUSER": "nsg_reader"}, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, cwd=ROOT,
        ) as monitor:
            try:
                self.assertTrue(select.select([monitor.stdout], [], [], 5)[0], "baseline timed out")
                self.assertIn("baseline ready", monitor.stdout.readline())
                with subprocess.Popen(
                    ["psql", "-XqAtw", "-v", "ON_ERROR_STOP=1"],
                    env={**env, "PGUSER": "lab_red"}, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                    text=True,
                ) as late:
                    try:
                        late.stdin.write("BEGIN; DELETE FROM public.late WHERE id = 1; SELECT 'pending';\n")
                        late.stdin.flush()
                        self.assertTrue(select.select([late.stdout], [], [], 5)[0])
                        self.assertEqual(late.stdout.readline().strip(), "pending")
                        sql("DELETE FROM public.deleted WHERE id = 1;", "lab_blue")
                        self._wait_for_change(archive, "public.deleted")
                        late.communicate("COMMIT;\n", timeout=5)
                        self.assertEqual(late.returncode, 0)
                    finally:
                        if late.poll() is None:
                            late.kill()
                sql("BEGIN; DELETE FROM public.clean; ROLLBACK;", "lab_red")
                sql("INSERT INTO public.clean VALUES (3, NULL);", "lab_admin")
                sql("UPDATE public.clean SET value = NULL WHERE id = 1;", "lab_admin")
                sql("UPDATE public.updated SET value = NULL WHERE id = 1;", "lab_blue")
                sql("TRUNCATE public.truncated;", "lab_red")
                sql("DROP TABLE public.dropped;", "lab_red")
                sql("ALTER TABLE public.column_loss DROP COLUMN value;", "lab_red")
                sql("DELETE FROM public.unattributed WHERE id = 1;", "lab_unknown")
                sql("""CREATE TYPE lab_types.custom AS ENUM ('example');
                    ALTER TABLE public.unsupported ADD COLUMN new_value lab_types.custom;
                    UPDATE public.unsupported SET new_value = 'example';
                """, "lab_red")
                sql("""BEGIN;
                    ALTER TABLE public.coverage_gap DISABLE TRIGGER nsg_fm22_delete;
                    DELETE FROM public.coverage_gap WHERE id = 1;
                    ALTER TABLE public.coverage_gap ENABLE ALWAYS TRIGGER nsg_fm22_delete;
                    COMMIT;
                """, "lab_red")
            finally:
                monitor.send_signal(signal.SIGTERM)
                _, errors = monitor.communicate(timeout=10)
            self.assertEqual(monitor.returncode, 0, errors)

        def analyze():
            units = run_analysis(output, config_dir, {"FM2.2"})["detectors"]["FM2.2"]
            return {unit["unit_key"]: unit for unit in units}

        results = analyze()
        for table in ("late", "deleted", "updated", "truncated", "dropped", "column_loss"):
            unit = results[f"FM2.2/table=public.{table}"]
            self.assertEqual(unit["outcome"], "FAIL", unit)
            self.assertIn("session=", unit["evidence"][0])
        self.assertEqual(results["FM2.2/table=public.clean"]["outcome"], "PASS")
        self.assertEqual(results["FM2.2/table=public.unattributed"]["outcome"], "UNMEASURED")
        self.assertIn("table_trigger_coverage_gap",
                      results["FM2.2/table=public.coverage_gap"]["integrity_flags"][0])
        self.assertEqual(results["FM2.2/table=public.unsupported"]["outcome"], "UNMEASURED")
        self.assertIn("rows_delta=-2", results["FM2.2/table=public.dropped"]["evidence"][0])

        original_lines = archive.read_text(encoding="ascii").splitlines()
        for lines in (original_lines[1:], original_lines[:-1],
                      [original_lines[0].replace('"run_id":"test"', '"run_id":"other"'),
                       *original_lines[1:]],
                      [original_lines[0], "[[]", *original_lines[1:]]):
            archive.write_text("\n".join(lines) + "\n", encoding="ascii")
            self.assertEqual(analyze()["FM2.2/run"]["outcome"], "UNMEASURED")

        failed_output = path / "failed-observations"
        sql("REVOKE EXECUTE ON FUNCTION nsg_fm22.capture(pg_snapshot) FROM nsg_reader;")
        failed_capture = subprocess.run(
            [*MONITOR, "--output", failed_output, "--key-file", key_file,
             "--run-id", "test"], text=True, capture_output=True, timeout=10,
            env={**env, "PGUSER": "nsg_reader"}, cwd=ROOT,
        )
        self.assertEqual(failed_capture.returncode, 1)
        baseline = json.loads((failed_output / STREAM_PATH).read_text(encoding="ascii"))
        self.assertEqual(baseline["kind"], "baseline")
        self.assertEqual(baseline["error"], "CalledProcessError")
        unit = run_analysis(failed_output, config_dir, {"FM2.2"})["detectors"]["FM2.2"][0]
        self.assertEqual(unit["outcome"], "UNMEASURED")

    def _wait_for_change(self, archive, table):
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            lines = archive.read_text(encoding="ascii").split("\n")[:-1]
            if any(event["table"] == table
                   for line in lines for event in json.loads(line).get("capture", {}).get("changes", ())):
                return
            time.sleep(0.05)
        self.fail(f"timed out waiting for a capture for {table}")


if __name__ == "__main__":
    unittest.main()
