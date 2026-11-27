#!/usr/bin/env python3
"""Exit-status capture for non-interactive shells (the bash-observer fallback).

The automated agent runs every command as a non-interactive ``bash -c '...'``,
which never triggers PROMPT_COMMAND or PS0.  The observer sources
``bash-observer.sh`` through BASH_ENV so an EXIT trap can record the command and
its ``$?``.  These tests exercise that path directly, without Docker.
"""

from __future__ import annotations

import glob
import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OBSERVER = ROOT / "observer" / "etc" / "bash-observer.sh"


@unittest.skipUnless(shutil.which("bash"), "bash is required")
@unittest.skipUnless(Path("/proc/self/cmdline").exists(), "/proc is required")
class BashObserverFallbackTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def run_bash(self, command: str) -> None:
        env = dict(os.environ)
        env["OBS_OUTPUT_DIR"] = str(self.root)
        env["BASH_ENV"] = str(OBSERVER)
        subprocess.run(["bash", "-c", command], env=env, check=False)

    def records(self) -> list[dict]:
        found: list[dict] = []
        for path in glob.glob(str(self.root / "tty" / "commands-*.jsonl")):
            with open(path, encoding="utf-8") as handle:
                found.extend(json.loads(line) for line in handle if line.strip())
        return found

    def test_exit_status_is_recorded_for_non_interactive_command(self) -> None:
        self.run_bash("exit 7")
        records = self.records()
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["event"], "command_completed")
        self.assertEqual(records[0]["exit_status"], 7)
        self.assertEqual(records[0]["command"], "exit 7")

    def test_successful_pivot_reports_zero(self) -> None:
        self.run_bash("true")
        records = self.records()
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["exit_status"], 0)

    def test_sshpass_password_is_redacted(self) -> None:
        # Both the spaced and glued password forms must never reach the log.
        self.run_bash("sshpass -p strato ssh user@10.0.0.9 id >/dev/null 2>&1 || true")
        self.run_bash("sshpass -pGLUEDpw ssh user@10.0.0.9 id >/dev/null 2>&1 || true")
        commands = [record["command"] for record in self.records()]
        self.assertEqual(len(commands), 2)
        for command in commands:
            self.assertNotIn("strato", command)
            self.assertNotIn("GLUEDpw", command)
            self.assertIn("xxxxxx", command)

    def test_observer_own_commands_are_skipped(self) -> None:
        self.run_bash(f"ls {self.root} >/dev/null 2>&1; true")
        self.assertEqual(self.records(), [])

    def test_plain_script_without_dash_c_is_not_recorded(self) -> None:
        script = self.root / "script.sh"
        script.write_text("exit 3\n", encoding="utf-8")
        env = dict(os.environ)
        env["OBS_OUTPUT_DIR"] = str(self.root)
        env["BASH_ENV"] = str(OBSERVER)
        subprocess.run(["bash", str(script)], env=env, check=False)
        self.assertEqual(self.records(), [])

    def test_records_are_valid_json(self) -> None:
        self.run_bash("printf 'a\"b\\tc' >/dev/null; exit 1")
        # records() parses every line, so no exception here means valid JSON.
        self.assertEqual(len(self.records()), 1)


if __name__ == "__main__":
    unittest.main()
