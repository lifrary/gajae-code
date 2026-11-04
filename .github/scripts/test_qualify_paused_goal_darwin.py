#!/usr/bin/env python3
"""Small subprocess fixtures; never builds or imports the runtime under test."""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("guard", Path(__file__).with_name("qualify_paused_goal_darwin.py"))
guard = importlib.util.module_from_spec(spec)
spec.loader.exec_module(guard)


class GuardTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.log = self.root / "stage.log"

    def tearDown(self):
        self.temp.cleanup()

    def run_child(self, script, **options):
        # Capacity fixture is isolated from changing host disk usage.
        with patch.object(guard, "free_bytes", return_value=12 * guard.GIB):
            guard.run_stage([sys.executable, "-B", "-c", script], self.root, self.log,
                            os.environ.copy(), options.pop("deadline", time.monotonic() + 3),
                            12 * guard.GIB, **options)

    def test_success_retains_output_and_exit(self):
        self.run_child("print('bounded fixture output')")
        self.assertEqual(self.log.read_text(), "bounded fixture output\n")
        receipt = json.loads(Path(str(self.log) + ".json").read_text())
        self.assertEqual(receipt["exit_code"], 0)
        self.assertIsNone(receipt["failure"])

    def test_nonzero_is_failure_without_retry(self):
        script = "from pathlib import Path; p=Path('attempt'); p.write_text(p.read_text()+'x' if p.exists() else 'x'); raise SystemExit(7)"
        with self.assertRaisesRegex(guard.Refusal, "no retry"):
            self.run_child(script)
        self.assertEqual((self.root / "attempt").read_text(), "x")
        self.assertEqual(json.loads(Path(str(self.log) + ".json").read_text())["exit_code"], 7)

    def test_deadline_stops_only_owned_process(self):
        unrelated = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(1)"], start_new_session=True)
        try:
            with self.assertRaisesRegex(guard.Refusal, "deadline"):
                self.run_child("import os,time; print(os.getpid(),flush=True); time.sleep(1)", deadline=time.monotonic() + 0.2)
            self.assertIsNone(unrelated.poll())
            pid = int(self.log.read_text().strip())
            with self.assertRaises(ProcessLookupError):
                os.kill(pid, 0)
        finally:
            unrelated.wait(timeout=3)

    def test_memory_limit_refuses_actual_child(self):
        with self.assertRaisesRegex(guard.Refusal, "memory"):
            self.run_child("import time; data=bytearray(1024*1024); time.sleep(0.5)", rss_limit=1)
        self.assertLess(json.loads(Path(str(self.log) + ".json").read_text())["exit_code"], 0)

    def test_log_ceiling_stops_noisy_child(self):
        with self.assertRaisesRegex(guard.Refusal, "log size"):
            self.run_child("print('x'*4096)", log_limit=128)
        self.assertLessEqual(self.log.stat().st_size, 128)

    def test_disk_floor_prevents_start(self):
        with patch.object(guard, "free_bytes", return_value=guard.FREE_FLOOR - 1):
            with self.assertRaisesRegex(guard.Refusal, "disk"):
                guard.run_stage([sys.executable, "-c", "raise SystemExit(0)"], self.root,
                                self.log, os.environ.copy(), time.monotonic() + 2, 12 * guard.GIB)
        self.assertFalse(self.log.exists())

    def test_growth_budget_refuses_even_above_floor(self):
        with patch.object(guard, "free_bytes", return_value=5 * guard.GIB):
            with self.assertRaisesRegex(guard.Refusal, "growth"):
                guard.enforce_capacity(self.root, 12 * guard.GIB)

    def test_elapsed_work_budget_prevents_start(self):
        with self.assertRaisesRegex(guard.Refusal, "before stage"):
            self.run_child("print('must not start')", deadline=time.monotonic() - 1)
        self.assertFalse(self.log.exists())

    def test_tree_sampler_includes_children_outside_group(self):
        rows = {10: (1, 10, 20, "birth-a", "parent"),
                11: (10, 11, 30, "birth-b", "escaped"),
                12: (11, 11, 40, "birth-c", "child"),
                15: (1, 15, 50, "birth-d", "unrelated")}
        self.assertEqual(set(guard.owned_tree(10, rows)), {10, 11, 12})

    def test_escaped_descendant_is_refused_and_stopped(self):
        script = (
            "import subprocess,sys; "
            "p=subprocess.Popen([sys.executable,'-c','import time; time.sleep(1)'],start_new_session=True); "
            "print(p.pid,flush=True); p.wait()"
        )
        with self.assertRaisesRegex(guard.Refusal, "escaped"):
            self.run_child(script)
        child = int(self.log.read_text().strip())
        result = subprocess.run(["ps", "-p", str(child), "-o", "stat="], capture_output=True, text=True)
        self.assertTrue(result.returncode == 1 or result.stdout.strip().startswith("Z"),
                        "escaped fixture must not remain executable")

    def test_failed_job_never_seals_candidate(self):
        upload = self.root / "upload"
        upload.mkdir()
        (upload / "manifest.json").write_text('{}')
        (upload / "candidate.tar").write_bytes(b'fixture')
        with patch.dict(os.environ, {"QUALIFICATION_JOB_STATUS": "failure"}):
            guard.seal(self.root)
        self.assertFalse((upload / "candidate.tar").exists())
        self.assertFalse((upload / "manifest.json").exists())
        self.assertFalse(json.loads((upload / "outcome.json").read_text())["qualified"])

    def test_missing_manifest_is_not_qualified(self):
        upload = self.root / "upload"
        upload.mkdir()
        with patch.dict(os.environ, {"QUALIFICATION_JOB_STATUS": "success"}):
            guard.seal(self.root)
        self.assertFalse(json.loads((upload / "outcome.json").read_text())["qualified"])

    def test_oversized_evidence_refuses_upload(self):
        upload = self.root / "upload"
        upload.mkdir()
        (upload / "stage.log").write_bytes(b'x'*1024)
        with patch.object(guard, "BUNDLE_LIMIT", 512):
            with self.assertRaisesRegex(guard.Refusal, "oversized"):
                guard.seal(self.root)
        self.assertFalse((upload / "outcome.json").exists())

    def test_wrong_host_environment_refuses_before_git_or_tools(self):
        with patch.dict(os.environ, {"RUNNER_ENVIRONMENT": "self-hosted"}):
            with patch.object(guard, "command") as command:
                with self.assertRaisesRegex(guard.Refusal, "standard hosted"):
                    guard.preflight(self.root, self.root)
                command.assert_not_called()

    def test_larger_runner_is_not_an_implicit_capacity_upgrade(self):
        with patch.dict(os.environ, {"RUNNER_ENVIRONMENT": "github-hosted"}):
            with patch.object(guard.platform, "system", return_value="Darwin"):
                with patch.object(guard.platform, "machine", return_value="arm64"):
                    with patch.object(guard, "command", side_effect=["8", str(16 * guard.GIB)]):
                        with self.assertRaisesRegex(guard.Refusal, "allocation"):
                            guard.preflight(self.root, self.root)

    def test_wrong_source_is_not_qualified_under_valid_control(self):
        with patch.dict(os.environ, {"RUNNER_ENVIRONMENT": "github-hosted"}):
            with patch.object(guard.platform, "system", return_value="Darwin"):
                with patch.object(guard.platform, "machine", return_value="arm64"):
                    with patch.object(guard, "command", side_effect=["3", str(7 * guard.GIB), "0" * 40]):
                        with self.assertRaisesRegex(guard.Refusal, "runtime checkout"):
                            guard.preflight(self.root, self.root)

    def test_control_pin_is_checked_independently(self):
        with patch.dict(os.environ, {"RUNNER_ENVIRONMENT": "github-hosted", "CONTROL_SHA": "a" * 40}):
            with patch.object(guard.platform, "system", return_value="Darwin"):
                with patch.object(guard.platform, "machine", return_value="arm64"):
                    with patch.object(guard, "command", side_effect=["3", str(7 * guard.GIB), guard.SOURCE, "b" * 40]):
                        with self.assertRaisesRegex(guard.Refusal, "control revision"):
                            guard.preflight(self.root, self.root)


if __name__ == "__main__":
    unittest.main()
