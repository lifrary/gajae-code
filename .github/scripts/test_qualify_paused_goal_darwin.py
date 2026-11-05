#!/usr/bin/env python3
"""Small subprocess fixtures; never builds or imports the runtime under test."""
import importlib.util
from contextlib import ExitStack, redirect_stderr
import io
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import Mock, patch

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

    def test_cleanup_error_does_not_replace_primary_exit(self):
        with patch.object(guard, "stop_owned", side_effect=OSError("cleanup fixture")):
            with self.assertRaisesRegex(guard.Refusal, "command failed") as caught:
                self.run_child("raise SystemExit(7)")
        receipt = json.loads(Path(str(self.log) + ".json").read_text())
        self.assertEqual(receipt["exit_code"], 7)
        self.assertIn("cleanup fixture", receipt["cleanup_errors"][0])
        self.assertEqual(caught.exception.secondary_errors, receipt["cleanup_errors"])

    def test_receipt_write_failure_preserves_primary_error(self):
        original = Path.write_text

        def write(path, text, *args, **kwargs):
            if path.name == "stage.log.json":
                raise OSError("receipt fixture")
            return original(path, text, *args, **kwargs)

        with patch.object(Path, "write_text", write):
            with self.assertRaisesRegex(guard.Refusal, "command failed") as caught:
                self.run_child("raise SystemExit(7)")
        self.assertIn("receipt fixture", caught.exception.secondary_errors[0])
        self.assertEqual(caught.exception.primary_stage["exit_code"], 7)
        self.assertIsNone(caught.exception.primary_stage["signal"])
        self.assertTrue(caught.exception.primary_stage["process_started"])

    def persisted_child_failure(self, fail_terminal):
        original = Path.write_text
        child_argv = [sys.executable, "-B", "-c", "raise SystemExit(7)"]

        def write(path, text, *args, **kwargs):
            if path.name == "tiny.log.json" or (fail_terminal and path.name == "failure.json"):
                raise OSError("injected persistence failure")
            return original(path, text, *args, **kwargs)

        def tiny_stage(source, root):
            guard.run_stage(child_argv, self.root, root / "upload/tiny.log",
                            os.environ.copy(), time.monotonic() + 3, 12 * guard.GIB)

        stderr = io.StringIO()
        with ExitStack() as stack:
            stack.enter_context(patch.object(guard, "qualify", side_effect=tiny_stage))
            stack.enter_context(patch.object(guard, "retain_native_failure"))
            stack.enter_context(patch.object(guard, "free_bytes", return_value=12 * guard.GIB))
            stack.enter_context(patch.object(Path, "write_text", write))
            stack.enter_context(patch.dict(os.environ, {"QUALIFICATION_ROOT": str(self.root)}))
            stack.enter_context(patch.object(sys, "argv", ["control", "qualify", str(self.root)]))
            stack.enter_context(redirect_stderr(stderr))
            with self.assertRaisesRegex(guard.Refusal, "command failed") as caught:
                guard.main()
        self.assertFalse((self.root / "upload/tiny.log.json").exists())
        self.assertEqual((self.root / "upload/tiny.log").stat().st_size, 0)
        report = (json.loads(stderr.getvalue()) if fail_terminal else
                  json.loads((self.root / "upload/failure.json").read_text()))
        self.assertEqual(report["primary_stage"], caught.exception.primary_stage)
        self.assertEqual(report["primary_stage"]["argv"], child_argv)
        self.assertEqual(report["primary_stage"]["exit_code"], 7)
        self.assertIsNone(report["primary_stage"]["signal"])
        self.assertTrue(report["primary_stage"]["process_started"])
        self.assertEqual(report["primary_stage"]["failure_cause"], "command failed; no retry permitted")
        self.assertEqual(report["primary_stage"]["cleanup"]["observed_exit_code"], 7)
        self.assertIn("stage receipt persistence:", report["secondary_errors"][0])
        return report

    def test_stage_persistence_failure_keeps_exact_exit_in_terminal_record(self):
        self.persisted_child_failure(False)

    def test_combined_persistence_failures_keep_exact_exit_in_stderr(self):
        report = self.persisted_child_failure(True)
        self.assertFalse((self.root / "upload/failure.json").exists())
        self.assertIn("failure persistence:", report["secondary_errors"][1])

    def test_spawn_failure_is_not_a_numeric_child_exit(self):
        with patch.object(guard, "free_bytes", return_value=12 * guard.GIB):
            with self.assertRaises(FileNotFoundError) as caught:
                guard.run_stage([str(self.root / "absent-executable")], self.root, self.log,
                                os.environ.copy(), time.monotonic() + 3, 12 * guard.GIB)
        stage = caught.exception.primary_stage
        self.assertFalse(stage["process_started"])
        self.assertIsNone(stage["exit_code"])
        self.assertIsNone(stage["signal"])
        self.assertFalse(stage["cleanup"]["attempted"])

    def test_native_signal_remains_distinct_from_cleanup_termination(self):
        with self.assertRaises(guard.Refusal) as caught:
            self.run_child("import os,signal; os.kill(os.getpid(),signal.SIGTERM)")
        stage = caught.exception.primary_stage
        self.assertEqual(stage["exit_code"], -15)
        self.assertEqual(stage["signal"], 15)
        self.assertEqual(stage["cleanup"]["observed_exit_code"], -15)

    def test_selector_setup_failure_still_cleans_owned_child(self):
        with patch.object(guard.selectors.DefaultSelector, "register", side_effect=RuntimeError("selector fixture")):
            with self.assertRaisesRegex(RuntimeError, "selector fixture"):
                self.run_child("import time; time.sleep(1)")
        receipt = json.loads(Path(str(self.log) + ".json").read_text())
        self.assertLess(receipt["exit_code"], 0)
        self.assertEqual(receipt["cleanup_errors"], [])

    def test_deadline_stops_only_owned_process(self):
        unrelated = subprocess.Popen([sys.executable, "-c", "import sys; sys.stdin.read()"],
                                     stdin=subprocess.PIPE, start_new_session=True)
        try:
            with self.assertRaisesRegex(guard.Refusal, "deadline") as caught:
                self.run_child(
                    "from pathlib import Path; import time; end=time.monotonic()+10; "
                    "exec(\"while not Path('deadline-release').exists() and time.monotonic()<end: time.sleep(0.01)\")",
                    deadline=time.monotonic() + 0.2,
                )
            stage = caught.exception.primary_stage
            self.assertTrue(stage["process_started"])
            self.assertIsNone(stage["exit_code"])
            self.assertIsNone(stage["signal"])
            self.assertTrue(stage["cleanup"]["attempted"])
            self.assertEqual(stage["cleanup"]["observed_exit_code"], -9)
            self.assertEqual(stage["cleanup"]["observed_signal"], 9)
            self.assertIsNone(unrelated.poll())
            pid = stage["root_pid"]  # Deadline may precede the first stdout drain.
            with self.assertRaises(ProcessLookupError):
                os.kill(pid, 0)
        finally:
            (self.root / "deadline-release").touch()
            unrelated.stdin.close()
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
            with self.assertRaisesRegex(guard.Refusal, "disk") as caught:
                guard.run_stage([sys.executable, "-c", "raise SystemExit(0)"], self.root,
                                self.log, os.environ.copy(), time.monotonic() + 2, 12 * guard.GIB)
        self.assertFalse(self.log.exists())
        self.assertFalse(caught.exception.primary_stage["process_started"])
        self.assertIsNone(caught.exception.primary_stage["exit_code"])

    def test_growth_budget_refuses_even_above_floor(self):
        with patch.object(guard, "free_bytes", return_value=5 * guard.GIB):
            with self.assertRaisesRegex(guard.Refusal, "growth"):
                guard.enforce_capacity(self.root, 12 * guard.GIB)

    def test_elapsed_work_budget_prevents_start(self):
        with self.assertRaisesRegex(guard.Refusal, "before stage"):
            self.run_child("print('must not start')", deadline=time.monotonic() - 1)
        self.assertFalse(self.log.exists())

    def test_detached_descendant_is_bound_and_settled(self):
        script = (
            "import subprocess,sys; "
            "p=subprocess.Popen([sys.executable,'-c','import time; time.sleep(0.4)'],start_new_session=True); "
            "print(p.pid,flush=True); p.wait()"
        )
        self.run_child(script)
        child = int(self.log.read_text().strip())
        result = subprocess.run(["ps", "-p", str(child), "-o", "stat="], capture_output=True, text=True)
        self.assertTrue(result.returncode == 1 or result.stdout.strip().startswith("Z"),
                        "detached fixture must not remain executable")
        receipt = json.loads(Path(str(self.log) + ".json").read_text())
        self.assertEqual(receipt["exit_code"], 0)
        self.assertEqual(receipt["peak_sampled_processes"], 2)
        self.assertGreaterEqual(receipt["ownership"]["settled_count"], 2)
        self.assertEqual(receipt["cleanup_errors"], [])

    def test_root_exit_keeps_detached_child_accounted_until_settlement(self):
        child_script = (
            "from pathlib import Path; import time; end=time.monotonic()+2; "
            "exec(\"while not Path('child-release').exists() and time.monotonic()<end: time.sleep(0.005)\")"
        )
        script = (
            "import subprocess,sys,time; from pathlib import Path; "
            f"p=subprocess.Popen([sys.executable,'-B','-c',{child_script!r}],"
            "start_new_session=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL); "
            "print(p.pid,flush=True); end=time.monotonic()+2.5; "
            "exec(\"while not Path('root-release').exists() and time.monotonic()<end: time.sleep(0.005)\")"
        )
        sample = guard.OwnedProcesses.sample
        bound_child = {}
        orphan_samples = []

        def release_when_bound(owner, deadline):
            live, names = sample(owner, deadline)
            for pid, info in live.items():
                if pid != owner.root:
                    bound_child[pid] = info
            if bound_child:
                (self.root / "root-release").touch()
            if owner.root not in live and live:
                orphan_samples.append(dict(live))
                (self.root / "child-release").touch()
            return live, names

        try:
            with patch.object(guard.OwnedProcesses, "sample", release_when_bound):
                self.run_child(script)
            self.assertTrue(orphan_samples, "root EOF must not silently drop the live detached child")
            self.assertTrue(all(info[0] == 1 for sample in orphan_samples for info in sample.values()))
            self.assertTrue(all(info[2] > 0 for sample in orphan_samples for info in sample.values()))
            receipt = json.loads(Path(str(self.log) + ".json").read_text())
            self.assertEqual(receipt["exit_code"], 0)
            ownership = receipt["ownership"]
            self.assertGreaterEqual(ownership["settled_count"] +
                                    sum(row["status"] == 5 for row in ownership["owned"]), 2)
        finally:
            # Only this fixture's previously bound Python child, never a group.
            (self.root / "child-release").touch()
            for pid, before in bound_child.items():
                now = guard.process_info(pid)
                if now is not None and now[3] == before[3] and now[4] != 5:
                    try:
                        os.kill(pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass

    def test_refusal_snapshot_survives_cleanup_and_receipt_persistence_failure(self):
        sample = guard.OwnedProcesses.sample
        write = Path.write_text
        first = True

        def refuse_once(owner, deadline):
            nonlocal first
            if first:
                first = False
                owner.refuse("unbound descendant identity", 9999999, (9999998, 9999999, 1, (1, 1), 2))
            return sample(owner, deadline)

        def fail_receipt(path, text, *args, **kwargs):
            if path.name == "stage.log.json":
                raise OSError("fixture receipt unavailable")
            return write(path, text, *args, **kwargs)

        with patch.object(guard.OwnedProcesses, "sample", refuse_once), patch.object(Path, "write_text", fail_receipt):
            with self.assertRaisesRegex(guard.Refusal, "unbound descendant") as caught:
                self.run_child("import time; time.sleep(1)")
        stage = caught.exception.primary_stage
        self.assertIsNone(stage["exit_code"])
        self.assertIsNone(stage["signal"])
        self.assertEqual(stage["ownership"]["offending"]["pid"], 9999999)
        self.assertEqual(stage["cleanup"]["observed_signal"], 9)
        self.assertTrue(stage["cleanup"]["ownership"]["settlement_uncertain"])
        self.assertTrue(any("cleanup not settled" in e for e in caught.exception.secondary_errors))
        self.assertTrue(any("receipt unavailable" in e for e in caught.exception.secondary_errors))
        self.assertLess(len(json.dumps(stage).encode()), 65536)

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


class QualificationTests(unittest.TestCase):
    """Only control orchestration runs; every target command is a mock."""

    SOURCES = [
        "packages/coding-agent/src/session/agent-session.ts",
        "packages/coding-agent/test/agent-session-todo-reminder.test.ts",
        "scripts/ci-validate-darwin-receipt.ts",
        "packages/coding-agent/scripts/build-binary.ts",
        "packages/coding-agent/scripts/generate-docs-index.ts",
        "packages/coding-agent/package.json",
        "scripts/ci-build-native.ts",
        "packages/natives/scripts/build-native.ts",
        "packages/natives/scripts/diagnostic-artifact-manifest.ts",
    ]
    NATIVE_FILES = [
        "packages/natives/native/pi_natives.darwin-arm64.node",
        "packages/natives/native/pi_natives.darwin-arm64.node.provenance.json",
        "packages/natives/native/diagnostic-artifact.json",
    ]
    GENERATED_DOCS = "packages/coding-agent/src/internal-urls/docs-index.generated.ts"
    PHASES = [
        "dependencies", "native", "docs-index", "binary", "loader-source",
        "loader-compiled", "goal-behavior", "compiled-smoke",
        "receipt-write", "receipt-validate", "package",
    ]

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.source = self.root / "source"
        self.source.mkdir()
        (self.source / "docs").mkdir()
        self.upload = self.root / "upload"
        self.upload.mkdir()
        self.clock = 100.0
        self.calls = []
        self.failure_at = None
        self.remove_provenance = None
        self.generator_seconds = 3
        self.native_size = None
        self.omit_generated = False
        self.primary = guard.Refusal("fixture primary build failure")
        for name in self.SOURCES:
            file = self.source / name
            file.parent.mkdir(parents=True, exist_ok=True)
            file.write_text("inert source fixture: " + name)
        (self.upload / "preflight.json").write_text(json.dumps({
            "source_sha": guard.SOURCE, "control_sha": "c" * 40,
            "started": self.clock, "initial_free_bytes": 12 * guard.GIB,
        }))

    def tearDown(self):
        self.temp.cleanup()

    def command(self, argv, cwd=None):
        if argv[:2] == ["rustup", "which"]:
            return "/fixture/rustc"
        return {("bun", "--version"): "1.4.0", ("node", "--version"): "v24.0.0",
                ("/fixture/rustc", "--version"): "inert rustc fixture"}[tuple(argv)]

    def fake_stage(self, argv, cwd, log, env, deadline, initial_free):
        name = log.stem
        self.calls.append((name, argv, deadline))
        log.write_text("inert mocked target output\n")
        if name == "native":
            addon = self.source / self.NATIVE_FILES[0]
            addon.parent.mkdir(parents=True, exist_ok=True)
            addon.write_bytes(b"inert native fixture")
            if self.native_size is not None:
                with addon.open("r+b") as stream:
                    stream.truncate(self.native_size)
            digest = guard.digest(addon)
            (self.source / self.NATIVE_FILES[1]).write_text(json.dumps({
                "schema": "gjc.diagnostic-artifact-provenance", "version": "fixture",
                "artifact": addon.name, "sha256": digest,
            }))
            (self.source / self.NATIVE_FILES[2]).write_text(json.dumps({
                "schema": "gjc.diagnostic-artifact", "version": "fixture",
                "artifacts": {addon.name: digest},
            }))
        elif name == "docs-index":
            generated = self.source / self.GENERATED_DOCS
            generated.parent.mkdir(parents=True, exist_ok=True)
            if not self.omit_generated:
                generated.write_text("inert generated docs fixture")
            self.clock += self.generator_seconds
        elif name == "binary":
            binary = self.source / "packages/coding-agent/dist/gjc"
            binary.parent.mkdir(parents=True, exist_ok=True)
            binary.write_bytes(b"inert binary fixture")
        elif name == "receipt-write":
            (self.source / ".ci-dev-darwin-arm64-receipt.json").write_text('{"mock": true}')
        if name == self.failure_at:
            if self.remove_provenance == "sidecar":
                (self.source / self.NATIVE_FILES[1]).unlink()
            elif self.remove_provenance == "source":
                (self.upload / "source-provenance.json").unlink()
            elif self.remove_provenance == "mismatch":
                sidecar = self.source / self.NATIVE_FILES[1]
                data = json.loads(sidecar.read_text())
                data["sha256"] = "0" * 64
                sidecar.write_text(json.dumps(data))
            raise self.primary

    def invoke(self, extra_patches=()):
        with ExitStack() as stack:
            stack.enter_context(patch.object(guard, "command", side_effect=self.command))
            stack.enter_context(patch.object(guard, "run_stage", side_effect=self.fake_stage))
            stack.enter_context(patch.object(guard, "free_bytes", return_value=12 * guard.GIB))
            stack.enter_context(patch.object(guard.time, "monotonic", side_effect=lambda: self.clock))
            stack.enter_context(patch.dict(os.environ, {"QUALIFICATION_ROOT": str(self.root)}))
            stack.enter_context(patch.object(sys, "argv", ["guard", "qualify", str(self.source)]))
            for context in extra_patches:
                stack.enter_context(context)
            guard.main()

    def assert_primary_failure(self, extra_patches=()):
        with self.assertRaises(guard.Refusal) as caught:
            self.invoke(extra_patches)
        self.assertIs(caught.exception, self.primary)
        self.assertEqual(json.loads((self.upload / "failure.json").read_text())["error"], str(self.primary))
        self.assertFalse((self.upload / "manifest.json").exists())
        self.assertFalse((self.upload / "candidate.tar").exists())
        return json.loads((self.upload / "failed-native.json").read_text())

    def test_generator_failure_prevents_compile_and_preserves_native_phase_only(self):
        self.failure_at = "docs-index"
        report = self.assert_primary_failure()
        self.assertEqual([x[0] for x in self.calls], ["dependencies", "native", "docs-index"])
        self.assertEqual(report["phases"]["docs-index"], "failed")
        self.assertEqual(report["phases"]["binary"], "unexecuted")
        self.assertFalse(report["qualified"])

    def test_successful_order_and_generated_identity_share_compile_budget(self):
        self.invoke()
        self.assertEqual([x[0] for x in self.calls], self.PHASES[:-1])
        generator, binary = self.calls[2:4]
        self.assertEqual(generator[1], ["bun", "--cwd=packages/coding-agent", "run", "generate-docs-index"])
        self.assertEqual(generator[2], binary[2])
        self.assertEqual(binary[2], 700)
        generated = json.loads((self.upload / "generated-docs.json").read_text())
        self.assertEqual(generated["sha256"], guard.digest(self.source / self.GENERATED_DOCS))
        self.assertEqual(generated["source_sha"], guard.SOURCE)
        self.assertEqual(generated["generator_sha256"], guard.digest(self.source / generated["generator"]))
        self.assertEqual(generated["docs_root"], "docs")
        self.assertEqual(generated["docs_tree_at_pinned_source"], "23176c8b8406d03d3eb62ceb1c3e2ca8d86c804d")
        manifest = json.loads((self.upload / "manifest.json").read_text())
        self.assertEqual(manifest["generated_docs"], generated)

    def test_missing_generated_output_prevents_compile(self):
        self.omit_generated = True
        with self.assertRaises(FileNotFoundError):
            self.invoke()
        self.assertEqual([x[0] for x in self.calls], ["dependencies", "native", "docs-index"])
        report = json.loads((self.upload / "failed-native.json").read_text())
        self.assertEqual(report["phases"]["docs-index"], "failed")
        self.assertEqual(report["phases"]["binary"], "unexecuted")

    def test_nearer_documentation_origin_prevents_generator_and_compile(self):
        (self.source / "packages/coding-agent/docs").mkdir()
        with self.assertRaisesRegex(guard.Refusal, "documentation origin"):
            self.invoke()
        self.assertEqual([x[0] for x in self.calls], ["dependencies", "native"])
        report = json.loads((self.upload / "failed-native.json").read_text())
        self.assertEqual(report["phases"]["docs-index"], "failed")

    def test_later_compile_failure_retains_bounded_native_and_source_provenance(self):
        self.failure_at = "binary"
        report = self.assert_primary_failure()
        self.assertFalse(report["qualified"])
        self.assertTrue(report["producer_binding_verified"])
        self.assertEqual(report["phases"]["native"], "passed")
        self.assertEqual(report["phases"]["binary"], "failed")
        self.assertTrue(all(report["phases"][name] == "unexecuted" for name in self.PHASES[4:]))
        for name, metadata in report["files"].items():
            retained = self.upload / metadata["retained_path"]
            self.assertEqual(retained.read_bytes(), (self.source / name).read_bytes())
            self.assertEqual(metadata["sha256"], guard.digest(retained))
        self.assertTrue(all(entry["unchanged"] for entry in report["source_files"].values()))
        with patch.dict(os.environ, {"QUALIFICATION_JOB_STATUS": "failure"}):
            guard.seal(self.root)
        self.assertFalse(json.loads((self.upload / "outcome.json").read_text())["qualified"])
        self.assertLess(guard.upload_size(self.upload), guard.BUNDLE_LIMIT)

    def test_missing_sidecar_is_explicit_not_native_qualification(self):
        self.failure_at = "binary"
        self.remove_provenance = "sidecar"
        report = self.assert_primary_failure()
        self.assertIn("error", report["files"][self.NATIVE_FILES[1]])
        self.assertFalse(report["producer_binding_verified"])

    def test_missing_source_provenance_remains_missing_despite_current_hashes(self):
        self.failure_at = "binary"
        self.remove_provenance = "source"
        report = self.assert_primary_failure()
        self.assertIn("source provenance:", report["collection_errors"][0])
        self.assertTrue(all(not entry["unchanged"] for entry in report["source_files"].values()))
        self.assertTrue(all("error" in entry for entry in report["source_files"].values()))

    def test_mismatched_producer_digest_is_not_verified(self):
        self.failure_at = "binary"
        self.remove_provenance = "mismatch"
        report = self.assert_primary_failure()
        self.assertFalse(report["producer_binding_verified"])
        self.assertIn("binding mismatch", report["collection_errors"][0])

    def test_unsettled_owned_cleanup_blocks_native_copy(self):
        self.failure_at = "binary"
        self.primary.secondary_errors = ["owned cleanup: fixture reader unsettled"]
        report = self.assert_primary_failure()
        self.assertTrue(all("unsettled" in entry["error"] for entry in report["files"].values()))
        self.assertFalse((self.upload / "failed-native").exists())
        failure = json.loads((self.upload / "failure.json").read_text())
        self.assertEqual(failure["secondary_errors"], self.primary.secondary_errors)

    def test_copy_failure_keeps_original_build_error_and_partial_evidence(self):
        self.failure_at = "binary"
        original = guard.file_evidence

        def read(file, *args, **kwargs):
            if file.name.endswith(".node") and len(args) == 5:
                raise OSError("copy fixture")
            return original(file, *args, **kwargs)

        report = self.assert_primary_failure([patch.object(guard, "file_evidence", side_effect=read)])
        self.assertIn("copy fixture", report["files"][self.NATIVE_FILES[0]]["error"])
        self.assertFalse(report["producer_binding_verified"])

    def test_collection_exception_does_not_mask_primary_build_error(self):
        self.failure_at = "binary"
        with self.assertRaises(guard.Refusal) as caught:
            self.invoke([patch.object(guard, "retain_native_failure", side_effect=OSError("collection fixture"))])
        self.assertIs(caught.exception, self.primary)
        failure = json.loads((self.upload / "failure.json").read_text())
        self.assertEqual(failure["error"], str(self.primary))
        self.assertIn("collection fixture", failure["secondary_errors"][0])
        self.assertFalse((self.upload / "manifest.json").exists())

    def test_failure_record_persistence_reports_original_error_to_stderr(self):
        self.failure_at = "binary"
        original = Path.write_text

        def write(path, text, *args, **kwargs):
            if path.name == "failure.json":
                raise OSError("failure persistence fixture")
            return original(path, text, *args, **kwargs)

        stderr = io.StringIO()
        with redirect_stderr(stderr):
            with self.assertRaises(guard.Refusal) as caught:
                self.invoke([patch.object(Path, "write_text", write)])
        self.assertIs(caught.exception, self.primary)
        report = json.loads(stderr.getvalue())
        self.assertEqual(report["error"], str(self.primary))
        self.assertIn("failure persistence fixture", report["secondary_errors"][0])

    def test_exhausted_generator_budget_never_renews_compile_or_copy_time(self):
        self.generator_seconds = 601
        with self.assertRaisesRegex(guard.Refusal, "deadline"):
            self.invoke()
        self.assertEqual([x[0] for x in self.calls], ["dependencies", "native", "docs-index"])
        report = json.loads((self.upload / "failed-native.json").read_text())
        self.assertTrue(all("deadline" in entry["error"] for entry in report["files"].values()))
        self.assertFalse((self.upload / "failed-native").exists())

    def test_artifact_budget_refuses_copy_without_enlarging_limit(self):
        self.failure_at = "binary"
        self.native_size = 3 * 1024 ** 2
        report = self.assert_primary_failure([patch.object(guard, "BUNDLE_LIMIT", 2 * 1024 ** 2)])
        self.assertIn("size", report["files"][self.NATIVE_FILES[0]]["error"])
        self.assertFalse((self.upload / "failed-native" / Path(self.NATIVE_FILES[0]).name).exists())
        self.assertLess(guard.upload_size(self.upload), 2 * 1024 ** 2)


class KernelIdentityTests(unittest.TestCase):
    def test_short_or_permission_denied_reply_is_not_absence(self):
        for result, error in [(0, guard.errno.EPERM), (-1, guard.errno.EPERM), (231, 0)]:
            with self.subTest(result=result, error=error):
                def api(*args):
                    guard.ctypes.set_errno(error)
                    return result
                with patch.object(guard, "process_api", return_value=api):
                    with self.assertRaisesRegex(guard.Refusal, "unreadable kernel"):
                        guard.process_info(10)

    def test_kernel_esrch_confirms_absence(self):
        def api(*args):
            guard.ctypes.set_errno(guard.errno.ESRCH)
            return 0
        with patch.object(guard, "process_api", return_value=api):
            self.assertIsNone(guard.process_info(10))

    def test_missing_task_memory_requires_a_confirmed_zombie(self):
        for status in (5, 2):
            with self.subTest(status=status):
                def api(pid, flavor, arg, buffer, size):
                    if flavor == 2:
                        guard.ctypes.set_errno(guard.errno.ESRCH)
                        return 0
                    bsd = guard.ctypes.cast(buffer, guard.ctypes.POINTER(guard._BSDInfo)).contents
                    bsd.pid, bsd.ppid, bsd.pgid = pid, 1, pid
                    bsd.start_sec, bsd.start_usec, bsd.status = 1000, 7, status
                    return size
                with patch.object(guard, "process_api", return_value=api):
                    if status == 5:
                        self.assertEqual(guard.process_info(10), (1, 10, 0, (1000, 7), 5))
                    else:
                        with self.assertRaisesRegex(guard.Refusal, "resident memory"):
                            guard.process_info(10)

    def test_mismatched_kernel_pid_is_refused(self):
        def api(pid, flavor, arg, buffer, size):
            info = guard.ctypes.cast(buffer, guard.ctypes.POINTER(guard._TaskAllInfo)).contents
            info.bsd.pid, info.bsd.start_sec = pid + 1, 1000
            return size
        with patch.object(guard, "process_api", return_value=api):
            with self.assertRaisesRegex(guard.Refusal, "invalid kernel"):
                guard.process_info(10)


class OwnershipTests(unittest.TestCase):
    """Deterministic samples; numeric identities never refer to real host processes."""
    def setUp(self):
        self.info = {
            10: (1, 10, 100, (1000, 10), 2),
            11: (10, 11, 200, (1000, 11), 2),
            12: (11, 11, 300, (1000, 12), 2),
            99: (1, 99, 900, (1000, 99), 2),
        }
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(patch.object(guard.os, "getpid", return_value=1))
        self.stack.enter_context(patch.object(guard, "process_info", side_effect=self.info.get))
        self.stack.enter_context(patch.object(guard, "table", side_effect=self.rows))
        self.owner = guard.OwnedProcesses(10)
        self.process = Mock(pid=10)
        self.process.poll.return_value = 0

    def rows(self, **kwargs):
        # ps is discovery only; deliberately wrong RSS cannot replace the
        # identity-bound kernel reading. Names never supply ancestry.
        return {pid: (r[0], r[1], 1, "coarse-second", "same-binary-sensitive-marker")
                for pid, r in self.info.items()}

    def sample(self):
        return self.owner.sample(time.monotonic() + 2)

    def test_single_and_detached_groups_use_ancestry_not_names(self):
        live, _ = self.sample()
        self.assertEqual(set(live), {10, 11, 12})
        self.assertEqual(sum(r[2] for r in live.values()), 600)
        self.assertNotIn(99, self.owner.owned)
        snapshot = json.dumps(self.owner.snapshot())
        self.assertNotIn("sensitive-marker", snapshot)
        self.assertNotIn('"pid": 99', snapshot)
        self.assertLess(len(snapshot.encode()), 65536)

    def test_normal_single_group_admission(self):
        self.info[11] = (10, 10, 200, (1000, 11), 2)
        self.info[12] = (11, 10, 300, (1000, 12), 2)
        self.assertEqual(set(self.sample()[0]), {10, 11, 12})

    def test_reparented_identity_and_its_new_child_remain_accounted(self):
        self.sample()
        del self.info[10]
        self.info[11] = (1, 11, 400, (1000, 11), 2)
        self.info[13] = (11, 13, 500, (1000, 13), 2)
        live, _ = self.sample()
        self.assertEqual(set(live), {11, 12, 13})
        self.assertEqual(sum(r[2] for r in live.values()), 1200)
        self.assertEqual(live[11][3], (1000, 11))

    def test_unobserved_group_member_is_never_admitted(self):
        self.info[20] = (1, 10, 50, (1000, 20), 2)
        with self.assertRaisesRegex(guard.Refusal, "unbound member"):
            self.sample()
        self.assertNotIn(20, self.owner.owned)
        self.assertEqual(self.owner.snapshot()["offending"]["pid"], 20)

    def test_new_child_without_parent_identity_continuity_is_refused(self):
        rows = self.rows()
        self.info[11] = (99, 11, 200, (1000, 11), 2)
        with patch.object(guard, "table", return_value=rows):
            with self.assertRaisesRegex(guard.Refusal, "unbound descendant"):
                self.sample()
        self.assertNotIn(11, self.owner.owned)
        self.assertEqual(self.owner.snapshot()["offending"]["parent"], 99)

    def test_parent_replacement_during_admission_is_refused(self):
        reads = 0

        def identity(pid):
            nonlocal reads
            if pid == 10:
                reads += 1
                if reads >= 3:
                    return (1, 10, 100, (1000, 999), 2)
            return self.info.get(pid)

        with patch.object(guard, "process_info", side_effect=identity):
            with self.assertRaisesRegex(guard.Refusal, "unbound descendant"):
                self.sample()
        self.assertNotIn(11, self.owner.owned)

    def test_microsecond_pid_replacement_is_refused_and_never_signalled(self):
        self.sample()
        self.info[11] = (10, 11, 200, (1000, 999), 2)
        with self.assertRaisesRegex(guard.Refusal, "PID identity changed"):
            self.sample()
        with patch.object(guard.os, "kill") as kill, patch.object(guard.os, "killpg") as killpg:
            with self.assertRaisesRegex(guard.Refusal, "cleanup not settled"):
                guard.stop_owned(self.process, self.owner)
        self.assertNotIn(11, [call.args[0] for call in kill.call_args_list])
        killpg.assert_not_called()
        self.assertEqual(self.owner.snapshot()["offending"]["expected_birth"], (1000, 11))

    def test_cleanup_revalidates_again_after_its_sample(self):
        self.info = {10: self.info[10]}
        original = self.owner.sample

        def replacement_after_sample(deadline):
            value = original(deadline)
            self.info[10] = (1, 10, 100, (1000, 999), 2)
            return value

        with patch.object(guard, "process_info", side_effect=lambda pid: self.info.get(pid)):
            with patch.object(self.owner, "sample", side_effect=replacement_after_sample):
                with patch.object(guard.os, "kill") as kill:
                    with self.assertRaises(guard.Refusal) as caught:
                        guard.stop_owned(self.process, self.owner)
        kill.assert_not_called()
        self.assertIn("cleanup PID identity", str(caught.exception))

    def test_cleanup_stops_bound_orphans_not_unrelated_processes(self):
        self.sample()
        del self.info[10]
        self.info[11] = (1, 11, 200, (1000, 11), 2)
        signalled = []

        def kill(pid, sig):
            self.assertEqual(sig, signal.SIGKILL)
            signalled.append(pid)
            self.info.pop(pid)

        with patch.object(guard.os, "kill", side_effect=kill), patch.object(guard.os, "killpg") as killpg:
            guard.stop_owned(self.process, self.owner)
        self.assertEqual(set(signalled), {11, 12})
        self.assertIn(99, self.info)
        self.assertEqual(self.owner.owned, {})
        killpg.assert_not_called()

    def test_cleanup_failure_cannot_claim_settlement(self):
        self.sample()
        with patch.object(guard.os, "kill", side_effect=PermissionError("fixture signal refused")):
            with self.assertRaisesRegex(guard.Refusal, "cleanup not settled.*signal refused"):
                guard.stop_owned(self.process, self.owner)
        self.assertTrue(self.owner.owned)

    def test_disappearance_does_not_erase_prior_unbound_identity_gap(self):
        self.info[20] = (1, 10, 50, (1000, 20), 2)
        with self.assertRaises(guard.Refusal):
            self.sample()
        self.info.clear()
        with patch.object(guard.os, "kill") as kill:
            with self.assertRaisesRegex(guard.Refusal, "ownership became uncertain"):
                guard.stop_owned(self.process, self.owner)
        kill.assert_not_called()
        self.assertTrue(self.owner.snapshot()["settlement_uncertain"])
        self.assertEqual(self.owner.snapshot()["offending"]["pid"], 20)

    def test_cleanup_deadline_refuses_unsettled_survivors(self):
        self.sample()
        clock = iter(range(100))
        with patch.object(guard.time, "monotonic", side_effect=lambda: next(clock)):
            with patch.object(guard.os, "kill"):
                with self.assertRaisesRegex(guard.Refusal, "settlement deadline"):
                    guard.stop_owned(self.process, self.owner)

    def test_unreadable_sample_cannot_be_promoted_to_clean_settlement(self):
        with patch.object(guard, "process_info", side_effect=guard.Refusal("unreadable identity")):
            with self.assertRaisesRegex(guard.Refusal, "unreadable identity"):
                self.sample()
        self.info.clear()
        with self.assertRaisesRegex(guard.Refusal, "ownership became uncertain"):
            guard.stop_owned(self.process, self.owner)

    def test_unbound_group_member_survives_cleanup_without_becoming_owned(self):
        self.info[20] = (1, 10, 50, (1000, 20), 2)
        with self.assertRaises(guard.Refusal):
            self.sample()
        with patch.object(guard.os, "kill") as kill:
            with self.assertRaisesRegex(guard.Refusal, "cleanup not settled"):
                guard.stop_owned(self.process, self.owner)
        self.assertNotIn(20, [call.args[0] for call in kill.call_args_list])
        self.assertNotIn(99, [call.args[0] for call in kill.call_args_list])

    def test_process_ceiling_and_diagnostic_size_remain_bounded(self):
        for pid in range(100, 170):
            self.info[pid] = (10, 10, 1, (1000, pid), 2)
        with self.assertRaisesRegex(guard.Refusal, "process-count ceiling"):
            self.sample()
        snapshot = self.owner.snapshot()
        self.assertEqual(len(snapshot["owned"]), guard.PROCESS_LIMIT + 1)
        self.assertLess(len(json.dumps(snapshot).encode()), 65536)
        self.assertIsNotNone(snapshot["offending"])

    def test_settled_zombies_are_nonexecuting_not_successful_child_exits(self):
        self.sample()
        del self.info[10]
        self.info[11] = (1, 11, 0, (1000, 11), 5)
        self.info[12] = (1, 11, 0, (1000, 12), 5)
        self.assertEqual(self.sample()[0], {})
        self.assertEqual(self.owner.snapshot()["owned"][0]["status"], 5)

    def test_expired_deadline_does_not_start_another_sampler(self):
        with patch.object(guard, "table") as table:
            with self.assertRaisesRegex(guard.Refusal, "deadline"):
                self.owner.sample(time.monotonic() - 1)
        table.assert_not_called()

    def test_sampler_timeout_is_a_refusal_with_uncertain_settlement(self):
        with patch.object(guard, "table", side_effect=subprocess.TimeoutExpired(["ps"], 0.1)):
            with self.assertRaisesRegex(guard.Refusal, "process sampling deadline"):
                self.sample()
        self.assertTrue(self.owner.snapshot()["settlement_uncertain"])


if __name__ == "__main__":
    unittest.main()
