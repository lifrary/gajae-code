#!/usr/bin/env python3
"""Small subprocess fixtures; never builds or imports the runtime under test."""
import importlib.util
from contextlib import ExitStack, redirect_stderr
import io
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
        unrelated = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(1)"], start_new_session=True)
        try:
            with self.assertRaisesRegex(guard.Refusal, "deadline") as caught:
                self.run_child("import os,time; print(os.getpid(),flush=True); time.sleep(1)", deadline=time.monotonic() + 0.2)
            stage = caught.exception.primary_stage
            self.assertTrue(stage["process_started"])
            self.assertIsNone(stage["exit_code"])
            self.assertIsNone(stage["signal"])
            self.assertTrue(stage["cleanup"]["attempted"])
            self.assertEqual(stage["cleanup"]["observed_exit_code"], -9)
            self.assertEqual(stage["cleanup"]["observed_signal"], 9)
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


if __name__ == "__main__":
    unittest.main()
