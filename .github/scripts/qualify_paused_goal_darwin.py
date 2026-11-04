#!/usr/bin/env python3
"""Control-plane wrapper only; never imports target packages or reimplements receipts."""
import hashlib
import json
import os
from pathlib import Path
import platform
import selectors
import shutil
import signal
import subprocess
import sys
import tarfile
import time

SOURCE = "27dd04bc8f90333a16cf3c385fb65278b71bc4a4"
GIB = 1024 ** 3
ENTRY_FREE = 10 * GIB
FREE_FLOOR = 4 * GIB
DISK_GROWTH = 6 * GIB
RSS_LIMIT = 4608 * 1024 ** 2
PROCESS_LIMIT = 64
LOG_LIMIT = 8 * 1024 ** 2
BUNDLE_LIMIT = 512 * 1024 ** 2
WORK_SECONDS = 40 * 60  # leaves five of the job's 45 minutes for upload/cleanup


class Refusal(RuntimeError):
    pass


def digest(file):
    value = hashlib.sha256()
    with Path(file).open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(block)
    return value.hexdigest()


def command(argv, cwd=None):
    return subprocess.check_output(argv, cwd=cwd, text=True, timeout=10).strip()


def free_bytes(directory):
    return shutil.disk_usage(directory).free


def table():
    rows = {}
    text = command(["ps", "-axo", "pid=,ppid=,pgid=,rss=,lstart=,comm="])
    for line in text.splitlines():
        parts = line.split(None, 9)
        if len(parts) != 10:
            raise Refusal("unreadable process identity")
        pid, parent, group, rss = map(int, parts[:4])
        rows[pid] = (parent, group, rss * 1024, " ".join(parts[4:9]), parts[9])
    return rows


def owned_tree(pid, rows):
    owned = {p for p, row in rows.items() if p == pid or row[1] == pid}
    while True:
        children = {p for p, row in rows.items() if row[0] in owned}
        enlarged = owned | children
        if enlarged == owned:
            return {p: rows[p] for p in owned}
        owned = enlarged


def stop_owned(process, observed):
    # Only this wrapper's isolated subprocess group and observed descendants.
    # Revalidate birth/parent/group before signalling an escaped descendant.
    pid = process.pid
    try:
        current = table()
        # Descendants first: killing the root first can reparent an escaped
        # process and invalidate the very identity used to clean it up.
        for child, before in reversed(list(observed.items())):
            if child == pid:
                continue
            now = current.get(child)
            if not now or (now[0], now[1], now[3]) != (before[0], before[1], before[3]):
                continue
            try:
                os.kill(child, signal.SIGKILL)
            except ProcessLookupError:
                pass
    finally:
        if process.poll() is None:
            try:
                os.killpg(pid, signal.SIGKILL)
            except ProcessLookupError:
                pass


def enforce_capacity(root, initial_free):
    remaining = free_bytes(root)
    if remaining < FREE_FLOOR or initial_free - remaining > DISK_GROWTH:
        raise Refusal("disk safety floor or growth budget reached")
    return remaining


def run_stage(argv, cwd, log, env, deadline, initial_free, rss_limit=RSS_LIMIT, log_limit=LOG_LIMIT):
    enforce_capacity(cwd, initial_free)
    if time.monotonic() >= deadline:
        raise Refusal("whole-job work budget exhausted before stage")
    process = subprocess.Popen(argv, cwd=cwd, env=env, stdout=subprocess.PIPE,
                               stderr=subprocess.STDOUT, start_new_session=True)
    observed = {}
    peak_rss = 0
    peak_processes = 0
    executables = set()
    written = 0
    start = time.monotonic()
    failure = None
    selector = selectors.DefaultSelector()
    selector.register(process.stdout, selectors.EVENT_READ)
    try:
        with Path(log).open("xb") as output:
            eof = False
            while process.poll() is None or not eof:
                now = time.monotonic()
                if now >= deadline:
                    raise Refusal("stage or whole-job deadline reached")
                enforce_capacity(cwd, initial_free)
                observed = owned_tree(process.pid, table())
                executables.update(row[4] for row in observed.values())
                if len(executables) > 128:
                    raise Refusal("observed executable inventory ceiling reached")
                peak_rss = max(peak_rss, sum(row[2] for row in observed.values()))
                peak_processes = max(peak_processes, len(observed))
                if any(row[1] != process.pid for row in observed.values()):
                    raise Refusal("subprocess escaped its owned process group")
                if peak_rss > rss_limit or len(observed) > PROCESS_LIMIT:
                    raise Refusal("sampled process-tree memory or process-count ceiling reached")
                for key, _ in selector.select(timeout=0.25):
                    block = os.read(key.fd, 65536)
                    if not block:
                        eof = True
                        selector.unregister(key.fileobj)
                        continue
                    if written + len(block) > log_limit:
                        raise Refusal("stage log size ceiling reached")
                    output.write(block)
                    written += len(block)
            if process.wait(timeout=2) != 0:
                raise Refusal("command failed; no retry permitted")
            observed = owned_tree(process.pid, table())
            if observed:
                raise Refusal("descendants remained after stage exit")
    except BaseException as error:
        failure = str(error)
        try:
            stop_owned(process, observed)
        finally:
            process.wait(timeout=5)
        raise
    finally:
        selector.close()
        process.stdout.close()
        Path(str(log) + ".json").write_text(json.dumps({
            "argv": argv, "exit_code": process.returncode, "failure": failure,
            "seconds": round(time.monotonic() - start, 3), "peak_sampled_tree_rss": peak_rss,
            "peak_sampled_processes": peak_processes, "log_bytes": written,
            "observed_executables": sorted(executables),
        }, indent=2) + "\n")


def preflight(source, root):
    upload = root / "upload"
    upload.mkdir(exist_ok=True)
    control = Path(__file__).resolve().parents[2]
    if os.environ.get("RUNNER_ENVIRONMENT") != "github-hosted":
        raise Refusal("only a standard hosted job is eligible")
    if platform.system() != "Darwin" or platform.machine() != "arm64":
        raise Refusal("Darwin arm64 required")
    cpus = int(command(["sysctl", "-n", "hw.logicalcpu"]))
    memory = int(command(["sysctl", "-n", "hw.memsize"]))
    if cpus != 3 or not 6 * GIB <= memory <= 7 * GIB:
        raise Refusal("runner exceeds approved standard allocation")
    if command(["git", "rev-parse", "HEAD"], source) != SOURCE:
        raise Refusal("runtime checkout differs from approved source")
    control_sha = command(["git", "rev-parse", "HEAD"], control)
    if control_sha != os.environ["CONTROL_SHA"]:
        raise Refusal("control revision differs from dispatch pin")
    if command(["git", "status", "--porcelain"], source):
        raise Refusal("runtime checkout is not clean")
    available = free_bytes(source)
    if available < ENTRY_FREE:
        raise Refusal("less than 10 GiB starting free space")
    started = json.loads((root / "started.json").read_text())["monotonic"]
    receipt = {"source_sha": SOURCE, "control_sha": control_sha, "logical_cpus": cpus,
               "physical_memory": memory, "initial_free_bytes": available, "started": started,
               "limits": {"rss_sampled": RSS_LIMIT, "free_floor": FREE_FLOOR,
                          "disk_growth": DISK_GROWTH, "processes": PROCESS_LIMIT,
                          "stage_log_bytes": LOG_LIMIT, "bundle_bytes": BUNDLE_LIMIT,
                          "work_seconds_from_first_step": WORK_SECONDS}}
    (upload / "preflight.json").write_text(json.dumps(receipt, indent=2) + "\n")


def qualify(source, root):
    upload = root / "upload"
    pre = json.loads((upload / "preflight.json").read_text())
    deadline = pre["started"] + WORK_SECONDS
    enforce_capacity(source, pre["initial_free_bytes"])
    if time.monotonic() >= deadline:
        raise Refusal("setup exhausted the work budget")
    critical_sources = [
        "packages/coding-agent/src/session/agent-session.ts",
        "packages/coding-agent/test/agent-session-todo-reminder.test.ts",
        "scripts/ci-validate-darwin-receipt.ts",
        "packages/coding-agent/scripts/build-binary.ts",
    ]
    source_hashes = {name: digest(source / name) for name in critical_sources}
    env = dict(os.environ)
    # Match the existing Darwin job, bypassing Homebrew's rustup shadow proxies.
    rustc = command(["rustup", "which", "--toolchain", "nightly-2026-08-12", "rustc"])
    env["PATH"] = str(Path(rustc).parent) + os.pathsep + env["PATH"]
    env.update(TARGET_PLATFORM="darwin", TARGET_ARCH="arm64", TARGET_VARIANTS="",
               RUSTUP_TOOLCHAIN="nightly-2026-08-12", CI_DEV_SOURCE_SHA=SOURCE)
    versions = {"bun": command(["bun", "--version"]), "node": command(["node", "--version"]),
                "rustc": command([rustc, "--version"])}
    if versions["bun"] != "1.4.0" or not versions["node"].startswith("v24."):
        raise Refusal("toolchain does not match the reviewed recipe")
    (upload / "toolchain.json").write_text(json.dumps(versions, indent=2) + "\n")
    smoke = root / "smoke"
    smoke.mkdir(exist_ok=False)
    smoke_env = {"HOME": str(smoke / "home"), "XDG_CONFIG_HOME": str(smoke / "xdg/config"),
                 "XDG_DATA_HOME": str(smoke / "xdg/data"), "XDG_CACHE_HOME": str(smoke / "xdg/cache")}
    for directory in smoke_env.values():
        Path(directory).mkdir(parents=True, exist_ok=True)
    commands = [
        ("dependencies", ["bun", "install", "--frozen-lockfile", "--ignore-scripts", "--network-concurrency", "2"], 180, env),
        ("native", ["bun", "run", "ci:build:native"], 1200, env),
        ("binary", ["bun", "--cwd=packages/coding-agent", "run", "build"], 600, env),
        ("loader-source", ["bun", "test", "./packages/natives/test/diagnostic-loader.test.ts", "--test-name-pattern", "verifies a local source addon"], 90, env),
        ("loader-compiled", ["bun", "test", "./packages/natives/test/diagnostic-loader.test.ts", "--test-name-pattern", "uses the verified local build digest carried by a compiled binary"], 90, env),
        ("goal-behavior", ["bun", "test", "packages/coding-agent/test/agent-session-todo-reminder.test.ts"], 90, env),
        ("compiled-smoke", ["packages/coding-agent/dist/gjc", "--smoke-test"], 120, {**env, **smoke_env}),
    ]
    for name, argv, seconds, stage_env in commands:
        run_stage(argv, source, upload / (name + ".log"), stage_env,
                  min(deadline, time.monotonic() + seconds), pre["initial_free_bytes"])
    receipt_env = {**env, "CI_DEV_DARWIN_BINARY": "packages/coding-agent/dist/gjc",
                   "CI_DEV_DARWIN_NATIVE_ADDON": "packages/natives/native/pi_natives.darwin-arm64.node",
                   **{"CI_DEV_DARWIN_SMOKE_" + key: value for key, value in smoke_env.items()}}
    for name, argv in [("receipt-write", ["bun", "scripts/ci-validate-darwin-receipt.ts", "--write"]),
                       ("receipt-validate", ["bun", "scripts/ci-validate-darwin-receipt.ts"])]:
        run_stage(argv, source, upload / (name + ".log"), receipt_env,
                  min(deadline, time.monotonic() + 60), pre["initial_free_bytes"])
    files = ["packages/coding-agent/dist/gjc", "packages/natives/native/pi_natives.darwin-arm64.node",
             "packages/natives/native/pi_natives.darwin-arm64.node.provenance.json",
             "packages/natives/native/diagnostic-artifact.json", ".ci-dev-darwin-arm64-receipt.json"]
    total = sum((source / name).stat().st_size for name in files)
    total += sum(p.stat().st_size for p in upload.iterdir() if p.is_file()) + 1024 ** 2
    if total > BUNDLE_LIMIT or time.monotonic() >= deadline:
        raise Refusal("artifact size or whole-job time ceiling reached")
    manifest = {"source_sha": SOURCE, "control_sha": pre["control_sha"], "files": {},
                "source_files": source_hashes,
                "scope": "target qualification only; not installed effect or real scheduler firing"}
    if any(digest(source / name) != expected for name, expected in source_hashes.items()):
        raise Refusal("qualification modified critical runtime source")
    for name in files:
        original = source / name
        if original.is_symlink() or not original.is_file():
            raise Refusal("unexpected artifact file type")
        target = upload / "payload" / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(original, target)
        if digest(original) != digest(target):
            raise Refusal("artifact copy digest mismatch")
        manifest["files"][name] = {"sha256": digest(target), "bytes": target.stat().st_size}
        enforce_capacity(source, pre["initial_free_bytes"])
    archive = upload / "candidate.tar"
    with tarfile.open(archive, "w") as bundle:
        for name in files:
            bundle.add(upload / "payload" / name, arcname=name, recursive=False)
            enforce_capacity(source, pre["initial_free_bytes"])
            if time.monotonic() >= deadline:
                raise Refusal("archive exhausted the work budget")
    shutil.rmtree(upload / "payload")
    if sum(p.stat().st_size for p in upload.iterdir() if p.is_file()) + 1024 ** 2 > BUNDLE_LIMIT:
        raise Refusal("final artifact size ceiling reached")
    manifest["archive_sha256"] = digest(archive)
    (upload / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")


def seal(root):
    upload = root / "upload"
    manifest = upload / "manifest.json"
    success = os.environ.get("QUALIFICATION_JOB_STATUS") == "success" and manifest.is_file()
    if not success:
        (upload / "candidate.tar").unlink(missing_ok=True)
        manifest.unlink(missing_ok=True)
    if sum(p.stat().st_size for p in upload.rglob("*") if p.is_file()) + 4096 > BUNDLE_LIMIT:
        raise Refusal("refusing oversized artifact upload")
    (upload / "outcome.json").write_text(json.dumps({
        "qualified": success,
        "job_status_before_upload": os.environ.get("QUALIFICATION_JOB_STATUS"),
        "installed_effect": False,
        "real_scheduler_fire": False,
    }) + "\n")


def main():
    mode, source_arg = sys.argv[1:]
    root = Path(os.environ["QUALIFICATION_ROOT"]).resolve()
    source = Path(source_arg).resolve()
    upload = root / "upload"
    upload.mkdir(exist_ok=True)
    try:
        if mode == "preflight":
            preflight(source, root)
        elif mode == "qualify":
            qualify(source, root)
        elif mode == "seal":
            seal(root)
        else:
            raise Refusal("unsupported operation")
    except BaseException as error:
        # Never upload partial binaries as a qualification result.
        shutil.rmtree(upload / "payload", ignore_errors=True)
        (upload / "candidate.tar").unlink(missing_ok=True)
        (upload / "manifest.json").unlink(missing_ok=True)
        (upload / "failure.json").write_text(json.dumps({"phase": mode, "error": str(error)[:1024]}) + "\n")
        raise


if __name__ == "__main__":
    main()
