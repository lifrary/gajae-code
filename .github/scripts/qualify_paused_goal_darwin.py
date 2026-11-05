#!/usr/bin/env python3
"""Control-plane wrapper only; never imports target packages or reimplements receipts."""
import ctypes
import errno
from functools import lru_cache
import hashlib
import json
import os
from pathlib import Path
import platform
import selectors
import shutil
import signal
import stat
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
CRITICAL_SOURCES = [
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
GENERATED_DOCS = "packages/coding-agent/src/internal-urls/docs-index.generated.ts"
DOCS_TREE = "23176c8b8406d03d3eb62ceb1c3e2ca8d86c804d"  # SOURCE:docs
NATIVE_FILES = [
    "packages/natives/native/pi_natives.darwin-arm64.node",
    "packages/natives/native/pi_natives.darwin-arm64.node.provenance.json",
    "packages/natives/native/diagnostic-artifact.json",
]
PHASES = [
    "dependencies", "native", "docs-index", "binary", "loader-source",
    "loader-compiled", "goal-behavior", "compiled-smoke",
    "receipt-write", "receipt-validate", "package",
]


class Refusal(RuntimeError):
    pass


def digest(file):
    value = hashlib.sha256()
    with Path(file).open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(block)
    return value.hexdigest()


def command(argv, cwd=None, timeout=10):
    return subprocess.check_output(argv, cwd=cwd, text=True, timeout=timeout).strip()


def free_bytes(directory):
    return shutil.disk_usage(directory).free


def table(timeout=10):
    rows = {}
    text = command(["ps", "-axo", "pid=,ppid=,pgid=,rss=,lstart=,comm="], timeout=timeout)
    for line in text.splitlines():
        parts = line.split(None, 9)
        if len(parts) != 10:
            raise Refusal("unreadable process identity")
        pid, parent, group, rss = map(int, parts[:4])
        rows[pid] = (parent, group, rss * 1024, " ".join(parts[4:9]), parts[9])
    return rows


class _BSDInfo(ctypes.Structure):
    # Public Darwin sys/proc_info.h: PROC_PIDTBSDINFO, MAXCOMLEN=16.
    _fields_ = [(name, ctypes.c_uint32) for name in (
        "flags", "status", "xstatus", "pid", "ppid", "uid", "gid",
        "ruid", "rgid", "svuid", "svgid", "reserved",
    )] + [("comm", ctypes.c_char * 16), ("name", ctypes.c_char * 32)] + [
        (name, ctypes.c_uint32) for name in ("nfiles", "pgid", "pjobc", "tdev", "tpgid")
    ] + [("nice", ctypes.c_int32), ("start_sec", ctypes.c_uint64),
         ("start_usec", ctypes.c_uint64)]


class _TaskInfo(ctypes.Structure):
    _fields_ = [(name, ctypes.c_uint64) for name in (
        "virtual", "resident", "total_user", "total_system", "threads_user", "threads_system",
    )] + [(name, ctypes.c_int32) for name in (
        "policy", "faults", "pageins", "cow_faults", "messages_sent", "messages_received",
        "syscalls_mach", "syscalls_unix", "csw", "threadnum", "numrunning", "priority",
    )]


class _TaskAllInfo(ctypes.Structure):
    _fields_ = [("bsd", _BSDInfo), ("task", _TaskInfo)]


@lru_cache(maxsize=1)
def process_api():
    if platform.system() != "Darwin":
        raise Refusal("Darwin kernel process identity required")
    if (ctypes.sizeof(_BSDInfo), ctypes.sizeof(_TaskInfo), ctypes.sizeof(_TaskAllInfo)) != (136, 96, 232):
        raise Refusal("unexpected Darwin process-info layout")
    api = ctypes.CDLL("/usr/lib/libproc.dylib", use_errno=True).proc_pidinfo
    api.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_uint64, ctypes.c_void_p, ctypes.c_int]
    api.restype = ctypes.c_int
    return api


def process_info(pid):
    """Kernel-bound (parent, group, RSS, microsecond birth, status), never argv/env."""
    def read(flavor, value):
        ctypes.set_errno(0)
        size = ctypes.sizeof(value)
        result = process_api()(pid, flavor, 0, ctypes.byref(value), size)
        if result == size:
            return value
        if result == 0 and ctypes.get_errno() == errno.ESRCH:
            return None
        raise Refusal(f"unreadable kernel process identity for pid {pid}")

    info = read(2, _TaskAllInfo())  # PROC_PIDTASKALLINFO binds RSS to this process.
    if info is not None:
        bsd, rss = info.bsd, info.task.resident
    else:
        bsd = read(3, _BSDInfo())
        if bsd is None:
            return None
        if bsd.status != 5:  # SZOMB: non-executing, awaiting its parent's wait.
            raise Refusal(f"unreadable resident memory for pid {pid}")
        rss = 0
    if bsd.pid != pid or not bsd.start_sec or bsd.start_usec >= 1000000:
        raise Refusal(f"invalid kernel process identity for pid {pid}")
    return (bsd.ppid, bsd.pgid, rss, (bsd.start_sec, bsd.start_usec), bsd.status)


class OwnedProcesses:
    """Sampled ancestry admission; a PGID or name never grants ownership.

    A child born and reparented between samples can escape discovery entirely.
    This is cooperative accounting, not kernel-total containment or atomic signalling.
    """
    def __init__(self, pid):
        root = process_info(pid)
        if root is None or root[0] != os.getpid() or root[1] != pid:
            raise Refusal("cannot bind newly spawned root identity")
        self.root = pid
        self.owned = {pid: root}
        self.groups = {root[1]}
        self.offending = None
        self.uncertain = False
        self.settled = 0

    def refuse(self, reason, pid, info, expected=None):
        self.uncertain = True
        self.offending = {"pid": pid, "parent": info[0], "group": info[1],
                          "birth": info[3], "status": info[4], "reason": reason,
                          "expected_birth": expected}
        raise Refusal(reason)

    def snapshot(self):
        # At most 64 admitted live processes plus the process that exceeds the cap.
        return {"root_pid": self.root, "identity": "pid + kernel start_sec/start_usec",
                "sampled_only": True, "settled_count": self.settled,
                "settlement_uncertain": self.uncertain,
                "observed_groups": sorted(self.groups)[:PROCESS_LIMIT + 1],
                "owned": [{"pid": pid, "parent": row[0], "group": row[1], "rss": row[2],
                           "birth": row[3], "status": row[4]}
                          for pid, row in list(self.owned.items())[:PROCESS_LIMIT + 1]],
                "offending": self.offending}

    def sample(self, deadline):
        try:
            return self._sample(deadline)
        except Exception:
            self.uncertain = True
            raise

    def _sample(self, deadline):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise Refusal("stage or whole-job deadline reached")
        try:
            rows = table(timeout=min(10, remaining))
        except subprocess.TimeoutExpired as error:
            raise Refusal("process sampling deadline reached") from error
        for pid, before in list(self.owned.items()):
            current = process_info(pid)
            if current is None:
                del self.owned[pid]
                self.settled += 1
            elif current[3] != before[3]:
                self.refuse("owned PID identity changed", pid, current, before[3])
            else:
                # Once ancestry is proved, the SAME process stays owned after
                # setsid, reparenting or root exit. Its new parent is not owned.
                self.owned[pid] = current
        while True:
            added = False
            for pid, row in rows.items():
                if pid in self.owned or row[0] not in self.owned:
                    continue
                if time.monotonic() >= deadline:
                    raise Refusal("stage or whole-job deadline reached")
                parent = row[0]
                bound = self.owned[parent]
                before = process_info(parent)
                child = process_info(pid)
                after = process_info(parent)
                if child is None or child[4] == 5:
                    continue
                if (before is None or after is None or before[4] == 5 or after[4] == 5 or
                        before[3] != bound[3] or after[3] != bound[3] or child[0] != parent):
                    self.refuse("unbound descendant identity", pid, child)
                if len(self.owned) >= PROCESS_LIMIT + 1:
                    self.refuse("sampled process-tree memory or process-count ceiling reached", pid, child)
                self.owned[pid] = child
                added = True
                if len(self.owned) > PROCESS_LIMIT:
                    self.refuse("sampled process-tree memory or process-count ceiling reached", pid, child)
            if not added:
                break
        self.groups.update(row[1] for row in self.owned.values())
        if len(self.groups) > PROCESS_LIMIT:
            self.uncertain = True
            raise Refusal("observed process-group inventory ceiling reached")
        for pid, row in rows.items():
            if pid in self.owned or row[1] not in self.groups:
                continue
            current = process_info(pid)
            if current is not None and current[4] != 5 and current[1] in self.groups:
                self.refuse("unbound member of an observed process group", pid, current)
        live = {pid: row for pid, row in self.owned.items() if row[4] != 5}
        executables = {rows[pid][4] for pid in live if pid in rows}
        return live, executables


def stop_owned(process, ownership):
    # No group signal: a group can contain a process we never bound. A fresh
    # birth check narrows (but cannot atomically eliminate) the check/signal race.
    if ownership is None:
        if process.poll() is None:
            process.kill()  # Our unreaped direct child only; never an inferred PID.
        raise Refusal("ownership unavailable; descendant settlement unknown")
    deadline = time.monotonic() + 5
    errors = []
    while time.monotonic() < deadline:
        try:
            live, _ = ownership.sample(deadline)
        except Exception as error:
            errors.append(str(error)[:256])
            live = ownership.owned
        if not live:
            if errors or ownership.uncertain:
                raise Refusal("owned cleanup not settled: " +
                              "; ".join(errors[:4] or ["sampled ownership became uncertain"]))
            return
        for pid, bound in reversed(list(ownership.owned.items())):
            try:
                current = process_info(pid)
                if current is None or current[4] == 5:
                    continue
                if current[3] != bound[3]:
                    raise Refusal(f"cleanup PID identity changed: {pid}")
                os.kill(pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            except Exception as error:
                errors.append(str(error)[:256])
        process.poll()
        if errors:
            raise Refusal("owned cleanup not settled: " + "; ".join(errors[:4]))
        time.sleep(0.02)
    raise Refusal("owned cleanup settlement deadline reached")


def enforce_capacity(root, initial_free):
    remaining = free_bytes(root)
    if remaining < FREE_FLOOR or initial_free - remaining > DISK_GROWTH:
        raise Refusal("disk safety floor or growth budget reached")
    return remaining


def evidence_budget(root, deadline, initial_free):
    if time.monotonic() >= deadline:
        raise Refusal("evidence collection reached existing phase/work deadline")
    enforce_capacity(root, initial_free)


def upload_size(upload):
    total = 0
    entries = 0
    pending = [upload]
    while pending:
        with os.scandir(pending.pop()) as children:
            for child in children:
                entries += 1
                if entries > 128 or child.is_symlink():
                    raise Refusal("unexpected evidence inventory")
                if child.is_dir(follow_symlinks=False):
                    pending.append(Path(child.path))
                elif child.is_file(follow_symlinks=False):
                    total += child.stat(follow_symlinks=False).st_size
                else:
                    raise Refusal("unexpected evidence file type")
    return total


def file_evidence(file, base, deadline, initial_free, maximum=LOG_LIMIT, target=None):
    """Bounded reads/copies of fixed paths; never loads addon bytes into memory."""
    evidence_budget(base, deadline, initial_free)
    relative = file.relative_to(base)
    if any((base / Path(*relative.parts[:i])).is_symlink()
           for i in range(1, len(relative.parts) + 1)):
        raise Refusal("symlink in evidence path")
    value = hashlib.sha256()
    with os.fdopen(os.open(file, os.O_RDONLY | os.O_NOFOLLOW), "rb") as stream:
        before = os.fstat(stream.fileno())
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_size > maximum:
            raise Refusal("evidence file identity or size refused")
        output = target.open("xb") if target is not None else None
        try:
            copied = 0
            while True:
                evidence_budget(base, deadline, initial_free)
                block = stream.read(min(1024 ** 2, maximum - copied + 1))
                if not block:
                    break
                copied += len(block)
                if copied > maximum:
                    raise Refusal("evidence grew beyond retained-byte budget")
                value.update(block)
                if output is not None:
                    output.write(block)
            after = os.fstat(stream.fileno())
            identity = lambda s: (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_nlink)
            if identity(before) != identity(after) or identity(after) != identity(file.lstat()):
                raise Refusal("evidence changed while reading")
            evidence_budget(base, deadline, initial_free)
        finally:
            if output is not None:
                output.close()
    return {"sha256": value.hexdigest(), "bytes": copied}


def retain_native_failure(source, root, error):
    """Best-effort phase evidence only, never a candidate or success receipt."""
    upload = root / "upload"
    pre = json.loads((upload / "preflight.json").read_text())
    state_path = upload / "phase-state.json"
    state = json.loads(state_path.read_text()) if state_path.exists() else {
        "current": "setup", "phases": {name: "unexecuted" for name in PHASES},
        "deadline": pre["started"] + WORK_SECONDS,
    }
    state["phases"][state["current"]] = "failed"
    deadline = min(state["deadline"], pre["started"] + WORK_SECONDS)
    report = {
        "qualified": False, "scope": "NOT_QUALIFIED native-phase evidence only",
        "source_sha": SOURCE, "control_sha": pre["control_sha"],
        "primary_error": str(error)[:1024], "phases": state["phases"],
        "collection_errors": [], "files": {}, "source_files": {},
        "installed_effect": False, "real_scheduler_fire": False, "composition": False,
    }
    try:
        provenance = json.loads((upload / "source-provenance.json").read_text())
        report["source_files"] = provenance["files"]
    except (OSError, ValueError, KeyError) as secondary:
        report["collection_errors"].append("source provenance: " + str(secondary)[:512])
    for name in CRITICAL_SOURCES:
        entry = report["source_files"].setdefault(name, {"error": "baseline provenance missing"})
        try:
            current = file_evidence(source / name, source, deadline, pre["initial_free_bytes"])
            entry["at_failure"] = current
            entry["unchanged"] = current.get("sha256") == entry.get("sha256")
            if not entry["unchanged"]:
                report["collection_errors"].append("source provenance changed or missing: " + name)
        except Exception as secondary:
            entry["collection_error"] = str(secondary)[:512]
    native_complete = (state["phases"].get("native") == "passed"
                       and not any(item.startswith("owned ")
                                   for item in getattr(error, "secondary_errors", [])))
    for name in NATIVE_FILES:
        target = upload / "failed-native" / Path(name).name
        try:
            if not native_complete:
                raise Refusal("native phase did not pass or owned cleanup is unsettled; no native bytes retained")
            evidence_budget(source, deadline, pre["initial_free_bytes"])
            remaining = BUNDLE_LIMIT - upload_size(upload) - 1024 ** 2
            if remaining <= 0:
                raise Refusal("no bounded artifact capacity remains")
            maximum = min(remaining, BUNDLE_LIMIT if name == NATIVE_FILES[0] else 65536)
            target.parent.mkdir(exist_ok=True)
            metadata = file_evidence(source / name, source, deadline, pre["initial_free_bytes"],
                                     maximum, target)
            retained = file_evidence(target, upload, deadline, pre["initial_free_bytes"],
                                     maximum)
            if retained != metadata:
                raise Refusal("retained native evidence digest mismatch")
            report["files"][name] = {**metadata, "retained_path": str(target.relative_to(upload))}
        except Exception as secondary:
            report["files"][name] = {"error": str(secondary)[:512]}
            try:
                target.unlink(missing_ok=True)
            except OSError as cleanup:
                report["collection_errors"].append("partial copy cleanup: " + str(cleanup)[:512])
    # Verify binding only within the original failed-stage budget. Missing or
    # unreadable sidecars never turn retained compilation into qualification.
    try:
        evidence_budget(source, deadline, pre["initial_free_bytes"])
        addon = report["files"][NATIVE_FILES[0]]
        sidecar_path = upload / "failed-native" / Path(NATIVE_FILES[1]).name
        if sidecar_path.stat().st_size > 65536:
            raise Refusal("native provenance metadata exceeds bounded read")
        sidecar = json.loads(sidecar_path.read_text())
        if (sidecar.get("schema") != "gjc.diagnostic-artifact-provenance"
                or sidecar.get("artifact") != Path(NATIVE_FILES[0]).name
                or sidecar.get("sha256") != addon.get("sha256")):
            raise Refusal("native producer sidecar binding mismatch")
        diagnostic_path = upload / "failed-native" / Path(NATIVE_FILES[2]).name
        if diagnostic_path.stat().st_size > 65536:
            raise Refusal("diagnostic manifest exceeds bounded read")
        diagnostic = json.loads(diagnostic_path.read_text())
        if (diagnostic.get("schema") != "gjc.diagnostic-artifact"
                or diagnostic.get("version") != sidecar.get("version")
                or diagnostic.get("artifacts", {}).get(Path(NATIVE_FILES[0]).name) != addon["sha256"]):
            raise Refusal("diagnostic manifest binding mismatch")
        report["producer_binding_verified"] = True
    except Exception as secondary:
        report["producer_binding_verified"] = False
        report["collection_errors"].append("producer binding: " + str(secondary)[:512])
    # Small terminal metadata, like failure.json, is allowed to report an
    # exhausted budget; no byte collection is attempted beyond that deadline.
    if upload_size(upload) + 1024 ** 2 > BUNDLE_LIMIT:
        raise Refusal("failure evidence exceeds artifact ceiling")
    (upload / "failed-native.json").write_text(json.dumps(report, indent=2) + "\n")


def run_stage(argv, cwd, log, env, deadline, initial_free, rss_limit=RSS_LIMIT, log_limit=LOG_LIMIT):
    process = None
    ownership = None
    peak_rss = 0
    peak_processes = 0
    executables = set()
    written = 0
    start = time.monotonic()
    failure = None
    primary = None
    secondary_errors = []
    selector = None
    stage = {
        "argv": list(argv), "process_started": False, "root_pid": None,
        "exit_code": None, "signal": None, "failure_cause": None,
        "cleanup": {"attempted": False, "observed_exit_code": None, "observed_signal": None},
    }

    def bind_primary(error):
        # Keep the pre-cleanup observation separate: a later SIGKILL from
        # cleanup is not the original command's exit or the refusal's cause.
        code = process.returncode if process is not None else None
        stage.update(exit_code=code, signal=-code if code is not None and code < 0 else None,
                     failure_cause=str(error)[:1024])
        if ownership is not None:
            stage["ownership"] = ownership.snapshot()
        error.primary_stage = stage
        error.secondary_errors = secondary_errors

    try:
        enforce_capacity(cwd, initial_free)
        if time.monotonic() >= deadline:
            raise Refusal("whole-job work budget exhausted before stage")
        selector = selectors.DefaultSelector()
        process = subprocess.Popen(argv, cwd=cwd, env=env, stdout=subprocess.PIPE,
                                   stderr=subprocess.STDOUT, start_new_session=True)
        stage["process_started"] = True
        stage["root_pid"] = process.pid
        ownership = OwnedProcesses(process.pid)
        selector.register(process.stdout, selectors.EVENT_READ)
        with Path(log).open("xb") as output:
            eof = False
            while True:
                code = process.poll()
                now = time.monotonic()
                if now >= deadline:
                    raise Refusal("stage or whole-job deadline reached")
                enforce_capacity(cwd, initial_free)
                observed, names = ownership.sample(deadline)
                executables.update(names)
                if len(executables) > 128:
                    raise Refusal("observed executable inventory ceiling reached")
                peak_rss = max(peak_rss, sum(row[2] for row in ownership.owned.values()))
                peak_processes = max(peak_processes, len(ownership.owned))
                if peak_rss > rss_limit or len(ownership.owned) > PROCESS_LIMIT:
                    raise Refusal("sampled process-tree memory or process-count ceiling reached")
                if code is not None and code != 0 and eof:
                    raise Refusal("command failed; no retry permitted")
                if code is not None and eof and not observed:
                    break
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
            observed, _ = ownership.sample(deadline)
            if observed:
                raise Refusal("descendants remained after stage exit")
    except BaseException as error:
        failure = str(error)
        primary = error
        bind_primary(error)  # attach before cleanup AND any receipt persistence
        if process is not None:
            stage["cleanup"]["attempted"] = True
            try:
                stop_owned(process, ownership)
            except Exception as cleanup:
                secondary_errors.append("owned cleanup: " + str(cleanup)[:512])
            try:
                process.wait(timeout=5)
            except Exception as cleanup:
                secondary_errors.append("owned wait: " + str(cleanup)[:512])
            code = process.returncode
            stage["cleanup"].update(observed_exit_code=code,
                                    observed_signal=-code if code is not None and code < 0 else None)
            if ownership is not None:
                stage["cleanup"]["ownership"] = ownership.snapshot()
        raise
    finally:
        for close in ([selector.close] if selector is not None else []) + (
                [process.stdout.close] if process is not None else []):
            try:
                close()
            except Exception as cleanup:
                secondary_errors.append("stream cleanup: " + str(cleanup)[:512])
        receipt = {
            "argv": argv, "exit_code": process.returncode if process is not None else None, "failure": failure,
            "seconds": round(time.monotonic() - start, 3), "peak_sampled_tree_rss": peak_rss,
            "peak_sampled_processes": peak_processes, "log_bytes": written,
            "observed_executables": sorted(executables),
            "cleanup_errors": secondary_errors,
            "primary_stage": stage if primary is not None else None,
            "ownership": ownership.snapshot() if ownership is not None else None,
        }
        try:
            Path(str(log) + ".json").write_text(json.dumps(receipt, indent=2) + "\n")
        except Exception as persistence:
            if primary is None:
                bind_primary(persistence)
                raise
            secondary_errors.append("stage receipt persistence: " + str(persistence)[:512])
        if primary is not None:
            primary.secondary_errors = secondary_errors
        elif secondary_errors:
            cleanup_failure = Refusal("stage stream cleanup failed: " + "; ".join(secondary_errors))
            bind_primary(cleanup_failure)
            raise cleanup_failure


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
    state = {"current": "setup", "deadline": deadline,
             "phases": {name: "unexecuted" for name in PHASES}}
    (upload / "phase-state.json").write_text(json.dumps(state) + "\n")
    provenance = {"source_sha": SOURCE, "control_sha": pre["control_sha"], "files": {}}
    for name in CRITICAL_SOURCES:
        try:
            provenance["files"][name] = file_evidence(
                source / name, source, deadline, pre["initial_free_bytes"])
        except Exception as error:
            provenance["files"][name] = {"error": str(error)[:512]}
    (upload / "source-provenance.json").write_text(json.dumps(provenance, indent=2) + "\n")
    if any("error" in entry for entry in provenance["files"].values()):
        raise Refusal("critical source provenance missing or unreadable")
    source_hashes = {name: entry["sha256"] for name, entry in provenance["files"].items()}
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
        ("docs-index", ["bun", "--cwd=packages/coding-agent", "run", "generate-docs-index"], 600, env),
        ("binary", ["bun", "--cwd=packages/coding-agent", "run", "build"], 600, env),
        ("loader-source", ["bun", "test", "./packages/natives/test/diagnostic-loader.test.ts", "--test-name-pattern", "verifies a local source addon"], 90, env),
        ("loader-compiled", ["bun", "test", "./packages/natives/test/diagnostic-loader.test.ts", "--test-name-pattern", "uses the verified local build digest carried by a compiled binary"], 90, env),
        ("goal-behavior", ["bun", "test", "packages/coding-agent/test/agent-session-todo-reminder.test.ts"], 90, env),
        ("compiled-smoke", ["packages/coding-agent/dist/gjc", "--smoke-test"], 120, {**env, **smoke_env}),
    ]
    receipt_env = {**env, "CI_DEV_DARWIN_BINARY": "packages/coding-agent/dist/gjc",
                   "CI_DEV_DARWIN_NATIVE_ADDON": "packages/natives/native/pi_natives.darwin-arm64.node",
                   **{"CI_DEV_DARWIN_SMOKE_" + key: value for key, value in smoke_env.items()}}
    commands += [
        ("receipt-write", ["bun", "scripts/ci-validate-darwin-receipt.ts", "--write"], 60, receipt_env),
        ("receipt-validate", ["bun", "scripts/ci-validate-darwin-receipt.ts"], 60, receipt_env),
    ]
    binary_deadline = None
    for name, argv, seconds, stage_env in commands:
        phase_deadline = min(deadline, time.monotonic() + seconds)
        if name == "docs-index":
            binary_deadline = phase_deadline
        elif name == "binary":
            phase_deadline = binary_deadline  # generator + compile share the original 600s
        state.update(current=name, deadline=phase_deadline)
        state["phases"][name] = "running"
        (upload / "phase-state.json").write_text(json.dumps(state) + "\n")
        if name == "docs-index":
            # The pinned generator walks upward. Never silently select a nearer
            # directory or fall back to documentation outside the runtime tree.
            for directory in ["packages/coding-agent/scripts/docs", "packages/coding-agent/docs", "packages/docs"]:
                if (source / directory).exists() or (source / directory).is_symlink():
                    raise Refusal("unexpected nearer documentation origin")
            if not (source / "docs").is_dir() or (source / "docs").is_symlink():
                raise Refusal("pinned runtime documentation origin unavailable")
        run_stage(argv, source, upload / (name + ".log"), stage_env,
                  phase_deadline, pre["initial_free_bytes"])
        if name == "docs-index":
            generated = file_evidence(source / GENERATED_DOCS, source, phase_deadline,
                                      pre["initial_free_bytes"], BUNDLE_LIMIT)
            (upload / "generated-docs.json").write_text(json.dumps({
                "source_sha": SOURCE, "command": argv,
                "generator": "packages/coding-agent/scripts/generate-docs-index.ts",
                "generator_sha256": source_hashes["packages/coding-agent/scripts/generate-docs-index.ts"],
                "docs_root": "docs", "docs_tree_at_pinned_source": DOCS_TREE,
                "output": GENERATED_DOCS, **generated,
                "shared_binary_deadline": binary_deadline,
            }, indent=2) + "\n")
        state["phases"][name] = "passed"
        (upload / "phase-state.json").write_text(json.dumps(state) + "\n")
    state.update(current="package", deadline=deadline)
    state["phases"]["package"] = "running"
    (upload / "phase-state.json").write_text(json.dumps(state) + "\n")
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
    if any(file_evidence(source / name, source, deadline, pre["initial_free_bytes"])["sha256"] != expected
           for name, expected in source_hashes.items()):
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
    manifest["generated_docs"] = json.loads((upload / "generated-docs.json").read_text())
    (upload / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    state["phases"]["package"] = "passed"
    (upload / "phase-state.json").write_text(json.dumps(state) + "\n")


def seal(root):
    upload = root / "upload"
    manifest = upload / "manifest.json"
    success = os.environ.get("QUALIFICATION_JOB_STATUS") == "success" and manifest.is_file()
    if not success:
        (upload / "candidate.tar").unlink(missing_ok=True)
        manifest.unlink(missing_ok=True)
    if upload_size(upload) + 4096 > BUNDLE_LIMIT:
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
        secondary = list(getattr(error, "secondary_errors", []))
        for path in [upload / "payload", upload / "candidate.tar", upload / "manifest.json"]:
            try:
                if path.is_dir():
                    shutil.rmtree(path)
                else:
                    path.unlink(missing_ok=True)
            except Exception as cleanup:
                secondary.append("candidate cleanup: " + str(cleanup)[:512])
        if mode == "qualify":
            try:
                retain_native_failure(source, root, error)
            except Exception as collection:
                secondary.append("failure evidence collection: " + str(collection)[:512])
        failure = {"phase": mode, "error": str(error)[:1024],
                   "primary_stage": getattr(error, "primary_stage", None),
                   "secondary_errors": secondary}
        try:
            (upload / "failure.json").write_text(json.dumps(failure, indent=2) + "\n")
        except Exception as persistence:
            failure["secondary_errors"].append("failure persistence: " + str(persistence)[:512])
            print(json.dumps(failure), file=sys.stderr)
        raise


if __name__ == "__main__":
    main()
