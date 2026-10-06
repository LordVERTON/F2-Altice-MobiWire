"""Deterministic offline Notion -> Python -> Git worker. Never chooses a next gate."""
from __future__ import annotations

import argparse
import ast
import ctypes
from datetime import datetime, timezone
import hashlib
import json
import logging
from logging.handlers import RotatingFileHandler
import os
from pathlib import Path, PurePosixPath
import re
import signal
import socket
import subprocess
import threading
import time
import uuid

from notion_queue import (BRANCH, SAFETY, BridgeError, Rejected, NotionUnavailable,
                          NotionQueue, environment, identifier, prop, rich, safe_text)

ROOT = Path(r"C:\Users\verto\F2-Altice-MobiWire")
PYTHON = r"C:\Users\verto\mtkclient\.venv\Scripts\python.exe"
AUTO = "research/f2/automation"
REPORTS = "research/f2/work/reports"
STOP = threading.Event()


def utc():
    return datetime.now(timezone.utc).isoformat()


def dump(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_suffix(".tmp")
    temp.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")
    temp.replace(path)


def parse_json(raw):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise Rejected("Duplicate JSON key")
            result[key] = value
        return result
    try:
        value = json.loads(raw.decode("utf-8-sig"), object_pairs_hook=unique,
                           parse_constant=lambda _: (_ for _ in ()).throw(Rejected("Invalid JSON number")))
    except (ValueError, UnicodeError):
        raise Rejected("Invalid UTF-8 JSON manifest") from None
    if not isinstance(value, dict):
        raise Rejected("Manifest must be a JSON object")
    return value


def scoped_path(repo, relative, prefix):
    if not isinstance(relative, str) or not relative or "\\" in relative or ":" in relative or "\x00" in relative:
        raise Rejected("Invalid relative path")
    parts = relative.split("/")
    if any(x in ("", ".", "..") for x in parts) or any(re.search(r'[<>"|?*]', x) or x.endswith((" ", ".")) for x in parts):
        raise Rejected("Path traversal or invalid Windows path")
    path = PurePosixPath(relative)
    if path.is_absolute() or not path.is_relative_to(PurePosixPath(prefix)) or str(path) == prefix:
        raise Rejected("Path is outside its allowed directory")
    result = repo.joinpath(*parts)
    for item in (repo, *result.parents, result):
        if item.exists() and (item.is_symlink() or bool(getattr(item.stat(), "st_file_attributes", 0) & 0x400)):
            raise Rejected("Symlink/junction forbidden")
    if not result.resolve().is_relative_to((repo / prefix).resolve()):
        raise Rejected("Resolved path escapes allowed directory")
    return result


def static_check(script):
    try:
        tree = ast.parse(script, filename="script.py")
    except (SyntaxError, ValueError, UnicodeError):
        raise Rejected("Script is not valid Python") from None
    denied = {"serial", "pyserial", "usb", "pyusb", "winusb", "socket", "requests",
              "urllib", "http", "httpx", "aiohttp", "subprocess", "ctypes", "winreg",
              "win32file", "win32api", "win32com", "importlib", "runpy", "multiprocessing"}
    # Deliberately conservative: reject networking/subprocess outright rather than
    # pretending to prove dynamic targets are safe. Comments/docstrings are not commands.
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            modules = [alias.name.split(".")[0] for alias in node.names]
        elif isinstance(node, ast.ImportFrom):
            modules = [(node.module or "").split(".")[0]]
        else:
            modules = []
        if set(modules) & denied:
            raise Rejected("Static policy: hardware/network/process import forbidden")
        if isinstance(node, (ast.Name, ast.Attribute)):
            name = node.id if isinstance(node, ast.Name) else node.attr
            if name in {"__import__", "eval", "exec", "compile", "system", "popen", "startfile", "fork", "spawnv", "spawnve"}:
                raise Rejected("Static policy: dynamic execution forbidden")
            if re.search(r"(?i)(?:^|_)(?:COM\d*|BROM|DA|D3|D5|D6|erase|repack|writeflash|flash_write)(?:_|$)", name):
                raise Rejected("Static policy: hardware operation identifier forbidden")
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            if re.search(r"(?i)(?:\\\\\.\\|\bCOM\d+\b|\bBROM\b|\b(?:DA|D3|D5|D6)\b|flash[ _-]*write|writeflash|\berase\b|\brepack\b)", node.value):
                raise Rejected("Static policy: hardware command/device literal forbidden")
    return tree


def validate(page, manifest_bytes, script_bytes, repo):
    job = parse_json(manifest_bytes)
    job_id = job.get("job_id")
    if not isinstance(job_id, str) or not re.fullmatch(r"[A-Za-z0-9._-]+", job_id) or job_id in (".", ".."):
        raise Rejected("Invalid job_id")
    if type(job.get("schema_version")) is not int or job["schema_version"] != 1 or job.get("enabled") is not True:
        raise Rejected("schema_version must be 1 and enabled must be true")
    if job.get("safety") != SAFETY or any(type(job.get("safety", {}).get(k)) is not bool for k in SAFETY if k != "mode"):
        raise Rejected("Manifest safety must be offline_analysis with phone_access/flash_write/erase/repack=false")
    if prop(page, "Branch") != BRANCH or job.get("branch", BRANCH) != BRANCH:
        raise Rejected("Branch must be automate-research")
    if prop(page, "Safety Mode", "select") != "offline_analysis":
        raise Rejected("Notion Safety Mode must be offline_analysis")
    for label in ("Phone Access", "Flash Write", "Erase", "Repack"):
        if prop(page, label, "checkbox") is not False:
            raise Rejected(f"Notion {label} must be false")
    digest = hashlib.sha256(script_bytes).hexdigest()
    if not isinstance(job.get("script_sha256"), str) or not re.fullmatch(r"[a-fA-F0-9]{64}", job["script_sha256"]) or job["script_sha256"].lower() != digest:
        raise Rejected("Script SHA256 mismatch")
    if prop(page, "Job ID") != job_id or prop(page, "Schema Version", "number") != 1 or prop(page, "Script SHA256").lower() != digest or prop(page, "Report Path") != job.get("report"):
        raise Rejected("Notion properties do not match manifest")
    if not isinstance(job.get("args"), list) or any(not isinstance(x, str) or "\x00" in x for x in job["args"]):
        raise Rejected("args must be a JSON array of strings without NUL")
    script_rel = f"{AUTO}/jobs/{job_id}.py"
    if job.get("script", script_rel) != script_rel:
        raise Rejected("script path must equal the reconstructed .py path")
    paths = {"script": script_rel, "manifest": f"{AUTO}/manifests/{job_id}.job.json",
             "result": f"{AUTO}/results/{job_id}.result.json", "report": job.get("report")}
    for kind, rel in paths.items():
        scoped_path(repo, rel, REPORTS if kind == "report" else f"{AUTO}/{dict(script='jobs',manifest='manifests',result='results')[kind]}")
    static_check(script_bytes)
    return job, paths, digest


def child_environment(secret):
    return {**{k: v for k, v in os.environ.items()
               if "NOTION" not in k.upper() and (not secret or secret not in v)},
            "F2_AUTOMATION_OFFLINE": "1", "PYTHONIOENCODING": "utf-8"}


class Git:
    def __init__(self, repo, secret="", remote="github"):
        self.repo, self.secret, self.remote = repo, secret, remote

    def run(self, *args, check=True):
        result = subprocess.run(["git.exe", "-C", str(self.repo), *args], capture_output=True,
            text=True, encoding="utf-8", errors="replace", env=child_environment(self.secret), timeout=120)
        if check and result.returncode:
            raise BridgeError(f"git {' '.join(args)} failed (exit {result.returncode}): " + safe_text(result.stderr + result.stdout, self.secret).strip())
        return result.stdout.strip() if check else result

    def clean(self):
        return not self.run("status", "--porcelain", "--untracked-files=all")

    def branch(self):
        if self.run("branch", "--show-current") != BRANCH:
            raise BridgeError("wrong branch: expected automate-research")
        for name in ("MERGE_HEAD", "CHERRY_PICK_HEAD", "REVERT_HEAD", "rebase-merge", "rebase-apply"):
            path = Path(self.run("rev-parse", "--git-path", name))
            if not path.is_absolute():
                path = self.repo / path
            if path.exists():
                raise BridgeError("unfinished Git operation: " + name)

    def fetch(self):
        self.run("fetch", self.remote, BRANCH)

    def synchronize(self):
        self.branch()
        self.fetch()
        if not self.clean():
            raise BridgeError("working tree not clean")
        ahead, behind = map(int, self.run("rev-list", "--left-right", "--count", f"HEAD...{self.remote}/{BRANCH}").split())
        if ahead:
            raise BridgeError("unknown local commits ahead; manual synchronization required")
        if behind:
            self.run("-c", "rebase.autoStash=false", "pull", "--ff-only", self.remote, BRANCH)

    def commit_result(self, paths, base, job_id, code):
        self.branch()
        if self.run("rev-parse", "HEAD") != base or self.run("diff", "--cached", "--name-only"):
            raise BridgeError("HEAD or index changed during execution; results preserved")
        changed = set(self.run("diff", "--name-only").splitlines()) | set(self.run("ls-files", "--others", "--exclude-standard").splitlines())
        if changed - set(paths.values()):
            raise BridgeError("unexpected working tree changes; results preserved")
        self.run("add", "--", paths["script"], paths["manifest"], paths["result"])
        self.run("add", "-f", "--", paths["report"])
        if set(self.run("diff", "--cached", "--name-only").splitlines()) != set(paths.values()):
            raise BridgeError("index scope mismatch; no commit")
        self.run("commit", "-m", f"automation: {job_id} (exit {code})")
        return self.run("rev-parse", "HEAD")

    def push_result(self, commit):
        self.branch()
        if not self.clean() or self.run("rev-parse", "HEAD") != commit:
            raise BridgeError("push blocked: working tree/HEAD changed")
        result = self.run("push", self.remote, BRANCH, check=False)
        if result.returncode:
            self.fetch()
            if not self.clean() or self.run("rev-list", f"{self.remote}/{BRANCH}..HEAD").splitlines() != [commit]:
                raise BridgeError("unsafe rebase; local result preserved: " + safe_text(result.stderr, self.secret))
            self.run("-c", "rebase.autoStash=false", "rebase", f"{self.remote}/{BRANCH}")
            commit = self.run("rev-parse", "HEAD")
            self.run("push", self.remote, BRANCH)
        self.confirm_pushed(commit)
        return commit

    def confirm_pushed(self, commit):
        self.fetch()
        if self.run("merge-base", "--is-ancestor", commit, f"{self.remote}/{BRANCH}", check=False).returncode:
            raise BridgeError("result commit is not confirmed on the remote")


class Mutex:
    """Same mutex as f2_runner.ps1, held for the entire worker lifetime."""
    def __enter__(self):
        if os.name != "nt":
            raise BridgeError("Production worker requires Windows")
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel.CreateMutexW.argtypes = [ctypes.c_void_p, ctypes.c_bool, ctypes.c_wchar_p]
        kernel.CreateMutexW.restype = ctypes.c_void_p
        kernel.WaitForSingleObject.argtypes = [ctypes.c_void_p, ctypes.c_uint32]
        kernel.ReleaseMutex.argtypes = [ctypes.c_void_p]
        kernel.CloseHandle.argtypes = [ctypes.c_void_p]
        self.kernel = kernel
        self.handle = kernel.CreateMutexW(None, False, r"Local\F2AlticeAutomationRunner")
        if not self.handle:
            raise BridgeError("Cannot create runner mutex")
        if kernel.WaitForSingleObject(self.handle, 0) not in (0, 0x80):
            kernel.CloseHandle(self.handle)
            raise BridgeError("Another Notion worker or ZIP/repo runner is active")
        return self

    def __exit__(self, *_):
        self.kernel.ReleaseMutex(self.handle)
        self.kernel.CloseHandle(self.handle)


class Worker:
    def __init__(self, config, queue, logger=None):
        self.config, self.queue = config, queue
        self.repo = Path(config["repo_root"])
        self.secret = queue._token
        self.git = Git(self.repo, self.secret)
        self.host = config["worker_host"]
        self.state_path = self.repo / f"{AUTO}/bridge/state/pending.json"
        self.logger = logger or logging.getLogger("f2.notion")

    def log(self, event, detail=""):
        self.logger.info("%s %s", event, safe_text(detail, self.secret))

    def save(self, state, **updates):
        state.update(updates)
        dump(self.state_path, state)

    def ownership(self, state, status):
        page = self.queue.page(state["page_id"])
        if prop(page, "Status", "select") != status or prop(page, "Worker Host") != self.host or prop(page, "Claim Token") != state["claim"]:
            raise BridgeError("Claim ownership lost; no execution or status overwrite")
        return page

    def terminal(self, state, status, error="", commit=None, code=None):
        self.ownership(state, state["notion_status"])
        properties = {"Status": {"select": {"name": status}}, "Finished At": {"date": {"start": utc()}},
                      "Error": rich(safe_text(error, self.secret))}
        if commit:
            properties["Result Commit"] = rich(commit)
        if code is not None:
            properties["Exit Code"] = {"number": code}
        self.queue.update(state["page_id"], properties)
        page = self.queue.page(state["page_id"])
        if prop(page, "Status", "select") != status or (commit and prop(page, "Result Commit") != commit):
            raise BridgeError("Notion terminal status could not be confirmed")
        self.log("status", status)

    def recover(self):
        if not self.state_path.exists():
            return
        state = json.loads(self.state_path.read_text(encoding="utf-8"))
        # A failed/ambiguous execution is never replayed automatically.
        if state.get("phase") != "pushed":
            raise BridgeError("Pending/incomplete job preserved; inspect bridge/state/pending.json before manual recovery")
        self.git.confirm_pushed(state["commit"])
        page = self.queue.page(state["page_id"])
        status = "COMPLETED" if state["exit_code"] == 0 else "FAILED"
        if prop(page, "Status", "select") == status and prop(page, "Result Commit") == state["commit"]:
            self.state_path.unlink()
            return
        self.terminal(state, status, "" if status == "COMPLETED" else f"Python exit {state['exit_code']}", state["commit"], state["exit_code"])
        self.state_path.unlink()

    def execute(self, state, job, paths, digest, manifest_bytes, script_bytes):
        base = self.git.run("rev-parse", "HEAD")
        for rel in paths.values():
            if (self.repo / rel).exists():
                raise Rejected("Existing job artifacts preserved; job is not executed again")
        for rel in paths.values():
            (self.repo / rel).parent.mkdir(parents=True, exist_ok=True)
        # Exclusive creation prevents overwriting historical evidence.
        for key, data in (("script", script_bytes), ("manifest", manifest_bytes)):
            with (self.repo / paths[key]).open("xb") as stream:
                stream.write(data)
        started = utc()
        self.save(state, phase="running", paths=paths, script_sha256=digest)
        self.log("execution", job["job_id"])
        header = ["=" * 104, "F2 AUTOMATION NOTION WORKER", "=" * 104,
                  f"JOB ID = {job['job_id']}", f"NOTION PAGE ID = {state['page_id']}",
                  f"SCRIPT SHA256 = {digest}", f"PYTHON = {self.config['python_exe']}", f"BRANCH = {BRANCH}",
                  "SAFETY MODE = offline_analysis", "PHONE ACCESS = false", "FLASH WRITE = false",
                  "ERASE = false", "REPACK = false", f"START UTC = {started}", "=" * 104]
        timed_out = threading.Event()
        with (self.repo / paths["report"]).open("x", encoding="utf-8", newline="\n") as report:
            report.write("\n".join(header) + "\n")
            process = subprocess.Popen([self.config["python_exe"], str(self.repo / paths["script"]), *job["args"]],
                cwd=self.repo, env=child_environment(self.secret), stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, encoding="utf-8", errors="replace",
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
            def timeout():
                timed_out.set()
                process.kill()
            timer = threading.Timer(self.config["job_timeout_seconds"], timeout)
            timer.daemon = True
            timer.start()
            try:
                for line in process.stdout:
                    report.write(safe_text(line, self.secret))
                code = process.wait()
                if timed_out.is_set():
                    code = 124
            finally:
                timer.cancel()
                process.stdout.close()
                if process.poll() is None:
                    process.kill()
                    process.wait()
            finished = utc()
            report.write(f"\n{'=' * 104}\nEXIT CODE = {code}\nFINISH UTC = {finished}\n{'=' * 104}\n")
        receipt = dict(schema_version=1, job_id=job["job_id"], status="completed" if code == 0 else "failed",
            exit_code=code, script=paths["script"], script_sha256=digest, manifest=paths["manifest"],
            report=paths["report"], notion_page_id=state["page_id"], started_utc=started,
            finished_utc=finished, safety=SAFETY, source_commit=base)
        with (self.repo / paths["result"]).open("x", encoding="utf-8") as output:
            output.write(json.dumps(receipt, indent=2) + "\n")
        self.log("exit", str(code))
        commit = self.git.commit_result(paths, base, job["job_id"], code)
        self.save(state, phase="committed", commit=commit, exit_code=code)
        self.log("commit", commit)
        commit = self.git.push_result(commit)
        self.save(state, phase="pushed", commit=commit)
        self.log("push", commit)
        self.terminal(state, "COMPLETED" if code == 0 else "FAILED", "" if code == 0 else f"Python exit {code}", commit, code)
        self.state_path.unlink()
        return receipt

    def tick(self, job_filter=None):
        self.recover()
        self.log("poll")
        self.git.branch()
        pages = self.queue.query(job_filter)
        if not pages:
            return None
        page = self.queue.page(pages[0]["id"])
        if prop(page, "Status", "select") != "QUEUED":
            return None
        state = dict(page_id=identifier(page["id"]), claim=uuid.uuid4().hex, phase="claiming", notion_status="CLAIMED")
        self.save(state)
        self.queue.update(state["page_id"], {"Status": {"select": {"name": "CLAIMED"}},
            "Worker Host": rich(self.host), "Claim Token": rich(state["claim"]),
            "Started At": {"date": {"start": utc()}}, "Error": rich("")})
        page = self.ownership(state, "CLAIMED")
        self.log("claim", state["page_id"])
        self.save(state, phase="claimed")
        try:
            self.git.synchronize()
            # Notion unavailable or mismatched ownership always prevents execution.
            page = self.ownership(state, "CLAIMED")
            files = self.queue.attachments(page)
            manifest_bytes = self.queue.download(files["job.json"], 128 * 1024)
            script_bytes = self.queue.download(files["script.py"], self.config["max_script_bytes"])
            job, paths, digest = validate(page, manifest_bytes, script_bytes, self.repo)
            if any((self.repo / rel).exists() for rel in paths.values()):
                raise Rejected("Existing job artifacts/receipt: no automatic re-execution")
            self.log("validation", job["job_id"] + " PASS")
            self.ownership(state, "CLAIMED")
            self.queue.update(state["page_id"], {"Status": {"select": {"name": "RUNNING"}}})
            self.save(state, notion_status="RUNNING")
            current = self.ownership(state, "RUNNING")
            validate(current, manifest_bytes, script_bytes, self.repo)
            if not self.git.clean():
                raise BridgeError("working tree not clean")
            return self.execute(state, job, paths, digest, manifest_bytes, script_bytes)
        except Rejected as exc:
            self.terminal(state, "REJECTED", str(exc))
            self.state_path.unlink()
            self.log("rejected", str(exc))
            return {"status": "rejected", "error": str(exc)}
        except (BridgeError, OSError, subprocess.SubprocessError) as exc:
            self.log("error", str(exc))
            if state.get("phase") != "pushed":
                try:
                    self.terminal(state, "FAILED", safe_text(exc, self.secret))
                except BridgeError:
                    self.log("status", "Notion update unavailable; pending state preserved")
            raise


def config_from(path):
    default = dict(repo_root=str(ROOT), python_exe=PYTHON, branch=BRANCH, remote="github", poll_seconds=15,
                   worker_host=socket.gethostname(), queue_id="", max_script_bytes=5242880, job_timeout_seconds=14400)
    if path.exists():
        data = json.loads(path.read_text(encoding="utf-8-sig"))
        if set(data) - set(default):
            raise BridgeError("Unknown config keys; tokens/secrets must be environment-only")
        default.update(data)
    if Path(default["repo_root"]).resolve() != ROOT.resolve() or default["python_exe"].lower() != PYTHON.lower() or default["branch"] != BRANCH or default["remote"] != "github":
        raise BridgeError("Production config must use the canonical repository/Python/branch/remote")
    if default["worker_host"].lower() != socket.gethostname().lower():
        raise BridgeError("This host is not the designated worker")
    for name, lower, upper in (("poll_seconds", 5, 3600), ("job_timeout_seconds", 1, 86400), ("max_script_bytes", 1, 20 * 1024 * 1024)):
        if type(default[name]) is not int or not lower <= default[name] <= upper:
            raise BridgeError("Invalid config value: " + name)
    default["queue_id"] = environment("F2_NOTION_QUEUE_ID") or default["queue_id"]
    return default


def verify_installation(worker):
    """Require live Notion and GitHub evidence before persistent polling is installed."""
    worker.git.synchronize()
    smoke = "notion_bridge_smoke_v1"
    path = worker.repo / f"{AUTO}/results/{smoke}.result.json"
    if not path.exists():
        raise BridgeError("Real Notion smoke receipt missing; scheduled installation refused")
    receipt = json.loads(path.read_text(encoding="utf-8-sig"))
    page = worker.queue.page(receipt["notion_page_id"])
    commit = prop(page, "Result Commit")
    if receipt.get("status") != "completed" or receipt.get("exit_code") != 0 or prop(page, "Status", "select") != "COMPLETED" or not re.fullmatch(r"[a-f0-9]{40}", commit):
        raise BridgeError("Real Notion smoke has not completed and published")
    worker.git.confirm_pushed(commit)
    report = (worker.repo / f"{REPORTS}/{smoke}.txt").read_text(encoding="utf-8-sig")
    if "NOTION BRIDGE SMOKE = PASS" not in report or "EXIT CODE = 0" not in report:
        raise BridgeError("Real Notion smoke report invalid")
    rejected = worker.queue.request("POST", f"data_sources/{worker.queue.queue_id}/query",
        {"filter": {"property": "Job ID", "rich_text": {"equals": "notion_bridge_rejection_v1"}}, "page_size": 2}).get("results", [])
    if len(rejected) != 1 or prop(rejected[0], "Status", "select") != "REJECTED":
        raise BridgeError("Real Notion rejection test not confirmed")
    if (worker.repo / f"{AUTO}/results/notion_bridge_rejection_v1.result.json").exists():
        raise BridgeError("Rejection test unexpectedly has an execution receipt")
    print("Live smoke + rejection + GitHub verification: PASS")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, default=Path(__file__).with_name("config.local.json"))
    parser.add_argument("--once", action="store_true")
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--verify-installation", action="store_true")
    parser.add_argument("--job-id", help="Explicit smoke/testing filter; never creates a job")
    args = parser.parse_args()
    secret = environment("F2_NOTION_TOKEN")
    try:
        config = config_from(args.config)
        queue = NotionQueue(secret, config["queue_id"])
        if not config["queue_id"]:
            raise BridgeError("F2_NOTION_QUEUE_ID or local queue_id is required")
        with Mutex():
            queue.check_schema(queue.resolve())
            worker = Worker(config, queue)
            worker.git.branch()
            if args.verify_installation:
                verify_installation(worker)
                return 0
            if args.check:
                if not worker.git.clean():
                    raise BridgeError("working tree not clean")
                print("Worker preflight: PASS")
                return 0
            log_dir = ROOT / f"{AUTO}/logs"
            log_dir.mkdir(parents=True, exist_ok=True)
            handler = RotatingFileHandler(log_dir / "notion_worker.log", maxBytes=2 * 1024 * 1024, backupCount=4, encoding="utf-8")
            handler.setFormatter(logging.Formatter("%(asctime)s %(message)s"))
            worker.logger.addHandler(handler)
            worker.logger.setLevel(logging.INFO)
            stop_file = Path(__file__).with_name("STOP")
            signal.signal(signal.SIGINT, lambda *_: STOP.set())
            signal.signal(signal.SIGTERM, lambda *_: STOP.set())
            while not STOP.is_set() and not stop_file.exists():
                try:
                    worker.tick(args.job_id)
                except NotionUnavailable:
                    if args.once or worker.state_path.exists():
                        raise
                    worker.log("poll", "Notion unavailable; no job executed")
                if args.once:
                    break
                for _ in range(config["poll_seconds"]):
                    if STOP.wait(1) or stop_file.exists():
                        break
            worker.log("stopped")
            return 0
    except (BridgeError, OSError, ValueError, subprocess.SubprocessError) as exc:
        message = safe_text(exc, secret)
        logging.getLogger("f2.notion").error(message)
        print(message)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
