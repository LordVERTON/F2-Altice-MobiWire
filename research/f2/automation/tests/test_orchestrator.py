"""Offline only: fake Notion/Git/Codex, real journal, lock and worker validators."""
from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "bridge"))
import research_orchestrator as r
from notion_queue import prop, rich, SAFETY
from notion_worker import validate, static_check, Rejected

SOURCE = "11111111-1111-4111-8111-111111111111"
NEXT = "22222222-2222-4222-8222-222222222222"
COMMIT = "a" * 40
SECRET = "ntn_" + "OfflineTestSecretNotARealToken0000"


def output():
    return {"review": {"schema_version": 1, "reviewed_job_id": "current", "result": "continue",
        "classification": {k: [] for k in r.CLASSES}, "next_job_id": "next", "reason": "One discriminating audit"},
        "next_script": "from pathlib import Path\nprint('offline analysis')\n",
        "next_job": {"schema_version": 1, "job_id": "next", "enabled": True, "branch": r.BRANCH,
            "safety": dict(SAFETY), "report": r.REPORTS + "/next.txt", "script_sha256": None, "args": []},
        "notion_update": "FACT: current result verified. UNKNOWN: one remaining distinction."}


def page(status="COMPLETED", review="PENDING"):
    manifest = output()["next_job"] | {"job_id": "current", "script_sha256": "b" * 64, "report": r.REPORTS + "/current.txt"}
    p = {"id": SOURCE, "properties": r.next_properties(manifest)}
    p["properties"].update({"Status": r.select(status), "Review Status": r.select(review), "Result Commit": rich(COMMIT),
        "Exit Code": {"number": 0}, "Next Job ID": rich(""), "Review Error": rich("")})
    return p


class Crash(BaseException):
    pass


class Queue:
    def __init__(self):
        self.pages = {SOURCE: page()}
        self.claims = self.creates = 0
        self.events = []
        self.crash = False
        self.missing_create = False

    def pending(self):
        return [deepcopy(p) for p in self.pages.values() if prop(p, "Status", "select") == "COMPLETED"
                and prop(p, "Review Status", "select") == "PENDING"][:1]

    def page(self, key):
        return deepcopy(self.pages[key])

    def by_job(self, job):
        return [deepcopy(p) for p in self.pages.values() if prop(p, "Job ID") == job]

    def active(self):
        return [deepcopy(p) for p in self.pages.values() if prop(p, "Status", "select") in ("QUEUED", "CLAIMED", "RUNNING")]

    def review_update(self, key, properties):
        if properties.get("Review Status") == r.select("CLAIMED"):
            self.claims += 1
        if properties.get("Review Status") == r.select("PROCESSED"):
            self.events.append("processed")
        self.pages[key]["properties"].update(deepcopy(properties))

    def current_state(self):
        return "CURRENT STATE: only this gate remains."

    def publish_document(self, doc, text, state, save):
        self.events.append(doc)

    def create_next(self, manifest, script, parent):
        self.creates += 1
        self.events.append("created")
        if self.missing_create:
            raise Crash()
        p = {"id": NEXT, "properties": r.next_properties(manifest), "manifest": deepcopy(manifest)}
        p["properties"].update({"Status": r.select("QUEUED"), "Review Status": r.select("PENDING")})
        self.pages[NEXT] = p
        if self.crash:
            raise Crash()
        return deepcopy(p)

    def verify_next(self, p, manifest, parent):
        r.require(p["manifest"] == manifest and parent == SOURCE, "Successor mismatch")


class Git:
    dirty = False
    wrong_branch = False
    def branch(self):
        r.require(not self.wrong_branch, "Wrong branch")
    def clean(self):
        return not self.dirty
    def confirm_pushed(self, commit):
        r.require(commit == COMMIT, "Unpublished commit")
    def run(self, *args, check=True):
        if args[1].endswith(".result.json"):
            return json.dumps({"job_id": "current", "status": "completed", "exit_code": 0,
                "report": r.REPORTS + "/current.txt", "safety": SAFETY, "notion_page_id": SOURCE, "script_sha256": "b" * 64})
        return subprocess.CompletedProcess(args, 0, "CURRENT REPORT: offline fixture. Reference research/f2/data/example.bin\n", "")


class Tests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.repo = Path(self.tmp.name)
        self.q, self.git, self.calls = Queue(), Git(), 0
        self.payload = output()
        def reviewer(bundle, directory, secret):
            self.calls += 1
            self.bundle = bundle
            return deepcopy(self.payload)
        self.worker = r.Orchestrator(self.q, self.git, self.repo, self.repo / "state", reviewer, SECRET)

    def test_empty(self):
        self.q.pages.clear()
        self.assertEqual(self.worker.tick(), 0)
        self.assertEqual(self.calls, 0)

    def test_noneligible_never_calls_codex(self):
        for status, review in (("QUEUED", "PENDING"), ("RUNNING", "PENDING"), ("FAILED", "PENDING"),
                ("REJECTED", "PENDING"), ("COMPLETED", "CLAIMED"), ("COMPLETED", "PROCESSED")):
            self.q.pages[SOURCE] = page(status, review)
            self.assertEqual(self.worker.tick(), 0)
        self.assertEqual(self.calls, 0)

    def test_continue_claim_once_and_publication_order(self):
        self.assertEqual(self.worker.tick(), 0)
        self.assertEqual((self.calls, self.q.claims, self.q.creates), (1, 1, 1))
        self.assertEqual(self.q.events, [*r.DOCUMENTS, "created", "processed"])
        self.assertEqual(prop(self.q.page(SOURCE), "Next Job ID"), "next")
        self.assertEqual(prop(self.q.page(NEXT), "Status", "select"), "QUEUED")
        self.assertEqual(set(self.bundle), {"job_id", "result_commit", "report_path", "receipt", "current_report", "current_state", "referenced_paths"})
        self.assertEqual(self.worker.tick(), 0)
        self.assertEqual(self.calls, 1)

    def test_represented_job_never_reviews_again(self):
        self.worker.tick()
        self.q.pages[SOURCE]["properties"]["Review Status"] = r.select("PENDING")
        with self.assertRaises(r.BridgeError):
            self.worker.tick()
        self.assertEqual(self.calls, 1)

    def test_duplicate_source_ids_never_review(self):
        duplicate = page()
        duplicate["id"] = NEXT
        self.q.pages[NEXT] = duplicate
        with self.assertRaises(r.BridgeError):
            self.worker.tick()
        self.assertEqual((self.calls, self.q.claims), (0, 0))

    def assert_rejected(self):
        self.assertEqual(self.worker.tick(), 1)
        self.assertEqual(prop(self.q.page(SOURCE), "Review Status", "select"), "ERROR")
        self.assertEqual(self.q.creates, 0)
        self.worker.tick()
        self.assertEqual(self.calls, 1)

    def test_invalid_output(self):
        self.payload = {"invalid": True}
        self.assert_rejected()

    def test_two_next_jobs(self):
        self.payload["next_job"] = [self.payload["next_job"], self.payload["next_job"]]
        self.assert_rejected()

    def test_safety_flags_true_or_nonboolean(self):
        for key in ("phone_access", "flash_write", "erase", "repack"):
            for value in (True, 0, "false"):
                p = output()
                p["next_job"]["safety"][key] = value
                with self.assertRaises(r.BridgeError):
                    r.validate_output(p, "current", self.repo, SECRET)

    def test_bad_sha(self):
        self.payload["next_job"]["script_sha256"] = "f" * 64
        self.assert_rejected()

    def test_calculated_sha_and_worker_regression(self):
        p = r.validate_output(self.payload, "current", self.repo, SECRET)
        self.assertEqual(p["next_job"]["script_sha256"], hashlib.sha256(p["next_script"].encode()).hexdigest())
        validate({"properties": r.next_properties(p["next_job"])}, json.dumps(p["next_job"]).encode(), p["next_script"].encode(), self.repo)

    def test_hardware_gate_latches(self):
        self.payload["review"].update(result="hardware_gate", next_job_id=None)
        self.payload.update(next_job=None, next_script=None)
        self.assertEqual(self.worker.tick(), 0)
        self.assertEqual(self.q.creates, 0)
        self.assertTrue((self.repo / "state/HARDWARE_GATE.json").exists())
        self.q.pages[SOURCE] = page()
        self.assertEqual(self.worker.tick(), 0)
        self.assertEqual(self.calls, 1)

    def test_hardware_gate_with_script_rejected(self):
        self.payload["review"].update(result="hardware_gate", next_job_id=None)
        self.assert_rejected()

    def test_crash_after_create_recovers_without_duplicate(self):
        self.q.crash = True
        with self.assertRaises(Crash):
            self.worker.tick()
        self.assertEqual(prop(self.q.page(SOURCE), "Review Status", "select"), "CLAIMED")
        self.assertEqual(self.worker.tick(), 0)
        self.assertEqual((self.calls, self.q.creates), (1, 1))
        self.assertEqual(prop(self.q.page(SOURCE), "Review Status", "select"), "PROCESSED")

    def test_ambiguous_create_does_not_repeat_post(self):
        self.q.missing_create = True
        with self.assertRaises(Crash):
            self.worker.tick()
        self.assertEqual(self.worker.tick(), 1)
        self.assertEqual((self.calls, self.q.creates), (1, 1))

    def test_crash_during_codex_does_not_repeat(self):
        def crash(*args):
            self.calls += 1
            raise Crash()
        self.worker.reviewer = crash
        with self.assertRaises(Crash):
            self.worker.tick()
        self.assertEqual(self.worker.tick(), 1)
        self.assertEqual(self.calls, 1)

    def test_existing_successor_not_duplicated(self):
        self.q.pages[NEXT] = {"id": NEXT, "properties": r.next_properties(output()["next_job"]) |
                             {"Status": r.select("QUEUED"), "Review Status": r.select("PENDING")}}
        self.assert_rejected()

    def test_dirty_or_wrong_branch_stops_before_poll(self):
        for attr in ("dirty", "wrong_branch"):
            setattr(self.git, attr, True)
            with self.assertRaises(r.BridgeError):
                self.worker.tick()
            setattr(self.git, attr, False)
        self.assertEqual(self.calls, 0)

    def test_unsafe_source_never_claims(self):
        for key, value in (("Branch", rich("main")), ("Phone Access", {"checkbox": True}),
                           ("Result Commit", rich("HEAD")), ("Report Path", rich("../escape.txt")), ("Exit Code", {"number": 1})):
            self.q.pages[SOURCE] = page()
            self.q.pages[SOURCE]["properties"][key] = value
            with self.assertRaises(r.BridgeError):
                self.worker.tick()
        self.assertEqual((self.calls, self.q.claims), (0, 0))

    def test_hardware_and_mutation_scripts_rejected(self):
        for script in ("import serial", "import usb", "import socket", "import subprocess", "import ctypes", "import os",
                       "print('COM4')", "print('BROM')", "print('DA')", "print('repack')", "exec('x')",
                       "from pathlib import Path\nPath('x').write_bytes(b'x')", "from pathlib import Path\nPath('//./PhysicalDrive0').read_bytes()",
                       "from pathlib import Path\nPath('//host/share/file').read_bytes()", "import pathlib\nprint(pathlib.os)"):
            p = output()
            p["next_script"] = script
            with self.assertRaises(r.BridgeError, msg=script):
                r.validate_output(p, "current", self.repo, SECRET)

    def test_secret_never_persisted(self):
        self.payload["notion_update"] = SECRET
        self.assert_rejected()
        for path in self.repo.rglob("*"):
            if path.is_file():
                self.assertNotIn(SECRET.encode(), path.read_bytes())
        with patch.dict(os.environ, {"F2_NOTION_TOKEN": SECRET, "GITHUB_TOKEN": SECRET, "OTHER_API_KEY": SECRET}):
            self.assertNotIn(SECRET, json.dumps(r.codex_environment(self.repo)))

    def test_read_only_lock_and_crash_recovery(self):
        path = self.repo / "orchestrator.lock"
        with r.local_lock(path) as first:
            self.assertTrue(first)
            with r.local_lock(path) as second:
                self.assertFalse(second)
        with r.local_lock(path) as again:
            self.assertTrue(again)
        code = "import sys,os;sys.path.insert(0,sys.argv[1]);from research_orchestrator import local_lock;from pathlib import Path\nwith local_lock(Path(sys.argv[2])) as locked: os._exit(0 if locked else 2)"
        proc = subprocess.run([sys.executable, "-c", code, str(r.HERE), str(path)], capture_output=True)
        self.assertEqual(proc.returncode, 0)
        with r.local_lock(path) as after_crash:
            self.assertTrue(after_crash)

    def test_current_excerpt_excludes_history(self):
        q = r.ReviewQueue(None)
        def block(kind, text):
            return {"type": kind, kind: {"rich_text": [{"plain_text": text}]}}
        q.top_blocks = lambda _: [block("heading_2", "Current"), block("paragraph", "Useful"),
                                   block("heading_2", "Historical"), block("paragraph", "Do not include")]
        self.assertEqual(q.current_state(), "Current\nUseful")

    def test_query_oldest_exact_filter(self):
        class Client:
            queue_id = r.QUEUE
            def request(self, method, url, payload):
                self.payload = payload
                return {"results": []}
        client = Client()
        r.ReviewQueue(client).pending()
        self.assertEqual(client.payload["page_size"], 1)
        self.assertEqual(client.payload["sorts"][0]["direction"], "ascending")
        self.assertEqual(len(client.payload["filter"]["and"]), 2)

    def test_document_write_is_bounded_and_idempotent(self):
        class Client:
            def __init__(self):
                self.blocks, self.calls = [], []
            def request(self, method, url, payload=None):
                if method == "GET":
                    return {"results": self.blocks}
                self.calls.append((url, payload))
                if "children" in payload:
                    self.blocks = [{"id": SOURCE, **payload["children"][0]}]
                return {}
        client = Client()
        q = r.ReviewQueue(client)
        state = {}
        q.publish_document(r.DOCUMENTS[0], r.MARKER + "\nCurrent", state, lambda: None)
        q.publish_document(r.DOCUMENTS[0], r.MARKER + "\nUpdated", state, lambda: None)
        self.assertEqual(client.calls[0][1]["position"], {"type": "start"})
        self.assertEqual(client.calls[1][0], "blocks/" + SOURCE)
        self.assertNotIn("children", client.calls[1][1])

    def test_ambiguous_document_creation_never_duplicates(self):
        class Client:
            def request(self, method, url, payload=None):
                if method == "GET":
                    return {"results": []}
                raise Crash()
        q, state = r.ReviewQueue(Client()), {}
        with self.assertRaises(Crash):
            q.publish_document(r.DOCUMENTS[0], r.MARKER, state, lambda: None)
        with self.assertRaises(r.BridgeError):
            q.publish_document(r.DOCUMENTS[0], r.MARKER, state, lambda: None)

    def test_output_directory_has_only_contract_files(self):
        self.worker.tick()
        artifacts = next((self.repo / "state/review").iterdir())
        self.assertEqual({p.name for p in artifacts.iterdir()}, {"review.json", "next_script.py", "next_job.json", "notion_update.md"})

    def test_final_patch_failure_recovers_without_codex(self):
        update = self.q.review_update
        def fail_once(key, properties):
            if properties.get("Review Status") == r.select("PROCESSED"):
                self.q.review_update = update
                raise r.BridgeError("Temporary Notion outage")
            return update(key, properties)
        self.q.review_update = fail_once
        self.assertEqual(self.worker.tick(), 1)
        self.assertEqual(self.worker.tick(), 0)
        self.assertEqual((self.calls, self.q.creates), (1, 1))

    def test_codex_launcher_has_no_tools_or_secrets(self):
        directory = self.repo / "invocation"
        directory.mkdir()
        home = self.repo / "original_home"
        home.mkdir()
        (home / "auth.json").write_text('{"fixture":"synthetic-auth"}')
        def launch(command, **kwargs):
            self.assertNotIn(SECRET, json.dumps(command) + kwargs["input"] + json.dumps(kwargs["env"]))
            self.assertIn("--ephemeral", command)
            self.assertIn("--ignore-user-config", command)
            self.assertIn("read-only", command)
            for f in ("shell_tool", "apps", "plugins", "multi_agent", "unified_exec"):
                self.assertIn(f, command)
                self.assertEqual(command[command.index(f) - 1], "--disable")
            Path(command[command.index("--output-last-message") + 1]).write_text(json.dumps(output()))
            return subprocess.CompletedProcess(command, 0, '{"type":"turn.completed","usage":{"input_tokens":123}}', '')
        with patch.dict(os.environ, {"CODEX_HOME": str(home), "F2_NOTION_TOKEN": SECRET}), \
                patch.object(r, "codex_binary", return_value=Path("codex.exe")), patch.object(r.subprocess, "run", side_effect=launch):
            result = r.run_codex({"current_report": "fixture"}, directory, SECRET)
        self.assertEqual(result["review"]["result"], "continue")
        self.assertFalse((directory / "codex_home/auth.json").exists())
        self.assertFalse((directory / "answer.json").exists())
        self.assertTrue((home / "auth.json").exists())

    def test_no_secret_in_git_diff_tracked_files_or_runtime_logs(self):
        # Purely local inspection. The credential never becomes a command argument.
        secret = r.environment("F2_NOTION_TOKEN")
        root = Path(__file__).resolve().parents[4]
        def git_bytes(*args):
            result = subprocess.run(["git.exe", "-C", str(root), *args], capture_output=True)
            self.assertEqual(result.returncode, 0)
            return result.stdout
        contents = [git_bytes("diff"), git_bytes("diff", "--cached")]
        tracked = git_bytes("ls-files", "-z").decode().split("\0")
        for name in filter(None, tracked):
            path = root / name
            if path.is_file() and path.stat().st_size <= 2 * 1024 * 1024:
                contents.append(path.read_bytes())
        for base in (r.HERE / "state", r.HERE.parent / "logs"):
            if base.exists():
                contents.extend(p.read_bytes() for p in base.rglob("*") if p.is_file() and p.suffix in (".txt", ".md", ".log", ".json"))
        for data in contents:
            if secret:
                self.assertFalse(secret.encode() in data, "Credential found; contents suppressed")
        self.assertFalse(any(name.startswith("research/f2/automation/bridge/state/") for name in tracked))
        self.assertNotIn("research/f2/automation/bridge/config.local.json", tracked)


if __name__ == "__main__":
    unittest.main(verbosity=1)
