"""Offline integration tests: real PowerShell/Python, disposable local Git remotes.

No GitHub, device access, or real Downloads inbox is used. Failed fixtures are
retained under TEMP for diagnosis. Run with the canonical Python executable.
"""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
import zipfile


RUNNER = Path(__file__).resolve().parents[1] / "f2_runner.ps1"
PYTHON = r"C:\Users\verto\mtkclient\.venv\Scripts\python.exe"
AUTO = "research/f2/automation"
REPORTS = "research/f2/work/reports"
BRANCH = "automate-research"
SAFETY = dict(mode="offline_analysis", phone_access=False, flash_write=False,
              erase=False, repack=False)


def git(repo, *args):
    p = subprocess.run(["git.exe", "-C", str(repo), *args], capture_output=True,
                       text=True, encoding="utf-8", errors="replace")
    if p.returncode:
        raise AssertionError(f"git {args}: {p.stdout}\n{p.stderr}")
    return p.stdout.strip()


def write(path, text):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(text.encode("utf-8"))


class RunnerTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix="f2_repoqueue_test_"))
        self.remote = self.root / "remote.git"
        self.publisher = self.root / "publisher"
        self.repo = self.root / "worker"
        self.inbox = self.root / "inbox"
        self.inbox.mkdir()
        self.publisher.mkdir()
        git(self.root, "init", "--bare", str(self.remote))
        git(self.publisher, "init", "-b", BRANCH)
        self.configure(self.publisher)
        write(self.publisher / ".gitignore", "research/f2/work/\n")
        write(self.publisher / f"{AUTO}/.gitattributes", "jobs/** -text\n")
        git(self.publisher, "add", "--", ".gitignore", f"{AUTO}/.gitattributes")
        git(self.publisher, "commit", "-m", "fixture baseline")
        git(self.publisher, "remote", "add", "github", str(self.remote))
        git(self.publisher, "push", "-u", "github", BRANCH)
        git(self.root, "clone", "--branch", BRANCH, "--origin", "github",
            str(self.remote), str(self.repo))
        self.configure(self.repo)

    def configure(self, repo):
        git(repo, "config", "user.name", "F2 runner integration test")
        git(repo, "config", "user.email", "f2-test@example.invalid")
        git(repo, "config", "core.autocrlf", "true")
        git(repo, "config", "commit.gpgsign", "false")

    def job(self, name="test_job", body=None, **changes):
        job_id = name
        script = body
        if script is None:
            script = ("import os, sys\nfrom pathlib import Path\n"
                      "assert os.environ['F2_AUTOMATION_OFFLINE'] == '1'\n"
                      "assert Path.cwd() == Path(__file__).resolve().parents[4]\n"
                      "print('FIXTURE SMOKE = PASS')\n")
        data = dict(schema_version=1, job_id=job_id, enabled=True,
                    safety=SAFETY.copy(), script=f"{AUTO}/jobs/{job_id}.py",
                    script_sha256=hashlib.sha256(script.encode()).hexdigest(),
                    report=f"{REPORTS}/{job_id}.txt", args=[])
        data.update(changes)
        write(self.publisher / f"{AUTO}/jobs/{job_id}.py", script)
        write(self.publisher / f"{AUTO}/queue/{job_id}.job.json", json.dumps(data))
        return data, script

    def publish(self):
        git(self.publisher, "add", "--", f"{AUTO}/jobs", f"{AUTO}/queue")
        git(self.publisher, "commit", "-m", "publish fixture jobs")
        git(self.publisher, "push", "github", BRANCH)

    def run_runner(self, expected=0):
        p = subprocess.run(["powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass",
                            "-File", str(RUNNER), "-RepoRoot", str(self.repo),
                            "-PythonExe", PYTHON, "-Inbox", str(self.inbox),
                            "-Branch", BRANCH, "-Remote", "github", "-Once"],
                           capture_output=True, text=True, errors="replace", timeout=90)
        write(self.root / "last-run.log", p.stdout + p.stderr)
        self.assertEqual(p.returncode, expected, f"Fixture: {self.root}\n{p.stdout}\n{p.stderr}")
        return p.stdout + p.stderr

    def receipt(self, job_id="test_job"):
        return json.loads((self.repo / f"{AUTO}/results/{job_id}.result.json").read_text(encoding="utf-8-sig"))

    def assert_synced(self):
        self.assertEqual(git(self.repo, "status", "--porcelain"), "")
        self.assertEqual(git(self.repo, "rev-parse", "HEAD"),
                         git(self.remote, "rev-parse", f"refs/heads/{BRANCH}"))

    def test_fetch_execute_exact_staging_and_skip(self):
        self.job()
        self.publish()
        log = self.run_runner()
        self.assertIn("Remote advancement integrated", log)
        receipt = self.receipt()
        self.assertEqual(receipt["status"], "completed")
        self.assertEqual(receipt["exit_code"], 0)
        self.assertEqual(receipt["safety"], SAFETY)
        self.assertEqual(set(git(self.repo, "diff-tree", "--no-commit-id", "--name-only", "-r", "HEAD").splitlines()),
                         {f"{REPORTS}/test_job.txt", f"{AUTO}/results/test_job.result.json"})
        before = git(self.repo, "rev-parse", "HEAD")
        self.assertIn("Receipt exists; skipping", self.run_runner())
        self.assertEqual(before, git(self.repo, "rev-parse", "HEAD"))
        self.assert_synced()

    def test_reject_unsafe_manifests_without_execution(self):
        self.job("bad_hash", script_sha256="0" * 64)
        self.job("escape_script", script=f"{AUTO}/jobs/../outside.py")
        self.job("escape_report", report=f"{REPORTS}/../outside.txt")
        self.job("wrong_extension", script=f"{AUTO}/jobs/tool.ps1")
        self.job("missing_script", script=f"{AUTO}/jobs/missing.py")
        self.job("bad_id", job_id="../../escape")
        self.job("bad_mode", safety={**SAFETY, "mode": "hardware"})
        for key in ("phone_access", "flash_write", "erase", "repack"):
            self.job("bad_" + key, safety={**SAFETY, key: True})
        self.job("string_boolean", safety={**SAFETY, "phone_access": "false"})
        self.job("missing_boolean", safety={k: v for k, v in SAFETY.items() if k != "erase"})
        self.job("bad_args", args="echo unsafe")
        self.publish()
        log = self.run_runner(expected=1)
        self.assertNotIn("Executing repo_queue", log)
        self.assertFalse((self.repo / f"{AUTO}/results").exists())
        self.assertEqual(git(self.repo, "status", "--porcelain"), "")

    def test_dirty_tree_blocks_pull_and_preserves_index(self):
        self.job()
        self.publish()
        write(self.repo / "user-work.txt", "keep me")
        git(self.repo, "add", "--", "user-work.txt")
        before = git(self.repo, "rev-parse", "HEAD")
        self.assertIn("BLOCKED: working tree is dirty", self.run_runner())
        self.assertEqual(before, git(self.repo, "rev-parse", "HEAD"))
        self.assertEqual(git(self.repo, "diff", "--cached", "--name-only"), "user-work.txt")
        self.assertFalse((self.repo / f"{AUTO}/queue/test_job.job.json").exists())

    def test_user_commit_not_rebased_or_pushed(self):
        write(self.repo / "user-work.txt", "keep me")
        git(self.repo, "add", "--", "user-work.txt")
        git(self.repo, "commit", "-m", "user work")
        before = git(self.repo, "rev-parse", "HEAD")
        self.job()
        self.publish()
        self.assertIn("not owned by this runner session", self.run_runner(expected=1))
        self.assertEqual(before, git(self.repo, "rev-parse", "HEAD"))
        self.assertEqual(git(self.repo, "status", "--porcelain"), "")

    def install_push_race(self, conflict=False):
        target = f"{AUTO}/results/test_job.result.json" if conflict else "remote-note.txt"
        write(self.publisher / target, '{"external":true}\n')
        publisher = self.publisher.as_posix()
        marker = (self.root / "race-fired").as_posix()
        hook = ("#!/bin/sh\n"
                f"if [ ! -f '{marker}' ]; then\n"
                f"  touch '{marker}'\n"
                f"  git -C '{publisher}' add -- '{target}' || exit 1\n"
                f"  git -C '{publisher}' commit -m 'concurrent remote update' || exit 1\n"
                f"  git -C '{publisher}' push github {BRANCH} || exit 1\n"
                "fi\nexit 0\n")
        write(self.repo / ".git/hooks/pre-push", hook)

    def test_concurrent_push_rebases_only_result(self):
        self.job()
        self.publish()
        self.install_push_race()
        log = self.run_runner()
        self.assertIn("Push failed; preserving local result commit", log)
        self.assertTrue((self.repo / "remote-note.txt").exists())
        self.assertEqual(self.receipt()["status"], "completed")
        self.assert_synced()

    def test_rebase_conflict_stops_and_preserves_original_commit(self):
        self.job()
        self.publish()
        self.install_push_race(conflict=True)
        self.run_runner(expected=1)
        self.assertTrue((self.repo / ".git/rebase-merge").exists())
        original = json.loads(git(self.repo, "show", f"ORIG_HEAD:{AUTO}/results/test_job.result.json").lstrip('\ufeff'))
        self.assertEqual(original["status"], "completed")
        remote = json.loads(git(self.remote, "show", f"{BRANCH}:{AUTO}/results/test_job.result.json"))
        self.assertEqual(remote, {"external": True})

    def test_nonzero_stderr_creates_failed_receipt(self):
        self.job(body="import sys\nprint('expected failure', file=sys.stderr)\nraise SystemExit(7)\n")
        self.publish()
        self.run_runner()
        self.assertEqual(self.receipt()["status"], "failed")
        self.assertEqual(self.receipt()["exit_code"], 7)
        report = (self.repo / f"{REPORTS}/test_job.txt").read_text(encoding="utf-8-sig")
        self.assertIn("expected failure", report)
        self.assert_synced()

    def test_unexpected_job_write_preserves_results_without_commit(self):
        self.job(body="from pathlib import Path\nPath('unexpected.txt').write_text('preserved')\n")
        self.publish()
        expected_head = git(self.publisher, "rev-parse", "HEAD")
        self.assertIn("Unexpected job modification", self.run_runner(expected=1))
        self.assertEqual(git(self.repo, "rev-parse", "HEAD"), expected_head)
        self.assertEqual(self.receipt()["status"], "completed")
        self.assertEqual((self.repo / "unexpected.txt").read_text(), "preserved")

    def test_zip_safety_rejection(self):
        data, script = self.job("zip_rejected", safety={**SAFETY, "flash_write": True})
        with zipfile.ZipFile(self.inbox / "f2job_rejected.zip", "w") as z:
            z.writestr("job.json", json.dumps(data))
            z.writestr("script.py", script)
        log = self.run_runner(expected=1)
        self.assertIn("safety.flash_write must be JSON false", log)
        self.assertFalse((self.repo / f"{AUTO}/results").exists())
        self.assertTrue((self.inbox / "F2AutomationFailed/f2job_rejected.zip").exists())

    def test_arguments_are_data_not_shell(self):
        argument = "hello; Write-Output INJECTION"
        self.job(body="import sys\nassert sys.argv[1] == 'hello; Write-Output INJECTION'\nprint('argument PASS')\n", args=[argument])
        self.publish()
        self.run_runner()
        self.assertEqual(self.receipt()["exit_code"], 0)
        self.assert_synced()

    def test_zip_fallback_and_queue_priority(self):
        self.job("queue_first")
        self.publish()
        data, script = self.job("zip_second")
        del data["script"]
        with zipfile.ZipFile(self.inbox / "f2job_zip_second.zip", "w") as z:
            z.writestr("job.json", json.dumps(data))
            z.writestr("script.py", script)
        log = self.run_runner()
        self.assertLess(log.index("Executing repo_queue"), log.index("Executing zip"))
        self.assertEqual(self.receipt("zip_second")["status"], "completed")
        self.assertTrue((self.inbox / "F2AutomationDone/f2job_zip_second.zip").exists())
        self.assert_synced()


if __name__ == "__main__":
    unittest.main(verbosity=2)
