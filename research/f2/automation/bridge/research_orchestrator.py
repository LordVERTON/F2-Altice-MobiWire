"""One deterministic Notion poll, at most one tool-free Codex review per result."""
from __future__ import annotations

import argparse
import ast
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys

from notion_queue import BRANCH, SAFETY, BridgeError, NotionQueue, environment, identifier, prop, rich, safe_text
from notion_worker import AUTO, REPORTS, ROOT, Git, dump, parse_json, scoped_path, utc, validate

HERE = Path(__file__).resolve().parent
QUEUE = "1bcea051-574f-40f5-ab62-d98debf41cb4"
DOCUMENTS = ("3e9173c5-7e04-8093-a8e3-ce8c03b398ac",
             "3e9173c5-7e04-8076-b559-c63e7a2bd708",
             "3ea173c5-7e04-81e3-83b1-eadbe67ad997")
MARKER = "F2 AUTOMATION CURRENT STATE"
HARDWARE = "AUTOMATION OFFLINE PHASE COMPLETE\nMANUAL HARDWARE GATE REQUIRED"
CLASSES = ("facts", "strongly_supported", "hypotheses", "unknown", "superseded")
MAX_REPORT = 192000


def require(condition, message):
    if not condition:
        raise BridgeError(message)


def no_secret(text, secret):
    require(not secret or secret not in text, "Credential found in content; refused")
    require(not re.search(r"\b(?:ntn_|secret_)[A-Za-z0-9_-]{16,}", text), "Credential-like content refused")
    return text


def job_id(value):
    require(isinstance(value, str) and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,159}", value), "Invalid Job ID")
    return value


def select(value):
    return {"select": {"name": value}}


def block_text(block):
    return "".join(x.get("plain_text", x.get("text", {}).get("content", ""))
                   for x in block.get(block["type"], {}).get("rich_text", []))


@contextmanager
def local_lock(path):
    """OS byte-range lock, released by the OS after death. Never unlink the inode."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a+b") as stream:
        stream.seek(0, 2)
        if not stream.tell():
            stream.write(b"0")
            stream.flush()
        stream.seek(0)
        acquired = False
        try:
            if os.name == "nt":
                import msvcrt
                msvcrt.locking(stream.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
            acquired = True
        except OSError:
            pass
        try:
            yield acquired
        finally:
            if acquired:
                stream.seek(0)
                if os.name == "nt":
                    msvcrt.locking(stream.fileno(), msvcrt.LK_UNLCK, 1)
                else:
                    fcntl.flock(stream, fcntl.LOCK_UN)


class ReviewQueue:
    """Separate review permissions; the execution worker's API stays unchanged."""
    def __init__(self, client):
        self.client = client

    def query(self, filters, size=2):
        data = self.client.request("POST", f"data_sources/{self.client.queue_id}/query", {
            "filter": {"and": filters}, "page_size": size,
            "sorts": [{"timestamp": "created_time", "direction": "ascending"}]})
        return data.get("results", [])

    def pending(self):
        return self.query([{"property": "Status", "select": {"equals": "COMPLETED"}},
                           {"property": "Review Status", "select": {"equals": "PENDING"}}], 1)

    def by_job(self, name):
        return self.query([{"property": "Job ID", "rich_text": {"equals": name}}])

    def active(self):
        return self.query([{"or": [{"property": "Status", "select": {"equals": s}}
                                     for s in ("QUEUED", "CLAIMED", "RUNNING")]}])

    def page(self, page_id):
        return self.client.page(page_id)

    def review_update(self, page_id, properties):
        require(not set(properties) - {"Review Status", "Review Error", "Reviewed At", "Next Job ID"},
                "Invalid review properties")
        return self.client.request("PATCH", "pages/" + identifier(page_id), {"properties": properties})

    def top_blocks(self, page_id):
        # One page only: never walk the historical Notion tree.
        return self.client.request("GET", f"blocks/{identifier(page_id)}/children?page_size=100")["results"]

    def current_state(self):
        blocks = self.top_blocks(DOCUMENTS[0])
        managed = [block_text(b) for b in blocks if block_text(b).startswith(MARKER)]
        require(len(managed) <= 1, "Duplicate managed current-state blocks")
        if managed:
            text = managed[0]
        else:
            lines, heading = [], False
            for b in blocks:
                if b["type"].startswith("heading"):
                    if heading:
                        break
                    heading = True
                if block_text(b):
                    lines.append(block_text(b))
            text = "\n".join(lines)
        require(bool(text) and len(text) <= 9000, "Current-state excerpt missing or too large")
        return text

    def publish_document(self, page_id, text, state, save):
        blocks = self.top_blocks(page_id)
        managed = [b for b in blocks if block_text(b).startswith(MARKER)]
        require(len(managed) <= 1, "Duplicate managed current-state blocks")
        content = {"rich_text": [{"type": "text", "text": {"content": text[i:i + 1800]}}
                                  for i in range(0, len(text), 1800)]}
        if managed:
            self.client.request("PATCH", "blocks/" + identifier(managed[0]["id"]), {"paragraph": content})
        else:
            # Ambiguous POST/PATCH creation must not be blindly retried after a crash.
            attempted = state.setdefault("document_attempts", [])
            require(page_id not in attempted, "Ambiguous document insertion; manual reconciliation required")
            attempted.append(page_id)
            save()
            self.client.request("PATCH", f"blocks/{page_id}/children", {
                "position": {"type": "start"},
                "children": [{"object": "block", "type": "paragraph", "paragraph": content}]})

    def create_next(self, manifest, script, parent):
        files = [self.client.upload("job.json", (json.dumps(manifest, indent=2) + "\n").encode()),
                 self.client.upload("script.py", script.encode())]
        properties = next_properties(manifest)
        properties["Files"] = {"files": files}
        properties["Name"] = {"title": [{"text": {"content": manifest["job_id"]}}]}
        properties["Status"] = select("QUEUED")
        properties["Review Status"] = select("PENDING")
        return self.client.request("POST", "pages", {
            "parent": {"type": "data_source_id", "data_source_id": self.client.queue_id},
            "properties": properties, "children": [{"object": "block", "type": "paragraph",
                "paragraph": {"rich_text": [{"text": {"content": "F2 review parent: " + parent}}]}}]})

    def verify_next(self, page, manifest, parent):
        require(prop(page, "Job ID") == manifest["job_id"] and
                prop(page, "Script SHA256") == manifest["script_sha256"] and
                prop(page, "Branch") == BRANCH and prop(page, "Report Path") == manifest["report"],
                "Existing next job differs; refusing adoption")
        require(any(block_text(b) == "F2 review parent: " + parent for b in self.top_blocks(page["id"])),
                "Existing next job has a different parent")
        files = self.client.attachments(page)
        script = self.client.download(files["script.py"], 64000)
        raw = self.client.download(files["job.json"], 16000)
        require(parse_json(raw) == manifest, "Existing next manifest differs")
        validate(page, raw, script, ROOT)


def next_properties(manifest):
    p = {"Job ID": rich(manifest["job_id"]), "Schema Version": {"number": 1},
         "Branch": rich(BRANCH), "Script SHA256": rich(manifest["script_sha256"]),
         "Report Path": rich(manifest["report"]), "Safety Mode": select("offline_analysis")}
    for label in ("Phone Access", "Flash Write", "Erase", "Repack"):
        p[label] = {"checkbox": False}
    return p


def validate_source(page, repo):
    require(prop(page, "Status", "select") == "COMPLETED", "Source not COMPLETED")
    require(prop(page, "Branch") == BRANCH, "Source branch mismatch")
    require(prop(page, "Safety Mode", "select") == "offline_analysis", "Source not offline")
    require(all(prop(page, label, "checkbox") is False for label in
                ("Phone Access", "Flash Write", "Erase", "Repack")), "Source safety flag enabled")
    code = prop(page, "Exit Code", "number")
    require(type(code) in (int, float) and code == 0, "Source exit code is not zero")
    commit = prop(page, "Result Commit")
    require(bool(re.fullmatch(r"[a-f0-9]{40}", commit)), "Invalid result commit")
    name = job_id(prop(page, "Job ID"))
    report = prop(page, "Report Path")
    scoped_path(repo, report, REPORTS)
    require(report.endswith(".txt"), "Expected text report")
    return name, commit, report


def validate_output(payload, source, repo, secret):
    require(isinstance(payload, dict) and set(payload) == {"review", "next_script", "next_job", "notion_update"},
            "Invalid Codex envelope; exactly one next job allowed")
    no_secret(json.dumps(payload, ensure_ascii=False), secret)
    review = payload["review"]
    require(isinstance(review, dict) and set(review) == {"schema_version", "reviewed_job_id", "result",
            "classification", "next_job_id", "reason"}, "Invalid review schema")
    require(type(review["schema_version"]) is int and review["schema_version"] == 1 and
            review["reviewed_job_id"] == source, "Review source mismatch")
    require(review["result"] in ("continue", "hardware_gate", "error"), "Invalid review result")
    require(isinstance(review["reason"], str) and 1 <= len(review["reason"]) <= 1200, "Invalid review reason")
    classes = review["classification"]
    require(isinstance(classes, dict) and set(classes) == set(CLASSES), "Invalid classification")
    for values in classes.values():
        require(isinstance(values, list) and len(values) <= 8 and
                all(isinstance(v, str) and 0 < len(v) <= 600 for v in values), "Classification too large/invalid")
    require(isinstance(payload["notion_update"], str) and 0 < len(payload["notion_update"]) <= 3500,
            "Invalid Notion summary")
    if review["result"] != "continue":
        require(review["next_job_id"] is None and payload["next_script"] is None and payload["next_job"] is None,
                "Non-continuation must not contain any next job")
        return payload
    name = job_id(review["next_job_id"])
    require(name != source, "Cannot repeat the current job")
    script, manifest = payload["next_script"], payload["next_job"]
    require(isinstance(script, str) and 0 < len(script.encode()) <= 64000, "Invalid next script")
    require(isinstance(manifest, dict) and set(manifest) == {"schema_version", "job_id", "enabled", "branch",
            "safety", "report", "script_sha256", "args"}, "Invalid next manifest schema")
    require(manifest["job_id"] == name and manifest["branch"] == BRANCH and manifest["args"] == [],
            "Invalid next job identity/arguments")
    digest = hashlib.sha256(script.encode()).hexdigest()
    require(manifest["script_sha256"] in (None, digest), "Incorrect script SHA256")
    manifest["script_sha256"] = digest
    # Reuse exactly the execution worker's AST, paths, safety and hash checks.
    _, paths, _ = validate({"properties": next_properties(manifest)}, json.dumps(manifest).encode(), script.encode(), repo)
    require(all(not (repo / p).exists() for p in paths.values()), "Next job artifacts already exist")
    # Generated analysis is deliberately narrower than legacy hand-written jobs.
    allowed = {"pathlib", "struct", "json", "re", "math", "hashlib", "collections", "itertools",
               "functools", "bisect", "statistics", "dataclasses", "typing", "enum", "capstone", "array"}
    for node in ast.walk(ast.parse(script)):
        if isinstance(node, ast.Import):
            require(all(x.name.split(".")[0] in allowed for x in node.names), "Generated script import outside analysis allowlist")
        if isinstance(node, ast.ImportFrom):
            require(node.level == 0 and (node.module or "").split(".")[0] in allowed, "Generated script import outside analysis allowlist")
        if isinstance(node, (ast.Name, ast.Attribute)):
            name = node.id if isinstance(node, ast.Name) else node.attr
            require((not name.startswith("__") or name in {"__name__", "__file__"}) and name not in {"open", "write", "write_bytes", "write_text", "touch", "mkdir",
                    "unlink", "rmdir", "rename", "replace", "chmod", "symlink_to", "hardlink_to", "getattr", "setattr", "globals", "locals"},
                    "Generated script must only read local analysis inputs and print")
            if isinstance(node, ast.Attribute):
                require(not name.startswith("_") and name not in {"os", "sys", "io", "ctypes"},
                        "Generated analysis cannot traverse module internals")
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            require(not re.search(r"(?i)(\\\\|//|/dev/|physicaldrive|globalroot|deviceiocontrol|://)", node.value),
                    "Device, network and special filesystem paths forbidden")
    return payload


def object_schema(properties):
    return {"type": "object", "properties": properties, "required": list(properties), "additionalProperties": False}


def output_schema():
    string = {"type": "string"}
    review = object_schema({"schema_version": {"type": "integer", "enum": [1]}, "reviewed_job_id": string,
        "result": {"type": "string", "enum": ["continue", "hardware_gate", "error"]},
        "classification": object_schema({k: {"type": "array", "items": string} for k in CLASSES}),
        "next_job_id": {"type": ["string", "null"]}, "reason": string})
    manifest = object_schema({"schema_version": {"type": "integer", "enum": [1]}, "job_id": string,
        "enabled": {"type": "boolean", "enum": [True]}, "branch": {"type": "string", "enum": [BRANCH]},
        "safety": object_schema({k: {"type": "string" if isinstance(v, str) else "boolean", "enum": [v]} for k, v in SAFETY.items()}),
        "report": string, "script_sha256": {"type": ["string", "null"]}, "args": {"type": "array", "items": string}})
    return object_schema({"review": review, "next_script": {"type": ["string", "null"]},
        "next_job": {"anyOf": [manifest, {"type": "null"}]}, "notion_update": string})


def codex_binary():
    npm = Path(os.environ.get("APPDATA", "")) / "npm/node_modules/@openai/codex/node_modules/@openai/codex-win32-x64/vendor/x86_64-pc-windows-msvc/bin/codex.exe"
    require(npm.is_file(), "Native Codex executable not found")
    return npm


def codex_environment(home):
    # Allowlist; no Notion, GitHub, inherited agent sessions or arbitrary API secrets.
    names = {"SYSTEMROOT", "WINDIR", "PATH", "PATHEXT", "TEMP", "TMP", "USERPROFILE", "APPDATA", "LOCALAPPDATA", "COMSPEC"}
    env = {k: v for k, v in os.environ.items() if k.upper() in names}
    env.update(CODEX_HOME=str(home), PYTHONIOENCODING="utf-8")
    return env


def run_codex(bundle, directory, secret):
    home, workspace = directory / "codex_home", directory / "workspace"
    home.mkdir(exist_ok=True)
    workspace.mkdir(exist_ok=True)
    # Isolate plugins, MCP, skills, rules and user configuration. Copy only Codex auth.
    original_home = Path(os.environ.get("CODEX_HOME", str(Path.home() / ".codex")))
    auth = original_home / "auth.json"
    require(auth.is_file(), "Codex file authentication unavailable; run codex login first")
    auth_bytes = auth.read_bytes()
    no_secret(auth_bytes.decode(), secret)
    schema, output = directory / "schema.json", directory / "answer.json"
    dump(schema, output_schema())
    require(not output.exists(), "Codex output already exists; no repeated invocation")
    prompt = no_secret(HERE.joinpath("review_prompt.txt").read_text(encoding="utf-8") + "\n" + json.dumps(bundle, ensure_ascii=False), secret)
    require(len(prompt) <= MAX_REPORT + 20000, "Review prompt exceeds context budget")
    command = [str(codex_binary()), "exec", "--ignore-user-config", "--ignore-rules", "--ephemeral",
        "--skip-git-repo-check", "--sandbox", "read-only", "-C", str(workspace), "--json",
        "--output-schema", str(schema), "--output-last-message", str(output),
        "-c", 'approval_policy="never"', "-c", 'web_search="disabled"',
        "-c", "project_doc_max_bytes=0", "-c", 'model_reasoning_effort="low"']
    for feature in ("daemon_auto_start", "shell_tool", "unified_exec", "apps", "plugins", "multi_agent", "multi_agent_v2", "browser_use",
                    "browser_use_external", "computer_use", "in_app_browser", "image_generation", "view_image", "skill_search"):
        command += ["--disable", feature]
    command.append("-")
    (home / "auth.json").write_bytes(auth_bytes)
    try:
        result = subprocess.run(command, input=prompt, capture_output=True, text=True, encoding="utf-8",
            errors="replace", env=codex_environment(home), cwd=workspace, timeout=600,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        require(result.returncode == 0 and output.is_file(), "Codex failed; no automatic retry")
        # Persist usage only, never raw CLI output, traces, prompts or stderr.
        usage = {}
        for line in result.stdout.splitlines():
            try:
                event = json.loads(line)
            except ValueError:
                continue
            if event.get("type") == "turn.completed":
                usage = event.get("usage", {})
            item = event.get("item", {})
            require(item.get("type") not in ("command_execution", "mcp_tool_call", "web_search", "file_change"),
                    "Unexpected Codex tool use; output refused")
        dump(directory / "usage.json", usage)
        require(output.stat().st_size <= 128000, "Codex output too large")
        return parse_json(no_secret(output.read_text(encoding="utf-8"), secret).encode())
    finally:
        # Short-lived authentication copy; never remove the user's original auth.
        (home / "auth.json").unlink(missing_ok=True)
        output.unlink(missing_ok=True)


class Orchestrator:
    def __init__(self, queue, git, repo=ROOT, state=None, reviewer=run_codex, secret=""):
        self.q, self.git, self.repo, self.reviewer, self.secret = queue, git, repo, reviewer, secret
        self.state = state or HERE / "state"
        self.active_path = self.state / "orchestrator.json"

    def guard(self):
        self.git.branch()
        require(self.git.clean(), "Working tree must be clean")

    def save(self, s):
        no_secret(json.dumps(s), self.secret)
        dump(self.active_path, s)

    def evidence(self, page):
        name, commit, report = validate_source(page, self.repo)
        self.git.confirm_pushed(commit)
        raw = self.git.run("show", f"{commit}:{AUTO}/results/{name}.result.json")
        receipt = parse_json(no_secret(raw, self.secret).encode())
        require(receipt.get("job_id") == name and receipt.get("status") == "completed" and
                type(receipt.get("exit_code")) is int and receipt["exit_code"] == 0 and
                receipt.get("report") == report and receipt.get("safety") == SAFETY and
                identifier(receipt.get("notion_page_id")) == identifier(page["id"]), "Receipt mismatch")
        require(all(receipt["safety"][key] is False for key in SAFETY if key != "mode"), "Receipt safety flags are not false")
        require(receipt.get("script_sha256") == prop(page, "Script SHA256") and
                bool(re.fullmatch(r"[a-f0-9]{64}", receipt.get("script_sha256", ""))), "Receipt script SHA mismatch")
        blob = self.git.run("show", f"{commit}:{report}", check=False)
        require(blob.returncode == 0, "Committed report unavailable")
        text = blob.stdout  # Keep the complete report, including leading/trailing whitespace.
        require(0 < len(text) <= MAX_REPORT, "Complete report exceeds compact-context limit; manual review required")
        no_secret(text, self.secret)
        excerpt = no_secret(self.q.current_state(), self.secret)
        references = sorted(set(re.findall(r"research/f2/[A-Za-z0-9_./-]+", text)))[:40]
        return {"job_id": name, "result_commit": commit, "report_path": report, "receipt": receipt,
                "current_report": text, "current_state": excerpt, "referenced_paths": references}

    def fail(self, s, exc):
        # Bridge errors contain our own fixed validation messages, never model text.
        message = safe_text(str(exc), self.secret)[:180] if isinstance(exc, BridgeError) else "Review stopped: " + type(exc).__name__
        s["error"] = message
        self.save(s)
        self.q.review_update(s["page_id"], {"Review Status": select("ERROR"), "Review Error": rich(message)})

    def tick(self):
        self.guard()
        if (self.state / "HARDWARE_GATE.json").exists() or (HERE / "ORCHESTRATOR_STOP").exists():
            return 0
        s = parse_json(self.active_path.read_bytes()) if self.active_path.exists() else None
        if not s or s["phase"] == "processed":
            pending = self.q.pending()
            if not pending:
                return 0
            page = self.q.page(pending[0]["id"])
            if prop(page, "Status", "select") != "COMPLETED" or prop(page, "Review Status", "select") != "PENDING":
                return 0
            name, commit, _ = validate_source(page, self.repo)
            sources = self.q.by_job(name)
            require(len(sources) == 1 and identifier(sources[0]["id"]) == identifier(page["id"]),
                    "Duplicate source Job IDs; manual reconciliation required")
            key = identifier(page["id"]) + "_" + commit
            directory = self.state / "transactions" / key
            require(not directory.exists(), "Result already attempted; refusing repeated Codex review")
            directory.mkdir(parents=True)
            s = dict(page_id=identifier(page["id"]), job_id=name, commit=commit, key=key, phase="claiming", invoked=False)
            self.save(s)  # Write-ahead, before the Notion claim.
        directory = self.state / "transactions" / s["key"]
        # A terminated previous invocation must not leave its auth copy behind.
        (directory / "codex_home/auth.json").unlink(missing_ok=True)
        try:
            page = self.q.page(s["page_id"])
            name, commit, _ = validate_source(page, self.repo)
            require((name, commit) == (s["job_id"], s["commit"]), "Claimed result changed")
            if s["phase"] == "claiming":
                status = prop(page, "Review Status", "select")
                require(status in ("PENDING", "CLAIMED"), "Review claim conflict")
                if status == "PENDING":
                    self.q.review_update(s["page_id"], {"Review Status": select("CLAIMED"), "Review Error": rich("")})
                require(prop(self.q.page(s["page_id"]), "Review Status", "select") == "CLAIMED", "Review claim not confirmed")
                s["phase"] = "claimed"
                self.save(s)
            if s["phase"] == "claimed":
                require(not s["invoked"], "Review was already invoked")
                bundle = self.evidence(page)
                s["phase"], s["invoked"] = "invoking", True
                self.save(s)  # Never repeat an ambiguous/non-zero/timed-out Codex call.
                payload = validate_output(self.reviewer(bundle, directory, self.secret), name, self.repo, self.secret)
                dump(directory / "validated.json", payload)
                self.materialize(self.state / "review" / s["key"], payload)
                s["phase"] = "validated"
                self.save(s)
            require(s["phase"] in ("validated", "publishing", "creating", "created"),
                    "Incomplete Codex invocation; automatic retry forbidden")
            payload = parse_json((directory / "validated.json").read_bytes())
            # Revalidate on every recovery, even when files were edited locally.
            # Existing artifacts are legitimate once our next job was published.
            if s["phase"] not in ("creating", "created"):
                validate_output(payload, name, self.repo, self.secret)
            else:
                no_secret(json.dumps(payload), self.secret)
                require(hashlib.sha256((directory / "validated.json").read_bytes()).hexdigest() == s["payload_sha256"],
                        "Published transaction payload changed")
            self.publish(s, payload)
            return 0
        except (BridgeError, OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as exc:
            self.fail(s, exc)
            return 1

    def materialize(self, directory, payload):
        directory.mkdir(parents=True, exist_ok=True)
        dump(directory / "review.json", payload["review"])
        (directory / "notion_update.md").write_text(payload["notion_update"], encoding="utf-8")
        if payload["next_job"]:
            dump(directory / "next_job.json", payload["next_job"])
            (directory / "next_script.py").write_bytes(payload["next_script"].encode())

    def publish(self, s, payload):
        self.guard()
        review = payload["review"]
        require(review["result"] != "error", "Codex requested manual review")
        page = self.q.page(s["page_id"])
        require(prop(page, "Result Commit") == s["commit"] and
                prop(page, "Review Status", "select") in ("CLAIMED", "ERROR", "PROCESSED"), "Review ownership changed")
        next_id = review["next_job_id"]
        require(prop(page, "Next Job ID") in ("", next_id), "Existing successor differs")
        matches = self.q.by_job(next_id) if next_id else []
        require(len(matches) <= 1, "Duplicate successor IDs")
        if matches:
            require(s["phase"] in ("creating", "created"), "Successor already exists; no duplicate created")
            self.q.verify_next(matches[0], payload["next_job"], s["page_id"])
        active = self.q.active()
        require(all(prop(p, "Job ID") == next_id for p in active), "Another offline job is already active")
        if s["phase"] not in ("creating", "created"):
            s["phase"] = "publishing"
            self.save(s)
            body = MARKER + "\nJob: " + s["job_id"] + "\nResult commit: " + s["commit"] + "\n" + payload["notion_update"]
            body += "\n" + (HARDWARE if review["result"] == "hardware_gate" else "Next offline job: " + next_id)
            for doc in DOCUMENTS:
                self.q.publish_document(doc, body, s, lambda: self.save(s))
            s["payload_sha256"] = hashlib.sha256((self.state / "transactions" / s["key"] / "validated.json").read_bytes()).hexdigest()
            if next_id:
                s["phase"] = "creating"
                self.save(s)
                # Recheck immediately before the one non-idempotent creation request.
                require(not self.q.by_job(next_id) and not self.q.active(), "Queue changed before successor creation")
                created = self.q.create_next(payload["next_job"], payload["next_script"], s["page_id"])
                matches = [created]
            s["phase"] = "created"
            self.save(s)
        elif next_id and not matches:
            raise BridgeError("Ambiguous successor creation; manual reconciliation required, no second POST")
        if next_id:
            # The worker may already have claimed/completed the successor; never reset it.
            require(len(matches) == 1, "Successor not visible")
            self.q.verify_next(self.q.page(matches[0]["id"]), payload["next_job"], s["page_id"])
        else:
            # Keep the active transaction until PROCESSED is acknowledged.
            s["hardware_gate"] = True
        self.q.review_update(s["page_id"], {"Next Job ID": rich(next_id or ""), "Reviewed At": {"date": {"start": utc()}},
            "Review Status": select("PROCESSED"), "Review Error": rich("")})
        if s.get("hardware_gate"):
            dump(self.state / "HARDWARE_GATE.json", {"job_id": s["job_id"], "message": HARDWARE, "at": utc()})
        s["phase"], s["error"] = "processed", ""
        self.save(s)


def preflight(client, git):
    git.branch()
    require(git.clean(), "Working tree must be clean")
    require(client.queue_id == QUEUE, "Noncanonical queue")
    client.check_schema(client.resolve())
    for page in DOCUMENTS:
        value = client.request("GET", "pages/" + page)
        require(not value.get("archived") and not value.get("in_trash"), "Canonical document unavailable")
    ReviewQueue(client).current_state()
    codex_binary()
    auth = Path(os.environ.get("CODEX_HOME", str(Path.home() / ".codex"))) / "auth.json"
    require(auth.is_file(), "Codex login required")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--status", action="store_true")
    args = parser.parse_args()
    state = HERE / "state"
    try:
        with local_lock(state / "orchestrator.lock") as acquired:
            if not acquired:
                return 0
            secret = environment("F2_NOTION_TOKEN")
            client = NotionQueue(secret, QUEUE)
            git = Git(ROOT, secret)
            if args.check:
                preflight(client, git)
                print("Orchestrator preflight: PASS")
                return 0
            if args.status:
                git.branch()
                require(git.clean(), "Working tree must be clean")
                local = state / "orchestrator.json"
                s = parse_json(local.read_bytes()) if local.exists() else {}
                print(json.dumps({"phase": s.get("phase", "idle"), "job_id": s.get("job_id"),
                    "error": s.get("error", ""), "hardware_gate": (state / "HARDWARE_GATE.json").exists(),
                    "pending_review": len(ReviewQueue(client).pending())}))
                return 0
            return Orchestrator(ReviewQueue(client), git, secret=secret).tick()
    except (BridgeError, OSError, ValueError, KeyError, subprocess.SubprocessError) as exc:
        detail = safe_text(str(exc), environment("F2_NOTION_TOKEN"))[:180] if isinstance(exc, BridgeError) else type(exc).__name__
        print("Orchestrator stopped: " + detail, file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
