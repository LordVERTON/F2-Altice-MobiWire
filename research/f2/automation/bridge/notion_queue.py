"""Direct Notion HTTP client and explicit bootstrap commands; no LLM dependency."""
from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import socket
import urllib.error
import urllib.parse
import urllib.request
import uuid

API_VERSION = "2025-09-03"
API_BASE = "https://api.notion.com/v1/"
BRANCH = "automate-research"
QUEUE_TITLE = "F2 Automation Queue"
STATUSES = ("QUEUED", "CLAIMED", "RUNNING", "COMPLETED", "FAILED", "REJECTED")
REVIEW_STATUSES = ("PENDING", "CLAIMED", "PROCESSED", "ERROR")
SAFETY = dict(mode="offline_analysis", phone_access=False, flash_write=False,
              erase=False, repack=False)


class BridgeError(Exception):
    pass


class Rejected(BridgeError):
    pass


class NotionUnavailable(BridgeError):
    pass


def environment(name):
    """Read fresh user values too: Task Scheduler can inherit an old environment."""
    if os.environ.get(name):
        return os.environ[name]
    if os.name == "nt":
        import winreg
        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, "Environment") as key:
                return winreg.QueryValueEx(key, name)[0]
        except FileNotFoundError:
            pass
    return ""


def safe_text(value, secret=""):
    text = str(value)
    if secret:
        text = text.replace(secret, "[REDACTED]")
    text = re.sub(r"https?://\S+", "[URL omitted]", text)
    text = re.sub(r"\b(?:ntn_|secret_)[A-Za-z0-9_-]{16,}", "[REDACTED]", text)
    return text


def identifier(value):
    try:
        return str(uuid.UUID(str(value)))
    except (ValueError, AttributeError):
        raise BridgeError("Invalid Notion UUID") from None


def rich(value):
    return {"rich_text": [{"type": "text", "text": {"content": str(value)[:1900]}}]} if value else {"rich_text": []}


def prop(page, name, kind="rich_text"):
    try:
        value = page["properties"][name][kind]
        if kind in ("rich_text", "title"):
            return "".join(x.get("plain_text", x.get("text", {}).get("content", "")) for x in value)
        if kind == "select":
            return value["name"] if value else ""
        return value
    except (KeyError, TypeError):
        raise Rejected(f"Missing or invalid Notion property: {name}") from None


def properties_schema():
    schema = {"Name": {"title": {}}, "Schema Version": {"number": {}},
              "Status": {"select": {"options": [{"name": s} for s in STATUSES]}},
              "Review Status": {"select": {"options": [{"name": s} for s in REVIEW_STATUSES]}},
              "Safety Mode": {"select": {"options": [{"name": "offline_analysis"}]}},
              "Exit Code": {"number": {}}, "Files": {"files": {}}}
    for name in ("Job ID", "Branch", "Script SHA256", "Report Path", "Result Commit", "Worker Host", "Error", "Claim Token", "Next Job ID", "Review Error"):
        schema[name] = {"rich_text": {}}
    for name in ("Phone Access", "Flash Write", "Erase", "Repack"):
        schema[name] = {"checkbox": {}}
    for name in ("Started At", "Finished At", "Reviewed At"):
        schema[name] = {"date": {}}
    return schema


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise NotionUnavailable("HTTP redirect refused")


class NotionQueue:
    def __init__(self, token, queue_id="", opener=None):
        if not token:
            raise BridgeError("F2_NOTION_TOKEN is not configured")
        self._token = token
        self.queue_id = identifier(queue_id) if queue_id else ""
        self.http = opener or urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())

    def request(self, method, path, payload=None, raw=None, content_type="application/json"):
        # Paths are constructed internally, never supplied by a manifest.
        if not re.fullmatch(r"[A-Za-z0-9_/-]+(?:\?page_size=100(?:&start_cursor=[a-f0-9-]+)?)?", path):
            raise BridgeError("Invalid internal API path")
        body = raw if raw is not None else (json.dumps(payload).encode() if payload is not None else None)
        request = urllib.request.Request(API_BASE + path, data=body, method=method,
            headers={"Authorization": "Bearer " + self._token, "Notion-Version": API_VERSION,
                     "Content-Type": content_type})
        try:
            with self.http.open(request, timeout=30) as response:
                return json.loads(response.read(8 * 1024 * 1024))
        except urllib.error.HTTPError as exc:
            # Never log response bodies, signed URLs, request headers or token-bearing reprs.
            raise NotionUnavailable(f"Notion HTTP {exc.code} ({method} {path.split('?')[0]})") from None
        except (urllib.error.URLError, TimeoutError, OSError, ValueError):
            raise NotionUnavailable("Notion request unavailable or invalid response") from None

    def resolve(self):
        if not self.queue_id:
            raise BridgeError("F2_NOTION_QUEUE_ID or local queue_id is required")
        try:
            source = self.request("GET", "data_sources/" + self.queue_id)
        except NotionUnavailable as exc:
            if "HTTP 404" not in str(exc):
                raise
            database = self.request("GET", "databases/" + self.queue_id)
            sources = database.get("data_sources", [])
            if len(sources) != 1:
                raise BridgeError("Queue database must have exactly one data source; configure its ID explicitly")
            self.queue_id = identifier(sources[0]["id"])
            source = self.request("GET", "data_sources/" + self.queue_id)
        title = "".join(x.get("plain_text", x.get("text", {}).get("content", "")) for x in source.get("title", []))
        if title != QUEUE_TITLE:
            raise BridgeError("Configured data source is not F2 Automation Queue")
        return source

    def check_schema(self, source):
        for name, definition in properties_schema().items():
            kind = next(iter(definition))
            if source.get("properties", {}).get(name, {}).get("type") != kind:
                raise BridgeError(f"Queue schema mismatch: {name}; run configure-schema explicitly")
        options = source["properties"]["Status"]["select"]["options"]
        if not set(STATUSES).issubset({x["name"] for x in options}):
            raise BridgeError("Queue Status options are incomplete")
        options = source["properties"]["Review Status"]["select"]["options"]
        if not set(REVIEW_STATUSES).issubset({x["name"] for x in options}):
            raise BridgeError("Queue Review Status options are incomplete")

    def query(self, job_id=None):
        filters = [{"property": "Status", "select": {"equals": "QUEUED"}},
                   {"property": "Branch", "rich_text": {"equals": BRANCH}},
                   {"property": "Safety Mode", "select": {"equals": "offline_analysis"}}]
        if job_id:
            filters.append({"property": "Job ID", "rich_text": {"equals": job_id}})
        return self.request("POST", f"data_sources/{self.queue_id}/query",
            {"filter": {"and": filters}, "sorts": [{"timestamp": "created_time", "direction": "ascending"}], "page_size": 1}).get("results", [])

    def page(self, page_id):
        page = self.request("GET", "pages/" + identifier(page_id))
        if page.get("parent", {}).get("data_source_id", "").replace("-", "") != self.queue_id.replace("-", ""):
            raise Rejected("Job page is outside the configured queue")
        if page.get("archived") or page.get("in_trash"):
            raise Rejected("Job page is archived")
        return page

    def update(self, page_id, properties):
        allowed = {"Status", "Worker Host", "Claim Token", "Started At", "Finished At",
                   "Error", "Result Commit", "Exit Code"}
        if set(properties) - allowed:
            raise BridgeError("Worker may only update execution properties")
        return self.request("PATCH", "pages/" + identifier(page_id), {"properties": properties})

    def blocks(self, page_id):
        cursor = ""
        for _ in range(10):
            path = f"blocks/{identifier(page_id)}/children?page_size=100"
            if cursor:
                path += "&start_cursor=" + identifier(cursor)
            data = self.request("GET", path)
            yield from data.get("results", [])
            if not data.get("has_more"):
                return
            cursor = data["next_cursor"]
        raise Rejected("Too many blocks in job page")

    def attachments(self, page):
        files = []
        for value in page.get("properties", {}).values():
            if value.get("type") == "files":
                files.extend(value.get("files", []))
        for block in self.blocks(page["id"]):
            if block.get("type") == "file":
                files.append(block["file"])
        selected = {}
        aliases = {
            "job.json": "job.json",
            "script.py": "script.py",
            "script.txt": "script.py",
        }
        for file in files:
            name = file.get("name", "")
            canonical = aliases.get(name)
            if canonical is None:
                continue
            if canonical in selected:
                raise Rejected(f"Duplicate attachment: {canonical}")
            if file.get("type") != "file":
                raise Rejected("Only native Notion uploaded attachments are accepted")
            selected[canonical] = file["file"]["url"]
        if set(selected) != {"job.json", "script.py"}:
            raise Rejected("Missing job.json and script.py/script.txt attachment (Files property or top-level file block)")
        return selected

    def download(self, url, limit):
        parsed = urllib.parse.urlsplit(url)
        host = (parsed.hostname or "").lower()
        allowed = (host == "secure.notion-static.com" or host.endswith(".notion-static.com")
                   or re.fullmatch(r"prod-files-secure\.s3\.[a-z0-9-]+\.amazonaws\.com", host)
                   or host == "s3.us-west-2.amazonaws.com")
        if parsed.scheme != "https" or parsed.port not in (None, 443) or parsed.username or parsed.password or not allowed:
            raise Rejected("Attachment download host/scheme is not approved Notion storage")
        try:
            addresses = socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)
            if not addresses or any(not ipaddress.ip_address(a[4][0]).is_global for a in addresses):
                raise Rejected("Attachment resolved to a non-public address")
            # Deliberately no Authorization header on storage downloads.
            with self.http.open(urllib.request.Request(url), timeout=30) as response:
                data = response.read(limit + 1)
        except (urllib.error.URLError, TimeoutError, OSError):
            raise NotionUnavailable("Attachment download unavailable; no execution") from None
        if len(data) > limit:
            raise Rejected("Attachment exceeds configured size limit")
        if self._token.encode() in data:
            raise Rejected("Attachment contains a credential; content is not archived")
        return data

    def upload(self, name, content):
        if name not in ("job.json", "script.py"):
            raise BridgeError("Unexpected bootstrap filename")
        upload = self.request("POST", "file_uploads", {"mode": "single_part", "filename": name, "content_type": "text/plain"})
        file_id = identifier(upload["id"])
        boundary = "F2Boundary" + uuid.uuid4().hex
        raw = (f'--{boundary}\r\nContent-Disposition: form-data; name="file"; filename="{name}"\r\n'
               'Content-Type: text/plain\r\n\r\n').encode() + content + f"\r\n--{boundary}--\r\n".encode()
        self.request("POST", f"file_uploads/{file_id}/send", raw=raw,
                     content_type="multipart/form-data; boundary=" + boundary)
        return {"name": name, "type": "file_upload", "file_upload": {"id": file_id}}

    def create_test_job(self, rejection=False):
        job_id = "notion_bridge_rejection_v1" if rejection else "notion_bridge_smoke_v1"
        existing = self.request("POST", f"data_sources/{self.queue_id}/query",
            {"filter": {"property": "Job ID", "rich_text": {"equals": job_id}}, "page_size": 2}).get("results", [])
        if existing:
            if len(existing) != 1:
                raise BridgeError("Duplicate test job IDs; resolve manually")
            return existing[0]["id"]
        script = ("import os\nfrom pathlib import Path\n\n"
                  "print('NOTION BRIDGE SMOKE TEST')\nprint('cwd:', Path.cwd())\n"
                  "print('offline:', os.environ.get('F2_AUTOMATION_OFFLINE'))\n"
                  "assert os.environ.get('F2_AUTOMATION_OFFLINE') == '1'\n"
                  "assert Path('research/f2').is_dir()\n"
                  "assert 'F2_NOTION_TOKEN' not in os.environ\n"
                  "print('NOTION BRIDGE SMOKE = PASS')\n").encode()
        safety = {**SAFETY, "flash_write": rejection}
        digest = hashlib.sha256(script).hexdigest()
        report = f"research/f2/work/reports/{job_id}.txt"
        manifest = dict(schema_version=1, job_id=job_id, enabled=True, safety=safety,
                        script_sha256=digest, report=report, args=[])
        files = [self.upload("job.json", (json.dumps(manifest, indent=2) + "\n").encode()), self.upload("script.py", script)]
        properties = {"Name": {"title": [{"text": {"content": job_id}}]},
                      "Job ID": rich(job_id), "Schema Version": {"number": 1},
                      "Status": {"select": {"name": "QUEUED"}}, "Branch": rich(BRANCH),
                      "Script SHA256": rich(digest), "Safety Mode": {"select": {"name": "offline_analysis"}},
                      "Report Path": rich(report), "Files": {"files": files}}
        for label, key in (("Phone Access", "phone_access"), ("Flash Write", "flash_write"), ("Erase", "erase"), ("Repack", "repack")):
            properties[label] = {"checkbox": safety[key]}
        return self.request("POST", "pages", {"parent": {"type": "data_source_id", "data_source_id": self.queue_id},
                                               "properties": properties})["id"]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("create", "configure-schema", "check", "smoke", "rejection"))
    parser.add_argument("--parent-id")
    parser.add_argument("--queue-id", default=environment("F2_NOTION_QUEUE_ID"))
    args = parser.parse_args()
    token = environment("F2_NOTION_TOKEN")
    try:
        queue = NotionQueue(token, args.queue_id)
        if args.command == "create":
            if not args.parent_id:
                raise BridgeError("create requires --parent-id; never searches the workspace")
            result = queue.request("POST", "databases", {"parent": {"type": "page_id", "page_id": identifier(args.parent_id)},
                "title": [{"text": {"content": QUEUE_TITLE}}], "initial_data_source": {"properties": properties_schema()}})
            print("Queue database ID:", result["id"])
            print("Queue data source ID:", result["data_sources"][0]["id"])
        else:
            source = queue.resolve()
            if args.command == "configure-schema":
                # Only add missing fields/options; do not mutate conflicting field types.
                existing = source.get("properties", {})
                additions = {}
                for name, definition in properties_schema().items():
                    if name not in existing:
                        additions[name] = definition
                    elif existing[name]["type"] != next(iter(definition)):
                        raise BridgeError(f"Existing property type conflict: {name}")
                    elif "select" in definition:
                        options = existing[name]["select"]["options"]
                        missing = [x for x in definition["select"]["options"]
                                   if x["name"] not in {o["name"] for o in options}]
                        if missing:
                            additions[name] = {"select": {"options": options + missing}}
                if additions:
                    queue.request("PATCH", "data_sources/" + queue.queue_id, {"properties": additions})
                source = queue.resolve()
            queue.check_schema(source)
            if args.command in ("smoke", "rejection"):
                print("Job page ID:", queue.create_test_job(args.command == "rejection"))
            else:
                print("Queue schema/access: PASS; data source ID:", queue.queue_id)
        return 0
    except BridgeError as exc:
        print(safe_text(exc, token))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
