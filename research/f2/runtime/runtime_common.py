"""Shared helpers for passive observation of short-lived Windows COM ports."""
from __future__ import annotations

import csv
import datetime as dt
import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent
CAPTURES = ROOT / "captures"
REPORTS = ROOT / "reports"
EVENTS_JSONL = ROOT / "transient_com_events.jsonl"
EVENTS_CSV = ROOT / "transient_com_events.csv"
for _directory in (CAPTURES, REPORTS):
    _directory.mkdir(parents=True, exist_ok=True)


def now_iso() -> str:
    return dt.datetime.now().astimezone().isoformat(timespec="milliseconds")


def stamp() -> str:
    return dt.datetime.now().astimezone().strftime("%Y%m%d_%H%M%S_%f")[:-3]


def next_run() -> int:
    path = ROOT / ".run_counter"
    try:
        value = int(path.read_text(encoding="ascii").strip()) + 1
    except (OSError, ValueError):
        value = 1
    path.write_text(str(value), encoding="ascii")
    return value


def port_record(port: Any) -> dict[str, Any]:
    return {
        "device": getattr(port, "device", None),
        "name": getattr(port, "name", None),
        "description": getattr(port, "description", None),
        "hwid": getattr(port, "hwid", None),
        "vid": getattr(port, "vid", None),
        "pid": getattr(port, "pid", None),
        "serial_number": getattr(port, "serial_number", None),
        "manufacturer": getattr(port, "manufacturer", None),
        "product": getattr(port, "product", None),
        "interface": getattr(port, "interface", None),
        "location": getattr(port, "location", None),
    }


def log_event(event: dict[str, Any]) -> None:
    event = {"timestamp": now_iso(), **event}
    with EVENTS_JSONL.open("a", encoding="utf-8") as stream:
        stream.write(json.dumps(event, ensure_ascii=False) + "\n")
    fields = ["timestamp", "run", "event", "device", "vid", "pid", "description", "manufacturer", "product", "hwid", "location", "lifetime_ms", "details"]
    exists = EVENTS_CSV.exists()
    with EVENTS_CSV.open("a", encoding="utf-8-sig", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=fields, extrasaction="ignore")
        if not exists:
            writer.writeheader()
        row = dict(event)
        row["details"] = json.dumps(event.get("details", {}), ensure_ascii=False)
        writer.writerow(row)


def pnp_snapshot_async(com_port: str, callback) -> None:
    """Collect matching Ports-class PnP properties without blocking detection."""
    import threading

    def worker() -> None:
        escaped_port = com_port.replace("'", "''")
        ps = (
            "$ErrorActionPreference='Stop';"
            f"$p='{escaped_port}';"
            "$d=Get-PnpDevice -PresentOnly -Class Ports | Where-Object {$_.FriendlyName -match ('\\('+$p+'\\)')};"
            "$d | ForEach-Object { $x=$_; $r=[ordered]@{InstanceId=$x.InstanceId;FriendlyName=$x.FriendlyName;Class=$x.Class;ClassGuid=$x.ClassGuid;Status=$x.Status};"
            "foreach($k in @('DEVPKEY_Device_HardwareIds','DEVPKEY_Device_CompatibleIds','DEVPKEY_Device_Service','DEVPKEY_Device_DriverProvider','DEVPKEY_Device_DriverVersion','DEVPKEY_Device_LocationInfo')) {"
            "try {$v=(Get-PnpDeviceProperty -InstanceId $x.InstanceId -KeyName $k -ErrorAction Stop).Data; $r[$k]=$v} catch {$r[$k]=$null}};"
            "$r | ConvertTo-Json -Depth 5 -Compress }"
        )
        encoded = __import__("base64").b64encode(ps.encode("utf-16le")).decode("ascii")
        try:
            result = subprocess.run(
                ["powershell.exe", "-NoLogo", "-NoProfile", "-NonInteractive", "-EncodedCommand", encoded],
                capture_output=True, text=True, timeout=4, check=False,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
            output = result.stdout.strip()
            try:
                parsed = json.loads(output) if output else None
            except json.JSONDecodeError:
                parsed = {"raw": output, "stderr": result.stderr.strip(), "returncode": result.returncode}
            callback({"pnp": parsed, "pnp_error": result.stderr.strip() or None})
        except Exception as exc:  # diagnostic collection must never block watcher
            callback({"pnp": None, "pnp_error": repr(exc)})

    threading.Thread(target=worker, daemon=True).start()


def serial_ports():
    try:
        from serial.tools import list_ports
    except ImportError as exc:
        raise RuntimeError("pyserial is required. Install with: py -m pip install pyserial") from exc
    return {p.device: p for p in list_ports.comports()}


def parse_vid_pid(record: dict[str, Any]) -> tuple[str | None, str | None]:
    vid = record.get("vid")
    pid = record.get("pid")
    if vid is None or pid is None:
        match = re.search(r"VID:PID=([0-9A-Fa-f]{4}):([0-9A-Fa-f]{4})", str(record.get("hwid", "")))
        if match:
            vid, pid = int(match.group(1), 16), int(match.group(2), 16)
    return (f"{vid:04X}" if isinstance(vid, int) else None, f"{pid:04X}" if isinstance(pid, int) else None)


def setupapi_excerpt(out_path: Path) -> dict[str, Any]:
    log = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "INF" / "setupapi.dev.log"
    terms = re.compile(r"VID_0E8D|MediaTek|MTK|0E8D", re.I)
    try:
        lines = log.read_text(encoding="utf-8", errors="replace").splitlines()
        hits = [i for i, line in enumerate(lines) if terms.search(line)]
        selected: set[int] = set()
        for i in hits[-80:]:
            selected.update(range(max(0, i - 3), min(len(lines), i + 4)))
        excerpt = "\n".join(f"{i + 1}: {lines[i]}" for i in sorted(selected))
        local = (
            "\n\nLocal mtkclient USB-ID mapping (from mtkclient/config/usb_ids.py):\n"
            "0E8D:0003 = MTK BROM; 0E8D:6000, 2000, 2001, 20FF, 3000 = MTK Preloader.\n"
            "These are repository mappings only; they do not classify the transient COM until its own VID/PID is captured.\n"
            "Port.py also uses the BROM handshake A0 0A 50 05 for USB CDC BROM; the transient COM is not probed with it.\n"
        )
        out_path.write_text(f"Source: {log}\nMatched lines: {len(hits)}\n\n{excerpt}{local}\n", encoding="utf-8")
        return {"path": str(log), "matches": len(hits), "report": str(out_path)}
    except Exception as exc:
        out_path.write_text(f"Could not read {log}: {exc!r}\n", encoding="utf-8")
        return {"path": str(log), "error": repr(exc), "report": str(out_path)}
