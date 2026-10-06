#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""F2 automation local-inbox smoke test. Strictly offline."""

from pathlib import Path
import os
import sys

repo = Path.cwd()
print("=" * 100)
print("F2 AUTOMATION LOCAL-INBOX SMOKE TEST")
print("=" * 100)
print("PHONE ACCESSED : NO")
print("FLASH MODIFIED : NO")
print("PATCH GENERATED: NO")
print(f"cwd             : {repo}")
print(f"python          : {sys.executable}")
print(f"offline env     : {os.environ.get('F2_AUTOMATION_OFFLINE')}")
print()

checks = {
    "research/f2 exists": (repo / "research" / "f2").is_dir(),
    "reports dir exists": (repo / "research" / "f2" / "work" / "reports").is_dir(),
    "offline env == 1": os.environ.get("F2_AUTOMATION_OFFLINE") == "1",
}
for name, ok in checks.items():
    print(f"{name:30s}: {'PASS' if ok else 'FAIL'}")

ok = all(checks.values())
print()
print(f"SMOKE TEST = {'PASS' if ok else 'FAIL'}")
raise SystemExit(0 if ok else 2)
