"""Minimal offline repo-queue smoke. No device access or research audit."""
from pathlib import Path
import os

ok = (
    os.environ.get("F2_AUTOMATION_OFFLINE") == "1"
    and Path.cwd().resolve() == Path(r"C:\Users\verto\F2-Altice-MobiWire").resolve()
)
print(f"F2_AUTOMATION_OFFLINE={os.environ.get('F2_AUTOMATION_OFFLINE')}")
print(f"cwd: {Path.cwd()}")
print(f"REPO QUEUE SMOKE = {'PASS' if ok else 'FAIL'}")
raise SystemExit(0 if ok else 2)
