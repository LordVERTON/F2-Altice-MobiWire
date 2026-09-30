"""Canonical local paths shared by F2 research scripts (firmware stays git-ignored)."""
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]
F2_ROOT = REPO_ROOT / "research" / "f2"
DATA_ROOT = F2_ROOT / "data"
WORK_ROOT = F2_ROOT / "work"
REPORTS_ROOT = WORK_ROOT / "reports"
EXTRACTED_ROOT = WORK_ROOT / "extracted"
ALTICE_ALICE = EXTRACTED_ROOT / "altice_alice"
QMOBILE_ALICE = EXTRACTED_ROOT / "qmobile_alice"
GHIDRA_ROOT = WORK_ROOT / "ghidra"
GHIDRA_REPORTS = GHIDRA_ROOT / "alice_reports"
GHIDRA_SCRIPTS = F2_ROOT / "scripts" / "ghidra"
UNALICE = F2_ROOT / "tools" / "unalice" / "unalice.py"
DUMP_MAIN = DATA_ROOT / "dumps" / "mobiwire_dump_2.bin"
ALTICE_PACKAGE = DATA_ROOT / "firmware-packages" / "altice-service" / "altice_service_package"
