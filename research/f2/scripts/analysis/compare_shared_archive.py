"""Hash files in a candidate RAR using Windows tar without extracting them."""
from __future__ import annotations

import hashlib
import subprocess
from pathlib import Path, PurePosixPath

archive = Path("research/f2/data/firmware-packages/unverified/dzgsm_share_kxQEAY4K.rar")
root = Path("research/f2/data/firmware-packages/altice-service/altice_service_package")
members = subprocess.check_output(["tar", "-tf", str(archive)], text=True).splitlines()
for member in members:
    if member.endswith("/") or member == "DL188_GX1882_NIKITI_PCB01_gsm_MT6261_S00":
        continue
    data = subprocess.check_output(["tar", "-xOf", str(archive), member])
    local_path = root.joinpath(*PurePosixPath(member).parts)
    local = local_path.read_bytes() if local_path.is_file() else None
    print(
        f"{member}\n  bytes={len(data)} sha256={hashlib.sha256(data).hexdigest()} "
        f"local_match={local is not None and local == data}"
    )
