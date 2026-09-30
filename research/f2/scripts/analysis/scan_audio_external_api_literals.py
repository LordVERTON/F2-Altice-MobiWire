#!/usr/bin/env python3
"""Check exact audio API literals and report (not classify) aligned F0-looking words."""
import re
import struct
from collections import Counter
from pathlib import Path

BASE = Path(__file__).resolve().parents[2]
REPORT = BASE / "work" / "ghidra" / "alice_reports"
api_reports = [REPORT / "media_api_targets.txt", REPORT / "media_backend_calltree.txt"]
targets = sorted({int(x, 16) for p in api_reports for x in re.findall(r"thunk_EXT_FUN_(f0[0-9a-f]{6})", p.read_text(encoding="utf-8", errors="replace"))})
PACKAGE = BASE / "data/firmware-packages/altice-service/altice_service_package/DL188_GX1882_NIKITI_PCB01_gsm_MT6261_S00"
files = {
    "service_ROM": PACKAGE / "ROM",
    "service_VIVA": PACKAGE / "VIVA",
    "ALICE_decompressed": BASE / "work/extracted/altice_alice/alice-py.bin",
}

print("Exact little-endian API address literals; this is not a complete import-table analysis.")
print(f"API targets collected from reports: {len(targets)}")
for name, path in files.items():
    data = path.read_bytes()
    hits = []
    for target in targets:
        for value in {target, target | 1}:
            needle = struct.pack("<I", value)
            pos = 0
            while True:
                pos = data.find(needle, pos)
                if pos < 0:
                    break
                hits.append((pos, target, value))
                pos += 1
    print(f"\n{name}: {len(data)} bytes; exact references={len(hits)}")
    for offset, target, value in sorted(hits)[:120]:
        print(f"  file+0x{offset:08x} -> API 0x{target:08x} (literal 0x{value:08x})")
    if len(hits) > 120:
        print(f"  ... {len(hits)-120} more")
    words = Counter()
    runs = []
    run_start = None
    run_values = []
    for offset in range(0, len(data) - 3, 4):
        value = struct.unpack_from("<I", data, offset)[0]
        if value >> 24 == 0xF0:
            words[value] += 1
            if run_start is None:
                run_start = offset
            run_values.append(value)
        else:
            if len(run_values) >= 3:
                runs.append((run_start, run_values))
            run_start = None
            run_values = []
    if len(run_values) >= 3:
        runs.append((run_start, run_values))
    print(f"Aligned 32-bit F0xxxxxx-looking words (code/data false positives expected): {sum(words.values())}; unique={len(words)}")
    odd = sum(count for value, count in words.items() if value & 1)
    print(f"Thumb-bit odd literals: {odd}; even literals: {sum(words.values())-odd}; consecutive runs >=3: {len(runs)}")
    for offset, values in runs[:30]:
        print(f"  run file+0x{offset:08x} len={len(values)}: " + " ".join(f"{v:08x}" for v in values[:12]))
    for value, count in words.most_common(40):
        print(f"  0x{value:08x}: {count}")
