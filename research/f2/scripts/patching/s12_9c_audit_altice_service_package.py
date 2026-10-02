#!/usr/bin/env python3

from pathlib import Path
import hashlib
import re
from collections import Counter

ROOT = Path(r"C:\Users\verto\F2-Altice-MobiWire")
MTK  = Path(r"C:\Users\verto\mtkclient")

PKG = (
    MTK
    / "research"
    / "f2"
    / "data"
    / "firmware-packages"
    / "altice-service"
    / "altice_service_package"
)

OUT = (
    ROOT
    / "research"
    / "f2"
    / "work"
    / "repro"
)

REPORT = OUT / "s12_9c_altice_service_package_audit.txt"

CANON = (
    MTK
    / "research"
    / "f2"
    / "data"
    / "dumps"
    / "mobiwire_dump_2.bin"
)

LIVE = OUT / "s12_8_serial_readback_A.bin"

CAND = (
    OUT
    / "s12_8e_live_preserving_candidate_NOT_FOR_FLASH.bin"
)

MAIN_NAME = (
    "DL188_GX1882_NIKITI_PCB01_gsm_MT6261_S00."
    "ALTICE_F2_DS_V02_1_181023_MP.bin"
)

BOOT_NAME_FRAGMENT = "BOOTLOADER_V005"


def sha(b):
    return hashlib.sha256(b).hexdigest()


def diff_stats(a, b):
    assert len(a) == len(b)

    changed = 0
    first = None
    last = None

    for i, (x, y) in enumerate(zip(a, b)):
        if x != y:
            changed += 1
            if first is None:
                first = i
            last = i

    return changed, first, last


def strings(data, minlen=5):
    found = []

    # ASCII
    for m in re.finditer(
        rb"[ -~]{%d,}" % minlen,
        data
    ):
        found.append(
            (
                m.start(),
                m.group().decode(
                    "ascii",
                    errors="replace",
                ),
            )
        )

    # UTF-16LE
    pat = (
        rb"(?:[ -~]\x00){"
        + str(minlen).encode()
        + rb",}"
    )

    for m in re.finditer(pat, data):
        try:
            text = m.group().decode("utf-16le")
        except Exception:
            continue

        found.append(
            (
                m.start(),
                text,
            )
        )

    return sorted(found)


print("=" * 112)
print("S12.9C - ALTICE SERVICE PACKAGE OFFLINE AUDIT")
print("=" * 112)
print()
print("NO DEVICE ACCESS")
print("NO FLASH WRITE")
print("NO ERASE")
print()


assert PKG.is_dir(), PKG

files = sorted(
    p
    for p in PKG.rglob("*")
    if p.is_file()
)


print("1. PACKAGE INVENTORY")
print("-" * 112)

print(
    f"package root : {PKG}"
)

print(
    f"file count   : {len(files)}"
)

exts = Counter(
    p.suffix.lower() or "<none>"
    for p in files
)

for ext, count in sorted(exts.items()):
    print(
        f"{ext:<12} {count}"
    )


lines = []

lines.append(
    "S12.9C - ALTICE SERVICE PACKAGE AUDIT"
)

lines.append("")
lines.append("PACKAGE FILES")
lines.append("-" * 112)


for p in files:

    data = p.read_bytes()

    rel = p.relative_to(PKG)

    lines.append(
        f"{rel} | "
        f"size=0x{len(data):X} | "
        f"sha256={sha(data)}"
    )


main_candidates = [
    p
    for p in files
    if p.name == MAIN_NAME
]

if len(main_candidates) != 1:
    raise RuntimeError(
        f"main image candidates={len(main_candidates)}"
    )

MAIN = main_candidates[0]

boot_candidates = [
    p
    for p in files
    if BOOT_NAME_FRAGMENT
    in p.name.upper()
]

if not boot_candidates:
    raise RuntimeError(
        "bootloader not found"
    )


main = MAIN.read_bytes()

canon = CANON.read_bytes()
live = LIVE.read_bytes()
cand = CAND.read_bytes()


print()
print("2. SERVICE MAIN IMAGE")
print("-" * 112)

print(
    f"path   : {MAIN}"
)

print(
    f"size   : 0x{len(main):X}"
)

print(
    f"sha256 : {sha(main)}"
)

assert len(main) == 0x300000


comparisons = (
    (
        "canonical[0:0x300000]",
        canon[:0x300000],
    ),
    (
        "live[0:0x300000]",
        live[:0x300000],
    ),
    (
        "candidate[0:0x300000]",
        cand[:0x300000],
    ),
)


print()
print("DIRECT MAPPING TEST")
print("-" * 112)

for name, ref in comparisons:

    changed, first, last = diff_stats(
        main,
        ref,
    )

    print(
        f"{name:<28} "
        f"equal={'YES' if main == ref else 'NO'} "
        f"changed={changed} "
        f"first={('NONE' if first is None else hex(first))} "
        f"last={('NONE' if last is None else hex(last))}"
    )


# Search exact full or substantial package prefixes
# inside the 4 MiB dump.
print()
print("3. OFFSET / MAPPING SEARCH")
print("-" * 112)

for sample_size in (
    0x100,
    0x1000,
    0x10000,
):

    sample = main[
        :sample_size
    ]

    hits = []

    pos = canon.find(
        sample
    )

    while pos != -1:
        hits.append(pos)

        pos = canon.find(
            sample,
            pos + 1,
        )

    print(
        f"main prefix 0x{sample_size:X}: "
        f"{[hex(x) for x in hits[:20]]}"
    )


# 64K census to see exactly where SAV differs.
print()
print("4. 64K CENSUS: SAV MAIN vs LIVE")
print("-" * 112)

sector = 0x10000

for base in range(
    0,
    0x300000,
    sector,
):

    end = base + sector

    a = main[
        base:end
    ]

    b = live[
        base:end
    ]

    changed = sum(
        x != y
        for x, y in zip(a, b)
    )

    print(
        f"0x{base:06X}-0x{end-1:06X} "
        f"changed={changed:6d} "
        f"{'SAME' if not changed else 'DIFF'}"
    )


print()
print("5. BOOTLOADER SEARCH")
print("-" * 112)

for boot in boot_candidates:

    data = boot.read_bytes()

    print()
    print(
        f"{boot.relative_to(PKG)}"
    )

    print(
        f"size   = 0x{len(data):X}"
    )

    print(
        f"sha256 = {sha(data)}"
    )

    for target_name, target in (
        ("canonical", canon),
        ("live", live),
        ("main image", main),
    ):

        pos = target.find(data)

        print(
            f"exact occurrence in "
            f"{target_name:<10}: "
            f"{'NONE' if pos < 0 else hex(pos)}"
        )

        # Also search a 256-byte prefix.
        if len(data) >= 0x100:

            pos2 = target.find(
                data[:0x100]
            )

            print(
                f"  prefix[0x100]     : "
                f"{'NONE' if pos2 < 0 else hex(pos2)}"
            )


print()
print("6. CONFIG / TOOL / FLASH KEYWORD SEARCH")
print("-" * 112)

keywords = (
    "NOR",
    "FLASH",
    "ERASE",
    "SECTOR",
    "BLOCK",
    "DOWNLOAD",
    "DA",
    "MT6261",
    "ADDRESS",
    "OFFSET",
    "BOOTLOADER",
    "FORMAT",
    "WRITE",
    "NVDM",
    "FAT",
)

interesting = []


for p in files:

    # Avoid huge firmware images for generic string census.
    if p.stat().st_size > 16 * 1024 * 1024:
        continue

    data = p.read_bytes()

    ss = strings(
        data,
        minlen=5,
    )

    hits = []

    for off, s in ss:

        upper = s.upper()

        if any(
            k in upper
            for k in keywords
        ):
            hits.append(
                (off, s)
            )

    if hits:

        interesting.append(
            (
                p,
                hits,
            )
        )

        print()
        print(
            f"--- {p.relative_to(PKG)} ---"
        )

        for off, s in hits[:200]:

            print(
                f"0x{off:08X}: "
                f"{s[:300]}"
            )


lines.append("")
lines.append("KEYWORD FILES")
lines.append("-" * 112)

for p, hits in interesting:

    lines.append(
        str(
            p.relative_to(PKG)
        )
    )

    for off, s in hits[:100]:

        lines.append(
            f"  0x{off:08X}: "
            f"{s[:300]}"
        )


print()
print("7. TEXT CONFIG CONTENT")
print("-" * 112)

text_exts = {
    ".txt",
    ".ini",
    ".cfg",
    ".xml",
    ".log",
    ".json",
    ".csv",
    ".bat",
    ".cmd",
}

for p in files:

    if p.suffix.lower() not in text_exts:
        continue

    if p.stat().st_size > 2 * 1024 * 1024:
        continue

    try:
        txt = p.read_text(
            encoding="utf-8",
            errors="replace",
        )
    except Exception:
        continue

    print()
    print(
        "=" * 80
    )

    print(
        p.relative_to(PKG)
    )

    print(
        "=" * 80
    )

    print(
        txt[:20000]
    )


print()
print("8. FINAL CLASSIFICATION")
print("-" * 112)

same_canon = (
    main
    == canon[:0x300000]
)

same_live = (
    main
    == live[:0x300000]
)

print(
    f"SAV main == canonical[0:0x300000] : "
    f"{same_canon}"
)

print(
    f"SAV main == live[0:0x300000]      : "
    f"{same_live}"
)

print()
print(
    "WRITE PATH IN MTKCLIENT          : PRESENT"
)

print(
    "EXPLICIT LEGACY NOR ERASE PATH  : NOT YET PROVEN"
)

print(
    "ACTUAL NOR ERASE GEOMETRY       : UNKNOWN"
)

print(
    "FLASH AUTHORIZED                 : NO"
)


REPORT.write_text(
    "\n".join(lines)
    + "\n",
    encoding="utf-8",
)

print()
print(
    "Report:",
    REPORT,
)
