#!/usr/bin/env python3

from pathlib import Path
import hashlib
import re
import struct


ROOT = Path(r"C:\Users\verto\F2-Altice-MobiWire")
MTK  = Path(r"C:\Users\verto\mtkclient")

DONOR = (
    MTK
    / "research" / "f2"
    / "work" / "donor_repos"
    / "MT2503-2"
)

PKG = (
    MTK
    / "research" / "f2"
    / "data" / "firmware-packages"
    / "altice-service"
    / "altice_service_package"
)

OUT = (
    ROOT
    / "research" / "f2"
    / "work" / "repro"
)

REPORT = (
    OUT
    / "s12_9o_romsa_asset_census.txt"
)


NAME_RX = re.compile(
    r"("
    r"rompatch|"
    r"romsa|"
    r"rom_patch|"
    r"rom.patch|"
    r"patch_release"
    r")",
    re.I,
)

TEXT_EXTS = {
    ".c", ".h", ".cpp",
    ".s", ".asm", ".inc",
    ".mak", ".mk", ".pl",
    ".txt", ".sym", ".map",
    ".lis", ".def", ".cfg",
    ".ini", ".ld", ".scat",
}

TEXT_PATTERNS = [
    "ROMSA_Init",
    "InitRegions2",
    "__ROMSA_SUPPORT__",
    "ROMSA_",
    "ROM_PATCH_RELEASE",
    "rompatch.lib",
    "MAUI_IN_ROM",
    "ROM_IMG_FILE",
    "ROM_PATCH_SIZE",
    "PATCH_RELEASE",
]

ADDRS = {
    0xF03A0000: "F03A0000",
    0xF03AC9D0: "patch first target",
    0xF03ACA54: "D3 target",
    0xF03ACA64: "D5 target",
    0xF03ACA6C: "D6 target",
    0xF03AD118: "patch last target",
}


def sha256_file(path):
    h = hashlib.sha256()

    with path.open("rb") as f:
        while True:
            b = f.read(1024 * 1024)

            if not b:
                break

            h.update(b)

    return h.hexdigest()


def read_text(path):
    try:
        return path.read_text(
            encoding="utf-8",
            errors="replace",
        )
    except Exception:
        return ""


def find_all(data, needle):
    out = []
    pos = 0

    while True:
        pos = data.find(
            needle,
            pos,
        )

        if pos < 0:
            return out

        out.append(pos)
        pos += 1


def valid_patch_record(data, off):
    if off + 12 > len(data):
        return None

    target, middle, value = struct.unpack_from(
        "<III",
        data,
        off,
    )

    if not (
        0xF0000000
        <= target
        < 0xF1000000
    ):
        return None

    if middle != 0:
        return None

    if value > 0xFFFF:
        return None

    return (
        target,
        value,
    )


def patch_runs(data):
    runs = []

    off = 0

    while off + 12 <= len(data):

        if valid_patch_record(
            data,
            off,
        ) is None:
            off += 4
            continue

        start = off
        records = []

        while True:

            rec = valid_patch_record(
                data,
                off,
            )

            if rec is None:
                break

            records.append(
                (
                    off,
                    rec[0],
                    rec[1],
                )
            )

            off += 0x0C

        if len(records) >= 3:

            runs.append(
                (
                    start,
                    off,
                    records,
                )
            )

        else:

            off = start + 4

    return runs


print("=" * 120)
print("S12.9O - ROMSA / ROMPATCH DONOR ASSET CENSUS")
print("=" * 120)

print()
print("NO DEVICE ACCESS")
print("NO BROM")
print("NO WRITE")
print("NO ERASE")

print()
print("DONOR:", DONOR)

if not DONOR.is_dir():
    raise RuntimeError(
        f"Donor missing: {DONOR}"
    )


# =================================================================
# A. Filename census
# =================================================================

print()
print("=" * 120)
print("A. ROMSA / ROMPATCH FILENAMES")
print("=" * 120)

named = []

for p in DONOR.rglob("*"):

    if not p.is_file():
        continue

    rel = str(
        p.relative_to(DONOR)
    )

    if NAME_RX.search(rel):

        named.append(p)

named.sort(
    key=lambda p: str(p).lower()
)

print(
    f"matching files = {len(named)}"
)

for p in named:

    size = p.stat().st_size

    print(
        f"{p.relative_to(DONOR)} "
        f"size=0x{size:X}"
    )


# =================================================================
# B. Important exact asset types
# =================================================================

print()
print("=" * 120)
print("B. HIGH-VALUE ASSETS")
print("=" * 120)

high = []

for p in DONOR.rglob("*"):

    if not p.is_file():
        continue

    low = p.name.lower()
    rel_low = str(
        p.relative_to(DONOR)
    ).lower()

    interesting = (
        "romsa" in low
        or "rompatch" in low
        or "rom_patch" in low
        or "patch_release" in low
        or (
            p.suffix.lower()
            in {
                ".sym",
                ".map",
                ".lis",
                ".lib",
                ".a",
            }
            and (
                "rom" in rel_low
                or "patch" in rel_low
            )
        )
    )

    if interesting:
        high.append(p)

high = sorted(
    set(high),
    key=lambda p: str(p).lower(),
)

for p in high:

    size = p.stat().st_size

    digest = (
        sha256_file(p)
        if size <= 64 * 1024 * 1024
        else "SKIPPED"
    )

    print()
    print(
        f"path   : {p.relative_to(DONOR)}"
    )

    print(
        f"size   : 0x{size:X}"
    )

    print(
        f"sha256 : {digest}"
    )


# =================================================================
# C. Text symbol/source search
# =================================================================

print()
print("=" * 120)
print("C. ROMSA / ROMPATCH SYMBOL AND BUILD REFERENCES")
print("=" * 120)

text_hits = 0

for p in DONOR.rglob("*"):

    if not p.is_file():
        continue

    if p.suffix.lower() not in TEXT_EXTS:
        continue

    if p.stat().st_size > 16 * 1024 * 1024:
        continue

    txt = read_text(p)

    if not txt:
        continue

    ll = txt.splitlines()

    for idx, line in enumerate(ll):

        if not any(
            pat.lower()
            in line.lower()
            for pat in TEXT_PATTERNS
        ):
            continue

        text_hits += 1

        print()
        print(
            f"{p.relative_to(DONOR)}:"
            f"{idx+1}"
        )

        lo = max(
            0,
            idx - 4,
        )

        hi = min(
            len(ll),
            idx + 5,
        )

        for n in range(
            lo,
            hi,
        ):

            print(
                f"  {n+1:6d}: "
                f"{ll[n]}"
            )

print()
print(
    f"text hits = {text_hits}"
)


# =================================================================
# D. MT6261-specific ROMSA candidates
# =================================================================

print()
print("=" * 120)
print("D. MT6261-SPECIFIC ROMSA / ROMPATCH PATHS")
print("=" * 120)

mt6261_candidates = []

for p in DONOR.rglob("*"):

    if not p.is_file():
        continue

    rel = str(
        p.relative_to(DONOR)
    )

    low = rel.lower()

    if (
        "6261" in low
        and (
            "rom" in low
            or "patch" in low
            or "sym" in low
        )
    ):

        mt6261_candidates.append(
            p
        )

for p in sorted(
    mt6261_candidates,
    key=lambda p: str(p).lower(),
):

    print(
        f"{p.relative_to(DONOR)} "
        f"size=0x{p.stat().st_size:X}"
    )

print()
print(
    "MT6261 candidate count =",
    len(mt6261_candidates),
)


# =================================================================
# E. Exact target-address search in donor assets
# =================================================================

print()
print("=" * 120)
print("E. F03A PATCH TARGET SEARCH IN HIGH-VALUE ASSETS")
print("=" * 120)

for p in high:

    size = p.stat().st_size

    if size == 0 or size > 64 * 1024 * 1024:
        continue

    try:
        data = p.read_bytes()
    except Exception:
        continue

    found_any = False

    results = []

    for value, label in ADDRS.items():

        needle = struct.pack(
            "<I",
            value,
        )

        hits = find_all(
            data,
            needle,
        )

        if hits:

            found_any = True

            results.append(
                (
                    value,
                    label,
                    hits,
                )
            )

    if not found_any:
        continue

    print()
    print(
        f"### {p.relative_to(DONOR)}"
    )

    for value, label, hits in results:

        print(
            f"0x{value:08X} "
            f"{label:<24} "
            f"count={len(hits)} "
            f"{[hex(x) for x in hits[:30]]}"
        )


# =================================================================
# F. Detect compatible patch tables in donor binary assets
# =================================================================

print()
print("=" * 120)
print("F. DONOR <TARGET,0,VALUE16> TABLE SEARCH")
print("=" * 120)

table_assets = []

for p in high:

    size = p.stat().st_size

    if size < 36 or size > 64 * 1024 * 1024:
        continue

    # Skip obvious text files here.
    if p.suffix.lower() in TEXT_EXTS:
        continue

    try:
        data = p.read_bytes()
    except Exception:
        continue

    runs = patch_runs(
        data
    )

    if not runs:
        continue

    table_assets.append(
        (
            p,
            runs,
        )
    )

    print()
    print(
        f"### {p.relative_to(DONOR)}"
    )

    for i, (
        start,
        end,
        records,
    ) in enumerate(runs):

        targets = [
            x[1]
            for x in records
        ]

        values = [
            x[2]
            for x in records
        ]

        print(
            f"run {i}: "
            f"0x{start:X}..0x{end-1:X} "
            f"records={len(records)} "
            f"targets="
            f"0x{min(targets):08X}"
            f"..0x{max(targets):08X} "
            f"values="
            f"0x{min(values):04X}"
            f"..0x{max(values):04X}"
        )


# =================================================================
# G. Inspect SAV ROM for ROMSA markers
# =================================================================

print()
print("=" * 120)
print("G. EXACT ALTICE SAV ROM MARKERS")
print("=" * 120)

roms = list(
    PKG.rglob("ROM")
)

assert len(roms) == 1

sav_rom = roms[0].read_bytes()

for marker in (
    b"ROMSA",
    b"romsa",
    b"ROM_PATCH",
    b"rompatch",
    b"PATCH_RELEASE",
):

    hits = find_all(
        sav_rom,
        marker,
    )

    print(
        f"{marker!r}: "
        f"{len(hits)} "
        f"{[hex(x) for x in hits[:30]]}"
    )

print()
print(
    "SAV ROM patch-table runs:"
)

for i, (
    start,
    end,
    records,
) in enumerate(
    patch_runs(
        sav_rom
    )
):

    print(
        f"run {i}: "
        f"0x{start:X}..0x{end-1:X} "
        f"records={len(records)}"
    )


# =================================================================
# H. Classification
# =================================================================

print()
print("=" * 120)
print("S12.9O RESULT")
print("=" * 120)

print(
    f"named ROMSA/rompatch assets : "
    f"{len(named)}"
)

print(
    f"high-value assets           : "
    f"{len(high)}"
)

print(
    f"MT6261-specific candidates  : "
    f"{len(mt6261_candidates)}"
)

print(
    f"donor patch-table assets    : "
    f"{len(table_assets)}"
)

print()

if mt6261_candidates:

    print(
        "MT6261 ROMSA/rompatch material exists locally: YES"
    )

else:

    print(
        "MT6261 ROMSA/rompatch material exists locally: "
        "NOT YET FOUND BY PATH"
    )

if table_assets:

    print(
        "Donor binary uses compatible target/zero/value16 "
        "table format: YES"
    )

else:

    print(
        "Compatible donor binary patch table: "
        "NOT FOUND in selected assets"
    )

print()
print(
    "STRONGLY SUPPORTED: SAV 'ROM' belongs to "
    "MediaTek ROMSA / ROM-patch machinery."
)

print(
    "Do NOT interpret SAV ROM as a simple "
    "linear runtime image without further proof."
)

print(
    "D5/D6 as DA service commands: UNKNOWN"
)

print(
    "ERASE-BEFORE-PROGRAM: UNKNOWN"
)

print(
    "FLASH AUTHORIZED: NO"
)


# PowerShell Tee captures stdout.
# Also create a short marker file.

REPORT.write_text(
    "\n".join([
        "S12.9O ROMSA asset census",
        f"named_assets={len(named)}",
        f"high_value_assets={len(high)}",
        f"mt6261_candidates={len(mt6261_candidates)}",
        f"donor_patch_table_assets={len(table_assets)}",
        "FLASH AUTHORIZED=NO",
        "",
    ]),
    encoding="utf-8",
)

print()
print(
    "Summary report:",
    REPORT,
)
