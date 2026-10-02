#!/usr/bin/env python3

from pathlib import Path
import hashlib
import re

ROOT = Path(r"C:\Users\verto\F2-Altice-MobiWire")
MTK  = Path(r"C:\Users\verto\mtkclient")

OUT = (
    ROOT
    / "research" / "f2"
    / "work" / "repro"
)

PKG = (
    MTK
    / "research" / "f2"
    / "data" / "firmware-packages"
    / "altice-service"
    / "altice_service_package"
)

DONOR = (
    MTK
    / "research" / "f2"
    / "work" / "donor_repos"
    / "MT2503-2"
)

CANON = (
    MTK
    / "research" / "f2"
    / "data" / "dumps"
    / "mobiwire_dump_2.bin"
)

LIVE = (
    OUT
    / "s12_8_serial_readback_A.bin"
)

REPORT = (
    OUT
    / "s12_9d_sf_geometry_audit.txt"
)

MAIN_NAME = (
    "DL188_GX1882_NIKITI_PCB01_gsm_MT6261_S00."
    "ALTICE_F2_DS_V02_1_181023_MP.bin"
)

CFG_NAME = "ALTICE_F2_DS_V02.1_181023_MP.cfg"


def log(lines, s=""):
    print(s)
    lines.append(s)


def hexdump(data, base=0):
    out = []

    for i in range(0, len(data), 16):
        row = data[i:i+16]

        hs = " ".join(
            f"{x:02X}"
            for x in row
        )

        asc = "".join(
            chr(x)
            if 32 <= x < 127
            else "."
            for x in row
        )

        out.append(
            f"{base+i:08X}  "
            f"{hs:<47}  "
            f"{asc}"
        )

    return out


def readable_text(path):
    try:
        return path.read_text(
            encoding="utf-8",
            errors="replace",
        )
    except Exception:
        return ""


def context(lines, idx, radius=5):
    lo = max(0, idx-radius)
    hi = min(len(lines), idx+radius+1)

    return [
        (n+1, lines[n])
        for n in range(lo, hi)
    ]


lines_out = []

log(lines_out, "=" * 118)
log(lines_out, "S12.9D - MT6261 SERIAL FLASH GEOMETRY / WRITE-PATH AUDIT")
log(lines_out, "=" * 118)

log(lines_out)
log(lines_out, "NO DEVICE ACCESS")
log(lines_out, "NO BROM SESSION")
log(lines_out, "NO FLASH WRITE")
log(lines_out, "NO ERASE")


# --------------------------------------------------------------------
# Inputs
# --------------------------------------------------------------------

main_hits = list(
    PKG.rglob(MAIN_NAME)
)

cfg_hits = list(
    PKG.rglob(CFG_NAME)
)

if len(main_hits) != 1:
    raise RuntimeError(
        f"main image count={len(main_hits)}"
    )

if len(cfg_hits) != 1:
    raise RuntimeError(
        f"cfg count={len(cfg_hits)}"
    )

MAIN = main_hits[0]
CFG = cfg_hits[0]

sav = MAIN.read_bytes()
live = LIVE.read_bytes()
canon = CANON.read_bytes()

assert len(sav) == 0x300000
assert len(live) == 0x400000
assert len(canon) == 0x400000


# --------------------------------------------------------------------
# A. Exact static differences
# --------------------------------------------------------------------

log(lines_out)
log(lines_out, "=" * 118)
log(lines_out, "A. SAV vs LIVE STATIC DIFFERENCES < 0x2C0000")
log(lines_out, "=" * 118)

diffs = []

for i in range(0x2C0000):

    if sav[i] != live[i]:

        diffs.append(
            (
                i,
                sav[i],
                live[i],
            )
        )

log(
    lines_out,
    f"changed byte count = {len(diffs)}"
)

for off, a, b in diffs:

    log(
        lines_out,
        f"D+0x{off:06X}: "
        f"SAV={a:02X} "
        f"LIVE={b:02X}"
    )


if diffs:

    lo = max(
        0,
        min(x[0] for x in diffs) - 0x40,
    )

    hi = min(
        len(sav),
        max(x[0] for x in diffs) + 0x41,
    )

    log(lines_out)
    log(
        lines_out,
        f"SAV context 0x{lo:X}..0x{hi-1:X}"
    )

    for s in hexdump(
        sav[lo:hi],
        lo,
    ):
        log(lines_out, s)

    log(lines_out)
    log(
        lines_out,
        f"LIVE context 0x{lo:X}..0x{hi-1:X}"
    )

    for s in hexdump(
        live[lo:hi],
        lo,
    ):
        log(lines_out, s)


# --------------------------------------------------------------------
# B. Parse exact JEDEC IDs from SAV config
# --------------------------------------------------------------------

cfg_text = readable_text(CFG)

jedec = []

rx = re.compile(
    r"flash_id:\s*\[\s*"
    r"(0x[0-9A-Fa-f]+)\s*,\s*"
    r"(0x[0-9A-Fa-f]+)\s*,\s*"
    r"(0x[0-9A-Fa-f]+)",
)

for m in rx.finditer(cfg_text):

    t = tuple(
        int(x, 16)
        for x in m.groups()
    )

    if t not in jedec:
        jedec.append(t)


log(lines_out)
log(lines_out, "=" * 118)
log(lines_out, "B. SERIAL FLASH JEDEC IDS FROM ALTICE CFG")
log(lines_out, "=" * 118)

for x in jedec:

    log(
        lines_out,
        " ".join(
            f"{v:02X}"
            for v in x
        )
    )

if len(jedec) != 6:
    log(
        lines_out,
        f"WARNING: expected 6 IDs, got {len(jedec)}"
    )


# --------------------------------------------------------------------
# C. Search donor MT6261 source tree
# --------------------------------------------------------------------

log(lines_out)
log(lines_out, "=" * 118)
log(lines_out, "C. DONOR MT2503 / MT6261 JEDEC-ID SEARCH")
log(lines_out, "=" * 118)


source_exts = {
    ".c", ".h", ".inc", ".txt",
    ".cfg", ".mak", ".mk", ".def",
    ".lis", ".map", ".log",
}

source_files = []

if DONOR.is_dir():

    for p in DONOR.rglob("*"):

        if (
            p.is_file()
            and p.suffix.lower()
            in source_exts
        ):
            source_files.append(p)

else:
    log(
        lines_out,
        f"DONOR MISSING: {DONOR}"
    )


def id_patterns(jid):

    a, b, c = jid

    variants = [
        rf"0x{a:02X}\s*,\s*0x{b:02X}\s*,\s*0x{c:02X}",
        rf"0x{a:02x}\s*,\s*0x{b:02x}\s*,\s*0x{c:02x}",
        rf"{a:02X}\s+{b:02X}\s+{c:02X}",
        rf"{a:02x}\s+{b:02x}\s+{c:02x}",
    ]

    return [
        re.compile(v)
        for v in variants
    ]


for jid in jedec:

    label = "".join(
        f"{x:02X}"
        for x in jid
    )

    log(lines_out)
    log(
        lines_out,
        f"--- JEDEC {label} ---"
    )

    patterns = id_patterns(jid)

    hits = 0

    for p in source_files:

        txt = readable_text(p)

        if not txt:
            continue

        ll = txt.splitlines()

        for idx, line in enumerate(ll):

            if any(
                rx.search(line)
                for rx in patterns
            ):

                hits += 1

                log(
                    lines_out,
                    f"{p.relative_to(DONOR)}:"
                    f"{idx+1}"
                )

                for no, val in context(
                    ll,
                    idx,
                    radius=8,
                ):

                    log(
                        lines_out,
                        f"  {no:6d}: {val}"
                    )

                log(lines_out)

    log(
        lines_out,
        f"hits={hits}"
    )


# --------------------------------------------------------------------
# D. Geometry/macros in known flash source areas
# --------------------------------------------------------------------

log(lines_out)
log(lines_out, "=" * 118)
log(lines_out, "D. SF / NOR GEOMETRY SOURCE CENSUS")
log(lines_out, "=" * 118)

keywords = re.compile(
    r"("
    r"erase|"
    r"sector|"
    r"block|"
    r"page[_ ]?size|"
    r"block[_ ]?size|"
    r"sector[_ ]?size|"
    r"erase[_ ]?size|"
    r"jedec|"
    r"device[_ ]?id|"
    r"flash[_ ]?id|"
    r"SF_WRITE|"
    r"SERIAL_FLASH|"
    r"FLASH_ERASE|"
    r"BUFFER_PROGRAM"
    r")",
    re.I,
)

preferred_names = (
    "combo_flash_nor",
    "flash_mtd_sf",
    "flash_mtd",
    "flash_disk",
    "custom_MemoryDevice",
    "MemoryDevice",
)


for p in source_files:

    ps = str(p).lower()

    if not any(
        x.lower() in ps
        for x in preferred_names
    ):
        continue

    txt = readable_text(p)

    ll = txt.splitlines()

    matched = []

    for idx, line in enumerate(ll):

        if keywords.search(line):
            matched.append(
                (
                    idx + 1,
                    line,
                )
            )

    if not matched:
        continue

    log(lines_out)
    log(
        lines_out,
        f"--- {p.relative_to(DONOR)} ---"
    )

    for no, line in matched[:400]:

        log(
            lines_out,
            f"{no:6d}: {line}"
        )


# --------------------------------------------------------------------
# E. mtkclient SF command references
# --------------------------------------------------------------------

log(lines_out)
log(lines_out, "=" * 118)
log(lines_out, "E. MTKCLIENT SF WRITE / ERASE REFERENCES")
log(lines_out, "=" * 118)

MTKSRC = MTK / "mtkclient"

rx_mtk = re.compile(
    r"("
    r"SF_WRITE_IMAGE|"
    r"NOR_WRITE_DATA|"
    r"NOR_WRITE_PTB|"
    r"FORMAT_CMD|"
    r"writeflash|"
    r"formatflash|"
    r"erase"
    r")",
    re.I,
)

for p in MTKSRC.rglob("*.py"):

    txt = readable_text(p)

    ll = txt.splitlines()

    for idx, line in enumerate(ll):

        if not rx_mtk.search(line):
            continue

        # Focus the output on legacy / iot / flash code.
        ps = str(p).lower()

        if not any(
            x in ps
            for x in (
                "legacy",
                "preloader",
                "storage",
            )
        ):
            continue

        log(
            lines_out,
            f"{p.relative_to(MTK)}:"
            f"{idx+1}: "
            f"{line}"
        )


# --------------------------------------------------------------------
# F. Config semantics
# --------------------------------------------------------------------

log(lines_out)
log(lines_out, "=" * 118)
log(lines_out, "F. ALTICE CFG RELEVANT LINES")
log(lines_out, "=" * 118)

for idx, line in enumerate(
    cfg_text.splitlines(),
    1,
):

    if re.search(
        r"platform|alignment|flash_type|flash_id|memory_type",
        line,
        re.I,
    ):

        log(
            lines_out,
            f"{idx:5d}: {line}"
        )


# --------------------------------------------------------------------
# G. Conservative classification
# --------------------------------------------------------------------

log(lines_out)
log(lines_out, "=" * 118)
log(lines_out, "S12.9D CLASSIFICATION")
log(lines_out, "=" * 118)

if len(diffs) == 2:

    log(
        lines_out,
        "FACT: SAV and live static firmware differ by exactly 2 bytes."
    )
else:

    log(
        lines_out,
        f"OBSERVED: static diff count = {len(diffs)}."
    )

log(
    lines_out,
    "FACT: Altice config identifies the storage family as SF."
)

log(
    lines_out,
    "FACT: Altice config states SF page alignment = 256 bytes."
)

log(
    lines_out,
    "UNKNOWN until source-table match: physical erase sector/block size."
)

log(
    lines_out,
    "UNKNOWN until command-path proof: whether SF write performs implicit erase."
)

log(
    lines_out,
    "FLASH AUTHORIZED: NO"
)


REPORT.write_text(
    "\n".join(lines_out) + "\n",
    encoding="utf-8",
)

print()
print(
    "Report:",
    REPORT,
)
