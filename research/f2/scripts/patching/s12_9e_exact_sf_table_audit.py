#!/usr/bin/env python3

from pathlib import Path
import struct


ROOT = Path(r"C:\Users\verto\F2-Altice-MobiWire")
MTK  = Path(r"C:\Users\verto\mtkclient")

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

REPORT = OUT / "s12_9e_exact_sf_table_audit.txt"


JEDEC = (
    (0xC2, 0x25, 0x36),
    (0xEF, 0x40, 0x16),
    (0xC2, 0x20, 0x16),
    (0xEF, 0x70, 0x16),
    (0xC8, 0x60, 0x16),
    (0xC2, 0x25, 0x38),
)


INTERESTING_VALUES = {
    0x00000100: "256 B page",
    0x00001000: "4 KiB",
    0x00008000: "32 KiB",
    0x00010000: "64 KiB",
    0x00400000: "4 MiB",
    0x01000000: "16 MiB",
    0x0001F8FC: "SAV word @408/410",
    0x0001F884: "LIVE word @408/410",
}


def hexdump(data, base):
    lines = []

    for i in range(0, len(data), 16):
        chunk = data[i:i+16]

        hx = " ".join(
            f"{x:02X}"
            for x in chunk
        )

        asc = "".join(
            chr(x)
            if 32 <= x <= 126
            else "."
            for x in chunk
        )

        lines.append(
            f"{base+i:08X}  "
            f"{hx:<47}  "
            f"{asc}"
        )

    return lines


def find_all(data, needle):
    out = []
    pos = 0

    while True:
        pos = data.find(
            needle,
            pos,
        )

        if pos < 0:
            break

        out.append(pos)
        pos += 1

    return out


def variants(jid):
    a, b, c = jid

    value24 = (
        (a << 16)
        | (b << 8)
        | c
    )

    return {
        "raw3":
            bytes((a, b, c)),

        "reverse3":
            bytes((c, b, a)),

        "cfg8":
            bytes(
                (a, b, c, 0, 0, 0, 0, 0)
            ),

        "u32_be":
            struct.pack(
                ">I",
                value24,
            ),

        "u32_le":
            struct.pack(
                "<I",
                value24,
            ),
    }


def nearby_values(data, center, radius=0x100):
    start = max(
        0,
        center - radius,
    )

    end = min(
        len(data),
        center + radius,
    )

    results = []

    for off in range(
        start,
        end - 3,
    ):

        le = struct.unpack_from(
            "<I",
            data,
            off,
        )[0]

        be = struct.unpack_from(
            ">I",
            data,
            off,
        )[0]

        if le in INTERESTING_VALUES:

            results.append(
                (
                    off,
                    "LE",
                    le,
                    INTERESTING_VALUES[le],
                )
            )

        if (
            be in INTERESTING_VALUES
            and be != le
        ):

            results.append(
                (
                    off,
                    "BE",
                    be,
                    INTERESTING_VALUES[be],
                )
            )

    # Deduplicate.
    unique = []

    seen = set()

    for x in results:

        if x in seen:
            continue

        seen.add(x)
        unique.append(x)

    return unique


targets = []

for p in PKG.rglob("*"):

    if not p.is_file():
        continue

    name = p.name.upper()

    if (
        name == "EXT_BOOTLOADER"
        or name == "ROM"
        or "BOOTLOADER" in name
        or p.suffix.lower() == ".bin"
    ):
        targets.append(p)


targets = sorted(
    set(targets)
)


lines = []


def log(s=""):
    print(s)
    lines.append(s)


log("=" * 116)
log("S12.9E - EXACT F2 SERIAL FLASH TABLE AUDIT")
log("=" * 116)
log()
log("NO DEVICE ACCESS")
log("NO BROM")
log("NO WRITE")
log("NO ERASE")


log()
log("=" * 116)
log("A. TARGET FILES")
log("=" * 116)

for p in targets:

    log(
        f"{p.relative_to(PKG)} "
        f"size=0x{p.stat().st_size:X}"
    )


log()
log("=" * 116)
log("B. JEDEC RAW SEARCH")
log("=" * 116)


all_hits = {}


for p in targets:

    data = p.read_bytes()

    log()
    log(
        f"### {p.relative_to(PKG)}"
    )

    file_hits = []

    for jid in JEDEC:

        label = "".join(
            f"{x:02X}"
            for x in jid
        )

        log()
        log(
            f"JEDEC {label}"
        )

        total = 0

        for variant_name, needle in variants(
            jid
        ).items():

            hits = find_all(
                data,
                needle,
            )

            total += len(hits)

            log(
                f"  {variant_name:<10}: "
                f"{len(hits)} "
                f"{[hex(x) for x in hits[:20]]}"
            )

            for off in hits[:20]:

                file_hits.append(
                    (
                        jid,
                        variant_name,
                        off,
                    )
                )

        log(
            f"  TOTAL={total}"
        )

    all_hits[p] = file_hits


log()
log("=" * 116)
log("C. CONTEXT AROUND JEDEC HITS")
log("=" * 116)


for p, hits in all_hits.items():

    if not hits:
        continue

    data = p.read_bytes()

    log()
    log(
        f"### {p.relative_to(PKG)}"
    )

    displayed = set()

    for jid, variant_name, off in hits:

        key = (
            off,
            jid,
        )

        if key in displayed:
            continue

        displayed.add(key)

        label = "".join(
            f"{x:02X}"
            for x in jid
        )

        lo = max(
            0,
            off - 0x80,
        )

        hi = min(
            len(data),
            off + 0x100,
        )

        log()
        log(
            f"JEDEC={label} "
            f"variant={variant_name} "
            f"offset=0x{off:X}"
        )

        vals = nearby_values(
            data,
            off,
            radius=0x180,
        )

        if vals:

            log(
                "Nearby known integers:"
            )

            for voff, endian, value, desc in vals:

                log(
                    f"  0x{voff:08X}: "
                    f"{endian} "
                    f"0x{value:08X} "
                    f"({desc})"
                )

        else:

            log(
                "Nearby known integers: NONE"
            )

        for line in hexdump(
            data[lo:hi],
            lo,
        ):

            log(line)


log()
log("=" * 116)
log("D. GLOBAL GEOMETRY CONSTANT SEARCH")
log("=" * 116)


for p in targets:

    data = p.read_bytes()

    log()
    log(
        f"### {p.relative_to(PKG)}"
    )

    for value, desc in INTERESTING_VALUES.items():

        le = struct.pack(
            "<I",
            value,
        )

        be = struct.pack(
            ">I",
            value,
        )

        le_hits = find_all(
            data,
            le,
        )

        be_hits = find_all(
            data,
            be,
        )

        log(
            f"0x{value:08X} "
            f"{desc:<24} "
            f"LE={len(le_hits):4d} "
            f"{[hex(x) for x in le_hits[:12]]} "
            f"BE={len(be_hits):4d} "
            f"{[hex(x) for x in be_hits[:12]]}"
        )


log()
log("=" * 116)
log("E. SAV/LIVE 0x408 WORD SEARCH")
log("=" * 116)


for p in targets:

    data = p.read_bytes()

    log()
    log(
        f"### {p.relative_to(PKG)}"
    )

    for value in (
        0x0001F8FC,
        0x0001F884,
        0x00010472,
    ):

        needle = struct.pack(
            "<I",
            value,
        )

        hits = find_all(
            data,
            needle,
        )

        log(
            f"LE 0x{value:08X}: "
            f"{len(hits)} "
            f"{[hex(x) for x in hits[:50]]}"
        )


log()
log("=" * 116)
log("F. CLUSTER / RECORD-SPACING ANALYSIS")
log("=" * 116)


for p, hits in all_hits.items():

    if not hits:
        continue

    positions = sorted(
        set(
            off
            for _jid, _variant, off
            in hits
        )
    )

    log()
    log(
        f"### {p.relative_to(PKG)}"
    )

    log(
        "JEDEC-related positions: "
        + ", ".join(
            hex(x)
            for x in positions
        )
    )

    if len(positions) >= 2:

        deltas = [
            positions[i+1]
            - positions[i]
            for i in range(
                len(positions)-1
            )
        ]

        log(
            "deltas: "
            + ", ".join(
                hex(x)
                for x in deltas
            )
        )


log()
log("=" * 116)
log("S12.9E CLASSIFICATION")
log("=" * 116)

log(
    "FACT: physical candidate SF parts support 256-byte programming pages."
)

log(
    "STRONGLY SUPPORTED: candidate SF parts support 4 KiB minimum sector erase."
)

log(
    "UNKNOWN: exact JEDEC ID fitted to this handset."
)

log(
    "UNKNOWN: exact BlockLayout selected by the F2 loader."
)

log(
    "UNKNOWN: whether service-loader write performs erase implicitly."
)

log(
    "FLASH AUTHORIZED: NO"
)


REPORT.write_text(
    "\n".join(lines) + "\n",
    encoding="utf-8",
)

print()
print(
    "Report:",
    REPORT,
)
