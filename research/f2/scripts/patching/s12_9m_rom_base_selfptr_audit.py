#!/usr/bin/env python3

from pathlib import Path
import hashlib
import struct
from collections import defaultdict


ROOT = Path(r"C:\Users\verto\F2-Altice-MobiWire")
MTK  = Path(r"C:\Users\verto\mtkclient")

PKG = (
    MTK
    / "research" / "f2"
    / "data"
    / "firmware-packages"
    / "altice-service"
    / "altice_service_package"
)

OUT = (
    ROOT
    / "research" / "f2"
    / "work"
    / "repro"
)

REPORT = (
    OUT
    / "s12_9m_rom_base_selfptr_audit.txt"
)

ROM_SHA = (
    "dbebc45c8e4334e61fd85bdab8988d4"
    "f271599263ce209520e36f571f3f4e37c"
)

PATCH_START = 0x3DB80
PATCH_END   = 0x3DC28

# Sweep the whole plausible F03x window,
# not only the four bases previously guessed.
BASES = list(
    range(
        0xF0300000,
        0xF0400000,
        0x10000,
    )
)


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def u32(data, off):
    return struct.unpack_from(
        "<I",
        data,
        off,
    )[0]


def inside_image(value, base, size):
    return (
        base
        <= value
        < base + size
    )


def pointer_target(value, base, size):
    # Direct aligned pointer.
    if inside_image(
        value,
        base,
        size,
    ):
        return (
            value,
            False,
        )

    # Thumb function pointer.
    if (
        value & 1
        and inside_image(
            value & ~1,
            base,
            size,
        )
    ):
        return (
            value & ~1,
            True,
        )

    return None


def scan_base(data, base):
    direct = []
    thumb = []
    header = []
    outside_patch = []

    for off in range(
        0,
        len(data) - 3,
        4,
    ):
        value = u32(
            data,
            off,
        )

        result = pointer_target(
            value,
            base,
            len(data),
        )

        if result is None:
            continue

        target, is_thumb = result

        item = (
            off,
            value,
            target,
        )

        if is_thumb:
            thumb.append(item)
        else:
            direct.append(item)

        if off < 0x1000:
            header.append(item)

        if not (
            PATCH_START
            <= off
            < PATCH_END
        ):
            outside_patch.append(
                item
            )

    return {
        "base": base,
        "direct": direct,
        "thumb": thumb,
        "header": header,
        "outside_patch": outside_patch,
    }


def cluster_pointer_words(items):
    # Cluster pointer-containing dwords by source offset.
    positions = sorted(
        x[0]
        for x in items
    )

    if not positions:
        return []

    groups = []
    current = [
        positions[0]
    ]

    for p in positions[1:]:
        if p - current[-1] <= 0x20:
            current.append(p)
        else:
            if len(current) >= 3:
                groups.append(
                    current
                )
            current = [p]

    if len(current) >= 3:
        groups.append(
            current
        )

    return groups


roms = list(
    PKG.rglob("ROM")
)

assert len(roms) == 1

ROM = roms[0]
rom = ROM.read_bytes()

assert sha256(rom) == ROM_SHA


import io
import contextlib

buf = io.StringIO()

with contextlib.redirect_stdout(buf):

    print("=" * 120)
    print("S12.9M - OBJECTIVE ROM RUNTIME-BASE AUDIT")
    print("=" * 120)

    print()
    print("NO DEVICE ACCESS")
    print("NO BROM")
    print("NO WRITE")
    print("NO ERASE")

    print()
    print(
        f"ROM size   : 0x{len(rom):X}"
    )

    print(
        f"ROM SHA256 : {sha256(rom)}"
    )

    print(
        "ROM identity : PASS"
    )


    # ==============================================================
    # A. Self-pointer density sweep
    # ==============================================================

    print()
    print("=" * 120)
    print("A. SELF-POINTER DENSITY BY 64K BASE")
    print("=" * 120)

    results = []

    for base in BASES:

        r = scan_base(
            rom,
            base,
        )

        clusters = cluster_pointer_words(
            r["outside_patch"]
        )

        row = {
            **r,
            "clusters": clusters,
            "total": (
                len(r["direct"])
                + len(r["thumb"])
            ),
        }

        results.append(
            row
        )

        print(
            f"base=0x{base:08X} "
            f"total={row['total']:5d} "
            f"direct={len(r['direct']):5d} "
            f"thumb={len(r['thumb']):5d} "
            f"outside_patch={len(r['outside_patch']):5d} "
            f"header={len(r['header']):4d} "
            f"clusters={len(clusters):4d}"
        )


    # ==============================================================
    # B. Ranking without patch-table contamination
    # ==============================================================

    print()
    print("=" * 120)
    print("B. RANKING - PATCH TABLE EXCLUDED")
    print("=" * 120)

    ranked = sorted(
        results,
        key=lambda r: (
            len(r["outside_patch"]),
            len(r["header"]),
            len(r["clusters"]),
            len(r["thumb"]),
        ),
        reverse=True,
    )

    for rank, r in enumerate(
        ranked[:16],
        1,
    ):

        print(
            f"{rank:2d}. "
            f"0x{r['base']:08X} "
            f"outside={len(r['outside_patch']):5d} "
            f"header={len(r['header']):4d} "
            f"clusters={len(r['clusters']):4d} "
            f"thumb={len(r['thumb']):5d}"
        )


    best = ranked[0]
    second = ranked[1]

    print()
    print(
        f"best   = 0x{best['base']:08X}"
    )

    print(
        f"second = 0x{second['base']:08X}"
    )

    best_count = len(
        best["outside_patch"]
    )

    second_count = len(
        second["outside_patch"]
    )

    ratio = (
        best_count / second_count
        if second_count
        else float("inf")
    )

    print(
        f"outside-patch ratio "
        f"best/second = {ratio:.3f}"
    )


    # ==============================================================
    # C. Detailed self-pointers for top candidates
    # ==============================================================

    print()
    print("=" * 120)
    print("C. TOP-CANDIDATE POINTER SAMPLES")
    print("=" * 120)

    for r in ranked[:4]:

        print()
        print(
            f"### BASE 0x{r['base']:08X}"
        )

        print(
            f"outside-patch pointers = "
            f"{len(r['outside_patch'])}"
        )

        for (
            off,
            raw,
            target,
        ) in r["outside_patch"][:100]:

            kind = (
                "THUMB"
                if raw & 1
                else "DIRECT"
            )

            print(
                f"ROM+0x{off:05X}: "
                f"raw=0x{raw:08X} "
                f"target=0x{target:08X} "
                f"{kind}"
            )


    # ==============================================================
    # D. Literal-pool-like clusters
    # ==============================================================

    print()
    print("=" * 120)
    print("D. POINTER CLUSTERS FOR BEST BASE")
    print("=" * 120)

    for ci, group in enumerate(
        best["clusters"][:50]
    ):

        print()
        print(
            f"cluster {ci}: "
            f"ROM+0x{group[0]:X}"
            f"..0x{group[-1]:X} "
            f"count={len(group)}"
        )

        group_set = set(
            group
        )

        for (
            off,
            raw,
            target,
        ) in best[
            "outside_patch"
        ]:

            if off not in group_set:
                continue

            print(
                f"  +0x{off:05X} "
                f"0x{raw:08X} -> "
                f"0x{target:08X}"
            )


    # ==============================================================
    # E. Explicit base constants in ROM
    # ==============================================================

    print()
    print("=" * 120)
    print("E. EXACT BASE-CONSTANT OCCURRENCES")
    print("=" * 120)

    for base in BASES:

        needle = struct.pack(
            "<I",
            base,
        )

        hits = []

        pos = 0

        while True:
            pos = rom.find(
                needle,
                pos,
            )

            if pos < 0:
                break

            hits.append(pos)
            pos += 1

        if hits:

            print(
                f"0x{base:08X}: "
                f"{len(hits)} hit(s) "
                + ", ".join(
                    f"0x{x:X}"
                    for x in hits[:40]
                )
            )


    # ==============================================================
    # F. Header-only pointer census
    # ==============================================================

    print()
    print("=" * 120)
    print("F. FIRST 0x1000 BYTES POINTER CENSUS")
    print("=" * 120)

    for r in ranked[:8]:

        print()
        print(
            f"base 0x{r['base']:08X}: "
            f"{len(r['header'])} pointer(s)"
        )

        for (
            off,
            raw,
            target,
        ) in r[
            "header"
        ][:80]:

            print(
                f"  ROM+0x{off:04X} "
                f"0x{raw:08X} -> "
                f"0x{target:08X}"
            )


    # ==============================================================
    # G. Compare priority hypotheses directly
    # ==============================================================

    print()
    print("=" * 120)
    print("G. PRIORITY BASE COMPARISON")
    print("=" * 120)

    priority = {
        r["base"]: r
        for r in results
        if r["base"]
        in {
            0xF0370000,
            0xF0380000,
            0xF0390000,
            0xF03A0000,
        }
    }

    for base in (
        0xF0370000,
        0xF0380000,
        0xF0390000,
        0xF03A0000,
    ):

        r = priority[
            base
        ]

        print(
            f"0x{base:08X}: "
            f"outside={len(r['outside_patch'])} "
            f"header={len(r['header'])} "
            f"clusters={len(r['clusters'])} "
            f"thumb={len(r['thumb'])}"
        )


    # ==============================================================
    # H. Conservative classification
    # ==============================================================

    print()
    print("=" * 120)
    print("S12.9M RESULT")
    print("=" * 120)

    print(
        f"BEST SELF-POINTER BASE : "
        f"0x{best['base']:08X}"
    )

    print(
        f"BEST/SECOND RATIO      : "
        f"{ratio:.3f}"
    )

    print()

    if (
        best["base"]
        == 0xF03A0000
        and ratio >= 1.50
        and len(best["header"])
        > len(second["header"])
    ):

        print(
            "STRONGLY SUPPORTED: "
            "ROM runtime base = 0xF03A0000."
        )

    elif (
        best["base"]
        == 0xF03A0000
    ):

        print(
            "F03A0000 ranks first, "
            "but separation is not strong enough "
            "for promotion."
        )

    else:

        print(
            "F03A0000 does not dominate "
            "the objective pointer census."
        )

    print()
    print(
        "PATCH WIDTH 16 BIT       : "
        "STRONGLY SUPPORTED"
    )

    print(
        "ROM-PATCH CONSUMER       : UNKNOWN"
    )

    print(
        "D5/D6 SERVICE HANDLERS   : UNKNOWN"
    )

    print(
        "ERASE-BEFORE-PROGRAM      : UNKNOWN"
    )

    print()
    print(
        "FLASH AUTHORIZED: NO"
    )


result = buf.getvalue()

print(
    result,
    end="",
)

REPORT.write_text(
    result,
    encoding="utf-8",
)

print()
print(
    "Report:",
    REPORT,
)
