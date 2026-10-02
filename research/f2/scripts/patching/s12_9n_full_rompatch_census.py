#!/usr/bin/env python3

from pathlib import Path
from collections import Counter
import hashlib
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

REPORT = (
    OUT
    / "s12_9n_full_rompatch_census.txt"
)

ROM_SHA = (
    "dbebc45c8e4334e61fd85bdab8988d4"
    "f271599263ce209520e36f571f3f4e37c"
)

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


def valid_patch_record(data, off):
    if off < 0 or off + 12 > len(data):
        return None

    target = u32(data, off)
    zero   = u32(data, off + 4)
    value  = u32(data, off + 8)

    # Known ROM-patch target family.
    if not (
        0xF0000000
        <= target
        < 0xF1000000
    ):
        return None

    if zero != 0:
        return None

    # Known patch table values are halfword-sized.
    if value > 0xFFFF:
        return None

    return (
        target,
        zero,
        value,
    )


def detect_patch_runs(data):
    runs = []

    # Tables of interest are all 32-bit aligned.
    off = 0

    while off + 12 <= len(data):

        first = valid_patch_record(
            data,
            off,
        )

        if first is None:
            off += 4
            continue

        records = []
        cur = off

        while True:

            rec = valid_patch_record(
                data,
                cur,
            )

            if rec is None:
                break

            records.append(
                (
                    cur,
                    rec[0],
                    rec[2],
                )
            )

            cur += 0x0C

        # Require at least three consecutive records
        # to avoid accidental matches.
        if len(records) >= 3:

            runs.append({
                "start": off,
                "end": cur,
                "records": records,
            })

            off = cur

        else:
            off += 4

    return runs


def in_ranges(off, ranges):
    return any(
        start <= off < end
        for start, end in ranges
    )


def classify_pointer(value, base, size):
    # Test Thumb FIRST.
    if value & 1:

        target = value & ~1

        if (
            base
            <= target
            < base + size
        ):
            return (
                "THUMB",
                target,
            )

        return None

    if (
        base
        <= value
        < base + size
    ):
        return (
            "DIRECT",
            value,
        )

    return None


def pointer_census(
    data,
    base,
    excluded,
):
    direct = []
    thumb = []

    for off in range(
        0,
        len(data) - 3,
        4,
    ):

        if in_ranges(
            off,
            excluded,
        ):
            continue

        raw = u32(
            data,
            off,
        )

        result = classify_pointer(
            raw,
            base,
            len(data),
        )

        if result is None:
            continue

        kind, target = result

        item = (
            off,
            raw,
            target,
        )

        if kind == "THUMB":
            thumb.append(item)
        else:
            direct.append(item)

    return {
        "direct": direct,
        "thumb": thumb,
        "total": (
            len(direct)
            + len(thumb)
        ),
    }


def find_exact(data, value):
    needle = struct.pack(
        "<I",
        value,
    )

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
    print("S12.9N - FULL ROM-PATCH TABLE CENSUS")
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
    # A. Detect all 0x0C patch-table runs
    # ==============================================================

    print()
    print("=" * 120)
    print("A. FULL <TARGET,0,VALUE16> TABLE CENSUS")
    print("=" * 120)

    runs = detect_patch_runs(
        rom
    )

    print(
        f"detected runs = {len(runs)}"
    )

    total_records = sum(
        len(r["records"])
        for r in runs
    )

    print(
        f"total records = {total_records}"
    )

    for i, run in enumerate(runs):

        records = run[
            "records"
        ]

        targets = [
            x[1]
            for x in records
        ]

        values = [
            x[2]
            for x in records
        ]

        target_deltas = [
            targets[j + 1]
            - targets[j]
            for j in range(
                len(targets) - 1
            )
        ]

        common_deltas = Counter(
            target_deltas
        ).most_common(6)

        contains_d3 = any(
            target == 0xF03ACA54
            and value == 0x29D3
            for _, target, value
            in records
        )

        print()
        print(
            f"RUN {i:02d}"
        )

        print(
            f"  file range : "
            f"ROM+0x{run['start']:05X}"
            f"..0x{run['end']-1:05X}"
        )

        print(
            f"  bytes      : "
            f"0x{run['end'] - run['start']:X}"
        )

        print(
            f"  records    : "
            f"{len(records)}"
        )

        print(
            f"  targets    : "
            f"0x{min(targets):08X}"
            f"..0x{max(targets):08X}"
        )

        print(
            f"  values     : "
            f"0x{min(values):04X}"
            f"..0x{max(values):04X}"
        )

        print(
            "  target deltas: "
            + ", ".join(
                f"0x{k:X} x{n}"
                for k, n
                in common_deltas
            )
        )

        print(
            "  contains D3 table : "
            f"{'YES' if contains_d3 else 'NO'}"
        )

        for (
            off,
            target,
            value,
        ) in records[:12]:

            print(
                f"    ROM+0x{off:05X} "
                f"target=0x{target:08X} "
                f"value=0x{value:04X}"
            )

        if len(records) > 12:
            print(
                "    ..."
            )


    # ==============================================================
    # B. Validate known D3-D7 records are inside detected run
    # ==============================================================

    print()
    print("=" * 120)
    print("B. KNOWN D3-D7 TABLE COVERAGE")
    print("=" * 120)

    wanted = {
        (0xF03ACA54, 0x29D3),
        (0xF03ACA5C, 0x29D4),
        (0xF03ACA64, 0x29D5),
        (0xF03ACA6C, 0x29D6),
        (0xF03ACA74, 0x29D7),
    }

    found = set()

    for run in runs:

        for _, target, value in run[
            "records"
        ]:

            pair = (
                target,
                value,
            )

            if pair in wanted:
                found.add(pair)

    for target, value in sorted(
        wanted
    ):

        print(
            f"0x{target:08X} "
            f"-> 0x{value:04X} : "
            f"{'PASS' if (target,value) in found else 'FAIL'}"
        )

    print()
    print(
        "D3-D7 all covered : "
        f"{'PASS' if found == wanted else 'FAIL'}"
    )


    # ==============================================================
    # C. Exclusion ranges
    # ==============================================================

    print()
    print("=" * 120)
    print("C. PATCH-TABLE EXCLUSION RANGES")
    print("=" * 120)

    excluded = [
        (
            r["start"],
            r["end"],
        )
        for r in runs
    ]

    excluded_bytes = sum(
        end - start
        for start, end
        in excluded
    )

    print(
        f"excluded ranges : {len(excluded)}"
    )

    print(
        f"excluded bytes  : "
        f"0x{excluded_bytes:X}"
    )

    for start, end in excluded:

        print(
            f"ROM+0x{start:05X}"
            f"..0x{end-1:05X}"
        )


    # ==============================================================
    # D. Corrected pointer census
    # ==============================================================

    print()
    print("=" * 120)
    print("D. CORRECTED SELF-POINTER CENSUS")
    print("=" * 120)

    results = []

    for base in BASES:

        census = pointer_census(
            rom,
            base,
            excluded,
        )

        result = {
            "base": base,
            **census,
        }

        results.append(
            result
        )

        print(
            f"base=0x{base:08X} "
            f"total={result['total']:5d} "
            f"direct={len(result['direct']):5d} "
            f"thumb={len(result['thumb']):5d}"
        )


    ranked = sorted(
        results,
        key=lambda r: (
            r["total"],
            len(r["thumb"]),
        ),
        reverse=True,
    )

    print()
    print("=" * 120)
    print("E. CORRECTED RANKING")
    print("=" * 120)

    for i, r in enumerate(
        ranked,
        1,
    ):

        print(
            f"{i:2d}. "
            f"0x{r['base']:08X} "
            f"total={r['total']:5d} "
            f"direct={len(r['direct']):5d} "
            f"thumb={len(r['thumb']):5d}"
        )

    best = ranked[0]
    second = ranked[1]

    ratio = (
        best["total"]
        / second["total"]
        if second["total"]
        else float("inf")
    )

    print()
    print(
        f"best   = 0x{best['base']:08X}"
    )

    print(
        f"second = 0x{second['base']:08X}"
    )

    print(
        f"ratio  = {ratio:.3f}"
    )


    # ==============================================================
    # F. Aligned vs unaligned exact base constants
    # ==============================================================

    print()
    print("=" * 120)
    print("F. EXACT BASE CONSTANT OCCURRENCES")
    print("=" * 120)

    for base in BASES:

        hits = find_exact(
            rom,
            base,
        )

        if not hits:
            continue

        print()
        print(
            f"0x{base:08X}"
        )

        for off in hits:

            print(
                f"  ROM+0x{off:05X} "
                f"alignment={off & 3}"
            )


    # ==============================================================
    # G. Best-base samples after exclusion
    # ==============================================================

    print()
    print("=" * 120)
    print("G. BEST-BASE POINTER SAMPLES AFTER PATCH EXCLUSION")
    print("=" * 120)

    print(
        f"base = 0x{best['base']:08X}"
    )

    print()
    print("DIRECT:")

    for off, raw, target in best[
        "direct"
    ][:80]:

        print(
            f"  ROM+0x{off:05X} "
            f"0x{raw:08X} -> "
            f"0x{target:08X}"
        )

    print()
    print("THUMB:")

    for off, raw, target in best[
        "thumb"
    ][:80]:

        print(
            f"  ROM+0x{off:05X} "
            f"0x{raw:08X} -> "
            f"0x{target:08X} "
            f"(Thumb)"
        )


    # ==============================================================
    # H. Conservative conclusion
    # ==============================================================

    print()
    print("=" * 120)
    print("S12.9N RESULT")
    print("=" * 120)

    print(
        f"PATCH TABLE RUNS DETECTED : "
        f"{len(runs)}"
    )

    print(
        f"PATCH RECORDS DETECTED    : "
        f"{total_records}"
    )

    print(
        f"EXCLUDED PATCH BYTES      : "
        f"0x{excluded_bytes:X}"
    )

    print(
        f"CORRECTED BEST BASE       : "
        f"0x{best['base']:08X}"
    )

    print(
        f"BEST/SECOND RATIO         : "
        f"{ratio:.3f}"
    )

    print(
        f"CORRECTED THUMB COUNT     : "
        f"{len(best['thumb'])}"
    )

    print()

    if (
        best["base"] == 0xF03A0000
        and ratio >= 1.25
    ):

        print(
            "STRONGLY SUPPORTED: "
            "F03A0000 remains dominant "
            "after removal of ROM-patch tables."
        )

    elif (
        best["base"] == 0xF03A0000
    ):

        print(
            "F03A0000 still ranks first, "
            "but does not dominate enough "
            "to prove the runtime base."
        )

    else:

        print(
            "F03A0000 no longer ranks first "
            "after proper patch-table exclusion."
        )

    print()
    print(
        "PATCH TABLE FAMILY       : FACT / STRONGLY SUPPORTED"
    )

    print(
        "PATCH WIDTH 16 BIT       : STRONGLY SUPPORTED"
    )

    print(
        "ROM RUNTIME BASE         : UNKNOWN until discriminating evidence"
    )

    print(
        "ROM-PATCH CONSUMER       : UNKNOWN"
    )

    print(
        "D5/D6 WRITE PROTOCOL     : UNKNOWN"
    )

    print(
        "ERASE-BEFORE-PROGRAM     : UNKNOWN"
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
