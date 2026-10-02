#!/usr/bin/env python3

from pathlib import Path
import hashlib
import struct


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

EXTRACTED = (
    MTK
    / "research"
    / "f2"
    / "work"
    / "extracted"
)

OUT = (
    ROOT
    / "research"
    / "f2"
    / "work"
    / "repro"
)

REPORT = (
    OUT
    / "s12_9k_rom_patch_table_resolution.txt"
)


ROM_SHA = (
    "dbebc45c8e4334e61fd85bdab8988d4"
    "f271599263ce209520e36f571f3f4e37c"
)

TABLE_START = 0x3DB80
TABLE_END   = 0x3DC20
RECORD_SIZE = 0x0C

CHAIN_VALUES = [
    0x29D3,
    0x29D4,
    0x29D5,
    0x29D6,
    0x29D7,
]

CHAIN_TARGETS = [
    0xF03ACA54,
    0xF03ACA5C,
    0xF03ACA64,
    0xF03ACA6C,
    0xF03ACA74,
]


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def u16(data, off):
    return struct.unpack_from(
        "<H",
        data,
        off,
    )[0]


def u32(data, off):
    return struct.unpack_from(
        "<I",
        data,
        off,
    )[0]


def parse_records(data):
    rows = []

    for off in range(
        TABLE_START,
        TABLE_END,
        RECORD_SIZE,
    ):

        if off + RECORD_SIZE > len(data):
            break

        target = u32(
            data,
            off + 0,
        )

        middle = u32(
            data,
            off + 4,
        )

        value = u32(
            data,
            off + 8,
        )

        rows.append({
            "file_off": off,
            "target": target,
            "middle": middle,
            "value": value,
        })

    return rows


def chain_hits(data):
    hits = []

    # We need:
    #
    # p+0x00 = D3 29
    # p+0x08 = D4 29
    # p+0x10 = D5 29
    # p+0x18 = D6 29
    # p+0x20 = D7 29

    need = 0x22

    if len(data) < need:
        return hits

    first = struct.pack(
        "<H",
        CHAIN_VALUES[0],
    )

    pos = 0

    while True:

        pos = data.find(
            first,
            pos,
        )

        if pos < 0:
            break

        if pos + need <= len(data):

            ok = True

            for i, value in enumerate(
                CHAIN_VALUES
            ):

                off = (
                    pos
                    + i * 8
                )

                if u16(
                    data,
                    off,
                ) != value:

                    ok = False
                    break

            if ok:
                hits.append(pos)

        pos += 1

    return hits


def candidate_files():
    seen = set()

    for root in (
        PKG,
        EXTRACTED,
    ):

        if not root.exists():
            continue

        for path in root.rglob("*"):

            if not path.is_file():
                continue

            try:
                size = path.stat().st_size
            except OSError:
                continue

            # Keep the scan bounded.
            if size == 0 or size > 0x2000000:
                continue

            key = str(path).lower()

            if key in seen:
                continue

            seen.add(key)

            yield path


roms = list(
    PKG.rglob("ROM")
)

assert len(roms) == 1

ROM = roms[0]
rom = ROM.read_bytes()

assert sha256(rom) == ROM_SHA


import contextlib
import io

buf = io.StringIO()

with contextlib.redirect_stdout(buf):

    print("=" * 120)
    print("S12.9K - RESOLVE ROM TARGET/VALUE TABLE")
    print("=" * 120)

    print()
    print("NO DEVICE ACCESS")
    print("NO BROM")
    print("NO WRITE")
    print("NO ERASE")

    print()
    print("ROM identity : PASS")
    print(
        f"ROM SHA256   : {sha256(rom)}"
    )


    # ==============================================================
    # A. Parse the real records
    # ==============================================================

    print()
    print("=" * 120)
    print("A. ROM TABLE PARSE")
    print("=" * 120)

    rows = parse_records(
        rom
    )

    for i, row in enumerate(
        rows
    ):

        marker = ""

        if (
            row["target"]
            in CHAIN_TARGETS
        ):
            marker = "  <<< D3-D7 TARGET"

        print(
            f"[{i:02d}] "
            f"ROM+0x{row['file_off']:05X} "
            f"target=0x{row['target']:08X} "
            f"middle=0x{row['middle']:08X} "
            f"value=0x{row['value']:08X}"
            f"{marker}"
        )


    # ==============================================================
    # B. Prove exact D3-D7 rows
    # ==============================================================

    print()
    print("=" * 120)
    print("B. D3-D7 TABLE ROWS")
    print("=" * 120)

    chain_rows = []

    for target, value in zip(
        CHAIN_TARGETS,
        CHAIN_VALUES,
    ):

        found = [
            r
            for r in rows
            if (
                r["target"] == target
                and
                r["middle"] == 0
                and
                r["value"] == value
            )
        ]

        print(
            f"target=0x{target:08X} "
            f"value=0x{value:04X} "
            f"{'PASS' if len(found) == 1 else 'FAIL'}"
        )

        assert len(found) == 1

        chain_rows.append(
            found[0]
        )

    target_stride = all(
        CHAIN_TARGETS[i + 1]
        - CHAIN_TARGETS[i]
        == 8
        for i in range(
            len(CHAIN_TARGETS) - 1
        )
    )

    print()
    print(
        "runtime target stride +8 :",
        "PASS"
        if target_stride
        else "FAIL",
    )


    # ==============================================================
    # C. Search actual code pattern in all local relevant blobs
    # ==============================================================

    print()
    print("=" * 120)
    print("C. SEARCH REAL D3-D7 CODE PATTERN AT STRIDE +8")
    print("=" * 120)

    candidates = []

    scanned = 0

    for path in candidate_files():

        try:
            data = path.read_bytes()
        except Exception:
            continue

        scanned += 1

        hits = chain_hits(
            data
        )

        if not hits:
            continue

        for hit in hits:

            base = (
                CHAIN_TARGETS[0]
                - hit
            )

            candidate = {
                "path": path,
                "data": data,
                "hit": hit,
                "base": base,
            }

            candidates.append(
                candidate
            )

            print()
            print(
                f"HIT: {path}"
            )

            print(
                f"file offset     : 0x{hit:X}"
            )

            print(
                f"candidate base  : 0x{base:08X}"
            )

            print(
                "derived mapping  : "
                f"0x{base:08X} + "
                f"0x{hit:X} = "
                f"0x{CHAIN_TARGETS[0]:08X}"
            )

            for i, (
                target,
                value,
            ) in enumerate(
                zip(
                    CHAIN_TARGETS,
                    CHAIN_VALUES,
                )
            ):

                mapped = (
                    target
                    - base
                )

                actual = (
                    u16(
                        data,
                        mapped,
                    )
                    if (
                        0 <= mapped
                        and mapped + 2
                        <= len(data)
                    )
                    else None
                )

                print(
                    f"  [{i}] "
                    f"runtime=0x{target:08X} "
                    f"file=0x{mapped:X} "
                    f"actual="
                    + (
                        f"0x{actual:04X}"
                        if actual is not None
                        else "OUT-OF-RANGE"
                    )
                    + f" expected=0x{value:04X} "
                    + (
                        "PASS"
                        if actual == value
                        else "FAIL"
                    )
                )


    print()
    print(
        f"files scanned : {scanned}"
    )

    print(
        f"code hits     : {len(candidates)}"
    )


    # ==============================================================
    # D. Test the mapping against every nearby table record
    # ==============================================================

    print()
    print("=" * 120)
    print("D. NEARBY TABLE RECORD VALIDATION")
    print("=" * 120)

    scored = []

    for ci, cand in enumerate(
        candidates
    ):

        data = cand[
            "data"
        ]

        base = cand[
            "base"
        ]

        matched16 = 0
        checked16 = 0

        print()
        print(
            f"CANDIDATE {ci}"
        )

        print(
            f"path = {cand['path']}"
        )

        print(
            f"base = 0x{base:08X}"
        )

        for row in rows:

            target = row[
                "target"
            ]

            value = row[
                "value"
            ]

            mapped = (
                target
                - base
            )

            if not (
                0 <= mapped
                and mapped + 2 <= len(data)
            ):
                continue

            # The table values in this region fit in 16 bits.
            if value > 0xFFFF:
                continue

            checked16 += 1

            actual = u16(
                data,
                mapped,
            )

            ok = (
                actual == value
            )

            if ok:
                matched16 += 1

            print(
                f"runtime=0x{target:08X} "
                f"file=0x{mapped:06X} "
                f"table=0x{value:04X} "
                f"blob=0x{actual:04X} "
                f"{'PASS' if ok else 'DIFF'}"
            )

        scored.append(
            (
                matched16,
                checked16,
                cand,
            )
        )

        print()
        print(
            f"matched16 = "
            f"{matched16}/{checked16}"
        )


    # ==============================================================
    # E. Best candidate
    # ==============================================================

    print()
    print("=" * 120)
    print("E. BEST MAPPING")
    print("=" * 120)

    if scored:

        scored.sort(
            key=lambda x: (
                x[0],
                x[1],
            ),
            reverse=True,
        )

        matched, checked, best = (
            scored[0]
        )

        print(
            f"path    : {best['path']}"
        )

        print(
            f"offset  : 0x{best['hit']:X}"
        )

        print(
            f"base    : 0x{best['base']:08X}"
        )

        print(
            f"matches : {matched}/{checked}"
        )

        full_chain = (
            matched >= 5
        )

        print()
        print(
            "D3-D7 direct runtime mapping : "
            f"{'PASS' if full_chain else 'PARTIAL'}"
        )

    else:

        best = None
        full_chain = False

        print(
            "No direct copy of the "
            "D3-D7 +8 code pattern found."
        )


    # ==============================================================
    # F. Correct classification
    # ==============================================================

    print()
    print("=" * 120)
    print("S12.9K RESULT")
    print("=" * 120)

    print(
        "FACT: ROM+0x3DBxx is a "
        "0x0C-stride data table."
    )

    print(
        "FACT: D3-D7 rows contain "
        "runtime targets F03ACA54..F03ACA74."
    )

    print(
        "FACT: corresponding values are "
        "Thumb halfwords 29D3..29D7."
    )

    if full_chain:

        print(
            "DIRECT CODE COPY FOUND       : PASS"
        )

        print(
            "RUNTIME->FILE MAPPING        : PASS"
        )

        print(
            "NEXT: disassemble the mapped "
            "runtime targets, especially D5/D6."
        )

    else:

        print(
            "DIRECT CODE COPY FOUND       : NO"
        )

        print(
            "NEXT: identify the consumer of "
            "the target/value table itself."
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
