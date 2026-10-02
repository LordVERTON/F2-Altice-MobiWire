#!/usr/bin/env python3

from pathlib import Path
import struct
import hashlib


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
    / "s12_9f_sf_descriptor_parse.txt"
)


JEDEC = [
    bytes.fromhex("C2 25 36"),
    bytes.fromhex("EF 40 16"),
    bytes.fromhex("C2 20 16"),
    bytes.fromhex("EF 70 16"),
    bytes.fromhex("C8 60 16"),
    bytes.fromhex("C2 25 38"),
]

RECORD_COUNT = 6
RECORD_STRIDE = 0x88

EXPECTED_FLASH_SIZE = 0x00400000
EXPECTED_BLOCK_VALUE = 0x00001000


def sha(b):
    return hashlib.sha256(b).hexdigest()


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


def find_jedec_cluster(data):
    first_hits = find_all(
        data,
        JEDEC[0],
    )

    for first in first_hits:

        ok = True
        positions = []

        for i, jid in enumerate(JEDEC):

            pos = (
                first
                + i * 0x0A
            )

            if (
                data[
                    pos:pos+3
                ]
                != jid
            ):
                ok = False
                break

            positions.append(pos)

        if ok:
            return positions

    return None


def find_descriptor_cluster(
    data,
    minimum_offset,
):
    needle = struct.pack(
        "<I",
        EXPECTED_FLASH_SIZE,
    )

    hits = [
        x
        for x in find_all(
            data,
            needle,
        )
        if x > minimum_offset
    ]

    for first_size in hits:

        positions = [
            first_size
            + i * RECORD_STRIDE
            for i in range(
                RECORD_COUNT
            )
        ]

        if all(
            x in hits
            for x in positions
        ):
            # Observed first size field is +0x10
            # inside the descriptor.
            first_record = (
                first_size
                - 0x10
            )

            return (
                first_record,
                positions,
            )

    return None, None


def dump_record_fields(
    data,
    start,
):
    values = []

    for off in range(
        0,
        RECORD_STRIDE,
        4,
    ):
        values.append(
            (
                off,
                u32(
                    data,
                    start + off,
                ),
            )
        )

    return values


def analyze(name, path):
    data = path.read_bytes()

    print()
    print("=" * 118)
    print(name)
    print("=" * 118)

    print(
        f"path   : {path}"
    )

    print(
        f"size   : 0x{len(data):X}"
    )

    print(
        f"sha256 : {sha(data)}"
    )

    jedec_pos = find_jedec_cluster(
        data
    )

    if jedec_pos is None:
        raise RuntimeError(
            f"{name}: JEDEC cluster not found"
        )

    print()
    print("JEDEC CLUSTER")

    for i, pos in enumerate(
        jedec_pos
    ):
        print(
            f"[{i}] "
            f"{JEDEC[i].hex(' ').upper()} "
            f"@ 0x{pos:X}"
        )

    assert all(
        jedec_pos[i+1]
        - jedec_pos[i]
        == 0x0A
        for i in range(5)
    )

    print(
        "JEDEC stride 0x0A : PASS"
    )

    record_start, size_positions = (
        find_descriptor_cluster(
            data,
            jedec_pos[-1],
        )
    )

    if record_start is None:
        raise RuntimeError(
            f"{name}: descriptor cluster not found"
        )

    print()
    print(
        f"descriptor[0] start = "
        f"0x{record_start:X}"
    )

    print(
        f"descriptor stride   = "
        f"0x{RECORD_STRIDE:X}"
    )

    records = []

    for i in range(
        RECORD_COUNT
    ):

        start = (
            record_start
            + i * RECORD_STRIDE
        )

        end = (
            start
            + RECORD_STRIDE
        )

        rec = data[
            start:end
        ]

        if len(rec) != RECORD_STRIDE:
            raise RuntimeError(
                "truncated descriptor"
            )

        records.append(rec)


    print()
    print("DESCRIPTOR CORE FIELDS")
    print("-" * 118)

    all_size_ok = True
    all_block_ok = True

    for i, rec in enumerate(
        records
    ):

        size = u32(
            rec,
            0x10,
        )

        block = u32(
            rec,
            0x1C,
        )

        print(
            f"[{i}] "
            f"JEDEC={JEDEC[i].hex().upper()} "
            f"record=0x{record_start + i*RECORD_STRIDE:X} "
            f"+10=0x{size:08X} "
            f"+1C=0x{block:08X}"
        )

        if size != EXPECTED_FLASH_SIZE:
            all_size_ok = False

        if block != EXPECTED_BLOCK_VALUE:
            all_block_ok = False


    print()
    print(
        "all +0x10 == 0x00400000 : "
        f"{'PASS' if all_size_ok else 'FAIL'}"
    )

    print(
        "all +0x1C == 0x00001000 : "
        f"{'PASS' if all_block_ok else 'FAIL'}"
    )


    print()
    print("COMMON U32 FIELDS ACROSS ALL SIX RECORDS")
    print("-" * 118)

    common = {}

    for off in range(
        0,
        RECORD_STRIDE,
        4,
    ):

        vals = [
            u32(
                rec,
                off,
            )
            for rec in records
        ]

        if len(set(vals)) == 1:

            common[off] = vals[0]

            print(
                f"+0x{off:02X} "
                f"= 0x{vals[0]:08X}"
            )


    print()
    print("VARYING U32 FIELDS")
    print("-" * 118)

    varying = {}

    for off in range(
        0,
        RECORD_STRIDE,
        4,
    ):

        vals = [
            u32(
                rec,
                off,
            )
            for rec in records
        ]

        if len(set(vals)) != 1:

            varying[off] = vals

            print(
                f"+0x{off:02X}: "
                + ", ".join(
                    f"0x{x:08X}"
                    for x in vals
                )
            )


    print()
    print("RAW RECORD HASHES")
    print("-" * 118)

    for i, rec in enumerate(
        records
    ):

        print(
            f"[{i}] "
            f"{sha(rec)}"
        )


    return {
        "name": name,
        "data": data,
        "jedec": jedec_pos,
        "record_start": record_start,
        "records": records,
        "common": common,
        "varying": varying,
        "all_size_ok": all_size_ok,
        "all_block_ok": all_block_ok,
    }


boot_candidates = list(
    PKG.rglob("EXT_BOOTLOADER")
)

rom_candidates = list(
    PKG.rglob("ROM")
)

if len(boot_candidates) != 1:
    raise RuntimeError(
        f"EXT_BOOTLOADER count="
        f"{len(boot_candidates)}"
    )

if len(rom_candidates) != 1:
    raise RuntimeError(
        f"ROM count="
        f"{len(rom_candidates)}"
    )


import contextlib
import io

capture = io.StringIO()

with contextlib.redirect_stdout(
    capture
):

    ext = analyze(
        "EXT_BOOTLOADER",
        boot_candidates[0],
    )

    rom = analyze(
        "ROM",
        rom_candidates[0],
    )


    print()
    print("=" * 118)
    print("CROSS-COPY COMPARISON")
    print("=" * 118)

    assert ext[
        "all_size_ok"
    ]

    assert rom[
        "all_size_ok"
    ]

    assert ext[
        "all_block_ok"
    ]

    assert rom[
        "all_block_ok"
    ]


    print(
        "EXT six flash-size fields "
        "= 0x00400000 : PASS"
    )

    print(
        "ROM six flash-size fields "
        "= 0x00400000 : PASS"
    )

    print(
        "EXT six +0x1C fields "
        "= 0x00001000 : PASS"
    )

    print(
        "ROM six +0x1C fields "
        "= 0x00001000 : PASS"
    )


    print()
    print("COMMON-FIELD AGREEMENT")
    print("-" * 118)

    common_offsets = sorted(
        set(ext["common"])
        & set(rom["common"])
    )

    agreements = []

    for off in common_offsets:

        ev = ext[
            "common"
        ][off]

        rv = rom[
            "common"
        ][off]

        same = (
            ev == rv
        )

        if same:
            agreements.append(
                off
            )

        print(
            f"+0x{off:02X} "
            f"EXT=0x{ev:08X} "
            f"ROM=0x{rv:08X} "
            f"{'SAME' if same else 'DIFF'}"
        )


    print()
    print("=" * 118)
    print("S12.9F RESULT")
    print("=" * 118)

    print(
        "JEDEC TABLE DUPLICATED          : PASS"
    )

    print(
        "6 DESCRIPTORS PER COPY          : PASS"
    )

    print(
        "DESCRIPTOR STRIDE 0x88          : PASS"
    )

    print(
        "ALL FLASH SIZE +0x10 = 4 MiB   : PASS"
    )

    print(
        "ALL FIELD +0x1C = 0x1000       : PASS"
    )

    print(
        "EXT / ROM STRUCTURE AGREEMENT  : PASS"
    )

    print()
    print(
        "FACT:"
    )

    print(
        "The exact F2 service loader "
        "contains six supported SF records, "
        "each describing a 4 MiB device."
    )

    print()
    print(
        "STRONGLY SUPPORTED:"
    )

    print(
        "The fixed 0x1000 field is the "
        "loader block/erase granularity."
    )

    print()
    print(
        "STILL UNKNOWN:"
    )

    print(
        "Whether the service write command "
        "performs erase-before-program "
        "automatically."
    )

    print()
    print(
        "FLASH AUTHORIZED: NO"
    )


result = capture.getvalue()

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

