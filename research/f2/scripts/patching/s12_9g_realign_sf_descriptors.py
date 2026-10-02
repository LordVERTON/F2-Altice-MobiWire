#!/usr/bin/env python3

from pathlib import Path
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
    / "s12_9g_sf_descriptor_realign.txt"
)

JEDEC = [
    bytes.fromhex("C2 25 36"),
    bytes.fromhex("EF 40 16"),
    bytes.fromhex("C2 20 16"),
    bytes.fromhex("EF 70 16"),
    bytes.fromhex("C8 60 16"),
    bytes.fromhex("C2 25 38"),
]

COUNT = 6
STRIDE = 0x88

FLASH_SIZE = 0x00400000
BLOCK_VALUE = 0x00001000
SERVICE_SIZE = 0x00300000


def sha(data):
    return hashlib.sha256(data).hexdigest()


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
        pos = data.find(needle, pos)

        if pos < 0:
            return out

        out.append(pos)
        pos += 1


def find_jedec_table(data):
    for first in find_all(
        data,
        JEDEC[0],
    ):

        positions = [
            first + i * 0x0A
            for i in range(COUNT)
        ]

        if all(
            data[pos:pos+3] == JEDEC[i]
            for i, pos in enumerate(positions)
        ):
            return positions

    raise RuntimeError(
        "JEDEC table not found"
    )


def find_records(data, after):
    needle = struct.pack(
        "<I",
        FLASH_SIZE,
    )

    hits = [
        p
        for p in find_all(data, needle)
        if p > after
    ]

    for first in hits:

        positions = [
            first + i * STRIDE
            for i in range(COUNT)
        ]

        if all(
            p in hits
            for p in positions
        ):
            return positions

    raise RuntimeError(
        "descriptor cluster not found"
    )


def analyze(name, path):
    data = path.read_bytes()

    print()
    print("=" * 112)
    print(name)
    print("=" * 112)

    print(
        f"path   : {path}"
    )

    print(
        f"size   : 0x{len(data):X}"
    )

    print(
        f"sha256 : {sha(data)}"
    )

    jedec = find_jedec_table(
        data
    )

    records = find_records(
        data,
        jedec[-1],
    )

    print()
    print("JEDEC TABLE")

    for i, pos in enumerate(jedec):

        print(
            f"[{i}] "
            f"{JEDEC[i].hex(' ').upper()} "
            f"@ 0x{pos:X}"
        )

    print()
    print("TRUE RECORD STARTS")

    for i, pos in enumerate(records):

        print(
            f"[{i}] "
            f"0x{pos:X}"
        )

    assert all(
        records[i+1] - records[i]
        == STRIDE
        for i in range(COUNT - 1)
    )

    print(
        "record stride 0x88 : PASS"
    )

    # Header immediately before the first real record.
    hdr_start = records[0] - 0x10

    header = data[
        hdr_start:records[0]
    ]

    print()
    print(
        f"PRECEDING HEADER @ 0x{hdr_start:X}"
    )

    print(
        header.hex(" ").upper()
    )

    recs = [
        data[
            pos:pos+STRIDE
        ]
        for pos in records
    ]

    assert all(
        len(x) == STRIDE
        for x in recs
    )

    print()
    print("CORE FIELDS")
    print("-" * 112)

    for i, rec in enumerate(recs):

        print(
            f"[{i}] "
            f"JEDEC={JEDEC[i].hex().upper()} "
            f"+00=0x{u32(rec,0x00):08X} "
            f"+04=0x{u32(rec,0x04):08X} "
            f"+08=0x{u32(rec,0x08):08X} "
            f"+0C=0x{u32(rec,0x0C):08X} "
            f"+48=0x{u32(rec,0x48):08X} "
            f"+4C=0x{u32(rec,0x4C):08X}"
        )

    assert all(
        u32(rec, 0x00)
        == FLASH_SIZE
        for rec in recs
    )

    assert all(
        u32(rec, 0x0C)
        == BLOCK_VALUE
        for rec in recs
    )

    assert all(
        u32(rec, 0x48)
        == SERVICE_SIZE
        for rec in recs
    )

    assert all(
        u32(rec, 0x4C)
        == 1
        for rec in recs
    )

    print()
    print(
        "all +0x00 == 0x00400000 : PASS"
    )

    print(
        "all +0x0C == 0x00001000 : PASS"
    )

    print(
        "all +0x48 == 0x00300000 : PASS"
    )

    print(
        "all +0x4C == 1          : PASS"
    )

    print()
    print("RECORD HASHES")
    print("-" * 112)

    hashes = []

    for i, rec in enumerate(recs):

        digest = sha(rec)

        hashes.append(digest)

        print(
            f"[{i}] {digest}"
        )

    identical = (
        len(set(hashes)) == 1
    )

    print()
    print(
        "all six records byte-identical : "
        f"{'PASS' if identical else 'FAIL'}"
    )

    print()
    print("ALL COMMON U32 FIELDS")
    print("-" * 112)

    common = {}

    for off in range(
        0,
        STRIDE,
        4,
    ):

        vals = [
            u32(rec, off)
            for rec in recs
        ]

        if len(set(vals)) == 1:

            common[off] = vals[0]

            print(
                f"+0x{off:02X} "
                f"= 0x{vals[0]:08X}"
            )

        else:

            print(
                f"+0x{off:02X} VARIES: "
                + ", ".join(
                    f"0x{x:08X}"
                    for x in vals
                )
            )

    return {
        "data": data,
        "jedec": jedec,
        "records": records,
        "record_bytes": recs,
        "hashes": hashes,
        "identical": identical,
        "common": common,
        "header": header,
    }


ext_paths = list(
    PKG.rglob("EXT_BOOTLOADER")
)

rom_paths = list(
    PKG.rglob("ROM")
)

assert len(ext_paths) == 1
assert len(rom_paths) == 1


import io
import contextlib

buf = io.StringIO()

with contextlib.redirect_stdout(buf):

    ext = analyze(
        "EXT_BOOTLOADER",
        ext_paths[0],
    )

    rom = analyze(
        "ROM",
        rom_paths[0],
    )

    print()
    print("=" * 112)
    print("CROSS-COPY CHECK")
    print("=" * 112)

    assert ext["identical"]
    assert rom["identical"]

    # The descriptor bytes themselves should
    # be identical between both embedded copies.
    for i in range(COUNT):

        assert (
            ext["record_bytes"][i]
            ==
            rom["record_bytes"][i]
        )

    print(
        "EXT six records identical : PASS"
    )

    print(
        "ROM six records identical : PASS"
    )

    print(
        "EXT records == ROM records : PASS"
    )

    assert (
        ext["common"][0x00]
        == FLASH_SIZE
    )

    assert (
        ext["common"][0x0C]
        == BLOCK_VALUE
    )

    assert (
        ext["common"][0x48]
        == SERVICE_SIZE
    )

    print()
    print("=" * 112)
    print("S12.9G RESULT")
    print("=" * 112)

    print(
        "TRUE RECORD START = SIZE FIELD : PASS"
    )

    print(
        "6 RECORDS / STRIDE 0x88        : PASS"
    )

    print(
        "ALL RECORDS BYTE-IDENTICAL     : PASS"
    )

    print(
        "EXT == ROM RECORD DATA         : PASS"
    )

    print(
        "FLASH SIZE FIELD +0x00 = 4 MiB : PASS"
    )

    print(
        "BLOCK FIELD +0x0C = 0x1000     : PASS"
    )

    print(
        "SERVICE SIZE +0x48 = 3 MiB     : PASS"
    )

    print()
    print("CLASSIFICATION")

    print(
        "FACT: exact F2 service-loader "
        "SF descriptor capacity = 4 MiB."
    )

    print(
        "FACT: exact F2 service-loader "
        "descriptor contains fixed 0x1000 field."
    )

    print(
        "STRONGLY SUPPORTED: "
        "0x1000 is the SF erase/block granularity."
    )

    print(
        "UNKNOWN: service write "
        "erase-before-program semantics."
    )

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
