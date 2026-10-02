#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
S13.2C - TARGET FIRMWARE SECTOR D6 PRE-WRITE BASELINE REHEARSAL

READ ONLY.

Target:
    0x00249000 .. 0x00249FFF

Purpose:
    - validate exact MT6261 / NOR / DA identity
    - D6-read the target sector twice
    - require exact byte equality with S13.2B BEFORE sector
    - save fresh D6 rollback copies
    - validate S13.2B AFTER sector
    - count NOR 0->1 and 1->0 transitions
    - absolutely no D3
    - absolutely no D5
    - absolutely no erase/write

This does NOT authorize a firmware-sector write.
The eventual mutating harness must repeat the exact D6 pre-read
in the SAME DA session immediately before D3+D5.
"""

from pathlib import Path
import hashlib
import json
import struct
import sys


ROOT = Path.cwd()

MTK = Path(
    r"C:\Users\verto\mtkclient"
)

#
# Make the already-proven local mtk_iot_api helper importable.
#
if str(MTK) not in sys.path:
    sys.path.insert(
        0,
        str(MTK),
    )

from mtk_iot_api import (
    init as mtk_init,
    connect as mtk_connect,
)


# =====================================================================
# EXACT ENVIRONMENT
# =====================================================================

EXPECTED_MTK_COMMIT = (
    "cd25cf9c1ff6d36e82697ac2c798e69e9cfb78c3"
)

LOADER_SHA256 = (
    "b14620c0131a269279e89830f661e39d"
    "c4f5a773d700ce56561c6f9e8e84dc8a"
)

HWCODE = 0x6261

FLASH_SIZE = 0x00400000

EXPECTED_NOR_DEV = (
    0x00EF,
    0x0070,
    0x0016,
)


# =====================================================================
# TARGET
# =====================================================================

TARGET_ADDR = 0x00249000
TARGET_LEN  = 0x00001000

LIVE_BOUNDARY = 0x002C0000

EXPECTED_BEFORE_SHA = (
    "dc8cc6b5be54d1554d71d60539f10a80"
    "77a375a3d7ddf92efe6149610ecffb1b"
)

EXPECTED_AFTER_SHA = (
    "29a21401b84442554dc051edd16ec561b"
    "bd842e01e048344e30ca547f78bb7f9"
)


BUNDLE = (
    ROOT
    / "research/f2/work/candidates/s13_2b"
    / "sector_bundle_NOT_FOR_WRITE_YET"
)

BEFORE_FILE = (
    BUNDLE
    / "sector_249000_before.bin"
)

AFTER_FILE = (
    BUNDLE
    / "sector_249000_after.bin"
)

MANIFEST_FILE = (
    ROOT
    / "research/f2/work/candidates/s13_2b"
    / "s13_2b_manifest.json"
)

OUTDIR = (
    ROOT
    / "research/f2/work/repro"
    / "s13_2c_target_sector_d6_gate"
)

OUT_JSON = (
    OUTDIR
    / "s13_2c_d6_gate.json"
)

READ_A_FILE = (
    OUTDIR
    / "fresh_d6_249000_A.bin"
)

READ_B_FILE = (
    OUTDIR
    / "fresh_d6_249000_B.bin"
)

ROLLBACK_FILE = (
    OUTDIR
    / "rollback_sector_249000_fresh.bin"
)


# =====================================================================
# HELPERS
# =====================================================================

def sha256(data):
    return hashlib.sha256(
        data
    ).hexdigest()


def banner(title):
    print()
    print("=" * 112)
    print(title)
    print("=" * 112)


def find_loader():

    candidates = [
        (
            MTK
            / "mtkclient/Loader"
            / "MTK_AllInOne_DA_iot.bin"
        ),
        (
            MTK
            / "Loader"
            / "MTK_AllInOne_DA_iot.bin"
        ),
    ]

    for p in candidates:

        if not p.is_file():
            continue

        data = p.read_bytes()

        digest = sha256(
            data
        )

        print(
            f"[LOADER] {p}"
        )

        print(
            f"[LOADER] SHA256 = {digest}"
        )

        if digest == LOADER_SHA256:
            return p

        print(
            "[REJECT] loader SHA mismatch"
        )

    raise RuntimeError(
        "exact audited MT6261 IoT loader not found"
    )


def connect_da(loader):

    mtk = mtk_init(
        preloader=None,
        loader=str(loader),
        serialport=None,
    )

    mtk.config.iot = True

    mtk, handler = mtk_connect(
        mtk,
        directory=".",
    )

    if mtk is None:
        raise RuntimeError(
            "Unable to connect/configure MT6261 DA"
        )

    if int(
        mtk.config.hwcode
    ) != HWCODE:
        raise RuntimeError(
            "wrong hwcode: "
            f"0x{int(mtk.config.hwcode):04X}"
        )

    legacy = mtk.daloader.da
    dc = legacy.daconfig

    if dc.storage.flashtype != "nor":
        raise RuntimeError(
            "wrong flash type: "
            f"{dc.storage.flashtype!r}"
        )

    if int(
        dc.storage.flashsize
    ) != FLASH_SIZE:
        raise RuntimeError(
            "wrong NOR size: "
            f"0x{int(dc.storage.flashsize):X}"
        )

    nor = dc.legacy_storage.nor

    dev = tuple(
        int(x)
        for x in nor.m_nor_flash_dev_code
    )

    if dev[:3] != EXPECTED_NOR_DEV:
        raise RuntimeError(
            "wrong NOR device code: "
            + "/".join(
                f"{x:04X}"
                for x in dev
            )
        )

    print(
        f"[DA] hwcode      = "
        f"0x{int(mtk.config.hwcode):04X}"
    )

    print(
        f"[DA] flash type  = "
        f"{dc.storage.flashtype}"
    )

    print(
        f"[DA] flash size  = "
        f"0x{int(dc.storage.flashsize):08X}"
    )

    print(
        "[DA] device code = "
        + "/".join(
            f"{x:04X}"
            for x in dev
        )
    )

    return mtk, legacy


def close_session(mtk):

    try:
        mtk.port.close(
            reset=True
        )

    except Exception:

        try:
            mtk.port.close()

        except Exception:
            pass


def d6_read_4k_native(
    legacy,
    addr,
):

    if (
        addr < 0
        or addr + 0x1000 > FLASH_SIZE
        or (addr & 0xFFF)
    ):
        raise ValueError(
            "invalid 4 KiB D6 address: "
            f"0x{addr:08X}"
        )

    try:

        data = legacy.readflash(
            addr=addr,
            length=0x1000,
            filename="",
            parttype=None,
            display=False,
        )

    except SystemExit as e:

        raise RuntimeError(
            "mtkclient USB backend disconnected "
            f"during native D6 @0x{addr:08X}"
        ) from e


    if (
        not isinstance(
            data,
            (
                bytes,
                bytearray,
            ),
        )
        or len(data) != 0x1000
    ):

        got = (
            len(data)
            if isinstance(
                data,
                (
                    bytes,
                    bytearray,
                ),
            )
            else type(data).__name__
        )

        raise RuntimeError(
            "native D6 returned "
            f"{got}, expected 4096 bytes"
        )

    return bytes(
        data
    )


def count_bit_transitions(
    old,
    new,
):

    zero_to_one = 0
    one_to_zero = 0

    changed = 0

    changed_offsets = []

    for i, (a, b) in enumerate(
        zip(
            old,
            new,
        )
    ):

        if a != b:

            changed += 1

            changed_offsets.append(
                i
            )

        zero_to_one += (
            ((~a) & b & 0xFF)
            .bit_count()
        )

        one_to_zero += (
            (a & (~b) & 0xFF)
            .bit_count()
        )

    return (
        changed,
        zero_to_one,
        one_to_zero,
        changed_offsets,
    )


# =====================================================================
# MAIN
# =====================================================================

def main():

    banner(
        "S13.2C - TARGET SECTOR D6 PRE-WRITE BASELINE REHEARSAL"
    )

    print()
    print(
        "TARGET = "
        f"0x{TARGET_ADDR:08X}.."
        f"0x{TARGET_ADDR+TARGET_LEN-1:08X}"
    )

    print(
        "LENGTH = "
        f"0x{TARGET_LEN:X}"
    )

    print()
    print(
        "FLASH WRITE : NONE"
    )

    print(
        "FLASH ERASE : NONE"
    )

    print(
        "D3 COMMAND  : NEVER"
    )

    print(
        "D5 COMMAND  : NEVER"
    )

    print(
        "D6 READ     : ONLY"
    )


    if (
        TARGET_ADDR
        + TARGET_LEN
        > LIVE_BOUNDARY
    ):
        raise RuntimeError(
            "target crosses live boundary"
        )


    # -------------------------------------------------------------
    # 1. LOCAL S13.2B ARTIFACTS
    # -------------------------------------------------------------

    banner(
        "1. LOCAL S13.2B SECTOR ARTIFACTS"
    )

    if not BEFORE_FILE.is_file():
        raise RuntimeError(
            f"missing BEFORE sector: {BEFORE_FILE}"
        )

    if not AFTER_FILE.is_file():
        raise RuntimeError(
            f"missing AFTER sector: {AFTER_FILE}"
        )

    if not MANIFEST_FILE.is_file():
        raise RuntimeError(
            f"missing manifest: {MANIFEST_FILE}"
        )


    before = BEFORE_FILE.read_bytes()
    after = AFTER_FILE.read_bytes()


    if len(before) != TARGET_LEN:
        raise RuntimeError(
            "BEFORE sector size mismatch"
        )

    if len(after) != TARGET_LEN:
        raise RuntimeError(
            "AFTER sector size mismatch"
        )


    before_sha = sha256(
        before
    )

    after_sha = sha256(
        after
    )


    print(
        f"BEFORE SHA = {before_sha}"
    )

    print(
        f"AFTER SHA  = {after_sha}"
    )


    if before_sha != EXPECTED_BEFORE_SHA:
        raise RuntimeError(
            "S13.2B BEFORE SHA mismatch"
        )

    if after_sha != EXPECTED_AFTER_SHA:
        raise RuntimeError(
            "S13.2B AFTER SHA mismatch"
        )


    print(
        "[PASS] exact S13.2B sector bundle"
    )


    # -------------------------------------------------------------
    # 2. OFFLINE NOR TRANSITIONS
    # -------------------------------------------------------------

    banner(
        "2. NOR BIT-TRANSITION ANALYSIS"
    )

    (
        changed,
        bits_0_to_1,
        bits_1_to_0,
        changed_offsets,
    ) = count_bit_transitions(
        before,
        after,
    )


    print(
        f"changed bytes = {changed}"
    )

    print(
        f"0 -> 1 bits   = {bits_0_to_1}"
    )

    print(
        f"1 -> 0 bits   = {bits_1_to_0}"
    )


    if changed != 37:
        raise RuntimeError(
            "expected exactly 37 changed physical bytes"
        )


    if not changed_offsets:
        raise RuntimeError(
            "sector unexpectedly identical"
        )


    first_abs = (
        TARGET_ADDR
        + changed_offsets[0]
    )

    last_abs = (
        TARGET_ADDR
        + changed_offsets[-1]
    )


    print(
        f"first change  = 0x{first_abs:08X}"
    )

    print(
        f"last change   = 0x{last_abs:08X}"
    )


    if first_abs != 0x00249AEF:
        raise RuntimeError(
            "unexpected first physical change"
        )

    if last_abs != 0x00249B13:
        raise RuntimeError(
            "unexpected last physical change"
        )


    print(
        "[PASS] physical locality exactly matches S13.2B"
    )


    # -------------------------------------------------------------
    # 3. EXACT MTKCLIENT / LOADER
    # -------------------------------------------------------------

    banner(
        "3. EXACT MTKCLIENT / LOADER GATE"
    )

    loader = find_loader()

    print(
        "[PASS] exact loader SHA"
    )


    # -------------------------------------------------------------
    # 4. USER PREPARATION
    # -------------------------------------------------------------

    banner(
        "4. HARDWARE PREPARATION"
    )

    print(
        "Prepare phone exactly as for S12.10B7:"
    )

    print(
        "  1. USB disconnected"
    )

    print(
        "  2. phone powered off"
    )

    print(
        "  3. remove battery ~10 seconds"
    )

    print(
        "  4. reinstall battery"
    )

    print(
        "  5. do not power phone on"
    )

    print()

    input(
        "Press ENTER, then connect USB when the MediaTek session waits..."
    )


    # -------------------------------------------------------------
    # 5. D6 ONLY
    # -------------------------------------------------------------

    banner(
        "5. FRESH NATIVE D6 READ"
    )

    mtk = None

    try:

        mtk, legacy = connect_da(
            loader
        )

        print()
        print(
            "[D6-A] reading "
            f"0x{TARGET_ADDR:08X}.."
            f"0x{TARGET_ADDR+TARGET_LEN-1:08X}"
        )

        read_a = d6_read_4k_native(
            legacy,
            TARGET_ADDR,
        )

        print(
            f"[D6-A] SHA256 = "
            f"{sha256(read_a)}"
        )


        print()
        print(
            "[D6-B] reading same sector again"
        )

        read_b = d6_read_4k_native(
            legacy,
            TARGET_ADDR,
        )

        print(
            f"[D6-B] SHA256 = "
            f"{sha256(read_b)}"
        )


    finally:

        if mtk is not None:
            close_session(
                mtk
            )


    # -------------------------------------------------------------
    # 6. EXACT PRECONDITION
    # -------------------------------------------------------------

    banner(
        "6. EXACT PRECONDITION GATE"
    )


    if read_a != read_b:

        raise RuntimeError(
            "D6 A/B mismatch"
        )


    if read_a != before:

        print(
            f"EXPECTED BEFORE SHA = "
            f"{EXPECTED_BEFORE_SHA}"
        )

        print(
            f"ACTUAL D6 SHA       = "
            f"{sha256(read_a)}"
        )

        raise RuntimeError(
            "TARGET SECTOR DOES NOT MATCH "
            "THE EXPECTED ORIGINAL. "
            "FUTURE WRITE MUST ABORT."
        )


    print(
        "[PASS] D6 A == D6 B"
    )

    print(
        "[PASS] D6 sector == exact S13.2B BEFORE bytes"
    )

    print(
        "[PASS] current target SHA256 = "
        + sha256(
            read_a
        )
    )


    # -------------------------------------------------------------
    # 7. SAVE FRESH ROLLBACK
    # -------------------------------------------------------------

    banner(
        "7. SAVE FRESH ROLLBACK"
    )

    OUTDIR.mkdir(
        parents=True,
        exist_ok=True,
    )


    READ_A_FILE.write_bytes(
        read_a
    )

    READ_B_FILE.write_bytes(
        read_b
    )

    ROLLBACK_FILE.write_bytes(
        read_a
    )


    if (
        ROLLBACK_FILE.read_bytes()
        != before
    ):
        raise RuntimeError(
            "saved rollback verification failed"
        )


    print(
        f"READ A   = {READ_A_FILE}"
    )

    print(
        f"READ B   = {READ_B_FILE}"
    )

    print(
        f"ROLLBACK = {ROLLBACK_FILE}"
    )

    print(
        f"ROLLBACK SHA256 = "
        f"{sha256(read_a)}"
    )


    # -------------------------------------------------------------
    # 8. MANIFEST
    # -------------------------------------------------------------

    state = {
        "stage": "S13.2C",
        "device_access": True,
        "flash_write": False,
        "flash_erase": False,
        "d3_used": False,
        "d5_used": False,
        "d6_used": True,

        "target": {
            "start": TARGET_ADDR,
            "end": (
                TARGET_ADDR
                + TARGET_LEN
            ),
            "size": TARGET_LEN,
        },

        "expected_before_sha256":
            EXPECTED_BEFORE_SHA,

        "candidate_after_sha256":
            EXPECTED_AFTER_SHA,

        "fresh_d6_a_sha256":
            sha256(read_a),

        "fresh_d6_b_sha256":
            sha256(read_b),

        "fresh_matches_expected_before":
            read_a == before,

        "changed_bytes":
            changed,

        "zero_to_one_bits":
            bits_0_to_1,

        "one_to_zero_bits":
            bits_1_to_0,

        "first_change":
            first_abs,

        "last_change":
            last_abs,

        "rollback_file":
            str(
                ROLLBACK_FILE
            ),

        "write_authorized":
            False,

        "next_gate": (
            "S13.3 mutating harness must repeat "
            "fresh D6 exact-before check in same "
            "DA session immediately before D3+D5"
        ),
    }


    OUT_JSON.write_text(
        json.dumps(
            state,
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )


    # -------------------------------------------------------------
    # FINAL
    # -------------------------------------------------------------

    banner(
        "S13.2C RESULT"
    )

    print(
        "MT6261 / NOR IDENTITY       : PASS"
    )

    print(
        "TARGET ADDRESS              : "
        "0x00249000..0x00249FFF PASS"
    )

    print(
        "D6 READ A                   : PASS"
    )

    print(
        "D6 READ B                   : PASS"
    )

    print(
        "D6 A == D6 B                : PASS"
    )

    print(
        "FRESH D6 == EXPECTED BEFORE : PASS"
    )

    print(
        "ROLLBACK SAVED              : PASS"
    )

    print(
        "D3 USED                     : NO"
    )

    print(
        "D5 USED                     : NO"
    )

    print(
        "FLASH ERASE                 : NO"
    )

    print(
        "FLASH WRITE                 : NO"
    )

    print()
    print(
        "PRE-WRITE BASELINE REHEARSAL: PASS"
    )

    print()
    print(
        "WRITE AUTHORIZED            : NO"
    )

    print()
    print(
        "NEXT:"
    )

    print(
        "Build S13.3 one-sector firmware write harness."
    )

    print(
        "That harness MUST repeat the exact D6 "
        "precondition in the SAME DA session before D3+D5."
    )


if __name__ == "__main__":

    try:
        main()

    except KeyboardInterrupt:

        print(
            "\n[ABORT] interrupted",
            file=sys.stderr,
        )

        raise

    except BaseException as exc:

        print(
            f"\n[ABORT] "
            f"{type(exc).__name__}: "
            f"{exc}",
            file=sys.stderr,
        )

        raise

