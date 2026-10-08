#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
S13.4E - true Image Viewer registration-stub POC audit

OFFLINE ONLY.
NO PHONE ACCESS.
NO BROM / DA / D6 / D3 / D5.
NO FLASH WRITE.
NO VIVA REPACK.
NO PHYSICAL FIRMWARE CANDIDATE.

This stage only:
  1. validates canonical ALICE + ZIMAGE;
  2. validates the static resolver rows:
       0x8313 -> F02F3F85
       0x8321 -> F02F3F85
       0x8928 -> 1033D841
  3. validates the true Image Viewer registration stub at F02F3F84;
  4. validates its literal F02F3F98 == F0301C8D;
  5. compares it with Audio registration 1033D840 -> 1033E815;
  6. builds ONE LOGICAL, DECOMPRESSED ZIMAGE candidate:
       F02F3F98: F0301C8D -> 1033E815
  7. proves the logical candidate differs by exactly four bytes.

The output is NOT flashable.
"""

from pathlib import Path
import hashlib
import json
import struct
import sys

from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_LITTLE_ENDIAN

ROOT = Path.cwd()

ALICE_PATH = ROOT / "research/f2/work/extracted/altice_alice/alice-py.bin"
ZIMAGE_PATH = ROOT / "research/f2/work/extracted/altice_platform/zimage.bin"
OUTDIR = ROOT / "research/f2/work/candidates/s13_4e"
REPORT = ROOT / "research/f2/work/reports/s13_4e_true_image_registration_poc_audit.txt"

ALICE_BASE = 0x1024EC00
ZIMAGE_BASE = 0xF023CA50

ALICE_SIZE = 0x157BB4
ZIMAGE_SIZE = 0x185E98

ALICE_SHA = "7246242b67afae0d13104452bc3257827cb778119b54e7a26fb7fb55993697ea"
ZIMAGE_SHA = "85fba8c8ae8161e4c1f8ced7983ec30d48c54ab10e51c69fcdfb900aca220954"

TABLE = 0xF0345E68
TABLE_COUNT = 58
TABLE_STRIDE = 8

IMAGE_ID_A = 0x8313
IMAGE_ID_B = 0x8321
AUDIO_ID = 0x8928

IMAGE_CALLBACK = 0xF02F3F85
AUDIO_CALLBACK = 0x1033D841

IMAGE_STUB = 0xF02F3F84
IMAGE_LITERAL = 0xF02F3F98
IMAGE_ORIGINAL_PTR = 0xF0301C8D

AUDIO_STUB = 0x1033D840
AUDIO_LITERAL = 0x1033D85C
AUDIO_INIT_PTR = 0x1033E815

IMAGE_TARGET_CODE = IMAGE_ORIGINAL_PTR & ~1
AUDIO_TARGET_CODE = AUDIO_INIT_PTR & ~1

md = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_LITTLE_ENDIAN)
md.detail = False


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def banner(title: str):
    print()
    print("=" * 120)
    print(title)
    print("=" * 120)


def off(base: int, addr: int) -> int:
    return addr - base


def require(cond: bool, message: str):
    if not cond:
        raise RuntimeError(message)
    print("[PASS]", message)


def u32(data: bytes, base: int, addr: int) -> int:
    o = off(base, addr)
    if o < 0 or o + 4 > len(data):
        raise RuntimeError(f"u32 out of bounds @0x{addr:08X}")
    return struct.unpack_from("<I", data, o)[0]


def all_u32_positions(data: bytes, value: int):
    pat = struct.pack("<I", value)
    out = []
    pos = 0
    while True:
        pos = data.find(pat, pos)
        if pos < 0:
            break
        out.append(pos)
        pos += 1
    return out


def disasm(data: bytes, base: int, start: int, size: int):
    o = off(base, start)
    if o < 0 or o + size > len(data):
        raise RuntimeError(f"disasm out of bounds @0x{start:08X}")
    for insn in md.disasm(data[o:o+size], start):
        print(
            f"0x{insn.address:08X}: "
            f"{insn.bytes.hex(' '):<14} "
            f"{insn.mnemonic:<8} {insn.op_str}"
        )


def table_rows(zimage: bytes):
    base_off = off(ZIMAGE_BASE, TABLE)
    require(base_off >= 0, "static table offset in ZIMAGE")
    require(
        base_off + TABLE_COUNT * TABLE_STRIDE <= len(zimage),
        "static table fully inside ZIMAGE",
    )

    rows = {}
    for i in range(TABLE_COUNT):
        roff = base_off + i * TABLE_STRIDE
        rid, field2, callback = struct.unpack_from("<HHI", zimage, roff)
        rows.setdefault(rid, []).append({
            "index": i,
            "runtime": ZIMAGE_BASE + roff,
            "field2": field2,
            "callback": callback,
            "raw": zimage[roff:roff+8].hex(" "),
        })
    return rows


def show_row(rows, rid, expected_callback, label):
    matches = rows.get(rid, [])
    require(len(matches) == 1, f"{label} has exactly one static resolver row")
    row = matches[0]
    require(row["field2"] == 0, f"{label} field2 == 0")
    require(
        row["callback"] == expected_callback,
        f"{label} callback == 0x{expected_callback:08X}",
    )
    print(
        f"  {label}: row={row['index']} "
        f"addr=0x{row['runtime']:08X} "
        f"callback=0x{row['callback']:08X}"
    )
    print(f"  raw={row['raw']}")
    return row


def diff_ranges(a: bytes, b: bytes):
    if len(a) != len(b):
        raise RuntimeError("diff length mismatch")
    positions = [i for i, (x, y) in enumerate(zip(a, b)) if x != y]
    if not positions:
        return [], positions

    ranges = []
    start = prev = positions[0]
    for p in positions[1:]:
        if p == prev + 1:
            prev = p
            continue
        ranges.append((start, prev))
        start = prev = p
    ranges.append((start, prev))
    return ranges, positions


def main():
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")

    alice = ALICE_PATH.read_bytes()
    zimage = ZIMAGE_PATH.read_bytes()

    OUTDIR.mkdir(parents=True, exist_ok=True)
    REPORT.parent.mkdir(parents=True, exist_ok=True)

    f = REPORT.open("w", encoding="utf-8")
    real_stdout = sys.stdout

    class Tee:
        def write(self, s):
            real_stdout.write(s)
            f.write(s)
            return len(s)
        def flush(self):
            real_stdout.flush()
            f.flush()

    sys.stdout = Tee()

    try:
        banner("S13.4E - TRUE IMAGE REGISTRATION-STUB POC AUDIT")
        print("OFFLINE ONLY")
        print("PHONE ACCESSED : NO")
        print("FLASH MODIFIED : NO")
        print("PHYSICAL CANDIDATE : NO")
        print()

        require(len(alice) == ALICE_SIZE, f"ALICE size = 0x{ALICE_SIZE:X}")
        require(sha256(alice) == ALICE_SHA, "canonical ALICE SHA256")
        require(len(zimage) == ZIMAGE_SIZE, f"ZIMAGE size = 0x{ZIMAGE_SIZE:X}")
        require(sha256(zimage) == ZIMAGE_SHA, "canonical ZIMAGE SHA256")

        banner("A. STATIC RESOLVER ROWS")
        rows = table_rows(zimage)
        row_a = show_row(rows, IMAGE_ID_A, IMAGE_CALLBACK, "IMAGE_A 0x8313")
        row_b = show_row(rows, IMAGE_ID_B, IMAGE_CALLBACK, "IMAGE_B 0x8321")
        row_audio = show_row(rows, AUDIO_ID, AUDIO_CALLBACK, "AUDIO 0x8928")

        banner("B. TRUE IMAGE VIEWER REGISTRATION STUB")
        image_lit = u32(zimage, ZIMAGE_BASE, IMAGE_LITERAL)
        require(
            image_lit == IMAGE_ORIGINAL_PTR,
            f"F02F3F98 == 0x{IMAGE_ORIGINAL_PTR:08X}",
        )
        print(f"IMAGE_STUB    = 0x{IMAGE_STUB:08X}")
        print(f"IMAGE_LITERAL = 0x{IMAGE_LITERAL:08X}")
        print(f"ZIMAGE+       = 0x{off(ZIMAGE_BASE, IMAGE_LITERAL):X}")
        print(f"IMAGE_PTR     = 0x{image_lit:08X}")
        print()
        disasm(zimage, ZIMAGE_BASE, IMAGE_STUB, 0x18)

        banner("C. IMAGE TARGET WRAPPER")
        print(f"Thumb pointer = 0x{IMAGE_ORIGINAL_PTR:08X}")
        print(f"Code address  = 0x{IMAGE_TARGET_CODE:08X}")
        disasm(zimage, ZIMAGE_BASE, IMAGE_TARGET_CODE, 0x50)

        banner("D. AUDIO REGISTRATION STUB / INIT WRAPPER")
        audio_lit = u32(alice, ALICE_BASE, AUDIO_LITERAL)
        require(
            audio_lit == AUDIO_INIT_PTR,
            f"1033D85C == 0x{AUDIO_INIT_PTR:08X}",
        )
        print()
        disasm(alice, ALICE_BASE, AUDIO_STUB, 0x24)

        print()
        print(f"AUDIO init pointer = 0x{AUDIO_INIT_PTR:08X}")
        disasm(alice, ALICE_BASE, AUDIO_TARGET_CODE, 0x18)

        banner("E. POINTER OCCURRENCE CENSUS")
        image_ptr_z = all_u32_positions(zimage, IMAGE_ORIGINAL_PTR)
        image_ptr_a = all_u32_positions(alice, IMAGE_ORIGINAL_PTR)
        audio_ptr_z = all_u32_positions(zimage, AUDIO_INIT_PTR)
        audio_ptr_a = all_u32_positions(alice, AUDIO_INIT_PTR)

        print(f"F0301C8D in ZIMAGE : {len(image_ptr_z)}")
        for x in image_ptr_z:
            print(f"  ZIMAGE+0x{x:X} runtime=0x{ZIMAGE_BASE+x:08X}")
        print(f"F0301C8D in ALICE  : {len(image_ptr_a)}")
        for x in image_ptr_a:
            print(f"  ALICE+0x{x:X} runtime=0x{ALICE_BASE+x:08X}")
        print(f"1033E815 in ZIMAGE : {len(audio_ptr_z)}")
        for x in audio_ptr_z:
            print(f"  ZIMAGE+0x{x:X} runtime=0x{ZIMAGE_BASE+x:08X}")
        print(f"1033E815 in ALICE  : {len(audio_ptr_a)}")
        for x in audio_ptr_a:
            print(f"  ALICE+0x{x:X} runtime=0x{ALICE_BASE+x:08X}")

        require(
            off(ZIMAGE_BASE, IMAGE_LITERAL) in image_ptr_z,
            "true Image literal is included in F0301C8D ZIMAGE occurrences",
        )

        banner("F. BUILD LOGICAL ZIMAGE CANDIDATE ONLY")
        candidate = bytearray(zimage)
        patch_off = off(ZIMAGE_BASE, IMAGE_LITERAL)

        original_bytes = bytes(candidate[patch_off:patch_off+4])
        expected_original_bytes = struct.pack("<I", IMAGE_ORIGINAL_PTR)
        replacement_bytes = struct.pack("<I", AUDIO_INIT_PTR)

        require(
            original_bytes == expected_original_bytes,
            "patch site original bytes exact",
        )

        candidate[patch_off:patch_off+4] = replacement_bytes
        candidate = bytes(candidate)

        ranges, positions = diff_ranges(zimage, candidate)

        require(len(candidate) == len(zimage), "candidate ZIMAGE size unchanged")
        require(len(positions) == 4, "candidate differs by exactly 4 bytes")
        require(
            ranges == [(patch_off, patch_off + 3)],
            "candidate has exactly one 4-byte diff range",
        )
        require(
            u32(candidate, ZIMAGE_BASE, IMAGE_LITERAL) == AUDIO_INIT_PTR,
            f"candidate F02F3F98 == 0x{AUDIO_INIT_PTR:08X}",
        )

        candidate_path = OUTDIR / "zimage-s13_4e-true-image-slot-audio-poc.bin"
        manifest_path = OUTDIR / "manifest.json"

        candidate_path.write_bytes(candidate)

        manifest = {
            "stage": "S13.4E",
            "status": "LOGICAL_ZIMAGE_ONLY_NOT_FLASHABLE",
            "phone_accessed": False,
            "flash_modified": False,
            "canonical_zimage": {
                "path": str(ZIMAGE_PATH),
                "size": len(zimage),
                "sha256": sha256(zimage),
                "base": f"0x{ZIMAGE_BASE:08X}",
            },
            "candidate_zimage": {
                "path": str(candidate_path),
                "size": len(candidate),
                "sha256": sha256(candidate),
            },
            "static_resolver": {
                "image_a": row_a,
                "image_b": row_b,
                "audio": row_audio,
            },
            "patch": {
                "runtime_address": f"0x{IMAGE_LITERAL:08X}",
                "zimage_offset": f"0x{patch_off:X}",
                "old_pointer": f"0x{IMAGE_ORIGINAL_PTR:08X}",
                "new_pointer": f"0x{AUDIO_INIT_PTR:08X}",
                "old_bytes": original_bytes.hex(" "),
                "new_bytes": replacement_bytes.hex(" "),
                "changed_bytes": len(positions),
                "diff_range": [
                    f"0x{ZIMAGE_BASE + ranges[0][0]:08X}",
                    f"0x{ZIMAGE_BASE + ranges[0][1]:08X}",
                ],
            },
            "limitations": [
                "No ZIMAGE LZMA recompression performed.",
                "No VIVA repack performed.",
                "No physical flash sector mapping derived in this stage.",
                "Runtime behavior remains unproven.",
                "Candidate must not be flashed.",
            ],
        }

        manifest_path.write_text(
            json.dumps(manifest, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )

        print()
        print(f"ORIGINAL ZIMAGE SHA = {sha256(zimage)}")
        print(f"CANDIDATE ZIMAGE SHA = {sha256(candidate)}")
        print(f"PATCH OFFSET         = ZIMAGE+0x{patch_off:X}")
        print(
            f"PATCH RUNTIME        = 0x{IMAGE_LITERAL:08X}: "
            f"0x{IMAGE_ORIGINAL_PTR:08X} -> 0x{AUDIO_INIT_PTR:08X}"
        )
        print(f"OLD BYTES            = {original_bytes.hex(' ')}")
        print(f"NEW BYTES            = {replacement_bytes.hex(' ')}")
        print(f"CHANGED BYTES        = {len(positions)}")
        print(f"CANDIDATE             = {candidate_path}")
        print(f"MANIFEST              = {manifest_path}")

        banner("S13.4E RESULT")
        print("CANONICAL ALICE / ZIMAGE       : PASS")
        print("STATIC IMAGE/AUDIO ROWS         : PASS")
        print("TRUE IMAGE REGISTRATION STUB    : PASS")
        print("IMAGE ORIGINAL POINTER          : PASS")
        print("AUDIO INIT POINTER              : PASS")
        print("LOGICAL 4-BYTE ZIMAGE CANDIDATE : PASS")
        print("ZIMAGE RECOMPRESS               : NOT DONE")
        print("VIVA REPACK                     : NOT DONE")
        print("PHYSICAL SECTOR CANDIDATE       : NOT DONE")
        print("PHONE ACCESSED                  : NO")
        print("FLASH MODIFIED                  : NO")
        print()
        print("S13.4E OFFLINE LOGICAL GATE: PASS")
        print("HARDWARE WRITE AUTHORIZED: NO")
        print(f"REPORT = {REPORT}")

    finally:
        sys.stdout = real_stdout
        f.close()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
