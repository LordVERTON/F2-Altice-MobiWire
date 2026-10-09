#!/usr/bin/env python3
"""S13.5A.111 — read-only B702 child-array relocation feasibility.

No phone, USB/COM, patch, ROM modification, flash/repack, emulator edit,
Notepad, binary output, or automatic selection of supposedly free ROM bytes.

This is a STRUCTURAL feasibility report, not a patch recipe. Static array
presence does not prove that exposing an ID invokes its native callback.
"""
from __future__ import annotations

import argparse
import hashlib
from pathlib import Path
import struct

ALICE_BASE = 0x1024EC00
ALICE_SIZE = 0x157BB4
ALICE_SHA = "7246242b67afae0d13104452bc3257827cb778119b54e7a26fb7fb55993697ea"
ZIMAGE_BASE = 0xF023CA50
ZIMAGE_SIZE = 0x185E98
ZIMAGE_SHA = "85fba8c8ae8161e4c1f8ced7983ec30d48c54ab10e51c69fcdfb900aca220954"

RECORDS_BASE = 0xF0378760
RECORD_STRIDE = 0x10
RECORD_COUNT = 895
RANGE_DESCRIPTOR = 0xF037C08C
EXPECTED_RANGE_BASE = 0xF037BF54
EXPECTED_RANGE_COUNT = 52
EXPECTED_B702_CHILD_PTR = 0xF0378720
EXPECTED_B703_FIRST = 0xA07B
REPORT_NAME = "s13_5a111_b702_safe_relocation_feasibility_audit.txt"

# The following ID->dense-index mapping was already established in S13.5A.47.
KNOWN_INDEX = {0x8928: 490, 0xB700: 882, 0xB702: 884, 0xB703: 885, 0xB709: 891}
EXPECTED_ROOT_CHILDREN = (0xB702, 0xAF2A, 0xB707, 0x8321, 0xB6FE, 0xB6FD, 0x9639, 0xB700, 0xB705)
EXPECTED_B702_CHILDREN = (0x8569, 0x87ED)


def fail(message: str) -> None:
    raise RuntimeError("ABORT: " + message)


def take(data: bytes, base: int, address: int, length: int) -> bytes:
    offset = address - base
    if offset < 0 or length < 0 or offset + length > len(data):
        fail(f"out-of-image READ at 0x{address:08X} len={length}")
    return data[offset:offset + length]


def u16(data: bytes, base: int, address: int) -> int:
    return int.from_bytes(take(data, base, address, 2), "little")


def u32(data: bytes, base: int, address: int) -> int:
    return int.from_bytes(take(data, base, address, 4), "little")


def record(data: bytes, base: int, index: int) -> dict:
    address = RECORDS_BASE + index * RECORD_STRIDE
    take(data, base, address, RECORD_STRIDE)
    return {
        "index": index,
        "addr": address,
        "parent": u16(data, base, address),
        "count": u16(data, base, address + 2),
        "ptr": u32(data, base, address + 12),
        "raw": take(data, base, address, RECORD_STRIDE).hex(),
    }


def child_list(data: bytes, base: int, rec: dict, *, ceiling: int = 1024) -> list[int]:
    count, pointer = rec["count"], rec["ptr"]
    if count > ceiling:
        fail(f"implausible count {count} at index {rec['index']}")
    if count == 0:
        return []
    if pointer & 1:
        fail(f"unaligned pool pointer 0x{pointer:08X} at index {rec['index']}")
    block = take(data, base, pointer, count * 2)
    return list(struct.unpack("<" + "H" * count, block))


def overlap(a: int, b: int, c: int, d: int) -> bool:
    return a < d and c < b


def guarded_image(path: Path, label: str, size: int, sha: str) -> tuple[bytes, str]:
    if not path.is_file():
        fail(f"missing {label} {path}")
    contents = path.read_bytes()
    found = hashlib.sha256(contents).hexdigest()
    if len(contents) != size or found != sha:
        fail(f"{label} canonical guard FAIL length=0x{len(contents):X} sha256={found}")
    return contents, f"{label}_GUARD=PASS SIZE=0x{len(contents):X} SHA256={found}"


def self_test() -> None:
    sample = bytearray(0x200)
    base = 0x1000
    # Record using an explicit 16-byte layout, verified in isolation.
    sample[0x10:0x20] = struct.pack("<HHII", 0xB709, 2, 0, 0) + struct.pack("<I", 0x1090)
    assert len(sample[0x10:0x20]) == 16
    assert u16(sample, base, 0x1010) == 0xB709
    assert u16(sample, base, 0x1012) == 2
    assert u32(sample, base, 0x101C) == 0x1090
    sample[0x90:0x96] = struct.pack("<HHH", 0x8569, 0x87ED, 0xA07B)
    assert list(struct.unpack("<HH", take(sample, base, 0x1090, 4))) == [0x8569, 0x87ED]
    assert overlap(0x1090, 0x1096, 0x1094, 0x1098)
    assert not overlap(0x1090, 0x1094, 0x1094, 0x1098)
    assert RECORDS_BASE + KNOWN_INDEX[0xB702] * 16 == 0xF037BEA0
    assert tuple(struct.unpack("<HHH", struct.pack("<HHH", *EXPECTED_B702_CHILDREN, 0x8928))) == (0x8569, 0x87ED, 0x8928)
    print("A111_SELF_TEST=PASS RECORD_LAYOUT_POOL_ADJACENCY_OVERLAP_AND_EXPECTED_METADATA")


def evaluate(alice: bytes, zimage: bytes, guard_a: str, guard_z: str) -> str:
    out: list[str] = []
    def say(message: str = "") -> None:
        out.append(message)

    say("S13.5A.111 — B702 PACKED CHILDREN: OFFLINE RELOCATION FEASIBILITY GATE")
    say("STRICTLY_OFFLINE=YES INPUTS_READ_ONLY=YES REPORT_ONLY=YES NO_PATCH_GENERATED=YES")
    say("NO_PHONE_USB_COM_FLASH_REPACK_NOTEPAD_EMULATOR_EDIT=YES")
    say(guard_a)
    say(guard_z)
    say("METHOD=PINNED_ZIMAGE_STATIC_REGISTRY_LAYOUT_AND_ALL_895_CHILD_INTERVALS")
    say("HISTORICAL_SOURCE=S13.5A.47-49 static ID->dense indices; A.105-110 generic framework CLOSED")
    say("LIMIT=ROM_STRUCTURAL_ONLY; no runtime RAM, UI labels, dispatch ABI, checksum, FS mapping or code-cave safety proof")
    say()

    if u32(zimage, ZIMAGE_BASE, RANGE_DESCRIPTOR) != RECORDS_BASE:
        fail("static descriptor record-array base mismatch")
    if u32(zimage, ZIMAGE_BASE, RANGE_DESCRIPTOR + 4) != EXPECTED_RANGE_BASE:
        fail("static descriptor range-array pointer mismatch")
    if u16(zimage, ZIMAGE_BASE, RANGE_DESCRIPTOR + 8) != EXPECTED_RANGE_COUNT:
        fail("static descriptor range count (u16) mismatch")
    say("=== A. STATIC DESCRIPTOR / KNOWN ID RECORDS ===")
    say(f"DESCRIPTOR=0x{RANGE_DESCRIPTOR:08X} RECORDS=0x{RECORDS_BASE:08X} STRIDE=0x{RECORD_STRIDE:X} COUNT={RECORD_COUNT}")
    say(f"RANGE_PTR=0x{EXPECTED_RANGE_BASE:08X} RANGE_COUNT={EXPECTED_RANGE_COUNT} GUARD=PASS")

    known = {}
    for ident, idx in KNOWN_INDEX.items():
        rec = record(zimage, ZIMAGE_BASE, idx)
        known[ident] = rec
        say(f"ID=0x{ident:04X} DENSE={idx} RECORD=0x{rec['addr']:08X} PARENT=0x{rec['parent']:04X} COUNT={rec['count']} CHILD_PTR=0x{rec['ptr']:08X} RAW={rec['raw']}")
    b702 = known[0xB702]
    b703 = known[0xB703]
    b709 = known[0xB709]
    audio = known[0x8928]
    if b702["parent"] != 0xB709 or b702["count"] != 2 or b702["ptr"] != EXPECTED_B702_CHILD_PTR:
        fail("B702 parent/count/child-pointer mismatch; abort rather than reinterpret")
    if audio["parent"] != 0xB702:
        fail("Audio ID 8928 static parent differs from historical evidence")
    if b709["count"] != len(EXPECTED_ROOT_CHILDREN):
        fail("B709 root child count mismatch")
    root_children = tuple(child_list(zimage, ZIMAGE_BASE, b709))
    if root_children != EXPECTED_ROOT_CHILDREN:
        fail("B709 root children differ from canonical topology")
    children = tuple(child_list(zimage, ZIMAGE_BASE, b702))
    if children != EXPECTED_B702_CHILDREN:
        fail("B702 two-child sequence mismatch")
    following = u16(zimage, ZIMAGE_BASE, b702["ptr"] + b702["count"] * 2)
    if following != EXPECTED_B703_FIRST:
        fail("expected adjacent B703 first child 0xA07B not present")
    say()
    say("=== B. B702 AND IMMEDIATE B703 ADJACENCY ===")
    say("ROOT_B709_CHILDREN=" + ",".join(f"0x{x:04X}" for x in root_children))
    say("B702_CHILDREN=" + ",".join(f"0x{x:04X}" for x in children))
    say(f"B702_POOL=[0x{b702['ptr']:08X},0x{b702['ptr']+4:08X})")
    say(f"NEXT_HALFWORD_0x{b702['ptr']+4:08X}=0x{following:04X}")
    say(f"B703_CHILD_PTR=0x{b703['ptr']:08X} B703_COUNT={b703['count']}")
    if b703["ptr"] == b702["ptr"] + 4 and b703["count"]:
        say("ADJACENCY=CONFIRMED_BY_B703_RECORD_POINTER")
    else:
        say("ADJACENCY=ONLY_SEQUENTIAL_HALFWORD_MATCH; B703_RECORD_POINTER_NOT_CONFIRMED")

    say()
    say("=== C. ARRAY OWNERSHIP / COLLISION AGAINST ALL RECORDS ===")
    extension_start = b702["ptr"] + 4
    extension_end = extension_start + 2
    invalid_nonzero = 0
    alias_old = []
    extension_owners = []
    many_pool_records = 0
    for i in range(RECORD_COUNT):
        rec = record(zimage, ZIMAGE_BASE, i)
        if rec["count"] == 0:
            continue
        # All positive counts are checked for valid ROM interval. Invalid/non-ROM pointers
        # are reported as unclassified (never silently assumed free).
        begin = rec["ptr"]
        end = begin + 2 * rec["count"]
        if begin < ZIMAGE_BASE or end > ZIMAGE_BASE + len(zimage) or end < begin or begin & 1:
            invalid_nonzero += 1
            continue
        many_pool_records += 1
        if overlap(begin, end, b702["ptr"], b702["ptr"] + 4) and i != b702["index"]:
            alias_old.append((i, begin, end))
        if overlap(begin, end, extension_start, extension_end) and i != b702["index"]:
            extension_owners.append((i, begin, end))
    say(f"RECORD_TOTAL={RECORD_COUNT} IN_IMAGE_NONEMPTY_ARRAYS={many_pool_records} UNCLASSIFIED_NONEMPTY_ARRAYS={invalid_nonzero}")
    say(f"B702_OLD_ARRAY_OTHER_OWNERS={len(alias_old)}")
    for i, begin, end in alias_old[:30]:
        say(f"  SHARED_OLD_ARRAY INDEX={i} SPAN=[0x{begin:08X},0x{end:08X})")
    say(f"IN_PLACE_APPEND_OVERLAP_COUNT={len(extension_owners)}")
    for i, begin, end in extension_owners[:30]:
        say(f"  APPEND_COLLISION INDEX={i} SPAN=[0x{begin:08X},0x{end:08X})")
    if extension_owners:
        say("IN_PLACE_COUNT_ONLY=UNSAFE_CONCRETE_OVERLAP")
    else:
        say("IN_PLACE_COUNT_ONLY=NOT_PROVEN_SAFE (adjacent data and aliasing cannot be excluded)")
    say("NOTE=nonempty record arrays outside this mapped ZIMAGE are not treated as proof of free space")

    say()
    say("=== D. DESIGN CONSTRAINTS — NOT A BINARY PATCH OR ALLOCATION ===")
    say("ABSTRACT_NEW_CHILDREN=0x8569,0x87ED,0x8928")
    say("ABSTRACT_NEW_BYTES_LITTLE_ENDIAN=6985ed872889")
    say("MIN_NEW_ARRAY_BYTES=6; RECOMMENDED_LOGICAL_ALLOCATION_AT_LEAST_8_ALIGNED_4=YES")
    say("RELOCATION_IN_PRINCIPLE=REQUIRES_VERIFIED_NEW_OWNED_DATA_STORAGE_AND_COUNT_AND_POINTER_UPDATE")
    say("MINIMUM_LOGICAL_FIELDS_TO_RECONCILE=B702.count(+2) AND B702.child_ptr(+0xC) PLUS_NEW_ARRAY_CONTENT")
    say("CANDIDATE_FREE_ROM_ADDRESS=NOT_PROPOSED")
    say("FREE_SPACE_VERIFIED=NO; BOOT_RELOCATION_AND_FLASH_LAYOUT_VERIFIED=NO; DATA_POINTER_REBASE_VERIFIED=NO")
    say("RUNTIME_F007F044_SOURCE_EQUALS_STATIC_RECORD_PROVEN_HERE=NO")
    say("NO_PATCH_BYTES_FOR_FIRMWARE_RECORDS_EMITTED=YES")
    say()
    say("=== E. UI -> ACTION -> AUDIO GATE ===")
    say(f"NATIVE_AUDIO_0x8928_RECORD_PARENT=0x{audio['parent']:04X} STATIC_RECORD_CONFIRMED=YES")
    say("NATIVE_AUDIO_REGISTRATION_CALLBACK=0x1033D841 HISTORICALLY_PROVEN_S11_S13_NOT_REAUDITED")
    say("B702_8928_CHILD_ENUMERATED=NO")
    say("VISIBLE_MENU_ID_TO_SELECTED_ACTION_AND_AUDIO_CALLBACK=UNPROVEN")
    say("FM_RADIO_NUMERIC_ROM_ID=UNKNOWN; NEVER_IDENTIFY_8569_WITH_FM_WITHOUT_RUNTIME_OR_CODE_PROOF")
    say("OLD_IMAGE_VIEWER_REDIRECT_PATCH=FAILED_FUNCTIONALLY; NOT_REPROPOSED")
    say("PHYSICAL_PATCH_AUTHORIZED=NO")
    say()
    say("=== DECISION ===")
    if extension_owners:
        say("SAFE_IN_PLACE_APPEND=NO; collision with other static child lists")
    else:
        say("SAFE_IN_PLACE_APPEND=NO_PROOF; count extension must NOT be used")
    say("RELOCATION_PROPOSAL=CONDITIONAL_ONLY; no reserved ROM space identified or verified")
    say("IMPLEMENTATION_READY=NO; requires (1) UI/action proof (2) trustworthy relocated storage (3) pointer and image-integrity model")
    say("NO_PHONE_USB_COM_FLASH_PATCH_REPACK=YES")
    return "\n".join(out) + "\n"


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(r"C:\Users\verto\F2-Altice-MobiWire"))
    parser.add_argument("--out", type=Path, default=None)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    self_test()
    if args.self_test:
        return
    root: Path = args.root
    alice_path = root / "research/f2/work/extracted/altice_alice/alice-py.bin"
    zimage_path = root / "research/f2/work/extracted/altice_platform/zimage.bin"
    out = args.out if args.out is not None else root / "research/f2/work/reports" / REPORT_NAME
    alice, a_guard = guarded_image(alice_path, "ALICE", ALICE_SIZE, ALICE_SHA)
    zimage, z_guard = guarded_image(zimage_path, "ZIMAGE", ZIMAGE_SIZE, ZIMAGE_SHA)
    report = evaluate(alice, zimage, a_guard, z_guard)
    if not out.parent.is_dir():
        fail(f"report directory missing {out.parent}")
    with out.open("x", encoding="utf-8", newline="\n") as fp:
        fp.write(report)
    print(f"A111_REPORT_CREATED={out} BYTES={out.stat().st_size}")
    print("A111_RESULT=STRUCTURAL_FEASIBILITY_REPORT_ONLY_REVIEW_REQUIRED")


if __name__ == "__main__":
    main()
