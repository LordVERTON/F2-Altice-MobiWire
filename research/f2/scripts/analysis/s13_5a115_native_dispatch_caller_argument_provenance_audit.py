#!/usr/bin/env python3
"""S13.5A.115 — exact native-executor/resolver caller provenance.

Research-only. Read canonical ALICE/ZIMAGE, find exact raw Thumb BL encodings
in ALICE targeting TWO historically-proven native functions. Print small
callsite instruction windows and possible r0 sources as CANDIDATES, not proof
of an executable UI->app path. No firmware or device changes are possible.

This does NOT rescan the generic 0x102D9DC8 gateway, native resolver table
implementation, F02E4228 generic framework, or ROM padding/caves.
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
REPORT = "s13_5a115_native_dispatch_caller_argument_provenance_audit.txt"

# S11 confirmed semantics. This script audits new callers only.
TARGETS = {
    0x1034C7E4: "NATIVE_DYNAMIC_THEN_STATIC_RESOLVER",
    0x10336788: "NATIVE_REGISTERED_CALLBACK_EXECUTOR",
}
# A103/A104 pre-existing witnesses used ONLY as BL decoder sanity controls.
BL_GUARDS = (
    (0x1039CCC4, bytes.fromhex("50f7bcfa"), 0x102ED240),
    (0x10342E2C, bytes.fromhex("02f01cfa"), 0x10345268),
)
B702_REC = 0xF037BEA0
B703_REC = 0xF037BEB0
AUDIO_REC = 0xF037A600
B702_CHILDREN = 0xF0378720
RESOLVER_ROW_IMAGE = 0xF0345ED8
RESOLVER_ROW_AUDIO = 0xF0345F18


def fail(msg: str) -> None:
    raise RuntimeError("A115_ABORT: " + msg)


def read_image(path: Path, name: str, size: int, sha: str) -> bytes:
    if not path.is_file():
        fail(f"missing {name}: {path}")
    data = path.read_bytes()
    found = hashlib.sha256(data).hexdigest()
    if len(data) != size or found != sha:
        fail(f"{name} canonical guard mismatch size=0x{len(data):X} sha256={found}")
    return data


def read_at(buf: bytes, base: int, addr: int, count: int) -> bytes:
    off = addr - base
    if off < 0 or count < 0 or off + count > len(buf):
        fail(f"out-of-image read at 0x{addr:08X} count={count}")
    return buf[off:off + count]


def u16(buf: bytes, base: int, addr: int) -> int:
    return struct.unpack("<H", read_at(buf, base, addr, 2))[0]


def u32(buf: bytes, base: int, addr: int) -> int:
    return struct.unpack("<I", read_at(buf, base, addr, 4))[0]


def thumb_bl_target(addr: int, half1: int, half2: int) -> int | None:
    """Decode Thumb-2 immediate BL with signed 25-bit byte offset.

    Excludes BLX and B.W. Raw 4-byte patterns are not reachability proof.
    """
    if (half1 & 0xF800) != 0xF000 or (half2 & 0xD000) != 0xD000:
        return None
    s = (half1 >> 10) & 1
    j1 = (half2 >> 13) & 1
    j2 = (half2 >> 11) & 1
    i1 = 1 ^ (j1 ^ s)
    i2 = 1 ^ (j2 ^ s)
    value = (s << 24) | (i1 << 23) | (i2 << 22) | ((half1 & 0x03FF) << 12) | ((half2 & 0x07FF) << 1)
    if value & (1 << 24):
        value -= 1 << 25
    return (addr + 4 + value) & 0xFFFFFFFF


def encode_bl(addr: int, target: int) -> bytes:
    """Self-test only; never used on firmware output or binary modification."""
    offset = target - (addr + 4)
    if offset % 2 or not (-(1 << 24) <= offset < (1 << 24)):
        fail("self-test BL offset out of range")
    v = offset & ((1 << 25) - 1)
    s = (v >> 24) & 1
    i1 = (v >> 23) & 1
    i2 = (v >> 22) & 1
    j1 = 1 ^ (i1 ^ s)
    j2 = 1 ^ (i2 ^ s)
    h1 = 0xF000 | (s << 10) | ((v >> 12) & 0x3FF)
    h2 = 0xD000 | (j1 << 13) | (j2 << 11) | ((v >> 1) & 0x7FF)
    return struct.pack("<HH", h1, h2)


def controls(alice: bytes, zimage: bytes) -> None:
    for addr, expected, target in BL_GUARDS:
        actual = read_at(alice, ALICE_BASE, addr, 4)
        if actual != expected:
            fail(f"A103 BL witness at 0x{addr:08X}: expected {expected.hex()}, got {actual.hex()}")
        h1, h2 = struct.unpack("<HH", actual)
        if thumb_bl_target(addr, h1, h2) != target:
            fail(f"BL witness decoding at 0x{addr:08X} drifted")
    if (
        u16(zimage, ZIMAGE_BASE, B702_REC) != 0xB709
        or u16(zimage, ZIMAGE_BASE, B702_REC + 2) != 2
        or u32(zimage, ZIMAGE_BASE, B702_REC + 12) != B702_CHILDREN
        or u32(zimage, ZIMAGE_BASE, B703_REC + 12) != B702_CHILDREN + 4
        or u16(zimage, ZIMAGE_BASE, AUDIO_REC) != 0xB702
        or tuple(u16(zimage, ZIMAGE_BASE, B702_CHILDREN + i * 2) for i in range(3)) != (0x8569, 0x87ED, 0xA07B)
    ):
        fail("A114 B702/B703/Audio static controls drift")
    for ptr, ident, callback in (
        (RESOLVER_ROW_IMAGE, 0x87ED, 0xF02F3F9D),
        (RESOLVER_ROW_AUDIO, 0x8928, 0x1033D841),
    ):
        if u16(zimage, ZIMAGE_BASE, ptr) != ident or u32(zimage, ZIMAGE_BASE, ptr + 4) != callback:
            fail(f"A114 native resolver row changed at 0x{ptr:08X}")


def scan_native_calls(alice: bytes) -> dict[int, list[int]]:
    result = {target: [] for target in TARGETS}
    for offset in range(0, len(alice) - 3, 2):
        h1, h2 = struct.unpack_from("<HH", alice, offset)
        target = thumb_bl_target(ALICE_BASE + offset, h1, h2)
        if target in result:
            result[target].append(ALICE_BASE + offset)
    return result


def decoder() -> object | None:
    try:
        from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB
    except ImportError:
        return None
    machine = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
    machine.detail = True
    return machine


def annotated_window(buf: bytes, addr: int, md: object | None) -> list[str]:
    start = max(ALICE_BASE, addr - 0x40) & ~1
    stop = min(ALICE_BASE + len(buf), addr + 0x12) & ~1
    code = read_at(buf, ALICE_BASE, start, stop - start)
    if md is None:
        return [f"  WINDOW_CAPSTONE=ABSENT RAW_HEX_ONLY=0x{start:08X}:{code.hex()}"]
    parsed = list(md.disasm(code, start))
    # Choosing start=site-0x40 is NOT a proof of true instruction alignment,
    # and Capstone does not prove whether any decoded instruction is reachable.
    rows = [f"  WINDOW_DISASM_START=0x{start:08X} MODE=THUMB LINEAR_NOT_CFG"]
    for ins in parsed:
        if addr - 0x2C <= ins.address <= addr + 0xC:
            mark = "SITE" if ins.address == addr else "    "
            rows.append(f"  {mark} 0x{ins.address:08X} {ins.bytes.hex():<10} {ins.mnemonic:<7} {ins.op_str}")
    if not any(ins.address == addr and ins.mnemonic.lower() == "bl" for ins in parsed):
        rows.append("  CALLSITE_CAPSTONE_ALIGNED_BL=NO_OR_UNRESOLVED; raw pattern only")
    else:
        rows.append("  CALLSITE_CAPSTONE_ALIGNED_BL=YES_IN_HEURISTIC_LINEAR_WINDOW; STILL_NOT_CFG_PROOF")
    # Deterministic lexical indicators only; NOT a reaching-definition analysis.
    preceding = [ins for ins in parsed if addr - 0x28 <= ins.address < addr]
    hints = []
    for ins in preceding:
        op = ins.op_str.lower().replace(" ", "")
        if ins.mnemonic.lower().startswith("ldrh") and ("#0x18" in op or "#24" in op):
            hints.append(f"LDHR_OFFSET18@0x{ins.address:08X}")
        if "0x10315514" in op or "0x10319df8" in op:
            hints.append(f"MENU_NAV_HELPER_IMMEDIATE@0x{ins.address:08X}")
        if ins.mnemonic.lower() in {"mov", "movs", "ldrh", "ldr", "bl"} and op.startswith("r0,"):
            hints.append(f"R0_TEXT_PRECEDENT@0x{ins.address:08X}")
    rows.append("  R0_HINTS_LEXICAL_ONLY=" + (",".join(hints[-12:]) if hints else "NONE_IN_WINDOW"))
    return rows


def self_test() -> None:
    for address, raw, target in BL_GUARDS:
        h1, h2 = struct.unpack("<HH", raw)
        assert thumb_bl_target(address, h1, h2) == target
        assert encode_bl(address, target) == raw
    assert thumb_bl_target(0x1000, 0x0000, 0xD000) is None
    assert thumb_bl_target(0x1000, 0xF000, 0xC000) is None
    fake = bytearray(b"\x00" * 16)
    fake[2:6] = encode_bl(0x3002, 0x300A)
    hits = []
    for off in range(0, len(fake) - 3, 2):
        x, y = struct.unpack_from("<HH", fake, off)
        if thumb_bl_target(0x3000 + off, x, y) == 0x300A:
            hits.append(off)
    assert hits == [2]
    print("A115_SELF_TEST=PASS BL_SIGNED_DECODER_POSITIVE_WITNESSES_AND_SYNTHETIC_SCAN")


def evaluate(alice: bytes, zimage: bytes) -> str:
    controls(alice, zimage)
    hits = scan_native_calls(alice)
    md = decoder()
    lines = [
        "S13.5A.115 — EXACT ALICE NATIVE RESOLVER/EXECUTOR BL CALLER R0-PROVENANCE TRIAGE",
        "STRICTLY_OFFLINE=YES SOURCE_IMAGES_READ_ONLY=YES NO_PATCH_NO_USB_NO_PHONE_NO_FLASH=YES",
        "METHOD=EXACT_RAW_THUMB_BL_TARGETS_TWO_KNOWN_NATIVE_HELPERS_AND_BOUNDED_LOCAL_CALLSITE_WINDOWS",
        "LIMIT=RAW_PATTERNS_AND_HEURISTIC_LINEAR_THUMB_WINDOWS_NOT_EXECUTABLE_CFG_PROOF",
        f"ALICE_GUARD=PASS SIZE=0x{len(alice):X} SHA256={ALICE_SHA}",
        f"ZIMAGE_GUARD=PASS SIZE=0x{len(zimage):X} SHA256={ZIMAGE_SHA}",
        "A103_BL_POSITIVE_CONTROLS=PASS",
        "A114_B702_B703_AUDIO_NATIVE_RESOLVER_CONTROLS=PASS",
        "EXPECTED_SELECTED_ID_POSITIVE_CONTROL=0x87ED USER_VISIBLE_IMAGE_VIEWER",
        "TARGET_AUDIO_ID=0x8928 NATIVE_REGISTRATION_CALLBACK=0x1033D841",
        "FM_NUMERIC_ID=UNKNOWN; NO_FM_ID_GUESS",
        "NOT_SCANNED=GENERIC_GATEWAY_102D9DC8;FRAMEWORK_F02E4228;ROM_PADDING",
        "",
    ]
    for target, role in TARGETS.items():
        found = hits[target]
        lines += [
            f"=== CALLER_TARGET=0x{target:08X} ROLE={role} ===",
            f"RAW_THUMB_BL_CANDIDATES_ALICE={len(found)}",
            "NO_DIRECT_BL_HIT_CANNOT_DISPROVE_INDIRECT_OR_VENEER_CALLS=YES",
        ]
        for addr in found[:48]:
            raw = read_at(alice, ALICE_BASE, addr, 4)
            lines += [f"CALLSITE=0x{addr:08X} BYTES={raw.hex()} DECODED_TARGET=0x{target:08X}"]
            lines.extend(annotated_window(alice, addr, md))
        if len(found) > 48:
            lines.append(f"CALLSITE_LIST_TRUNCATED=YES TOTAL={len(found)} DISPLAYED=48")
        lines.append("")
    lines += [
        "=== DECISION ===",
        "STATIC_NATIVE_CALLBACK_8928_EXISTS=YES_A114",
        "STATIC_B702_ENUMERATION_8928_EXISTS=NO_A114",
        "MENU_SELECTED_87ED_TO_NATIVE_EXECUTOR_PROVEN=NO_STATIC_CALLSITE_SCAN_ONLY",
        "MENU_SELECTED_8928_TO_NATIVE_EXECUTOR_PROVEN=NO_STATIC_CALLSITE_SCAN_ONLY",
        "NATIVE_CALLER_R0_REACHING_DEFINITION=NOT_PROVEN_BY_LOCAL_WINDOWS",
        "NO_NEW_ROM_RELOCATION_STORAGE_FOUND_OR_PROPOSED=YES",
        "NEXT=REVIEW_EXACT_CALLSITE_OWNER_AND_REAL_SELECTED_ID_PROVENANCE_ONLY_IF_NEW_RELEVANT_EDGE",
        "IF_NO_MENU_DERIVED_CALLSITE=STOP_NATIVE_CALLSITE_XREF_DETOUR_USE_BETTER_UI_TRACE_EVIDENCE",
        "NO_BINARY_EDIT_NO_PATCH_NO_EMULATOR_EDIT_NO_PHONE=YES",
    ]
    return "\n".join(lines) + "\n"


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(r"C:\Users\verto\F2-Altice-MobiWire"))
    parser.add_argument("--out", type=Path)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    self_test()
    if args.self_test:
        return
    root = args.root
    out = args.out or root / "research/f2/work/reports" / REPORT
    a = read_image(root / "research/f2/work/extracted/altice_alice/alice-py.bin", "ALICE", ALICE_SIZE, ALICE_SHA)
    z = read_image(root / "research/f2/work/extracted/altice_platform/zimage.bin", "ZIMAGE", ZIMAGE_SIZE, ZIMAGE_SHA)
    report = evaluate(a, z)
    if not out.parent.is_dir():
        fail("missing report folder: " + str(out.parent))
    with out.open("x", encoding="utf-8", newline="\n") as handle:
        handle.write(report)
    print(f"A115_REPORT_CREATED={out} BYTES={out.stat().st_size}")
    print("A115_RESULT=REVIEW_NATIVE_CALLER_CANDIDATES_NO_UI_TO_AUDIO_PROOF_ASSUMED")


if __name__ == "__main__":
    main()
