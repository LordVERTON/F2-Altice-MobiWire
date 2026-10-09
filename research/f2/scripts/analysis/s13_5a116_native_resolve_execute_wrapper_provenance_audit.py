#!/usr/bin/env python3
"""S13.5A.116 — offline, fail-closed audit of the NEW A115 resolver+BLX wrapper.

Only: Thumb 0x102F37C4, its immediate ARM veneer at 0x102FC804, and exact
BL/pointer references to this wrapper in canonical ALICE/ZIMAGE. Never edits
firmware, executes firmware, touches phone/USB/COM, or chooses ROM free space.
The report explicitly distinguishes exact bytes, syntactic calls, and UI proof.
"""
from __future__ import annotations

import argparse
import hashlib
from pathlib import Path
import struct

ALICE_BASE, ALICE_SIZE = 0x1024EC00, 0x157BB4
ALICE_SHA = "7246242b67afae0d13104452bc3257827cb778119b54e7a26fb7fb55993697ea"
ZIMAGE_BASE, ZIMAGE_SIZE = 0xF023CA50, 0x185E98
ZIMAGE_SHA = "85fba8c8ae8161e4c1f8ced7983ec30d48c54ab10e51c69fcdfb900aca220954"
WRAPPER = 0x102F37C4
ARM_ENTRY = 0x102FC804
RESOLVER = 0x1034C7E4
EXECUTOR = 0x10336788
REPORT = "s13_5a116_native_resolve_execute_wrapper_provenance_audit.txt"

# Exact A115 user report instruction bytes, not guessed.
ANCHORS = {
    0x102F37C4: "10b5",  # PUSH {r4,lr}
    0x102F37C6: "0181",  # STRH r1,[r0,#8]
    0x102F37C8: "c088",  # LDRH r0,[r0,#6]
    0x102F37CA: "0028",  # CMP r0,#0
    0x102F37CC: "08d0",  # BEQ return
    0x102F37CE: "0904",  # LSLS r1,r1,#16
    0x102F37D0: "090c",  # LSRS r1,r1,#16
    0x102F37D2: "09f018e8",  # BLX immediate -> ARM veneer
    0x102F37D6: "59f005f8",  # BL resolver
    0x102F37DA: "0028",  # CMP r0,#0
    0x102F37DC: "00d0",  # BEQ return
    0x102F37DE: "8047",  # BLX r0
    0x102F37E0: "10bd",  # POP {r4,pc}
    0x10336788: "f8b5",  # existing native executor entry
    0x1033678C: "16f02af8",  # executor's BL to same resolver
}


def fail(msg: str) -> None:
    raise RuntimeError("A116_ABORT: " + msg)


def guarded(root: Path, relative: str, label: str, size: int, expected: str) -> bytes:
    path = root / relative
    if not path.is_file():
        fail(f"{label} missing: {path}")
    blob = path.read_bytes()
    digest = hashlib.sha256(blob).hexdigest()
    if len(blob) != size or digest != expected:
        fail(f"{label} canonical guard FAIL size={len(blob):#x} sha={digest}")
    return blob


def take(buf: bytes, base: int, addr: int, length: int) -> bytes:
    offset = addr - base
    if offset < 0 or length < 0 or offset + length > len(buf):
        fail(f"address outside bounded image: 0x{addr:08X} length={length}")
    return buf[offset:offset + length]


def u32(buf: bytes, base: int, addr: int) -> int:
    return struct.unpack("<I", take(buf, base, addr, 4))[0]


def decode_thumb_bl(addr: int, x: int, y: int) -> int | None:
    """Thumb-2 BL (not BLX), signed 25-bit offset. Syntactic only."""
    if (x & 0xF800) != 0xF000 or (y & 0xD000) != 0xD000:
        return None
    s, j1, j2 = (x >> 10) & 1, (y >> 13) & 1, (y >> 11) & 1
    i1, i2 = 1 ^ j1 ^ s, 1 ^ j2 ^ s
    v = (s << 24) | (i1 << 23) | (i2 << 22) | ((x & 0x03FF) << 12) | ((y & 0x07FF) << 1)
    if v & (1 << 24):
        v -= 1 << 25
    return (addr + 4 + v) & 0xFFFFFFFF


def find_bl_to_wrapper(alice: bytes) -> list[int]:
    hits = []
    for off in range(0, len(alice) - 3, 2):
        a, b = struct.unpack_from("<HH", alice, off)
        if decode_thumb_bl(ALICE_BASE + off, a, b) == WRAPPER:
            hits.append(ALICE_BASE + off)
    return hits


def raw_pointer_refs(images: tuple[tuple[str, bytes, int], ...], limit: int = 80):
    targets = {WRAPPER: [], WRAPPER | 1: []}
    counts = {WRAPPER: 0, WRAPPER | 1: 0}
    for name, blob, base in images:
        for off in range(len(blob) - 3):  # all raw byte alignments
            value = struct.unpack_from("<I", blob, off)[0]
            if value in targets:
                counts[value] += 1
                if len(targets[value]) < limit:
                    targets[value].append((name, base + off))
    return counts, targets


def disasm_at(md, blob: bytes, base: int, addr: int, size: int):
    return list(md.disasm(take(blob, base, addr, size), addr))


def resolve_arm_veneer(alice: bytes, md_arm, md_thumb):
    """Only one strict ARM `ldr pc,[pc,#imm]` literal veneer (no speculated targets)."""
    from capstone.arm import ARM_OP_MEM, ARM_OP_REG, ARM_REG_PC
    ins = disasm_at(md_arm, alice, ALICE_BASE, ARM_ENTRY, 4)
    if len(ins) != 1 or ins[0].size != 4:
        return ["ARM_VENEER=DECODE_FAILURE"], None
    first = ins[0]
    lines = [f"ARM_VENEER_INSN=0x{first.address:08X} {first.bytes.hex()} {first.mnemonic} {first.op_str}"]
    if first.mnemonic.lower() != "ldr" or len(first.operands) < 2:
        return lines + ["ARM_VENEER=NOT_A_SINGLE_LDR_PC_LITERAL; TARGET_UNKNOWN"], None
    a, b = first.operands[:2]
    if (a.type != ARM_OP_REG or a.reg != ARM_REG_PC or b.type != ARM_OP_MEM or b.mem.base != ARM_REG_PC or b.mem.index != 0):
        return lines + ["ARM_VENEER=NONSTANDARD_PC_REGISTER_TRANSFER; TARGET_UNKNOWN"], None
    cell = (ARM_ENTRY + 8 + b.mem.disp) & 0xFFFFFFFF
    if not ALICE_BASE <= cell <= ALICE_BASE + len(alice) - 4:
        return lines + ["ARM_VENEER=PC_LITERAL_OUTSIDE_ALICE; TARGET_UNKNOWN"], None
    target = u32(alice, ALICE_BASE, cell)
    lines.append(f"ARM_PC_LITERAL_CELL=0x{cell:08X} VALUE=0x{target:08X}")
    lines.append("ARM_INTERWORKING_RESOLVED=YES SINGLE_LITERAL_VENEER_ONLY")
    return lines, target


def self_test() -> None:
    assert len(ANCHORS) == 15
    assert ANCHORS[0x102F37D2] == "09f018e8"
    assert ANCHORS[0x102F37DE] == "8047"
    assert sum(len(bytes.fromhex(v)) for v in ANCHORS.values()) == 36
    for addr, raw, expected in ((0x102F37D6, "59f005f8", RESOLVER), (0x1033678C, "16f02af8", RESOLVER)):
        x, y = struct.unpack("<HH", bytes.fromhex(raw))
        assert decode_thumb_bl(addr, x, y) == expected
    assert decode_thumb_bl(0x1000, 0xF000, 0xC000) is None
    synthetic = bytearray(b"\x00" * 20)
    struct.pack_into("<I", synthetic, 1, WRAPPER | 1)
    struct.pack_into("<I", synthetic, 9, WRAPPER)
    counts, hits = raw_pointer_refs((("SYNTH", bytes(synthetic), 0x1000),))
    assert counts == {WRAPPER: 1, WRAPPER | 1: 1}
    assert hits[WRAPPER | 1] == [("SYNTH", 0x1001)]
    print("A116_SELF_TEST=PASS_WRAPPER_ANCHORS_BL_DECODER_POINTER_REFS")


def report(alice: bytes, zimage: bytes, cs_thumb, cs_arm) -> str:
    from capstone.arm import ARM_OP_IMM
    for addr, raw in ANCHORS.items():
        expected = bytes.fromhex(raw)
        actual = take(alice, ALICE_BASE, addr, len(expected))
        if actual != expected:
            fail(f"A115 exact anchor changed at 0x{addr:08X}: {actual.hex()} vs {raw}")
    for addr, dest in ((0x102F37D6, RESOLVER), (0x1033678C, RESOLVER)):
        x, y = struct.unpack("<HH", take(alice, ALICE_BASE, addr, 4))
        if decode_thumb_bl(addr, x, y) != dest:
            fail(f"A115 BL control does not decode at 0x{addr:08X}")
    # Validate specifically the transfer-mode boundary by decoding an exact Thumb BLX.
    br = disasm_at(cs_thumb, alice, ALICE_BASE, 0x102F37D2, 4)
    if not br or br[0].mnemonic.lower() != "blx" or len(br[0].operands) != 1 or br[0].operands[0].type != ARM_OP_IMM or (br[0].operands[0].imm & 0xFFFFFFFF) != ARM_ENTRY:
        fail("Thumb BLX anchor no longer enters ARM 102FC804")
    lines = [
        "S13.5A.116 — A115 NEW RESOLVE-THEN-BLX WRAPPER / INCOMING-ID PROVENANCE",
        "STRICTLY_OFFLINE=YES SOURCES_READ_ONLY=YES TEXT_REPORT_ONLY=YES NO_PHONE_USB_COM_FLASH_PATCH_REPACK=YES",
        f"ALICE_GUARD=PASS SIZE=0x{len(alice):X} SHA256={ALICE_SHA}",
        f"ZIMAGE_GUARD=PASS SIZE=0x{len(zimage):X} SHA256={ZIMAGE_SHA}",
        f"A115_EXACT_THUMB_ANCHORS=PASS COUNT={len(ANCHORS)}",
        "A115_TWO_BL_TO_NATIVE_RESOLVER_ANCHORS=PASS",
        "METHOD=EXACT_WRAPPER_LOCAL_INSTRUCTIONS_PLUS_ARM_VENEER_PLUS_WRAPPER_CALLER_AND_PTR_REFS",
        "LIMIT=RAW_POINTERS_AND_BL_PATTERN_SYNTACTIC_NOT_CFG_OR_USER_OK_TRACE",
        "NOT_SCANNED=GENERIC_102D9DC8_GATEWAY;B702_ROM_PADDING;FRAMEWORK_F02E4228",
        "",
        "=== A. WRAPPER LOCAL THUMB BODY (EXACT ENTRY, CONTROL FLOW BOUNDED) ===",
        f"WRAPPER=0x{WRAPPER:08X} ENTRY_PUSH=PASS",
    ]
    insns = disasm_at(cs_thumb, alice, ALICE_BASE, WRAPPER, 0x1E)
    expected_addresses = sorted(addr for addr in ANCHORS if WRAPPER <= addr <= 0x102F37E0)
    have = {x.address for x in insns}
    if not set(expected_addresses).issubset(have):
        fail("Capstone did not align all exact A115 wrapper instructions from real entry")
    for ins in insns:
        lines.append(f"  0x{ins.address:08X} {ins.bytes.hex():10s} {ins.mnemonic:8s} {ins.op_str}")
    lines += [
        "INPUT_R0=POINTER_TO_STRUCT_WITH_U16_AT_PLUS6_AND_WRITTEN_U16_AT_PLUS8; POINTER_ORIGIN_UNKNOWN",
        "INPUT_R1=U16_WRITTEN_TO_STRUCT_PLUS8_AND_MASKED_TO_16_BITS_BEFORE_HELPER; VALUE_UNKNOWN",
        "ZERO_CHECK=IF_U16_INPUT_PLUS6_IS_ZERO_SKIP_HELPER_AND_RESOLVER",
        "ARM_HELPER_INPUT_R0=U16[ORIGINAL_R0_PTR+6] ARM_HELPER_INPUT_R1=LOW16_ORIGINAL_R1",
        "R0_AFTER_ARM_HELPER=PASSED_UNMODIFIED_TO_NATIVE_RESOLVER_AT_0x102F37D6",
        "NATIVE_RESOLVER_RESULT_NONZERO=BLX_R0_AT_0x102F37DE; CALLBACK_ABI_UNCLASSIFIED",
        "CRITICAL=CALLBACK_INIT_REGISTRATION_IS_NOT_YET_PROVEN_MENU_LEAF_LAUNCH",
        "",
        "=== B. EXACT ARM INTERWORKING VENEER 0x102FC804 ===",
    ]
    arm_rows, target = resolve_arm_veneer(alice, cs_arm, cs_thumb)
    lines += arm_rows
    if target is None:
        lines.append("RESOLVED_HELPER_TARGET=UNKNOWN; NO_SPECULATIVE_FOLLOW")
    else:
        effective = target & ~1
        mode = "THUMB" if target & 1 else "ARM"
        selected = None
        if ALICE_BASE <= effective < ALICE_BASE + len(alice):
            selected = ("ALICE", alice, ALICE_BASE)
        if ZIMAGE_BASE <= effective < ZIMAGE_BASE + len(zimage):
            selected = ("ZIMAGE", zimage, ZIMAGE_BASE)
        lines.append(f"RESOLVED_HELPER_TARGET_RAW=0x{target:08X} EFFECTIVE=0x{effective:08X} MODE={mode} IMAGE={selected[0] if selected else 'OUTSIDE_SOURCES'}")
        if selected:
            label, blob, base = selected
            md = cs_thumb if target & 1 else cs_arm
            size = min(0x60, len(blob) - (effective - base))
            code = disasm_at(md, blob, base, effective, size)
            lines.append("RESOLVED_HELPER_PREFIX=LINEAR_DISASSEMBLY_NOT_CFG_ONLY_FIRST_24")
            for ins in code[:24]:
                lines.append(f"  0x{ins.address:08X} {ins.bytes.hex():10s} {ins.mnemonic:8s} {ins.op_str}")
                if ins.mnemonic.lower() in ("bx", "pop", "tbb", "tbh") or (ins.mnemonic.lower().startswith("b") and ins.mnemonic.lower() not in ("bic", "bics", "bkpt")):
                    lines.append("  STOP=FIRST_CONTROL_TRANSFER_IN_LINEAR_PREFIX")
                    break
    lines += ["", "=== C. CALLER REFERENCES TO NEW WRAPPER ==="]
    bls = find_bl_to_wrapper(alice)
    counts, ptrs = raw_pointer_refs((("ALICE", alice, ALICE_BASE), ("ZIMAGE", zimage, ZIMAGE_BASE)))
    lines.append(f"EXACT_RAW_ALICE_THUMB_BL_TARGETING_WRAPPER={len(bls)}")
    for va in bls[:24]:
        lines.append(f"BL_CALLSITE=0x{va:08X} BYTES={take(alice, ALICE_BASE, va, 4).hex()} STATUS=RAW_PATTERN_NOT_CFG")
        start = max(ALICE_BASE, va - 0x16) & ~1
        available = min(0x28, ALICE_BASE + len(alice) - start)
        insn = disasm_at(cs_thumb, alice, ALICE_BASE, start, available)
        for i in insn:
            if va - 0x14 <= i.address <= va + 4:
                lines.append(f"  0x{i.address:08X} {i.bytes.hex():10s} {i.mnemonic:8s} {i.op_str}")
    if len(bls) > 24:
        lines.append(f"BL_CALLSITE_LIST_TRUNCATED_TO_24_TOTAL={len(bls)}")
    for key in (WRAPPER, WRAPPER | 1):
        lines.append(f"RAW_U32_ALL_ALIGNMENTS_POINTER=0x{key:08X} TOTAL={counts[key]}")
        for label, va in ptrs[key]:
            lines.append(f"  RAW_POINTER_VALUE_AT={label}:0x{va:08X} EXECUTABILITY_NOT_PROVEN")
    lines += [
        "", "=== D. DECISION ===",
        "EXACT_REGISTERED_AUDIO_CALLBACK_8928=HISTORICAL_A114_ONLY_NOT_RERUN",
        "UI_SELECTED_87ED_POSITIVE_CONTROL_TO_WRAPPER=UNPROVEN",
        "UI_SELECTED_8928_TO_WRAPPER=UNPROVEN",
        "B702_ROM_STORAGE_AND_DATA_POINTER_INTEGRITY=UNPROVEN",
        "NEXT_IF_CONCRETE_WRAPPER_CALLER=TRACE_ONLY_EXACT_CALLER_CONTEXT_AND_INPUT_POINTER_ORIGIN",
        "NEXT_IF_NO_CONCRETE_CALLER=STOP_GENERIC_NATIVE_DISPATCH_XREF_AND_USE_TRUSTED_UI_TRACE_EVIDENCE",
        "NO_PATCH_NO_PHONE_NO_EMULATOR_EDIT=YES",
    ]
    return "\n".join(lines) + "\n"


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--root", type=Path, default=Path(r"C:\Users\verto\F2-Altice-MobiWire"))
    p.add_argument("--out", type=Path, default=None)
    p.add_argument("--self-test", action="store_true")
    args = p.parse_args()
    self_test()
    if args.self_test:
        return
    try:
        from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_LITTLE_ENDIAN, CS_MODE_THUMB
    except ImportError:
        fail("Capstone required from canonical mtkclient .venv Python")
    root = args.root
    alice = guarded(root, "research/f2/work/extracted/altice_alice/alice-py.bin", "ALICE", ALICE_SIZE, ALICE_SHA)
    zimage = guarded(root, "research/f2/work/extracted/altice_platform/zimage.bin", "ZIMAGE", ZIMAGE_SIZE, ZIMAGE_SHA)
    thumb = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_LITTLE_ENDIAN)
    arm = Cs(CS_ARCH_ARM, CS_MODE_ARM | CS_MODE_LITTLE_ENDIAN)
    thumb.detail = True
    arm.detail = True
    result = report(alice, zimage, thumb, arm)
    out = args.out or (root / "research/f2/work/reports" / REPORT)
    if not out.parent.is_dir():
        fail(f"report directory is missing: {out.parent}")
    with out.open("x", encoding="utf-8", newline="\n") as f:
        f.write(result)
    print(f"A116_REPORT_CREATED={out} BYTES={out.stat().st_size}")
    print("A116_RESULT=REVIEW_WRAPPER_AND_CALLER_PROVENANCE_NO_PATCH")


if __name__ == "__main__":
    main()
