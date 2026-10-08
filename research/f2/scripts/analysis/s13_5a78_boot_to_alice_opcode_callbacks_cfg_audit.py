#!/usr/bin/env python3
"""S13.5A.78 -- BOOT event table to three ALICE Thumb callback entries.

STRICT OFFLINE: read exactly two already-extracted, SHA-pinned .bin files;
print stdout only. No USB, COM, device, flash, writes, erase, repack,
patch, emulator execution, or network. Capstone is used only to decode.

A.77 resolved three callbacks that were labelled outside the two images
loaded in A.77. This audit adds the already-known third image, ALICE,
and follows only those three exact entries. Does NOT prove menu/audio launch.
"""
from __future__ import annotations

import argparse
import hashlib
import sys
from pathlib import Path

BOOT_BASE = 0xF01F19E4
BOOT_SIZE = 0x4B06C
BOOT_SHA = "aa070292e9c1685eddb12080b3f0bbca763102adaf085016b4e503a3930b4c3e"
ALICE_BASE = 0x1024EC00
ALICE_SIZE = 0x157BB4
ALICE_SHA = "7246242b67afae0d13104452bc3257827cb778119b54e7a26fb7fb55993697ea"
TABLE = 0xF022FAA8
SINK = 0xF0217F16

# Code -> (BOOT row base, first word = ALICE Thumb callback).
# Exactly A77's new code-proven evidence. 0x33 is an alias of code 0x01.
EVIDENCE = {
    0x01: (0xF022FBDC, 0x102C8FFD),
    0x02: (0xF022FBF0, 0x102C9343),
    0x04: (0xF022FC18, 0x102C9059),
    0x33: (0xF022FBDC, 0x102C8FFD),
}
# Next nearby known callback entry serves as a fail-closed boundary for
# the first two, NOT a proven function-size estimate.
TARGET_WINDOWS = {
    0x102C8FFC: (0x102C9058, "NEXT_KNOWN_CALLBACK_BOUNDARY"),
    0x102C9058: (0x102C9342, "NEXT_KNOWN_CALLBACK_BOUNDARY"),
    0x102C9342: (0x102C9542, "BOUNDED_0x200_ONLY"),
}
CONDITIONAL = {"beq", "bne", "bcs", "bcc", "bhs", "blo", "bmi", "bpl",
               "bvs", "bvc", "bhi", "bls", "bge", "blt", "bgt", "ble", "cbz", "cbnz"}


def banner(name: str) -> None:
    print("\n" + "=" * 108 + "\n" + name + "\n" + "=" * 108)


def resolve_boot(value: str | None) -> Path:
    if value:
        return Path(value).expanduser()
    relative = Path("research/f2/work/extracted/altice_platform/boot_zimage.bin")
    candidates = [Path.cwd() / relative, Path.home() / "mtkclient" / relative]
    for candidate in candidates:
        if candidate.is_file():
            return candidate
    raise RuntimeError("BOOT_ZIMAGE not found; pass --boot with the historical extracted image path")


def verify(path: Path, size: int, sha: str, label: str) -> bytes:
    if not path.is_file():
        raise RuntimeError(f"{label} source missing: {path}")
    raw = path.read_bytes()
    digest = hashlib.sha256(raw).hexdigest()
    passed = len(raw) == size and digest == sha
    print(f"{label}: file={path} size=0x{len(raw):X} sha256={digest} GUARD={'PASS' if passed else 'FAIL'}")
    if not passed:
        raise RuntimeError(f"{label} canonical guard failure; analysis aborted")
    return raw


def read_word(blob: bytes, base: int, address: int) -> int:
    off = address - base
    if off < 0 or off + 4 > len(blob):
        raise RuntimeError(f"U32 out of verified range @0x{address:08X}")
    return int.from_bytes(blob[off:off + 4], "little")


def inst_at(cs, blob: bytes, base: int, address: int):
    off = address - base
    if off < 0 or off + 2 > len(blob):
        return None
    return next(iter(cs.disasm(blob[off:off + 4], address, count=1)), None)


def branch_target(ins, arm):
    if ins is None:
        return None
    operands = getattr(ins, "operands", [])
    if len(operands) != 1 or operands[0].type != arm.ARM_OP_IMM:
        return None
    return (int(operands[0].imm) & 0xFFFFFFFF) & ~1


def literal(ins, arm, blob, base):
    if ins.mnemonic.lower() not in ("ldr", "ldr.w") or len(ins.operands) < 2:
        return None
    src = ins.operands[1]
    if src.type != arm.ARM_OP_MEM or src.mem.base != arm.ARM_REG_PC:
        return None
    cell = ((ins.address + 4) & ~3) + src.mem.disp
    if not base <= cell < base + len(blob) - 3:
        return f"LITERAL_CELL=0x{cell:08X} OUTSIDE_THIS_IMAGE"
    return f"LITERAL_CELL=0x{cell:08X} U32=0x{read_word(blob, base, cell):08X}"


def describe(ins, arm, blob, base):
    desc = f"0x{ins.address:08X}: {ins.mnemonic:8s} {ins.op_str:29s} bytes={ins.bytes.hex(' ')}"
    lit = literal(ins, arm, blob, base)
    return desc + (" ; " + lit if lit else "")


def anchored_dispatch(cs, boot: bytes, alice: bytes, arm):
    banner("B. A77 EXACT BOOT TABLE -> PINNED ALICE THUMB LINK (FAIL CLOSED)")
    for address, mnemonic, operands in ((0xF0217EB4, "ldr", "r2, [pc"),
                                        (0xF0217EB8, "ldr", "r1, [r2, r1]"),
                                        (0xF0217EF6, "ldr", "r3, [r0]"),
                                        (SINK, "blx", "r4")):
        ins = inst_at(cs, boot, BOOT_BASE, address)
        if ins is None or ins.address != address or ins.mnemonic.lower() != mnemonic or not ins.op_str.startswith(operands):
            raise RuntimeError(f"A77 dispatch anchor mismatch at 0x{address:08X}: {ins}")
        print("PASS " + describe(ins, arm, boot, BOOT_BASE))
    if read_word(boot, BOOT_BASE, 0xF0217F70) != TABLE:
        raise RuntimeError("A77 PC-relative table literal changed")
    print(f"TABLE_PC_LITERAL=PASS 0xF0217F70 => 0x{TABLE:08X}")
    result = {}
    for opcode, (entry, thumb_pointer) in EVIDENCE.items():
        cell = TABLE + 4 * opcode
        actual_entry = read_word(boot, BOOT_BASE, cell)
        actual_pointer = read_word(boot, BOOT_BASE, actual_entry)
        if actual_entry != entry or actual_pointer != thumb_pointer:
            raise RuntimeError(f"A77 table mismatch for code 0x{opcode:02X}: entry={actual_entry:#x} callback={actual_pointer:#x}")
        if not (thumb_pointer & 1):
            raise RuntimeError(f"Expected Thumb pointer at opcode 0x{opcode:02X}")
        function = thumb_pointer & ~1
        offset = function - ALICE_BASE
        if not (0 <= offset < len(alice) - 4):
            raise RuntimeError(f"Thumb callback not in verified ALICE for opcode 0x{opcode:02X}")
        print(f"code=0x{opcode:02X} BOOT_TABLE_CELL=0x{cell:08X} ROW=0x{entry:08X} "
              f"THUMB_PTR=0x{thumb_pointer:08X} ALICE_ENTRY=0x{function:08X} OFFSET=0x{offset:X} LINK=PASS")
        result[opcode] = function
    if result[0x01] != result[0x33] or len(set(result.values())) != 3:
        raise RuntimeError("Unexpected shared/different callbacks: A77 regression")
    print("THREE_DISTINCT_ALICE_CALLBACKS=PASS; 0x01 and 0x33 are aliases; static bytes only")
    return result


def bounded_graph(cs, arm, alice: bytes, entry: int, upper: int):
    """Conservative static decode graph, no call-following and no presumed runtime entry."""
    if entry >= upper or entry < ALICE_BASE or upper > ALICE_BASE + len(alice):
        raise RuntimeError("CFG boundary outside ALICE or inverted")
    instruction_cap = 180
    block_cap = 42
    pending = [entry]
    visited = {}
    blocks = []
    calls = []
    edges = []
    warnings = []
    while pending and len(visited) < instruction_cap and len(blocks) < block_cap:
        start = pending.pop(0)
        if not (entry <= start < upper) or start in visited:
            continue
        address = start
        got = []
        while len(got) < 65 and len(visited) < instruction_cap:
            if not entry <= address < upper or address in visited:
                if address >= upper:
                    warnings.append(f"0x{address:08X} outside audit window")
                break
            ins = inst_at(cs, alice, ALICE_BASE, address)
            if ins is None or ins.address != address:
                warnings.append(f"0x{address:08X} instruction decode failure")
                break
            m = ins.mnemonic.lower().split(".")[0]
            nxt = address + ins.size
            visited[address] = ins
            got.append(ins)
            if m in ("bl", "blx"):
                tgt = branch_target(ins, arm)
                calls.append((address, tgt, ins.op_str))
                if tgt is None:
                    warnings.append(f"0x{address:08X} indirect call target unresolved")
                address = nxt
                continue
            if m in CONDITIONAL:
                tgt = branch_target(ins, arm)
                edges.append((address, "conditional", tgt))
                if tgt is not None and entry <= tgt < upper:
                    pending.append(tgt)
                elif tgt is None:
                    warnings.append(f"0x{address:08X} unknown conditional target")
                else:
                    warnings.append(f"0x{address:08X} conditional edge outside audit window -> 0x{tgt:08X}")
                address = nxt
                continue
            if m == "b":
                tgt = branch_target(ins, arm)
                edges.append((address, "unconditional", tgt))
                if tgt is not None and entry <= tgt < upper:
                    pending.append(tgt)
                else:
                    warnings.append(f"0x{address:08X} branch/tail outside window -> {tgt!r}")
                break
            if (m in {"bx", "bxj", "tbb", "tbh", "udf", "svc", "bkpt"}
                or (m == "pop" and "pc" in ins.op_str)
                or (m == "ldr" and ins.op_str.startswith("pc,"))):
                if m in {"tbb", "tbh"} or (m == "ldr" and ins.op_str.startswith("pc,")):
                    warnings.append(f"0x{address:08X} computed branch unresolved")
                break
            address = nxt
        else:
            warnings.append(f"0x{start:08X} per-block instruction cap")
        blocks.append((start, got))
    if pending:
        warnings.append("PENDING_BLOCKS: bounded graph incomplete")
    if len(visited) >= instruction_cap:
        warnings.append("INSTRUCTION_CAP reached")
    if len(blocks) >= block_cap:
        warnings.append("BLOCK_CAP reached")
    for base, instructions in blocks:
        print(f"\nCFG_BLOCK start=0x{base:08X} count={len(instructions)}")
        for ins in instructions:
            print("  " + describe(ins, arm, alice, ALICE_BASE))
    print(f"CFG_SUMMARY entry=0x{entry:08X} visited={len(visited)} blocks={len(blocks)} "
          f"pending={len(pending)} calls={len(calls)} bounds=[0x{entry:08X},0x{upper:08X})")
    print("CALLS (not followed, even if ALICE):")
    for address, target, operand in calls[:40]:
        print(f"  0x{address:08X} -> {('0x%08X' % target) if target is not None else 'INDIRECT'} ({operand})")
    if not calls:
        print("  none")
    print("EDGES / boundary constraints:")
    for address, kind, target in edges[:45]:
        print(f"  0x{address:08X} {kind} -> {('0x%08X' % target) if target is not None else 'UNKNOWN'}")
    if not edges:
        print("  none")
    print("WARNINGS:")
    for warning in warnings[:35]:
        print("  " + warning)
    if not warnings:
        print("  none in bounded static CFG; does NOT prove runtime reachability")
    print("CALLER ABI AT 0xF0217F16 per A77: r0=r5 (flag mix), r1=[sp+0x5C], "
          "r2=[sp+0x48], r3=r6, plus outgoing stack arguments. Callee semantics unknown.")
    return len(visited), calls, warnings


def main() -> int:
    parser = argparse.ArgumentParser(description="S13.5A.78 strict offline BOOT opcode -> ALICE Thumb callback audit")
    parser.add_argument("--boot", help="Canonical BOOT_ZIMAGE location, historical path accepted")
    parser.add_argument("--alice", default="research/f2/work/extracted/altice_alice/alice-py.bin")
    args = parser.parse_args()
    print("S13.5A.78 - BOOT EVENT OPCODE ALICE CALLBACK FUNCTION CFG AUDIT")
    print("STRICTLY OFFLINE: no phone/USB/COM/BROM/DA/flash/write/erase/repack/patch; stdout only")
    banner("A. CANONICAL SHA256 / SIZE GUARDS -- FAIL CLOSED")
    boot = verify(resolve_boot(args.boot), BOOT_SIZE, BOOT_SHA, "BOOT_ZIMAGE")
    alice = verify(Path(args.alice), ALICE_SIZE, ALICE_SHA, "ALICE")
    if BOOT_BASE + BOOT_SIZE != 0xF023CA50:
        raise RuntimeError("Canonical BOOT end geometry wrong")
    from capstone import CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_LITTLE_ENDIAN, Cs
    from capstone import arm
    cs = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_LITTLE_ENDIAN)
    cs.detail = True
    result = anchored_dispatch(cs, boot, alice, arm)
    banner("C. EXACT THREE UNIQUE ALICE THUMB CALLBACK CFGS (NO GENERAL REVERSE XREF)")
    results = {}
    for code, entry in ((0x01, result[0x01]), (0x04, result[0x04]), (0x02, result[0x02])):
        upper, why = TARGET_WINDOWS[entry]
        print(f"\n--- BOOT code=0x{code:02X}; ALICE entry=0x{entry:08X}; offset=0x{entry - ALICE_BASE:X}; "
              f"upper=0x{upper:08X} {why} ---")
        first = inst_at(cs, alice, ALICE_BASE, entry)
        if first is None or first.address != entry:
            raise RuntimeError(f"Cannot decode ALICE target @0x{entry:08X}")
        print("ENTRY_PREVIEW " + describe(first, arm, alice, ALICE_BASE))
        results[entry] = bounded_graph(cs, arm, alice, entry, upper)
    banner("D. INTERPRETATION GATE")
    print("A78_OFFLINE_COMPLETED=YES")
    print("A77 OUTSIDE_PINNED_IMAGES for the three pointers was a source-coverage limit; ALICE mapping now checked.")
    print("A77's code=0x01 and code=0x33 share ALICE entry=0x102C8FFC. code 0x02 and 0x04 have distinct entries.")
    print("Do NOT assume code 0x01/0x02/0x04 represent menu IDs, or that these callbacks launch app 0x8928.")
    print("Decoded ALICE callback bytes are source code evidence, not a runtime dispatch trace or an authorized firmware patch.")
    print("PHONE ACCESSED=NO; FLASH MODIFIED=NO; PATCH=NO; REPACK=NO; HARDWARE WRITE AUTHORIZED=NO")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print("ABORT: " + str(exc), file=sys.stderr)
        raise SystemExit(1)
