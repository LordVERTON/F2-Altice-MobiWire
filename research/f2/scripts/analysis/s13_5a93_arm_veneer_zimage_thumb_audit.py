#!/usr/bin/env python3
"""S13.5A.93: exact ARM veneer -> ZIMAGE Thumb target investigation.

Strictly OFFLINE. Reads canonical ALICE and ZIMAGE, writes one text report.
No USB, COM, flash, patch, firmware writes, or phone access.
Target function's semantics remain UNKNOWN until manually established.
"""
from __future__ import annotations

import argparse
import hashlib
import struct
from collections import deque
from pathlib import Path

try:
    from capstone import CS_ARCH_ARM, CS_MODE_LITTLE_ENDIAN, CS_MODE_THUMB, Cs
    from capstone.arm import ARM_OP_IMM, ARM_OP_MEM, ARM_REG_PC
except ImportError:
    Cs = None
    ARM_OP_IMM = ARM_OP_MEM = ARM_REG_PC = None

ALICE_BASE = 0x1024EC00
ALICE_SIZE = 0x157BB4
ALICE_SHA = "7246242b67afae0d13104452bc3257827cb778119b54e7a26fb7fb55993697ea"
ZIMAGE_BASE = 0xF023CA50
ZIMAGE_SIZE = 0x185E98
ZIMAGE_SHA = "85fba8c8ae8161e4c1f8ced7983ec30d48c54ab10e51c69fcdfb900aca220954"
VENEER = 0x102FC624
# Known instruction ARM: LDR PC, [PC, #-4]; PC in ARM state reads as current+8.
VENEER_INS = bytes.fromhex("04 f0 1f e5")
MAX_INSNS = 280
MAX_SPAN = 0x2000
BR_CONDS = {"beq", "bne", "bcs", "bcc", "bhs", "blo", "bmi", "bpl", "bvs", "bvc", "bhi", "bls", "bge", "blt", "bgt", "ble"}


def abort(why: str) -> None:
    raise SystemExit("ABORT: " + why)


def grab(image: bytes, base: int, address: int, size: int) -> bytes | None:
    offset = address - base
    if offset < 0 or offset + size > len(image):
        return None
    return image[offset: offset + size]


def require_image(path: Path, expected_size: int, expected_sha: str, label: str) -> bytes:
    if not path.is_file():
        abort(f"{label} introuvable: {path}")
    blob = path.read_bytes()
    sha = hashlib.sha256(blob).hexdigest()
    if len(blob) != expected_size or sha != expected_sha:
        abort(f"{label} GUARD FAIL: size=0x{len(blob):X} sha256={sha}")
    return blob


def resolve_veneer(alice: bytes, zimage: bytes) -> tuple[int, int, int]:
    ins = grab(alice, ALICE_BASE, VENEER, 4)
    if ins != VENEER_INS:
        abort(f"ARM veneer raw mismatch at 0x{VENEER:08X}: {(ins or b'').hex()}")
    cell_va = VENEER + 8 - 4
    raw_ptr = grab(alice, ALICE_BASE, cell_va, 4)
    if raw_ptr is None:
        abort("ARM veneer literal outside ALICE")
    pointer = struct.unpack("<I", raw_ptr)[0]
    if not pointer & 1:
        abort(f"unexpected even ARM veneer pointer: 0x{pointer:08X}; do not assume Thumb")
    entry = pointer & ~1
    if grab(zimage, ZIMAGE_BASE, entry, 4) is None:
        abort(f"veneer target outside canonical ZIMAGE: 0x{entry:08X}")
    return cell_va, pointer, entry


def decode_thumb(md: Cs, image: bytes, address: int):
    data = grab(image, ZIMAGE_BASE, address, 4)
    if data is None:
        return None
    items = list(md.disasm(data, address, count=1))
    return items[0] if items and items[0].address == address else None


def read_literal(ins, image: bytes):
    if not ins.mnemonic.lower().startswith("ldr") or len(ins.operands) < 2:
        return None
    operand = ins.operands[1]
    if operand.type != ARM_OP_MEM or operand.mem.base != ARM_REG_PC or operand.mem.index:
        return None
    # Literal loads use aligned PC+4 in Thumb state.
    cell = ((ins.address + 4) & ~3) + operand.mem.disp
    size = 1 if ins.mnemonic.startswith("ldrb") else 2 if ins.mnemonic.startswith("ldrh") else 4
    blob = grab(image, ZIMAGE_BASE, cell, size)
    if blob is None:
        return (cell, None)
    return (cell, int.from_bytes(blob, "little"))


def imm_target(ins):
    # Branch target is the final immediate operand for CBZ/CBNZ, first for B/BL.
    for operand in reversed(ins.operands):
        if operand.type == ARM_OP_IMM:
            return operand.imm & 0xFFFFFFFF
    return None


def probe(zimage: bytes, entry: int, span: int) -> list[str]:
    end = entry + span
    md = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_LITTLE_ENDIAN)
    md.detail = True
    pending = deque([entry])
    seen = {}
    calls = []
    branches = []
    exits = []
    issues = []
    while pending and len(seen) < MAX_INSNS:
        pc = pending.popleft()
        if pc in seen:
            continue
        if not (entry <= pc < end):
            issues.append(f"OUTSIDE_BOUNDARY 0x{pc:08X}")
            continue
        ins = decode_thumb(md, zimage, pc)
        if ins is None or pc + ins.size > end:
            issues.append(f"DECODE_FAIL 0x{pc:08X}")
            continue
        seen[pc] = ins
        name = ins.mnemonic.lower().split(".")[0]
        nextpc = pc + ins.size
        target = imm_target(ins)
        op = ins.op_str.lower()
        if name in ("bl", "blx"):
            calls.append(f"0x{pc:08X} {ins.mnemonic} {ins.op_str} => {('0x%08X' % target) if target is not None else 'INDIRECT'}")
            pending.append(nextpc)  # assuming a normal return, not functional proof
        elif name in ("b", "b.w"):
            if target is None:
                issues.append(f"UNRESOLVED_BRANCH 0x{pc:08X} {ins.mnemonic} {ins.op_str}")
            else:
                branches.append(f"0x{pc:08X} -> 0x{target:08X} unconditional")
                pending.append(target & ~1)
        elif name in BR_CONDS or name in ("cbz", "cbnz"):
            if target is None:
                issues.append(f"UNRESOLVED_CONDITION 0x{pc:08X} {ins.mnemonic} {ins.op_str}")
            else:
                branches.append(f"0x{pc:08X} -> 0x{target:08X} {name}")
                pending.append(target & ~1)
            pending.append(nextpc)
        elif name in ("tbb", "tbh") or (name == "bx" and "lr" not in op) or (name == "ldr" and op.startswith("pc,")) or (name == "mov" and op.startswith("pc,")):
            issues.append(f"INDIRECT_CONTROL_FLOW 0x{pc:08X} {ins.mnemonic} {ins.op_str}")
        elif name == "bx" and "lr" in op or (name == "pop" and "pc" in op):
            exits.append(f"0x{pc:08X} {ins.mnemonic} {ins.op_str}")
        else:
            pending.append(nextpc)
    if pending:
        issues.append(f"INSTRUCTION_CAP {MAX_INSNS}, {len(pending)} pending paths")

    lines = [
        f"target_zimage_file_offset=0x{entry-ZIMAGE_BASE:X}",
        f"window=[0x{entry:08X}, 0x{end:08X})",
        f"reachable_thumb_instructions={len(seen)}",
        f"return_sites={len(exits)}",
        f"direct_call_sites={len(calls)}",
        f"unresolved_or_out_of_window={len(issues)}",
        "NOTE: heuristic local CFG, NOT function or leaf-launch proof; BL assumed to return.",
        "NOTE: IT predication and indirect branches can invalidate some static paths.",
        "", "=== REACHABLE THUMB ==="
    ]
    for pc, ins in sorted(seen.items()):
        lit = read_literal(ins, zimage)
        suffix = ""
        if lit is not None:
            suffix = f" ; LITERAL[0x{lit[0]:08X}]=" + (f"0x{lit[1]:08X}" if lit[1] is not None else "OUT_OF_IMAGE")
        lines.append(f"0x{pc:08X} {ins.bytes.hex():<10} {ins.mnemonic:<10} {ins.op_str}{suffix}")
    for heading, values in [("DIRECT CALLS", calls), ("BRANCHES", branches), ("RETURNS", exits), ("UNRESOLVED", issues)]:
        lines.extend(["", "=== " + heading + " ===", *(values or ["none"])] )
    return lines


def self_test() -> None:
    tiny_alice = VENEER_INS + struct.pack("<I", ZIMAGE_BASE | 1)
    literal = tiny_alice[4:8]
    assert literal == bytes.fromhex("51 ca 23 f0")
    assert (struct.unpack("<I", literal)[0] & ~1) == ZIMAGE_BASE
    # Resolve a tiny synthetic ALICE ARM veneer and synthetic ZIMAGE target.
    fake_a = bytearray(VENEER - ALICE_BASE + 8)
    fake_a[-8:-4] = VENEER_INS
    fake_a[-4:] = struct.pack("<I", (ZIMAGE_BASE + 0x20) | 1)
    fake_z = bytes(0x30)
    assert resolve_veneer(fake_a, fake_z) == (VENEER + 4, (ZIMAGE_BASE + 0x20) | 1, ZIMAGE_BASE + 0x20)
    if Cs is not None:
        result = probe(bytes.fromhex("70 47 00 bf"), ZIMAGE_BASE, 4)
        assert any("reachable_thumb_instructions=1" in x for x in result)
        assert any("bx" in x and "lr" in x for x in result)
        print("SELF-TEST PASS: ARM literal math, veneer resolve, and Thumb decoder")
    else:
        print("SELF-TEST PASS: ARM literal math and veneer resolve (Capstone absent: Thumb decoder NOT tested)")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--alice", type=Path)
    parser.add_argument("--zimage", type=Path)
    parser.add_argument("--out", type=Path)
    parser.add_argument("--span", type=lambda s: int(s, 0), default=0x600)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        self_test()
        return
    if Cs is None:
        abort("Capstone absent: lancer avec l’environnement Python de mtkclient contenant Capstone")
    if not args.alice or not args.zimage or not args.out:
        parser.error("--alice, --zimage and --out are required")
    if not 0 < args.span <= MAX_SPAN:
        parser.error(f"--span must be 1..0x{MAX_SPAN:X}")
    alice = require_image(args.alice, ALICE_SIZE, ALICE_SHA, "ALICE")
    zimage = require_image(args.zimage, ZIMAGE_SIZE, ZIMAGE_SHA, "ZIMAGE")
    literal_va, pointer, target = resolve_veneer(alice, zimage)
    lines = [
        "S13.5A.93 — ALICE ARM VENEER -> ZIMAGE THUMB AUDIT (STRICTLY OFFLINE)",
        "ALICE_GUARD=PASS size=0x%X sha256=%s" % (len(alice), ALICE_SHA),
        "ZIMAGE_GUARD=PASS size=0x%X sha256=%s" % (len(zimage), ZIMAGE_SHA),
        "ARM_VENEER_OPCODE=PASS at 0x%08X: %s" % (VENEER, VENEER_INS.hex()),
        "ARM_PC=0x%08X" % (VENEER + 8),
        "LITERAL_CELL=0x%08X" % literal_va,
        "THUMB_POINTER=0x%08X" % pointer,
        "ZIMAGE_THUMB_ENTRY=0x%08X" % target,
        "" 
    ] + probe(zimage, target, args.span) + [
        "", "=== INTERPRETATION BOUNDARY ===",
        "The ARM veneer reaches this Thumb entry; classification of its behavior is OPEN.",
        "No evidence of Audio Player app launch unless selected-ID->activation is separately proven.",
        "NO USB/COM, firmware writes, patch generation, flash erase, or phone access.",
    ]
    if args.out.exists():
        abort(f"report already exists (will not overwrite): {args.out}")
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("A93 PASS: exact ALICE ARM veneer, ZIMAGE Thumb pointer, SHA guards")
    print(f"target=0x{target:08X} file_offset=0x{target-ZIMAGE_BASE:X}")
    print(f"Report: {args.out} ({len(lines)} lines), firmware writes=0")


if __name__ == "__main__":
    main()
