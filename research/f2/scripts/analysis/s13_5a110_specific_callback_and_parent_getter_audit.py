#!/usr/bin/env python3
"""S13.5A.110: exact A.109 callback 1033F46C and parent-source 103956A4.

Strictly offline; reads only SHA-pinned canonical ALICE and ZIMAGE binaries.
Only generated artifact: exclusive-create .txt report in research/f2/work/reports.
No generic registry audit, no device I/O, USB, COM, flash, repack or firmware patch.

A.109 linked Thumb BLX -> ARM veneer -> previously known GENERIC F02E4228.
Here we do NOT re-audit that framework. We examine only the newly recovered
callback pointer 1033F46D (Thumb function entry 1033F46C), plus 103956A4,
which supplies r0 (the generic registration's first input) in A.107.

All CFG and call arguments are STATIC candidates, not phone execution or proof
of visible Multimedia selection. Indirect calls, IT predicates, runtime values,
interprocedural aliasing and branches outside local windows remain unresolved.
"""
from __future__ import annotations

import argparse
from collections import defaultdict, deque
import hashlib
from pathlib import Path
import struct

ALICE_BASE, ALICE_SIZE = 0x1024EC00, 0x157BB4
ALICE_SHA = "7246242b67afae0d13104452bc3257827cb778119b54e7a26fb7fb55993697ea"
ZIMAGE_BASE, ZIMAGE_SIZE = 0xF023CA50, 0x185E98
ZIMAGE_SHA = "85fba8c8ae8161e4c1f8ced7983ec30d48c54ab10e51c69fcdfb900aca220954"
CALLBACK_ENTRY = 0x1033F46C
PARENT_SOURCE = 0x103956A4
CALLBACK_PTR_CELL = 0x1031C7B4
CALLBACK_PTR = 0x1033F46D
VENEER = 0x102FD194
VENEER_LITERAL = 0x102FD198
TARGET_FRAMEWORK = 0xF02E4229
AUDIO_NATIVE_CORE = {0x1033D840, 0x1033E814, 0x1033F83C}
REPORT_NAME = "s13_5a110_specific_callback_and_parent_getter_audit.txt"

# Only literal bytes previously documented in A.107/A.108/A.109.
ALICE_ANCHORS = {
    0x1031C79A: "064a",      # LDR r2,=0x1033F46D
    0x1031C79C: "0198",      # restore entry r0
    0x1031C79E: "2300",      # r3=record
    0x1031C7A0: "0421",      # r1=4
    0x1031C7A2: "e0f7f8ec",  # BLX ARM veneer
    0x10393772: "1148",      # literal=103956D1, callback registration context
    0x10393784: "01f08eff",  # BL 103956A4
    0x10393788: "0c4d",      # constant r5=2E69
    0x10393796: "88f7bdff",  # BL 1031C714
    0x1039379C: "01f0b6ff",  # BL 1039570C setter
    0x1039570E: "4880",      # STRH r0,[r1,#2]
    0x102FD194: "04f01fe5",  # ARM LDR pc,[pc,#-4]
}
ZIMAGE_ANCHORS = {
    0xF02E4228: "7cb5",       # Generic registration entry, no deeper audit
    0xF02E4232: "fff78ffe",   # BL generic lookup F02E3F54
}
MAX_INSNS = 350
MAX_BLOCKS = 100
MAX_STEPS_PER_BLOCK = 96
CONDITIONAL_BRANCHES = {"beq", "bne", "bgt", "bge", "blt", "ble", "bhi", "bhs", "blo", "bls", "bmi", "bpl", "bvs", "bvc", "cbz", "cbnz", "bcs", "bcc"}


def abort(msg: str) -> None:
    raise RuntimeError("ABORT: " + msg)


def decode_bl(data: bytes, pc: int) -> int:
    """Thumb-2 32-bit BL, used for positive guards without Capstone."""
    if len(data) != 4:
        raise ValueError("BL requires 4 bytes")
    a, b = struct.unpack("<HH", data)
    if (a & 0xF800) != 0xF000 or (b & 0xD000) != 0xD000:
        raise ValueError("not a Thumb BL")
    s, j1, j2 = (a >> 10) & 1, (b >> 13) & 1, (b >> 11) & 1
    i1, i2 = 1 ^ (j1 ^ s), 1 ^ (j2 ^ s)
    imm = (s << 24) | (i1 << 23) | (i2 << 22) | ((a & 0x3FF) << 12) | ((b & 0x7FF) << 1)
    if s:
        imm -= 1 << 25
    return (pc + 4 + imm) & 0xFFFFFFFF


def self_test() -> None:
    assert len(ALICE_ANCHORS) == 12 and len(ZIMAGE_ANCHORS) == 2
    assert decode_bl(bytes.fromhex(ALICE_ANCHORS[0x10393784]), 0x10393784) == PARENT_SOURCE
    assert decode_bl(bytes.fromhex(ALICE_ANCHORS[0x10393796]), 0x10393796) == 0x1031C714
    assert decode_bl(bytes.fromhex(ALICE_ANCHORS[0x1039379C]), 0x1039379C) == 0x1039570C
    assert CALLBACK_PTR == (CALLBACK_ENTRY | 1)
    assert VENEER % 4 == 0
    try:
        decode_bl(bytes.fromhex("70470000"), 0x10393784)
    except ValueError:
        pass
    else:
        raise AssertionError("negative BL check failed")
    print("A110_SELF_TEST=PASS known_BLs=3, 14_exact_anchor_metadata, callback_thumb_pointer")


class Image:
    def __init__(self, label: str, path: Path, base: int, size: int, sha: str):
        if not path.is_file():
            abort(f"{label} MISSING {path}")
        self.data = path.read_bytes()
        h = hashlib.sha256(self.data).hexdigest()
        if len(self.data) != size or h != sha:
            abort(f"{label} CANON FAIL bytes=0x{len(self.data):X} sha={h}")
        self.base, self.label = base, label
        self.guard = f"{label}_GUARD=PASS BYTES=0x{len(self.data):X} SHA256={h}"

    def read(self, addr: int, length: int) -> bytes | None:
        i = addr - self.base
        if i < 0 or length < 0 or i + length > len(self.data):
            return None
        return self.data[i:i+length]

    def word(self, addr: int) -> int | None:
        b = self.read(addr, 4)
        return int.from_bytes(b, "little") if b is not None else None


def decode_one(cs, image: Image, pc: int):
    b = image.read(pc, 4)
    if b is None:
        return None
    got = list(cs.disasm(b, pc, count=1))
    return got[0] if got and got[0].address == pc else None


def opname(ins) -> str:
    return ins.mnemonic.lower().split(".")[0]


def call_target(ins):
    from capstone.arm import ARM_OP_IMM
    for op in reversed(ins.operands):
        if op.type == ARM_OP_IMM:
            return (int(op.imm) & 0xFFFFFFFF) & ~1
    return None


def literal(ins, image: Image):
    from capstone.arm import ARM_OP_MEM, ARM_REG_PC
    if opname(ins) != "ldr" or len(ins.operands) < 2:
        return None
    op = ins.operands[1]
    if op.type != ARM_OP_MEM or op.mem.base != ARM_REG_PC or op.mem.index:
        return None
    cell = (((ins.address + 4) & ~3) + op.mem.disp) & 0xFFFFFFFF
    b = image.read(cell, 4)
    return (cell, int.from_bytes(b,"little")) if b is not None else None


def printable(ins, image: Image) -> str:
    line = f"0x{ins.address:08X} {ins.bytes.hex():10s} {ins.mnemonic:9s} {ins.op_str}"
    lit = literal(ins, image)
    if lit is not None:
        line += f" ; LITERAL[0x{lit[0]:08X}]=0x{lit[1]:08X}"
    return line


def is_return(ins):
    name = opname(ins)
    args = ins.op_str.lower().replace(" ", "")
    if name == "pop" and "pc" in args:
        return "POP_PC"
    if name == "bx":
        return "BX_LR" if args == "lr" else "INDIRECT_BX"
    if name in ("tbb", "tbh"):
        return "INDIRECT_SWITCH"
    if name == "ldr" and args.startswith("pc,"):
        return "INDIRECT_LDR_PC"
    if name in ("mov", "movs") and args == "pc,lr":
        return "MOV_PC_LR"
    return None


def bounded_cfg(cs, image: Image, entry: int, limit: int, emit):
    seen = {}
    blocks = set()
    todo = deque([entry])
    calls = []
    branches = []
    endings = []
    notes = []
    while todo and len(seen) < MAX_INSNS and len(blocks) < MAX_BLOCKS:
        pc = todo.popleft()
        if pc in blocks or not entry <= pc < limit:
            continue
        blocks.add(pc)
        steps = 0
        while entry <= pc < limit and pc not in seen and steps < MAX_STEPS_PER_BLOCK and len(seen) < MAX_INSNS:
            ins = decode_one(cs, image, pc)
            if ins is None or pc + ins.size > limit:
                notes.append(f"DECODE_OR_WINDOW_0x{pc:08X}")
                break
            seen[pc] = ins
            steps += 1
            op = opname(ins)
            next_pc = pc + ins.size
            if op.startswith("it"):
                notes.append(f"IT_CONDITIONAL_SEMANTICS_UNMODELED_0x{pc:08X}")
            if op in ("bl", "blx"):
                calls.append((pc, op, call_target(ins)))
                # Treat direct callee as returning; preserve indirect uncertainty.
                if call_target(ins) is None:
                    notes.append(f"INDIRECT_CALL_UNRESOLVED_0x{pc:08X}")
                pc = next_pc
                continue
            if op in CONDITIONAL_BRANCHES or op == "b":
                tgt = call_target(ins)
                branches.append((pc, op, tgt))
                if tgt is not None and entry <= tgt < limit:
                    todo.append(tgt)
                else:
                    notes.append(f"OUT_OF_WINDOW_OR_UNKNOWN_BRANCH_0x{pc:08X}_TO_{tgt}")
                if op != "b":
                    todo.append(next_pc)
                break
            ret = is_return(ins)
            if ret is not None:
                endings.append((pc, ret))
                if ret.startswith("INDIRECT"):
                    notes.append(f"INDIRECT_CONTROL_FLOW_0x{pc:08X}")
                break
            pc = next_pc
        if steps >= MAX_STEPS_PER_BLOCK:
            notes.append(f"BLOCK_STEP_LIMIT_0x{pc:08X}")
    if todo or len(seen) >= MAX_INSNS or len(blocks) >= MAX_BLOCKS:
        notes.append(f"CFG_LIMIT_REACHED INSNS={len(seen)} BLOCKS={len(blocks)} PENDING={len(todo)}")
    if entry not in seen:
        abort(f"entry not disassembled 0x{entry:08X}")
    emit(f"ENTRY=0x{entry:08X} LOCAL_LIMIT_EXCLUSIVE=0x{limit:08X}")
    emit(f"LOCAL_CFG_INSNS={len(seen)} BLOCKS={len(blocks)} CALLS={len(calls)} BRANCHES={len(branches)} RETURNS_OR_INDIRECTS={len(endings)} NOTES={len(notes)}")
    emit("WARNING=LOCAL_CFG_ONLY, CALLEES_NOT_FOLLOWED, ALL_BL_ASSUMED_RETURN, NO_RUNTIME_ID_SEMANTICS")
    emit("\n=== REACHABLE_INSTRUCTIONS ===")
    for a, ins in sorted(seen.items()):
        emit(printable(ins, image))
    emit("\n=== DIRECT_AND_INDIRECT_CALLS ===")
    for a, op, tgt in sorted(calls):
        emit(f"0x{a:08X} {op} -> " + (f"0x{tgt:08X}" if tgt is not None else "INDIRECT"))
    emit("\n=== LOCAL_BRANCHES ===")
    for a, op, tgt in sorted(branches):
        emit(f"0x{a:08X} {op} -> " + (f"0x{tgt:08X}" if tgt is not None else "UNKNOWN"))
    emit("\n=== RETURNS_AND_R0_NEIGHBORS (PC NEIGHBORS, NOT SSA) ===")
    for a, kind in sorted(endings):
        emit(f"RETURN_OR_INDIRECT 0x{a:08X} {kind}")
        for x in sorted(i for i in seen if a - 0x22 <= i < a):
            ins = seen[x]
            if ins.reg_name(ins.operands[0].reg) == "r0" if ins.operands and ins.operands[0].type == 1 else False:
                emit("  R0_NEAR="+printable(ins,image))
    emit("\n=== NOTES ===")
    for note in notes[:100]:
        emit(note)
    if not notes:
        emit("NONE_IN_LOCAL_BOUNDS")
    return calls


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument("--out", type=Path)
    parser.add_argument("--self-test", action="store_true")
    a = parser.parse_args()
    self_test()
    if a.self_test:
        return 0
    root = a.root.resolve()
    expected_folder = (root / "research/f2/work/reports").resolve()
    out = (a.out if a.out is not None else expected_folder / REPORT_NAME).resolve()
    if out != expected_folder / REPORT_NAME:
        abort("report must be the canonical work/reports filename")
    if out.exists():
        print(f"REPORT_ALREADY_EXISTS_UNCHANGED={out}")
        return 0
    try:
        from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_LITTLE_ENDIAN
    except ImportError as exc:
        abort("Capstone required for analysis in Windows Python environment: " + str(exc))
    alice = Image("ALICE", root / "research/f2/work/extracted/altice_alice/alice-py.bin", ALICE_BASE, ALICE_SIZE, ALICE_SHA)
    zimage = Image("ZIMAGE", root / "research/f2/work/extracted/altice_platform/zimage.bin", ZIMAGE_BASE, ZIMAGE_SIZE, ZIMAGE_SHA)
    for addr, code in ALICE_ANCHORS.items():
        got = alice.read(addr, len(bytes.fromhex(code)))
        if got != bytes.fromhex(code):
            abort(f"ALICE byte anchor FAIL addr=0x{addr:08X} expected={code} got={got}")
    for addr, code in ZIMAGE_ANCHORS.items():
        got = zimage.read(addr, len(bytes.fromhex(code)))
        if got != bytes.fromhex(code):
            abort(f"ZIMAGE byte anchor FAIL addr=0x{addr:08X} expected={code} got={got}")
    if alice.word(CALLBACK_PTR_CELL) != CALLBACK_PTR:
        abort("callback literal at 0x1031C7B4 differs from 0x1033F46D")
    if alice.word(VENEER_LITERAL) != TARGET_FRAMEWORK:
        abort("ARM veneer literal at 0x102FD198 differs from 0xF02E4229")
    if alice.word(0x103937BC) != 0x2E69:
        abort("A107 r3 literal 0x2E69 mismatch")
    cs = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_LITTLE_ENDIAN)
    cs.detail = True
    output = []
    emit = output.append
    emit("S13.5A.110 — A109 CONCRETE REGISTERED CALLBACK AND PARENT SOURCE")
    emit("STRICTLY_OFFLINE=YES READ_ONLY_CANONICAL_IMAGES=YES REPORT_ONLY=YES NO_NOTEPAD=YES")
    emit(alice.guard)
    emit(zimage.guard)
    emit(f"ALICE_EXACT_BYTE_ANCHORS=PASS COUNT={len(ALICE_ANCHORS)} ZIMAGE_EXACT_BYTE_ANCHORS=PASS COUNT={len(ZIMAGE_ANCHORS)}")
    emit("LITERAL_CHAIN=1031C7B4:1033F46D -> Thumb callback 1033F46C")
    emit("REGISTRATION_CONTEXT=10393784 BL 103956A4 -> 1031C714 r0; logical child r1=4; r2=callback; r3=pool slot")
    emit("HISTORICAL_FRAMEWORK=F02E4228 ALREADY CLASSIFIED S11; NOT REAUDITED")
    emit("WARNING=no menu ID, direct Audio launcher, 0x6314/0x6316 event binding or slot+0x0C setter proven")
    emit("\n=== A. CALLBACK 0x1033F46C — ONLY LOCAL THUMB CFG ===")
    callback_calls = bounded_cfg(cs, alice, CALLBACK_ENTRY, CALLBACK_ENTRY+0x500, emit)
    relevant = sorted(set(t for _,_,t in callback_calls if t in AUDIO_NATIVE_CORE))
    emit("CALLBACK_DIRECT_TARGETS_EXACT_AUDIO_CORE=" + (", ".join(f"0x{x:08X}" for x in relevant) if relevant else "NONE_IN_LOCAL_CFG"))
    emit("NOTES=address proximity alone does not link callback to native Audio Player")
    emit("\n=== B. PARENT / REGISTRATION-FIRST-ARG SOURCE 0x103956A4 ===")
    bounded_cfg(cs, alice, PARENT_SOURCE, PARENT_SOURCE+0x300, emit)
    emit("\n=== DECISION ===")
    emit("CLASSIFY_ONLY_IF=callback exact path and getter return semantics show concrete Audio/Multimedia linkage")
    emit("DO_NOT_CONFLATE=F02E4228 generic parent/key with packed B702 Multimedia child enumeration")
    emit("AUDIO_NATIVE_0x8928_MENU_BINDING=UNPROVEN FM_NUMERIC_ROM_ID=UNKNOWN")
    emit("FIRMWARE_MODIFIED=NO; USB_COM_PHONE_FLASH_PATCH_REPACK=NO")
    expected_folder.mkdir(parents=True, exist_ok=True)
    with out.open("x", encoding="utf-8", newline="\n") as f:
        f.write("\n".join(output) + "\n")
    print(f"A110_REPORT_CREATED={out} BYTES={out.stat().st_size}")
    print("A110_STATUS=REPORT_AVAILABLE_REVIEW_REQUIRED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
