#!/usr/bin/env python3
"""S13.5A.109: bounded ARM interworking audit of the exact A108 BLX callee.

Offline, SHA-pinned, read-only firmware inspection.  Only a .txt report is written.
No USB, COM, firmware writing, flashing, repacking or Notepad use.

The A108 call at 0x1031C7A2 is Thumb BLX (immediate): callee 0x102FD194
MUST be decoded as ARM, not Thumb.  Recover a direct ARM tail/veneer target,
when it can be proven from literal-loaded registers, and decode only a short
window of the resolved target.  Does not execute code, prove callback reachability,
or classify a returned handle without further evidence.
"""
from __future__ import annotations
import argparse
import hashlib
from pathlib import Path
import sys

ALICE_BASE, ALICE_SIZE = 0x1024EC00, 0x157BB4
ALICE_SHA = "7246242b67afae0d13104452bc3257827cb778119b54e7a26fb7fb55993697ea"
ZIMAGE_BASE, ZIMAGE_SIZE = 0xF023CA50, 0x185E98
ZIMAGE_SHA = "85fba8c8ae8161e4c1f8ced7983ec30d48c54ab10e51c69fcdfb900aca220954"
CALLSITE = 0x1031C7A2
ARM_ENTRY = 0x102FD194
CALLBACK_LITERAL = 0x1031C7B4
CALLBACK_THUMB = 0x1033F46D
FIELD_STORE = 0x1039570E

# Exactly documented A.107/A.108 anchors, no guessed firmware bytes.
ANCHORS = {
    0x1031C79A: "064a",      # LDR r2, =callback
    0x1031C79C: "0198",      # LDR r0, [sp,#4]
    0x1031C79E: "2300",      # MOVS r3,r4
    0x1031C7A0: "0421",      # MOVS r1,#4
    0x1031C7A2: "e0f7f8ec",  # BLX ARM_ENTRY
    0x1031C7A6: "05b0",      # ADD sp,#0x14
    0x1031C7A8: "f0bd",      # POP {...,pc}
    0x10393796: "88f7bdff",  # BL 1031C714
    0x1039379C: "01f0b6ff",  # BL setter
    0x1039570C: "0149",      # LDR r1,=F0115F64
    0x1039570E: "4880",      # STRH r0,[r1,#2]
}


def abort(message: str) -> None:
    raise RuntimeError("ABORT: " + message)


class Image:
    def __init__(self, label: str, path: Path, base: int, size: int, sha: str):
        if not path.is_file():
            abort(f"{label} missing: {path}")
        self.label, self.base = label, base
        self.data = path.read_bytes()
        digest = hashlib.sha256(self.data).hexdigest()
        if len(self.data) != size or digest != sha:
            abort(f"{label} CANON GUARD FAIL: size={len(self.data):#x} sha256={digest}")
        self.guard = f"{label}_GUARD=PASS BYTES=0x{size:X} SHA256={digest}"

    def read(self, addr: int, n: int) -> bytes | None:
        p = addr - self.base
        if p < 0 or n < 0 or p + n > len(self.data):
            return None
        return self.data[p:p+n]

    def u32(self, addr: int) -> int | None:
        b = self.read(addr, 4)
        return int.from_bytes(b, "little") if b is not None else None


def locate(images: list[Image], addr: int, n: int = 4) -> Image | None:
    return next((im for im in images if im.read(addr, n) is not None), None)


def decode_one(cs, im: Image, addr: int):
    raw = im.read(addr, 4)
    if raw is None:
        return None
    ins = list(cs.disasm(raw, addr, count=1))
    return ins[0] if ins and ins[0].address == addr else None


def arm_literal(ins, im, ARM_OP_MEM, ARM_REG_PC):
    """Resolve standard ARM PC-relative LDR of a literal, with no index register."""
    if not ins.mnemonic.lower().startswith("ldr") or len(ins.operands) < 2:
        return None
    op = ins.operands[1]
    if op.type != ARM_OP_MEM or op.mem.base != ARM_REG_PC or op.mem.index != 0:
        return None
    cell = (ins.address + 8 + op.mem.disp) & 0xffffffff
    value = im.u32(cell)
    return (cell, value) if value is not None else None


def inspect_arm_veneer(cs, images, ARM_OP_REG, ARM_OP_IMM, ARM_REG_PC, ARM_OP_MEM):
    im = locate(images, ARM_ENTRY)
    if im is None:
        abort("ARM entry out of canonical images")
    out = ["=== A109 ARM ENTRY DISASSEMBLY ===", f"ARM_ENTRY=0x{ARM_ENTRY:08X} IMAGE={im.label}"]
    out.append("MODE=ARM as required by Thumb BLX immediate at 1031C7A2")
    regs = {}
    pc = ARM_ENTRY
    resolved = None
    reason = "UNKNOWN"
    # Follow one straight-line ARM veneer: stop at the first control flow.
    for index in range(24):
        ins = decode_one(cs, im, pc)
        if ins is None or ins.size != 4:
            out.append(f"DECODE_STOP 0x{pc:08X}")
            break
        m = ins.mnemonic.lower().split(".")[0]
        line = f"0x{pc:08X} {ins.bytes.hex()} {ins.mnemonic:9s} {ins.op_str}"
        lit = arm_literal(ins, im, ARM_OP_MEM, ARM_REG_PC)
        if lit:
            line += f" ; literal[0x{lit[0]:08X}]=0x{lit[1]:08X}"
            if ins.operands and ins.operands[0].type == ARM_OP_REG:
                regs[ins.operands[0].reg] = lit[1]
        elif ins.operands and ins.operands[0].type == ARM_OP_REG and m in ("mov", "movs") and len(ins.operands) > 1:
            if ins.operands[1].type == ARM_OP_REG:
                src = ins.operands[1].reg
                if src in regs:
                    regs[ins.operands[0].reg] = regs[src]
                else:
                    regs.pop(ins.operands[0].reg, None)
            else:
                regs.pop(ins.operands[0].reg, None)
        out.append(line)
        # ARM LDR pc, [pc,#literal] is common absolute veneer.
        if m.startswith("ldr") and ins.operands and ins.operands[0].type == ARM_OP_REG and ins.operands[0].reg == ARM_REG_PC:
            if lit:
                resolved = lit[1]
                reason = "ARM_LDR_PC_LITERAL"
            else:
                reason = "ARM_PC_LOAD_NOT_STATIC"
            break
        if m in ("bx", "blx") and ins.operands:
            op = ins.operands[0]
            if op.type == ARM_OP_REG:
                if op.reg in regs:
                    resolved = regs[op.reg]
                    reason = f"ARM_{m.upper()}_REGISTER_KNOWN_LITERAL"
                else:
                    reason = f"ARM_{m.upper()}_REGISTER_UNRESOLVED"
            elif op.type == ARM_OP_IMM:
                resolved = op.imm & 0xffffffff
                reason = f"ARM_{m.upper()}_IMMEDIATE"
            break
        if m == "b" and ins.operands and ins.operands[0].type == ARM_OP_IMM:
            resolved = ins.operands[0].imm & 0xffffffff
            reason = "ARM_B_IMMEDIATE"
            break
        if m.startswith(("bne", "beq", "bgt", "blt", "bhs", "blo", "bge", "ble", "bpl", "bmi")):
            reason = "ARM_CONDITIONAL_BRANCH_UNFOLLOWED"
            break
        if m in ("pop", "ldm", "ldmia", "ldmfd") and "pc" in ins.op_str.lower():
            reason = "ARM_PC_RETURN_OR_DYNAMIC_BRANCH"
            break
        if m in ("bl",):
            reason = "ARM_FUNCTION_BODY_CALL_NOT_A_SIMPLE_VENEER"
            break
        pc += 4
    else:
        reason = "ARM_LINEAR_LIMIT_24"
    out.append(f"ARM_DIRECT_TRANSFER_REASON={reason}")
    out.append(f"ARM_DIRECT_TRANSFER_TARGET={'0x%08X' % resolved if resolved is not None else 'UNRESOLVED'}")
    return out, resolved, reason


def show_bounded_target(cs_arm, cs_thumb, images, target):
    out = ["", "=== RESOLVED TARGET LOCAL INSTRUCTION WINDOW (NOT CFG) ==="]
    if target is None:
        out.append("TARGET=UNRESOLVED; NO_SPECULATIVE_FOLLOW")
        return out
    is_thumb = bool(target & 1)
    addr = target & ~1
    im = locate(images, addr)
    if im is None:
        out.append(f"TARGET=0x{target:08X} OUTSIDE_CANONICAL_IMAGES; STOP")
        return out
    mode = "THUMB" if is_thumb else "ARM"
    out.append(f"TARGET_RAW=0x{target:08X} EFFECTIVE=0x{addr:08X} MODE={mode} IMAGE={im.label}")
    cs = cs_thumb if is_thumb else cs_arm
    for _ in range(24):
        ins = decode_one(cs, im, addr)
        if ins is None:
            out.append(f"DECODE_STOP 0x{addr:08X}")
            break
        out.append(f"0x{addr:08X} {ins.bytes.hex():10s} {ins.mnemonic:9s} {ins.op_str}")
        m = ins.mnemonic.lower().split(".")[0]
        if m in ("b", "bx", "bl", "blx", "pop", "tbb", "tbh") or m.startswith(("bne", "beq", "bgt", "blt", "bhs", "blo")):
            out.append("STOP=CONTROL_TRANSFER_UNFOLLOWED")
            break
        addr += ins.size
    return out


def self_test():
    assert len(ANCHORS) == 11
    assert bytes.fromhex(ANCHORS[CALLSITE]) == b"\xe0\xf7\xf8\xec"
    assert bytes.fromhex(ANCHORS[0x1031C79C]) == b"\x01\x98"
    assert bytes.fromhex(ANCHORS[0x1031C7A0]) == b"\x04\x21"
    assert int.from_bytes((CALLBACK_THUMB).to_bytes(4, "little"), "little") == CALLBACK_THUMB
    assert ARM_ENTRY % 4 == 0
    print("A109_SELF_TEST=PASS 11_ANCHORS_AND_ARM_THUMB_INTERWORKING_ASSUMPTIONS")


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--root", type=Path, default=Path.cwd())
    ap.add_argument("--out", type=Path, default=None)
    ap.add_argument("--self-test", action="store_true")
    args = ap.parse_args()
    self_test()
    if args.self_test:
        return 0
    root = args.root.resolve()
    out = args.out or root / "research/f2/work/reports/s13_5a109_102fd194_arm_interworking_audit.txt"
    if out.exists():
        print(f"REPORT_ALREADY_EXISTS_UNCHANGED={out}")
        return 0
    try:
        from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_THUMB, CS_MODE_LITTLE_ENDIAN
        from capstone.arm import ARM_OP_REG, ARM_OP_IMM, ARM_OP_MEM, ARM_REG_PC
    except ImportError as e:
        abort("Capstone required in Windows Python environment: " + str(e))
    alice = Image("ALICE", root/"research/f2/work/extracted/altice_alice/alice-py.bin", ALICE_BASE, ALICE_SIZE, ALICE_SHA)
    zimage = Image("ZIMAGE", root/"research/f2/work/extracted/altice_platform/zimage.bin", ZIMAGE_BASE, ZIMAGE_SIZE, ZIMAGE_SHA)
    images = [alice, zimage]
    for addr, expected in ANCHORS.items():
        raw = alice.read(addr, len(bytes.fromhex(expected)))
        if raw != bytes.fromhex(expected):
            abort(f"ALICE anchor mismatch at 0x{addr:08X}: got {raw}, expected {expected}")
    if alice.u32(CALLBACK_LITERAL) != CALLBACK_THUMB:
        abort(f"callback pointer literal mismatch at 0x{CALLBACK_LITERAL:08X}")
    md_arm = Cs(CS_ARCH_ARM, CS_MODE_ARM | CS_MODE_LITTLE_ENDIAN)
    md_thumb = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_LITTLE_ENDIAN)
    md_arm.detail = True
    md_thumb.detail = True
    call = decode_one(md_thumb, alice, CALLSITE)
    if not call or call.mnemonic != "blx" or not call.operands or call.operands[-1].type != ARM_OP_IMM or (call.operands[-1].imm & ~1) != ARM_ENTRY:
        abort("A108 callsite not Thumb BLX immediate to ARM 0x102FD194")
    lines = [
        "S13.5A.109 — A108 0x102FD194 ARM INTERWORKING VENEER / RETURN-PATH AUDIT",
        "STRICTLY_OFFLINE=YES INPUTS_READ_ONLY=YES NO_USB_COM_PHONE_FLASH_PATCH_REPACK=YES",
        alice.guard,zimage.guard,
        "A108_EXACT_INSTRUCTION_ANCHORS=PASS COUNT=11",
        "A108_CALLBACK_LITERAL=PASS 0x1031C7B4->0x1033F46D",
        f"THUMB_BLX_CALLSITE=PASS 0x{CALLSITE:08X} {call.bytes.hex()} -> 0x{ARM_ENTRY:08X} MODE_ARM",
        "CALL_ARG_R0=ORIGINAL_ENTRY_R0_STORED_IN_PUSH_FRAME; ACTUAL_VALUE=UNKNOWN",
        "CALL_ARG_R1=4 CALL_ARG_R2=0x1033F46D_THUMB_CALLBACK CALL_ARG_R3=R4_POOL_RECORD",
        "KNOWN_A107_CALLER_ARG_R3_TO_1031C714=0x2E69 (record+0x12)",
        "A107_SETTER_RECEIVES=LOW16_RETURN_OF_A108_CALL; EXACT_SEMANTICS_NOT_ASSUMED",
        "WARNING=ARM_VENEER_ONLY; A_RESOLVED_BRANCH_TARGET_IS_NOT_YET_A_CALLBACK_LAUNCH_PROOF",
        "",
    ]
    veneer, target, reason = inspect_arm_veneer(md_arm, images, ARM_OP_REG, ARM_OP_IMM, ARM_REG_PC, ARM_OP_MEM)
    lines.extend(veneer)
    lines.extend(show_bounded_target(md_arm, md_thumb, images, target))
    lines.extend(["", "=== DECISION GATE ===",
       "If ARM target is resolved, follow that exact code path and return value only; do not repeat menu registry scans.",
       "If unresolved, collect local ARM control flow to understand ABI; do not guess indirect jump targets.",
       "F0115F66_RUNTIME_VALUE=UNPROVEN AUDIO_0x8928_MENU_CALLBACK=UNPROVEN FM_NUMERIC_ID=UNKNOWN",
       "REPORT_ONLY=YES NO_NOTEPAD=YES NO_FIRMWARE_MODIFICATIONS=YES",
       ""])
    out.parent.mkdir(parents=True, exist_ok=True)
    try:
        with out.open("x", encoding="utf-8", newline="\n") as f:
            f.write("\n".join(lines))
    except FileExistsError:
        print(f"REPORT_ALREADY_EXISTS_UNCHANGED={out}")
        return 0
    print(f"A109_REPORT_CREATED={out} BYTES={out.stat().st_size}")
    print(f"A109_ARM_TRANSFER={reason} TARGET={'0x%08X' % target if target is not None else 'UNRESOLVED'}")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except RuntimeError as e:
        sys.exit(str(e))
