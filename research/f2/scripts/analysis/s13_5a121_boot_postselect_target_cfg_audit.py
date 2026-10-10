#!/usr/bin/env python3
"""S13.5A.121: classify the actual BOOT_ZIMAGE target of ALICE's post-selection BLX.

STRICTLY OFFLINE. Read-only canonical images; writes only one exclusive TXT report.
No hardware/USB/COM, no firmware mutation, no emulated callback execution.

The target address and BOOT image metadata are historical S13.5A.34/35 facts.
CFG disassembly is intentionally bounded; it cannot prove real UI OK or app launch.
"""
from __future__ import annotations

import argparse
import hashlib
import re
import struct
import sys
from collections import deque
from pathlib import Path

ALICE_BASE = 0x1024EC00
BOOT_BASE = 0xF01F19E4
ZIMAGE_BASE = 0xF023CA50

ALICE_SIZE = 0x157BB4
BOOT_SIZE = 0x4B06C
ZIMAGE_SIZE = 0x185E98

ALICE_SHA = "7246242b67afae0d13104452bc3257827cb778119b54e7a26fb7fb55993697ea"
BOOT_SHA = "aa070292e9c1685eddb12080b3f0bbca763102adaf085016b4e503a3930b4c3e"
ZIMAGE_SHA = "85fba8c8ae8161e4c1f8ced7983ec30d48c54ab10e51c69fcdfb900aca220954"

CALLSITE = 0x10342FDE
VENEER = 0x102FD0A4
LITERAL_CELL = 0x102FD0A8
TARGET_PTR = 0xF020D0A9
TARGET = TARGET_PTR & ~1
MAX_BYTES = 0x280
MAX_INSN = 240


def assert_canonical(path: Path, label: str, size: int, sha: str) -> bytes:
    if not path.is_file():
        raise RuntimeError(f"MISSING_{label}={path}")
    blob = path.read_bytes()
    observed = hashlib.sha256(blob).hexdigest()
    if len(blob) != size or observed != sha:
        raise RuntimeError(
            f"{label}_HASH_OR_SIZE_MISMATCH path={path} size=0x{len(blob):X} "
            f"sha256={observed} expected_size=0x{size:X} expected_sha256={sha}"
        )
    return blob


def u32(buf: bytes, offset: int) -> int:
    return struct.unpack_from("<I", buf, offset)[0]


def check_inputs(alice: bytes, boot: bytes, zimage: bytes) -> None:
    if len(alice) != ALICE_SIZE or len(boot) != BOOT_SIZE or len(zimage) != ZIMAGE_SIZE:
        raise RuntimeError("IMAGE_SIZE_GUARD_FAILURE")
    if BOOT_BASE + BOOT_SIZE != ZIMAGE_BASE:
        raise RuntimeError("BOOT_ZIMAGE_BOUNDARY_ERROR")
    if not (BOOT_BASE <= TARGET < ZIMAGE_BASE):
        raise RuntimeError("TARGET_NOT_IN_BOOT_ZIMAGE")
    call_off = CALLSITE - ALICE_BASE
    ve_off = VENEER - ALICE_BASE
    if alice[call_off:call_off+4] != bytes.fromhex("baf762e8"):
        raise RuntimeError(f"A120_CALLSITE_BYTES_MISMATCH={alice[call_off:call_off+4].hex()}")
    if alice[ve_off:ve_off+4] != bytes.fromhex("04f01fe5"):
        raise RuntimeError("A120_ARM_VENEER_BYTES_MISMATCH")
    if u32(alice, LITERAL_CELL - ALICE_BASE) != TARGET_PTR:
        raise RuntimeError("A120_ARM_VENEER_LITERAL_MISMATCH")
    if TARGET - BOOT_BASE != 0x1B6C4:
        raise RuntimeError("TARGET_BOOT_OFFSET_MISMATCH")


def make_decoder():
    try:
        from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_LITTLE_ENDIAN
    except ImportError as e:
        raise RuntimeError("CAPSTONE_MODULE_REQUIRED") from e
    md = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_LITTLE_ENDIAN)
    md.detail = True
    return md


def decode_one(md, boot: bytes, addr: int):
    if not (BOOT_BASE <= addr < ZIMAGE_BASE):
        return None
    offset = addr - BOOT_BASE
    return next(md.disasm(boot[offset:offset + 4], addr, 1), None)


def immediate_dest(insn):
    try:
        from capstone.arm import ARM_OP_IMM
        operands = insn.operands
        if operands and operands[-1].type == ARM_OP_IMM:
            return operands[-1].imm & 0xFFFFFFFF
    except (AttributeError, ImportError, IndexError):
        return None
    return None


def branch_kind(insn):
    """Return (classification, branch target). No inferred dynamic targets."""
    m = insn.mnemonic.lower().split(".")[0]
    op = insn.op_str.lower().replace(" ", "")
    # Function exit, load-pc and indirect branches must not be followed.
    if m == "pop" and "pc" in op or m == "bx" and op == "lr":
        return ("RETURN", None)
    if m in ("bx", "blx") and m == "bx":
        return ("INDIRECT_BRANCH", None)
    if m in ("bl", "blx"):
        dest = immediate_dest(insn)
        return (("DIRECT_CALL" if dest is not None else "INDIRECT_CALL"), dest)
    if m in ("cbz", "cbnz"):
        return ("CONDITIONAL_BRANCH", immediate_dest(insn))
    if m in ("tbb", "tbh"):
        return ("COMPUTED_BRANCH", None)
    if m.startswith("b") and m not in ("bic", "bfi", "bfc", "bkpt"):
        dst = immediate_dest(insn)
        if m in ("b",):
            return ("UNCONDITIONAL_BRANCH", dst)
        if m in ("beq", "bne", "bcs", "bcc", "bhs", "blo", "bmi", "bpl",
                 "bvs", "bvc", "bhi", "bls", "bge", "blt", "bgt", "ble"):
            return ("CONDITIONAL_BRANCH", dst)
    if m in ("mov", "movs", "ldr", "ldm", "ldmia", "add", "adds", "sub", "subs") and re.match(r"^pc[, ]", insn.op_str.lower()):
        return ("COMPUTED_BRANCH", None)
    if m in ("svc", "udf", "bkpt"):
        return ("TRAP", None)
    return ("LINEAR", None)


def literal_info(insn, boot: bytes):
    """Only ordinary Thumb PC-relative LDR word; no alias/execution inference."""
    if insn.mnemonic.split(".")[0] not in ("ldr",):
        return None
    try:
        from capstone.arm import ARM_OP_MEM, ARM_REG_PC
        ops = insn.operands
        if len(ops) < 2 or ops[1].type != ARM_OP_MEM or ops[1].mem.base != ARM_REG_PC:
            return None
        addr = ((insn.address + 4) & ~3) + ops[1].mem.disp
        if not (BOOT_BASE <= addr <= ZIMAGE_BASE - 4):
            return (addr, None)
        return (addr, u32(boot, addr - BOOT_BASE))
    except (ImportError, AttributeError, IndexError):
        return None


def walk_cfg(boot: bytes):
    md = make_decoder()
    lo, hi = TARGET, min(TARGET + MAX_BYTES, ZIMAGE_BASE)
    todo = deque([TARGET]); seen = {}; calls = []; branches = []; literals = []
    problems = []; exits = []; budget = MAX_INSN
    while todo:
        ip = todo.popleft()
        if ip in seen:
            continue
        if ip < lo or ip >= hi:
            problems.append(f"OUTSIDE_BOUNDED_ENTRY={ip:#010x}")
            continue
        if budget == 0:
            problems.append("INSTRUCTION_CAP_REACHED")
            break
        insn = decode_one(md, boot, ip)
        if insn is None:
            problems.append(f"DECODE_FAILED={ip:#010x}")
            continue
        budget -= 1
        seen[ip] = insn
        kind, target = branch_kind(insn)
        if (lit := literal_info(insn, boot)) is not None:
            literals.append((ip, *lit))
        nxt = ip + insn.size
        if kind == "RETURN":
            exits.append((ip, kind))
        elif kind in ("TRAP", "INDIRECT_BRANCH", "COMPUTED_BRANCH"):
            problems.append(f"UNRESOLVED_{kind}={ip:#010x}")
        elif kind in ("DIRECT_CALL", "INDIRECT_CALL"):
            calls.append((ip, kind, target))
            todo.append(nxt)
        elif kind in ("UNCONDITIONAL_BRANCH", "CONDITIONAL_BRANCH"):
            branches.append((ip, kind, target))
            if target is None:
                problems.append(f"UNKNOWN_BRANCH_DEST={ip:#010x}")
            else:
                todo.append(target)
            if kind == "CONDITIONAL_BRANCH":
                todo.append(nxt)
        else:
            todo.append(nxt)
    return seen, calls, branches, literals, exits, problems


def report(alice: bytes, boot: bytes, zimage: bytes, bootpath: Path) -> str:
    # Verified images before report(); checks are intentionally repeated here.
    check_inputs(alice, boot, zimage)
    selected, calls, branches, literals, exits, problems = walk_cfg(boot)
    lines = [
        "S13.5A.121 — BOOT_ZIMAGE TARGET OF POST-SELECTION 0x10342FDE BLX",
        "STRICTLY_OFFLINE=YES IMAGES_READ_ONLY=YES NO_USB_COM_PHONE_FLASH_PATCH_REPACK=YES",
        "NO_GUEST_CALLBACK_EXECUTION=YES NO_UI_OK_PROOF=YES",
        f"ALICE_GUARD=PASS SIZE=0x{ALICE_SIZE:X} SHA256={ALICE_SHA}",
        f"BOOT_ZIMAGE_GUARD=PASS SIZE=0x{BOOT_SIZE:X} SHA256={BOOT_SHA}",
        f"ZIMAGE_GUARD=PASS SIZE=0x{ZIMAGE_SIZE:X} SHA256={ZIMAGE_SHA}",
        f"BOOT_FILE_USED={bootpath}",
        f"BOOT_RUNTIME_RANGE=[0x{BOOT_BASE:08X},0x{ZIMAGE_BASE:08X})",
        f"A120_CALLSITE_GUARD=PASS BLX_AT=0x{CALLSITE:08X} ARM_VENEER=0x{VENEER:08X}",
        f"A120_LITERAL_GUARD=PASS RAW_PTR=0x{TARGET_PTR:08X} BOOT_THUMB_TARGET=0x{TARGET:08X}",
        f"BOOT_TARGET_FILE_OFFSET=0x{TARGET-BOOT_BASE:X} WITHIN_BOOT=YES",
        "HISTORICAL_NOTE=F020D0A8_ALSO_REFERENCED_BY_A79;THIS_AUDIT_ONLY_TRACES_A119_SELECTION_EDGE",
        "LIMIT=BOUNDED_CFG_ONLY_NOT_FULL_RUNTIME_NOT_APPLICATION_OPENING",
        "",
        "=== A. REACHABLE BOUNDED THUMB INSTRUCTIONS (TARGET-LOCAL CFG) ===",
        f"TARGET=0x{TARGET:08X} CAP_INSTRUCTIONS={MAX_INSN} WINDOW_BYTES=0x{MAX_BYTES:X}",
    ]
    for a, insn in sorted(selected.items()):
        k, dest = branch_kind(insn)
        ds = f" -> 0x{dest:08X}" if dest is not None else ""
        lines.append(f"  0x{a:08X} {insn.bytes.hex():10} {insn.mnemonic:9} {insn.op_str:32} [{k}]{ds}")
    lines.extend(["", "=== B. DISPATCH / CALL / BRANCH EVIDENCE ===", f"VISITED_INSTRUCTIONS={len(selected)}", f"DIRECT_OR_INDIRECT_CALLS={len(calls)}"])
    for src, kind, dst in calls:
        lines.append(f"CALL=0x{src:08X} KIND={kind} TARGET={('0x%08X'%dst) if dst is not None else 'UNKNOWN_INDIRECT'}")
    lines.append(f"EXPLICIT_BRANCHES={len(branches)}")
    for src, kind, dst in branches:
        lines.append(f"BRANCH=0x{src:08X} KIND={kind} TARGET={('0x%08X'%dst) if dst is not None else 'UNKNOWN'}")
    lines.append(f"EXITS={len(exits)}")
    for src, kind in exits:
        lines.append(f"EXIT=0x{src:08X} KIND={kind}")
    lines.append(f"PC_LITERALS={len(literals)}")
    for src, at, v in literals:
        lines.append(f"PC_LITERAL_USE=0x{src:08X} CELL=0x{at:08X} VALUE={('0x%08X'%v) if v is not None else 'OUTSIDE_BOOT'}")
    lines.extend([f"BOUNDARY_NOTES={len(problems)}", *problems])
    lines.extend([
        "", "=== C. HONEST EVIDENCE GATES ===",
        f"TARGET_PREFIX_CLASSIFIED={'YES' if selected and TARGET in selected else 'NO'}",
        f"BOUNDED_CFG_HAS_UNRESOLVED_EDGES={'YES' if problems else 'NO'}",
        "ABI_R0_R1_ON_REAL_DEVICE=UNPROVEN_A119_SYNTHETIC_CONTEXT_ONLY",
        "REAL_B702_VISIBLE_MENU_OK_TO_APPLICATION_DISPATCH=UNPROVEN",
        "AUDIO_8928_REGISTRATION_CALLBACK_IS_DIRECT_LAUNCH=UNPROVEN",
        "SAFE_ROM_RELOCATION_STORAGE_AND_BOOT_INTEGRITY=UNPROVEN",
        "NO_HARDWARE_PATCH_AUTHORIZED=YES",
        "NEXT=CLASSIFY_ACTUAL_REACHABLE_TARGET_FUNCTION_FROM_THIS_REPORT_NOT_GENERIC_SCAN",
    ])
    return "\n".join(lines) + "\n"


def self_test():
    assert BOOT_BASE + BOOT_SIZE == ZIMAGE_BASE
    assert TARGET - BOOT_BASE == 0x1B6C4
    assert (TARGET_PTR & 1) == 1 and TARGET == 0xF020D0A8
    dummy_alice = bytearray(ALICE_SIZE)
    dummy_alice[CALLSITE-ALICE_BASE:CALLSITE-ALICE_BASE+4] = bytes.fromhex('baf762e8')
    dummy_alice[VENEER-ALICE_BASE:VENEER-ALICE_BASE+4] = bytes.fromhex('04f01fe5')
    struct.pack_into('<I', dummy_alice, LITERAL_CELL-ALICE_BASE, TARGET_PTR)
    check_inputs(bytes(dummy_alice), bytes(BOOT_SIZE), bytes(ZIMAGE_SIZE))
    dummy_alice[LITERAL_CELL-ALICE_BASE] ^= 0x01
    try:
        check_inputs(bytes(dummy_alice), bytes(BOOT_SIZE), bytes(ZIMAGE_SIZE))
    except RuntimeError as e:
        assert 'LITERAL_MISMATCH' in str(e)
    else:
        raise AssertionError('invalid literal was accepted')
    print('A121_SELF_TEST=PASS_BOOT_RANGE_AND_A120_VENEER_GUARDS')


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--root', type=Path, help='F2-Altice-MobiWire working tree containing ALICE and ZIMAGE')
    p.add_argument('--boot', type=Path, help='Exact canonical BOOT_ZIMAGE extraction, usually in mtkclient research tree')
    p.add_argument('--out', type=Path, help='Exclusive TXT report pathname; never overwritten')
    p.add_argument('--self-test', action='store_true')
    a = p.parse_args()
    if a.self_test:
        self_test()
        if a.root is None and a.boot is None and a.out is None:
            return 0
    if not (a.root and a.boot and a.out):
        p.error('canonical --root, --boot, and --out are required unless --self-test only')
    try:
        alice = assert_canonical(a.root/'research/f2/work/extracted/altice_alice/alice-py.bin', 'ALICE', ALICE_SIZE, ALICE_SHA)
        zimage = assert_canonical(a.root/'research/f2/work/extracted/altice_platform/zimage.bin', 'ZIMAGE', ZIMAGE_SIZE, ZIMAGE_SHA)
        boot = assert_canonical(a.boot, 'BOOT_ZIMAGE', BOOT_SIZE, BOOT_SHA)
        text = report(alice, boot, zimage, a.boot.resolve())
        a.out.parent.mkdir(parents=True, exist_ok=True)
        # Exclusive creation avoids overwriting established evidence.
        with a.out.open('x', encoding='utf-8', newline='\n') as fp:
            fp.write(text)
        print('A121_REPORT_CREATED='+str(a.out.resolve()))
        print('A121_RESULT=BOUNDED_CFG_PRODUCED_VERIFY_SEMANTICS_MANUALLY')
        return 0
    except (OSError, RuntimeError, ValueError, IndexError) as e:
        print('A121_ABORT='+str(e), file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
