#!/usr/bin/env python3
"""S13.5A.106 — exact F0115F66 halfword origin: literal consumers + local store hints.

Strictly read-only firmware. Writes only an exclusive-create TXT research report.
This is an exact-literal / local linear trace, NOT proof of executable CFG,
full pointer alias coverage, or leaf Audio activation.
"""
from __future__ import annotations

import argparse
import hashlib
from pathlib import Path
import struct

ALICE = (0x1024EC00, 0x157BB4, "7246242b67afae0d13104452bc3257827cb778119b54e7a26fb7fb55993697ea")
ZIMAGE = (0xF023CA50, 0x185E98, "85fba8c8ae8161e4c1f8ced7983ec30d48c54ab10e51c69fcdfb900aca220954")
GLOBAL_BASE = 0xF0115F64
TARGET_BYTE = GLOBAL_BASE + 2
KNOWN_BYTES = {
    0x102EF5DC: "0148",           # ldr r0, PC literal
    0x102EF5DE: "4088",           # ldrh r0,[r0,#2]
    0x102EF5E0: "7047",           # bx lr
    0x102EF5E4: "645f11f0",       # F0115F64
    0x1039CCC0: "52f78cfc",       # BL 102EF5DC
    0x1039CCC4: "50f7bcfa",       # BL 102ED240
    0x1039E49C: "51f79ef8",       # BL 102EF5DC
    0x1039E4A0: "4ef7cefe",       # BL 102ED240
    0x103A232C: "4df756f9",       # BL 102EF5DC
    0x103A2330: "4af786ff",       # BL 102ED240
}
MAX_LITERALS_PER_VALUE = 240
MAX_CONSUMERS_PER_LITERAL = 30


def abort(msg: str) -> None:
    raise SystemExit("ABORT: " + msg)


def byte_at(image, addr, n):
    base, data = image
    off = addr - base
    if off < 0 or off + n > len(data):
        return None
    return data[off:off+n]


def load(path: Path, label: str, metadata, report):
    base, size, expected = metadata
    if not path.is_file():
        abort(f"{label} missing: {path}")
    data = path.read_bytes()
    sha = hashlib.sha256(data).hexdigest()
    good = len(data) == size and sha == expected
    report.append(f"{label}_GUARD={'PASS' if good else 'FAIL'} SIZE=0x{len(data):X} SHA256={sha}")
    if not good:
        abort(f"{label} canonical file size/hash guard failed")
    return base, data


def exact_hits(data: bytes, value: int) -> list[int]:
    # All byte alignments: some packed literal pools are not word-aligned.
    needle = struct.pack('<I', value)
    hits, index = [], 0
    while True:
        index = data.find(needle, index)
        if index < 0:
            return hits
        hits.append(index)
        index += 1


def self_test():
    # Known canonical 16-bit literal LDR: PC=0x102EF5DC -> cell=0x102EF5E4.
    thumb_op = 0x4801
    pc = 0x102EF5DC
    cell = ((pc + 4) & ~3) + ((thumb_op & 0xff) << 2)
    assert cell == 0x102EF5E4
    assert (0x8840 & 0xf800) == 0x8800  # Thumb LDRH immediate family
    assert exact_hits(b'xx' + struct.pack('<I', GLOBAL_BASE) + b'z' +
                      struct.pack('<I', TARGET_BYTE), GLOBAL_BASE) == [2]
    assert exact_hits(b'xx' + struct.pack('<I', GLOBAL_BASE) + b'z' +
                      struct.pack('<I', TARGET_BYTE), TARGET_BYTE) == [7]
    assert sorted(KNOWN_BYTES) == list(KNOWN_BYTES)
    print("A106_SELF_TEST=PASS THUMB16_LITERAL_AND_UNALIGNED_U32_AND_EXACT_ANCHORS")


def get_insn(md, image, addr):
    raw = byte_at(image, addr, 4)
    if raw is None:
        return None
    decoded = list(md.disasm(raw, addr, count=1))
    return decoded[0] if decoded and decoded[0].address == addr else None


def pretty(ins):
    return f"{ins.address:08X} {ins.bytes.hex()} {ins.mnemonic} {ins.op_str}"


def mnemonic(ins):
    return ins.mnemonic.lower().split('.')[0]


def find_consumers(md, image, literal_cell, ARM_OP_IMM, ARM_OP_MEM, ARM_OP_REG, ARM_REG_PC):
    base, data = image
    # Thumb-2 LDR (literal) may reach within approximately 4 KiB.
    start = max(base, literal_cell - 0x1020)
    stop = min(base + len(data) - 4, literal_cell)
    consumers = []
    for at in range((start + 1) & ~1, stop, 2):
        ins = get_insn(md, image, at)
        if ins is None or mnemonic(ins) != 'ldr' or len(ins.operands) < 2:
            continue
        dst, src = ins.operands[:2]
        if dst.type != ARM_OP_REG or src.type != ARM_OP_MEM or src.mem.base != ARM_REG_PC:
            continue
        if getattr(src.mem, 'index', 0):
            continue
        actual = ((at + 4) & ~3) + src.mem.disp
        if actual == literal_cell:
            consumers.append((ins, ins.reg_name(dst.reg)))
    return consumers


def accesses_local(md, image, ldr, base_reg, literal_value,
                   ARM_OP_IMM, ARM_OP_MEM, ARM_OP_REG):
    # Linear trace only. NOT CFG; stops at call, unconditional jump or return.
    known = {base_reg: 0}
    results = []
    pc = ldr.address + ldr.size
    for _ in range(22):
        ins = get_insn(md, image, pc)
        if ins is None:
            results.append("  STOP=DECODE_OR_IMAGE_BOUNDS")
            break
        op_name = mnemonic(ins)
        ops = ins.operands
        if op_name in ('bl', 'blx'):
            results.append("  STOP=CALL_CLOBBER_UNTRACKED " + pretty(ins))
            break
        if op_name in ('bx', 'b', 'pop', 'tbb', 'tbh'):
            results.append("  STOP=BRANCH_OR_RETURN_UNTRACKED " + pretty(ins))
            break
        if op_name.startswith('b') or op_name.startswith('cb') or op_name == 'it':
            results.append("  STOP=CONDITIONAL_CONTROL_FLOW_UNTRACKED " + pretty(ins))
            break

        # Calculate address relative to F0115F64 if the base is tracked.
        if op_name in ('strh', 'strb', 'str', 'ldrh', 'ldrb', 'ldr') and len(ops) >= 2:
            mem = ops[1]
            if mem.type == ARM_OP_MEM:
                reg = ins.reg_name(mem.mem.base)
                if reg in known and not mem.mem.index:
                    pos = known[reg] + mem.mem.disp
                    size = {'strb': 1, 'ldrb': 1, 'strh': 2, 'ldrh': 2,
                            'str': 4, 'ldr': 4}[op_name]
                    overlap = pos <= 2 < pos + size
                    label = 'TARGET_FIELD_CANDIDATE' if overlap else 'OTHER_FIELD'
                    rw = 'WRITE' if op_name.startswith('str') else 'READ'
                    results.append(f"  {label} {rw} OFFSET={pos:+d} "+pretty(ins))
        # Propagate a simple register-to-register move; invalidate destination
        # for other register-writing ops. Intra-instruction read precedes kill.
        if ops and ops[0].type == ARM_OP_REG:
            dest = ins.reg_name(ops[0].reg)
            if op_name in ('mov', 'movs') and len(ops)>1 and ops[1].type==ARM_OP_REG:
                src = ins.reg_name(ops[1].reg)
                if src in known:
                    known[dest] = known[src]
                else:
                    known.pop(dest, None)
            elif op_name in ('add', 'adds', 'sub', 'subs'):
                # Default conservative: we don't infer offset arithmetic here.
                known.pop(dest, None)
            elif op_name not in ('str', 'strh', 'strb', 'cmp', 'cmn', 'tst'):
                known.pop(dest, None)
        pc += ins.size
    if not results:
        results.append('  NO_DIRECT_LOCAL_TARGET_ACCESS_SEEN; DOES_NOT_EXCLUDE_WRITERS')
    return results


def audit(root: Path, alice_path: Path, zimage_path: Path, out: Path):
    try:
        from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_LITTLE_ENDIAN
        from capstone.arm import ARM_OP_IMM, ARM_OP_MEM, ARM_OP_REG, ARM_REG_PC
    except ImportError as exc:
        abort('Capstone required in Windows Python venv: '+str(exc))
    lines = [
        'S13.5A.106 — GLOBAL F0115F66 HALFWORD: EXACT LITERAL READ/WRITE CANDIDATES',
        'STRICTLY_OFFLINE=YES; INPUTS_READ_ONLY=YES; REPORT_ONLY=YES; NO_NOTEPAD=YES',
        'METHOD=FULL_IMAGE_EXACT_LITERAL_REFERENCE_CENSUS_THEN_LOCAL_LINEAR_CONSUMERS',
        'BOUNDARY=NO_GLOBAL_CFG_NO_COMPUTED_ADDRESS_NO_MEMORY_ALIAS_PROOF',
    ]
    alice = load(alice_path, 'ALICE', ALICE, lines)
    zimage = load(zimage_path, 'ZIMAGE', ZIMAGE, lines)
    for addr, expected_hex in KNOWN_BYTES.items():
        actual = byte_at(alice, addr, len(bytes.fromhex(expected_hex)))
        if actual is None or actual.hex() != expected_hex:
            abort(f'known A105/A104 anchor mismatch {addr:08X}: {None if actual is None else actual.hex()}')
    lines.append(f'A105_A104_EXACT_ANCHORS=PASS count={len(KNOWN_BYTES)}')
    lines.append('EXACT_GETTER=102EF5DC LDR F0115F64; 102EF5DE LDRH [r0,#2]; 102EF5E0 BX LR')
    lines.append('GETTER_RETURNS=U16_AT_F0115F66; VALUE_SEMANTICS=UNPROVEN')
    lines.append('KNOWN_THREE_CALLERS=1039CCC0/1039E49C/103A232C THEN 102ED240')
    md = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_LITTLE_ENDIAN)
    md.detail = True

    for label, image in [('ALICE', alice), ('ZIMAGE', zimage)]:
        base, data = image
        lines.append(f'\n=== {label}: EXACT U32 LITERAL ADDRESS HITS ===')
        for target in (GLOBAL_BASE, TARGET_BYTE):
            hits = exact_hits(data, target)
            lines.append(f'LITERAL_VALUE=0x{target:08X} ALL_ALIGNMENT_HITS={len(hits)}')
            if len(hits) > MAX_LITERALS_PER_VALUE:
                abort(f'{label} 0x{target:08X}: unexpected many literals ({len(hits)}), cap to avoid unbounded report')
            for off in hits:
                cell = base + off
                lines.append(f'  CELL=0x{cell:08X} OFF=0x{off:X} ALIGNED4={not(cell & 3)}')
                consumers = find_consumers(md,image,cell,ARM_OP_IMM,ARM_OP_MEM,ARM_OP_REG,ARM_REG_PC)
                lines.append(f'  THUMB_LDR_LITERAL_RAW_CONSUMERS={len(consumers)}')
                if len(consumers) > MAX_CONSUMERS_PER_LITERAL:
                    abort(f'{label} 0x{cell:08X}: too many raw LDR consumers, refuse truncation')
                for ins, reg in consumers:
                    lines.append('    LDR_CONSUMER '+pretty(ins)+' RETURN_REG='+reg)
                    lines.extend('    '+x for x in accesses_local(
                        md,image,ins,reg,target,ARM_OP_IMM,ARM_OP_MEM,ARM_OP_REG))
    lines.extend([
        '\n=== DECISION GATE ===',
        'A store marked TARGET_FIELD_CANDIDATE is an exact-literal local linear hint, NOT a reachable producer proof.',
        'An LDR consumer is also heuristic until executable ownership and register provenance are established.',
        'No matching local store does NOT exclude indirect/computed/encoded/ARM-mode writers or platform runtime code.',
        'DO_NOT_EQUATE=F0115F66_with_6314_or_6316_or_selected_child_without_value_proof',
        'NATIVE_AUDIO_0x8928_MENU_ACTION=UNPROVEN; FM_ROM_ID=UNKNOWN',
        'NO_USB_COM_PHONE_FLASH_PATCH_REPACK=YES',
    ])
    if not out.parent.is_dir():
        abort(f'reports directory missing: {out.parent}')
    try:
        with out.open('x', encoding='utf-8', newline='\n') as file:
            file.write('\n'.join(lines)+'\n')
    except FileExistsError:
        print(f'A106_REPORT_ALREADY_EXISTS_UNCHANGED={out}')
        return
    print(f'A106_REPORT_CREATED={out} BYTES={out.stat().st_size}')
    print('A106_PROOF_STATUS=REPORT_AVAILABLE_REVIEW_REQUIRED')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=Path.cwd())
    parser.add_argument('--alice', type=Path)
    parser.add_argument('--zimage', type=Path)
    parser.add_argument('--out', type=Path)
    parser.add_argument('--self-test', action='store_true')
    args = parser.parse_args()
    self_test()
    if args.self_test:
        return
    root = args.root.resolve()
    alice = args.alice or root/'research/f2/work/extracted/altice_alice/alice-py.bin'
    zimage = args.zimage or root/'research/f2/work/extracted/altice_platform/zimage.bin'
    out = args.out or root/'research/f2/work/reports/s13_5a106_f0115f66_exact_reference_writer_audit.txt'
    audit(root,alice,zimage,out)


if __name__ == '__main__':
    main()
