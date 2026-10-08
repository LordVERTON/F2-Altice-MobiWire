#!/usr/bin/env python3
"""S13.5A.77: inspect one already-proven BOOT_ZIMAGE dispatch table + one producer.

OFFLINE ONLY. Two immutable SHA-pinned extracted images, stdout only.
No USB, COM, flash, phone, firmware write, erase, repack, or patch.

Scope: 0xF0217E80 (call to F0211358), 0xF0217EB0..F0217F16
and the 0xF022FAA8 table of selected *bounded* opcode indices.
A static table's file bytes may differ from relocated/runtime RAM contents.
"""
from __future__ import annotations

import argparse
import hashlib
import sys
from pathlib import Path

BOOT_BASE, BOOT_SIZE = 0xF01F19E4, 0x4B06C
BOOT_SHA = 'aa070292e9c1685eddb12080b3f0bbca763102adaf085016b4e503a3930b4c3e'
Z_BASE, Z_SIZE = 0xF023CA50, 0x185E98
Z_SHA = '85fba8c8ae8161e4c1f8ced7983ec30d48c54ab10e51c69fcdfb900aca220954'
BOOT_END, Z_END = BOOT_BASE + BOOT_SIZE, Z_BASE + Z_SIZE
TABLE = 0xF022FAA8
CONSUMER = 0xF0217E30
PRODUCER = 0xF0211358
INDIRECT = 0xF0217F16
SELECTED_OPCODES = (0x00, 0x01, 0x02, 0x04, 0x33, 0x46, 0x47, 0x50)


def section(t):
    print('\n' + '='*110 + '\n' + t + '\n' + '='*110)


def boot_path(value: str | None) -> Path:
    if value:
        return Path(value).expanduser()
    rel = Path('research/f2/work/extracted/altice_platform/boot_zimage.bin')
    for p in (Path.cwd() / rel, Path.home()/'mtkclient'/rel):
        if p.is_file():
            return p
    raise RuntimeError('BOOT_ZIMAGE missing; supply --boot historical canonical path')


def guard(path: Path, size: int, sha: str, label: str) -> bytes:
    if not path.is_file():
        raise RuntimeError(f'{label}: file missing: {path}')
    raw = path.read_bytes()
    actual = hashlib.sha256(raw).hexdigest()
    ok = len(raw) == size and actual == sha
    print(f'{label}: path={path} size=0x{len(raw):X} sha256={actual} GUARD={"PASS" if ok else "FAIL"}')
    if not ok:
        raise RuntimeError(f'{label}: FAIL CLOSED, no further analysis')
    return raw


def region_for(addr: int, boot: bytes, z: bytes, n: int = 1):
    address = addr & ~1
    for label, base, blob in (('BOOT_ZIMAGE', BOOT_BASE, boot), ('ZIMAGE', Z_BASE, z)):
        off = address - base
        if 0 <= off and off + n <= len(blob):
            return label, base, blob, off
    return None


def read_u32(addr: int, boot: bytes, z: bytes):
    loc = region_for(addr, boot, z, 4)
    return (int.from_bytes(loc[2][loc[3]:loc[3]+4], 'little') if loc else None)


def ins_at(cs, addr: int, boot: bytes, z: bytes):
    loc = region_for(addr, boot, z, 4)
    if loc is None:
        return None
    return next(iter(cs.disasm(loc[2][loc[3]:loc[3]+4], addr, count=1)), None)


def target(ins, arm):
    if ins is None:
        return None
    imms = [int(op.imm) for op in ins.operands if op.type == arm.ARM_OP_IMM]
    return (imms[-1] & 0xFFFFFFFF) & ~1 if imms else None


def pcrel_literal(inst, arm, boot, z):
    if inst is None or inst.mnemonic != 'ldr' or len(inst.operands) < 2:
        return None
    op = inst.operands[1]
    if op.type != arm.ARM_OP_MEM or op.mem.base != arm.ARM_REG_PC:
        return None
    cell = ((inst.address+4) & ~3) + op.mem.disp
    return cell, read_u32(cell, boot, z)


def format_ins(inst, arm, boot, z):
    if inst is None:
        return 'UNDECODABLE'
    text = f'0x{inst.address:08X}: {inst.mnemonic:8s} {inst.op_str:31s} bytes={inst.bytes.hex(" ")}'
    lit = pcrel_literal(inst, arm, boot, z)
    if lit is not None:
        cell, val = lit
        text += f' ; PC_CELL=0x{cell:08X}'
        if val is not None:
            text += f' U32=0x{val:08X}'
        else:
            text += ' NOT_IN_PINNED_IMAGES'
    return text


def strict_anchors(cs, arm, boot, z):
    section('B. EXACT PREVIOUS A.75/A.76 DISPATCH INSTRUCTION ANCHORS')
    # Restrict to execution sources and exact table pointer, without assuming action meaning.
    checks = (
        (0xF022A570, 'bl', 0xF0217E30, None),
        (0xF0217E80, 'bl', PRODUCER, None),
        (0xF0217EB4, 'ldr', None, TABLE),
        (0xF0217EB6, 'lsls', None, None),
        (0xF0217EB8, 'ldr', None, None),
        (0xF0217EBA, 'str', None, None),
        (0xF0217EF4, 'ldr', None, None),
        (0xF0217EF6, 'ldr', None, None),
        (0xF0217F0A, 'movs', None, None),
        (0xF0217F16, 'blx', None, None),
    )
    for addr, expected_mnemonic, expected_call, expected_lit in checks:
        i=ins_at(cs,addr,boot,z)
        ok=(i is not None and i.address==addr and i.mnemonic.lower()==expected_mnemonic)
        if ok and expected_call is not None:
            ok=target(i,arm)==expected_call
        if ok and expected_lit is not None:
            pl=pcrel_literal(i,arm,boot,z)
            ok=pl is not None and pl[1]==expected_lit
        print(('PASS' if ok else 'FAIL') + ' ' + format_ins(i,arm,boot,z))
        if not ok:
            raise RuntimeError(f'A76 anchor changed at 0x{addr:08X}; abort')
    print('ANCHOR_GUARD=PASS')


def bounded_consumer(cs, arm, boot, z):
    section('C. EXACT SOURCE/INDEX/PTR/BLX SLICE: F0217E8E..F0217F18')
    lo,hi=0xF0217E8E,0xF0217F18
    addr=lo
    while addr<hi:
        ins=ins_at(cs,addr,boot,z)
        if ins is None or ins.address!=addr:
            print(f'  DECODE_FAIL@0x{addr:08X}');break
        print('  '+format_ins(ins,arm,boot,z))
        addr+=ins.size
    print('SEMANTIC_CAUTION: linear slice includes both sides of branches. It does NOT prove')
    print('  which opcode is possible, table mutability, dynamic reachability or Audio app launch.')
    print('REQUIRED_CHAIN: code byte from local [sp+0x2C] -> TABLE[code] -> entry[0] -> BLX r4.')


def table_preview(cs, arm, boot, z):
    section('D. EXACT 8 BRANCH-GROUNDED TABLE INDICES, NOT A FULL TABLE CENSUS')
    loc=region_for(TABLE,boot,z,4*(max(SELECTED_OPCODES)+1))
    if not loc or loc[0]!='BOOT_ZIMAGE':
        raise RuntimeError('Static table not fully inside pinned BOOT image')
    print(f'TABLE=0x{TABLE:08X} BOOT_OFFSET=0x{TABLE-BOOT_BASE:X} table_window_through_code_50=PASS')
    print('WARNING: these are ON-DISK DECOMPRESSED bytes, not captured runtime table entries.')
    print('CODE_VALIDITY: 0x0 usually error; 0x01..0x46 candidates; 0x47 rejected; 0x50 special.')
    print('  These classifications follow the bounded A76 branches; not a proof each code occurs.')
    for code in SELECTED_OPCODES:
        cell=TABLE+4*code
        val=read_u32(cell,boot,z)
        label=''
        if val is None:
            label='NOT_MAPPED'
        elif val==0:
            label='NULL_ENTRY'
        else:
            target_loc=region_for(val,boot,z,4)
            label=(f'{target_loc[0]}+0x{target_loc[3]:X}' if target_loc else 'OUTSIDE_PINNED_IMAGES')
        print(f'  code=0x{code:02X} U32@0x{cell:08X}=0x{val:08X} entry_storage={label}' if val is not None else f'  code=0x{code:02X} unmapped')
        if val and region_for(val,boot,z,4):
            word=read_u32(val & ~1,boot,z)
            where=region_for(word,boot,z,4) if word else None
            print(f'     entry.first_u32=0x{word:08X}' + (f' -> {where[0]}+0x{where[3]:X}' if where else ' -> OUTSIDE_PINNED_IMAGES/UNKNOWN'))
            if where and (word & 1):
                print('     THUMB_TARGET_PREVIEW (not invoked or CFG-certified):')
                pc=word&~1
                for _ in range(8):
                    ins=ins_at(cs,pc,boot,z)
                    if ins is None or ins.address!=pc:
                        break
                    print('       '+format_ins(ins,arm,boot,z))
                    pc+=ins.size
                    if ins.mnemonic in ('bx','pop','b','b.w'):
                        break


def producer_preview(cs, arm, boot, z):
    section('E. F0211358 - EXACT PRODUCER ENTRY / EARLY INSTRUCTIONS ONLY')
    loc=region_for(PRODUCER,boot,z,0x100)
    if not loc or loc[0]!='BOOT_ZIMAGE':
        raise RuntimeError('Producer not in canonical BOOT')
    print(f'CALLER F0217E80: r0=[sp+0x24], r1=encoded selected value or F0210508 result,')
    print('  r2=&local[sp+0x20], r3=&local[sp+0x2C], extra pointer args on stack.')
    print('  F0211358 writes a local result; code byte later read from [sp+0x2C].')
    print('  Read only 0x100 bytes from function entry: linear path, not fully reconstructed CFG.')
    pc=PRODUCER;end=min(PRODUCER+0x100,BOOT_END)
    for index in range(85):
        if pc>=end:break
        ins=ins_at(cs,pc,boot,z)
        if ins is None or ins.address!=pc:
            print(f'  STOP: undecodable at 0x{pc:08X}');break
        print('  '+format_ins(ins,arm,boot,z))
        pc+=ins.size
        if ins.mnemonic in ('bx','pop') and 'pc' in ins.op_str:
            print('  STOP: return instruction (further bytes may be different function)');break
    print('This entry preview is only to select a discriminating next analysis target,')
    print('  not to assert a complete F0211358 argument-to-code proof.')


def main():
    p=argparse.ArgumentParser(description='S13.5A.77 narrow BOOT dispatch opcode/table audit; strictly offline')
    p.add_argument('--boot',help='Canonical historical BOOT_ZIMAGE path')
    p.add_argument('--zimage',default='research/f2/work/extracted/altice_platform/zimage.bin')
    a=p.parse_args()
    print('S13.5A.77 - BOOT EVENT CODE TABLE AND INDIRECT CALLBACK SOURCE AUDIT')
    print('STRICTLY OFFLINE: NO USB/COM/PHONE/FLASH/PATCH/WRITE/ERASE/REPACK, stdout only')
    section('A. FAIL-CLOSED PINNED SOURCES')
    boot=guard(boot_path(a.boot),BOOT_SIZE,BOOT_SHA,'BOOT_ZIMAGE')
    z=guard(Path(a.zimage),Z_SIZE,Z_SHA,'ZIMAGE')
    if BOOT_END!=Z_BASE or CONSUMER-BOOT_BASE!=0x2644C or TABLE-BOOT_BASE!=0x3E0C4:
        # Assert *known* offsets without assuming a linker object or a raw NOR mapping.
        raise RuntimeError('Memory geometry mismatch')
    from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_LITTLE_ENDIAN
    from capstone import arm
    cs=Cs(CS_ARCH_ARM,CS_MODE_THUMB|CS_MODE_LITTLE_ENDIAN)
    cs.detail=True
    strict_anchors(cs,arm,boot,z)
    bounded_consumer(cs,arm,boot,z)
    table_preview(cs,arm,boot,z)
    producer_preview(cs,arm,boot,z)
    section('F. RESULT / NEXT MISSING LINK')
    print('A77_OFFLINE_COMPLETED=YES')
    print('STATIC DISPATCH LAYER LOCATED: table address and indirect call field handoff.')
    print('NOT PROVEN: actual runtime table pointer contents; opcode produced on physical user selection;')
    print('  target app-ID 0x8928 or opening of MP3 player. Physical phone and flash untouched.')
    return 0


if __name__=='__main__':
    try:
        raise SystemExit(main())
    except Exception as exc:
        print('ABORT: '+str(exc), file=sys.stderr)
        raise SystemExit(1)
