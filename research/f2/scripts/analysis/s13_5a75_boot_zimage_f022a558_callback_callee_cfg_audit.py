#!/usr/bin/env python3
"""S13.5A.75: guarded, narrow, offline BOOT_ZIMAGE F022A558 analysis.

Reads canonical BOOT_ZIMAGE and ZIMAGE only. NEVER touches connected devices,
write/erase/patch/repack interfaces or mutates any input files. Writes stdout only.
"""
from __future__ import annotations

import argparse
import hashlib
from pathlib import Path
import sys

BOOT_BASE = 0xF01F19E4
BOOT_SIZE = 0x4B06C
BOOT_SHA = 'aa070292e9c1685eddb12080b3f0bbca763102adaf085016b4e503a3930b4c3e'
BOOT_END = BOOT_BASE + BOOT_SIZE
Z_BASE = 0xF023CA50
Z_SIZE = 0x185E98
Z_SHA = '85fba8c8ae8161e4c1f8ced7983ec30d48c54ab10e51c69fcdfb900aca220954'
ENTRY = 0xF022A558
WRAPPER = 0xF028877A
CALLBACK = 0xF028877B
SLOT = 0xF009343C
LIMIT = 0x300
MAX_INS = 240
CONDITIONAL = {'beq','bne','bcs','bcc','bhs','blo','bmi','bpl','bvs','bvc',
               'bhi','bls','bge','blt','bgt','ble','cbz','cbnz'}


def out(title):
    print('\n' + '='*106)
    print(title)
    print('='*106)


def guard(path: Path, size: int, sha: str, name: str):
    if not path.is_file():
        raise RuntimeError(f'{name} MISSING: {path}')
    bs = path.read_bytes()
    digest = hashlib.sha256(bs).hexdigest()
    ok = len(bs) == size and digest.lower() == sha.lower()
    print(f'{name}: path={path} size=0x{len(bs):X} sha256={digest} GUARD={"PASS" if ok else "FAIL"}')
    if not ok:
        raise RuntimeError(f'{name}: FAIL CLOSED, unexpected byte identity')
    return bs


def get_boot_path(arg: str | None) -> Path:
    if arg:
        return Path(arg).expanduser()
    relative = Path('research/f2/work/extracted/altice_platform/boot_zimage.bin')
    options = [Path.cwd()/relative, Path.home()/'mtkclient'/relative]
    for p in options:
        if p.is_file():
            return p
    print('BOOT_ZIMAGE missing in known exact locations:')
    for p in options:
        print('  ' + str(p))
    print('Use --boot "C:\\path\\to\\boot_zimage.bin" from A.35 canonical extraction.')
    raise RuntimeError('BOOT_ZIMAGE_NOT_LOCATED; NO NEW DECOMPRESSION REQUIRED')


def pc_cell(addr: int, op_disp: int) -> int:
    return ((addr + 4) & ~3) + op_disp


def get_ins(cs, data: bytes, address: int, base: int):
    off = address - base
    if off < 0 or off >= len(data):
        return None
    return next(iter(cs.disasm(data[off:off+4], address, count=1)), None)


def target_imm(ins, arm):
    for op in ins.operands:
        if op.type == arm.ARM_OP_IMM:
            return (op.imm & 0xFFFFFFFF) & ~1
    return None


def fmt(ins):
    bs=' '.join(f'{b:02x}' for b in ins.bytes)
    return f'0x{ins.address:08X}: {ins.mnemonic:9s} {ins.op_str:31s} bytes={bs}'


def verify_wrapper(cs, arm, zi: bytes):
    out('B. PINNED ZIMAGE: REGISTERED WRAPPER INSTRUCTION CHECK')
    checks = [('push',None), ('bl',ENTRY), ('pop',None)]
    addr = WRAPPER
    instructions = []
    for mnemonic, dest in checks:
        ins=get_ins(cs,zi,addr,Z_BASE)
        if ins is None or ins.mnemonic != mnemonic:
            raise RuntimeError(f'WRAPPER check FAIL at 0x{addr:08X}; got {ins.mnemonic if ins else "NONE"}')
        if dest is not None and target_imm(ins,arm) != dest:
            raise RuntimeError(f'WRAPPER target FAIL: expected 0x{dest:08X} decoded={ins.op_str}')
        print(fmt(ins))
        instructions.append(ins)
        addr += ins.size
    if [x.address for x in instructions] != [0xF028877A,0xF028877C,0xF0288780]:
        raise RuntimeError('WRAPPER addresses differ from proven A.73/A.74')
    if 'r4' not in instructions[0].op_str or 'lr' not in instructions[0].op_str:
        raise RuntimeError('WRAPPER entry not exact push {r4,lr}')
    print(f'WRAPPER_GUARD=PASS callback=0x{CALLBACK:08X} (Thumb) => BL 0x{ENTRY:08X}')
    print('ABI: push{r4,lr} and BL leave incoming r0/r1/r2 untouched at direct callee entry.')
    print('DO NOT infer what r0/r1/r2 mean or that an MP3 application is launched.')


def entry_linear(cs, bs: bytes, count=72):
    out('D. BOOT_ZIMAGE ENTRY: EXACT THUMB BYTES + LINEAR PREVIEW (NOT REACHABILITY)')
    off=ENTRY-BOOT_BASE
    print(f'address=0x{ENTRY:08X} offset=0x{off:X} file_end=0x{BOOT_SIZE:X}')
    print('entry_64_bytes=' + bs[off:off+64].hex(' '))
    decoded=list(cs.disasm(bs[off:off+0xC0],ENTRY))
    for ins in decoded[:count]:
        print(fmt(ins))
    print(f'linear_instructions_displayed={min(count,len(decoded))}')
    if not decoded or decoded[0].address != ENTRY:
        raise RuntimeError('NO THUMB DECODE at target despite valid BOOT hash')
    return decoded


def focused_cfg(cs, arm, bs: bytes):
    out('E. BOUNDED THUMB CFG (NO UNSUPPORTED BRANCH REACHABILITY CLAIMS)')
    lo,hi=ENTRY, min(ENTRY+LIMIT,BOOT_END)
    todo=[ENTRY]
    visited={}
    branch_edges=[]
    calls=[]
    uncertain=[]
    blocks=[]
    while todo and len(visited)<MAX_INS:
        start=todo.pop(0)
        if start in visited or not (lo<=start<hi):
            continue
        addr=start
        block=[]
        while lo<=addr<hi and addr not in visited and len(visited)<MAX_INS:
            ins=get_ins(cs,bs,addr,BOOT_BASE)
            if ins is None or ins.address!=addr or ins.size==0:
                uncertain.append((addr,'decode failure')); break
            visited[addr]=ins
            block.append(ins)
            m=ins.mnemonic.lower().split('.')[0]
            nxt=addr+ins.size
            if m in ('bl','blx'):
                target=target_imm(ins,arm)
                calls.append((addr,target,ins.op_str))
                if target is None:
                    uncertain.append((addr,'register-indirect call'))
                addr=nxt
                continue
            if m in CONDITIONAL:
                dest=target_imm(ins,arm)
                if dest is not None:
                    branch_edges.append((addr,dest,'cond'))
                    if lo<=dest<hi: todo.append(dest)
                else:
                    uncertain.append((addr,'conditional branch unresolved'))
                addr=nxt
                continue
            if m in ('b','b.w') or (m=='b' and ins.op_str.startswith('#')):
                dest=target_imm(ins,arm)
                if dest is not None:
                    branch_edges.append((addr,dest,'jump'))
                    if lo<=dest<hi: todo.append(dest)
                else: uncertain.append((addr,'branch unresolved'))
                break
            if m in ('bx','bxj','tbb','tbh') or (m=='pop' and 'pc' in ins.op_str) or (m=='ldr' and ins.op_str.startswith('pc,')):
                if m in ('tbb','tbh') or (m=='ldr'):
                    uncertain.append((addr,'possible computed jump'))
                break
            if m in ('udf','bkpt','svc'):
                uncertain.append((addr,m+' terminator'))
                break
            addr=nxt
        blocks.append((start,block))
    for start,insns in blocks:
        print(f'\n-- CFG BLOCK 0x{start:08X} decoded={len(insns)} --')
        for ins in insns:
            print(fmt(ins))
    print(f'\nCFG_BOUNDS=[0x{lo:X},0x{hi:X}); visited_unique={len(visited)} blocks={len(blocks)} pending={len(todo)} cap={MAX_INS}')
    print('CALLEE_CALLS_IN_THIS_BOUNDED_GRAPH:')
    for addr,tgt,op in calls:
        print(f'  0x{addr:08X} -> '+(f'0x{tgt:08X}' if tgt is not None else 'REGISTER_INDIRECT')+f' [{op}]')
    if not calls: print('  none observed')
    print('OUT_OF_WINDOW_BRANCHES:')
    for a,b,k in branch_edges:
        if not (lo<=b<hi): print(f'  0x{a:08X} {k} -> 0x{b:08X} NOT FOLLOWED')
    print('UNRESOLVED/UNCERTAIN:')
    for a,x in uncertain: print(f'  0x{a:08X}: {x}')
    if not uncertain: print('  none detected within visited slices (not whole-function proof)')
    print('R2_REFERENCES_IN_VISITED_INSTRUCTIONS (register not ID proof):')
    hits=[i for i in visited.values() if 'r2' in (i.op_str or '').lower()]
    for ins in sorted(hits,key=lambda x:x.address)[:45]: print(fmt(ins))
    print(f'  count={len(hits)} (first 45 shown)')
    if todo: print('WARNING: CFG instruction cap reached or branches remain pending')
    return len(visited)


def main(argv=None):
    p=argparse.ArgumentParser(description='S13.5A.75 BOOT_ZIMAGE F022A558 verified narrow disassembly')
    p.add_argument('--boot',help='Canonical BOOT_ZIMAGE filename, no rewriting/decompression')
    p.add_argument('--zimage',default='research/f2/work/extracted/altice_platform/zimage.bin')
    args=p.parse_args(argv)
    print('S13.5A.75 - VERIFIED BOOT_ZIMAGE F022A558 CALLBACK CALLEE CFG AUDIT')
    print('STRICTLY OFFLINE: no USB/COM/phone/BROM/DA/readflash/writeflash/erase/patch/repack')
    print('READS ONLY two SHA256-pinned image files, prints stdout, NO output file writes')
    out('A. CANONICAL GUARDS & PHYSICAL-IMAGE COVERAGE')
    bp=get_boot_path(args.boot)
    boot=guard(bp,BOOT_SIZE,BOOT_SHA,'BOOT_ZIMAGE')
    zi=guard(Path(args.zimage),Z_SIZE,Z_SHA,'ZIMAGE')
    print(f'BOOT range [0x{BOOT_BASE:X},0x{BOOT_END:X}); ZIMAGE begins 0x{Z_BASE:X}')
    if BOOT_END!=Z_BASE or not BOOT_BASE<=ENTRY<BOOT_END:
        raise RuntimeError('RUNTIME IMAGE COVERAGE FAIL')
    print(f'TARGET 0x{ENTRY:X} is in BOOT_ZIMAGE at offset 0x{ENTRY-BOOT_BASE:X}; COVERAGE=PASS')
    try:
        from capstone import Cs,CS_ARCH_ARM,CS_MODE_THUMB,CS_MODE_LITTLE_ENDIAN
        from capstone import arm as arm_consts
    except ImportError:
        raise RuntimeError('CAPSTONE MISSING in selected Python; use C:\\Users\\verto\\mtkclient\\.venv\\Scripts\\python.exe')
    cs=Cs(CS_ARCH_ARM,CS_MODE_THUMB|CS_MODE_LITTLE_ENDIAN)
    cs.detail=True
    verify_wrapper(cs,arm_consts,zi)
    out('C. EXACT TARGET REGION')
    off=ENTRY-BOOT_BASE
    print('BOOTSOURCE=' + str(bp))
    print(f'file_offset=0x{off:X}, remaining=0x{BOOT_SIZE-off:X}; endian=LITTLE; ISA=THUMB (BL caller)')
    entry_linear(cs,boot)
    n=focused_cfg(cs,arm_consts,boot)
    out('F. RESULT / GATE')
    print('A75_OFFLINE_AUDIT_COMPLETED=YES')
    print(f'DISASSEMBLED_ENTRY=0x{ENTRY:X} BYTES_VERIFIED=YES CFG_VISITED={n}')
    print('NO AUTOMATIC INFERENCE: This callback may be UI/event/resource logic, not an Audio 0x8928 launcher.')
    print('NEXT: interpret bounded CFG and exact incoming argument r2; no patch authorization.')
    print('PHONE ACCESSED=NO FLASH MODIFIED=NO PATCH=NO REPACK=NO WRITE AUTHORIZED=NO')
    return 0


if __name__=='__main__':
    try:
        sys.exit(main())
    except Exception as exc:
        print('ABORT: '+str(exc),file=sys.stderr)
        sys.exit(1)
