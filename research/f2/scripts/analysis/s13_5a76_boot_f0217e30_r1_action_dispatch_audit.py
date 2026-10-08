#!/usr/bin/env python3
"""S13.5A.76: offline, SHA-pinned CFG audit for BOOT_ZIMAGE F0217E30.

Exact single-target audit after A.75. Reads existing BOOT_ZIMAGE/ZIMAGE;
prints stdout only; no write, USB, COM, phone, device access, repack or patch.
The CFG is bounded, may miss dynamic edges, and does not claim runtime reachability.
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
WRAPPER = 0xF028877A
ADAPTER = 0xF022A558
ADAPTER_CALL = 0xF022A570
ENTRY = 0xF0217E30
CFG_LIMIT = 0x700  # strict: do not cover unrelated code further away
CFG_CAP = 300
BLOCK_CAP = 60
CONDITIONAL = {'beq', 'bne', 'bcs', 'bcc', 'bhs', 'blo', 'bmi', 'bpl', 'bvs', 'bvc',
               'bhi', 'bls', 'bge', 'blt', 'bgt', 'ble', 'cbz', 'cbnz'}


def sep(s: str):
    print('\n' + '=' * 107 + '\n' + s + '\n' + '=' * 107)


def guarded(path: Path, expected_size: int, sha: str, label: str) -> bytes:
    if not path.is_file():
        raise RuntimeError(f'{label}: MISSING {path}')
    b = path.read_bytes()
    digest = hashlib.sha256(b).hexdigest()
    ok = len(b) == expected_size and digest.lower() == sha.lower()
    print(f'{label}: path={path} size=0x{len(b):X} sha256={digest} GUARD={"PASS" if ok else "FAIL"}')
    if not ok:
        raise RuntimeError(f'{label}: SOURCE GUARD FAIL; no analysis')
    return b


def boot_path(explicit: str | None) -> Path:
    if explicit:
        return Path(explicit).expanduser()
    rel = Path('research/f2/work/extracted/altice_platform/boot_zimage.bin')
    for p in (Path.cwd() / rel, Path.home() / 'mtkclient' / rel):
        if p.is_file():
            return p
    raise RuntimeError('BOOT_ZIMAGE not found: supply --boot canonical historical path')


def ins_at(cs, b: bytes, base: int, addr: int):
    off = addr - base
    if off < 0 or off + 2 > len(b):
        return None
    return next(iter(cs.disasm(b[off:off+4], addr, count=1)), None)


def tgt(ins, arm):
    if ins is None:
        return None
    imms = [int(op.imm) for op in ins.operands if op.type == arm.ARM_OP_IMM]
    return (imms[-1] & 0xFFFFFFFF) & ~1 if imms else None


def pc_cell(addr: int, imm: int) -> int:
    return ((addr + 4) & ~3) + imm


def literal(cs, arm, b, base, ins):
    if ins.mnemonic != 'ldr' or len(ins.operands) < 2:
        return None
    src = ins.operands[1]
    if src.type != arm.ARM_OP_MEM or src.mem.base != arm.ARM_REG_PC:
        return None
    cell = pc_cell(ins.address, src.mem.disp)
    off = cell - base
    if off < 0 or off+4 > len(b):
        return f'LITERAL_CELL=0x{cell:08X} OUTSIDE_PINNED_SEGMENT'
    return f'LITERAL_CELL=0x{cell:08X} VALUE=0x{int.from_bytes(b[off:off+4], "little"):08X}'


def fmt(ins, cs, arm, b, base):
    out = f'0x{ins.address:08X}: {ins.mnemonic:9s} {ins.op_str:30s} bytes={ins.bytes.hex(" ")}'
    lit = literal(cs, arm, b, base, ins)
    return out + (' ; '+lit if lit else '')


def check_prior(cs, arm, boot, zimage):
    sep('B. A.75 ABI / DIRECT CALL VALIDATION (FAIL CLOSED)')
    w = [ins_at(cs, zimage, Z_BASE, a) for a in (0xF028877A,0xF028877C,0xF0288780)]
    if any(i is None for i in w) or [i.mnemonic for i in w] != ['push','bl','pop'] or tgt(w[1],arm) != ADAPTER:
        raise RuntimeError('ZIMAGE wrapper differs from A.75')
    print('WRAPPER_ZIMAGE=PASS: F028877A -> F022A558')
    a = [ins_at(cs, boot, BOOT_BASE, p) for p in (
        0xF022A558,0xF022A55A,0xF022A55E,0xF022A568,0xF022A56A,
        0xF022A56C,0xF022A56E,0xF022A570,0xF022A576)]
    expected = {
        0xF022A558:'push',0xF022A55A:'movs',0xF022A55E:'movs',
        0xF022A568:'stm',0xF022A56A:'movs',0xF022A56C:'movs',
        0xF022A56E:'movs',0xF022A570:'bl',0xF022A576:'pop'}
    for ins, addr in zip(a,expected):
        if ins is None or ins.address!=addr or ins.mnemonic.lower()!=expected[addr]:
            raise RuntimeError(f'ADAPTER anchor FAIL at {addr:#x}: {ins.mnemonic if ins else "NONE"}')
    if tgt(a[-2],arm) != ENTRY:
        raise RuntimeError('ADAPTER BL does not target F0217E30')
    if ('r5, r2' not in a[1].op_str or 'r1, r5' not in a[4].op_str or
        'r2, #0' not in a[2].op_str or 'r0, r2' not in a[5].op_str or
        'r3, r2' not in a[6].op_str):
        raise RuntimeError('Adapter incoming r2 -> r5 -> r1 dataflow changed')
    print('ADAPTER_BOOT=PASS: F022A558 -> F0217E30; r1_call = original callback r2')
    print('ADAPTER_CALL_ABI: F0217E30 r0=0, r1=STATIC[selected].field10, r2=0, r3=0')
    print('ADAPTER_STACK: [sp+0]=original callback r0; [sp+4]=original callback r1;')
    print('               [sp+8..+0x14]=0, as initialized in F022A558')
    print('IMPORTANT: callback r2 originates from STATIC +0x10, NOT DYNAMIC +0x10.')


def explore(cs, arm, boot):
    sep('C. F0217E30 EXACT THUMB ENTRY + BOUNDED CFG')
    if not BOOT_BASE <= ENTRY < BOOT_END or ENTRY+CFG_LIMIT>BOOT_END:
        raise RuntimeError('BOOT target CFG outside source; abort')
    off=ENTRY-BOOT_BASE
    print(f'ENTRY=0x{ENTRY:08X} BOOT_OFFSET=0x{off:X} first_48={boot[off:off+48].hex(" ")}')
    start_ins=ins_at(cs,boot,BOOT_BASE,ENTRY)
    if start_ins is None:
        raise RuntimeError('No decode at entry')
    lo,hi=ENTRY,ENTRY+CFG_LIMIT
    pending=[ENTRY]; visited={}; blocks=[]; edges=[]; calls=[]; warnings=[]
    while pending and len(visited)<CFG_CAP:
        start=pending.pop(0)
        if not lo<=start<hi or start in visited:
            continue
        addr=start; got=[]
        for _ in range(BLOCK_CAP):
            if not lo<=addr<hi or addr in visited or len(visited)>=CFG_CAP:
                break
            inst=ins_at(cs,boot,BOOT_BASE,addr)
            if inst is None or inst.address!=addr:
                warnings.append((addr,'decode failure'));break
            visited[addr]=inst
            got.append(inst)
            m=inst.mnemonic.lower().split('.')[0]
            next_addr=addr+inst.size
            if m in ('bl','blx'):
                to=tgt(inst,arm)
                calls.append((inst.address,to,inst.op_str))
                if to is None:
                    warnings.append((addr,'indirect call target unresolved'))
                addr=next_addr
                continue
            if m in CONDITIONAL:
                to=tgt(inst,arm)
                edges.append((addr,to,'conditional'))
                if to is not None and lo<=to<hi:
                    pending.append(to)
                elif to is None:
                    warnings.append((addr,'conditional destination unknown'))
                else:
                    warnings.append((addr,'conditional branch OUTSIDE audit bounds'))
                addr=next_addr
                continue
            if m=='b':
                to=tgt(inst,arm)
                edges.append((addr,to,'unconditional'))
                if to is not None and lo<=to<hi:
                    pending.append(to)
                else:
                    warnings.append((addr,'branch outside bounded CFG or unknown'))
                break
            if (m in {'bx','bxj','tbb','tbh','udf','bkpt','svc'} or
                (m=='pop' and 'pc' in inst.op_str) or
                (m=='ldr' and inst.op_str.startswith('pc,'))):
                if m in ('tbb','tbh') or (m=='ldr' and inst.op_str.startswith('pc,')):
                    warnings.append((addr,'indirect/computed branch'))
                break
            addr=next_addr
        else:
            warnings.append((addr, "BLOCK_CAP_REACHED; path truncated"))
        blocks.append((start,got))
    for start, instructions in blocks:
        print(f'\n-- CFG_BLOCK 0x{start:08X} ({len(instructions)} ins) --')
        for ins in instructions:
            print(fmt(ins,cs,arm,boot,BOOT_BASE))
    print('\nCFG_SUMMARY visited={} blocks={} pending={} bound=[0x{:X},0x{:X}) cap={}'.format(
        len(visited),len(blocks),len(pending),lo,hi,CFG_CAP))
    print('DIRECT/INDIRECT CALLS:')
    for a,t,op in calls:
        print(f'  0x{a:08X} -> '+(f'0x{t:08X}' if t is not None else 'REG_INDIRECT')+f' {op}')
    if not calls: print('  none in bounded CFG')
    print('BRANCH EDGES:')
    for a,t,k in edges[:90]:
        print(f'  0x{a:08X} {k} -> '+(f'0x{t:08X}' if t is not None else 'UNKNOWN'))
    print('WARNINGS / CFG LIMITATIONS:')
    for a,w in warnings[:60]:print(f'  0x{a:08X}: {w}')
    if len(visited)>=CFG_CAP or pending: print('  CAP_OR_PENDING: graph not complete')
    if not warnings and len(visited)<CFG_CAP and not pending:print('  no structural warning in this bounded graph; not whole call-graph proof')
    return visited,calls,edges,warnings


def r1_sources(cs,arm,boot,visited):
    sep('D. ENTRY-r1 / STACK PAYLOAD CONSUMERS (EVIDENCE, NOT COMPLETE DATAFLOW)')
    print('CALLER: r1 = STATIC[selected].field10. Explicit r1 operand does not prove its original value survives a call.')
    notes = 0
    for i in sorted(visited.values(),key=lambda ins:ins.address):
        if not i.operands: continue
        reads_r1=False; writes_r1=False; mem_r1=False
        for index,op in enumerate(i.operands):
            if op.type==arm.ARM_OP_REG and op.reg==arm.ARM_REG_R1:
                if index==0 and i.mnemonic.lower().split('.')[0] in ('mov','movs','ldr','ldrb','ldrh','add','adds','sub','subs','and','ands','orr','orrs','eor','eors','mul','lsls','lsrs','asrs'):
                    writes_r1=True
                else:
                    reads_r1=True
            if op.type==arm.ARM_OP_MEM and (op.mem.base==arm.ARM_REG_R1 or op.mem.index==arm.ARM_REG_R1):
                mem_r1=True
        if reads_r1 or writes_r1 or mem_r1:
            print(f'  {fmt(i,cs,arm,boot,BOOT_BASE)} ; r1_read={reads_r1} r1_write={writes_r1} mem_by_r1={mem_r1}')
            notes+=1
            if notes>=90:
                print('  TRUNCATED to 90 r1-related observations');break
    print('ARM ABI: r0-r3 caller-saved across BL/BLX; no semantic inference without callee body.')
    print('Stack arguments: caller F022A558 placed six words at its outgoing SP; callee prologue changes SP.')
    print('Next gate ONLY if function delegates to a narrowly identified callee; no broad ID search.')


def main():
    p=argparse.ArgumentParser(description='S13.5A.76 narrow F0217E30 BOOT_ZIMAGE CFG, strictly offline')
    p.add_argument('--boot',help='Exact existing canonical BOOT_ZIMAGE path')
    p.add_argument('--zimage',default='research/f2/work/extracted/altice_platform/zimage.bin')
    args=p.parse_args()
    print('S13.5A.76 - BOOT_ZIMAGE F0217E30 ACTION DISPATCH ARGUMENT / CFG AUDIT')
    print('STRICTLY OFFLINE: NO USB/COM/PHONE/BROM/DA/FLASH/ERASE/PATCH/REPACK; READ TWO FILES / STDOUT ONLY')
    sep('A. SHA-PINNED FILE GUARDS (FAIL CLOSED)')
    boot=guarded(boot_path(args.boot),BOOT_SIZE,BOOT_SHA,'BOOT_ZIMAGE')
    zi=guarded(Path(args.zimage),Z_SIZE,Z_SHA,'ZIMAGE')
    if BOOT_END != Z_BASE or ENTRY-BOOT_BASE != 0x2644C:
        raise RuntimeError('IMAGE MAPPING mismatch / wrong target offset')
    from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_LITTLE_ENDIAN
    from capstone import arm
    cs=Cs(CS_ARCH_ARM,CS_MODE_THUMB|CS_MODE_LITTLE_ENDIAN);cs.detail=True
    check_prior(cs,arm,boot,zi)
    visited,calls,edges,warnings=explore(cs,arm,boot)
    r1_sources(cs,arm,boot,visited)
    sep('E. OUTCOME')
    print(f'A76_OFFLINE_AUDIT_COMPLETED=YES CFG_VISITED={len(visited)} CALL_SITES={len(calls)}')
    print('UNKNOWN: whether F0217E30 or its callees eventually dispatch Audio app 0x8928.')
    print('No hardware write, no firmware patches, no action/launcher semantics claimed.')
    return 0

if __name__=='__main__':
    try:
        raise SystemExit(main())
    except Exception as exc:
        print('ABORT: '+str(exc),file=sys.stderr)
        raise SystemExit(1)
