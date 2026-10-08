#!/usr/bin/env python3
"""S13.5A.84 — OFFLINE bounded selector/branch origin audit for the sole
A83 code-referenced caller F02AE130 -> F02F2C10 -> BLX MEM[F004C5E8].

Does NOT certify MENU OK, event IDs, native Audio 8928, runtime targets or a
flashable modification. No USB/COM/phone/readflash/writeflash/erase/repack.
"""
from __future__ import annotations

import argparse
import hashlib
from collections import deque
from pathlib import Path

from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_LITTLE_ENDIAN
from capstone.arm import ARM_OP_IMM, ARM_OP_MEM, ARM_REG_PC

ZBASE = 0xF023CA50
ZSIZE = 0x185E98
ZSHA = '85fba8c8ae8161e4c1f8ced7983ec30d48c54ab10e51c69fcdfb900aca220954'
ABASE = 0x1024EC00
ASIZE = 0x157BB4
ASHA = '7246242b67afae0d13104452bc3257827cb778119b54e7a26fb7fb55993697ea'
SINK = 0xF02F2C80
SLOT = 0xF004C5E8
ENTRY = 0xF02F2C10
CALLER = 0xF02AE130
JOIN = 0xF02AE1FE
CASES = (
    (0xF02AE118, 0xF02F260C),
    (0xF02AE120, 0xF02FC0A0),
    (0xF02AE128, 0xF02FBF7C),
    (CALLER, ENTRY),
)
CONDITIONAL = {'beq','bne','bge','bgt','ble','blt','bhi','bhs','blo','bls',
               'bpl','bmi','bvc','bvs','cbz','cbnz'}
TERMINATORS = {'bx','udf','bkpt','svc'}


def abort(s): raise SystemExit('ABORT: ' + s)


def pinned(path, label, size, sha):
    if not path.is_file(): abort(f'{label} missing at {path}')
    data = path.read_bytes()  # strictly read-only
    digest = hashlib.sha256(data).hexdigest()
    ok = len(data) == size and digest == sha
    print(f'{label} PATH={path} SIZE=0x{len(data):X} SHA256={digest} GUARD={"PASS" if ok else "FAIL"}')
    if not ok: abort(f'{label} canonical SHA256/size mismatch')
    return data


def raw_at(data, addr, n=4):
    off = addr-ZBASE
    if off < 0 or n < 0 or off+n > len(data): return None
    return data[off:off+n]


def single(md, data, addr):
    raw = raw_at(data, addr)
    if raw is None: return None
    ins = list(md.disasm(raw, addr, count=1))
    return ins[0] if ins and ins[0].address == addr else None


def opname(i): return i.mnemonic.lower().split('.')[0]


def imm(i):
    if i is None: return None
    for operand in i.operands:
        if operand.type == ARM_OP_IMM: return operand.imm & 0xFFFFFFFF & ~1
    return None


def literal(i,data):
    if opname(i)!='ldr' or len(i.operands) < 2: return None
    operand=i.operands[1]
    if operand.type!=ARM_OP_MEM or operand.mem.base!=ARM_REG_PC or operand.mem.index: return None
    cell=((i.address+4)&~3)+operand.mem.disp
    b=raw_at(data,cell,4)
    return (cell,int.from_bytes(b,'little')) if b is not None else None


def descr(i,data):
    x=literal(i,data)
    s=f'{i.address:08X} {i.mnemonic:<9} {i.op_str:<31} bytes={i.bytes.hex(" ")}'
    return s+(f' PC_CELL={x[0]:08X} U32={x[1]:08X}' if x else '')


def exact(md,data,addr,mnemonic,target=None,op_contains=None,raw=None):
    i=single(md,data,addr)
    if i is None or opname(i)!=mnemonic:abort(f'instruction mismatch at 0x{addr:08X}; wanted {mnemonic}')
    if target is not None and imm(i)!=target:abort(f'target mismatch at 0x{addr:08X}: {imm(i)!r} != {target:X}')
    if op_contains is not None and op_contains.replace(' ','').lower() not in i.op_str.replace(' ','').lower():
        abort(f'operands mismatch at 0x{addr:08X}: {i.op_str!r}')
    if raw is not None and i.bytes != bytes.fromhex(raw): abort(f'bytes mismatch at 0x{addr:08X}')
    print('  '+descr(i,data))
    return i


def verify(md,data):
    print('\n[A] EXACT A83 CALLSITE + A82 SLOT + SIBLINGS — FAIL CLOSED')
    exact(md,data,0xF02AE12E,'add',op_contains='r0,sp,#0x4c',raw='13 a8')
    exact(md,data,CALLER,'bl',target=ENTRY,raw='44 f0 6e fd')
    exact(md,data,CALLER+4,'b',target=JOIN,raw='63 e0')
    exact(md,data,ENTRY,'push',op_contains='lr')
    exact(md,data,0xF02F2C2E,'beq',target=0xF02F2C84,raw='29 d0')
    exact(md,data,0xF02F2C36,'beq',target=0xF02F2C78,raw='1f d0')
    exact(md,data,0xF02F2C7C,'ldr',op_contains='r0,[pc',raw='06 48')
    lit=literal(single(md,data,0xF02F2C7C),data)
    if lit!=(0xF02F2C98,SLOT):abort('A82 exact slot PC-LDR cell mismatch')
    exact(md,data,0xF02F2C7E,'ldr',op_contains='r0,[r0]',raw='00 68')
    exact(md,data,SINK,'blx',op_contains='r0',raw='80 47')
    for site,target in CASES:
        exact(md,data,site,'bl',target=target)
    for site in (0xF02AE11C,0xF02AE124,0xF02AE12C,0xF02AE134):
        exact(md,data,site,'b',target=JOIN)
    print('A84_ANCHORS_PASS=YES')


def linear_window(md,data,lo,hi):
    """Intentionally labelled non-CFG: may decode data/PC literal pools."""
    print(f'BOUNDED_RAW_THUMB_WINDOW=[0x{lo:08X},0x{hi:08X}) NOT_CERTIFIED_CFG')
    span=raw_at(data,lo,hi-lo)
    if span is None:abort('window out of bounds')
    decoded=list(md.disasm(span,lo))
    for i in decoded:
        print('  '+descr(i,data))
    return decoded


def cfg(md,data,start,end,target):
    """Path reachability within a fixed local envelope; no indirect jump guesses."""
    todo=deque([start]); seen={}; blocks=set(); branches=[];calls=[];unknown=[]
    max_ins=850;max_blocks=170;block_limit=180
    while todo and len(seen)<max_ins and len(blocks)<max_blocks:
        pos=todo.popleft()
        if pos in blocks or not (start<=pos<end):continue
        blocks.add(pos);n=0
        while start<=pos<end and pos not in seen and n<block_limit and len(seen)<max_ins:
            i=single(md,data,pos)
            if i is None or pos+i.size>end:
                unknown.append(f'BAD_DECODE_AT=0x{pos:08X}');break
            seen[pos]=i;n+=1;m=opname(i);nxt=pos+i.size
            if m in {'bl','blx'}:calls.append((pos,m,imm(i),i.op_str))
            if m in CONDITIONAL or m=='b':
                dst=imm(i);branches.append((pos,m,dst))
                if dst is not None and start<=dst<end:
                    todo.append(dst)
                elif dst is not None:unknown.append(f'EXIT_BRANCH=0x{pos:08X}->0x{dst:08X}')
                else:unknown.append(f'DYNAMIC_BRANCH=0x{pos:08X}')
                if m=='b':break
            if m in TERMINATORS or (m=='pop' and 'pc' in i.op_str.lower()) or (m=='ldr' and i.op_str.lower().startswith('pc,')):
                break
            if m in ('tbb','tbh'):
                unknown.append(f'JUMPTABLE_UNRESOLVED=0x{pos:08X}');break
            pos=nxt
        if n>=block_limit:unknown.append(f'BLOCK_LIMIT=0x{pos:08X}')
    complete=(not todo and len(seen)<max_ins and len(blocks)<max_blocks
              and not any(s.startswith(('BAD_','BLOCK_','JUMPTABLE_','DYNAMIC_')) for s in unknown))
    return dict(start=start,seen=seen,blocks=blocks,branches=branches,calls=calls,
                unknown=unknown,complete=complete, reached=(target in seen))


def inspect_selected_case(md,data):
    print('\n[B] BOUNDED DISPATCH CASE NEIGHBORHOOD — A83 NEW TEST')
    linear_window(md,data,0xF02AE080,0xF02AE13A)
    print('CASE_SEQUENCE:')
    for site,target in CASES:
        j=single(md,data,site+4)
        print(f'  0x{site:08X} -> 0x{target:08X} -> B_JOIN=0x{imm(j):08X}')
    print('Case-neighbor adjacency does NOT prove a menu action; selector source not yet inferred.')


def inspect_provenance(md,data):
    print('\n[C] CALLSITE SELECTOR CONTROL-FLOW: SCAN ONLY BOUNDED PROLOGUE CANDIDATES')
    lo=CALLER-0x480
    end=0xF02AE238
    if raw_at(data,lo,end-lo) is None:abort('bounded CFG envelope outside image')
    found=[];tested=0
    for start in range(lo,CALLER,2):
        i=single(md,data,start)
        if i is None or opname(i)!='push' or 'lr' not in i.op_str.lower():continue
        tested+=1
        r=cfg(md,data,start,end,CALLER)
        if r['reached']:found.append(r)
    print(f'PROLOGUES_TESTED={tested} REACHABLE_CANDIDATES={len(found)}')
    for r in found[:6]:
        print(f'  OWNER_CANDIDATE={r["start"]:08X} reachable=True decoded={len(r["seen"])} '
              f'blocks={len(r["blocks"])} complete={r["complete"]} unknown={r["unknown"][:8]}')
        preds=[(a,m,t) for a,m,t in r['branches'] if t in (0xF02AE116,0xF02AE11E,0xF02AE126,0xF02AE12E,CALLER)]
        print('  VERIFIED_CFG_CASE_INCOMING_BRANCHES='+(repr([(f'{a:08X}',m,hex(t)) for a,m,t in preds]) if preds else 'NONE'))
        local=[i for addr,i in sorted(r['seen'].items()) if 0xF02ADF80<=addr<=CALLER and opname(i) in {'cmp','tst','cbz','cbnz','tbb','tbh','ldrb','ldrh','ldr','subs','beq','bne','bhi','bls','bge','blt'}]
        print(f'  SELECTOR_RELATED_REACHED_INSTRUCTIONS={len(local)} printed_last_65')
        for i in local[-65:]:print('    '+descr(i,data))
        print('  BRANCHES_NEAR_CASES:')
        for a,m,t in r['branches']:
            if 0xF02AE0A0<=a<=CALLER:
                print(f'    0x{a:08X} {m:<6} -> '+(f'0x{t:08X}' if t is not None else 'DYNAMIC'))
    if len(found)>6:print(f'REACHABLE_CANDIDATES_CAPPED: {len(found)} total; first6 printed')
    if len(found)!=1 or not found[0]['complete']:
        print('SELECTOR_SOURCE_NOT_CERTIFIED: ambiguous/incomplete owner or dynamic branch possible')
    else:
        print('UNIQUE_BOUNDED_OWNER_CANDIDATE; full menu-event semantics STILL NOT PROVEN')


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--alice',type=Path,default=Path('research/f2/work/extracted/altice_alice/alice-py.bin'))
    p.add_argument('--zimage',type=Path,default=Path('research/f2/work/extracted/altice_platform/zimage.bin'))
    args=p.parse_args()
    print('S13.5A.84 - F02AE130 CASE SELECTOR / DISPATCH PROVENANCE')
    print('STRICTLY OFFLINE: canonical ALICE+ZIMAGE local reads only, NO PHONE OR FIRMWARE MUTATION')
    pinned(args.alice,'ALICE',ASIZE,ASHA)
    data=pinned(args.zimage,'ZIMAGE',ZSIZE,ZSHA)
    md=Cs(CS_ARCH_ARM,CS_MODE_THUMB|CS_MODE_LITTLE_ENDIAN);md.detail=True
    verify(md,data)
    inspect_selected_case(md,data)
    inspect_provenance(md,data)
    print('\n[D] SAFETY / EVIDENCE GATE')
    print('A84_OFFLINE_AUDIT_COMPLETED=YES')
    print('Only exact F02AE130->F02F2C10 source-path/sibling branch proven; no claim on runtime trigger, selected OK, Audio 8928 or patchability.')
    print('CONSUMER_B_OWNER_F03221B4=UNRESOLVED_IN_A83; intentionally NOT re-audited here.')
    print('PHONE_ACCESSED=NO FIRMWARE_MODIFIED=NO WRITE_AUTHORIZED=NO')

if __name__=='__main__': main()
