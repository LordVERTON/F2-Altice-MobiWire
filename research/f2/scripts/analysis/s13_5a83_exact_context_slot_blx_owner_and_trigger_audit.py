#!/usr/bin/env python3
"""S13.5A.83: narrow, SHA-pinned OFFLINE owners/callers of TWO exact
F004C5E8 selected-context callback invocation sites discovered by A.82.

NO USB/COM/PHONE, extraction, patch/repack, erase/write/flash, menu/ID census.
No semantic assertion of OK/Select or Audio application 0x8928.
"""
from __future__ import annotations

import argparse
import hashlib
from collections import deque
from pathlib import Path

from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_LITTLE_ENDIAN
from capstone.arm import ARM_OP_IMM, ARM_OP_MEM, ARM_REG_PC

PINNED = {
    'ALICE': (0x1024EC00, 0x157BB4, '7246242b67afae0d13104452bc3257827cb778119b54e7a26fb7fb55993697ea'),
    'ZIMAGE': (0xF023CA50, 0x185E98, '85fba8c8ae8161e4c1f8ced7983ec30d48c54ab10e51c69fcdfb900aca220954'),
}
CONTEXT = 0xF004C5CC
FIELD = CONTEXT + 0x1C
# Exact proven A82 PC-relative LDR -> dereference -> BLX, unrelated to the
# static selected ROW field F00B9A30[selected]+0x1C.
SITES = [
    ('CONSUMER_A', 0xF02F2C7C, 0xF02F2C98,
     ((0xF02F2C7C,'ldr'),(0xF02F2C7E,'ldr'),(0xF02F2C80,'blx')),
     0xF02F2C82, 'movs'),
    ('CONSUMER_B', 0xF03221B0, 0xF032225C,
     ((0xF03221B0,'ldr'),(0xF03221B2,'ldr'),(0xF03221B4,'blx')),
     0xF03221B6, 'b'),
]
CONDITIONAL = {'beq','bne','bge','bgt','ble','blt','bhi','bhs','blo','bls','bpl','bmi','bvc','bvs','cbz','cbnz'}
TERMINATE = {'bx','udf','bkpt','svc'}


def abort(reason: str) -> None:
    raise SystemExit('ABORT: ' + reason)


def guarded(path: Path, name: str):
    base, size, sha = PINNED[name]
    if not path.is_file(): abort(f'{name} missing: {path}')
    raw = path.read_bytes()  # read-only
    digest = hashlib.sha256(raw).hexdigest()
    ok = len(raw) == size and digest == sha
    print(f'{name}: {path} SIZE=0x{len(raw):X} SHA256={digest} GUARD={"PASS" if ok else "FAIL"}')
    if not ok: abort(f'{name} expected pinned size and SHA256')
    return base, raw


def at(base: int, data: bytes, addr: int, n: int = 4):
    offset = addr - base
    if offset < 0 or n < 0 or offset+n > len(data): return None
    return data[offset:offset+n]


def single(md, base, data, addr):
    raw=at(base,data,addr)
    if raw is None: return None
    ds=list(md.disasm(raw,addr,count=1))
    return ds[0] if ds and ds[0].address==addr else None


def mn(i): return i.mnemonic.lower().split('.')[0]


def lit(i,base,data):
    if mn(i)!='ldr' or len(i.operands)<2: return None
    op=i.operands[1]
    if op.type!=ARM_OP_MEM or op.mem.base!=ARM_REG_PC or op.mem.index:return None
    addr=((i.address+4)&~3)+op.mem.disp
    raw=at(base,data,addr,4)
    return (addr,int.from_bytes(raw,'little')) if raw is not None else None


def immediate(i):
    if i is None:return None
    for op in i.operands:
        if op.type==ARM_OP_IMM:return op.imm & 0xFFFFFFFE & 0xFFFFFFFF
    return None


def describe(i,base,data):
    s=f'0x{i.address:08X} {i.mnemonic:<8} {i.op_str:<35} bytes={i.bytes.hex(" ")}'
    p=lit(i,base,data)
    return s+(f' ; PC_LITERAL=0x{p[0]:08X} -> 0x{p[1]:08X}' if p else '')


def verify_exact(md,base,data):
    print('\n[A] A82 TWO EXACT CALL CHAINS (fail-closed)')
    for label,start,cell,insns,after,after_name in SITES:
        raw=at(base,data,cell,4)
        if raw is None or int.from_bytes(raw,'little')!=FIELD:
            abort(f'{label} literal mismatch at 0x{cell:08X}')
        print(f'{label}: consumer=0x{start:08X}, slot=0x{FIELD:08X}, literal_cell=0x{cell:08X}')
        for address,mnemonic in insns:
            i=single(md,base,data,address)
            if i is None or mn(i)!=mnemonic or i.size!=2:
                abort(f'{label} instruction mismatch at 0x{address:08X}')
            if address==start and lit(i,base,data)!=(cell,FIELD):
                abort(f'{label} PC-relative address load mismatch')
            if address==start+2 and (len(i.operands)<2 or i.op_str.replace(' ','').lower()!='r0,[r0]'):
                abort(f'{label} pointer dereference mismatch')
            if address==start+4 and i.op_str.strip().lower()!='r0':
                abort(f'{label} BLX does not invoke r0')
            print('  '+describe(i,base,data))
        i=single(md,base,data,after)
        if i is None or mn(i)!=after_name:abort(f'{label} post-BLX control mismatch')
        print('  AFTER '+describe(i,base,data))
    print('EXACT_TWO_SLOT_CONSUMERS=PASS')


def preview(md,base,data,lo,hi,label,spot):
    print(f'\n{label}: LINEAR WINDOW [0x{lo:08X},0x{hi:08X}), including 0x{spot:08X} (NOT a certified CFG)')
    raw=at(base,data,lo,hi-lo)
    if raw is None:abort(f'window OOB {label}')
    for i in md.disasm(raw,lo):
        if i.address >= hi: break
        prefix='  >>> ' if i.address in {spot,spot+2,spot+4} else '      '
        print(prefix+describe(i,base,data))
        # No implication that literal-pool data is code outside reached CFG.


def cfg(md,base,data,start,end,site,print_blocks=False):
    """Conservative bounded Thumb reachability; no interprocedural traversal."""
    todo=deque([start]); seen=set(); blocks=set(); calls=[];conds=[];notes=[]
    while todo and len(seen)<350 and len(blocks)<100:
        addr=todo.popleft()
        if addr in blocks or not(start<=addr<end):continue
        blocks.add(addr)
        count=0
        while start<=addr<end and addr not in seen and count<105 and len(seen)<350:
            i=single(md,base,data,addr)
            if i is None or addr+i.size>end:
                notes.append(f'UNDECODABLE_OR_BOUND=0x{addr:08X}');break
            seen.add(addr);count+=1;m=mn(i);nxt=addr+i.size
            if m in ('bl','blx'):
                calls.append((addr,m,immediate(i),i.op_str))
            if m in CONDITIONAL:
                conds.append((addr,m,immediate(i),i.op_str))
            if m in CONDITIONAL or m=='b':
                t=immediate(i)
                if t is not None and start<=t<end:todo.append(t)
                elif t is not None: notes.append(f'BRANCH_EXIT=0x{addr:08X}->0x{t:08X}')
                if m=='b':break
            if m in TERMINATE or (m=='pop' and 'pc' in i.op_str.lower()) or (m=='ldr' and i.op_str.lower().startswith('pc,')):
                break
            addr=nxt
        if count>=105:notes.append(f'BLOCK_CAP=0x{addr:08X}')
    matched=site in seen and site+2 in seen and site+4 in seen
    complete=not todo and len(seen)<350 and len(blocks)<100 and not any('CAP' in v for v in notes)
    return dict(start=start,seen=seen,blocks=blocks,calls=calls,conds=conds,notes=notes,matched=matched,complete=complete)


def function_candidates(md,base,data,site):
    lo=max(base,site-0x1C0);lo+=lo&1
    options=[]
    for candidate in range(lo,site+1,2):
        i=single(md,base,data,candidate)
        if i is None or mn(i)!='push' or 'lr' not in i.op_str.lower():continue
        result=cfg(md,base,data,candidate,min(site+0x100,base+len(data)),site)
        if result['matched']:
            options.append(result)
    options.sort(key=lambda d:d['start'],reverse=True)
    return options


def caller_scan(md,base,data,entry):
    """Only exact BL target; candidate callsites can be data (must say so)."""
    out=[]
    for offset in range(0,len(data)-3,2):
        a=int.from_bytes(data[offset:offset+2],'little')
        b=int.from_bytes(data[offset+2:offset+4],'little')
        # Thumb-2 BL: high-halfword 11110xxxxx..., low-halfword 11xxxxx...
        if (a & 0xF800)!=0xF000 or (b & 0xD000)!=0xD000:continue
        site=base+offset
        i=single(md,base,data,site)
        if i is not None and mn(i)=='bl' and immediate(i)==entry:out.append(site)
    return out


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--alice',type=Path,default=Path('research/f2/work/extracted/altice_alice/alice-py.bin'))
    p.add_argument('--zimage',type=Path,default=Path('research/f2/work/extracted/altice_platform/zimage.bin'))
    args=p.parse_args()
    print('S13.5A.83 - TWO EXACT CONTEXT CALLBACK BLX OWNER / TRIGGER CANDIDATE AUDIT')
    print('STRICTLY OFFLINE: only canonical ALICE/ZIMAGE local reads; no USB/COM/phone/patch/repack/write/erase/flash')
    alice_base,alice=guarded(args.alice,'ALICE')
    base,data=guarded(args.zimage,'ZIMAGE')
    md=Cs(CS_ARCH_ARM,CS_MODE_THUMB|CS_MODE_LITTLE_ENDIAN)
    md.detail=True
    verify_exact(md,base,data)
    print('\n[B] BOUNDED CONSUMER ENTRY / GUARD WINDOWS')
    for label,site,cell,_,after,_ in SITES:
        lo=max(base,site-0x70)
        lo += lo & 1
        hi=min(base+len(data),max(site+0x34,after+8))
        preview(md,base,data,lo,hi,label,site)
    print('\n[C] BACKWARD THUMB-PROLOGUE CANDIDATES (not assumed definitive)')
    chosen=[]
    for label,site,*_ in SITES:
        opts=function_candidates(md,base,data,site)
        print(f'{label} SINK=0x{site+4:08X} PROLOGUE_REACHABLE_CANDIDATES={len(opts)}')
        for d in opts[:6]:
            prev=sorted(x for x in d['conds'] if x[0]<site)[-12:]
            print(f'  CANDIDATE_ENTRY=0x{d["start"]:08X} site_reached={d["matched"]} instructions={len(d["seen"])} blocks={len(d["blocks"])} complete={d["complete"]} notes={d["notes"][:4]}')
            for addr,m,t,_ in prev:
                print(f'    PRE_SITE_GUARD 0x{addr:08X} {m} -> '+(f'0x{t:08X}' if t is not None else 'dynamic'))
        if len(opts)==1 and opts[0]['complete']:
            chosen.append((label,opts[0]['start'],site))
        elif opts:
            print('  OWNER_UNCERTAIN: multiple candidates or bounded CFG incomplete; direct caller search NOT promoted')
        else:
            print('  OWNER_UNRESOLVED: no confirmed prologue; do not infer event or menu trigger')
    print('\n[D] SINGLE-HOP EXACT THUMB BL CALLER CANDIDATES — ONLY UNIQUE COMPLETE OWNERS')
    for label,entry,site in chosen:
        matches=caller_scan(md,base,data,entry)
        print(f'{label}: VERIFIED_BRANCH_ENCODING_TARGET=0x{entry:08X} CANDIDATE_BL_REFERENCES={len(matches)}')
        for callsite in matches[:20]:
            i=single(md,base,data,callsite)
            print('  CANDIDATE_CALLER '+describe(i,base,data))
            left=max(base,callsite-0x18);left+=left&1
            preview(md,base,data,left,min(callsite+8,base+len(data)),f'  LOCAL_CALLSITE 0x{callsite:08X}',callsite)
        if len(matches)>20:print('  REFERENCES_CAPPED at 20; no exhaustive caller reachability claim')
        print('  NOTE: raw Thumb BL target matching does NOT certify a true executable callsite (literal/data can mimic opcodes).')
    if not chosen:print('  NO_PROMOTED_OWNER: early stop by design; do not scan broad xrefs')
    print('\n[E] PROMOTION GATE')
    print('PROVEN: two static ZIMAGE instruction sequences dereference and BLX MEM[F004C5E8].')
    print('NOT_PROVEN: dynamic value at execution, exact event triggering either site, MENU OK/SELECT, Audio 0x8928, flash patch eligibility.')
    print('OTHER_POTENTIAL_CONSUMERS: derived-base/dynamic callbacks not excluded.')
    print('NO_PHONE_ACCESS=YES NO_FIRMWARE_WRITE=YES A83_OFFLINE_COMPLETE=YES')

if __name__=='__main__':main()
