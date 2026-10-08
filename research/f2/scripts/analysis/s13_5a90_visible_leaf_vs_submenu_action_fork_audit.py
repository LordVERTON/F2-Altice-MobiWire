#!/usr/bin/env python3
"""S13.5A.90 — two KNOWN menu-navigation callers: leaf vs submenu action fork.

Strictly offline, SHA-pinned READS only. Does NOT repeat A.89's generic ID
gateway; does NOT re-prove the S13.5A.8–A.16 menu selection callbacks.

Already established in S13.5A.8–A.10:
  10315514(index) -> descriptor.children[index]
  10342FDC stores selected child into descriptor+0x18
  10387DB8/BA copies selected child +0x18 to parent +0x14 for submenu
  10387DD4 -> 10347432 -> 10340ADC -> 10343050 rebuilds submenu
  102ED26C and 103452AC are the two direct calls to 10387D94.

Only new question: what are the alternative control-flow arms adjacent to the two
KNOWN calls to ENTER_SUBMENU, particularly when a selected leaf cannot enter?
A candidate leaf call is NOT promoted to OK/Select or Audio launch without
proven descriptor identity and ID/argument flow. No patch is generated.
"""
from __future__ import annotations
import argparse
import hashlib
from pathlib import Path
from collections import deque
try:
    from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_LITTLE_ENDIAN
    from capstone.arm import ARM_OP_IMM, ARM_OP_MEM, ARM_REG_PC
except ImportError as ex:
    raise SystemExit('ABORT: Capstone unavailable in user offline environment: '+str(ex))

ALICE=(0x1024EC00,0x157BB4,'7246242b67afae0d13104452bc3257827cb778119b54e7a26fb7fb55993697ea')
ZIMAGE=(0xF023CA50,0x185E98,'85fba8c8ae8161e4c1f8ced7983ec30d48c54ab10e51c69fcdfb900aca220954')
SUBMENU=0x10387D94
SITES=(0x102ED26C,0x103452AC)
KNOWN_SELECTED_COPY=(0x10387DB8,0x10387DBA)
CONDITIONAL={'beq','bne','bgt','bge','blt','ble','bhi','bhs','blo','bls','bmi','bpl','bvs','bvc','cbz','cbnz'}
RETURNS={'bx','bkpt','udf','tbb','tbh'}

def abort(msg):
    raise SystemExit('ABORT: '+msg)

def load(path,label,meta):
    base,size,expected=meta
    if not path.is_file(): abort(f'{label} missing: {path}')
    raw=path.read_bytes(); sha=hashlib.sha256(raw).hexdigest()
    valid=len(raw)==size and sha==expected
    print(f'{label}: {path} size=0x{len(raw):X} sha256={sha} GUARD={"PASS" if valid else "FAIL"}')
    if not valid: abort('source guard failed for '+label)
    return base,raw

def rd(img,addr,n=4):
    base,data=img; off=addr-base
    if off<0 or off+n>len(data): return None
    return data[off:off+n]

def inst(md,img,addr):
    data=rd(img,addr,4)
    if data is None: return None
    a=list(md.disasm(data,addr,count=1))
    return a[0] if a and a[0].address==addr else None

def mn(ins): return ins.mnemonic.lower().split('.')[0]

def target(ins):
    if not ins or not ins.operands: return None
    for op in reversed(ins.operands):
        if op.type==ARM_OP_IMM: return (op.imm & 0xFFFFFFFF)&~1
    return None

def literal(ins,img):
    if mn(ins)!='ldr' or len(ins.operands)<2: return None
    op=ins.operands[1]
    if op.type != ARM_OP_MEM or op.mem.base != ARM_REG_PC or op.mem.index: return None
    cell=(((ins.address+4)&~3)+op.mem.disp)&0xFFFFFFFF
    data=rd(img,cell,4)
    return (cell,int.from_bytes(data,'little')) if data else None

def show(ins,img):
    s=f'{ins.address:08X} {ins.mnemonic:8s} {ins.op_str:36s} {ins.bytes.hex(" ")}'
    lt=literal(ins,img)
    if lt: s+=f' ; CELL={lt[0]:08X} VALUE={lt[1]:08X}'
    return s

def guard(md,alice,zimage):
    print('\n[A] CANONICAL EXISTING NAVIGATION ANCHORS')
    for site in SITES:
        ins=inst(md,alice,site)
        if not ins or mn(ins) not in ('bl','blx') or target(ins)!=SUBMENU:
            abort(f'known submenu caller moved/encoding invalid at {site:08X}: {ins}')
        print('  SUBMENU_CALL_PASS '+show(ins,alice))
    a,b=[inst(md,alice,i) for i in KNOWN_SELECTED_COPY]
    if not a or not b or mn(a)!='ldrh' or mn(b)!='strh' or '#0x18' not in a.op_str.lower() or '#0x14' not in b.op_str.lower():
        abort('S13.5A.8 descriptor selected-child to current-parent anchor mismatch')
    print('  SELECTED_TO_PARENT_PASS '+show(a,alice)); print('  SELECTED_TO_PARENT_PASS '+show(b,alice))
    if rd(zimage,0xF0345E68,58*8) is None: abort('ZIMAGE resolver table bound invalid')
    print('  This is NOT re-analysis of S13.5A.8..16 selection or A87 resolver.')


def cfg(md,img,start,site,end):
    todo=deque([start]); blocks=set(); seen={}; branches=[]; issues=[]; calls=[]
    while todo and len(seen)<280 and len(blocks)<55:
        pc=todo.popleft()
        if pc in blocks or not(start<=pc<end):continue
        blocks.add(pc); steps=0
        while start<=pc<end and pc not in seen and steps<90 and len(seen)<280:
            ins=inst(md,img,pc)
            if not ins or pc+ins.size>end:
                issues.append(f'DECODE/BOUND {pc:08X}'); break
            seen[pc]=ins; steps+=1; name=mn(ins); nxt=pc+ins.size
            if name in ('bl','blx'):
                calls.append((pc,name,target(ins)))
            if name in CONDITIONAL or name=='b':
                t=target(ins);branches.append((pc,name,t))
                if t is None:
                    issues.append(f'UNKNOWN_BRANCH {pc:08X}')
                elif start<=t<end:
                    todo.append(t)
                elif t>=end or t<start:
                    # Outside this *local window* does not establish a completed function.
                    issues.append(f'OUT_OF_WINDOW {pc:08X}->{t:08X}')
                if name=='b':break
            if name in RETURNS or (name=='pop' and 'pc' in ins.op_str.lower()) or (name=='ldr' and ins.op_str.lower().startswith('pc,')):
                if name in ('tbb','tbh','bx') and not (name=='bx' and 'lr' in ins.op_str.lower()):
                    issues.append(f'INDIRECT_FLOW {pc:08X}')
                break
            pc=nxt
        if steps>=90:issues.append(f'BLOCK_CAP {pc:08X}')
    complete=not todo and len(seen)<280 and len(blocks)<55 and not any('CAP' in x or 'INDIRECT' in x or 'DECODE' in x for x in issues)
    # Any OUT_OF_WINDOW means our bounded owner may have an upstream path not audited.
    local_complete=complete and not any('OUT_OF_WINDOW' in x for x in issues)
    return dict(start=start,seen=seen,branches=branches,calls=calls,issues=issues,
                local_complete=local_complete,reached=site in seen,block_count=len(blocks))

def owners(md,img,site):
    lo=(site-0x160)&~1; hi=site+0x36
    found=[]; tested=0
    for addr in range(lo,site,2):
        ins=inst(md,img,addr)
        if ins and mn(ins)=='push' and 'lr' in ins.op_str.lower():
            tested+=1
            r=cfg(md,img,addr,site,hi)
            if r['reached']:found.append(r)
    print(f'  PROLOGUES_TESTED={tested} REACHED={len(found)} WINDOW=0x{lo:08X}..0x{hi:08X}')
    for v in found[:7]:
        print(f'    OWNER_CANDIDATE={v["start"]:08X} INSNS={len(v["seen"])} BLOCKS={v["block_count"]} WINDOW_COMPLETE={v["local_complete"]} ISSUES={v["issues"][:6]}')
    if len(found)==1 and found[0]['local_complete']:
        print('  UNIQUE_COMPLETE_LOCAL_OWNER=YES (NOT function caller/reachability proof)')
    else:print('  UNIQUE_COMPLETE_LOCAL_OWNER=NO; raw windows remain non-certified')
    return found

def audit_site(md,img,site):
    print(f'\n[B] SUBMENU_CALLSITE_{site:08X} — BOUNDED PREDECESSOR / LEAF FORK')
    found=owners(md,img,site)
    unique=found[0] if len(found)==1 and found[0]['local_complete'] else None
    if unique:
        branchlist=[x for x in unique['branches'] if abs(x[0]-site)<=0xC0]
        for pc,m,t in branchlist:
            print(f'  CFG_BRANCH_{pc:08X} {m} => '+(f'{t:08X}' if t is not None else 'INDIRECT'))
        print('  CFG_NEAR_CALLS: candidate sibling call paths; not automatically leaves')
        for pc,m,t in unique['calls']:
            if site-0x110<=pc<=site+0x30:
                print(f'    {pc:08X} {m} {t:08X}' if t is not None else f'    {pc:08X} {m} INDIRECT')
        print('  CFG_LOCAL_INSTRUCTIONS +/-0x50:')
        for addr in sorted(unique['seen']):
            if site-0x50<=addr<=site+0x24:print('    '+show(unique['seen'][addr],img))
    else:
        print('  RAW_LOCAL_ONLY_NOT_CFG:')
        for addr in range(site-0x50,site+0x28,2):
            ins=inst(md,img,addr)
            if not ins:continue
            if site-0x30<=addr<=site+0x20 and (mn(ins) in CONDITIONAL|{'b','bl','blx','ldrh','cmp','cbz','cbnz'}):
                print('    '+show(ins,img))
    print('  DECISION_PENDING: identify pre-call predicate on descriptor+0x18 and alternative leaf-action target; no menu-ID inference here')

def main():
    arg=argparse.ArgumentParser(description=__doc__)
    arg.add_argument('--alice',type=Path,default=Path('research/f2/work/extracted/altice_alice/alice-py.bin'))
    arg.add_argument('--zimage',type=Path,default=Path('research/f2/work/extracted/altice_platform/zimage.bin'))
    x=arg.parse_args()
    print('S13.5A.90 — VISIBLE-ITEM LEAF ACTION VS ENTER-SUBMENU CONTROL-FLOW FORK')
    print('STRICTLY OFFLINE READ ONLY, NO PHONE/USB/COM/FLASH/ERASE/REPACK/PATCH/WRITE')
    alice=load(x.alice,'ALICE',ALICE); zimage=load(x.zimage,'ZIMAGE',ZIMAGE)
    md=Cs(CS_ARCH_ARM,CS_MODE_THUMB|CS_MODE_LITTLE_ENDIAN);md.detail=True
    guard(md,alice,zimage)
    for site in SITES: audit_site(md,alice,site)
    print('\n[C] SUMMARY/GATE')
    print('EXISTING_SELECTION_CHAIN_S13_5A_8_TO_16=GIVEN_NOT_RESCANNED')
    print('NEW_AUDIT_SCOPE=TWO_PROVEN_SUBMENU_CALLERS_ONLY')
    print('FM_RADIO_ID=UNKNOWN; AUDIO_APP_ID=8928_BUT_NOT_MENU_ID_PROVEN')
    print('LEAF_ACTION_ROUTE=UNPROVEN_UNTIL_FUNCTION_ID_ARGUMENT_PROVEN')
    print('NO_PHONE_ACCESS=YES FIRMWARE_MODIFIED=NO WRITE_AUTHORIZED=NO')
if __name__=='__main__':main()
