#!/usr/bin/env python3
"""S13.5A.82 — OFFLINE, PINNED, NARROW SELECTED-CONTEXT CALLBACK DIFFERENTIAL.

A.81 already inspected a no-op ALICE callback (103694FC) and first 48
F004C5CC literal cells. New work ONLY: the three alternative Thumb targets,
uninspected literal cells [48:], and exact address F004C5E8 of context+0x1C.
This is not a runtime trace nor a menu/Audio-launch proof. NO DEVICE I/O.
"""
from pathlib import Path
import argparse, hashlib
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_LITTLE_ENDIAN
from capstone.arm import ARM_OP_IMM, ARM_OP_MEM, ARM_REG_PC

SOURCE = {
    'ALICE': (0x1024EC00, 0x157BB4, '7246242b67afae0d13104452bc3257827cb778119b54e7a26fb7fb55993697ea'),
    'ZIMAGE': (0xF023CA50, 0x185E98, '85fba8c8ae8161e4c1f8ced7983ec30d48c54ab10e51c69fcdfb900aca220954'),
}
CONTEXT = 0xF004C5CC
FIELD = CONTEXT + 0x1C
ALTS = [
    ('A: F031103A/F031103C',0xF031103A,0xF031103C,0xF03110C0,0xF0316DE5,0xF0316DE4,0xF0316E60),
    ('B: F03111A4/F03111A6',0xF03111A4,0xF03111A6,0xF03111D0,0xF0316E61,0xF0316E60,0xF0316F80),
    ('C: F0312938/F031293A',0xF0312938,0xF031293A,0xF031298C,0xF02DB249,0xF02DB248,0xF02DB368),
]

def abort(msg):
    raise SystemExit('ABORT: '+msg)

def read_guard(path,name):
    base,size,sha_expected=SOURCE[name]
    if not path.is_file():abort(f'{name} missing: {path}')
    b=path.read_bytes()
    sha=hashlib.sha256(b).hexdigest()
    status='PASS' if len(b)==size and sha==sha_expected else 'FAIL'
    print(f'{name}: path={path} size=0x{len(b):X} sha256={sha} GUARD={status}')
    if status!='PASS':abort(f'{name} canonical guard failed')
    return base,b

def raw_at(base,b,addr,n):
    off=addr-base
    return b[off:off+n] if 0<=off and 0<=n and off+n<=len(b) else None

def one(md,base,b,addr):
    raw=raw_at(base,b,addr,4)
    if raw is None:abort(f'out-of-range instruction {addr:08X}')
    ins=list(md.disasm(raw,addr,count=1))
    if len(ins)!=1 or ins[0].address!=addr:abort(f'undecodable Thumb {addr:08X}')
    return ins[0]

def mn(i):return i.mnemonic.lower().split('.')[0]

def literal(i,base,b):
    if mn(i)!='ldr' or len(i.operands)<2:return None
    op=i.operands[1]
    if op.type!=ARM_OP_MEM or op.mem.base!=ARM_REG_PC or op.mem.index:return None
    c=((i.address+4)&~3)+op.mem.disp
    raw=raw_at(base,b,c,4)
    return (c,int.from_bytes(raw,'little')) if raw is not None else None

def display(i,base,b):
    s=f'0x{i.address:08X}: {i.mnemonic:<9} {i.op_str:<33} bytes={i.bytes.hex(" ")}'
    p=literal(i,base,b)
    return s+(f' ; LITERAL_CELL=0x{p[0]:08X} VALUE=0x{p[1]:08X}' if p else '')

def target(i):
    for op in reversed(i.operands):
        if op.type==ARM_OP_IMM:return op.imm&0xfffffffe&0xffffffff
    return None

def small_cfg(md,base,b,start,end):
    print(f'BOUND=[0x{start:08X},0x{end:08X}); STATIC CFG, calls not followed')
    todo=[start];blocks=set();visited=set();calls=[];notes=[]
    cond={'beq','bne','bge','bgt','ble','blt','bhi','bhs','blo','bls','bpl','bmi','bvc','bvs','cbz','cbnz'}
    while todo and len(visited)<150 and len(blocks)<22:
        addr=todo.pop(0)
        if addr in blocks or not start<=addr<end:continue
        blocks.add(addr);count=0
        while start<=addr<end and addr not in visited and count<75 and len(visited)<150:
            i=one(md,base,b,addr)
            if addr+i.size>end:notes.append(f'END_BOUNDARY at 0x{addr:08X}');break
            print('  '+display(i,base,b))
            visited.add(addr);count+=1;m=mn(i);nxt=addr+i.size
            if m in ('bl','blx'):
                calls.append((addr,m,target(i),i.op_str))
            if m in cond or m=='b':
                t=target(i)
                if t is not None:
                    if start<=t<end:todo.append(t)
                    else:notes.append(f'BRANCH_OUT 0x{addr:08X}->0x{t:08X}')
                if m=='b':break
            if m=='bx' or (m=='pop' and 'pc' in i.op_str.lower()) or m in ('udf','bkpt'):break
            addr=nxt
        if count>=75:notes.append(f'PER_BLOCK_CAP at 0x{addr:08X}')
    for site,m,t,arg in calls:
        print(f'  CALL 0x{site:08X} {m} => '+(f'0x{t:08X}' if t is not None else 'INDIRECT')+f' ({arg})')
    for item in notes:print('  NOTE '+item)
    print(f'CFG_RESULT instructions={len(visited)} blocks={len(blocks)} calls={len(calls)} queued={len(todo)}')
    if todo or len(visited)>=150 or len(blocks)>=22:print('  WARNING PARTIAL_CFG_LIMIT')

def literal_cells(base,b,val):
    needle=val.to_bytes(4,'little');offs=[];start=0
    while True:
        pos=b.find(needle,start)
        if pos<0:break
        if pos%4==0:offs.append(base+pos)
        start=pos+1
    return offs

def validated_pc_loaders(md,base,b,cell,value):
    lo=max(base,cell-0x400);lo+=lo&1
    out=[]
    for addr in range(lo,cell,2):
        raw=raw_at(base,b,addr,4)
        if raw is None:continue
        trial=list(md.disasm(raw,addr,count=1))
        if not trial or trial[0].address!=addr:continue
        p=literal(trial[0],base,b)
        if p==(cell,value):out.append(trial[0])
    return out

def local_slice(md,base,b,at):
    end=min(at+0x2C,base+len(b));raw=raw_at(base,b,at,end-at)
    if raw is None:return
    for i in md.disasm(raw,at):
        if i.address>=end:break
        print('    '+display(i,base,b))
        if mn(i)=='bx' or (mn(i)=='pop' and 'pc' in i.op_str.lower()) or mn(i)=='b':break

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--alice',type=Path,default=Path('research/f2/work/extracted/altice_alice/alice-py.bin'))
    p.add_argument('--zimage',type=Path,default=Path('research/f2/work/extracted/altice_platform/zimage.bin'))
    a=p.parse_args()
    print('S13.5A.82 - SELECTED CONTEXT CALLBACK VARIANTS AND UNCHECKED READERS')
    print('STRICTLY OFFLINE: no USB/COM/phone/flash/patch/write/repack; binary read only')
    abase,alice=read_guard(a.alice,'ALICE');zbase,z=read_guard(a.zimage,'ZIMAGE')
    md=Cs(CS_ARCH_ARM,CS_MODE_THUMB|CS_MODE_LITTLE_ENDIAN);md.detail=True
    print('\nA. A81 NO-OP SANITY GUARD')
    x=raw_at(abase,alice,0x103694FC,2)
    print(f'ALICE 0x103694FC bytes={x.hex(" ") if x else None}')
    if x!=bytes.fromhex('70 47'):abort('prior no-op byte guard mismatch')
    print('NO_OP=PASS (BX LR); this was completely characterized in A81, NOT reaudited')
    print('\nB. EXACT 3 NEW CONTEXT+0x1C REGISTRATIONS AND THUMB TARGETS')
    for label,la,st,cell,ptr,entry,end in ALTS:
        load=one(md,zbase,z,la);store=one(md,zbase,z,st)
        lit=literal(load,zbase,z)
        good=lit==(cell,ptr) and mn(store)=='str' and '[r' in store.op_str.lower() and '#0x1c]' in store.op_str.lower()
        if not good:abort('installer instruction/literal guard failure at '+label)
        print(f'PASS {label} pointer=0x{ptr:08X} entry=0x{entry:08X}')
        print('  '+display(load,zbase,z))
        print('  '+display(store,zbase,z))
        if ptr!=(entry|1):abort('target Thumb bit mismatch')
        small_cfg(md,zbase,z,entry,end)
    print('\nC. CONTEXT F004C5CC — ONLY A81 UNCHECKED LITERAL CELLS [48:]')
    cells=literal_cells(zbase,z,CONTEXT)
    print(f'CONTEXT_LITERAL_CELLS={len(cells)} A81_CHECKED_FIRST=min(48,{len(cells)}) A82_CHECKED_REMAINING={max(0,len(cells)-48)}')
    for cell in cells[48:]:
        found=validated_pc_loaders(md,zbase,z,cell,CONTEXT)
        print(f'  CELL=0x{cell:08X} PC_LDR_OWNERS={len(found)}')
        for ins in found[:5]:
            print('  VERIFIED_LOAD '+display(ins,zbase,z))
            local_slice(md,zbase,z,ins.address)
    print('\nD. EXACT PHYSICAL SLOT ADDRESS F004C5E8 (ALICE+ZIMAGE)')
    total=0
    for name,base,b in [('ALICE',abase,alice),('ZIMAGE',zbase,z)]:
        slots=literal_cells(base,b,FIELD)
        print(f'  {name} literal_cells_exact_field_address={len(slots)}')
        for cell in slots:
            found=validated_pc_loaders(md,base,b,cell,FIELD)
            print(f'  SLOT_CELL=0x{cell:08X} PC_LDR_OWNERS={len(found)}')
            for ins in found[:5]:
                total+=1
                print('  VERIFIED_SLOT_ADDRESS_LOAD '+display(ins,base,b))
                local_slice(md,base,b,ins.address)
    print(f'EXACT_SLOT_PC_LDR_SITES={total}; zero does NOT exclude derived-base consumers or runtime initialization')
    print('\nE. PROMOTION / SAFETY GATE')
    print('STATIC_EVIDENCE_ONLY=YES; execution / menu OK / Audio 8928 / full setter semantics remain UNPROVEN')
    print('NO ALICE/ZIMAGE MODIFICATION; NO DEVICE ACCESS; NO WRITE AUTHORIZED')
    print('A82_OFFLINE_COMPLETE=YES')

if __name__=='__main__':main()
