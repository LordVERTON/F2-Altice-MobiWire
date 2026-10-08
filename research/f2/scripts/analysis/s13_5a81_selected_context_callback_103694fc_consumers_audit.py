#!/usr/bin/env python3
"""S13.5A.81: source-guarded, offline selected-context callback semantics.

Targets exactly proven A.80 registration F0303A84 -> [F004C5CC+0x1C]
of the Thumb pointer 103694FD (ALICE entry 103694FC), plus literal-based
candidate consumers of the SAME selected-context field. No device I/O/writes.
"""
import argparse
import hashlib
from pathlib import Path

try:
    from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_LITTLE_ENDIAN
    from capstone.arm import ARM_OP_IMM, ARM_OP_MEM, ARM_REG_PC
except ImportError as exc:
    raise SystemExit('ABORT: install capstone in your existing mtkclient venv: '+str(exc))

SOURCES = {
    'ALICE': (0x1024EC00, 0x157BB4, '7246242b67afae0d13104452bc3257827cb778119b54e7a26fb7fb55993697ea'),
    'ZIMAGE': (0xF023CA50, 0x185E98, '85fba8c8ae8161e4c1f8ced7983ec30d48c54ab10e51c69fcdfb900aca220954'),
}
CONTEXT = 0xF004C5CC
CALLBACK_THUMB = 0x103694FD
CALLBACK_ENTRY = CALLBACK_THUMB & ~1
ANCHORED = {
    0xF0303A3E: ('ldr', 'r7'),
    0xF0303A56: ('ldr', 'r6'),
    0xF0303A84: ('str', 'r6'),
}


def fail(message):
    raise SystemExit('ABORT: '+message)


def load(path, name):
    base, size, wanted = SOURCES[name]
    if not path.is_file(): fail(f'{name} file missing: {path}')
    b=path.read_bytes()
    sha=hashlib.sha256(b).hexdigest()
    good=len(b)==size and sha==wanted
    print(f'{name} path={path} size=0x{len(b):X} sha256={sha} GUARD={"PASS" if good else "FAIL"}')
    if not good: fail(f'{name} canonical byte guard')
    return base,b


def cut(data, base, addr, n):
    off=addr-base
    if off<0 or n<0 or off+n>len(data): return None
    return data[off:off+n]


def instr(md, data, base, addr):
    b=cut(data,base,addr,4)
    if b is None: fail('instruction outside image '+hex(addr))
    out=list(md.disasm(b,addr,count=1))
    if len(out)!=1 or out[0].address!=addr: fail('undecodable instruction '+hex(addr))
    return out[0]


def pc_literal(md_i, data, base):
    if md_i.mnemonic.lower().split('.')[0]!='ldr' or len(md_i.operands)<2: return None
    op=md_i.operands[1]
    if op.type!=ARM_OP_MEM or op.mem.base!=ARM_REG_PC or op.mem.index: return None
    cell=((md_i.address+4)&~3)+op.mem.disp
    b=cut(data,base,cell,4)
    return (cell,int.from_bytes(b,'little')) if b is not None else None


def fmt(i, data, base):
    x=f'0x{i.address:08X}: {i.mnemonic:<9} {i.op_str:<33} bytes={i.bytes.hex(" ")}'
    p=pc_literal(i,data,base)
    if p: x+=f' ; PC_CELL=0x{p[0]:08X} U32=0x{p[1]:08X}'
    return x


def branch_target(i):
    if not i.operands: return None
    op=i.operands[0]
    return (op.imm&0xffffffff)&~1 if op.type==ARM_OP_IMM else None


def thumb_cfg(md, data, base, start, end, max_ins=220, max_blocks=32):
    todo=[start]; visited=set(); starts=set(); calls=[]; boundaries=[]; per_block=[]
    while todo and len(visited)<max_ins and len(starts)<max_blocks:
        here=todo.pop(0)
        if here in starts or not(start<=here<end):continue
        starts.add(here)
        n=0
        while start<=here<end and here not in visited and len(visited)<max_ins and n<110:
            i=instr(md,data,base,here)
            if i.address+i.size>end:
                boundaries.append('block ran beyond window '+hex(here));break
            visited.add(here);n+=1
            print('  '+fmt(i,data,base))
            m=i.mnemonic.lower().split('.')[0]
            next_ip=here+i.size
            if m in ('bl','blx'):
                target=branch_target(i)
                calls.append((here,m,target,i.op_str))
            if m in ('b','b.w','beq','bne','bgt','bge','blt','ble','bhi','bhs','blo','bls','bpl','bmi','bvc','bvs','cbz','cbnz'):
                target=branch_target(i)
                if target is not None:
                    boundaries.append(f'edge 0x{here:08X}: {m} -> 0x{target:08X}')
                    if start<=target<end:todo.append(target)
                    else:boundaries.append('out-of-window branch '+hex(target))
                # Unconditional b: no fallthrough. CBZ/CBNZ/condition: also visit fallthrough.
                if m in ('b','b.w'):break
                here=next_ip
                continue
            if m in ('bx','pop') and (m=='bx' or 'pc' in i.op_str.lower()):break
            if m in ('udf','bkpt'):break
            here=next_ip
        per_block.append((n,here))
        if n>=110:boundaries.append('per-block cap at '+hex(here))
    print(f'CFG_SUMMARY instructions={len(visited)} blocks={len(starts)} calls={len(calls)} pending={len(todo)} bounds=[0x{start:X},0x{end:X})')
    for a,m,t,raw in calls:
        print(f'  CALL 0x{a:08X} {m} => '+(f'0x{t:08X}' if t is not None else 'REGISTER_INDIRECT')+' '+raw)
    for e in boundaries[:65]:print('  '+e)
    if todo:print('WARNING: CFG capacity/branch limit reached; not complete')


def context_refs(md, z, zbase, max_cells=48, max_sites=48):
    # Single value, PC-relative Thumb LDR only. This does NOT prove alias,
    # field use, reachable control flow, or runtime execution.
    val=CONTEXT.to_bytes(4,'little'); positions=[];off=0
    while True:
        off=z.find(val,off)
        if off<0:break
        if off%4==0:positions.append(zbase+off)
        off+=1
    print(f'CONTEXT_LITERAL_CELLS=0x{CONTEXT:08X} count={len(positions)} checked_max={max_cells}')
    if len(positions)>max_cells:print('WARNING: literal cell enumeration capped')
    found=set(); candidate_count=0
    for cell in positions[:max_cells]:
        # Thumb literal LDR t1 reaches positive offsets <=0x3fc.
        a_start=max(zbase,cell-0x400)
        for a in range(a_start+(a_start&1),cell,2):
            try: i=instr(md,z,zbase,a)
            except SystemExit: continue
            if i.mnemonic.lower().split('.')[0]!='ldr':continue
            p=pc_literal(i,z,zbase)
            if p!=(cell,CONTEXT) or a in found:continue
            found.add(a)
            if candidate_count>=max_sites:continue
            candidate_count+=1
            # bounded subsequent slice, stop on returns; textual reference only.
            max_end=min(a+0x42,zbase+len(z))
            raw=cut(z,zbase,a,max_end-a)
            print(f'\nCONTEXT_LDR_CANDIDATE at=0x{a:08X} literal_cell=0x{cell:08X} ; no CFG/reachability claim')
            for j in md.disasm(raw,a):
                if j.address>=max_end:break
                print('  '+fmt(j,z,zbase))
                if j.address>=a+0x28:break
                m=j.mnemonic.lower().split('.')[0]
                if m=='bx' or (m=='pop' and 'pc' in j.op_str):break
    print(f'CONTEXT_PC_LDR_SITES={len(found)} printed={candidate_count} cap={max_sites}')
    print('CAUTION: PC-LDR proximity does not establish [context+0x1C] read, BLX target, or execution.')


def main():
    pa=argparse.ArgumentParser(description=__doc__)
    pa.add_argument('--alice',type=Path,default=Path('research/f2/work/extracted/altice_alice/alice-py.bin'))
    pa.add_argument('--zimage',type=Path,default=Path('research/f2/work/extracted/altice_platform/zimage.bin'))
    args=pa.parse_args()
    print('S13.5A.81 - SELECTED CONTEXT CALLBACK TARGET + FIELD CONSUMER AUDIT')
    print('STRICTLY OFFLINE: READ LOCAL ALICE/ZIMAGE ONLY. NO USB/COM/PHONE/FLASH/PATCH/WRITE/REPACK')
    abase,a=load(args.alice,'ALICE');zbase,z=load(args.zimage,'ZIMAGE')
    md=Cs(CS_ARCH_ARM,CS_MODE_THUMB|CS_MODE_LITTLE_ENDIAN)
    md.detail=True
    print('\nA.80 EXACT REGISTRATION ANCHORS - FAIL CLOSED')
    for addr,(m,reg) in ANCHORED.items():
        i=instr(md,z,zbase,addr)
        good=i.mnemonic.split('.')[0]==m and i.op_str.lower().startswith(reg+',')
        if addr==0xF0303A84: good=good and '[r7, #0x1c]' in i.op_str.lower()
        print(('PASS' if good else 'FAIL')+' '+fmt(i,z,zbase))
        if not good:fail('anchor mismatch at '+hex(addr))
    a1=instr(md,z,zbase,0xF0303A3E);a2=instr(md,z,zbase,0xF0303A56)
    if pc_literal(a1,z,zbase)!=(0xF0303B20,CONTEXT):fail('context literal mismatch')
    if pc_literal(a2,z,zbase)!=(0xF0303B28,CALLBACK_THUMB):fail('installed Thumb value mismatch')
    if not(abase<=CALLBACK_ENTRY<abase+len(a)):fail('target not covered by canonical ALICE')
    print(f'PROVEN_SOURCE_DATA context=0x{CONTEXT:08X} +0x1C <- Thumb=0x{CALLBACK_THUMB:08X}; ALICE_ENTRY=0x{CALLBACK_ENTRY:08X}; OFFSET=0x{CALLBACK_ENTRY-abase:X}')
    print('NOTE: code installs pointer, but dynamic execution and menu OK/Select role are NOT established.')
    print('\nB. EXACT ALICE CALLBACK BODY; BOUNDED BRANCH-CAUTIOUS THUMB CFG')
    thumb_cfg(md,a,abase,CALLBACK_ENTRY,CALLBACK_ENTRY+0x240)
    print('\nC. EXACT SELECTED-CONTEXT PC-LITERAL CONSUMER CANDIDATES (ZIMAGE ONLY)')
    context_refs(md,z,zbase)
    print('\nD. RESULT / SAFETY GATE')
    print('A81_OFFLINE_AUDIT_COMPLETED=YES')
    print('UNKNOWN: runtime consumer of selected-context+0x1C; native Audio 0x8928 OK/Select or menu exposure still unproven.')
    print('PHONE_ACCESSED=NO FIRMWARE_MODIFIED=NO PATCH=NO WRITE_AUTHORIZED=NO')

if __name__=='__main__':main()
