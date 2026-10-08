#!/usr/bin/env python3
"""S13.5A.80: bounded provenance of the selected-row +0x1C callback field.

Uses the *already identified* A.68/A.70 shortlist of five writes, not a new
symbol-wide search. Reads only SHA-pinned ALICE/ZIMAGE image files and writes
only stdout. Disassembly/def-use previews are not whole-function CFG proofs.
"""
import argparse
import hashlib
from pathlib import Path
import sys

try:
    from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_LITTLE_ENDIAN
    from capstone.arm import ARM_OP_MEM, ARM_OP_IMM, ARM_OP_REG, ARM_REG_PC
except ImportError as exc:
    raise SystemExit('ABORT: capstone required in existing mtkclient venv: ' + str(exc))

PINNED = {
    'ALICE': (0x1024EC00, 0x157BB4, '7246242b67afae0d13104452bc3257827cb778119b54e7a26fb7fb55993697ea'),
    'ZIMAGE': (0xF023CA50, 0x185E98, '85fba8c8ae8161e4c1f8ced7983ec30d48c54ab10e51c69fcdfb900aca220954'),
}
TABLE = 0xF00B9A30
SINKS = (0xF030C0A0, 0xF0312FD2)
# Precisely the A.70 fixed-table same-address indexed RMW sites plus the A.68 +0x1C store.
SITES = (
    ('W1 fixed-table indexed read/modify/write', 0xF030022E, 0xF0300200, 0xF0300234),
    ('W2 fixed-table indexed read/modify/write', 0xF0300276, 0xF030024C, 0xF030027C),
    ('W3 fixed-table indexed read/modify/write', 0xF030396C, 0xF0303928, 0xF0303970),
    ('W4 fixed-table indexed read/modify/write', 0xF0303980, 0xF0303970, 0xF03039A0),
    ('W5 candidate direct field +0x1C store', 0xF0303A84, 0xF03039D0, 0xF0303A90),
)
LITERALS = {
    0xF00B9A30: 'STATIC_ROWS_BASE',
    0xF004C5CC: 'SELECTED_CONTEXT',
    0xF004C5AC: 'OTHER_GLOBAL_FUNCPTR_SLOT',
    0xF004C5B0: 'OTHER_GLOBAL_FUNCPTR_SLOT_2',
    0xF004C5B4: 'DYNAMIC_PTR_SLOT (NOT STATIC ROW BASE)',
    0xF00B9778: 'CALL_CONTEXT_BASE',
}

def die(message):
    raise SystemExit('ABORT: ' + message)

def read_file(path, name):
    base, length, expected = PINNED[name]
    if not path.is_file():
        die(f'{name} missing: {path}')
    raw = path.read_bytes()
    sha = hashlib.sha256(raw).hexdigest()
    passed = len(raw) == length and sha == expected
    print(f'{name}: file={path} size=0x{len(raw):X} sha256={sha} GUARD={"PASS" if passed else "FAIL"}')
    if not passed: die(f'{name} size/hash differs from canonical image')
    return name, base, raw

def locate(segments, address, n):
    for name, base, data in segments:
        off = address-base
        if 0 <= off <= len(data)-n:
            return name, data[off:off+n]
    return None

def u32(segments, addr):
    b=locate(segments, addr, 4)
    return int.from_bytes(b[1], 'little') if b else None

def one(md, segments, at):
    got=locate(segments,at,4)
    if got is None: die('instruction outside pinned image: '+hex(at))
    x=list(md.disasm(got[1],at,count=1))
    if not x or x[0].address != at: die('unaligned/undecodable site '+hex(at))
    return x[0]

def decoded(md, segments, a, z, cap=175):
    found=locate(segments,a,z-a)
    if not found:die('window outside pinned image: '+hex(a)+'..'+hex(z))
    result=[]
    for i in md.disasm(found[1],a):
        if i.address+i.size>z or len(result)>=cap:break
        result.append(i)
    return result

def pc_value(i,segments):
    if i.mnemonic.split('.')[0] != 'ldr' or len(i.operands)<2:return None
    op=i.operands[1]
    if op.type!=ARM_OP_MEM or op.mem.base!=ARM_REG_PC or op.mem.index!=0:return None
    cell=((i.address+4)&~3)+op.mem.disp
    val=u32(segments,cell)
    return (cell,val) if val is not None else None

def disp(i,segments):
    line=f'0x{i.address:08X} {i.mnemonic:<9} {i.op_str:<30} bytes={i.bytes.hex(" ")}'
    p=pc_value(i,segments)
    if p:
        cell,val=p
        line+=f' ; PC_CELL=0x{cell:08X} VALUE=0x{val:08X}'
        if val in LITERALS:line+=' '+LITERALS[val]
    return line

def store_info(i):
    if not i.mnemonic.split('.')[0].startswith('str'):return None
    if len(i.operands)<2 or i.operands[1].type!=ARM_OP_MEM:return None
    m=i.operands[1].mem
    return dict(base=i.reg_name(m.base),index=(i.reg_name(m.index) if m.index else None),disp=m.disp)

def check_anchors(md,segments):
    print('\nB. STRICT EXISTING A.68/A.69/A.70 SITE ANCHORS')
    for a in SINKS:
        i=one(md,segments,a)
        if i.mnemonic!='blx' or i.op_str!='r5':die(f'BLX differs at {a:08X}: '+disp(i,segments))
        print('PASS SINK '+disp(i,segments))
    for _,a,_,_ in SITES:
        i=one(md,segments,a)
        if not i.mnemonic.startswith('str'):die(f'candidate writer no longer STR at {a:08X}: '+disp(i,segments))
        info=store_info(i)
        if a==0xF0303A84:
            if not info or info['disp']!=0x1C or info['base']!='r7' or i.op_str.split(',')[0]!='r6':
                die('W5 exact +0x1C write mismatch at 0xF0303A84: '+disp(i,segments))
        print('PASS WRITER '+disp(i,segments))
    for a in (0xF030C060,0xF0312FA8):
        i=one(md,segments,a)
        pv=pc_value(i,segments)
        if pv is None or pv[1]!=TABLE:die('fixed-table base literal differs at '+hex(a))
        print(f'PASS STATIC_ROWS_BASE site=0x{a:08X} literal_cell=0x{pv[0]:08X} value=0x{pv[1]:08X}')

def analysis(md,segments):
    print('\nC. ONLY FIVE PREVIOUSLY NOMINATED WRITER WINDOWS - BOUNDED THUMB')
    for name,site,start,end in SITES:
        print('\n'+'-'*112)
        print(f'{name}; site=0x{site:08X}; window=[0x{start:08X},0x{end:08X}); instruction decode NOT CFG')
        ins=decoded(md,segments,start,end)
        print(f'WINDOW decoded={len(ins)} includes_site={any(i.address==site for i in ins)}')
        for i in ins:
            if i.address > site+8:break # do not disassemble unrelated literal pools after return/target
            print('  '+disp(i,segments))
        i=one(md,segments,site)
        inf=store_info(i)
        print('EXACT_STORE base={base} index={index} disp={disp}; this alone does NOT prove static +0x1C row write'.format(**inf))
        print('STATIC_BASE_LITERAL_IN_WINDOW='+str([(f'0x{x.address:08X}',f'0x{pc_value(x,segments)[0]:08X}') for x in ins if pc_value(x,segments) and pc_value(x,segments)[1]==TABLE]))
    print('\nD. W5 UPSTREAM SOURCE TRACK - REGISTER DEFINITIONS ONLY')
    print('Read r6 (stored value) and r7 (destination base) preceding W5; BL preserves these registers by ABI,')
    print('but branches/loops mean latest *linear* write is NOT proof of executed dataflow.')
    ins=decoded(md,segments,0xF03038E0,0xF0303A86,cap=350)
    print(f'W5 upstream decoded={len(ins)}; W5 present={any(i.address==0xF0303A84 for i in ins)}')
    definitions=[]
    for i in ins:
        if i.address>0xF0303A84: break
        # register write observed by Capstone: includes data-dependent stores and side effects
        try:
            _,writes=i.regs_access()
            target=[i.reg_name(r) for r in writes if i.reg_name(r) in ('r6','r7')]
        except Exception:
            target=[]
        # Conservative fallback for explicit named first operands; not a proof of assignment
        if not target and i.mnemonic.startswith(('ldr','mov','add','sub','adr','pop')) and i.operands:
            o=i.operands[0]
            if o.type==ARM_OP_REG and i.reg_name(o.reg) in ('r6','r7'):
                target=[i.reg_name(o.reg)]
        if target:
            definitions.append((i,target))
    for i,targets in definitions[-28:]:
        print('  DEF? '+','.join(targets)+' '+disp(i,segments))
    print('W5 note: if r7 points to unrelated global/context state, +0x1C is not the fixed-table callback field.')
    print('W5 note: a store through an unknown base or index must remain NOT_PROVEN; do not invent alias.')

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--alice',default='research/f2/work/extracted/altice_alice/alice-py.bin')
    p.add_argument('--zimage',default='research/f2/work/extracted/altice_platform/zimage.bin')
    args=p.parse_args()
    print('S13.5A.80 - STATIC SELECTED ROW +0x1C CALLBACK WRITER PROVENANCE')
    print('STRICTLY OFFLINE; NO USB/COM/PHONE/BROM/DA/FLASH/ERASE/WRITE/PATCH/REPACK')
    print('READ ONLY SHA256-pinned ALICE & ZIMAGE; STDOUT only. No extraction or new ID census.')
    seg=[read_file(Path(args.alice),'ALICE'),read_file(Path(args.zimage),'ZIMAGE')]
    md=Cs(CS_ARCH_ARM,CS_MODE_THUMB+CS_MODE_LITTLE_ENDIAN)
    md.detail=True
    check_anchors(md,seg)
    analysis(md,seg)
    print('\nE. RESULT / PATCH GATE')
    print('A80_OFFLINE_AUDIT_COMPLETED=YES')
    print('NO AUTOMATIC PROOF of field+0x1C producer, runtime target or OK/Select callback semantics.')
    print('NEXT: decide from exact W1-W5 producer/destination evidence only; no repeat of B702/audio/backend.')
    print('PHONE_ACCESSED=NO FIRMWARE_MODIFIED=NO WRITE_AUTHORIZED=NO')
    return 0

if __name__=='__main__':
    sys.exit(main())
