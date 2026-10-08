#!/usr/bin/env python3
"""S13.5A.79: examine ONLY two selected-row callback callsites.

Offline SHA-pinned file reads. No hardware access, patching, export or file writes.
The two callsites are historical candidates, NOT established menu OK/Select dispatch.
"""
import argparse
import hashlib
from pathlib import Path
import sys

try:
    from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_LITTLE_ENDIAN
    from capstone.arm import ARM_OP_MEM, ARM_OP_IMM, ARM_REG_PC
except ImportError as exc:
    raise SystemExit('ABORT: Python capstone is required in the existing mtkclient venv: '+str(exc))

IMAGES = {
 'ALICE': (0x1024EC00, 0x157BB4, '7246242b67afae0d13104452bc3257827cb778119b54e7a26fb7fb55993697ea'),
 'ZIMAGE': (0xF023CA50, 0x185E98, '85fba8c8ae8161e4c1f8ced7983ec30d48c54ab10e51c69fcdfb900aca220954'),
}
SINKS = [
 ('SINK_A_F030C0A0', 0xF030C0A0),
 ('SINK_B_F0312FD2', 0xF0312FD2),
]
INTERESTING_LITERALS = {
 0xF00B9A30:'STATIC_SELECTED_ROW_TABLE',
 0xF004C5CC:'SELECTED_CONTEXT',
 0xF004C5B4:'DYNAMIC_BUFFER_PTR_SLOT',
 0xF009343C:'GRAPHICS_OR_RESOURCE_CALLBACK_SLOT_CLOSED_A78',
 0xF00B97F8:'STATIC_CONTEXT',
}

def die(s): raise SystemExit('ABORT: '+s)

def resolve_default(p, fallback=None):
    a=Path(p)
    if a.is_file(): return a
    if fallback and Path(fallback).is_file(): return Path(fallback)
    die('canonical file absent: '+str(a))

def read_guard(path, kind):
    base,size,expected=IMAGES[kind]
    raw=path.read_bytes()
    digest=hashlib.sha256(raw).hexdigest()
    good=len(raw)==size and digest==expected
    print('%s: file=%s bytes=0x%X sha256=%s GUARD=%s'%(kind,str(path),len(raw),digest,'PASS' if good else 'FAIL'))
    if not good: die('canonical '+kind+' file mismatch')
    return base,raw

def get(segments,addr,size):
    for label,base,raw in segments:
        off=addr-base
        if 0<=off and off+size<=len(raw):
            return (label,raw[off:off+size])
    return None

def uint32(segments,a):
    got=get(segments,a,4)
    return int.from_bytes(got[1],'little') if got else None

def fmt(i, segments):
    msg=f'{i.address:08X}: {i.mnemonic:<10} {i.op_str:<29} bytes={i.bytes.hex(" ")}'
    try:
        if i.mnemonic.lower().split('.')[0].startswith('ldr') and len(i.operands)>=2:
            m=i.operands[1]
            if m.type==ARM_OP_MEM and m.mem.base==ARM_REG_PC and m.mem.index==0:
                cell=((i.address+4)&~3)+m.mem.disp
                data=uint32(segments,cell)
                if data is not None:
                    msg+=f' ; PC_CELL={cell:08X} U32={data:08X}'
                    if data in INTERESTING_LITERALS: msg+=' '+INTERESTING_LITERALS[data]
        if i.mnemonic.lower().split('.')[0] in ('bl','blx','b') and i.operands and i.operands[0].type==ARM_OP_IMM:
            dst=i.operands[0].imm & 0xFFFFFFFF
            where=get(segments,dst & ~1,2)
            msg+=' ; DIRECT_TARGET_REGION='+ (where[0] if where else 'OUTSIDE_PINNED')
    except Exception as exc:
        msg+=' ; DECODER_NOTE='+str(exc)[:90]
    return msg

def decode(md,segments,start,end,cap=140):
    got=get(segments,start,end-start)
    if not got: return []
    out=[]
    for i in md.disasm(got[1],start):
        if i.address+i.size>end or len(out)>=cap:break
        out.append(i)
    return out

def run_site(md,segments,label,site):
    print('\n'+'='*116)
    print(label, f'0x{site:08X}', 'NOT_CERTIFIED_AS_OK_SELECT')
    print('='*116)
    raw=get(segments,site,12)
    if raw is None:die('sink outside pinned image at '+hex(site))
    print('EXACT_SITE_BYTES='+raw[1].hex(' '))
    spot=decode(md,segments,site,site+12,6)
    for i in spot:print('  EXACT '+fmt(i,segments))
    print('CAUTION: actual BLX location may be before/after this historical site label.')
    best=[]
    for phase in (0,2):
        start=site-0x7C+phase
        inst=decode(md,segments,start,site+0x2C)
        inear=[i for i in inst if site-0x3C<=i.address<=site+0x1C]
        calls=[i for i in inear if i.mnemonic.lower().startswith(('blx','bx'))]
        ldr_rows=[i for i in inear if i.mnemonic.lower().startswith('ldr') and '0x1c' in i.op_str.lower()]
        literals=[]
        for i in inear:
            if i.mnemonic.lower().split('.')[0]!='ldr' or len(i.operands)<2:continue
            m=i.operands[1]
            if m.type!=ARM_OP_MEM or m.mem.base!=ARM_REG_PC or m.mem.index!=0:continue
            cell=((i.address+4)&~3)+m.mem.disp
            v=uint32(segments,cell)
            if v in INTERESTING_LITERALS:literals.append((i.address,v))
        print(f'\nCANDIDATE_PHASE={phase} start=0x{start:X} decoded={len(inst)} nearest_blx/bx={len(calls)} nearest_record_field_1C={len(ldr_rows)} known_literal_loads={len(literals)}')
        for i in inear: print('  '+fmt(i,segments))
        if len(calls)+len(ldr_rows):
            best.append((phase,[i.address for i in calls],[i.address for i in ldr_rows],literals))
    print('SITE_SUMMARY CANDIDATE_PHASES='+repr(best))
    print('IMPORTANT: linear slices are NOT a verified CFG, branches and literal pools can disrupt apparent dataflow.')

def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--alice',default='research/f2/work/extracted/altice_alice/alice-py.bin')
    ap.add_argument('--zimage',default='research/f2/work/extracted/altice_platform/zimage.bin')
    a=ap.parse_args()
    print('S13.5A.79 - TWO SELECTED-ROW CALLBACK SINK ABI DIFFERENTIAL')
    print('STRICTLY OFFLINE: no USB/COM/phone/BROM/DA/readflash/writeflash/erase/patch/repack; stdout only')
    print('Only ZIMAGE selected index + static row callback candidates; NO menu census and NO graphics detour.')
    alice=resolve_default(a.alice)
    zim=resolve_default(a.zimage)
    segments=[]
    for name,path in (('ALICE',alice),('ZIMAGE',zim)):
        base,raw=read_guard(path,name)
        segments.append((name,base,raw))
    md=Cs(CS_ARCH_ARM,CS_MODE_THUMB+CS_MODE_LITTLE_ENDIAN)
    md.detail=True
    for label,site in SINKS:run_site(md,segments,label,site)
    print('\nDECISION: determine whether any actual selected-row +0x1C BLX has genuine MENU OK/SELECT semantics.')
    print('NO CLAIM: runtime callback target, audio app 0x8928, executable menu route or firmware patch.')
    print('A79_OFFLINE_COMPLETE=YES; PHONE_ACCESSED=NO; FLASH_MODIFIED=NO')
    return 0
if __name__=='__main__':
    sys.exit(main())
