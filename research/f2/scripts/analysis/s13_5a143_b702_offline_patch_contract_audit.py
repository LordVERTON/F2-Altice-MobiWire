#!/usr/bin/env python3
"""S13.5A.143: B702 patch contract and exhaustive existing pool ownership.

READ ONLY: canonical ALICE, BOOT_ZIMAGE, ZIMAGE are SHA-pinned. Output is
one exclusive TXT report. No patch binaries, no ROM write, no device access.
The audit does not identify a safe relocation address or prove UI dispatch.
"""
from __future__ import annotations
import argparse
import hashlib
import struct
import sys
from pathlib import Path

IMAGES = {
    'ALICE': (0x1024EC00, 0x157BB4, '7246242b67afae0d13104452bc3257827cb778119b54e7a26fb7fb55993697ea'),
    'ZIMAGE': (0xF023CA50, 0x185E98, '85fba8c8ae8161e4c1f8ced7983ec30d48c54ab10e51c69fcdfb900aca220954'),
    'BOOT_ZIMAGE': (0xF01F19E4, 0x4B06C, 'aa070292e9c1685eddb12080b3f0bbca763102adaf085016b4e503a3930b4c3e'),
}
RECORDS = 0xF0378760
DESCRIPTOR = 0xF037C08C
RANGES = 0xF037BF54
TOTAL = 895
IDX_B702, IDX_B703, IDX_AUDIO = 884, 885, 490
CHILDREN = (0x8569,0x87ED)
AUDIO = 0x8928

def require(ok, msg):
    if not ok: raise RuntimeError(msg)

def load(path: Path, label: str):
    base,size,sha=IMAGES[label]
    require(path.is_file(), f'MISSING_{label}={path}')
    raw=path.read_bytes()
    require(len(raw)==size and hashlib.sha256(raw).hexdigest()==sha, f'{label}_SIZE_SHA_MISMATCH')
    return raw

def read(raw, address, n):
    start=address-IMAGES['ZIMAGE'][0]
    require(start>=0 and n>=0 and start+n<=len(raw), f'OUT_OF_ROM_READ=0x{address:08X}+{n}')
    return raw[start:start+n]

def u16(raw,p):return struct.unpack('<H',read(raw,p,2))[0]
def u32(raw,p):return struct.unpack('<I',read(raw,p,4))[0]
def record(raw,idx):
    p=RECORDS+idx*16
    return (p,u16(raw,p),u16(raw,p+2),u32(raw,p+12))

def intersection(a,b,c,d):return a<d and c<b

def run(a):
    alice=load(a.root/'research/f2/work/extracted/altice_alice/alice-py.bin','ALICE')
    boot=load(a.boot,'BOOT_ZIMAGE')
    zimage=load(a.root/'research/f2/work/extracted/altice_platform/zimage.bin','ZIMAGE')
    del alice,boot
    require(u32(zimage,DESCRIPTOR)==RECORDS,'DESCRIPTOR_RECORDS_MISMATCH')
    require(u32(zimage,DESCRIPTOR+4)==RANGES,'DESCRIPTOR_RANGES_MISMATCH')
    require(u16(zimage,DESCRIPTOR+8)==52,'DESCRIPTOR_RANGE_COUNT_MISMATCH')
    bp,parent,count,ptr=record(zimage,IDX_B702)
    ap,aparent,acount,aptr=record(zimage,IDX_AUDIO)
    naddr,nparent,ncount,nptr=record(zimage,IDX_B703)
    require((bp,parent,count,ptr)==(0xF037BEA0,0xB709,2,0xF0378720),'B702_RECORD_MISMATCH')
    require((ap,aparent)==(0xF037A600,0xB702),'AUDIO_PARENT_MISMATCH')
    require(tuple(struct.unpack('<HH',read(zimage,ptr,4)))==CHILDREN,'B702_CHILDREN_MISMATCH')
    next_halfword=u16(zimage,ptr+4)
    require(next_halfword==0xA07B,'B703_ADJACENCY_VALUE_MISMATCH')
    lines=['S13.5A.143 — B702 OFFLINE PATCH CONTRACT / POOL OWNERSHIP',
      'STRICTLY_OFFLINE=YES NO_USB_COM_PHONE_PATCH_FLASH_REPACK=YES',
      'OUTPUT_REPORT_ONLY=YES NO_PATCH_BYTES_EMITTED=YES',
      'ALICE_GUARD=PASS','ZIMAGE_GUARD=PASS','BOOT_ZIMAGE_GUARD=PASS',
      'A111_B702_STATIC_ANCHORS=PASS',
      f'DESCRIPTOR=0x{DESCRIPTOR:08X} RECORDS=0x{RECORDS:08X} RANGES=0x{RANGES:08X} TOTAL={TOTAL}',
      f'B702_RECORD=0x{bp:08X} PARENT=0x{parent:04X} COUNT={count} PTR=0x{ptr:08X}',
      f'AUDIO_RECORD=0x{ap:08X} PARENT=0x{aparent:04X} COUNT={acount} PTR=0x{aptr:08X}',
      f'B703_RECORD=0x{naddr:08X} COUNT={ncount} PTR=0x{nptr:08X} NEXT_U16=0x{next_halfword:04X}',
      'ORIGINAL_CHILDREN=0x8569,0x87ED',
      'DESIRED_CHILDREN_SYNTHETIC=0x8569,0x87ED,0x8928',
      'REQUIRED_LOGICAL_CHANGES=B702_COUNT_2_TO_3;B702_CHILD_PTR_TO_VERIFIED_6BYTE_POOL;NEW_POOL_CONTENT',
      'DO_NOT_APPEND_AT_ORIGINAL_PTR=YES',
      '=== ALL STATIC CHILD-ARRAY OWNERS OF OLD AND WOULD-BE APPEND ===']
    oldowners=[]; appendowners=[]; invalid=[]; occupied=[]
    for i in range(TOTAL):
        rp,par,c,p=record(zimage,i)
        if not c: continue
        end=p+c*2
        if p&1 or p<IMAGES['ZIMAGE'][0] or end>IMAGES['ZIMAGE'][0]+len(zimage) or end<p:
            invalid.append((i,c,p));continue
        occupied.append((p,end,i))
        if i!=IDX_B702 and intersection(p,end,ptr,ptr+4):oldowners.append((i,p,end))
        if i!=IDX_B702 and intersection(p,end,ptr+4,ptr+6):appendowners.append((i,p,end))
    lines += [f'VALID_STATIC_ARRAYS={len(occupied)}',f'UNCLASSIFIED_NONEMPTY_ARRAYS={len(invalid)}',
       f'OLD_B702_ALIAS_OWNERS={len(oldowners)}',f'IN_PLACE_APPEND_COLLISION_OWNERS={len(appendowners)}']
    for i,p,e in oldowners[:40]:lines.append(f'OLD_ALIAS INDEX={i} [0x{p:08X},0x{e:08X})')
    for i,p,e in appendowners[:40]:lines.append(f'APPEND_OWNER INDEX={i} [0x{p:08X},0x{e:08X})')
    for i,c,p in invalid[:20]:lines.append(f'UNCLASSIFIED INDEX={i} COUNT={c} PTR=0x{p:08X}')
    lines += ['=== PATCH SAFETY DECISION ===',
       'IN_PLACE_COUNT_ONLY_SAFE=NO',
       'RELOCATION_DESTINATION_VERIFIED=NO',
       'ROM_FREE_SPACE_VERIFIED=NO',
       'RELOCATION_REFERENCES_COMPLETE=NO',
       'RUNTIME_F007F044_ALIASES_STATIC_RECORDS=UNPROVEN',
       'UI_OK_TO_AUDIO_LAUNCHER=UNPROVEN',
       'FLASH_LAYOUT_CRC_AND_ROLLBACK_VALIDATED=NO',
       'OFFLINE_PATCH_PLAN_REPORTED=YES',
       'PATCH_FLASH_READY=NO',
       'NEXT=ESTABLISH_VERIFIED_6BYTE_DESTINATION_AND_POINTER_REBASE_IN_OFFLINE_IMAGE;THEN_TEST_SYNTHETIC_UI_DISPATCH']
    a.out.parent.mkdir(parents=True,exist_ok=True)
    with a.out.open('x',encoding='utf-8') as f:f.write('\n'.join(lines)+'\n')
    print('A143_REPORT='+str(a.out));print('OFFLINE_PATCH_PLAN_REPORTED=YES')

def main():
    p=argparse.ArgumentParser();p.add_argument('--root',type=Path);p.add_argument('--boot',type=Path);p.add_argument('--out',type=Path);p.add_argument('--self-test',action='store_true');a=p.parse_args()
    if a.self_test:
        require(RECORDS+IDX_B702*16==0xF037BEA0,'A143_SELFTEST_RECORD_INDEX')
        require(RECORDS+IDX_AUDIO*16==0xF037A600,'A143_SELFTEST_AUDIO_INDEX')
        require(intersection(4,6,4,8) and not intersection(2,4,4,8),'A143_SELFTEST_INTERVAL')
        print('A143_SELF_TEST=PASS')
        if not any((a.root,a.boot,a.out)):return 0
    if not all((a.root,a.boot,a.out)):p.error('requires --root --boot --out')
    try:run(a);return 0
    except Exception as e:print('A143_ABORT='+repr(e),file=sys.stderr);return 1
if __name__=='__main__':sys.exit(main())
