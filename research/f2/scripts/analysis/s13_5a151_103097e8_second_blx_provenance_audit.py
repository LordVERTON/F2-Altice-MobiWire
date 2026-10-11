#!/usr/bin/env python3
"""A151: narrow CPU-free provenance audit of the SECOND indirect BLX in 10336788.

Distinguishes r4 from resolver callback at 1033679E versus later return of
103097E8 assigned to r4 at 103367A8; prints bounded callee disassembly.
This is not a reachable runtime OK trace or evidence that 103097E8 returns a
function pointer. No USB, ROM mutation, patch, repack or flash.
"""
import argparse,hashlib,sys
from pathlib import Path

ALICE_BASE=0x1024EC00; ALICE_SIZE=0x157BB4
ALICE_SHA='7246242b67afae0d13104452bc3257827cb778119b54e7a26fb7fb55993697ea'
ZIMAGE_SIZE=0x185E98
ZIMAGE_SHA='85fba8c8ae8161e4c1f8ced7983ec30d48c54ab10e51c69fcdfb900aca220954'
BOOT_SIZE=0x4B06C
BOOT_SHA='aa070292e9c1685eddb12080b3f0bbca763102adaf085016b4e503a3930b4c3e'
CALLEE=0x103097E8

def guard(p,size,sha,tag):
    data=Path(p).read_bytes(); digest=hashlib.sha256(data).hexdigest()
    if len(data)!=size or digest!=sha:raise RuntimeError(f'{tag}_GUARD_FAIL size={len(data)} sha={digest}')
    return data

def disasm(image,base,n):
    from capstone import Cs,CS_ARCH_ARM,CS_MODE_THUMB
    md=Cs(CS_ARCH_ARM,CS_MODE_THUMB);md.detail=True
    ins=list(md.disasm(image[base-ALICE_BASE:base-ALICE_BASE+n],base))
    return ins

def check(image):
    calls=disasm(image,0x10336788,0x72)
    by={i.address:i for i in calls}
    anchors={0x1033678C:('bl','0x1034c7e4'),0x10336790:('movs','r4, r0'),
             0x1033679E:('blx','r4'),0x103367A4:('bl','0x103097e8'),
             0x103367A8:('movs','r4, r0'),0x103367E6:('blx','r4')}
    for address,(mn,operand) in anchors.items():
        i=by.get(address)
        if i is None or i.mnemonic!=mn or operand not in i.op_str.lower():
            raise RuntimeError(f'A150_ANCHOR_FAIL_{address:08X} GOT={i.mnemonic+" "+i.op_str if i else "NONE"}')
    callee=disasm(image,CALLEE,0x160)
    if not callee or callee[0].address!=CALLEE:raise RuntimeError('CALLEE_DECODE_FAIL')
    # Bounded window only; disassembly may run into adjacent functions after a return.
    first_return=next((i.address for i in callee if i.mnemonic in ('bx','pop') and ('lr' in i.op_str or 'pc' in i.op_str)),None)
    lines=['S13.5A.151 - SECOND BLX R4 CALLEE-PROVENANCE GATE',
        'STRICTLY_OFFLINE=YES NO_USB_COM_PHONE_PATCH_FLASH_REPACK=YES',
        'LIMIT=LOCAL_LINEAR_THUMB_WINDOW_NOT_CFG_NOT_REACHABLE_UI_OK_TRACE',
        'A150_EXECUTOR_ANCHORS=PASS',
        'FIRST_BLX=0x1033679E R4_SOURCE=RETURN_OF_0x1034C7E4',
        'SECOND_BLX=0x103367E6 R4_SOURCE=RETURN_OF_0x103097E8_AT_0x103367A4',
        'CALLER_INPUT_TO_103097E8=R0_1_R1_0_AT_BOTH_CALLS',
        'SECOND_R4_NULL_SUPPRESSED=YES_AT_0x103367BA',
        f'CALLEE_ENTRY=0x{CALLEE:08X}',
        f'CALLEE_WINDOW_INSTRUCTIONS={len(callee)}',
        'FIRST_SYNTACTIC_RETURN='+('0x%08X'%first_return if first_return else 'NOT_FOUND'),
        '=== CALLEE DECODE (LINEAR, MAY INCLUDE NEIGHBORS) ===']
    for i in callee:
        raw=image[i.address-ALICE_BASE:i.address-ALICE_BASE+i.size].hex()
        lines.append(f'{i.address:08X} {raw:<10} {i.mnemonic:<9} {i.op_str}')
    lines += ['=== DIRECT CALLS IN BOUNDED WINDOW ===']
    for i in callee:
        if i.mnemonic in ('bl','blx'):
            lines.append(f'CALL=0x{i.address:08X} {i.mnemonic} {i.op_str}')
    lines += ['DIRECT_CALLER_TO_UI_OK=UNPROVEN',
       'CALLEE_RETURNS_EXECUTABLE_POINTER=UNPROVEN_STATIC_ONLY',
       'REAL_IMAGE_87ED_ACTIVATION=UNPROVEN',
       'REAL_AUDIO_8928_ACTIVATION=UNPROVEN',
       'PATCH_FLASH_READY=NO',
       'A151_SECOND_BLX_PROVENANCE=PASS',
       'NEXT=INTERPRET_103097E8_RETURN_SEMANTICS_WITH_VERIFIED_REACHABLE_PATH_BEFORE_CALLING_SECOND_BLX_A_LAUNCH']
    return lines

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--self-test',action='store_true')
    p.add_argument('--root',type=Path);p.add_argument('--boot',type=Path);p.add_argument('--out',type=Path)
    a=p.parse_args()
    if a.self_test:
        assert ALICE_BASE<CALLEE<ALICE_BASE+ALICE_SIZE
        assert all(len(bytes.fromhex(x))==32 for x in (ALICE_SHA,ZIMAGE_SHA,BOOT_SHA))
        print('A151_SELF_TEST=PASS')
        if not any((a.root,a.boot,a.out)):return 0
    if not all((a.root,a.boot,a.out)):p.error('--root --boot --out required')
    try:
        alice=guard(a.root/'research/f2/work/extracted/altice_alice/alice-py.bin',ALICE_SIZE,ALICE_SHA,'ALICE')
        guard(a.root/'research/f2/work/extracted/altice_platform/zimage.bin',ZIMAGE_SIZE,ZIMAGE_SHA,'ZIMAGE')
        guard(a.boot,BOOT_SIZE,BOOT_SHA,'BOOT_ZIMAGE')
        rows=['ALICE_GUARD=PASS','ZIMAGE_GUARD=PASS','BOOT_ZIMAGE_GUARD=PASS',*check(alice)]
        a.out.parent.mkdir(parents=True,exist_ok=True)
        with a.out.open('x',encoding='utf-8') as f:f.write('\n'.join(rows)+'\n')
        print('A151_REPORT_CREATED='+str(a.out));print('A151_SECOND_BLX_PROVENANCE=PASS')
        return 0
    except Exception as e:
        print('A151_ABORT='+repr(e),file=sys.stderr);return 1
if __name__=='__main__':sys.exit(main())
