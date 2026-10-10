#!/usr/bin/env python3
"""S13.5A.133: Verify ZIMAGE copy-loop bound and ALICE working-list allocation layout. Offline only."""
from __future__ import annotations
import argparse, importlib.util, struct, sys
from pathlib import Path

ANCHORS={0x10340B0C:'ff20',0x10340B0E:'c130',0x10340B10:'bbf78ced',
         0x10340B20:'3868',0x10340B22:'ff30',0x10340B24:'0130',0x10340B26:'2064',
         0x10343064:'ff31',0x10343066:'0131',0x10343068:'b9f778e9',
         0x1034306E:'b9f7bee9',0x10343076:'8864',0x103430D0:'8853',0x103430EA:'0170'}
A_BASE=0x1024EC00; Z_BASE=0xF023CA50

def read_dep():
 p=Path(__file__).with_name('s13_5a121_boot_postselect_target_cfg_audit.py')
 if not p.exists():raise RuntimeError('MISSING_A121_DEPENDENCY')
 spec=importlib.util.spec_from_file_location('a121_for_a133',p);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m

def linear(md,blob,base,addr,size):
 seg=blob[addr-base:addr-base+size]
 if len(seg)!=size:raise RuntimeError('DECODE_OUT_OF_RANGE')
 ins=list(md.disasm(seg,addr));return ['%08X %-10s %-10s %s'%(i.address,i.bytes.hex(),i.mnemonic,i.op_str) for i in ins]

def go(opts):
 a=read_dep();root=opts.root
 alice=a.assert_canonical(root/'research/f2/work/extracted/altice_alice/alice-py.bin','ALICE',a.ALICE_SIZE,a.ALICE_SHA)
 z=a.assert_canonical(root/'research/f2/work/extracted/altice_platform/zimage.bin','ZIMAGE',a.ZIMAGE_SIZE,a.ZIMAGE_SHA)
 boot=a.assert_canonical(opts.boot,'BOOT_ZIMAGE',a.BOOT_SIZE,a.BOOT_SHA)
 a.check_inputs(alice,boot,z)
 for addr,expected in ANCHORS.items():
  raw=bytes.fromhex(expected)
  if alice[addr-A_BASE:addr-A_BASE+len(raw)]!=raw:raise RuntimeError('ANCHOR_MISMATCH_%08X'%addr)
 # Resolve allocator veneer without assumptions on external allocator semantics.
 veneer=0x102FC62C; v=alice[veneer-A_BASE:veneer-A_BASE+8]
 if v[:4]!=bytes.fromhex('04f01fe5'):raise RuntimeError('ALLOC_VENEER_NOT_ARM_LDR_PC')
 ptr=struct.unpack_from('<I',v,4)[0];target=ptr&~1
 if not Z_BASE<=target<Z_BASE+len(z):raise RuntimeError('ALLOC_TARGET_NOT_IN_ZIMAGE')
 from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_LITTLE_ENDIAN
 md=Cs(CS_ARCH_ARM,CS_MODE_THUMB|CS_MODE_LITTLE_ENDIAN)
 out=['S13.5A.133 — WORKING BUFFER LAYOUT / COPY BOUNDARY',
  'STRICTLY_OFFLINE=YES NO_PHONE_USB_COM_IMAGE_PATCH_FLASH=YES',
  'ALICE_GUARD=PASS SHA256='+a.ALICE_SHA,'ZIMAGE_GUARD=PASS SHA256='+a.ZIMAGE_SHA,
  'BOOT_ZIMAGE_GUARD=PASS SHA256='+a.BOOT_SHA,'A132_LAYOUT_ANCHORS=PASS',
  'ALLOCATOR_CALL=0x10340B10 ARG_R0_STATIC=0x1C0 (0xFF+0xC1)',
  'WORKING_LIST_OFFSET=0x100; ID_U16_AREA=[+0x100,+0x180); FLAGS_AT=+0x180',
  'STATIC_64_U16_SLOTS_BEFORE_FLAG_AREA=YES (capacity is a layout bound, not a proven count)',
  'ALLOCATION_CAPACITY_REAL=UNPROVEN (depends on allocator contract/return)',
  'LIST_COUNT_ACTUAL=DERIVED_BY_0xF02D8870_THROUGH_NATIVE_REGISTRY',
  'COPY_SOURCE_REGISTRY=0xF007F044;REGISTRY_CONTENT=NOT_PRESENT_IN_CANONICAL_IMAGES',
  'ALLOC_VENEER=0x%08X PTR=0x%08X TARGET_THUMB=0x%08X'%(veneer,ptr,target),
  '', '=== A. ZIMAGE COPY BUILDER (0xF032ACDC) ===']
 out+=linear(md,z,Z_BASE,0xF032ACDC,0x58)
 out+=['','=== B. NATIVE COUNT (0xF02D8870) ===']+linear(md,z,Z_BASE,0xF02D8870,0x1C)
 out+=['','=== C. ALLOCATOR ENTRY (resolved ARM veneer 0x102FC62C) ===']+linear(md,z,Z_BASE,target,0x74)
 out+=['','=== D. ALICE BUFFER USE AND COUNT ===']
 for addr,n in ((0x10340B0C,0x30),(0x10343060,0x1A),(0x103430C8,0x2E)):
  out+=['WINDOW=0x%08X'%addr]+linear(md,alice,A_BASE,addr,n)
 out+=['','A133_LAYOUT_AND_COPY_BOUNDARY_REPORTED=YES',
       'THREE_ITEM_RAM_INSERTION_SAFE=UNPROVEN',
       'REAL_UI_OK_LEAF_DISPATCH=UNPROVEN','PATCH_FLASH_READY=NO',
       'NEXT=CHECK_COPY_LOOP_END_AND_SOURCE_COUNT_THEN_DESIGN_SHADOW_INSERTION_HARNESS_WITH_EXACT_GUARDS']
 opts.out.parent.mkdir(parents=True,exist_ok=True)
 with opts.out.open('x',encoding='utf-8') as f:f.write('\n'.join(out)+'\n')
 print('A133_REPORT_CREATED='+str(opts.out));print('A133_LAYOUT_AND_COPY_BOUNDARY_REPORTED=YES')

def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--root',type=Path);p.add_argument('--boot',type=Path);p.add_argument('--out',type=Path);p.add_argument('--self-test',action='store_true');o=p.parse_args()
 if o.self_test:
  assert 0x1C0==0xFF+0xC1 and 0x180-0x100==64*2
  assert len(ANCHORS)==14
  print('A133_SELF_TEST=PASS')
  if not(o.root or o.boot or o.out):return 0
 if not all((o.root,o.boot,o.out)):p.error('--root --boot --out required')
 try:go(o);return 0
 except Exception as e:print('A133_ABORT=%s: %s'%(type(e).__name__,e),file=sys.stderr);return 1
if __name__=='__main__':sys.exit(main())
