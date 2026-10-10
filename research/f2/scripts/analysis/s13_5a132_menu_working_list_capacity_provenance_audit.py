#!/usr/bin/env python3
"""S13.5A.132: exact read-only provenance audit of B702 working-list builder.
No flashing, no firmware mutation, no real OK/MP3 launch assertions.
"""
from __future__ import annotations
import argparse, importlib.util, struct, sys
from pathlib import Path

ANCHORS={0x10343076:'8864',0x103430D0:'8853',0x103430F0:'806c',0x10340B26:'2064',0x10340C64:'d4f756fc',0x103452C4:'c179'}
VEENERS=(0x102FC35C,0x102FC3EC,0x102FC334,0x102FA0C4,0x102FA0D4)
ALIASES={0x10343050:'WORKING_LIST_CONSTRUCTOR',0x10340ADC:'MENU_REFRESH',0x103452B8:'ITEM_PREDICATE'}

def load_a121():
 p=Path(__file__).with_name('s13_5a121_boot_postselect_target_cfg_audit.py')
 if not p.exists():raise RuntimeError('A121_DEPENDENCY_MISSING')
 sp=importlib.util.spec_from_file_location('a121_for_a132',p);m=importlib.util.module_from_spec(sp);sp.loader.exec_module(m);return m

def block(md,blob,base,start,limit):
 out=[]; pos=start
 for _ in range(limit):
  if not base<=pos<base+len(blob)-4:break
  x=next(md.disasm(blob[pos-base:pos-base+4],pos,1),None)
  if x is None: break
  line='  %08X %-10s %-8s %s'%(pos,x.bytes.hex(),x.mnemonic,x.op_str)
  if x.mnemonic=='ldr' and '[pc,' in x.op_str.lower():
   import re
   mt=re.search(r'\[pc,\s*#(-?0x[0-9a-fA-F]+|-?\d+)\]',x.op_str)
   if mt:
    loc=((pos+4)&~3)+int(mt.group(1),0)
    if base<=loc<=base+len(blob)-4:
     line+='  ; LITERAL_CELL=%08X VALUE=%08X'%(loc,struct.unpack_from('<I',blob,loc-base)[0])
  out.append(line)
  pos+=x.size
  if (x.mnemonic=='pop' and 'pc' in x.op_str) or (x.mnemonic=='bx' and x.op_str=='lr'):break
 return out

def run(a):
 m=load_a121();root=a.root
 alice=m.assert_canonical(root/'research/f2/work/extracted/altice_alice/alice-py.bin','ALICE',m.ALICE_SIZE,m.ALICE_SHA)
 z=m.assert_canonical(root/'research/f2/work/extracted/altice_platform/zimage.bin','ZIMAGE',m.ZIMAGE_SIZE,m.ZIMAGE_SHA)
 boot=m.assert_canonical(a.boot,'BOOT_ZIMAGE',m.BOOT_SIZE,m.BOOT_SHA)
 m.check_inputs(alice,boot,z)
 for addr,raw in ANCHORS.items():
  if alice[addr-m.ALICE_BASE:addr-m.ALICE_BASE+len(bytes.fromhex(raw))]!=bytes.fromhex(raw):raise RuntimeError('ANCHOR_MISMATCH_%08X'%addr)
 from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_ARM, CS_MODE_LITTLE_ENDIAN
 md=Cs(CS_ARCH_ARM,CS_MODE_THUMB|CS_MODE_LITTLE_ENDIAN);md.detail=True
 arm=Cs(CS_ARCH_ARM,CS_MODE_ARM|CS_MODE_LITTLE_ENDIAN);arm.detail=True
 o=['S13.5A.132 — B702 WORKING LIST ORIGIN / CAPACITY / ALIAS BOUNDARY',
    'STRICTLY_OFFLINE=YES NO_USB_COM_PHONE_PATCH_FLASH_REPACK=YES',
    'ALICE_GUARD=PASS SHA256='+m.ALICE_SHA,'ZIMAGE_GUARD=PASS SHA256='+m.ZIMAGE_SHA,
    'BOOT_ZIMAGE_GUARD=PASS SHA256='+m.BOOT_SHA,'A131_WORKING_LIST_ANCHORS=PASS',
    'IMPORTANT=RAM_PROVENANCE_CAPACITY_AND_3_ITEM_INSERTION_NOT_YET_PROVEN',
    '=== A. GLOBAL LIST BASE AND BUILDER SOURCE ===',
    'GLOBAL_POINTER_STORAGE_ADDRESS=0xF00B1C38 (outside canonical ALICE/BOOT/ZIMAGE; runtime contents not present)',
    'WORKING_LIST_BUILDER=0x10343050','LIST_COUNT_WRITER=0x10343076 descriptor+0x48',
    'U16_ID_WRITER=0x103430D0',
    'ITEM_FLAGS_WRITER=0x103430EA',
    'REFRESH_LIST_PTR_WRITER=0x10340B26 descriptor+0x40',
    'PREDICATE_SCAN=0x103452B8 descriptor+0x60 and 50 four-byte records']
 for key,addr,n in [('BUILDER_PROLOGUE',0x10343050,24),('BUILDER_LOOP',0x10343078,63),('REFRESH_ALLOC',0x10340AFC,25),('REFRESH_POINTER_ASSIGN',0x10340B10,13),('PREDICATE_RECORD_SCAN',0x103452B8,28)]:
  o+=['','=== %s ==='%key]+block(md,alice,m.ALICE_BASE,addr,n)
 o+=['','=== B. ALICE ARM VENEERS FOR THE FIVE BUILDER HELPERS ===']
 for v in VEENERS:
  raw=alice[v-m.ALICE_BASE:v-m.ALICE_BASE+8];i=next(arm.disasm(raw[:4],v,1),None)
  lit=struct.unpack_from('<I',raw,4)[0]
  if raw[:4]!=bytes.fromhex('04f01fe5'):raise RuntimeError('UNEXPECTED_ARM_VENEER_%08X'%v)
  dest=lit&~1;area=('ALICE' if m.ALICE_BASE<=dest<m.ALICE_BASE+len(alice) else ('BOOT' if m.BOOT_BASE<=dest<m.BOOT_BASE+len(boot) else ('ZIMAGE' if m.ZIMAGE_BASE<=dest<m.ZIMAGE_BASE+len(z) else 'UNMAPPED')))
  o.append('VENEER=0x%08X INSN=%s LITERAL=0x%08X THUMB_TARGET=0x%08X AREA=%s'%(v,i.mnemonic+' '+i.op_str if i else 'INVALID',lit,dest,area))
  if area=='ZIMAGE':o+=block(md,z,m.ZIMAGE_BASE,dest,18)
  if area=='BOOT':o+=block(md,boot,m.BOOT_BASE,dest,18)
 o+=['','=== C. EVIDENCE BOUNDARIES / PATCH GATES ===','A132_BUILDER_PROVENANCE_REPORTED=YES',
     'WORKING_LIST_STORAGE_CAPACITY=UNKNOWN_UNTIL_ALLOCATION_AND_COUNT_PROVEN',
     'B702_THIRD_ITEM_IN_RAM_SAFE=UNPROVEN','B702_THIRD_ITEM_IN_ROM_SAFE=NO_KNOWN_ADJACENT_COLLISION',
     'REAL_OK_TO_IMAGE_87ED=UNPROVEN','REAL_OK_TO_AUDIO_8928=UNPROVEN',
     'PATCH_FLASH_READY=NO',
     'NEXT=TRACE_COUNT_AND_LIST_BUFFER_ORIGIN_FOR_REAL_3_ITEM_CAPACITY;THEN_OFFLINE_PATCH_PROTOTYPE']
 a.out.parent.mkdir(parents=True,exist_ok=True)
 with a.out.open('x',encoding='utf-8',newline='\n') as f:f.write('\n'.join(o)+'\n')
 print('A132_BUILDER_PROVENANCE_REPORTED=YES');print('A132_REPORT_CREATED='+str(a.out.resolve()))

def main():
 p=argparse.ArgumentParser(description=__doc__)
 p.add_argument('--self-test',action='store_true');p.add_argument('--root',type=Path);p.add_argument('--boot',type=Path);p.add_argument('--out',type=Path)
 a=p.parse_args()
 if a.self_test:
  assert len(ANCHORS)==6 and len(VEENERS)==5
  assert (0x103430D0-math_base()) >=0
  print('A132_SELF_TEST=PASS_ANCHORS_AND_TARGETS')
  if not(a.root or a.boot or a.out):return 0
 if not all((a.root,a.boot,a.out)):p.error('--root --boot --out required')
 try:run(a);return 0
 except Exception as e:print('A132_ABORT=%s: %s'%(type(e).__name__,e),file=sys.stderr);return 1

def math_base():return 0x1024EC00
if __name__=='__main__':sys.exit(main())
