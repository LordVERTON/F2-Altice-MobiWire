#!/usr/bin/env python3
"""S13.5A.135: targeted native-registry root/global producer census; strictly offline.
Does not infer a real launcher, ROM insertion space, or runtime writes from static xrefs.
"""
from __future__ import annotations
import argparse,importlib.util,struct,sys
from pathlib import Path

GLOBAL=0xF007F044
ANCHORED=(0xF032ACE2,0xF02D8876,0xF02D4D56,0xF02F9CD2)

def helper():
 p=Path(__file__).with_name('s13_5a121_boot_postselect_target_cfg_audit.py')
 if not p.is_file(): raise RuntimeError('A121_DEPENDENCY_MISSING')
 s=importlib.util.spec_from_file_location('a121_for_a135',p);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m

def run(a):
 m=helper();rt=a.root
 images=[('ALICE',m.ALICE_BASE,m.assert_canonical(rt/'research/f2/work/extracted/altice_alice/alice-py.bin','ALICE',m.ALICE_SIZE,m.ALICE_SHA)),('ZIMAGE',m.ZIMAGE_BASE,m.assert_canonical(rt/'research/f2/work/extracted/altice_platform/zimage.bin','ZIMAGE',m.ZIMAGE_SIZE,m.ZIMAGE_SHA)),('BOOT_ZIMAGE',m.BOOT_BASE,m.assert_canonical(a.boot,'BOOT_ZIMAGE',m.BOOT_SIZE,m.BOOT_SHA))]
 from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_LITTLE_ENDIAN
 decoder=Cs(CS_ARCH_ARM,CS_MODE_THUMB|CS_MODE_LITTLE_ENDIAN);decoder.detail=True
 out=['S13.5A.135 - NATIVE REGISTRY GLOBAL ROOT PRODUCER CENSUS','STRICTLY_OFFLINE=YES NO_PHONE_NO_PATCH_NO_FLASH=YES',*(f'{n}_GUARD=PASS SHA256={getattr(m, "BOOT_SHA" if n == "BOOT_ZIMAGE" else n + "_SHA")}' for n,_,_ in images),'GLOBAL_ROOT=0xF007F044','NOTE=STATIC_POINTER_XREFS_ONLY_NOT_RUNTIME_WRITES']
 total=0;anchorpass=True
 for name,base,blob in images:
  needle=struct.pack('<I',GLOBAL)
  offsets=[i for i in range(len(blob)-3) if blob[i:i+4]==needle]
  out += ['',f'=== {name} RAW GLOBAL-ROOT POINTER XREFS={len(offsets)} ===']
  for off in offsets:
   cell=base+off; total+=1
   if total>140:raise RuntimeError('TOO_MANY_ROOT_XREFS_RESTRICT_SEARCH')
   out.append(f'CELL=0x{cell:08X} OFFSET=0x{off:X}')
   # Enumerate bounded PC-relative loads near this literal, with limited starts.
   uses=[]
   for start in range(max(0,off-0x180)&~1,off,2):
    for ins in decoder.disasm(blob[start:start+4],base+start,1):
     if ins.mnemonic.lower().split('.')[0] != 'ldr' or '[pc' not in ins.op_str.lower():continue
     import re
     q=re.search(r'\[pc(?:,\s*#(-?0x[0-9a-f]+|-?\d+))?\]',ins.op_str.lower())
     if q:
      disp=int(q.group(1),0) if q.group(1) else 0
      target=(((base+start)+4)&~3)+disp
      if target==cell:uses.append((base+start,ins))
   for pc,ins in uses[-32:]:
    out.append(f'PC_REL_USE=0x{pc:08X} {ins.mnemonic} {ins.op_str}')
    lo=max(0,pc-base-0x14)&~1;hi=min(len(blob),pc-base+0x28)
    for instr in decoder.disasm(blob[lo:hi],base+lo):
     if abs(instr.address-pc)<=0x16:
      out.append(f'  0x{instr.address:08X} {instr.mnemonic} {instr.op_str}')
   out.append(f'POTENTIAL_THUMB_LITERAL_CONSUMERS={len(uses)} (candidate decodes; not CFG provenance)')
 for addr in ANCHORED:
  name,base,blob=next(((n,b,z) for n,b,z in images if b<=addr<b+len(z)),(None,None,None))
  if name is None: anchorpass=False;continue
  ins=next(decoder.disasm(blob[addr-base:addr-base+4],addr,1),None)
  ok=ins is not None and ins.mnemonic.lower().startswith('ldr') and '[pc' in ins.op_str.lower()
  out.append(f'ANCHOR=0x{addr:08X} FOUND={ok} {ins.mnemonic if ins else "NONE"} {ins.op_str if ins else ""}')
  if not ok:anchorpass=False
 if not anchorpass:raise RuntimeError('A134_GLOBAL_ANCHOR_MISMATCH')
 out += ['A134_GLOBAL_ANCHORS=PASS','A135_NATIVE_ROOT_XREF_CENSUS=YES','PRODUCER_WRITES_IDENTIFIED=NO_STATIC_ONLY','REAL_NATIVE_REGISTRY_B702_3_ITEMS=UNPROVEN','PATCH_FLASH_READY=NO','NEXT=REVIEW_NARROW_CANDIDATE_INITIALIZERS_FOR_COUNT_AND_SOURCE_PTR']
 a.out.parent.mkdir(parents=True,exist_ok=True)
 with a.out.open('x',encoding='utf-8') as f:f.write('\n'.join(out)+'\n')
 print('A135_NATIVE_ROOT_XREF_CENSUS=YES');print('A135_REPORT='+str(a.out))

def main():
 p=argparse.ArgumentParser();p.add_argument('--root',type=Path);p.add_argument('--boot',type=Path);p.add_argument('--out',type=Path);p.add_argument('--self-test',action='store_true');a=p.parse_args()
 if a.self_test:
  assert GLOBAL==0xF007F044 and len(ANCHORED)==4
  print('A135_SELF_TEST=PASS')
  if not(a.root or a.boot or a.out):return 0
 if not all((a.root,a.boot,a.out)):p.error('requires --root --boot --out')
 try:run(a);return 0
 except Exception as exc:print('A135_ABORT='+repr(exc),file=sys.stderr);return 1
if __name__=='__main__':sys.exit(main())
