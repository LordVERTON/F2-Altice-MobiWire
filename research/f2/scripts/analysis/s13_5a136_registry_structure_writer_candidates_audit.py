#!/usr/bin/env python3
"""A136: targeted ROM-native registry writer candidate CFG, strict read-only."""
from __future__ import annotations
import argparse, hashlib, importlib.util, struct, sys
from collections import deque
from pathlib import Path

CANDIDATES=((0xF02FBC24,'REGISTRY_MUTATOR_NEIGHBOR'),(0xF02D53DC,'NATIVE_RECORD_ITERATOR'),(0xF02F9CE4,'NATIVE_REGISTRY_FLAG_NEIGHBOR'))
ANCHORS=((0xF02D8876,'0349'),(0xF032ACE2,'0d4e'),(0xF02FBC3A,'0' ))

def main():
 p=argparse.ArgumentParser();p.add_argument('--root',type=Path);p.add_argument('--boot',type=Path);p.add_argument('--out',type=Path);p.add_argument('--self-test',action='store_true');x=p.parse_args()
 if x.self_test:
  assert len(CANDIDATES)==3 and all(a%2==0 for a,_ in CANDIDATES)
  print('A136_SELF_TEST=PASS')
  if not (x.root or x.boot or x.out):return 0
 if not (x.root and x.boot and x.out):p.error('--root --boot --out required')
 spec=importlib.util.spec_from_file_location('a121_for_a136',Path(__file__).with_name('s13_5a121_boot_postselect_target_cfg_audit.py'))
 if spec is None or spec.loader is None:raise RuntimeError('A121_MISSING')
 a=importlib.util.module_from_spec(spec);spec.loader.exec_module(a)
 alice=a.assert_canonical(x.root/'research/f2/work/extracted/altice_alice/alice-py.bin','ALICE',a.ALICE_SIZE,a.ALICE_SHA)
 z=a.assert_canonical(x.root/'research/f2/work/extracted/altice_platform/zimage.bin','ZIMAGE',a.ZIMAGE_SIZE,a.ZIMAGE_SHA)
 boot=a.assert_canonical(x.boot,'BOOT_ZIMAGE',a.BOOT_SIZE,a.BOOT_SHA)
 a.check_inputs(alice,boot,z)
 from capstone import Cs,CS_ARCH_ARM,CS_MODE_THUMB,CS_MODE_LITTLE_ENDIAN
 from capstone.arm import ARM_OP_IMM
 md=Cs(CS_ARCH_ARM,CS_MODE_THUMB|CS_MODE_LITTLE_ENDIAN);md.detail=True
 base=a.ZIMAGE_BASE
 # Distinct prior proven exact literal anchors, not a synthetic opcode guess.
 for addr,raw in ((0xF02D8876,'0349'),(0xF032ACE2,'0d4e')):
  if z[addr-base:addr-base+2].hex()!=raw:raise RuntimeError('A135_ANCHOR_MISMATCH_%08X'%addr)
 lines=['S13.5A.136 - TARGETED NATIVE REGISTRY STRUCTURE/WRITER CANDIDATES','STRICTLY_OFFLINE=YES NO_USB_COM_PATCH_FLASH=YES',
 'ALICE_GUARD=PASS SHA256='+a.ALICE_SHA,'ZIMAGE_GUARD=PASS SHA256='+a.ZIMAGE_SHA,
 'BOOT_ZIMAGE_GUARD=PASS SHA256='+a.BOOT_SHA,'A135_NATIVE_ROOT_ANCHORS=PASS',
 'ROOT_POINTER=0xF007F044;NO_RUNTIME_REGISTRY_CONTENT',
 'CANDIDATE_CONTEXT=STATIC_CFG_ONLY_NO_WRITER_PROVEN']
 for entry,name in CANDIDATES:
  q=deque([entry]);seen={};edges=[];lit=[];ind=[];notes=[]
  while q and len(seen)<360:
   at=q.popleft()
   if at in seen:continue
   if not(entry<=at<entry+0x850 and base<=at<base+len(z)):
    notes.append('BOUNDARY=0x%08X'%at);continue
   i=next(md.disasm(z[at-base:at-base+4],at,1),None)
   if i is None:notes.append('DECODE_FAILED=0x%08X'%at);continue
   seen[at]=i;m=i.mnemonic.lower().split('.')[0];op=i.op_str.lower().replace(' ','')
   dest=i.operands[-1].imm&0xffffffff if i.operands and i.operands[-1].type==ARM_OP_IMM else None
   if m=='ldr' and '[pc,' in op:
    import re
    mo=re.search(r'\[pc,#(-?0x[\da-f]+|-?\d+)\]',op)
    if mo:
     cell=((at+4)&~3)+int(mo.group(1),0)
     if base<=cell<=base+len(z)-4:lit.append((at,cell,struct.unpack_from('<I',z,cell-base)[0]))
   if m in ('str','strh','strb','stm','stmia'):
    if '[sp' not in op:ind.append((at,i.mnemonic,i.op_str))
   if m=='pop' and 'pc' in op or m=='bx' and op=='lr':continue
   if m in ('bl','blx'):
    edges.append((at,'CALL',dest));q.append(at+i.size)
   elif m in ('bx','tbb','tbh') or (op.startswith('pc,') and m in ('mov','ldr','add')):
    edges.append((at,'INDIRECT_EXIT',None))
   elif m=='b' or m in ('beq','bne','bhi','bls','bgt','bge','blt','ble','bcs','bcc','blo','bhs','bmi','bpl','cbz','cbnz'):
    edges.append((at,'BRANCH',dest))
    if dest is not None:q.append(dest)
    if m!='b':q.append(at+i.size)
   else:q.append(at+i.size)
  if q:notes.append('INSTRUCTION_LIMIT')
  lines.extend(['','=== %s ENTRY=0x%08X INSTRUCTIONS=%d EDGES=%d WRITES=%d NOTES=%d ==='%(name,entry,len(seen),len(edges),len(ind),len(notes))])
  for at,i in sorted(seen.items()):lines.append('0x%08X %s %-8s %s'%(at,i.bytes.hex(),i.mnemonic,i.op_str))
  for at,kind,dest in edges:lines.append('EDGE=0x%08X %s %s'%(at,kind,'0x%08X'%dest if dest is not None else 'INDIRECT'))
  for at,cell,v in lit:lines.append('LITERAL=0x%08X CELL=0x%08X VALUE=0x%08X'%(at,cell,v))
  for at,m,op in ind:lines.append('MEMORY_WRITE=0x%08X %s %s'%(at,m,op))
  for n in notes:lines.append('NOTE='+n)
 lines+=['','A136_TARGETED_CANDIDATE_CFG=YES','REGISTRY_PRODUCER_PROVEN=NO_STATIC_ONLY','B702_AUDIO_REAL=UNPROVEN','PATCH_FLASH_READY=NO','NEXT=CLASSIFY_WRITES_VS_READS_AND_FIND_B702_COUNT_SOURCE_WHOLE_REGISTRY_INITIALIZATION']
 x.out.parent.mkdir(parents=True,exist_ok=True)
 with x.out.open('x',encoding='utf8') as f:f.write('\n'.join(lines)+'\n')
 print('A136_TARGETED_CANDIDATE_CFG=YES');print('A136_REPORT='+str(x.out))
 return 0
if __name__=='__main__':
 try:sys.exit(main())
 except Exception as e:print('A136_ABORT=%s(%s)'%(type(e).__name__,e),file=sys.stderr);sys.exit(1)
