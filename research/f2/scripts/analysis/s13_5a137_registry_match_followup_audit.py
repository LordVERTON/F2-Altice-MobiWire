#!/usr/bin/env python3
"""A137: bound and classify followup F02FEFB4 from a real registry-match branch.
Canonical images read-only; no device I/O or ROM changes. Not a writer proof.
"""
from __future__ import annotations
import argparse, importlib.util, struct, sys, re
from pathlib import Path
from collections import deque

ENTRY=0xF02FEFB4
ANCHORS=((0xF02FBC76,'03f09df9'),(0xF02FBC90,'44f007f0'))

def inspect_cfg(blob,base,max_ins=240,span=0x600):
 from capstone import Cs,CS_ARCH_ARM,CS_MODE_THUMB,CS_MODE_LITTLE_ENDIAN
 from capstone.arm import ARM_OP_IMM
 md=Cs(CS_ARCH_ARM,CS_MODE_THUMB|CS_MODE_LITTLE_ENDIAN);md.detail=True
 q=deque([ENTRY]);seen={};edges=[];lits=[];writes=[];notes=[]
 while q and len(seen)<max_ins:
  at=q.popleft()
  if at in seen:continue
  if not(ENTRY<=at<ENTRY+span and base<=at<base+len(blob)):
   notes.append(f'BOUNDED_EXIT=0x{at:08X}');continue
  i=next(md.disasm(blob[at-base:at-base+4],at,1),None)
  if i is None:notes.append(f'DECODE_FAILED=0x{at:08X}');continue
  seen[at]=i;m=i.mnemonic.lower().split('.')[0];op=i.op_str.lower().replace(' ','')
  dest=i.operands[-1].imm&0xffffffff if i.operands and i.operands[-1].type==ARM_OP_IMM else None
  if m=='ldr' and '[pc,' in op:
   mo=re.search(r'\[pc,#(-?0x[0-9a-f]+|-?\d+)\]',op)
   if mo:
    cell=((at+4)&~3)+int(mo.group(1),0)
    if base<=cell<=base+len(blob)-4:lits.append((at,cell,struct.unpack_from('<I',blob,cell-base)[0]))
  if m.startswith('str') or m.startswith('stm'):
   writes.append((at,i.mnemonic,i.op_str))
  if (m=='pop' and 'pc' in op) or (m=='bx' and op=='lr'):continue
  if m in ('bl','blx'):
   edges.append((at,'DIRECT_CALL' if dest is not None else 'INDIRECT_CALL',dest));q.append(at+i.size)
  elif m in ('bx','tbb','tbh') or (op.startswith('pc,') and m in ('mov','ldr','add')):
   edges.append((at,'INDIRECT_EXIT',None))
  elif m=='b' or m in ('beq','bne','bhi','bls','bgt','bge','blt','ble','bcs','bcc','blo','bhs','bmi','bpl','cbz','cbnz'):
   edges.append((at,'JUMP' if m=='b' else 'CJUMP',dest))
   if dest is not None:q.append(dest)
   if m!='b':q.append(at+i.size)
  else:q.append(at+i.size)
 if q:notes.append('INSTRUCTION_LIMIT')
 return seen,edges,lits,writes,notes

def main():
 p=argparse.ArgumentParser();p.add_argument('--root',type=Path);p.add_argument('--boot',type=Path);p.add_argument('--out',type=Path);p.add_argument('--self-test',action='store_true');a=p.parse_args()
 if a.self_test:
  assert ENTRY%2==0 and len(ANCHORS)==2
  print('A137_SELF_TEST=PASS')
  if not (a.root or a.boot or a.out):return 0
 if not all((a.root,a.boot,a.out)):p.error('--root --boot --out are required')
 dep=Path(__file__).with_name('s13_5a121_boot_postselect_target_cfg_audit.py')
 if not dep.is_file():raise RuntimeError('A121_DEPENDENCY_MISSING')
 spec=importlib.util.spec_from_file_location('a121_for_a137',dep);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
 alice=m.assert_canonical(a.root/'research/f2/work/extracted/altice_alice/alice-py.bin','ALICE',m.ALICE_SIZE,m.ALICE_SHA)
 boot=m.assert_canonical(a.boot,'BOOT_ZIMAGE',m.BOOT_SIZE,m.BOOT_SHA)
 z=m.assert_canonical(a.root/'research/f2/work/extracted/altice_platform/zimage.bin','ZIMAGE',m.ZIMAGE_SIZE,m.ZIMAGE_SHA)
 m.check_inputs(alice,boot,z)
 base=m.ZIMAGE_BASE
 # Callsite opcode is exact; literal cell is a pointer, not disassembled Thumb.
 if z[0xF02FBC76-base:0xF02FBC7A-base].hex()!='03f09df9':raise RuntimeError('A136_MATCH_FOLLOWUP_ANCHOR_MISMATCH')
 if struct.unpack_from('<I',z,0xF02FBC90-base)[0]!=0xF007F044:raise RuntimeError('A136_REGISTRY_ROOT_ANCHOR_MISMATCH')
 ins,edges,lits,writes,notes=inspect_cfg(z,base)
 lines=['S13.5A.137 — REGISTRY MATCH FOLLOWUP 0xF02FEFB4',
 'STRICTLY_OFFLINE=YES NO_USB_COM_PHONE_FIRMWARE_WRITE=YES',
 'ALICE_GUARD=PASS SHA256='+m.ALICE_SHA,'ZIMAGE_GUARD=PASS SHA256='+m.ZIMAGE_SHA,
 'BOOT_ZIMAGE_GUARD=PASS SHA256='+m.BOOT_SHA,'A136_MATCH_FOLLOWUP_ANCHORS=PASS',
 'EVIDENCE=STATIC_BOUNDED_CFG_NOT_RUNTIME_WRITER_PROOF',
 f'ENTRY=0x{ENTRY:08X} INSTRUCTIONS={len(ins)} EDGES={len(edges)} LITERALS={len(lits)} MEMORY_WRITES={len(writes)} NOTES={len(notes)}','']
 for at,i in sorted(ins.items()):lines.append(f'0x{at:08X} {i.bytes.hex():<10} {i.mnemonic:<9} {i.op_str}')
 for at,k,d in edges:lines.append(f'EDGE=0x{at:08X} KIND={k} TARGET={"0x%08X"%d if d is not None else "INDIRECT"}')
 for at,cell,v in lits:lines.append(f'LITERAL=0x{at:08X} CELL=0x{cell:08X} VALUE=0x{v:08X}')
 for at,mn,op in writes:lines.append(f'WRITE_CANDIDATE=0x{at:08X} {mn} {op}')
 for n in notes:lines.append('NOTE='+n)
 lines.extend(['','A137_MATCH_FOLLOWUP_CFG=YES','NATIVE_REGISTRY_WRITER_PROVEN=NO_STATIC_ONLY',
 'REAL_B702_3_CHILDREN=UNPROVEN','REAL_OK_TO_AUDIO=UNPROVEN','PATCH_FLASH_READY=NO',
 'NEXT=IF_NOT_REGISTRY_WRITER_STOP_BRANCH;IDENTIFY_NATIVE_REGISTRY_INITIALIZATION_AND_COUNT_POINTER_WRITERS'])
 a.out.parent.mkdir(parents=True,exist_ok=True)
 with a.out.open('x',encoding='utf-8',newline='\n') as f:f.write('\n'.join(lines)+'\n')
 print('A137_MATCH_FOLLOWUP_CFG=YES');print('A137_REPORT='+str(a.out));return 0
if __name__=='__main__':
 try:sys.exit(main())
 except Exception as e:print(f'A137_ABORT={type(e).__name__}: {e}',file=sys.stderr);sys.exit(1)
