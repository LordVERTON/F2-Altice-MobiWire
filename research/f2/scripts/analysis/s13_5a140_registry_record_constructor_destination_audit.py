#!/usr/bin/env python3
"""A140: targeted offline CFG of the function after native count accessor.
Do not mistake neighboring stores for provenance; inspect their R0 definitions.
Canonical binaries read-only. Writes only an exclusive report. No hardware or flash.
"""
from __future__ import annotations
import argparse,hashlib,struct,sys,re
from pathlib import Path
from collections import deque

IMAGES={
 'ALICE':(0x1024EC00,0x157BB4,'7246242b67afae0d13104452bc3257827cb778119b54e7a26fb7fb55993697ea','research/f2/work/extracted/altice_alice/alice-py.bin'),
 'ZIMAGE':(0xF023CA50,0x185E98,'85fba8c8ae8161e4c1f8ced7983ec30d48c54ab10e51c69fcdfb900aca220954','research/f2/work/extracted/altice_platform/zimage.bin'),
 'BOOT_ZIMAGE':(0xF01F19E4,0x4B06C,'aa070292e9c1685eddb12080b3f0bbca763102adaf085016b4e503a3930b4c3e',None),
}
ENTRY=0xF02D8888
END=0xF02D8970
STORES=(0xF02D8898,0xF02D889A,0xF02D889C)

def read(a):
 imgs={}
 for name,(base,size,digest,rel) in IMAGES.items():
  path=a.boot if rel is None else a.root/rel
  raw=path.read_bytes(); actual=hashlib.sha256(raw).hexdigest()
  if len(raw)!=size or actual!=digest: raise RuntimeError(f'{name}_GUARD_FAIL size={len(raw)} sha256={actual}')
  imgs[name]=(base,raw,digest)
 return imgs

def main():
 p=argparse.ArgumentParser()
 p.add_argument('--root',type=Path);p.add_argument('--boot',type=Path);p.add_argument('--out',type=Path);p.add_argument('--self-test',action='store_true');a=p.parse_args()
 if a.self_test:
  assert STORES==(0xF02D8898,0xF02D889A,0xF02D889C)
  assert ENTRY<STORES[0]<END
  print('A140_SELF_TEST=PASS')
  if not any((a.root,a.boot,a.out)):return 0
 if not all((a.root,a.boot,a.out)):p.error('requires --root --boot --out')
 from capstone import Cs,CS_ARCH_ARM,CS_MODE_THUMB,CS_MODE_LITTLE_ENDIAN
 from capstone.arm import ARM_OP_IMM,ARM_OP_MEM,ARM_REG_PC
 images=read(a);base,z,sha=images['ZIMAGE']
 md=Cs(CS_ARCH_ARM,CS_MODE_THUMB|CS_MODE_LITTLE_ENDIAN);md.detail=True
 def one(addr):
  if not(base<=addr<base+len(z)):return None
  return next(md.disasm(z[addr-base:addr-base+4],addr,1),None)
 # exact anchors: confirm actual stores and base register R0
 for target in STORES:
  ins=one(target)
  if not ins or not ins.mnemonic.startswith('str') or '[r0' not in ins.op_str:
   raise RuntimeError(f'STORE_ANCHOR_INVALID=0x{target:08X} {ins}')
 q=deque([ENTRY]);nodes={};edges=[];literals=[];writes=[];calls=[];notes=[]
 branches={'beq','bne','bhi','bls','bge','bgt','blt','ble','bcs','bcc','blo','bhs','bmi','bpl','cbz','cbnz'}
 while q and len(nodes)<200:
  pc=q.popleft()
  if pc in nodes:continue
  if not(ENTRY<=pc<END): notes.append(f'OUT_OF_BOUNDS=0x{pc:08X}');continue
  ins=one(pc)
  if ins is None:notes.append(f'DECODE_FAILURE=0x{pc:08X}');continue
  nodes[pc]=ins;m=ins.mnemonic.lower().split('.')[0];op=ins.op_str.lower().replace(' ','')
  dst=(ins.operands[-1].imm & 0xffffffff) if ins.operands and ins.operands[-1].type==ARM_OP_IMM else None
  if m=='ldr':
   for x in ins.operands:
    if x.type==ARM_OP_MEM and x.mem.base==ARM_REG_PC:
     cell=((pc+4)&~3)+x.mem.disp
     if base<=cell<=base+len(z)-4:
      literals.append((pc,cell,struct.unpack_from('<I',z,cell-base)[0]))
  if m.startswith(('str','stm')):writes.append((pc,ins.mnemonic,ins.op_str))
  if m in ('bl','blx'):
   calls.append((pc,dst));q.append(pc+ins.size)
  elif (m=='pop' and 'pc' in op) or(m=='bx' and op=='lr'):pass
  elif m=='b':edges.append((pc,'JMP',dst)); q.extend([dst] if dst is not None else [])
  elif m in branches:
   edges.append((pc,'CJMP',dst));q.append(pc+ins.size)
   if dst is not None:q.append(dst)
  elif m in ('bx','tbb','tbh') or (m in ('ldr','mov','add') and op.startswith('pc,')):
   notes.append(f'INDIRECT_EXIT=0x{pc:08X}')
  else:q.append(pc+ins.size)
 if q:notes.append('INSTRUCTION_LIMIT')
 lines=['S13.5A.140 - NATIVE RECORD CONSTRUCTOR DESTINATION CFG','STRICTLY_OFFLINE=YES NO_PHONE_USB_COM_PATCH_FLASH=YES',
 'EVIDENCE=BOUNDED_STATIC_CFG_NOT_RUNTIME_PROOF',
 *(f'{n}_GUARD=PASS SHA256={v[2]}' for n,v in images.items()),
 'A139_THREE_NEARBY_STORE_ANCHORS=PASS',
 f'ENTRY=0x{ENTRY:08X} COUNT={len(nodes)} EDGES={len(edges)} CALLS={len(calls)} WRITES={len(writes)} NOTES={len(notes)}','']
 for addr,i in sorted(nodes.items()):lines.append(f'0x{addr:08X} {i.bytes.hex():<10} {i.mnemonic:<10} {i.op_str}')
 lines += ['','=== WRITE INSTRUCTIONS ===']
 for addr,m,op in writes:lines.append(f'WRITE=0x{addr:08X} {m} {op}')
 lines += ['','=== CALLS ===']
 for addr,dst in calls:lines.append(f'CALL=0x{addr:08X} TARGET={"0x%08X"%dst if dst is not None else "INDIRECT"}')
 lines += ['','=== PC LITERALS ===']
 for addr,cell,value in literals:lines.append(f'LITERAL=0x{addr:08X} CELL=0x{cell:08X} VALUE=0x{value:08X}')
 lines += ['','=== BRANCHES ===']
 for addr,typ,dst in edges:lines.append(f'EDGE=0x{addr:08X} {typ} {"0x%08X"%dst if dst is not None else "INDIRECT"}')
 lines.extend(['NOTE='+s for s in notes]);lines += ['A140_DESTINATION_CFG_REPORTED=YES',
  'DESTINATION_PROVEN_AS_NATIVE_REGISTRY=NO_CFG_ONLY', 'B702_THIRD_CHILD_REAL=UNPROVEN','PATCH_FLASH_READY=NO',
  'NEXT=ANALYZE_R0_PROVENANCE_AND_CALLEE_CONTEXT_IF_STORES_REACHABLE']
 a.out.parent.mkdir(parents=True,exist_ok=True)
 with a.out.open('x',encoding='utf-8',newline='\n') as f:f.write('\n'.join(lines)+'\n')
 print('A140_DESTINATION_CFG_REPORTED=YES');print('A140_REPORT='+str(a.out));return 0
if __name__=='__main__':
 try:sys.exit(main())
 except Exception as ex:print('A140_ABORT='+repr(ex),file=sys.stderr);sys.exit(1)
