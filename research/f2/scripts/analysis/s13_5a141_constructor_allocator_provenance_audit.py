#!/usr/bin/env python3
"""S13.5A.141: inspect record-constructor destination returned by F021604A.
Strictly offline, read-only canonical images, exclusive report; no hardware or patch.
"""
from __future__ import annotations
import argparse,hashlib,struct,sys
from pathlib import Path
from collections import deque

IMAGES={
 'ALICE':(0x1024EC00,0x157BB4,'7246242b67afae0d13104452bc3257827cb778119b54e7a26fb7fb55993697ea','research/f2/work/extracted/altice_alice/alice-py.bin'),
 'ZIMAGE':(0xF023CA50,0x185E98,'85fba8c8ae8161e4c1f8ced7983ec30d48c54ab10e51c69fcdfb900aca220954','research/f2/work/extracted/altice_platform/zimage.bin'),
 'BOOT_ZIMAGE':(0xF01F19E4,0x4B06C,'aa070292e9c1685eddb12080b3f0bbca763102adaf085016b4e503a3930b4c3e',None)}
CALLEE=0xF021604A
CALLSITE=0xF02D8894
CONSTRUCTOR=0xF02D8888

def main():
 p=argparse.ArgumentParser();p.add_argument('--root',type=Path);p.add_argument('--boot',type=Path);p.add_argument('--out',type=Path);p.add_argument('--self-test',action='store_true');a=p.parse_args()
 if a.self_test:
  assert CALLEE<CALLSITE and CONSTRUCTOR<CALLSITE and len(IMAGES)==3
  print('A141_SELF_TEST=PASS')
  if not (a.root or a.boot or a.out):return 0
 if not all((a.root,a.boot,a.out)):p.error('requires --root --boot --out')
 from capstone import Cs,CS_ARCH_ARM,CS_MODE_THUMB,CS_MODE_LITTLE_ENDIAN
 from capstone.arm import ARM_OP_IMM,ARM_OP_MEM,ARM_REG_PC
 blobs={}
 for name,(base,size,sha,rel) in IMAGES.items():
  path=a.boot if rel is None else a.root/rel
  raw=path.read_bytes(); got=hashlib.sha256(raw).hexdigest()
  if len(raw)!=size or got!=sha:raise RuntimeError(f'{name}_GUARD_FAIL size={len(raw)} sha={got}')
  blobs[name]=(base,raw,sha)
 md=Cs(CS_ARCH_ARM,CS_MODE_THUMB|CS_MODE_LITTLE_ENDIAN);md.detail=True
 def one(addr):
  for name,(base,raw,_) in blobs.items():
   if base<=addr<base+len(raw):return next(md.disasm(raw[addr-base:addr-base+4],addr,1),None),name
  return None,None
 anchor,_=one(CALLSITE)
 if not anchor or anchor.mnemonic!='bl' or not anchor.operands or anchor.operands[-1].type!=ARM_OP_IMM or (anchor.operands[-1].imm & 0xFFFFFFFF)!=CALLEE:
  raise RuntimeError(f'A140_CALLEE_EDGE_MISMATCH={anchor}')
 lines=['S13.5A.141 - CONSTRUCTOR R0 ORIGIN / CALLEE CFG',
        'STRICTLY_OFFLINE=YES NO_PHONE_USB_COM_PATCH_FLASH=YES',
        'EVIDENCE=STATIC_BOUNDED_CFG_NOT_RUNTIME_PROOF',
        *(f'{name}_GUARD=PASS SHA256={sha}' for name,(_,_,sha) in blobs.items()),
        'A140_CALLEE_EDGE=PASS','CALLSITE=0xF02D8894 BL 0xF021604A',
        'DESTINATION_FOR_A140_STORES=RETURN_R0_FROM_F021604A']
 branches={'beq','bne','bhi','bls','bge','bgt','blt','ble','bcs','bcc','blo','bhs','bmi','bpl','cbz','cbnz'}
 for entry,limit,label in [(CALLEE,260,'CALLEE_ALLOCATOR_OR_LOOKUP'),(CONSTRUCTOR,80,'CALLER_CONTEXT')]:
  lines+=['',f'=== {label} ENTRY=0x{entry:08X} ===']
  q=deque([entry]);seen={};calls=[];stores=[];literals=[];notes=[]
  while q and len(seen)<limit:
   pc=q.popleft()
   if pc in seen:continue
   if not(entry<=pc<entry+0x700):notes.append(f'BRANCH_OUTSIDE_WINDOW=0x{pc:08X}');continue
   ins,area=one(pc)
   if not ins:notes.append(f'BAD_DECODE=0x{pc:08X}');continue
   m=ins.mnemonic.lower().split('.')[0];op=ins.op_str.lower().replace(' ','');seen[pc]=ins
   imm=ins.operands[-1].imm&0xffffffff if ins.operands and ins.operands[-1].type==ARM_OP_IMM else None
   if m=='ldr':
    for operand in ins.operands:
     if operand.type==ARM_OP_MEM and operand.mem.base==ARM_REG_PC:
      cell=((pc+4)&~3)+operand.mem.disp
      for nm,(base,raw,_) in blobs.items():
       if base<=cell<=base+len(raw)-4:literals.append((pc,cell,struct.unpack_from('<I',raw,cell-base)[0]));break
   if m.startswith(('str','stm')):stores.append((pc,ins.mnemonic,ins.op_str))
   if m in ('bl','blx'):
    calls.append((pc,imm));q.append(pc+ins.size)
   elif (m=='pop' and 'pc' in op) or (m=='bx' and op=='lr'):pass
   elif m=='b':
    if imm is not None:q.append(imm)
    else:notes.append(f'INDIRECT_BRANCH=0x{pc:08X}')
   elif m in branches:
    q.append(pc+ins.size)
    if imm is not None:q.append(imm)
   elif m in ('bx','tbb','tbh') or(m in ('ldr','mov','add') and op.startswith('pc,')):
    notes.append(f'INDIRECT_EXIT=0x{pc:08X}')
   else:q.append(pc+ins.size)
  if q:notes.append('INSN_LIMIT')
  lines.append(f'INSTRUCTIONS={len(seen)} CALLS={len(calls)} STORES={len(stores)} NOTES={len(notes)}')
  for addr,ins in sorted(seen.items()):lines.append(f'0x{addr:08X} {ins.bytes.hex():<10} {ins.mnemonic:<9} {ins.op_str}')
  lines+=['-- CALLS --'];lines += [f'CALL=0x{x:08X} TARGET={"0x%08X"%y if y is not None else "INDIRECT"}' for x,y in calls]
  lines+=['-- STORES --'];lines += [f'WRITE=0x{x:08X} {m} {o}' for x,m,o in stores]
  lines+=['-- LITERALS --'];lines += [f'LITERAL=0x{x:08X} CELL=0x{y:08X} VALUE=0x{v:08X}' for x,y,v in literals]
  lines += [f'NOTE={s}' for s in notes]
 lines+=['A141_CALLEE_CFG_REPORTED=YES','REAL_NATIVE_REGISTRY_RECORD_PROVEN=NO_STATIC_ONLY','REAL_B702_THIRD_CHILD=UNPROVEN','PATCH_FLASH_READY=NO','NEXT=CLASSIFY_RETURN_R0_DESTINATION_AND_ALLOCATION_LIFETIME_FROM_CFG']
 a.out.parent.mkdir(parents=True,exist_ok=True)
 with a.out.open('x',encoding='utf-8',newline='\n') as f:f.write('\n'.join(lines)+'\n')
 print('A141_CALLEE_CFG_REPORTED=YES');print('A141_REPORT='+str(a.out));return 0
if __name__=='__main__':
 try:sys.exit(main())
 except Exception as e:print('A141_ABORT='+repr(e),file=sys.stderr);sys.exit(1)
