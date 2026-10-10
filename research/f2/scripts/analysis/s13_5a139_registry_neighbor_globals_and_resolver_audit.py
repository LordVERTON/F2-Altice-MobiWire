#!/usr/bin/env python3
"""A139: offline, bounded inspection of registry neighbor globals and native resolver.
No device access, patch, write to canonical images, or runtime proof implied.
"""
from __future__ import annotations
import argparse,hashlib,struct,sys
from pathlib import Path

IMAGES={
 'ALICE':(0x1024EC00,0x157BB4,'7246242b67afae0d13104452bc3257827cb778119b54e7a26fb7fb55993697ea','research/f2/work/extracted/altice_alice/alice-py.bin'),
 'ZIMAGE':(0xF023CA50,0x185E98,'85fba8c8ae8161e4c1f8ced7983ec30d48c54ab10e51c69fcdfb900aca220954','research/f2/work/extracted/altice_platform/zimage.bin'),
 'BOOT_ZIMAGE':(0xF01F19E4,0x4B06C,'aa070292e9c1685eddb12080b3f0bbca763102adaf085016b4e503a3930b4c3e',None),
}
GLOBALS=(0xF007F040,0xF007F044,0xF007F048,0xF007F04C,0xF007F050)
RESOLVER=0xF02E01B0

def read_images(root,boot):
 out={}
 for label,(base,size,digest,relative) in IMAGES.items():
  path=boot if relative is None else root/relative
  if not path.is_file():raise RuntimeError(f'MISSING_{label}={path}')
  blob=path.read_bytes();sha=hashlib.sha256(blob).hexdigest()
  if len(blob)!=size or sha!=digest:raise RuntimeError(f'{label}_GUARD_FAIL size={len(blob)} sha={sha}')
  out[label]=(base,blob,digest)
 return out

def decode(md,blob,base,address,count=1):
 off=address-base
 if off<0 or off>=len(blob):return []
 return list(md.disasm(blob[off:off+min(4*count,512)],address,count))

def report(a):
 from capstone import Cs,CS_ARCH_ARM,CS_MODE_THUMB,CS_MODE_LITTLE_ENDIAN
 md=Cs(CS_ARCH_ARM,CS_MODE_THUMB|CS_MODE_LITTLE_ENDIAN);md.detail=True
 imgs=read_images(a.root,a.boot)
 lines=['S13.5A.139 — REGISTRY NEIGHBOR GLOBALS / RESOLVER AUDIT',
  'STRICTLY_OFFLINE=YES NO_DEVICE_NO_PATCH_NO_FLASH=YES',
  'METHOD=STATIC_LITERAL_XREF_AND_BOUNDED_RESOLVER_CFG',
  'NOTE=NO_PROOF_OF_WRITES_OR_RUNTIME_INITIALIZER']
 for n,(b,blob,sha) in imgs.items(): lines.append(f'{n}_GUARD=PASS SHA256={sha}')
 counts={}
 for value in GLOBALS:
  lines.append(f'=== GLOBAL=0x{value:08X} ===');cnt=0
  for name,(base,blob,_) in imgs.items():
   needle=struct.pack('<I',value);positions=[];start=0
   while True:
    j=blob.find(needle,start)
    if j<0:break
    positions.append(j);start=j+1
   lines.append(f'{name}_RAW_CELLS={len(positions)}')
   for off in positions[:80]:
    cell=base+off;uses=[]
    for instoff in range(max(0,off-0x120)&~1,off,2):
     x=decode(md,blob,base,base+instoff)
     if not x:continue
     ins=x[0]
     if ins.mnemonic.lower().split('.')[0]!='ldr' or '[pc' not in ins.op_str.lower():continue
     from capstone.arm import ARM_OP_MEM,ARM_REG_PC
     try:
      m=next(z for z in ins.operands if z.type==ARM_OP_MEM and z.mem.base==ARM_REG_PC)
     except StopIteration:continue
     addr=(((ins.address+4)&~3)+m.mem.disp)&0xffffffff
     if addr==cell:uses.append(ins)
    lines.append(f'CELL=0x{cell:08X} PCREL_USES={len(uses)}')
    for ins in uses[:12]:
     cnt+=1
     lines.append(f'  LOAD=0x{ins.address:08X} {ins.mnemonic} {ins.op_str}')
     for k in range(1,25):
      after=decode(md,blob,base,ins.address+ins.size+2*(k-1))
      if not after:break
      q=after[0]
      if q.mnemonic.lower().startswith(('str','stm','push')):
       lines.append(f'    NEAR_STORE=0x{q.address:08X} {q.mnemonic} {q.op_str} [HEURISTIC_ONLY]')
  counts[value]=cnt
 lines.append(f'=== RESOLVER=0x{RESOLVER:08X} bounded disassembly ===')
 base,blob,_=imgs['ZIMAGE']
 if not(base<=RESOLVER<base+len(blob)):raise RuntimeError('RESOLVER_OUTSIDE_ZIMAGE')
 for i in decode(md,blob,base,RESOLVER,96):
  lines.append(f'0x{i.address:08X} {i.bytes.hex():<10} {i.mnemonic:<10} {i.op_str}')
  if i.mnemonic=='bx' and i.op_str.strip()=='lr':break
 lines += [f'GLOBAL_XREF_USES_0x{g:08X}={counts[g]}' for g in GLOBALS]
 lines += ['A139_NEIGHBOR_AND_RESOLVER_REPORTED=YES','REGISTRY_PRODUCER_PROVEN=NO','REAL_B702_THIRD_CHILD=UNPROVEN','PATCH_FLASH_READY=NO','NEXT=INSPECT_NEIGHBOR_REFERENCES_FOR_PROVEN_INIT_CALLER_AND_EXACT_STORE_DATAFLOW']
 a.out.parent.mkdir(parents=True,exist_ok=True)
 with a.out.open('x',encoding='utf-8') as f:f.write('\n'.join(lines)+'\n')
 print('A139_NEIGHBOR_AND_RESOLVER_REPORTED=YES');print('A139_REPORT='+str(a.out))

def main():
 p=argparse.ArgumentParser();p.add_argument('--root',type=Path);p.add_argument('--boot',type=Path);p.add_argument('--out',type=Path);p.add_argument('--self-test',action='store_true');a=p.parse_args()
 if a.self_test:
  assert len(GLOBALS)==5 and RESOLVER==0xF02E01B0 and IMAGES['BOOT_ZIMAGE'][1]==0x4B06C
  print('A139_SELF_TEST=PASS')
  if not any((a.root,a.boot,a.out)):return 0
 if not all((a.root,a.boot,a.out)):p.error('requires --root --boot --out')
 try:report(a);return 0
 except Exception as e:print('A139_ABORT='+repr(e),file=sys.stderr);return 1
if __name__=='__main__':sys.exit(main())
