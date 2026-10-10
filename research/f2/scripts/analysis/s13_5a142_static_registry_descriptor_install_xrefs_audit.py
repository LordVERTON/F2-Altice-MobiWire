#!/usr/bin/env python3
"""A142: identify static descriptor installation candidates. Read-only, no devices.
Focus on ROM descriptor and record base, not previously-censused RAM consumers.
"""
import argparse, hashlib, struct, sys, re
from pathlib import Path

IMAGES = {
 'ALICE':(0x1024EC00,0x157BB4,'7246242b67afae0d13104452bc3257827cb778119b54e7a26fb7fb55993697ea','research/f2/work/extracted/altice_alice/alice-py.bin'),
 'ZIMAGE':(0xF023CA50,0x185E98,'85fba8c8ae8161e4c1f8ced7983ec30d48c54ab10e51c69fcdfb900aca220954','research/f2/work/extracted/altice_platform/zimage.bin'),
 'BOOT_ZIMAGE':(0xF01F19E4,0x4B06C,'aa070292e9c1685eddb12080b3f0bbca763102adaf085016b4e503a3930b4c3e',None),
}
DESC=0xF037C08C
RECORDS=0xF0378760
RANGES=0xF037BF54
CHILD=0xF0378720
REGROOT=0xF007F044
INDEX_B702=884
INDEX_AUDIO=490

def u16(data,base,addr):
 o=addr-base
 if o<0 or o+2>len(data):raise RuntimeError(f'OUT_OF_BOUNDS_U16_0x{addr:X}')
 return struct.unpack_from('<H',data,o)[0]
def u32(data,base,addr):
 o=addr-base
 if o<0 or o+4>len(data):raise RuntimeError(f'OUT_OF_BOUNDS_U32_0x{addr:X}')
 return struct.unpack_from('<I',data,o)[0]
def imgs(root,boot):
 result={}; lines=[]
 for n,(base,size,digest,path) in IMAGES.items():
  p=boot if path is None else root/path
  if not p.is_file():raise RuntimeError(f'MISSING_{n}={p}')
  b=p.read_bytes(); got=hashlib.sha256(b).hexdigest()
  if len(b)!=size or got!=digest:raise RuntimeError(f'{n}_CANONICAL_GUARD_FAIL')
  result[n]=(base,b)
  lines.append(f'{n}_GUARD=PASS SHA256={got}')
 return result,lines

def literal_uses(blob,base,off,md):
 cell=base+off
 out=[]
 for pc_off in range(max(0,off-0x220)&~1,off,2):
  ins=next(md.disasm(blob[pc_off:pc_off+4],base+pc_off,1),None)
  if not ins or ins.mnemonic.lower().split('.')[0] != 'ldr':continue
  q=re.search(r'\[pc(?:,\s*#(-?0x[0-9a-f]+|-?\d+))?\]',ins.op_str.lower())
  if not q:continue
  disp=int(q.group(1),0) if q.group(1) else 0
  target=((ins.address+4)&~3)+disp
  if target==cell:out.append(ins)
 return out

def run(args):
 from capstone import Cs,CS_ARCH_ARM,CS_MODE_THUMB,CS_MODE_LITTLE_ENDIAN
 ims,lines=imgs(args.root,args.boot)
 base,z=ims['ZIMAGE']
 if (u32(z,base,DESC)!=RECORDS or u32(z,base,DESC+4)!=RANGES or u16(z,base,DESC+8)!=52):
  raise RuntimeError('A111_STATIC_DESCRIPTOR_ANCHOR_MISMATCH')
 b702=RECORDS+INDEX_B702*16;audio=RECORDS+INDEX_AUDIO*16
 if (u16(z,base,b702)!=0xB709 or u16(z,base,b702+2)!=2 or u32(z,base,b702+12)!=CHILD or u16(z,base,audio)!=0xB702 or u16(z,base,CHILD)!=0x8569 or u16(z,base,CHILD+2)!=0x87ED or u16(z,base,CHILD+4)!=0xA07B):
  raise RuntimeError('A111_B702_AUDIO_CHILD_ANCHORS_MISMATCH')
 lines[:0]=['S13.5A.142 - STATIC NATIVE REGISTRY DESCRIPTOR INSTALL XREFS','STRICTLY_OFFLINE=YES NO_USB_COM_PATCH_FLASH=YES','METHOD=STATIC_ROM_DESCRIPTOR_XREFS_AND_BOUNDED_CONSUMER_CONTEXT','LIMIT=RAW_CONSTANT_XREFS_DO_NOT_PROVE_INIT_OR_POINTER_ASSIGNMENT']
 lines+=['A111_STATIC_DESCRIPTOR_ANCHORS=PASS',f'DESCRIPTOR=0x{DESC:08X} RECORDS=0x{RECORDS:08X} RANGES=0x{RANGES:08X}',f'B702_RECORD=0x{b702:08X} COUNT=2 CHILD_PTR=0x{CHILD:08X}',f'AUDIO_RECORD=0x{audio:08X} PARENT=0x{u16(z,base,audio):04X}']
 md=Cs(CS_ARCH_ARM,CS_MODE_THUMB|CS_MODE_LITTLE_ENDIAN)
 # Search descriptor address and static record array references in all three canonical images.
 targets=[('REGISTRY_DESCRIPTOR',DESC),('REGISTRY_RECORDS',RECORDS),('REGISTRY_RANGES',RANGES),('B702_CHILD_POOL',CHILD),('ROOT_RUNTIME_GLOBAL',REGROOT)]
 total=0
 for tag,address in targets:
  lines.append(f'=== {tag}=0x{address:08X} ===')
  for name,(imagebase,blob) in ims.items():
   needle=struct.pack('<I',address)
   offs=[i for i in range(0,len(blob)-3) if blob[i:i+4]==needle]
   lines.append(f'{tag}_{name}_LITERAL_CELLS={len(offs)}')
   if len(offs)>128:raise RuntimeError(f'TOO_MANY_{tag}_{name}_CELLS')
   for off in offs:
    total+=1
    cell=imagebase+off
    lines.append(f'CELL=0x{cell:08X} SOURCE={name}')
    uses=literal_uses(blob,imagebase,off,md)
    lines.append(f'PCREL_THUMB_USE_COUNT={len(uses)}')
    for ins in uses[:20]:
     lines.append(f'  USE=0x{ins.address:08X} {ins.mnemonic} {ins.op_str}')
     # decode only 24 bytes from the precise instruction, avoid implying CFG.
     start=ins.address-imagebase
     for j in md.disasm(blob[start:start+28],ins.address):
      if j.address>=ins.address+24:break
      lines.append(f'    NEXT=0x{j.address:08X} {j.mnemonic} {j.op_str}')
 lines += [f'A142_RAW_LITERAL_CELLS_TOTAL={total}', 'A142_STATIC_DESCRIPTOR_INSTALL_CANDIDATES=REPORTED', 'RUNTIME_REGISTRY_SOURCE_EQ_ROM=UNPROVEN','B702_THIRD_CHILD_IN_ROM=UNPROVEN','PATCH_FLASH_READY=NO','NEXT=TRACE_RELEVANT_DESCRIPTOR_LOAD_TO_GLOBAL_ASSIGNMENT_OR_CLOSED_STATIC_SOURCE_PATH']
 args.out.parent.mkdir(parents=True,exist_ok=True)
 with args.out.open('x',encoding='utf-8') as f:f.write('\n'.join(lines)+'\n')
 print('A111_STATIC_DESCRIPTOR_ANCHORS=PASS')
 print('A142_STATIC_DESCRIPTOR_INSTALL_CANDIDATES=REPORTED')
 print('A142_REPORT='+str(args.out))

def main():
 p=argparse.ArgumentParser();p.add_argument('--root',type=Path);p.add_argument('--boot',type=Path);p.add_argument('--out',type=Path);p.add_argument('--self-test',action='store_true');a=p.parse_args()
 if a.self_test:
  assert RECORDS+INDEX_B702*16==0xF037BEA0
  assert len(IMAGES)==3 and struct.pack('<I',DESC)==bytes.fromhex('8cc037f0')
  print('A142_SELF_TEST=PASS')
  if not (a.root or a.boot or a.out):return 0
 if not all((a.root,a.boot,a.out)):p.error('requires --root --boot --out')
 try:run(a);return 0
 except Exception as e:print('A142_ABORT='+repr(e),file=sys.stderr);return 1
if __name__=='__main__':sys.exit(main())
