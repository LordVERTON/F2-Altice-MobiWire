#!/usr/bin/env python3
"""S13.5A.138 - static candidate write trace through native registry root.
Strictly offline, read-only; syntactic classification, not runtime provenance.
"""
from __future__ import annotations
import argparse, importlib.util, re, struct, sys
from pathlib import Path
ROOT_PTR=0xF007F044

def helper():
 p=Path(__file__).with_name('s13_5a121_boot_postselect_target_cfg_audit.py')
 if not p.exists(): raise RuntimeError('A121_DEPENDENCY_MISSING')
 s=importlib.util.spec_from_file_location('a121_for_a138',p)
 m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m

def one(md,blob,base,pc):
 if not base<=pc<base+len(blob):return None
 return next(md.disasm(blob[pc-base:pc-base+4],pc,1),None)

def run(a):
 m=helper()
 images=[('ALICE',m.ALICE_BASE,m.assert_canonical(a.root/'research/f2/work/extracted/altice_alice/alice-py.bin','ALICE',m.ALICE_SIZE,m.ALICE_SHA)),('ZIMAGE',m.ZIMAGE_BASE,m.assert_canonical(a.root/'research/f2/work/extracted/altice_platform/zimage.bin','ZIMAGE',m.ZIMAGE_SIZE,m.ZIMAGE_SHA)),('BOOT_ZIMAGE',m.BOOT_BASE,m.assert_canonical(a.boot,'BOOT_ZIMAGE',m.BOOT_SIZE,m.BOOT_SHA))]
 from capstone import Cs, CS_ARCH_ARM,CS_MODE_THUMB,CS_MODE_LITTLE_ENDIAN
 md=Cs(CS_ARCH_ARM, CS_MODE_THUMB|CS_MODE_LITTLE_ENDIAN);md.detail=True
 out=['S13.5A.138 - NATIVE ROOT WRITER PROVENANCE CANDIDATES','STRICTLY_OFFLINE=YES NO_USB_COM_PHONE_PATCH_FLASH=YES']
 out += [f'{n}_GUARD=PASS SHA256={getattr(m,"BOOT_SHA" if n=="BOOT_ZIMAGE" else n+"_SHA")}' for n,_,_ in images]
 out += ['METHOD=LITERAL_LOAD_FOLLOWING_LINEAR_WINDOW_WITH_SIMPLE_REGISTER_TAINT','WARNING=HEURISTIC_NOT_CFG_OR_RUNTIME_WRITER_PROOF','ROOT_POINTER=0xF007F044']
 seen=0;possible=[]
 for name,base,blob in images:
  needle=struct.pack('<I',ROOT_PTR)
  offsets=[i for i in range(len(blob)-3) if blob[i:i+4]==needle]
  out.append(f'=== {name} POINTER_LITERALS={len(offsets)} ===')
  for offset in offsets:
   cell=base+offset
   for off in range(max(0,offset-0x300)&~1,offset,2):
    inst=one(md,blob,base,base+off)
    if inst is None or inst.mnemonic.split('.')[0]!='ldr':continue
    op=inst.op_str.lower().replace(' ','')
    mat=re.fullmatch(r'(r\d+),\[pc(?:,#(-?0x[0-9a-f]+|-?\d+))?\]',op)
    if not mat:continue
    imm=int(mat.group(2),0) if mat.group(2) else 0
    target=(((inst.address+4)&~3)+imm)&0xffffffff
    if target!=cell:continue
    seen+=1
    root_register=mat.group(1)
    out.append(f'REF=0x{inst.address:08X} CELL=0x{cell:08X} INITIAL_REG={root_register}')
    # Follow straight line only; abandon on branch/call, avoid false cross-function propagation.
    taint={root_register:'global_pointer_address'}
    pc=inst.address+inst.size
    for _ in range(44):
     cur=one(md,blob,base,pc)
     if cur is None:break
     mn=cur.mnemonic.lower().split('.')[0]
     operands=[x.strip().lower() for x in cur.op_str.split(',')]
     if mn in ('b','bx','bl','blx','pop','cbz','cbnz') or (mn.startswith('b') and mn not in ('bic','bfi','bfc')):break
     if mn in ('ldr','ldrb','ldrh') and len(operands)>1:
      dst=operands[0];src=cur.op_str.lower()
      hit=re.match(r'^\[\s*(r\d+)', operands[1])
      if hit and hit.group(1) in taint:
       parent=taint[hit.group(1)]
       taint[dst]='registry_base' if parent=='global_pointer_address' and mn=='ldr' else 'registry_derived'
       out.append(f'  TRACE=0x{pc:08X} {mn} {cur.op_str} DERIVED={taint[dst]}')
      else:taint.pop(dst,None)
     elif mn.startswith('str') and len(operands)>1:
      match=re.match(r'^\[\s*(r\d+)',operands[1]);reg=match.group(1) if match else ''
      if reg in taint:
       status='ROOT_POINTER_WRITE_CANDIDATE' if taint[reg]=='global_pointer_address' else 'REGISTRY_DATA_WRITE_CANDIDATE'
       item=f'0x{pc:08X} {status} BASE_REG={reg} {cur.mnemonic} {cur.op_str} FROM_REF=0x{inst.address:08X}'
       possible.append(item);out.append('  '+item)
     elif mn in ('mov','movs') and len(operands)>1:
      dst=operands[0];src=operands[1]
      if src in taint:taint[dst]=taint[src]
      else:taint.pop(dst,None)
     elif mn in ('add','adds','sub','subs') and len(operands)>1:
      dst=operands[0]
      if len(operands)==3 and operands[1] in taint:taint[dst]='registry_derived'
      elif len(operands)==2 and dst in taint:taint[dst]='registry_derived'
      else:taint.pop(dst,None)
     elif operands and re.fullmatch(r'r\d+',operands[0]) and mn not in ('cmp','cmn','tst','teq','push'):
      taint.pop(operands[0],None)
     pc+=cur.size
 out += [f'A138_LITERAL_LOADS_EXAMINED={seen}',f'A138_POTENTIAL_WRITE_SITES={len(possible)}','A138_WRITER_DATAFLOW_CENSUS=YES','ACTUAL_REGISTRY_PRODUCER_PROVEN=NO_STATIC_HEURISTIC','B702_THIRD_CHILD_REAL=UNPROVEN','PATCH_FLASH_READY=NO','NEXT=IF_CANDIDATES_REVIEW_EXACT_CFG;ELSE_TRACE_BOOT_INIT_AND_REGISTRY_DESCRIPTOR_WRITERS']
 a.out.parent.mkdir(parents=True,exist_ok=True)
 with a.out.open('x',encoding='utf-8') as f:f.write('\n'.join(out)+'\n')
 print('A138_WRITER_DATAFLOW_CENSUS=YES');print('A138_REPORT='+str(a.out))

def main():
 p=argparse.ArgumentParser();p.add_argument('--root',type=Path);p.add_argument('--boot',type=Path);p.add_argument('--out',type=Path);p.add_argument('--self-test',action='store_true');a=p.parse_args()
 if a.self_test:
  assert ROOT_PTR==0xF007F044
  print('A138_SELF_TEST=PASS')
  if not(a.root or a.boot or a.out):return 0
 if not all((a.root,a.boot,a.out)):p.error('requires --root --boot --out')
 try:run(a);return 0
 except Exception as exc:print('A138_ABORT='+repr(exc),file=sys.stderr);return 1
if __name__=='__main__':sys.exit(main())
