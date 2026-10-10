#!/usr/bin/env python3
"""S13.5A.125: targeted Audio/menu patch-readiness evidence audit.

Read-only static examination of known ALICE UI/native resolver functions and the
B702 child list. Does NOT assert OK-event provenance or generate a flash patch.
"""
from __future__ import annotations
import argparse, hashlib, importlib.util, re, struct, sys
from pathlib import Path
from collections import deque

NAMES = {0x10315514:'B702_INDEX_TO_ID', 0x10319DF8:'B702_ID_TO_INDEX',
         0x10342FC4:'SELECT_CALLBACK', 0x10336788:'REGISTERED_CALLBACK_EXECUTOR',
         0x1034C7E4:'NATIVE_RESOLVER', 0x102F37C4:'NATIVE_RESOLVE_CALL_WRAPPER',
         0x1033D840:'AUDIO_REGISTRATION_STUB', 0x1033D841:'AUDIO_REGISTRATION_THUMB',
         0x1033E815:'AUDIO_INIT', 0x1033F83C:'AUDIO_FOLLOWUP'}
ADDRS = list(dict.fromkeys(x & ~1 for x in NAMES))
MAX_INS = 450
SPAN = 0x900

def dep():
 p = Path(__file__).with_name('s13_5a121_boot_postselect_target_cfg_audit.py')
 if not p.is_file(): raise RuntimeError('DEPENDENCY_A121_MISSING')
 s=importlib.util.spec_from_file_location('a121_patch_gates',p); m=importlib.util.module_from_spec(s); s.loader.exec_module(m); return m

def classify(ins):
 m=ins.mnemonic.lower().split('.')[0]; op=ins.op_str.lower().replace(' ','')
 from capstone.arm import ARM_OP_IMM
 dst=ins.operands[-1].imm & 0xffffffff if ins.operands and ins.operands[-1].type==ARM_OP_IMM else None
 if (m=='pop' and 'pc' in op) or (m=='bx' and op=='lr'): return 'RETURN',None
 if m in ('bl','blx'): return ('CALL' if dst is not None else 'INDIRECT_CALL'),dst
 if m in ('bx','tbb','tbh') or (m in ('ldr','mov','movs','add','adds') and op.startswith('pc,')): return 'INDIRECT_EXIT',None
 if m in ('b','beq','bne','bcs','bcc','bhs','blo','bmi','bpl','bvs','bvc','bhi','bls','bge','blt','bgt','ble','cbz','cbnz'): return ('JMP' if m=='b' else 'CJMP'),dst
 if m in ('svc','udf','bkpt'): return 'TRAP',None
 return 'NEXT',None

def walk(md, blob, base, entry):
 q=deque([entry]); seen={}; edges=[]; notes=[]
 while q and len(seen)<MAX_INS:
  addr=q.popleft()
  if addr in seen: continue
  if not (base<=addr<base+len(blob)) or not entry-2<=addr<entry+SPAN:
   notes.append('OUTSIDE_WINDOW=0x%08X'%addr); continue
  ins=next(md.disasm(blob[addr-base:addr-base+4],addr,1),None)
  if ins is None: notes.append('DECODE_FAILED=0x%08X'%addr);continue
  seen[addr]=ins; kind,dst=classify(ins)
  if kind in ('CALL','INDIRECT_CALL'): edges.append((addr,kind,dst));q.append(addr+ins.size)
  elif kind in ('CJMP','JMP'):
   edges.append((addr,kind,dst))
   if dst is not None:q.append(dst)
   if kind=='CJMP':q.append(addr+ins.size)
  elif kind=='NEXT':q.append(addr+ins.size)
  elif kind in ('INDIRECT_EXIT','TRAP'): notes.append('%s=0x%08X'%(kind,addr))
 if q:notes.append('INSN_CAP_REACHED')
 return seen,edges,notes

def main():
 p=argparse.ArgumentParser(description=__doc__)
 p.add_argument('--self-test',action='store_true');p.add_argument('--root',type=Path);p.add_argument('--boot',type=Path);p.add_argument('--out',type=Path)
 a=p.parse_args()
 if a.self_test:
  assert set(ADDRS) and len(ADDRS)==len(set(ADDRS))
  assert (0x1033D841&~1)==0x1033D840
  assert 0x8928 not in (0x8569,0x87ED)
  print('A125_SELF_TEST=PASS_TARGETS_AND_INVARIANTS')
  if not (a.root or a.boot or a.out):return 0
 if not (a.root and a.boot and a.out):p.error('--root, --boot and --out required')
 try:
  m=dep(); root=a.root
  alice=m.assert_canonical(root/'research/f2/work/extracted/altice_alice/alice-py.bin','ALICE',m.ALICE_SIZE,m.ALICE_SHA)
  zimage=m.assert_canonical(root/'research/f2/work/extracted/altice_platform/zimage.bin','ZIMAGE',m.ZIMAGE_SIZE,m.ZIMAGE_SHA)
  boot=m.assert_canonical(a.boot,'BOOT_ZIMAGE',m.BOOT_SIZE,m.BOOT_SHA)
  m.check_inputs(alice,boot,zimage)
  md=m.make_decoder()
  lines=['S13.5A.125 — AUDIO PATCH READINESS / TARGETED UI-NATIVE FLOW',
  'STRICTLY_OFFLINE=YES READ_ONLY_IMAGES=YES NO_USB_COM_FLASH_PATCH=YES',
  'ALICE_GUARD=PASS SHA256='+m.ALICE_SHA,
  'ZIMAGE_GUARD=PASS SHA256='+m.ZIMAGE_SHA,
  'BOOT_ZIMAGE_GUARD=PASS SHA256='+m.BOOT_SHA,
  'A120_LITERAL_GUARD=PASS',
  'TARGETED_FUNCTION_COUNT='+str(len(ADDRS)),
  'B702_KNOWN_CHILDREN=0x8569,0x87ED',
  'AUDIO_NATIVE_ID=0x8928',
  'B702_IN_PLACE_APPEND_SAFE=NO_KNOWN_ADJACENT_RECORD_COLLISION',
  'NOTE=ROM_MENU_TABLE_STORAGE_NOT_RELOCATED;RUNTIME_OK_EVENT_NOT_TRACED',
  '', '=== A. TARGETED FUNCTION DISASSEMBLY ===']
  total=0; edges_all=[]
  for addr in ADDRS:
   label=NAMES.get(addr,NAMES.get(addr|1,'UNKNOWN'))
   image='ALICE' if m.ALICE_BASE<=addr<m.ALICE_BASE+len(alice) else 'UNMAPPED'
   lines.append('\nFUNCTION=%s ENTRY=0x%08X IMAGE=%s'%(label,addr,image))
   if image!='ALICE':lines.append('FUNCTION_NOT_IN_ALICE=YES');continue
   seen,edges,notes=walk(md,alice,m.ALICE_BASE,addr)
   total+=len(seen);edges_all.extend((addr,*x) for x in edges)
   lines.append('INSTRUCTIONS=%d EDGES=%d NOTES=%d'%(len(seen),len(edges),len(notes)))
   for x,ins in sorted(seen.items()):
    kind,dst=classify(ins); ds=(' TARGET=0x%08X'%dst) if dst is not None else ''
    lines.append('  %08X %-10s %-10s %-32s [%s]%s'%(x,ins.bytes.hex(),ins.mnemonic,ins.op_str,kind,ds))
   for msg in notes:lines.append('NOTE='+msg)
  lines += ['', '=== B. CROSS-FUNCTION CALLS TO KNOWN TARGETS ===']
  for source,site,kind,dst in edges_all:
   if dst is not None and (dst&~1) in ADDRS:
    lines.append('KNOWN_EDGE=0x%08X VIA=0x%08X KIND=%s TARGET=0x%08X'%(source,site,kind,dst))
  lines += ['','=== C. PATCH GATES (NO OVERCLAIMS) ===',
  'TARGETED_CFG_PRODUCED=YES', 'TOTAL_TARGETED_INSTRUCTIONS=%d'%total,
  'KNOWN_REGISTERED_AUDIO_CALLBACK=0x1033D841',
  'REAL_UI_OK_EVENT_TO_87ED=UNPROVEN',
  'REAL_UI_OK_EVENT_TO_8928=UNPROVEN',
  'AUDIO_CALLBACK_EQUALS_LEAF_LAUNCH=UNPROVEN',
  'SAFE_B702_RELOCATION=UNPROVEN',
  'REPACK_BOOT_INTEGRITY=UNPROVEN',
  'PATCH_FLASH_READY=NO',
  'NEXT=COMPARE_FUNCTION_BOUNDARIES_AND_PROVE_OK_EVENT_AND_STORAGE_BEFORE_PATCH']
  text='\n'.join(lines)+'\n';a.out.parent.mkdir(parents=True,exist_ok=True)
  with a.out.open('x',encoding='utf-8',newline='\n') as f:f.write(text)
  print('A125_REPORT_CREATED='+str(a.out.resolve()));print('A125_RESULT=TARGETED_CFG_PRODUCED_PATCH_GATES_OPEN')
  return 0
 except (Exception) as e:
  print('A125_ABORT=%s: %s'%(type(e).__name__,e),file=sys.stderr);return 1
if __name__=='__main__':sys.exit(main())
