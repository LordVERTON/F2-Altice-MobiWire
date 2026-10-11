#!/usr/bin/env python3
"""S13.5A.144 — conservative offline ROM padding inventory, not free-space proof.

Reads SHA-pinned images, writes only an exclusive TXT report. No firmware edits,
no patch bytes, no device access. Constant bytes are NEVER classified as safe.
"""
from __future__ import annotations
import argparse,hashlib,struct,sys
from pathlib import Path

META={
 'ALICE':('research/f2/work/extracted/altice_alice/alice-py.bin',0x157BB4,'7246242b67afae0d13104452bc3257827cb778119b54e7a26fb7fb55993697ea'),
 'ZIMAGE':('research/f2/work/extracted/altice_platform/zimage.bin',0x185E98,'85fba8c8ae8161e4c1f8ced7983ec30d48c54ab10e51c69fcdfb900aca220954'),
 'BOOT_ZIMAGE':(None,0x4B06C,'aa070292e9c1685eddb12080b3f0bbca763102adaf085016b4e503a3930b4c3e')}
BASE=0xF023CA50;RECORDS=0xF0378760;DESC=0xF037C08C;TOTAL=895;RANGES=0xF037BF54

def need(v,why):
 if not v:raise RuntimeError(why)
def load(path,size,sha):
 need(path.is_file(),'MISSING_IMAGE='+str(path));b=path.read_bytes()
 need(len(b)==size and hashlib.sha256(b).hexdigest()==sha,'CANONICAL_IMAGE_GUARD_FAILED='+str(path));return b
def u16(z,p):return struct.unpack_from('<H',z,p-BASE)[0]
def u32(z,p):return struct.unpack_from('<I',z,p-BASE)[0]
def overlap(a,b,c,d):return a<d and c<b

def runs(z,n=6):
 """Maximal FF/00 runs, aligned candidate starts only, no false free labels."""
 out=[];i=0
 while i<len(z):
  c=z[i]
  if c not in (0,255):i+=1;continue
  j=i+1
  while j<len(z) and z[j]==c:j+=1
  if j-i>=n:out.append((i,j,c))
  i=j
 return out

def run(args):
 blobs={}
 for key,(rel,size,sha) in META.items():
  path=args.boot if rel is None else args.root/rel
  blobs[key]=load(path,size,sha)
 z=blobs['ZIMAGE'];need(u32(z,DESC)==RECORDS and u32(z,DESC+4)==RANGES and u16(z,DESC+8)==52,'A111_DESCRIPTOR_ANCHOR_FAIL')
 b702=RECORDS+884*16;need(u16(z,b702)==0xB709 and u16(z,b702+2)==2 and u32(z,b702+12)==0xF0378720,'A111_B702_ANCHOR_FAIL')
 need(tuple(struct.unpack_from('<HH',z,0xF0378720-BASE))==(0x8569,0x87ED),'A111_CHILDREN_MISMATCH')
 # Known occupied intervals; other data/code/resource owners not comprehensively known.
 occupied=[(RECORDS,RECORDS+TOTAL*16,'RECORDS'),(RANGES,RANGES+52*6,'RANGES'),(DESC,DESC+12,'DESCRIPTOR')]
 invalid=[];count=0
 for idx in range(TOTAL):
  p=RECORDS+idx*16;c=u16(z,p+2);s=u32(z,p+12)
  if not c:continue
  e=s+c*2
  if s<BASE or e>BASE+len(z) or s&1:
   invalid.append(idx);continue
  occupied.append((s,e,f'CHILDREN_{idx}'));count+=1
 need(not invalid,'CHILD_RECORD_OUTSIDE_IMAGE')
 allruns=runs(z);candidates=[];discard=0
 for a,b,byte in allruns:
  # Reserve full run: any overlap with a known occupied interval is excluded.
  absolute_a=BASE+a;absolute_b=BASE+b
  if any(overlap(absolute_a,absolute_b,c,d) for c,d,_ in occupied):
   discard+=1;continue
  aligned=(absolute_a+1)&~1
  if aligned+6>absolute_b:continue
  # Only a bounded ranking, still unverified. Longer runs listed first.
  candidates.append((b-a,aligned,byte,a,b))
 candidates.sort(key=lambda x:(-x[0],x[1]));lines=[
  'S13.5A.144 — B702 ROM CONSTANT-RUN / KNOWN-OWNERSHIP EXCLUSION SURVEY',
  'STRICTLY_OFFLINE=YES NO_USB_COM_PHONE_PATCH_FLASH_REPACK=YES',
  'NO_ROM_MODIFICATION=YES NO_PATCH_BYTES_EMITTED=YES',
  'ALICE_GUARD=PASS','ZIMAGE_GUARD=PASS','BOOT_ZIMAGE_GUARD=PASS',
  'A111_B702_STATIC_ANCHORS=PASS',
  'METHOD=MAXIMAL_FF_00_RUNS_EXCLUDING_ALL_KNOWN_STATIC_RECORDS_RANGES_DESCRIPTOR_AND_CHILD_ARRAYS',
  'IMPORTANT=UNCLASSIFIED_CODE_RESOURCES_REFERENCES_AND_FLASH_PACKING_MAY_OCCUPY_EVERY_LISTED_REGION',
  f'KNOWN_CHILD_ARRAYS={count}',f'EXCLUDED_KNOWN_INTERVALS={len(occupied)}',
  f'FF_00_RUNS_GE_6={len(allruns)}',f'RUNS_OVERLAPPING_KNOWN_OWNERS={discard}',
  f'UNVERIFIED_RUNS_REMAINING={len(candidates)}',
  '=== UNVERIFIED CONSTANT RUNS (TOP 30 BY LENGTH; NOT CODE CAVES) ===']
 for ln,ptr,v,a,b in candidates[:30]:
  off=ptr-BASE
  before=z[max(0,off-8):off].hex();after=z[off+6:min(len(z),off+14)].hex()
  # literal XREF into candidate range; not exhaustive for computed pointers
  ptrbytes=struct.pack('<I',ptr)
  raw_xref=sum(x.count(ptrbytes) for x in blobs.values())
  lines.append(f'RUN_START=0x{BASE+a:08X} RUN_END=0x{BASE+b:08X} LEN={ln} BYTE={v:02X} ALIGNED6=0x{ptr:08X} RAW_U32_EXACT_XREF={raw_xref} BEFORE={before} AFTER={after} CLASS=UNVERIFIED')
 lines += ['CANDIDATES_ARE_SAFE=NO','ROM_FREE_SPACE_VERIFIED=NO','RELOCATION_POINTER_REBASE_VERIFIED=NO','RUNTIME_F007F044_ALIASES_STATIC_RECORDS=UNPROVEN','UI_OK_TO_AUDIO_LAUNCHER=UNPROVEN','FLASH_LAYOUT_CRC_AND_ROLLBACK_VALIDATED=NO','A144_PADDING_EXCLUSION_SURVEY=PASS','PATCH_FLASH_READY=NO','NEXT=CLASSIFY_ONE_CANDIDATE_FULL_ROM_OWNERSHIP_EXECUTABLE_RESOURCE_BOUNDARIES_AND_RUNTIME_MAPPING_BEFORE_OFFLINE_PATCH']
 args.out.parent.mkdir(parents=True,exist_ok=True)
 with args.out.open('x',encoding='utf-8') as f:f.write('\n'.join(lines)+'\n')
 print('A144_PADDING_EXCLUSION_SURVEY=PASS');print('A144_REPORT='+str(args.out))

def main():
 p=argparse.ArgumentParser();p.add_argument('--root',type=Path);p.add_argument('--boot',type=Path);p.add_argument('--out',type=Path);p.add_argument('--self-test',action='store_true');a=p.parse_args()
 if a.self_test:
  assert runs(b'\x01\xff'*3+b'\x00'*7+b'\x12')==[(6,13,0)]
  assert overlap(2,5,4,6) and not overlap(2,4,4,6)
  assert RECORDS+884*16==0xF037BEA0
  print('A144_SELF_TEST=PASS')
  if not(a.root or a.boot or a.out):return 0
 if not all((a.root,a.boot,a.out)):p.error('requires --root --boot --out')
 try:run(a);return 0
 except Exception as e:print('A144_ABORT='+repr(e),file=sys.stderr);return 1
if __name__=='__main__':sys.exit(main())
