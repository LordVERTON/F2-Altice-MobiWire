#!/usr/bin/env python3
"""S13.5A.131: bounded, read-only menu leaf predicate / refresh gates audit.

Standalone except existing canonical A121 loader in same scripts/analysis directory.
Does not patch images, query USB, or assert a physical OK-key path.
"""
from __future__ import annotations
import argparse, importlib.util, sys, struct
from collections import deque
from pathlib import Path

TARGETS = ((0x103452B8, 'MENU_ITEM_PREDICATE'), (0x10343050, 'REFRESH_PARENT_HELPER'),
           (0x103431BC, 'REFRESH_FINALIZER'))
ANCHORS = ((0x10340C64, bytes.fromhex('d4f756fc')), (0x10340C68, bytes.fromhex('04f026fb')),
           (0x10340C72, bytes.fromhex('a06c')), (0x10340C76, bytes.fromhex('f4dc')))


def load_a121():
    p = Path(__file__).with_name('s13_5a121_boot_postselect_target_cfg_audit.py')
    if not p.is_file(): raise RuntimeError('A121_DEPENDENCY_MISSING')
    spec=importlib.util.spec_from_file_location('f2_a121_dependency_for_a131',p)
    m=importlib.util.module_from_spec(spec); spec.loader.exec_module(m); return m


def decode_cfg(blob, base, entry, max_ins=300, max_span=0x700):
    from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_LITTLE_ENDIAN
    from capstone.arm import ARM_OP_IMM
    md=Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_LITTLE_ENDIAN); md.detail=True
    q=deque([entry]); seen={}; edges=[]; literals=[]; notes=[]
    while q and len(seen)<max_ins:
        a=q.popleft()
        if a in seen: continue
        if not (base<=a<base+len(blob) and entry<=a<entry+max_span):
            notes.append('OUTSIDE_BOUNDED_REGION=0x%08X'%a);continue
        ins=next(md.disasm(blob[a-base:a-base+4],a,1),None)
        if ins is None: notes.append('DECODE_FAILED=0x%08X'%a);continue
        seen[a]=ins; m=ins.mnemonic.lower().split('.')[0]; op=ins.op_str.lower().replace(' ','')
        dst=(ins.operands[-1].imm & 0xffffffff) if ins.operands and ins.operands[-1].type==ARM_OP_IMM else None
        if m=='ldr' and '[pc,' in op:
            import re
            z=re.search(r'\[pc,#(-?0x[0-9a-f]+|-?\d+)\]',op)
            if z:
                cell=((a+4)&~3)+int(z.group(1),0)
                if base<=cell<=base+len(blob)-4:
                    value=struct.unpack_from('<I',blob,cell-base)[0]
                    literals.append((a,cell,value))
        ret=(m=='pop' and 'pc' in op) or (m=='bx' and op=='lr')
        if ret: continue
        if m in ('bl','blx'):
            edges.append((a,'CALL' if dst is not None else 'INDIRECT_CALL',dst));q.append(a+ins.size)
        elif m in ('bx','tbb','tbh') or ((m in ('mov','movs','ldr','add','adds')) and op.startswith('pc,')):
            edges.append((a,'INDIRECT_EXIT',None))
        elif m=='b' or m in ('beq','bne','blo','bhs','bcs','bcc','bmi','bpl','bvs','bvc','bhi','bls','bge','blt','bgt','ble','cbz','cbnz'):
            typ='JMP' if m=='b' else 'CJMP';edges.append((a,typ,dst))
            if dst is not None:q.append(dst)
            if typ=='CJMP':q.append(a+ins.size)
        elif m in ('bkpt','udf','svc'):notes.append('TRAP=0x%08X'%a)
        else:q.append(a+ins.size)
    if q:notes.append('INSTRUCTION_LIMIT')
    return seen,edges,literals,notes


def run(args):
    a=load_a121();root=args.root
    alice=a.assert_canonical(root/'research/f2/work/extracted/altice_alice/alice-py.bin','ALICE',a.ALICE_SIZE,a.ALICE_SHA)
    zimage=a.assert_canonical(root/'research/f2/work/extracted/altice_platform/zimage.bin','ZIMAGE',a.ZIMAGE_SIZE,a.ZIMAGE_SHA)
    boot=a.assert_canonical(args.boot,'BOOT_ZIMAGE',a.BOOT_SIZE,a.BOOT_SHA)
    a.check_inputs(alice,boot,zimage)
    for addr,raw in ANCHORS:
        if alice[addr-a.ALICE_BASE:addr-a.ALICE_BASE+len(raw)]!=raw:
            raise RuntimeError('A130_LOOP_ANCHOR_MISMATCH_%08X'%addr)
    lines=['S13.5A.131 — MENU ITEM PREDICATE / REFRESH GATES',
           'STRICTLY_OFFLINE=YES NO_USB_COM_DEVICE_PATCH_FLASH=YES',
           'ALICE_GUARD=PASS SHA256='+a.ALICE_SHA,
           'ZIMAGE_GUARD=PASS SHA256='+a.ZIMAGE_SHA,
           'BOOT_ZIMAGE_GUARD=PASS SHA256='+a.BOOT_SHA,
           'A130_LOOP_ANCHORS=PASS',
           'SOURCE=TARGETED_CFG_FROM_KNOWN_REFRESH_LOOP_NOT_REAL_OK_EVENT',
           'LOOP=0x10340C64 INDEX_TO_ID_10315514;0x10340C68_PREDICATE_103452B8;COUNT_AT_DESCRIPTOR_PLUS_0x48']
    for entry,name in TARGETS:
        seen,edges,lits,notes=decode_cfg(alice,a.ALICE_BASE,entry)
        lines.extend(['','=== FUNCTION %s ENTRY=0x%08X ==='%(name,entry),
                      'INSTRUCTIONS=%d EDGES=%d LITERALS=%d NOTES=%d'%(len(seen),len(edges),len(lits),len(notes))])
        for addr,ins in sorted(seen.items()):
            lines.append('0x%08X %-10s %-9s %s'%(addr,ins.bytes.hex(),ins.mnemonic,ins.op_str))
        for addr,kind,dst in edges:lines.append('EDGE=0x%08X TYPE=%s TARGET=%s'%(addr,kind,'0x%08X'%dst if dst is not None else 'UNKNOWN'))
        for addr,cell,v in lits:lines.append('LITERAL=0x%08X CELL=0x%08X VALUE=0x%08X'%(addr,cell,v))
        for note in notes:lines.append('NOTE='+note)
    lines+=['','A131_TARGETED_CFG_PRODUCED=YES','REAL_OK_TO_87ED=UNPROVEN',
            'REAL_OK_TO_8928=UNPROVEN','SAFE_B702_RELOCATION=UNPROVEN',
            'PATCH_FLASH_READY=NO','NEXT=CLASSIFY_ITEM_PREDICATE_AND_POSITIVE_IMAGE_LEAF_ACTION;THEN_PREPARE_OFFLINE_PATCH_STORAGE_PLAN']
    args.out.parent.mkdir(parents=True,exist_ok=True)
    with args.out.open('x',encoding='utf8',newline='\n') as f:f.write('\n'.join(lines)+'\n')
    print('A131_REPORT_CREATED='+str(args.out));print('A131_TARGETED_CFG_PRODUCED=YES')


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--root',type=Path);p.add_argument('--boot',type=Path);p.add_argument('--out',type=Path);p.add_argument('--self-test',action='store_true')
    x=p.parse_args()
    if x.self_test:
        assert len(TARGETS)==3 and len(ANCHORS)==4
        assert all((z&1)==0 for z,_ in TARGETS)
        print('A131_SELF_TEST=PASS')
        if not(x.root or x.boot or x.out):return 0
    if not all((x.root,x.boot,x.out)):p.error('--root --boot --out required')
    try:run(x);return 0
    except Exception as e:print('A131_ABORT=%s: %s'%(type(e).__name__,e),file=sys.stderr);return 1

if __name__=='__main__':sys.exit(main())
