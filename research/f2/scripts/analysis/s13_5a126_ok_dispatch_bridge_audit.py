#!/usr/bin/env python3
"""S13.5A.126 - selected UI continuation vs registered callback executor.

Read-only, offline, canonical-SHA guarded. Maps precise call edges and scans
ALICE direct Thumb BL/BLX callsites to the known registration executor and
selection continuation. Does NOT claim an OK event, Audio launch, or safe patch.
"""
from __future__ import annotations
import argparse, importlib.util, sys, struct
from pathlib import Path
from collections import deque

ROOT_TARGETS = {
    0x102EF44C: 'SELECTED_UI_CONTINUATION',
    0x10336788: 'REGISTERED_CALLBACK_EXECUTOR',
    0x1034C7E4: 'NATIVE_RESOLVER',
    0x10342FC4: 'SELECTION_CALLBACK',
}
TARGET_CALLS = set(ROOT_TARGETS) | {0x10315514, 0x102F37C4}

def dependency():
    p = Path(__file__).with_name('s13_5a121_boot_postselect_target_cfg_audit.py')
    if not p.is_file(): raise RuntimeError('A121_DEPENDENCY_MISSING')
    spec = importlib.util.spec_from_file_location('f2_a121_for_a126',p)
    module=importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module

def decoder():
    from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_LITTLE_ENDIAN
    md=Cs(CS_ARCH_ARM,CS_MODE_THUMB|CS_MODE_LITTLE_ENDIAN);md.detail=True
    return md

def branch(ins):
    from capstone.arm import ARM_OP_IMM
    m=ins.mnemonic.lower().split('.')[0]; op=ins.op_str.lower().replace(' ','')
    dest=None
    if ins.operands and ins.operands[-1].type==ARM_OP_IMM:
        dest=ins.operands[-1].imm & 0xffffffff
    if (m=='bx' and op=='lr') or (m=='pop' and 'pc' in op):return 'RETURN',None
    if m in ('bl','blx'):return ('CALL' if dest is not None else 'INDIRECT_CALL'),dest
    if m in ('b','beq','bne','bhs','blo','bcs','bcc','bge','blt','bgt','ble','bmi','bpl','bvs','bvc','bhi','bls','cbz','cbnz'):
        return ('JUMP' if m=='b' else 'CONDITIONAL'),dest
    if m in ('bx','tbb','tbh') or (m in ('ldr','mov','movs') and op.startswith('pc,')):return 'INDIRECT_EXIT',None
    if m in ('svc','udf','bkpt'):return 'TRAP',None
    return 'NEXT',None

def walk(blob,base,entry,md,span=0x900,cap=550):
    todo=deque([entry]);seen={};edges=[];notes=[]
    while todo and len(seen)<cap:
        addr=todo.popleft()
        if addr in seen:continue
        if addr < entry or addr>=entry+span or addr < base or addr+4>base+len(blob):
            notes.append('OUTSIDE_BOUND=0x%08X'%addr);continue
        ins=next(md.disasm(blob[addr-base:addr-base+4],addr,1),None)
        if ins is None: notes.append('DECODE_FAILED=0x%08X'%addr);continue
        seen[addr]=ins;k,d=branch(ins);nxt=addr+ins.size
        if k in ('CALL','INDIRECT_CALL'):
            edges.append((addr,k,d));todo.append(nxt)
        elif k in ('JUMP','CONDITIONAL'):
            edges.append((addr,k,d))
            if d is not None:todo.append(d)
            else:notes.append('UNRESOLVED_BRANCH=0x%08X'%addr)
            if k=='CONDITIONAL':todo.append(nxt)
        elif k=='NEXT':todo.append(nxt)
        elif k in ('INDIRECT_EXIT','TRAP'):notes.append('%s=0x%08X'%(k,addr))
    if todo:notes.append('CAP_REACHED')
    return seen,edges,notes

def calls_to(blob,base,targets,md):
    """Bounded exact direct-call references; no guess from ordinary data halfwords."""
    out=[]
    # True Thumb BL and BLX immediate are 32-bit aligned on halfword boundaries.
    for off in range(0,len(blob)-3,2):
        h1=struct.unpack_from('<H',blob,off)[0]
        if (h1 & 0xf800)!=0xf000:continue
        h2=struct.unpack_from('<H',blob,off+2)[0]
        if (h2 & 0xc000)!=0xc000:continue
        addr=base+off
        ins=next(md.disasm(blob[off:off+4],addr,1),None)
        if ins is None or ins.size!=4 or ins.mnemonic.split('.')[0] not in ('bl','blx'):continue
        k,d=branch(ins)
        if d is not None and (d & ~1) in targets:
            out.append((addr,ins.mnemonic,d & ~1,blob[off:off+4].hex()))
    return sorted(set(out))

def self_test():
    assert len(ROOT_TARGETS)==4
    assert 0x10336788 in TARGET_CALLS
    b=bytes.fromhex('00bf7047')
    assert struct.unpack_from('<H',b,0)[0]==0xbf00
    print('A126_SELF_TEST=PASS_STATIC_GATES')

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--root',type=Path);p.add_argument('--boot',type=Path)
    p.add_argument('--out',type=Path);p.add_argument('--self-test',action='store_true')
    a=p.parse_args()
    if a.self_test:
        self_test()
        if not (a.root or a.boot or a.out):return 0
    if not (a.root and a.boot and a.out):p.error('--root --boot --out required')
    try:
        m=dependency()
        alice=m.assert_canonical(a.root/'research/f2/work/extracted/altice_alice/alice-py.bin','ALICE',m.ALICE_SIZE,m.ALICE_SHA)
        zimage=m.assert_canonical(a.root/'research/f2/work/extracted/altice_platform/zimage.bin','ZIMAGE',m.ZIMAGE_SIZE,m.ZIMAGE_SHA)
        boot=m.assert_canonical(a.boot,'BOOT_ZIMAGE',m.BOOT_SIZE,m.BOOT_SHA)
        m.check_inputs(alice,boot,zimage)
        md=decoder()
        lines=['S13.5A.126 — OK-DISPATCH BRIDGE EVIDENCE; NOT A PATCH',
               'STRICTLY_OFFLINE=YES NO_USB_COM_PHONE_FLASH_PATCH_REPACK=YES',
               'ALICE_GUARD=PASS SHA256='+m.ALICE_SHA,
               'ZIMAGE_GUARD=PASS SHA256='+m.ZIMAGE_SHA,
               'BOOT_ZIMAGE_GUARD=PASS SHA256='+m.BOOT_SHA,
               'A120_LITERAL_GUARD=PASS',
               'SCOPE=FOUR_UI_EXECUTION_TARGETS_PLUS_EXACT_THUMB_CALLER_REFERENCES',
               'CONTROL_IMAGE_ID=0x87ED AUDIO_ID=0x8928',
               '', '=== A. CONCRETE FUNCTION CFG AND CALL EDGES ===']
        results={}
        for entry,label in ROOT_TARGETS.items():
            seen,edges,notes=walk(alice,m.ALICE_BASE,entry,md)
            results[entry]=(seen,edges,notes)
            lines.append('\nFUNCTION=%s ENTRY=0x%08X INSTRUCTIONS=%d EDGES=%d NOTES=%d'%(label,entry,len(seen),len(edges),len(notes)))
            for addr,ins in sorted(seen.items()):
                kind,dest=branch(ins)
                lines.append('  0x%08X %-10s %-9s %-32s [%s]%s'%(addr,ins.bytes.hex(),ins.mnemonic,ins.op_str,kind,(' => 0x%08X'%dest if dest is not None else '')))
            for src,kind,dest in edges:lines.append('EDGE_FROM=0x%08X TYPE=%s TARGET=%s'%(src,kind,'0x%08X'%dest if dest is not None else 'UNKNOWN'))
            for note in notes:lines.append('NOTE='+note)
        lines.append('\n=== B. EXACT DIRECT THUMB CALLER CANDIDATES (NOT EXECUTION PROOF) ===')
        refs=calls_to(alice,m.ALICE_BASE,TARGET_CALLS,md)
        for source,mnemonic,dest,raw in refs:
            lines.append('DIRECT_CALLSITE=0x%08X OPCODE=%s RAW=%s TARGET=0x%08X LABEL=%s'%(source,mnemonic,raw,dest,ROOT_TARGETS.get(dest,'OTHER_KNOWN')))
        lines.append('DIRECT_CALLSITE_COUNT=%d'%len(refs))
        lines.append('\n=== C. CONCLUSIONS / PATCH GATES ===')
        lines.append('TARGETED_UI_DISPATCH_AUDIT_PRODUCED=YES')
        lines.append('A126_CONCRETE_UI_EXECUTOR_CALLERS_FOUND=%d'%sum(d==0x10336788 for _,_,d,_ in refs))
        lines.extend(['THUMB_DIRECT_CALLS_ARE_CANDIDATES_ONLY=YES',
                      'REAL_OK_EVENT_TO_87ED=UNPROVEN_WITHOUT_EVENT_PROVENANCE',
                      'REAL_OK_EVENT_TO_8928=UNPROVEN',
                      'SAFE_B702_RELOCATION=UNPROVEN',
                      'NO_FIRMWARE_IMAGE_WRITTEN=YES',
                      'PATCH_FLASH_READY=NO',
                      'NEXT=REVIEW_CONCRETE_CALLSITES_AND_SELECTED_UI_CONTINUATION_BEFORE_DECIDING_PATCH_STRATEGY'])
        a.out.parent.mkdir(parents=True,exist_ok=True)
        with a.out.open('x',encoding='utf-8',newline='\n') as f:f.write('\n'.join(lines)+'\n')
        print('A126_REPORT_CREATED='+str(a.out.resolve()))
        print('A126_RESULT=TARGETED_UI_DISPATCH_AUDIT_PRODUCED')
        return 0
    except Exception as e:
        print('A126_ABORT=%s: %s'%(type(e).__name__,e),file=sys.stderr);return 1
if __name__=='__main__':sys.exit(main())
