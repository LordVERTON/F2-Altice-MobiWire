#!/usr/bin/env python3
"""A130: bound the verified ZIMAGE UI transport target and ALICE menu refresh callee.
Read-only canonical images, no device access, exclusive TXT report.
"""
from __future__ import annotations
import argparse, importlib.util, struct, sys
from collections import deque
from pathlib import Path

TARGETS=((0xF02B61FC,'ZIMAGE_UI_TRANSPORT'),(0x10340ADC,'ALICE_MENU_REFRESH'))
MAX_INS=420
SPAN=0x800

def dep():
    p=Path(__file__).with_name('s13_5a121_boot_postselect_target_cfg_audit.py')
    if not p.is_file(): raise RuntimeError('A121_DEPENDENCY_MISSING')
    sp=importlib.util.spec_from_file_location('a121_a130',p)
    m=importlib.util.module_from_spec(sp);sp.loader.exec_module(m);return m

def flow(ins):
    from capstone.arm import ARM_OP_IMM
    mn=ins.mnemonic.lower().split('.')[0]; op=ins.op_str.lower().replace(' ','')
    dst=(ins.operands[-1].imm & 0xffffffff) if ins.operands and ins.operands[-1].type==ARM_OP_IMM else None
    if mn=='pop' and 'pc' in op or mn=='bx' and op=='lr':return 'RETURN',None
    if mn in ('bl','blx'):return ('CALL' if dst is not None else 'INDIRECT_CALL'),dst
    if mn in ('bx','tbb','tbh') or (mn in ('ldr','mov','movs','add','adds') and op.startswith('pc,')):return 'INDIRECT_EXIT',None
    if mn in ('b','beq','bne','bcs','bcc','bhs','blo','bmi','bpl','bvs','bvc','bhi','bls','bge','blt','bgt','ble','cbz','cbnz'):return ('JMP' if mn=='b' else 'CJMP'),dst
    if mn in ('svc','udf','bkpt'):return 'TRAP',None
    return 'NEXT',None

def examine(md,blob,base,entry):
    q=deque([entry]);seen={};edges=[];notes=[];literals=[];memory=[]
    while q and len(seen)<MAX_INS:
        addr=q.popleft()
        if addr in seen:continue
        if not(base<=addr<base+len(blob)) or not(entry-2<=addr<entry+SPAN):
            notes.append('OUT_OF_FUNCTION_BOUND=0x%08X'%addr);continue
        ins=next(md.disasm(blob[addr-base:addr-base+4],addr,1),None)
        if ins is None:notes.append('DECODE_FAILED=0x%08X'%addr);continue
        seen[addr]=ins;k,d=flow(ins);n=addr+ins.size
        if '[' in ins.op_str:memory.append((addr,ins.mnemonic,ins.op_str))
        try:
            from capstone.arm import ARM_OP_MEM,ARM_REG_PC
            if ins.mnemonic.lower().split('.')[0]=='ldr' and len(ins.operands)>1 and ins.operands[1].type==ARM_OP_MEM and ins.operands[1].mem.base==ARM_REG_PC:
                cell=((addr+4)&~3)+ins.operands[1].mem.disp
                val=struct.unpack_from('<I',blob,cell-base)[0] if base<=cell<=base+len(blob)-4 else None
                literals.append((addr,cell,val))
        except (AttributeError,IndexError,ValueError):pass
        if k in ('CALL','INDIRECT_CALL'):
            edges.append((addr,k,d));q.append(n)
        elif k in ('CJMP','JMP'):
            edges.append((addr,k,d))
            if d is not None:q.append(d)
            if k=='CJMP':q.append(n)
        elif k=='NEXT':q.append(n)
        elif k in ('INDIRECT_EXIT','TRAP'):notes.append('%s=0x%08X'%(k,addr))
    if q:notes.append('INSTRUCTION_CAP_REACHED')
    return seen,edges,notes,literals,memory

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--root',type=Path);p.add_argument('--boot',type=Path);p.add_argument('--out',type=Path);p.add_argument('--self-test',action='store_true')
    a=p.parse_args()
    if a.self_test:
        assert TARGETS[0][0]==0xF02B61FC and TARGETS[1][0]==0x10340ADC
        assert (0xF02B61FD & ~1)==TARGETS[0][0]
        print('A130_SELF_TEST=PASS_TARGETS_AND_BOUNDS')
        if not(a.root or a.boot or a.out):return 0
    if not(a.root and a.boot and a.out):p.error('--root --boot --out required')
    try:
        m=dep();root=a.root
        alice=m.assert_canonical(root/'research/f2/work/extracted/altice_alice/alice-py.bin','ALICE',m.ALICE_SIZE,m.ALICE_SHA)
        z=m.assert_canonical(root/'research/f2/work/extracted/altice_platform/zimage.bin','ZIMAGE',m.ZIMAGE_SIZE,m.ZIMAGE_SHA)
        boot=m.assert_canonical(a.boot,'BOOT_ZIMAGE',m.BOOT_SIZE,m.BOOT_SHA)
        m.check_inputs(alice,boot,z)
        # A129 transport opcode/literal and ALICE followup edge guards.
        if alice[0x102FC624-m.ALICE_BASE:0x102FC628-m.ALICE_BASE]!=bytes.fromhex('04f01fe5') or struct.unpack_from('<I',alice,0x102FC628-m.ALICE_BASE)[0]!=0xF02B61FD:raise RuntimeError('A129_TRANSPORT_VENEER_GUARD_FAIL')
        if alice[0x10347442-m.ALICE_BASE:0x10347446-m.ALICE_BASE]!=bytes.fromhex('f9f74bfb'):raise RuntimeError('A129_REFRESH_CALL_GUARD_FAIL')
        md=m.make_decoder()
        lines=['S13.5A.130 — ZIMAGE UI TRANSPORT TARGET + ALICE MENU TRANSITION CALLEE',
          'STRICTLY_OFFLINE=YES NO_USB_COM_PHONE_FLASH_PATCH_REPACK=YES',
          'ALICE_GUARD=PASS SHA256='+m.ALICE_SHA,
          'BOOT_ZIMAGE_GUARD=PASS SHA256='+m.BOOT_SHA,
          'ZIMAGE_GUARD=PASS SHA256='+m.ZIMAGE_SHA,
          'A129_TRANSPORT_VENEER_GUARD=PASS','A129_REFRESH_CALL_GUARD=PASS',
          'A130_TARGETS=0xF02B61FC,0x10340ADC','LIMIT=BOUNDED_STATIC_CFG_NOT_RUNTIME_EVENT_OR_OK_TRACE']
        for addr,name in TARGETS:
            blob,base=(z,m.ZIMAGE_BASE) if name.startswith('ZIMAGE') else (alice,m.ALICE_BASE)
            insns,edges,notes,lits,mem=examine(md,blob,base,addr)
            lines += ['','=== FUNCTION %s ENTRY=0x%08X ==='%(name,addr),'INSTRUCTIONS=%d EDGES=%d NOTES=%d LITERALS=%d MEMORY_REFS=%d'%(len(insns),len(edges),len(notes),len(lits),len(mem))]
            for at,ins in sorted(insns.items()):
                k,d=flow(ins);lines.append('  0x%08X %-10s %-9s %-34s [%s]%s'%(at,ins.bytes.hex(),ins.mnemonic,ins.op_str,k,(' => 0x%08X'%d) if d is not None else ''))
            for at,k,d in edges:lines.append('EDGE=0x%08X KIND=%s TARGET=%s'%(at,k,('0x%08X'%d if d is not None else 'INDIRECT')))
            for at,cell,val in lits:lines.append('LITERAL=0x%08X CELL=0x%08X VALUE=%s'%(at,cell,('0x%08X'%val if val is not None else 'UNMAPPED')))
            for at,mn,ops in mem:lines.append('MEMORY=0x%08X %s %s'%(at,mn,ops))
            for n in notes:lines.append('NOTE='+n)
        lines += ['','A130_BOUNDED_CFG_PRODUCED=YES','REAL_OK_TO_IMAGE_87ED=UNPROVEN','REAL_OK_TO_AUDIO_8928=UNPROVEN','B702_RELOCATION_SAFE=UNPROVEN','PATCH_FLASH_READY=NO','NEXT=INTERPRET_TRANSPORT_CALLEE_AND_MENU_REFRESH_OR_STOP_IF_PLATFORM_GENERIC']
        a.out.parent.mkdir(parents=True,exist_ok=True)
        with a.out.open('x',encoding='utf-8',newline='\n') as f:f.write('\n'.join(lines)+'\n')
        print('A130_REPORT_CREATED='+str(a.out.resolve()))
        return 0
    except Exception as e:
        print('A130_ABORT=%s: %s'%(type(e).__name__,e),file=sys.stderr);return 1
if __name__=='__main__':sys.exit(main())
