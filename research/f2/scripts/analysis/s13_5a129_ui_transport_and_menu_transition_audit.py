#!/usr/bin/env python3
"""S13.5A.129: narrow interworking/transition audit after A128. STRICTLY OFFLINE.
Loads exactly the three SHA-pinned canonical images. Emits a new TXT, never edits ROM.
Looks at the ARM veneer 0x102FC624, its literal destination, and ALICE helper
0x10347432, with CFG-limited code and evidence gates. Not a proof of key OK.
"""
from __future__ import annotations
import argparse, hashlib, importlib.util, struct, sys
from collections import deque
from pathlib import Path

A121='s13_5a121_boot_postselect_target_cfg_audit.py'
CALL_TRANSPORT=0x102EF48A; VENEER=0x102FC624
FOLLOWUP_CALL=0x10387DD4; FOLLOWUP_TARGET=0x10347432
MAX_INS=350; SPAN=0x900

def prior():
    p=Path(__file__).with_name(A121)
    if not p.is_file(): raise RuntimeError('DEPENDENCY_A121_MISSING')
    s=importlib.util.spec_from_file_location('a121_shared_for_129',p)
    m=importlib.util.module_from_spec(s);s.loader.exec_module(m)
    return m

def make_md(arm):
    from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_THUMB, CS_MODE_LITTLE_ENDIAN
    md=Cs(CS_ARCH_ARM,(CS_MODE_ARM if arm else CS_MODE_THUMB)|CS_MODE_LITTLE_ENDIAN)
    md.detail=True
    return md

def one(md,data,base,addr):
    if not base <= addr < base+len(data): return None
    return next(md.disasm(data[addr-base:addr-base+4],addr,1),None)

def op_dst(ins):
    from capstone.arm import ARM_OP_IMM
    return (ins.operands[-1].imm & 0xffffffff) if ins.operands and ins.operands[-1].type==ARM_OP_IMM else None

def walk(data,base,entry):
    md=make_md(False); queue=deque([entry]); seen={};edges=[];limits=[]; literals=[]
    while queue and len(seen)<MAX_INS:
        addr=queue.popleft()
        if addr in seen:continue
        if not (entry<=addr<entry+SPAN and base<=addr<base+len(data)):
            limits.append(f'OUTSIDE_FUNCTION_WINDOW=0x{addr:08X}');continue
        ins=one(md,data,base,addr)
        if ins is None:limits.append(f'DECODE_FAILED=0x{addr:08X}');continue
        seen[addr]=ins
        mnemonic=ins.mnemonic.lower().split('.')[0]; ops=ins.op_str.lower().replace(' ',''); dest=op_dst(ins)
        if mnemonic=='ldr':
            from capstone.arm import ARM_OP_MEM, ARM_REG_PC
            if len(ins.operands)>1 and ins.operands[1].type==ARM_OP_MEM and ins.operands[1].mem.base==ARM_REG_PC:
                cell=((addr+4)&~3)+ins.operands[1].mem.disp
                val=struct.unpack_from('<I',data,cell-base)[0] if base<=cell<=base+len(data)-4 else None
                literals.append((addr,cell,val))
        nextaddr=addr+ins.size
        if (mnemonic=='pop' and 'pc' in ops) or (mnemonic=='bx' and ops=='lr'):
            edges.append((addr,'RETURN',None));continue
        if mnemonic in ('bl','blx'):
            edges.append((addr,'DIRECT_CALL' if dest is not None else 'INDIRECT_CALL',dest));queue.append(nextaddr);continue
        if mnemonic in ('b','beq','bne','bge','bgt','blt','ble','bcs','bcc','bhi','bls','bmi','bpl','cbz','cbnz'):
            cond=mnemonic!='b';edges.append((addr,'CONDITIONAL' if cond else 'JUMP',dest))
            if dest is not None:queue.append(dest)
            else:limits.append(f'UNKNOWN_BRANCH_DEST=0x{addr:08X}')
            if cond:queue.append(nextaddr)
            continue
        if mnemonic in ('bx','tbb','tbh') or (mnemonic in ('ldr','mov','movs') and ops.startswith('pc,')):
            limits.append(f'INDIRECT_CONTROL=0x{addr:08X}');continue
        if mnemonic in ('svc','udf','bkpt'):
            limits.append(f'TRAP=0x{addr:08X}');continue
        queue.append(nextaddr)
    if queue:limits.append('INSTRUCTION_CAP_REACHED')
    return seen,edges,limits,literals

def self_test():
    assert VENEER%4==0 and (FOLLOWUP_TARGET&1)==0
    assert CALL_TRANSPORT == 0x102EF48A and FOLLOWUP_CALL==0x10387DD4
    assert struct.unpack('<I',bytes.fromhex('04f01fe5'))[0]==0xe51ff004
    print('A129_SELF_TEST=PASS_ADDRESSES_ARM_VENEER_OPCODE_AND_GATES')

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--self-test',action='store_true');p.add_argument('--root',type=Path)
    p.add_argument('--boot',type=Path);p.add_argument('--out',type=Path)
    a=p.parse_args()
    if a.self_test:
        self_test()
        if not (a.root or a.boot or a.out):return 0
    if not(a.root and a.boot and a.out):p.error('--root --boot --out required')
    try:
        m=prior()
        alice=m.assert_canonical(a.root/'research/f2/work/extracted/altice_alice/alice-py.bin','ALICE',m.ALICE_SIZE,m.ALICE_SHA)
        z=m.assert_canonical(a.root/'research/f2/work/extracted/altice_platform/zimage.bin','ZIMAGE',m.ZIMAGE_SIZE,m.ZIMAGE_SHA)
        boot=m.assert_canonical(a.boot,'BOOT_ZIMAGE',m.BOOT_SIZE,m.BOOT_SHA)
        m.check_inputs(alice,boot,z)
        thumb=make_md(False);arm=make_md(True)
        call=one(thumb,alice,m.ALICE_BASE,CALL_TRANSPORT)
        if call is None or call.mnemonic!='blx' or op_dst(call)!=VENEER:raise RuntimeError('A128_TRANSPORT_CALL_GUARD_FAIL')
        follow=one(thumb,alice,m.ALICE_BASE,FOLLOWUP_CALL)
        if follow is None or follow.mnemonic!='bl' or op_dst(follow)!=FOLLOWUP_TARGET:raise RuntimeError('A128_FOLLOWUP_CALL_GUARD_FAIL')
        av=one(arm,alice,m.ALICE_BASE,VENEER)
        if av is None:raise RuntimeError('VENEER_NOT_DECODABLE')
        off=VENEER-m.ALICE_BASE
        if alice[off:off+4]!=bytes.fromhex('04f01fe5'):raise RuntimeError('TRANSPORT_NOT_EXPECTED_ARM_LITERAL_VENEER')
        cell=VENEER+4;dest=struct.unpack_from('<I',alice,cell-m.ALICE_BASE)[0]
        norm=dest&~1;mode='THUMB' if dest&1 else 'ARM'
        imgs=[('ALICE',m.ALICE_BASE,alice),('BOOT_ZIMAGE',m.BOOT_BASE,boot),('ZIMAGE',m.ZIMAGE_BASE,z)]
        matched=next(((label,base,blob) for label,base,blob in imgs if base<=norm<base+len(blob)),None)
        lines=['S13.5A.129 — UI TRANSPORT VENEER AND SUBMENU TRANSITION BOUNDARY',
          'STRICTLY_OFFLINE=YES NO_USB_COM_PHONE_FLASH_PATCH_REPACK=YES',
          f'ALICE_GUARD=PASS SHA256={m.ALICE_SHA}',f'ZIMAGE_GUARD=PASS SHA256={m.ZIMAGE_SHA}',
          f'BOOT_ZIMAGE_GUARD=PASS SHA256={m.BOOT_SHA}',
          'A128_TRANSPORT_CALL_GUARD=PASS','A128_FOLLOWUP_CALL_GUARD=PASS',
          f'CALLSITE=0x{CALL_TRANSPORT:08X} RAW={call.bytes.hex()} DEST=0x{VENEER:08X}',
          f'ARM_VENEER=0x{VENEER:08X} RAW={av.bytes.hex()} MNEMONIC={av.mnemonic} {av.op_str}',
          f'VENEER_LITERAL_CELL=0x{cell:08X} POINTER=0x{dest:08X} MODE={mode}',
          f'NORMALIZED_DEST=0x{norm:08X} DEST_IMAGE={matched[0] if matched else "UNMAPPED_IN_THREE_IMAGES"}',
          '']
        if matched:
            label,base,blob=matched;md=thumb if mode=='THUMB' else arm
            i=one(md,blob,base,norm)
            lines.append(f'DEST_PREFIX={i.mnemonic} {i.op_str} RAW={i.bytes.hex()}' if i else 'DEST_PREFIX=DECODE_FAILED')
        lines += ['','=== A. 0x10347432 TRANSITION CALLEE CFG ===']
        ins,edges,notes,literals=walk(alice,m.ALICE_BASE,FOLLOWUP_TARGET)
        lines.append(f'FOLLOWUP_INSTRUCTIONS={len(ins)} CALL_BRANCH_EDGES={len(edges)} LIMIT_NOTES={len(notes)}')
        for addr,i in sorted(ins.items()):lines.append(f'  0x{addr:08X} {i.bytes.hex():10} {i.mnemonic:9} {i.op_str}')
        for addr,kind,target in edges:lines.append(f'EDGE=0x{addr:08X} TYPE={kind} TARGET={"0x%08X"%target if target is not None else "UNRESOLVED"}')
        for addr,cell,val in literals:lines.append(f'PC_LITERAL=0x{addr:08X} CELL=0x{cell:08X} VALUE={"0x%08X"%val if val is not None else "OUTSIDE_ALICE"}')
        for note in notes:lines.append('BOUNDARY_NOTE='+note)
        lines += ['','=== B. EVIDENCE AND PATCH BLOCKERS ===',
          'UI_TRANSPORT_AND_TRANSITION_CLASSIFIED=YES',
          'REAL_OK_KEY_TO_87ED=UNPROVEN','REAL_OK_KEY_TO_8928=UNPROVEN',
          'B702_SAFE_RELOCATION=UNPROVEN','AUDIO_NATIVE_PLAYBACK=UNPROVEN',
          'PATCH_FLASH_READY=NO',
          'NEXT=COMPARE_ACTUAL_EVENT_CONSUMER_OR_RUNTIME_OK_TRACE_AND_FIND_SAFE_MENU_STORAGE']
        a.out.parent.mkdir(parents=True,exist_ok=True)
        with a.out.open('x',encoding='utf-8',newline='\n') as f:f.write('\n'.join(lines)+'\n')
        print('A129_REPORT_CREATED='+str(a.out.resolve()))
        print('A129_RESULT=OFFLINE_TRANSPORT_AND_TRANSITION_BOUNDARY_REPORTED')
        return 0
    except Exception as e:
        print(f'A129_ABORT={type(e).__name__}: {e}',file=sys.stderr);return 1
if __name__=='__main__':sys.exit(main())
