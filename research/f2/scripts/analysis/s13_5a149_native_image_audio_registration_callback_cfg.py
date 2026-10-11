#!/usr/bin/env python3
"""A149: bounded differential CFG of native 87ED/8928 registration callbacks.
Offline only. Does NOT prove physical OK action, callback invocation or MP3 playback.
"""
import argparse, hashlib, struct, sys
from collections import deque
from pathlib import Path

ALICE_BASE=0x1024EC00
ALICE_SIZE=0x157BB4
ALICE_SHA='7246242b67afae0d13104452bc3257827cb778119b54e7a26fb7fb55993697ea'
Z_BASE=0xF023CA50
Z_SIZE=0x185E98
Z_SHA='85fba8c8ae8161e4c1f8ced7983ec30d48c54ab10e51c69fcdfb900aca220954'
BOOT_SIZE=0x4B06C
BOOT_SHA='aa070292e9c1685eddb12080b3f0bbca763102adaf085016b4e503a3930b4c3e'
TABLE=0xF0345E68
ROWS=((14,0x87ED,0xF02F3F9D),(22,0x8928,0x1033D841))
NAME='s13_5a149_native_image_audio_registration_callback_cfg'

def guarded(path,size,digest,label):
    d=path.read_bytes()
    if len(d)!=size or hashlib.sha256(d).hexdigest()!=digest:
        raise RuntimeError(f'{label}_GUARD_FAIL size={len(d)} sha={hashlib.sha256(d).hexdigest()}')
    return d

def signed(value,bits):
    return value-(1<<bits) if value&(1<<(bits-1)) else value

def analyse(data,base,entry,limit_bytes=0x180,limit_instructions=180):
    from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB
    from capstone.arm import ARM_OP_IMM
    md=Cs(CS_ARCH_ARM,CS_MODE_THUMB)
    md.detail=True
    begin=entry&~1; end=min(begin+limit_bytes,base+len(data))
    q=deque([begin]); visited=set(); insns=[]; edges=[]; calls=[]; literals=[]; fault=[]
    while q and len(visited)<limit_instructions:
        addr=q.popleft()
        if addr in visited:continue
        if not (begin<=addr<end) or (addr-base)<0:
            edges.append((addr,'OUT_OF_BOUND'));continue
        off=addr-base
        it=list(md.disasm(data[off:off+4],addr,count=1))
        if not it:
            fault.append(f'UNDECODED_0x{addr:08X}');continue
        x=it[0]
        visited.add(addr)
        insns.append((x.address,x.mnemonic,x.op_str))
        m=x.mnemonic.lower().split('.')[0]
        imm=[op.imm for op in x.operands if op.type==ARM_OP_IMM]
        next_addr=x.address+x.size
        if m in ('bl','blx'):
            target=imm[-1] if imm else None
            calls.append((addr,m,target))
            q.append(next_addr)
        elif m in ('b','b.w') and imm:
            target=imm[-1]
            edges.append((addr,f'BRANCH_0x{target&0xffffffff:08X}'))
            if begin<=target<end:q.append(target)
        elif m.startswith('b') and m not in ('bic','bics','bkpt','bl','blx','bx','b') and imm:
            target=imm[-1]
            edges.append((addr,f'COND_{m}_0x{target&0xffffffff:08X}'))
            if begin<=target<end:q.append(target)
            q.append(next_addr)
        elif m in ('cbz','cbnz') and imm:
            target=imm[-1]
            edges.append((addr,f'COND_{m}_0x{target&0xffffffff:08X}'))
            if begin<=target<end:q.append(target)
            q.append(next_addr)
        elif m in ('pop','ldmia','ldm') and 'pc' in x.op_str.lower():
            edges.append((addr,'RETURN_PC'))
        elif m in ('bx','bxj'):
            edges.append((addr,'INDIRECT_BRANCH_OR_RETURN'))
        elif m in ('tbb','tbh'):
            edges.append((addr,'COMPUTED_BRANCH_NOT_FOLLOWED'))
        elif m=='ldr' and 'pc,' in x.op_str.lower():
            edges.append((addr,'PC_TRANSFER_UNRESOLVED'))
        else:q.append(next_addr)
        if m in ('ldr','ldrh','ldrb') and '[pc,' in x.op_str.lower():
            literals.append((addr,x.op_str))
    return {'insns':sorted(insns),'calls':calls,'edges':edges,'literals':literals,'fault':fault,'truncated':bool(q)}

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--self-test',action='store_true')
    p.add_argument('--root',type=Path)
    p.add_argument('--boot',type=Path)
    p.add_argument('--out',type=Path)
    a=p.parse_args()
    if a.self_test:
        assert Z_BASE <= TABLE < Z_BASE+Z_SIZE
        assert ALICE_BASE <= (ROWS[1][2]&~1) < ALICE_BASE+ALICE_SIZE
        assert Z_BASE <= (ROWS[0][2]&~1) < Z_BASE+Z_SIZE
        assert signed(0xffff,16)==-1
        print('A149_SELF_TEST=PASS')
        if not(a.root or a.boot or a.out):return 0
    if not all((a.root,a.boot,a.out)):
        p.error('--root, --boot, --out required')
    try:
        root=a.root
        alice=guarded(root/'research/f2/work/extracted/altice_alice/alice-py.bin',ALICE_SIZE,ALICE_SHA,'ALICE')
        z=guarded(root/'research/f2/work/extracted/altice_platform/zimage.bin',Z_SIZE,Z_SHA,'ZIMAGE')
        guarded(a.boot,BOOT_SIZE,BOOT_SHA,'BOOT_ZIMAGE')
        out=['S13.5A.149 - BOUNDED NATIVE REGISTRATION CALLBACK DIFFERENTIAL',
             'STRICTLY_OFFLINE=YES NO_USB_COM_PHONE_FLASH_PATCH_REPACK=YES',
             'ALICE_GUARD=PASS','ZIMAGE_GUARD=PASS','BOOT_ZIMAGE_GUARD=PASS',
             'SCOPE=ONLY_ROW14_IMAGE_AND_ROW22_AUDIO_CALLBACK_CFG_NO_GENERIC_XREF_SCAN',
             'LIMIT=STATIC_ENTRY_BOUND_0x180_MAX_180_INSTRUCTIONS_PER_CALLBACK',
             'WARNING=CALLBACK_TABLE_MEMBERS_ARE_REGISTRATION_NOT_PROVEN_UI_LAUNCHERS']
        for row,identity,ptr in ROWS:
            off=TABLE-Z_BASE+row*8
            gotid,gotptr=struct.unpack_from('<II',z,off)
            # Row format may be u16 ID plus 2-byte extra header. Show both.
            actualid=gotid&0xffff
            if actualid!=identity or gotptr!=ptr:
                raise RuntimeError(f'ROW{row}_ANCHOR_MISMATCH ID={actualid:04X} PTR={gotptr:08X}')
            out.append(f'ROW{row}_ANCHOR=PASS ID=0x{identity:04X} PTR=0x{ptr:08X}')
        for label,ptr,data,base in [('IMAGE_87ED',ROWS[0][2],z,Z_BASE),('AUDIO_8928',ROWS[1][2],alice,ALICE_BASE)]:
            r=analyse(data,base,ptr)
            out.extend(['',f'=== {label} ENTRY=0x{ptr:08X} ===',
                        f'REACHABLE_INSTRUCTIONS={len(r["insns"])} DIRECT_CALLS={len(r["calls"])}',
                        f'BRANCH_BOUNDARY_NOTES={len(r["edges"])} PC_LITERAL_LOADS={len(r["literals"])}',
                        f'TRUNCATED={str(r["truncated"]).upper()} DECODE_FAULTS={len(r["fault"])}',
                        '-- CFG INSTRUCTIONS --'])
            out.extend(f'0x{addr:08X} {m} {op}' for addr,m,op in r['insns'])
            out.append('-- DIRECT CALLS --')
            out.extend(f'0x{addr:08X} {mnemonic} -> '+(f'0x{target&0xffffffff:08X}' if target is not None else 'INDIRECT') for addr,mnemonic,target in r['calls'])
            out.append('-- BRANCHES / BOUNDARIES --')
            out.extend(f'0x{addr:08X} {reason}' for addr,reason in r['edges'])
            out.extend(r['fault'])
        out.extend(['','A149_NATIVE_CALLBACK_BOUNDED_CFG=PASS',
                    'IMAGE_OK_TO_CALLBACK_EXECUTION_PROVEN=NO',
                    'AUDIO_LAUNCH_PROVEN=NO',
                    'REGISTRY_BOOT_ALIAS=UNPROVEN',
                    'PATCH_FLASH_READY=NO',
                    'NEXT=EXAMINE_ONLY_DIFFERENTIAL_DIRECT_CALL_TARGETS_WITH_IMAGE_POSITIVE_CONTROL'])
        a.out.parent.mkdir(parents=True,exist_ok=True)
        with a.out.open('x',encoding='utf-8') as f:f.write('\n'.join(out)+'\n')
        print('A149_NATIVE_CALLBACK_BOUNDED_CFG=PASS')
        print('REPORT='+str(a.out.resolve()))
        return 0
    except Exception as exc:
        print(f'A149_ABORT={type(exc).__name__}: {exc}',file=sys.stderr)
        return 1
if __name__=='__main__':sys.exit(main())
