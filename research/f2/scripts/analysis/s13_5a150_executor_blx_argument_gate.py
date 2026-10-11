#!/usr/bin/env python3
"""A150: local, byte-grounded instruction audit of UI callback executor BLX.

Does not identify a physical OK key event, invoke firmware, or patch images.
Unlike A125's cross-function census, this audit enumerates exact reaching
instruction windows around each indirect BLX in 10336788 and tracks the
possible source register of its indirect target and ID input locally.
"""
import argparse, hashlib, sys
from pathlib import Path

ALICE_BASE=0x1024EC00
ALICE_SIZE=0x157BB4
ALICE_SHA='7246242b67afae0d13104452bc3257827cb778119b54e7a26fb7fb55993697ea'
ZIMAGE_SIZE=0x185E98
ZIMAGE_SHA='85fba8c8ae8161e4c1f8ced7983ec30d48c54ab10e51c69fcdfb900aca220954'
BOOT_SIZE=0x4B06C
BOOT_SHA='aa070292e9c1685eddb12080b3f0bbca763102adaf085016b4e503a3930b4c3e'
FUNC=0x10336788
# bounded to known callback executor only, not global callsite census
WINDOW=0xB0

def guard(p,size,sha,tag):
    b=Path(p).read_bytes();h=hashlib.sha256(b).hexdigest()
    if len(b)!=size or h!=sha:raise RuntimeError(f'{tag}_GUARD_FAIL size={len(b)} sha={h}')
    return b

def analysis(data):
    from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB
    from capstone.arm import ARM_OP_REG, ARM_OP_IMM
    md=Cs(CS_ARCH_ARM,CS_MODE_THUMB);md.detail=True
    off=FUNC-ALICE_BASE
    ins=list(md.disasm(data[off:off+WINDOW],FUNC))
    if not ins or ins[0].address!=FUNC:raise RuntimeError('EXECUTOR_ENTRY_DECODE_FAIL')
    lines=[]; calls=[]
    for x in ins:
        raw=data[x.address-ALICE_BASE:x.address-ALICE_BASE+x.size].hex()
        lines.append(f'{x.address:08X} {raw:<10} {x.mnemonic:<8} {x.op_str}')
        if x.mnemonic.startswith('blx') or x.mnemonic=='bl':
            direct=(len(x.operands)==1 and x.operands[0].type==ARM_OP_IMM)
            calls.append((x, direct))
    indirect=[(x,d) for x,d in calls if not d]
    # Evidence is expressly limited to a local window, not a control-flow graph.
    out=['S13.5A.150 — CALLBACK EXECUTOR INDIRECT CALL ARGUMENT BOUNDARY',
        'STRICTLY_OFFLINE=YES NO_USB_COM_PATCH_FLASH_REPACK=YES',
        'METHOD=LOCAL_THUMB_DECODE_NO_GLOBAL_XREF_CENSUS',
        'LIMIT=LINEAR_WINDOW_NOT_FULL_CFG_OR_ACTUAL_OK_TRACE',
        f'EXECUTOR=0x{FUNC:08X}',f'INSN_COUNT={len(ins)}',
        f'CALL_COUNT={len(calls)}',f'INDIRECT_BLX_COUNT={len(indirect)}','',
        '=== INSTRUCTION WINDOW ===',*lines,'','=== CALL BOUNDARIES ===']
    for x,d in calls:
        out.append(f'CALL=0x{x.address:08X} TYPE={"DIRECT" if d else "INDIRECT"} OPERAND={x.op_str}')
        if not d:
            before=[y for y in ins if y.address<x.address][-15:]
            out.append('PREVIOUS_15_INSTRUCTIONS:')
            out.extend(f'  {y.address:08X} {y.mnemonic} {y.op_str}' for y in before)
    found=any(x.mnemonic=='blx' and 'r4' in x.op_str for x,_ in indirect)
    out += ['A125_EXECUTOR_BLX_R4_ANCHOR='+('PASS' if found else 'NOT_FOUND'),
        'CALL_ARGUMENT_PROVENANCE=INSUFFICIENT_WITHOUT_REACHABLE_CFG_AND_CALL_CONTEXT',
        'ACTUAL_UI_OK_TO_IMAGE_87ED=UNPROVEN',
        'ACTUAL_UI_OK_TO_AUDIO_8928=UNPROVEN',
        'PATCH_FLASH_READY=NO',
        'A150_EXECUTOR_BOUNDARY_AUDIT='+('PASS' if found else 'INCONCLUSIVE'),
        'NEXT=USE_EXACT_BLX_R4_PC_AND_LOCAL_REGISTERS_TO_DESIGN_REACHABLE_TRACE_WITH_POSITIVE_CONTROL']
    return out,found

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--self-test',action='store_true')
    p.add_argument('--root',type=Path)
    p.add_argument('--boot',type=Path)
    p.add_argument('--out',type=Path)
    a=p.parse_args()
    if a.self_test:
        assert ALICE_BASE<FUNC<ALICE_BASE+ALICE_SIZE
        assert len(bytes.fromhex(ALICE_SHA))==32 and len(bytes.fromhex(ZIMAGE_SHA))==32
        print('A150_SELF_TEST=PASS')
        if not any((a.root,a.boot,a.out)):return 0
    if not all((a.root,a.boot,a.out)):p.error('--root --boot --out required')
    try:
        alice=guard(a.root/'research/f2/work/extracted/altice_alice/alice-py.bin',ALICE_SIZE,ALICE_SHA,'ALICE')
        guard(a.root/'research/f2/work/extracted/altice_platform/zimage.bin',ZIMAGE_SIZE,ZIMAGE_SHA,'ZIMAGE')
        guard(a.boot,BOOT_SIZE,BOOT_SHA,'BOOT_ZIMAGE')
        out,ok=analysis(alice)
        out=['ALICE_GUARD=PASS','ZIMAGE_GUARD=PASS','BOOT_ZIMAGE_GUARD=PASS',*out]
        a.out.parent.mkdir(parents=True,exist_ok=True)
        with a.out.open('x',encoding='utf-8') as f:f.write('\n'.join(out)+'\n')
        print('A150_REPORT_CREATED='+str(a.out))
        print('A150_EXECUTOR_BOUNDARY_AUDIT='+('PASS' if ok else 'INCONCLUSIVE'))
        return 0 if ok else 1
    except Exception as e:
        print('A150_ABORT='+repr(e),file=sys.stderr);return 1
if __name__=='__main__':sys.exit(main())
