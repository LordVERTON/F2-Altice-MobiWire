#!/usr/bin/env python3
"""S13.5A.128 — selected ID -> UI continuation / following callback gates.

Static read-only audit. Does not prove real key OK, native MP3 launch or safe patch.
Requires sibling A121 script and Capstone installed in the Windows Python venv.
"""
from __future__ import annotations
import argparse
import hashlib
import importlib.util
import struct
import sys
from collections import deque
from pathlib import Path

TARGETS = {
    0x10345268: 'SELECTED_ID_TO_INDEX_AND_FOLLOWUP',
    0x10387D94: 'POST_CONTINUATION_FOLLOWUP',
    0x102EF44C: 'UI_MESSAGE_CONSTRUCTOR',
    0x10319DF8: 'ID_TO_INDEX_CONTROL',
}
ANCHORS = {
    0x10345268: 'f8b5',
    0x10345276: '018b',       # ldrh r1,[r0,#0x18]
    0x10345282: 'd4f7b9fd',  # bl ID->INDEX
    0x10345296: 'aaf7d9f8',  # bl UI message
    0x103452AC: '42f072fd',  # bl followup
    0x103453B2: 'aaf74bf8',
    0x102EF48A: '0df0cce8',  # BLX to UI platform transport
}
IMAGE_ID = 0x87ED
AUDIO_ID = 0x8928
FUNC_WINDOW = 0x500
FUNC_INS_CAP = 350


def a121():
    path = Path(__file__).with_name('s13_5a121_boot_postselect_target_cfg_audit.py')
    if not path.is_file():
        raise RuntimeError('REQUIRED_SIBLING_A121_MISSING')
    spec = importlib.util.spec_from_file_location('f2_a121_common_128', path)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def guard_anchors(blob, base):
    for address, hx in ANCHORS.items():
        raw = bytes.fromhex(hx)
        if blob[address-base:address-base+len(raw)] != raw:
            raise RuntimeError(f'A127_ANCHOR_MISMATCH={address:#x}')


def classify(ins):
    from capstone.arm import ARM_OP_IMM
    op = ins.op_str.lower().replace(' ', '')
    mnem = ins.mnemonic.lower().split('.')[0]
    dst = None
    if ins.operands and ins.operands[-1].type == ARM_OP_IMM:
        dst = ins.operands[-1].imm & 0xffffffff
    if mnem == 'pop' and 'pc' in op or mnem == 'bx' and op == 'lr':
        return 'RETURN', None
    if mnem in ('bl', 'blx'):
        return 'CALL' if dst is not None else 'INDIRECT_CALL', dst
    if mnem in ('bx','tbb','tbh') or (mnem in ('ldr','mov','movs','add','adds') and op.startswith('pc,')):
        return 'INDIRECT_EXIT', None
    if mnem in ('b', 'beq','bne','bcs','bcc','bhs','blo','bmi','bpl','bvs','bvc',
                'bhi','bls','bge','blt','bgt','ble','cbz','cbnz'):
        return ('JUMP' if mnem == 'b' else 'CONDITIONAL'), dst
    if mnem in ('svc','udf','bkpt'):
        return 'TRAP', None
    return 'NEXT', None


def pc_literal(ins, blob, base):
    from capstone.arm import ARM_OP_MEM, ARM_REG_PC
    if ins.mnemonic.split('.')[0] != 'ldr' or len(ins.operands) < 2:
        return None
    mem = ins.operands[1]
    if mem.type != ARM_OP_MEM or mem.mem.base != ARM_REG_PC:
        return None
    cell = ((ins.address + 4) & ~3) + mem.mem.disp
    if not (base <= cell <= base + len(blob) - 4):
        return (cell, None)
    return (cell, struct.unpack_from('<I', blob, cell-base)[0])


def walk(md, blob, base, entry):
    pending = deque([entry]); seen = {}; edges=[]; literals=[]; problems=[]; exits=[]
    hi = min(entry + FUNC_WINDOW, base + len(blob))
    while pending and len(seen) < FUNC_INS_CAP:
        address = pending.popleft()
        if address in seen: continue
        if not (entry <= address < hi):
            problems.append(f'OUT_OF_FUNCTION_BOUND=0x{address:08X}')
            continue
        ins = next(md.disasm(blob[address-base:address-base+4], address, count=1), None)
        if ins is None:
            problems.append(f'DECODE_FAILED=0x{address:08X}')
            continue
        seen[address] = ins
        k, target = classify(ins)
        literal = pc_literal(ins, blob, base)
        if literal is not None: literals.append((address, *literal))
        if k == 'RETURN': exits.append(address)
        elif k in ('TRAP','INDIRECT_EXIT'):
            problems.append(f'{k}=0x{address:08X}')
        elif k in ('CALL','INDIRECT_CALL'):
            edges.append((address,k,target)); pending.append(address+ins.size)
        elif k in ('CONDITIONAL','JUMP'):
            edges.append((address,k,target))
            if target is not None: pending.append(target)
            else: problems.append(f'BRANCH_UNRESOLVED=0x{address:08X}')
            if k == 'CONDITIONAL': pending.append(address+ins.size)
        else: pending.append(address+ins.size)
    if pending: problems.append('FUNCTION_INSTRUCTION_LIMIT_REACHED')
    return seen, edges, literals, exits, problems


def describe_memory(ins):
    op = ins.op_str.lower()
    if '[' in op or ins.mnemonic.lower().startswith(('ldm','stm','push','pop')):
        return f'MEMORY=0x{ins.address:08X} {ins.mnemonic} {ins.op_str}'
    return None


def create_report(alice, boot, zimage, m):
    m.check_inputs(alice,boot,zimage)
    guard_anchors(alice,m.ALICE_BASE)
    md = m.make_decoder()
    lines = [
        'S13.5A.128 — SELECTED ID / UI EVENT GATE AND NEXT HANDLER',
        'STRICTLY_OFFLINE=YES NO_USB_COM_DEVICE_PATCH_FLASH_REPACK=YES',
        f'ALICE_GUARD=PASS SHA256={m.ALICE_SHA}',
        f'ZIMAGE_GUARD=PASS SHA256={m.ZIMAGE_SHA}',
        f'BOOT_ZIMAGE_GUARD=PASS SHA256={m.BOOT_SHA}',
        'A127_SEVEN_ANCHOR_GUARD=PASS',
        f'CONTROL_IMAGE=0x{IMAGE_ID:04X} AUDIO_ID=0x{AUDIO_ID:04X}',
        'CAUTION=BOUNDED_STATIC_CFG_NOT_REAL_KEY_EVENT_NOT_AUDIO_PLAYBACK',
        '', '=== A. EXACT SELECTED-ID CONTROL AND HANDOFF ===',
        'SELECTED_ID_READ=0x10345276 DESCRIPTOR_OFFSET=0x18',
        'ID_TO_INDEX=0x10345282 TARGET=0x10319DF8',
        'UI_CONTINUATION=0x10345296 TARGET=0x102EF44C',
        'FOLLOWUP=0x103452AC TARGET=0x10387D94 CONDITIONAL=YES',
    ]
    for entry,name in TARGETS.items():
        seen,edges,literals,exits,problems=walk(md,alice,m.ALICE_BASE,entry)
        lines += ['', f'=== B. {name} ENTRY=0x{entry:08X} ===',
                  f'INSTRUCTIONS={len(seen)} CALL_BRANCH_EDGES={len(edges)} LITERALS={len(literals)} RETURNS={len(exits)} NOTES={len(problems)}']
        for addr,ins in sorted(seen.items()):
            k,target=classify(ins)
            t=f' TARGET=0x{target:08X}' if target is not None else ''
            lines.append(f'0x{addr:08X} {ins.bytes.hex():10} {ins.mnemonic:10} {ins.op_str:34} [{k}]{t}')
        for src,kind,dst in edges:
            lines.append(f'EDGE=0x{src:08X} KIND={kind} TARGET={f"0x{dst:08X}" if dst is not None else "UNKNOWN"}')
        for source,cell,value in literals:
            lines.append(f'PC_LITERAL_USE=0x{source:08X} CELL=0x{cell:08X} VALUE={f"0x{value:08X}" if value is not None else "OUTSIDE_ALICE"}')
        for addr in sorted(seen):
            mem=describe_memory(seen[addr])
            if mem: lines.append(mem)
        for issue in problems: lines.append('NOTE='+issue)
    lines += ['', '=== C. PATCH GATES ===',
        'A128_SELECTED_ID_FLOW_CLASSIFIED=YES',
        'REAL_KEY_OK_TO_87ED=UNPROVEN',
        'REAL_KEY_OK_TO_8928=UNPROVEN',
        'AUDIO_REGISTRATION_CALLBACK_IS_LAUNCH=UNPROVEN',
        'SAFE_B702_ARRAY_RELOCATION=UNPROVEN',
        'PATCH_FLASH_READY=NO',
        'NEXT=REVIEW_FOLLOWUP_10387D94_AND_UI_PLATFORM_TRANSPORT_102FC624_FOR_EVENT_SEMANTICS',
    ]
    return '\n'.join(lines)+'\n'


def self_test():
    assert len(ANCHORS) == 7
    assert IMAGE_ID != AUDIO_ID and 0x10345268 in TARGETS
    try:
        guard_anchors(bytes(0x200000),0x1024EC00)
    except RuntimeError as exc:
        assert 'A127_ANCHOR_MISMATCH' in str(exc)
    else: raise AssertionError('anchor guard failed to reject mismatched fixture')
    print('A128_SELF_TEST=PASS_ANCHORS_AND_BOUNDARIES')


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--root',type=Path)
    p.add_argument('--boot',type=Path)
    p.add_argument('--out',type=Path)
    p.add_argument('--self-test',action='store_true')
    args=p.parse_args()
    if args.self_test:
        self_test()
        if not (args.root or args.boot or args.out): return 0
    if not (args.root and args.boot and args.out):
        p.error('All of --root --boot --out required')
    try:
        m=a121()
        alice=m.assert_canonical(args.root/'research/f2/work/extracted/altice_alice/alice-py.bin','ALICE',m.ALICE_SIZE,m.ALICE_SHA)
        zimage=m.assert_canonical(args.root/'research/f2/work/extracted/altice_platform/zimage.bin','ZIMAGE',m.ZIMAGE_SIZE,m.ZIMAGE_SHA)
        boot=m.assert_canonical(args.boot,'BOOT_ZIMAGE',m.BOOT_SIZE,m.BOOT_SHA)
        output=create_report(alice,boot,zimage,m)
        args.out.parent.mkdir(parents=True,exist_ok=True)
        with args.out.open('x',encoding='utf-8',newline='\n') as fp: fp.write(output)
        print('A128_REPORT_CREATED='+str(args.out.resolve()))
        print('A128_RESULT=SELECTED_ID_FLOW_CLASSIFIED_NOT_PATCH_READY')
        return 0
    except Exception as exc:
        print(f'A128_ABORT={type(exc).__name__}: {exc}',file=sys.stderr)
        return 1

if __name__=='__main__': sys.exit(main())
