#!/usr/bin/env python3
"""S13.5A.108 — strictly offline CFG of only 0x1031C714, producer of F0115F66.

This is an investigation, NOT firmware modification. The pre-existing A.107 report
proves 0x10393796 BL 0x1031C714 immediately precedes 0x1039379C BL
0x1039570C which stores the returned low 16 bits to global F0115F66.

No USB/COM/phone access, no write/repack/flash, no global xrefs or menu scans.
Output is solely an exclusive-create UTF-8 text report in work/reports.
"""
from __future__ import annotations

import argparse
import hashlib
import io
import re
import struct
from collections import defaultdict, deque
from pathlib import Path

ALICE_BASE, ALICE_SIZE, ALICE_SHA = (
    0x1024EC00, 0x157BB4,
    '7246242b67afae0d13104452bc3257827cb778119b54e7a26fb7fb55993697ea',
)
ZIMAGE_BASE, ZIMAGE_SIZE, ZIMAGE_SHA = (
    0xF023CA50, 0x185E98,
    '85fba8c8ae8161e4c1f8ced7983ec30d48c54ab10e51c69fcdfb900aca220954',
)
START, END = 0x1031C714, 0x1031D714
CALLSITE, SETTER_SITE, SETTER = 0x10393796, 0x1039379C, 0x1039570C
GUARDS = {
    0x10393784: '01f08eff',   # preceding context caller, 103956A4
    0x10393788: '0c4d',       # literal 0x2E69 through r5
    0x10393790: '1100',       # movs r1,r2
    0x10393792: '2b00',       # movs r3,r5
    0x10393796: '88f7bdff',   # bl 1031C714
    0x1039379A: '0400',       # movs r4,r0
    0x1039379C: '01f0b6ff',   # bl 1039570C
    0x1039570C: '0149',       # literal global base
    0x1039570E: '4880',       # strh r0,[r1,#2]
    0x10395710: '7047',       # bx lr
    0x102EF5DC: '0148',       # A105 getter
    0x102EF5DE: '4088',       # ldrh r0,[r0,#2]
}
MAX_INSNS = 650
MAX_BLOCKS = 140
MAX_BLOCK_STEPS = 120
BRANCHES = {'b','beq','bne','bcs','bcc','bhs','blo','bmi','bpl','bvs','bvc',
            'bhi','bls','bge','blt','bgt','ble','cbz','cbnz'}


def abort(message: str) -> None:
    raise SystemExit('ABORT: ' + message)


def decode_thumb_bl(data: bytes, address: int) -> int:
    """Pure-Python decoding of the 32-bit Thumb BL encoding for guards/tests."""
    if len(data) != 4:
        raise ValueError('BL needs four bytes')
    hi, lo = struct.unpack('<HH', data)
    if (hi & 0xF800) != 0xF000 or (lo & 0xD000) != 0xD000:
        raise ValueError('not a Thumb BL')
    s = (hi >> 10) & 1
    j1, j2 = (lo >> 13) & 1, (lo >> 11) & 1
    i1, i2 = (1 ^ (j1 ^ s)), (1 ^ (j2 ^ s))
    imm = ((s << 24) | (i1 << 23) | (i2 << 22) |
           ((hi & 0x3FF) << 12) | ((lo & 0x7FF) << 1))
    if s:
        imm -= 1 << 25
    return (address + 4 + imm) & 0xFFFFFFFF


def self_test() -> None:
    assert decode_thumb_bl(bytes.fromhex('88f7bdff'), CALLSITE) == START
    assert decode_thumb_bl(bytes.fromhex('01f0b6ff'), SETTER_SITE) == SETTER
    assert decode_thumb_bl(bytes.fromhex('01f08eff'), 0x10393784) == 0x103956A4
    assert len(GUARDS) == 12
    try:
        decode_thumb_bl(bytes.fromhex('70470000'), CALLSITE)
    except ValueError:
        pass
    else:
        raise AssertionError('negative BL test failed')
    print('A108_SELF_TEST=PASS known BLs, negative BL, exact anchor metadata')


def load(path: Path, label: str, expected_size: int, expected_sha: str) -> bytes:
    if not path.is_file():
        abort(f'{label} missing: {path}')
    raw = path.read_bytes()
    digest = hashlib.sha256(raw).hexdigest()
    if len(raw) != expected_size or digest != expected_sha:
        abort(f'{label} canonical guard FAIL: size=0x{len(raw):X}, sha256={digest}')
    return raw


def chunk(raw: bytes, va: int, count: int = 4, base: int = ALICE_BASE) -> bytes | None:
    offset = va - base
    if offset < 0 or offset + count > len(raw):
        return None
    return raw[offset:offset+count]


def insn(md, raw: bytes, va: int):
    d = chunk(raw, va, 4)
    if d is None:
        return None
    seq = list(md.disasm(d, va, count=1))
    return seq[0] if seq and seq[0].address == va else None


def mnemonic(ins) -> str:
    return ins.mnemonic.lower().split('.')[0]


def target(ins):
    from capstone.arm import ARM_OP_IMM
    for arg in reversed(ins.operands):
        if arg.type == ARM_OP_IMM:
            return (int(arg.imm) & 0xFFFFFFFF) & ~1
    return None


def literal(ins, raw: bytes):
    from capstone.arm import ARM_OP_MEM, ARM_REG_PC
    if mnemonic(ins) != 'ldr' or len(ins.operands) < 2:
        return None
    arg = ins.operands[1]
    if arg.type != ARM_OP_MEM or arg.mem.base != ARM_REG_PC or arg.mem.index:
        return None
    cell = ((ins.address + 4) & ~3) + arg.mem.disp
    d = chunk(raw, cell, 4)
    return (cell, int.from_bytes(d, 'little')) if d is not None else None


def fmt(ins, raw: bytes):
    result = f'{ins.address:08X} {ins.bytes.hex():10s} {ins.mnemonic:8s} {ins.op_str}'
    lt = literal(ins, raw)
    if lt is not None:
        result += f' ; LITERAL[{lt[0]:08X}]={lt[1]:08X}'
    return result


def return_kind(ins):
    name = mnemonic(ins)
    op = ins.op_str.lower().replace(' ', '')
    if name == 'pop' and 'pc' in op:
        return 'POP_PC_RETURN'
    if name == 'bx':
        return 'BX_LR_RETURN' if op == 'lr' else 'INDIRECT_BX'
    if name in ('mov','movs') and op in ('pc,lr', 'pc,r14'):
        return 'MOV_PC_LR_RETURN'
    if name in ('tbb','tbh'):
        return 'INDIRECT_JUMPTABLE'
    if name == 'ldr' and op.startswith('pc,'):
        return 'INDIRECT_PC_LOAD'
    return None


def audit_cfg(md, raw: bytes, emit):
    pending = deque([START])
    block_starts = set()
    seen = {}
    calls = []
    branches = []
    returns = []
    issues = []
    edges = defaultdict(set)
    while pending and len(seen) < MAX_INSNS and len(block_starts) < MAX_BLOCKS:
        pc = pending.popleft()
        if pc in block_starts or not START <= pc < END:
            continue
        block_starts.add(pc)
        steps = 0
        while START <= pc < END and pc not in seen and steps < MAX_BLOCK_STEPS and len(seen) < MAX_INSNS:
            ins = insn(md, raw, pc)
            if ins is None or pc + ins.size > END:
                issues.append(f'DECODE_OR_WINDOW_BOUNDARY=0x{pc:08X}')
                break
            seen[pc] = ins
            steps += 1
            name = mnemonic(ins)
            nxt = pc + ins.size
            if name in ('bl','blx'):
                calls.append((pc, name, target(ins), ins.op_str))
                edges[pc].add(nxt)
                pc = nxt
                continue
            if name.startswith('it'):
                issues.append(f'IT_BLOCK_PRESENT=0x{pc:08X}; conditional execution not modeled')
            if name in BRANCHES:
                t = target(ins)
                branches.append((pc, name, t))
                if t is not None and START <= t < END:
                    pending.append(t)
                    edges[pc].add(t)
                else:
                    issues.append(f'BRANCH_LEAVES_LOCAL_WINDOW=0x{pc:08X}->{t}')
                if name != 'b':
                    edges[pc].add(nxt)
                    pending.append(nxt)
                break
            ending = return_kind(ins)
            if ending is not None:
                returns.append((pc,ending))
                if ending.startswith('INDIRECT'):
                    issues.append(f'{ending}=0x{pc:08X}')
                break
            edges[pc].add(nxt)
            pc = nxt
        if steps >= MAX_BLOCK_STEPS:
            issues.append(f'BLOCK_LIMIT=0x{pc:08X}')
    if pending or len(seen) >= MAX_INSNS or len(block_starts) >= MAX_BLOCKS:
        issues.append(f'CFG_CAP: PENDING={len(pending)} INSNS={len(seen)} BLOCKS={len(block_starts)}')
    if not seen or START not in seen:
        abort('entry 1031C714 could not be decoded')
    emit(f'CFG_LOCAL_ENTRY=0x{START:08X} END_EXCLUSIVE=0x{END:08X}')
    emit(f'REACHABLE_INSNS={len(seen)} BASIC_BLOCK_STARTS={len(block_starts)} DIRECT_CALLS={len(calls)} BRANCHES={len(branches)} RETURNS={len(returns)} ISSUES={len(issues)}')
    emit('LIMIT=local Thumb CFG, all BL/BLX treated as returning; interprocedural execution, IT conditions and runtime values NOT proven')
    emit('\n=== REACHABLE LOCAL INSTRUCTIONS ===')
    for address, ins in sorted(seen.items()):
        flag = ' ; RETURN' if any(address == pc for pc,_ in returns) else ''
        emit(fmt(ins,raw)+flag)
    emit('\n=== DIRECT CALLS / CANDIDATE RETURN SOURCES ===')
    for site,mode,dest,operand in sorted(calls):
        emit(f'CALL 0x{site:08X} {mode} -> '+(f'0x{dest:08X}' if dest is not None else 'INDIRECT')+f' ({operand})')
    emit('\n=== BRANCHES ===')
    for pc,name,t in sorted(branches):
        emit(f'{pc:08X} {name} -> '+(f'0x{t:08X}' if t is not None else 'UNKNOWN'))
    emit('\n=== RETURN_SITES / LOCAL_R0_NEIGHBORS ===')
    for at,kind in sorted(returns):
        emit(f'RETURN 0x{at:08X} {kind}')
        # PC-neighbor evidence is NOT path-reachability / register SSA.
        for pc in sorted(q for q in seen if at-0x24 <= q < at):
            ins = seen[pc]
            if (re.match(r'^r0(?:\b|,)',ins.op_str.strip(),re.I) or
                mnemonic(ins) in ('bl','blx','mov','movs','ldr','ldrh','ldrb','pop')):
                emit('  PC_NEIGHBOR_NOT_PREDECESSOR_PROOF '+fmt(ins,raw))
    emit('\n=== CFG_WARNINGS ===')
    for x in issues:
        emit(x)
    if not issues:
        emit('NONE_IN_LOCAL_BOUNDS')
    emit('RESULT_R0_EXACT_VALUE=UNPROVEN_WITHOUT_ARGUMENT_AND_INTERPROCEDURAL_ANALYSIS')
    return len(seen),len(returns),len(issues)


def main() -> None:
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--root',type=Path,default=Path.cwd())
    p.add_argument('--alice',type=Path,default=None)
    p.add_argument('--zimage',type=Path,default=None)
    p.add_argument('--out',type=Path,default=None)
    p.add_argument('--self-test',action='store_true')
    args=p.parse_args()
    self_test()
    if args.self_test:
        return
    alice_path = args.alice or args.root/'research/f2/work/extracted/altice_alice/alice-py.bin'
    zimage_path = args.zimage or args.root/'research/f2/work/extracted/altice_platform/zimage.bin'
    outfile = args.out or args.root/'research/f2/work/reports/s13_5a108_c714_return_value_callee_audit.txt'
    if outfile.exists():
        print('REPORT_ALREADY_EXISTS_UNCHANGED='+str(outfile.resolve()))
        return
    try:
        from capstone import Cs,CS_ARCH_ARM,CS_MODE_THUMB,CS_MODE_LITTLE_ENDIAN
    except ImportError as ex:
        abort('Capstone unavailable in offline environment: '+str(ex))
    alice = load(alice_path,'ALICE',ALICE_SIZE,ALICE_SHA)
    _zimage = load(zimage_path,'ZIMAGE',ZIMAGE_SIZE,ZIMAGE_SHA)
    for addr,hexstr in GUARDS.items():
        d = chunk(alice,addr,len(hexstr)//2)
        if d is None or d.hex() != hexstr:
            abort(f'A107/105 anchor mismatch at 0x{addr:08X}: expected={hexstr} got={d.hex() if d else None}')
    for at,tgt in ((CALLSITE,START),(SETTER_SITE,SETTER),(0x10393784,0x103956A4)):
        if decode_thumb_bl(chunk(alice,at,4),at)!=tgt:
            abort(f'A107 caller BL guard failed at 0x{at:08X}')
    if int.from_bytes(chunk(alice,0x103937BC,4),'little')!=0x2E69:
        abort('A107 event literal 2E69 mismatch')
    if int.from_bytes(chunk(alice,0x10395714,4),'little')!=0xF0115F64:
        abort('A107 global field literal mismatch')
    md = Cs(CS_ARCH_ARM,CS_MODE_THUMB|CS_MODE_LITTLE_ENDIAN)
    md.detail=True
    lines=[]
    lines.append('S13.5A.108 — EXACT A107 RETURN PRODUCER 0x1031C714: BOUNDED THUMB CFG')
    lines.append('STRICTLY_OFFLINE=YES INPUT_FILES_READ_ONLY=YES REPORT_ONLY=YES NO_NOTEPAD=YES')
    lines.append('ALICE_GUARD=PASS SHA256='+ALICE_SHA)
    lines.append('ZIMAGE_GUARD=PASS SHA256='+ZIMAGE_SHA)
    lines.append('A107_A105_EXACT_ANCHORS=PASS count='+str(len(GUARDS)))
    lines.append('A107_EVENT_LITERAL=0x2E69 DIRECT_CALL_10393796_TO_1031C714=PASS')
    lines.append('A107_DIRECT_STORE_1039379C_TO_1039570C=PASS (U16 F0115F66)')
    lines.append('A107_CALLER_ARGS: r3=0x2E69; r1=0; r2=0; [sp]=1; [sp+4]=0; r0=prior_call_103956A4_return_UNKNOWN')
    lines.append('NOT_PROVEN: 0x2E69 role; r0 numeric result; AUDIO 0x8928 event/launch binding; FM numeric ID')
    lines.append('')
    seen,ret,issues=audit_cfg(md,alice,lines.append)
    lines.extend(['','=== DECISION ===',
          'If helper simply delegates, inspect only concrete return-producing callee(s), not generic registries.',
          'If helper yields an allocated key/token/handle, classify before suggesting any menu/Audio patch.',
          'A107 STORE_VALUE=LOW16_RETURN_1031C714; ACTUAL_RUNTIME_VALUE=UNKNOWN.',
          'NO_PHONE_USB_COM_FLASH_PATCH_REPACK=YES'])
    outfile.parent.mkdir(parents=True,exist_ok=True)
    try:
        with outfile.open('x',encoding='utf-8',newline='\n') as fd:
            fd.write('\n'.join(lines)+'\n')
    except FileExistsError:
        print('REPORT_ALREADY_EXISTS_UNCHANGED='+str(outfile.resolve()))
        return
    print('A108_REPORT_CREATED='+str(outfile.resolve()))
    print('A108_RESULT=REACHABLE_INSNS='+str(seen)+' RETURN_SITES='+str(ret)+' CFG_WARNINGS='+str(issues))
    print('A108_PROOF_STATUS=REPORT_AVAILABLE_REVIEW_REQUIRED')

if __name__=='__main__':
    main()
