#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""S13.5A.107 — classify the exact F0115F66 store and locate its callers.

STRICTLY OFFLINE. Reads canonical SHA-pinned ALICE and ZIMAGE only and
writes one new report .txt (exclusive create); no Notepad or firmware writes.

NARROW SCOPE: 0x1039570C is A106's exact literal-backed STRH at global+2.
Search only direct Thumb BL/B.W to that address and literal pointers to it,
then inspect bounded local owner candidates and incoming r0 hints. Literal
references/isolated instruction matches are not runtime callback proof.
"""
from __future__ import annotations

import argparse
import hashlib
import struct
from collections import deque
from pathlib import Path

ALICE = (0x1024EC00, 0x157BB4, '7246242b67afae0d13104452bc3257827cb778119b54e7a26fb7fb55993697ea')
ZIMAGE = (0xF023CA50, 0x185E98, '85fba8c8ae8161e4c1f8ced7983ec30d48c54ab10e51c69fcdfb900aca220954')
SETTER = 0x1039570C
FIELD = 0xF0115F66
GLOBAL_BASE = FIELD - 2
KNOWN = {
    SETTER: '0149',           # LDR r1,[pc,#4]
    SETTER + 2: '4880',       # STRH r0,[r1,#2]
    SETTER + 4: '7047',       # BX LR
    SETTER + 8: '645f11f0',   # literal global base
    0x102EF5DC: '0148',      # A105 getter
    0x102EF5DE: '4088',
    0x102EF5E0: '7047',
    0x102EF5E4: '645f11f0',
    0x10342E2A: '0248',      # A104 wrapper 0x6316
    0x10342E34: '16630000',
    0x10345332: '0248',      # A104 wrapper 0x6314
    0x1034533C: '14630000',
}
KNOWN_BL_CONTROLS = {
    0x1039CCC4: (0x102ED240, '50f7bcfa'),
    0x1039E4A0: (0x102ED240, '4ef7cefe'),
    0x103A2330: (0x102ED240, '4af786ff'),
    0x10342E2C: (0x10345268, '02f01cfa'),
    0x10345334: (0x10345268, 'fff798ff'),
}
MAX_SITES = 32
MAX_LOCAL_OWNER = 5
CONDITIONS = {'beq','bne','bgt','bge','blt','ble','bhi','bhs','blo','bls','bpl','bmi','bvs','bvc','cbz','cbnz'}


def abort(msg: str) -> None:
    raise SystemExit('ABORT: ' + msg)


def raw_at(img, addr: int, count: int):
    base, blob = img
    off = addr - base
    if off < 0 or off + count > len(blob):
        return None
    return blob[off:off + count]


def load(path: Path, label: str, expected, output):
    base, size, sha = expected
    if not path.is_file():
        abort(f'{label} missing: {path}')
    blob = path.read_bytes()
    got = hashlib.sha256(blob).hexdigest()
    ok = len(blob) == size and got == sha
    output.append(f'{label}_GUARD={"PASS" if ok else "FAIL"} SIZE=0x{len(blob):X} SHA256={got}')
    if not ok:
        abort(f'{label} canonical size/hash check failed')
    return base, blob


def branch_at(addr: int, h1: int, h2: int):
    """A103 proven Thumb BL/B.W relative decoder (not BLX/conditional B)."""
    if (h1 & 0xF800) != 0xF000:
        return None
    tag = h2 & 0xD000
    if tag == 0xD000:
        kind = 'BL'
    elif tag == 0x9000:
        kind = 'B.W'
    else:
        return None
    s = (h1 >> 10) & 1
    j1 = (h2 >> 13) & 1
    j2 = (h2 >> 11) & 1
    i1 = 1 ^ (j1 ^ s)
    i2 = 1 ^ (j2 ^ s)
    delta = (s << 24) | (i1 << 23) | (i2 << 22) | ((h1 & 0x3FF) << 12) | ((h2 & 0x7FF) << 1)
    if delta & (1 << 24):
        delta -= 1 << 25
    return kind, (addr + 4 + delta) & 0xFFFFFFFF


def self_test():
    for site, (target, hx) in KNOWN_BL_CONTROLS.items():
        found = branch_at(site, *struct.unpack('<HH', bytes.fromhex(hx)))
        assert found == ('BL', target), (hex(site), found)
    assert branch_at(0x10000000, 0xB510, 0xBD10) is None
    assert branch_at(0x10000000, *struct.unpack('<HH', bytes.fromhex('00f002b8'))) == ('B.W', 0x10000008)
    assert ((SETTER + 4) & ~3) + 4 == SETTER + 8  # 16-bit LDR literal to known cell
    assert int.from_bytes(bytes.fromhex(KNOWN[SETTER + 8]), 'little') == GLOBAL_BASE
    assert len(KNOWN) == 12
    print('A107_SELF_TEST=PASS FIVE_BL_CONTROLS; SETTER_LITERAL; B.W; NEGATIVE')


def verify(img):
    for addr, hx in KNOWN.items():
        expected = bytes.fromhex(hx)
        if raw_at(img, addr, len(expected)) != expected:
            abort(f'A106/A105/A104 exact anchor mismatch 0x{addr:08X}')
    for addr, (dest, hx) in KNOWN_BL_CONTROLS.items():
        if raw_at(img, addr, 4) != bytes.fromhex(hx):
            abort(f'BL control bytes changed at 0x{addr:08X}')
        if branch_at(addr, *struct.unpack('<HH', raw_at(img, addr, 4))) != ('BL', dest):
            abort(f'BL control target changed at 0x{addr:08X}')


def m(ins):
    return ins.mnemonic.lower().split('.')[0]


def insn(md, img, at):
    raw = raw_at(img, at, 4)
    if raw is None:
        return None
    i = next(md.disasm(raw, at, count=1), None)
    return i if i and i.address == at else None


def direct_target(ins):
    from capstone.arm import ARM_OP_IMM
    if not ins:
        return None
    for op in reversed(ins.operands):
        if op.type == ARM_OP_IMM:
            return int(op.imm) & ~1 & 0xFFFFFFFF
    return None


def lit(ins, img):
    from capstone.arm import ARM_OP_MEM, ARM_REG_PC
    if not ins or m(ins) != 'ldr' or len(ins.operands) < 2:
        return None
    mem = ins.operands[1]
    if mem.type != ARM_OP_MEM or mem.mem.base != ARM_REG_PC or mem.mem.index:
        return None
    cell = ((ins.address + 4) & ~3) + mem.mem.disp
    raw = raw_at(img, cell, 4)
    return (cell, struct.unpack('<I', raw)[0]) if raw else None


def fmt(ins, img):
    literal = lit(ins, img)
    return (f'0x{ins.address:08X} {ins.bytes.hex():<10} {ins.mnemonic:<9} {ins.op_str}'
            + (f' ; LITERAL[0x{literal[0]:08X}]=0x{literal[1]:08X}' if literal else ''))


def is_return(ins):
    ops = ins.op_str.lower().replace(' ', '')
    return (m(ins) == 'bx' and ops == 'lr') or (m(ins) == 'pop' and 'pc' in ops) or (m(ins) == 'ldr' and ops.startswith('pc,'))


def cfg(md, img, start, site):
    """Bounded local reachability, NOT full executable function ownership."""
    low, high = start, site + 0x28
    queue = deque([start]); visited = {}; issues=[]; calls=[]
    while queue and len(visited) < 180:
        pc = queue.popleft()
        if pc in visited:
            continue
        if not low <= pc < high:
            issues.append(f'OUTSIDE_LOCAL_WINDOW 0x{pc:08X}')
            continue
        item = insn(md, img, pc)
        if item is None:
            issues.append(f'DECODE_FAIL 0x{pc:08X}')
            continue
        visited[pc] = item
        op = m(item); after = pc + item.size
        if op in ('bl', 'blx'):
            calls.append((pc, direct_target(item)))
            queue.append(after)
        elif is_return(item):
            pass
        elif op == 'b' or op in CONDITIONS:
            t = direct_target(item)
            if t is None:
                issues.append(f'UNKNOWN_BRANCH_TARGET 0x{pc:08X}')
            else:
                queue.append(t)
            if op != 'b':
                queue.append(after)
        elif op in ('bx','tbb','tbh'):
            issues.append(f'INDIRECT_TRANSFER 0x{pc:08X}')
        else:
            queue.append(after)
    if queue:
        issues.append('CFG_INSTRUCTION_CAP')
    return visited, calls, issues


def candidates(md, img, site):
    start = max(img[0], site - 0x100)
    entry_candidates = []
    for pc in range(start, site, 2):
        op = insn(md, img, pc)
        if op and m(op) == 'push' and 'lr' in op.op_str.lower():
            entry_candidates.append(pc)
    owners=[]
    for start in entry_candidates:
        visited, calls, issues = cfg(md, img, start, site)
        if site in visited:
            owners.append((start, visited, calls, issues))
    owners.sort(key=lambda it: (len(it[3]), site - it[0]))
    return len(entry_candidates), owners


def census(img):
    base, blob = img
    found=[]; scanned=0
    for off in range(0, len(blob)-3, 2):
        h1 = blob[off] | (blob[off+1] << 8)
        if (h1 & 0xF800) != 0xF000:
            continue
        h2 = blob[off+2] | (blob[off+3] << 8)
        op = branch_at(base+off, h1, h2)
        if not op:
            continue
        scanned += 1
        if op[1] == SETTER:
            found.append((base+off, op[0]))
    return found, scanned


def word_refs(img, value):
    base, blob = img
    term = struct.pack('<I', value)
    pos=0; result=[]
    while True:
        pos = blob.find(term, pos)
        if pos < 0:
            return result
        result.append(base + pos)
        pos += 1


def run(root, alice_path, zimage_path, out):
    try:
        from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_LITTLE_ENDIAN
    except ImportError as ex:
        abort('Capstone unavailable in Windows Python venv: ' + str(ex))
    lines=[
      'S13.5A.107 — F0115F66 EXACT SETTER: DIRECT CALLERS AND INCOMING R0 HINTS',
      'STRICTLY_OFFLINE=YES; TWO_CANONICAL_FILES_READ_ONLY; REPORT_ONLY=YES; NO_NOTEPAD=YES',
      'SCOPE=ONLY_DIRECT_BL_BW_TARGET_1039570C_AND_EXACT_U32_POINTERS; NO_GENERIC_MENU_SCAN',
      'LIMIT=RAW_HALFWORD_SCAN_NOT_PROOF_OF_EXECUTABILITY; LOCAL_CFG_NOT_INTERPROCEDURAL',
    ]
    alice=load(alice_path,'ALICE',ALICE,lines)
    zimage=load(zimage_path,'ZIMAGE',ZIMAGE,lines)
    verify(alice)
    lines.append(f'A106_SETTER_AND_PRIOR_CONTROL_ANCHORS=PASS count={len(KNOWN) + len(KNOWN_BL_CONTROLS)}')
    md=Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_LITTLE_ENDIAN)
    md.detail=True
    proof=[insn(md,alice,SETTER+i) for i in (0,2,4)]
    if any(i is None for i in proof) or [m(i) for i in proof] != ['ldr','strh','bx']:
        abort('A106 setter executable instruction decoding mismatch')
    from capstone.arm import ARM_OP_REG,ARM_OP_MEM,ARM_REG_R0,ARM_REG_R1
    store=proof[1]
    if not (len(store.operands)>=2 and store.operands[0].type==ARM_OP_REG
            and store.operands[0].reg==ARM_REG_R0 and store.operands[1].type==ARM_OP_MEM
            and store.operands[1].mem.base==ARM_REG_R1 and store.operands[1].mem.disp==2):
        abort('A106 exact STRH r0,[r1,#2] decode mismatch')
    if lit(proof[0],alice) != (SETTER+8,GLOBAL_BASE):
        abort('A106 setter literal PC source mismatch')
    lines += [
       '\n=== A106 EXACT STORE SEMANTICS ===',
       *[fmt(p,alice) for p in proof],
       'STORE_VALUE=INCOMING_R0_LOW_16_BITS',
       'STORE_TARGET=U16_AT_F0115F66',
       'VALUE_AND_CALLERS=UNKNOWN_UNTIL_A107_ANALYSIS',
    ]
    total=0; pointer_total=0
    for label,img in (('ALICE',alice),('ZIMAGE',zimage)):
        hits,count=census(img)
        if len(hits) > MAX_SITES:
            abort(f'{label}: {len(hits)} raw caller matches exceeds safety cap {MAX_SITES}')
        lines += [f'\n=== {label} EXACT TARGET CALLS ===',
                  f'RECOGNIZED_THUMB_BL_BW_INSTRUCTIONS={count}',
                  f'DIRECT_CALL_OR_JUMP_TO_0x{SETTER:08X}_RAW_COUNT={len(hits)}']
        total+=len(hits)
        for site,kind in hits:
            lines.append(f'  RAW_SITE=0x{site:08X} KIND={kind} TARGET=0x{SETTER:08X}')
            if kind!='BL':
                lines.append('    NONCALL_BW_BRANCH; NOT AN ARGUMENTED SUBROUTINE CALL PROOF')
            decoded=insn(md,img,site)
            if not decoded or m(decoded) != ('bl' if kind=='BL' else 'b') or direct_target(decoded)!=SETTER:
                lines.append('    CAPSTONE_MISMATCH=ABORT_TO_AVOID_RAW_PATTERN_MISCLASSIFICATION')
                abort(f'{label} branch pattern/Capstone mismatch at {site:08X}')
            lines.append('    CAPSTONE_ANCHOR=PASS '+fmt(decoded,img))
            tested,owners=candidates(md,img,site)
            lines.append(f'    PUSH_LR_PROLOGUES_TESTED={tested} LOCAL_OWNERS_REACHING_SITE={len(owners)}')
            for ix,(begin,visited,calls,notes) in enumerate(owners[:MAX_LOCAL_OWNER],1):
                lines.append(f'    OWNER_CANDIDATE_{ix}=0x{begin:08X} INSNS={len(visited)} NOTES={len(notes)}')
                for note in notes[:8]:lines.append('      CFG_NOTE '+note)
                for pc in sorted(visited):
                    if site-0x40 <= pc <= site+0x4:
                        lines.append('      '+fmt(visited[pc],img))
                lines.append('      R0_NEAR_CALL_HINTS (NOT SSA/ARGUMENT PROOF):')
                printed=0
                for pc in sorted(visited):
                    if site-0x40 <= pc < site:
                        op=visited[pc]
                        if (op.op_str.lower().replace(' ','').startswith('r0,')
                                or m(op) in ('bl','blx')):
                            lines.append('        '+fmt(op,img))
                            printed+=1
                if not printed:lines.append('        NONE; incoming r0 may be preserved from upstream caller')
            if len(owners)>MAX_LOCAL_OWNER:
                lines.append(f'    LOCAL_OWNERS_ABOVE_PRINT_CAP={len(owners)-MAX_LOCAL_OWNER} (not certified)')
            if not owners:
                for at in range(site-0x16,site,2):
                    i=insn(md,img,at)
                    if i and (m(i) in ('push','bl','blx','ldr','ldrh','mov','movs','b','bx')):
                        lines.append('    RAW_WINDOW_NOT_CFG '+fmt(i,img))
        lines.append(f'\n=== {label} EXACT U32 POINTER VALUES ===')
        for target in (SETTER, SETTER | 1):
            refs=word_refs(img,target)
            pointer_total+=len(refs)
            if len(refs)>MAX_SITES:abort(f'{label} excessive setter literal refs 0x{target:08X}')
            lines.append(f'POINTER_VALUE=0x{target:08X} EXACT_U32_HITS={len(refs)}')
            for cell in refs:lines.append(f'  RAW_CELL=0x{cell:08X} ALIGNED4={cell%4==0}')
    lines += [
       '\n=== NEXT DECISION GATE ===',
       f'TOTAL_RAW_DIRECT_BRANCH_MATCHES={total}',
       f'TOTAL_EXACT_U32_POINTER_MATCHES={pointer_total}',
       'If BL owner candidates present: audit only those owner callsites and incoming r0 producing the setter value.',
       'If only function-pointer refs: resolve consuming registration site before treating it as executable.',
       'If no references: this bounded census cannot exclude dynamic/indirect/ARM BLX or computed writers.',
       'NO_PROOF=0x6314_or_0x6316_equals_this_field; NO_SELECTED_LEAF_TO_AUDIO_0x8928_ACTION',
       'FM_ROM_ID=UNKNOWN; DESCRIPTOR_0C_SET_TO_1=UNPROVEN',
       'NO_PHONE_USB_COM_FLASH_REPACK_PATCH=YES',
    ]
    if not out.parent.is_dir():
        abort(f'expected reports dir missing: {out.parent}')
    try:
        with out.open('x',encoding='utf-8',newline='\n') as fd:
            fd.write('\n'.join(lines)+'\n')
    except FileExistsError:
        print(f'A107_REPORT_ALREADY_EXISTS_UNCHANGED={out}')
        return
    print(f'A107_REPORT_CREATED={out} BYTES={out.stat().st_size}')
    print(f'A107_RESULT=BL_BW_MATCHES_{total}_POINTER_REFS_{pointer_total}')


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--root',type=Path,default=Path.cwd())
    p.add_argument('--alice',type=Path)
    p.add_argument('--zimage',type=Path)
    p.add_argument('--out',type=Path)
    p.add_argument('--self-test',action='store_true')
    args=p.parse_args()
    self_test()
    if args.self_test:
        return
    root=args.root.resolve()
    alice=args.alice or root/'research/f2/work/extracted/altice_alice/alice-py.bin'
    zimage=args.zimage or root/'research/f2/work/extracted/altice_platform/zimage.bin'
    out=args.out or root/'research/f2/work/reports/s13_5a107_f0115f66_setter_callers_audit.txt'
    run(root,alice,zimage,out)


if __name__ == '__main__':
    main()
