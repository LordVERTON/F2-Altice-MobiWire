#!/usr/bin/env python3
"""S13.5A.89 — ONE callsite from A88: function ownership and r0/r1 provenance gate.

READ ONLY. SHA-pinned canonical ALICE + ZIMAGE. No USB, COM, device, write,
flash, patch, erase, repack, file materialization or broad XREF census.

Only new question: is A88's 0x1037E21E -> 0x102D9DC8 executable from a
bounded function prologue, and can r1 be tied to a selected visible-menu ID?
The older S11 resolver/dispatcher ABI is GIVEN, not re-analysed here.

The local r0/r1 trail may have multiple predecessors, so a linear slice is
NEVER promoted to proof of runtime argument values or of menu origin.
"""
from __future__ import annotations

import argparse
import hashlib
from collections import deque
from pathlib import Path

try:
    from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_LITTLE_ENDIAN
    from capstone.arm import ARM_OP_IMM, ARM_OP_MEM, ARM_REG_PC
except ImportError as exc:
    raise SystemExit('Missing Capstone in local offline Python environment: ' + str(exc))

ALICE = (0x1024EC00, 0x157BB4, '7246242b67afae0d13104452bc3257827cb778119b54e7a26fb7fb55993697ea')
ZIMAGE = (0xF023CA50, 0x185E98, '85fba8c8ae8161e4c1f8ced7983ec30d48c54ab10e51c69fcdfb900aca220954')
SITE = 0x1037E21E
GATE = 0x102D9DC8
# A88 bytes: site, predecessor guards, both exits, and distinct helper path.
ANCHORS = {
    0x1037E202: '77f74df9',  # BL 102F54A0
    0x1037E206: '2089',
    0x1037E208: 'a1f7fcfb',  # BL 1031FA04
    0x1037E20C: '09e0',      # B directly to return path, cannot fall into +0x20E
    0x1037E20E: '6189',
    0x1037E210: '8918',
    0x1037E212: '01d0',
    0x1037E214: '0129',
    0x1037E216: '04d1',
    0x1037E218: '0100',
    0x1037E21A: '2800',
    0x1037E21C: '1a30',
    SITE: '5bf7d3fd',
    0x1037E222: '0020',
    0x1037E224: 'f8bd',
}
CONDS = {'beq','bne','bgt','bge','blt','ble','bhi','bhs','blo','bls','bmi','bpl','bvs','bvc','cbz','cbnz'}
TERMINATORS = {'bx','udf','bkpt','svc','tbb','tbh'}


def fail(s):
    raise SystemExit('ABORT: ' + s)


def load(path: Path, label: str, info):
    base, size, sha = info
    if not path.is_file():
        fail(f'{label} not found: {path}')
    raw = path.read_bytes()
    h = hashlib.sha256(raw).hexdigest()
    ok = len(raw) == size and h == sha
    print(f'{label} path={path} size=0x{len(raw):X} sha256={h} GUARD={"PASS" if ok else "FAIL"}')
    if not ok:
        fail(label + ' must match pinned source image')
    return (base, raw)


def rd(img, addr, n=4):
    base, raw = img
    off = addr - base
    return raw[off:off+n] if 0 <= off and n >= 0 and off+n <= len(raw) else None


def one(md, img, addr):
    data = rd(img, addr, 4)
    if data is None:
        return None
    result = list(md.disasm(data, addr, count=1))
    return result[0] if result and result[0].address == addr else None


def mname(ins):
    return ins.mnemonic.lower().split('.')[0]


def imm_branch(ins):
    if not ins or not ins.operands:
        return None
    for x in reversed(ins.operands):
        if x.type == ARM_OP_IMM:
            return x.imm & 0xFFFFFFFF & ~1
    return None


def pcliteral(ins, img):
    if mname(ins) != 'ldr' or len(ins.operands) < 2:
        return None
    op = ins.operands[1]
    if op.type != ARM_OP_MEM or op.mem.base != ARM_REG_PC or op.mem.index:
        return None
    loc = (((ins.address+4) & ~3) + op.mem.disp) & 0xFFFFFFFF
    data = rd(img, loc, 4)
    return (loc, int.from_bytes(data, 'little')) if data is not None else None


def desc(ins, img):
    s = f'{ins.address:08X} {ins.mnemonic:<8} {ins.op_str:<40} bytes={ins.bytes.hex(" ")}'
    p = pcliteral(ins, img)
    return s + (f' ; literal {p[0]:08X}={p[1]:08X}' if p else '')


def guard(md, img):
    print('\n[A] FAIL-CLOSED A88 EXACT INSTRUCTION ANCHORS')
    for a, expected in ANCHORS.items():
        raw = rd(img, a, len(bytes.fromhex(expected)))
        ins = one(md, img, a)
        ok = raw is not None and raw.hex() == expected and ins is not None and ins.size == len(raw)
        if a == SITE:
            ok = ok and mname(ins) == 'bl' and imm_branch(ins) == GATE
        if a == 0x1037E20C:
            ok = ok and mname(ins) == 'b' and imm_branch(ins) == 0x1037E222
        if a == 0x1037E224:
            ok = ok and mname(ins) == 'pop' and 'pc' in ins.op_str
        if not ok:
            fail(f'anchor mismatch 0x{a:08X}: expected {expected}; observed {raw.hex() if raw else None}; ins={ins}')
        print('  PASS ' + desc(ins,img))
    print('A88_SINGLE_CALLSITE_ANCHORS=PASS')


def cfg(md,img,start,end=SITE+8):
    """Bounded branch-aware reachability for a *candidate* function start.

    This proves only local instruction encoding/reachability for decoded branches,
    not caller reachability nor menu ownership. Unknown indirect jumps cause
    an explicit incomplete flag (even if the site is seen on a different branch).
    """
    queue = deque([start]); seen = {}; blocks = set(); notes=[]; edges=[]
    while queue and len(seen) < 260 and len(blocks) < 50:
        cur=queue.popleft()
        if cur in blocks or not (start<=cur<end):
            continue
        blocks.add(cur)
        steps=0
        while start<=cur<end and cur not in seen and steps<90 and len(seen)<260:
            ins=one(md,img,cur)
            if ins is None or cur + ins.size > end:
                notes.append(f'DECODE_OR_BOUND at {cur:08X}')
                break
            seen[cur]=ins
            steps+=1
            mn=mname(ins); nxt=cur+ins.size
            if mn in CONDS or mn == 'b':
                target=imm_branch(ins)
                edges.append((cur,mn,target))
                if target is not None and start<=target<end:
                    queue.append(target)
                else:
                    notes.append(f'EXIT/UNKNOWN_TARGET {cur:08X}->{target}')
                if mn=='b':
                    break
            if mn in TERMINATORS or (mn=='pop' and 'pc' in ins.op_str.lower()) or (mn=='ldr' and ins.op_str.lower().startswith('pc,')):
                if mn in ('tbb','tbh'):
                    notes.append(f'UNRESOLVED_COMPUTED_BRANCH {cur:08X}')
                break
            cur=nxt
        if steps>=90:
            notes.append(f'BLOCK_CAP {cur:08X}')
    complete=(not queue and len(seen)<260 and len(blocks)<50 and not any(('CAP' in x or 'UNRESOLVED' in x or 'DECODE' in x) for x in notes))
    return {'start':start,'seen':seen,'blocks':blocks,'edges':edges,'notes':notes,'complete':complete,'reaches':SITE in seen}


def candidate_owners(md,img):
    print('\n[B] ONLY BOUNDED LOCAL PUSH-LR -> CALLSITE REACHABILITY')
    lo=(SITE-0x300)&~1
    candidates=[]
    for addr in range(lo,SITE,2):
        ins=one(md,img,addr)
        if ins is not None and mname(ins)=='push' and 'lr' in ins.op_str.lower():
            data=cfg(md,img,addr)
            candidates.append(data)
    reaches=[v for v in candidates if v['reaches']]
    print(f'SEARCH_RANGE=0x{lo:08X}..0x{SITE:08X} PROLOGUES_TESTED={len(candidates)} REACHABLE={len(reaches)}')
    for p in reaches[:8]:
        print(f'  START={p["start"]:08X} REACHED=YES COMPLETE={p["complete"]} INSNS={len(p["seen"])} BLOCKS={len(p["blocks"])} NOTES={p["notes"][:5]}')
        guards=[(a,m,t) for a,m,t in p['edges'] if SITE-0x50<=a<=SITE]
        for a,m,t in guards:
            print(f'    BRANCH 0x{a:08X} {m} -> '+(f'0x{t:08X}' if t is not None else 'unknown'))
    if len(reaches)>8:
        print('  REACHABLE_PRINT_CAPPED; no unique owner can be promoted')
    if len(reaches)==1 and reaches[0]['complete']:
        print(f'UNIQUE_COMPLETE_BOUNDED_OWNER=0x{reaches[0]["start"]:08X} (not full interprocedural identity)')
    else:
        print('UNIQUE_OWNER_NOT_PROVEN: zero/multiple candidates or incomplete bounded CFG')
    return reaches


def show_sources(md,img,reaches):
    print('\n[C] CFG-REACHED LOCAL INSTRUCTIONS, OTHERWISE A88 EXACT RAW WINDOW')
    trusted=(len(reaches)==1 and reaches[0]['complete'])
    print('WINDOW_SOURCE=' + ('UNIQUE_BOUNDED_CFG' if trusted else 'A88_EXACT_BOUNDARY_RAW — no owner certified'))
    if trusted:
        picked=sorted(k for k in reaches[0]['seen'] if SITE-0x160<=k<=SITE+6)
        if len(picked)>110:
            print('  PRINT_LIMIT=110 of '+str(len(picked))+' reachable instructions')
        for address in picked[:110]:
            print('  CFG_REACHED '+desc(reaches[0]['seen'][address],img))
    else:
        # This exact starting boundary was disassembled and printed in A88;
        # it is a window, never treated as a certified function CFG.
        addr=0x1037E1FC
        while addr<SITE+8:
            ins=one(md,img,addr)
            if ins is None or addr+ins.size>SITE+8:
                print(f'  RAW_STOP 0x{addr:08X}')
                break
            print('  RAW_ONLY '+desc(ins,img))
            addr+=ins.size
    print('LOCAL_GUARD: 1037E210 computes r1=MEM16[r4+0xA]+r2; only values 0 or 1 enter 1037E218')
    print('CRITICAL_BRANCH: 1037E208 BL 1031FA04 -> 1037E20C unconditional B 1037E222; its return r0 is NOT the source at 1037E218 on that path')
    print('AT_CALLSITE: r0=r5+0x1A; r1=prior r0; full prior r0 and r5 origins, relation to selected visible menu remain unproven')
    print('DATAFLOW_LIMIT: no global interprocedural taint or static menu-ID claim')


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--alice',type=Path,default=Path('research/f2/work/extracted/altice_alice/alice-py.bin'))
    p.add_argument('--zimage',type=Path,default=Path('research/f2/work/extracted/altice_platform/zimage.bin'))
    a=p.parse_args()
    print('S13.5A.89 — ONE CODE-ENCODED CALLSITE / BOUNDED ARGUMENT-OWNER GATE')
    print('STRICT OFFLINE READ-ONLY; NO PHONE, USB, FLASH, ERASE, PATCH, REPACK, WRITE')
    img=load(a.alice,'ALICE',ALICE)
    z=load(a.zimage,'ZIMAGE',ZIMAGE)
    # Fail if a future variant moves source/target off pinned image bounds.
    if rd(img,SITE,4) is None or rd(img,GATE,2) is None or rd(z,0xF0345E68,58*8) is None:
        fail('required A88 locations outside pinned canonical maps')
    md=Cs(CS_ARCH_ARM,CS_MODE_THUMB | CS_MODE_LITTLE_ENDIAN)
    md.detail=True
    guard(md,img)
    reaches=candidate_owners(md,img)
    show_sources(md,img,reaches)
    print('\n[D] STOP/PROMOTION GATE')
    print('DO_NOT_REPEAT_S11_RESOLVER_OR_S13_A79_A85_UI_DETOUR=YES')
    print('MISSING: proven selected visible-menu state/ID -> 102D9DC8(ctx, ID); FM Radio internal ID remains unknown')
    print('NO_MENU_OK_AUDIO_8928_PROOF=YES')
    print('IF_NO_REAL_MENU_PROVENANCE: CLOSE THIS DIRECT-GATEWAY BRANCH AND PIVOT TO S13 PROVIDER-BACKED VISIBLE MENU BUILDER')
    print('NO_PHONE_ACCESS=YES NO_FIRMWARE_MUTATION=YES PATCH_AUTHORIZED=NO')

if __name__=='__main__':
    main()
