#!/usr/bin/env python3
"""S13.5A.123: resolve the four A122 BLX targets in their actual instruction-set mode.
Offline, read-only canonical images; writes only an exclusive TXT report. No flash.
"""
from __future__ import annotations
import argparse
import hashlib
import struct
import sys
from collections import deque
from pathlib import Path

ALICE = (0x1024EC00, 0x157BB4, '7246242b67afae0d13104452bc3257827cb778119b54e7a26fb7fb55993697ea')
BOOT = (0xF01F19E4, 0x4B06C, 'aa070292e9c1685eddb12080b3f0bbca763102adaf085016b4e503a3930b4c3e')
ZIMAGE = (0xF023CA50, 0x185E98, '85fba8c8ae8161e4c1f8ced7983ec30d48c54ab10e51c69fcdfb900aca220954')
# A122 direct BLX edges (Thumb source -> ARM destination), including both repeated calls.
EDGES = [(0xF021819A, 0xF02105A8), (0xF02181C4, 0xF02105A0),
         (0xF02181CE, 0xF02105A8), (0xF02181EC, 0xF02105A0),
         (0xF020C188, 0xF02104D0), (0xF020C190, 0xF0210420)]
TARGETS = sorted(set(dst for _, dst in EDGES))
SPAN = 0x400
MAX_INSN = 220


def guard(path: Path, spec, name):
    if not path.is_file():
        raise RuntimeError(f'MISSING_{name}={path}')
    data = path.read_bytes()
    sha = hashlib.sha256(data).hexdigest()
    if len(data) != spec[1] or sha != spec[2]:
        raise RuntimeError(f'{name}_HASH_SIZE_FAIL got=0x{len(data):x}/{sha}')
    return data


def engines():
    try:
        from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_THUMB, CS_MODE_LITTLE_ENDIAN
    except ImportError as e:
        raise RuntimeError('CAPSTONE_REQUIRED') from e
    arm = Cs(CS_ARCH_ARM, CS_MODE_ARM | CS_MODE_LITTLE_ENDIAN)
    thumb = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_LITTLE_ENDIAN)
    arm.detail = thumb.detail = True
    return arm, thumb


def one(md, data, addr):
    off = addr - BOOT[0]
    if not (0 <= off < len(data)):
        return None
    return next(md.disasm(data[off:off+4], addr, 1), None)


def imm_target(ins):
    from capstone.arm import ARM_OP_IMM
    if ins.operands and ins.operands[-1].type == ARM_OP_IMM:
        return ins.operands[-1].imm & 0xffffffff
    return None


def classification(ins):
    m = ins.mnemonic.lower().split('.')[0]
    op = ins.op_str.lower().replace(' ', '')
    if (m == 'bx' and op == 'lr') or (m in ('pop','ldm','ldmia') and 'pc' in op):
        return 'RETURN', None
    if m in ('bx','blx') and (m == 'bx' or imm_target(ins) is None):
        return 'INDIRECT_CONTROL', None
    if m in ('bl','blx'):
        return 'CALL', imm_target(ins)
    if m in ('b','beq','bne','bcs','bcc','bhs','blo','bmi','bpl','bvs','bvc','bhi','bls','bge','blt','bgt','ble'):
        return ('JUMP' if m == 'b' else 'CONDITIONAL'), imm_target(ins)
    if m.startswith('ldr') and op.startswith('pc,'):
        return 'INDIRECT_CONTROL', None
    if m in ('mov','add','sub','orr','adr') and op.startswith('pc,'):
        return 'INDIRECT_CONTROL', None
    if m in ('svc','udf','bkpt'):
        return 'TRAP', None
    return 'LINEAR', None


def literals(ins, boot):
    from capstone.arm import ARM_OP_MEM, ARM_REG_PC
    out = []
    for op in ins.operands:
        if op.type == ARM_OP_MEM and op.mem.base == ARM_REG_PC:
            # ARM PC is instruction address+8, Thumb literal PC is aligned address+4.
            cell = ins.address + 8 + op.mem.disp
            val = None
            off = cell - BOOT[0]
            if 0 <= off <= len(boot)-4:
                val = struct.unpack_from('<I', boot, off)[0]
            out.append((cell, val))
    return out


def walk_arm(md, boot, entry):
    q = deque([entry]); visited = {}; edges=[]; lits=[]; notes=[]
    lo, hi = entry, min(entry + SPAN, BOOT[0]+BOOT[1])
    while q and len(visited) < MAX_INSN:
        at = q.popleft()
        if at in visited: continue
        if not lo <= at < hi:
            notes.append(f'OUT_OF_LOCAL_BOUND=0x{at:08X}')
            continue
        ins = one(md, boot, at)
        if ins is None or ins.size != 4:
            notes.append(f'ARM_DECODE_FAILED=0x{at:08X}')
            continue
        kind, target = classification(ins)
        visited[at] = (ins, kind, target)
        for cell, value in literals(ins, boot):
            lits.append((at, cell, value))
        if kind in ('CALL','JUMP','CONDITIONAL'):
            edges.append((at,kind,target))
        if kind in ('RETURN','TRAP','INDIRECT_CONTROL'):
            if kind != 'RETURN': notes.append(f'{kind}=0x{at:08X}')
            continue
        if kind in ('JUMP','CONDITIONAL') and target is not None:
            q.append(target)
        if kind != 'JUMP':
            q.append(at+ins.size)
    if q: notes.append('CAP_REACHED=YES')
    return visited,edges,lits,notes


def self_test():
    assert BOOT[0]+BOOT[1] == ZIMAGE[0]
    assert len(TARGETS)==4 and all(BOOT[0] <= t < BOOT[0]+BOOT[1] for t in TARGETS)
    arm, thumb = engines()
    # ARM BX LR, and Thumb BX LR have different encodings; ensure both engines work.
    assert next(arm.disasm(bytes.fromhex('1eff2fe1'),0x1000)).mnemonic == 'bx'
    assert next(thumb.disasm(bytes.fromhex('7047'),0x2000)).mnemonic == 'bx'
    assert classification(next(arm.disasm(bytes.fromhex('1eff2fe1'),0x1000)))[0] == 'RETURN'
    print('A123_SELF_TEST=PASS_ARM_THUMB_MODE_AND_RANGE')


def build(alice, boot, zimage):
    arm,thumb = engines()
    lines = ['S13.5A.123 — A122 BLX INTERWORKING RESOLUTION (ARM CALLEES)',
             'STRICTLY_OFFLINE=YES IMAGES_READ_ONLY=YES NO_USB_COM_PHONE_FLASH_PATCH_REPACK=YES',
             'NO_DYNAMIC_UI_TRACE=YES',
             f'ALICE_GUARD=PASS SIZE=0x{ALICE[1]:X} SHA256={ALICE[2]}',
             f'BOOT_ZIMAGE_GUARD=PASS SIZE=0x{BOOT[1]:X} SHA256={BOOT[2]}',
             f'ZIMAGE_GUARD=PASS SIZE=0x{ZIMAGE[1]:X} SHA256={ZIMAGE[2]}',
             '=== A. A122 CALLSITE CROSS-CHECK (THUMB BLX TO ARM) ===']
    for src,dst in EDGES:
        ins = one(thumb,boot,src)
        if not ins or ins.mnemonic.split('.')[0] != 'blx' or imm_target(ins) != dst:
            got = 'NONE' if not ins else ins.mnemonic+' '+ins.op_str
            raise RuntimeError(f'A122_BLX_EDGE_MISMATCH at=0x{src:08X} expected=0x{dst:08X} got={got}')
        lines.append(f'A122_EDGE_GUARD=PASS FROM=0x{src:08X} RAW={ins.bytes.hex()} OP={ins.mnemonic} TARGET=0x{dst:08X} TARGET_MODE=ARM')
    lines.append('A122_BLX_EDGE_GUARD=PASS')
    count=0
    for entry in TARGETS:
        v, edges, lits, notes = walk_arm(arm,boot,entry)
        if not v: raise RuntimeError(f'ARM_DECODE_UNAVAILABLE=0x{entry:08X}')
        count+=len(v)
        lines.extend(['', f'=== B. ARM TARGET 0x{entry:08X} ===', f'ENTRY=0x{entry:08X} INSTRUCTIONS={len(v)} CALL_BRANCH_EDGES={len(edges)} NOTES={len(notes)}'])
        for at,(ins,kind,dst) in sorted(v.items()):
            lines.append(f'  0x{at:08X} {ins.bytes.hex():9} {ins.mnemonic:12} {ins.op_str:34} [{kind}]' + (f' -> 0x{dst:08X}' if dst is not None else ''))
        for at,kind,dst in edges:
            lines.append(f'EDGE=0x{at:08X} KIND={kind} TARGET='+ (f'0x{dst:08X}' if dst is not None else 'UNRESOLVED'))
        for at,cell,val in lits:
            lines.append(f'PC_LITERAL_USE=0x{at:08X} CELL=0x{cell:08X} VALUE='+ (f'0x{val:08X}' if val is not None else 'OUTSIDE_BOOT'))
        for note in notes: lines.append('NOTE='+note)
    lines.extend(['', '=== C. GATES ===', 'ARM_TARGETS_CLASSIFIED=YES', f'TOTAL_ARM_INSTRUCTIONS={count}',
                  'MODE_SWITCH_FROM_THUMB_BLX=STATICALLY_VERIFIED',
                  'TARGET_CONTROL_FLOW_NOT_FULL_RUNTIME_PROOF=YES',
                  'REAL_OK_TO_AUDIO_8928_DISPATCH=UNPROVEN', 'AUDIO_8928_PLAYBACK=UNPROVEN',
                  'SAFE_ROM_RELOCATION=UNPROVEN','NO_HARDWARE_PATCH_AUTHORIZED=YES',
                  'NEXT=INTERPRET_ARM_CALLEES_AND_DECIDE_WHETHER_TO_CLOSE_POSTSELECTION_TASK_PATH'])
    return '\n'.join(lines)+'\n'


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--root',type=Path); p.add_argument('--boot',type=Path); p.add_argument('--out',type=Path)
    p.add_argument('--self-test',action='store_true')
    a=p.parse_args()
    try:
        if a.self_test:
            self_test()
            if not any((a.root,a.boot,a.out)):return 0
        if not all((a.root,a.boot,a.out)):p.error('--root --boot --out required unless --self-test')
        alice=guard(a.root/'research/f2/work/extracted/altice_alice/alice-py.bin',ALICE,'ALICE')
        boot=guard(a.boot,BOOT,'BOOT_ZIMAGE')
        zimage=guard(a.root/'research/f2/work/extracted/altice_platform/zimage.bin',ZIMAGE,'ZIMAGE')
        report=build(alice,boot,zimage)
        a.out.parent.mkdir(parents=True,exist_ok=True)
        with a.out.open('x',encoding='utf-8',newline='\n') as f:f.write(report)
        print('A123_REPORT_CREATED='+str(a.out.resolve()))
        print('ARM_TARGETS_CLASSIFIED=YES')
        return 0
    except (OSError,RuntimeError,ValueError,IndexError,AssertionError) as e:
        print('A123_ABORT='+str(e),file=sys.stderr)
        return 1
if __name__=='__main__':sys.exit(main())
