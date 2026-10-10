#!/usr/bin/env python3
"""S13.5A.122 — offline BOOT post-selection callee and bounded call-graph audit.

Read-only. Three canonical SHA checks; no USB, ROM patch, guest execution or flash.
Imports the reviewed A121 module from the same directory to reuse its provenance guards.
"""
from __future__ import annotations
import argparse
import hashlib
import importlib.util
import re
import struct
import sys
from collections import deque
from pathlib import Path

ENTRY = 0xF0218180
CALLER = 0xF020D0A8
MAX_DEPTH = 2
MAX_FUNCTIONS = 24
MAX_INSNS_PER_FUNCTION = 500
MAX_TOTAL_INSNS = 4500
MAX_SPAN = 0x1000


def load_a121():
    path = Path(__file__).with_name('s13_5a121_boot_postselect_target_cfg_audit.py')
    if not path.is_file():
        raise RuntimeError(f'A121_DEPENDENCY_MISSING={path}')
    spec = importlib.util.spec_from_file_location('f2_a121_local', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def image_at(images, addr, size=4):
    for name, (base, blob) in images.items():
        if base <= addr and addr + size <= base + len(blob):
            return name, blob[addr-base:addr-base+size]
    return None, None


def u32_at(images, addr):
    name, raw = image_at(images, addr, 4)
    return name, struct.unpack('<I', raw)[0] if raw is not None else None


def mnemonic_base(ins):
    return ins.mnemonic.lower().split('.')[0]


def dest_of(ins):
    try:
        from capstone.arm import ARM_OP_IMM
        ops = ins.operands
        return (ops[-1].imm & 0xffffffff) if ops and ops[-1].type == ARM_OP_IMM else None
    except (AttributeError, IndexError):
        return None


def classify(ins):
    m = mnemonic_base(ins)
    op = ins.op_str.lower().replace(' ', '')
    dst = dest_of(ins)
    if (m == 'pop' and 'pc' in op) or (m == 'bx' and op == 'lr'):
        return 'RETURN', None
    if m in ('bl', 'blx'):
        return ('CALL_DIRECT' if dst is not None else 'CALL_INDIRECT'), dst
    if m == 'bx' or m in ('tbb','tbh'):
        return 'BRANCH_INDIRECT', None
    if m in ('cbz', 'cbnz'):
        return 'BRANCH_CONDITIONAL', dst
    if m == 'b':
        return 'BRANCH_UNCONDITIONAL', dst
    if m in ('beq','bne','bcs','bcc','bhs','blo','bmi','bpl','bvs','bvc','bhi','bls','bge','blt','bgt','ble'):
        return 'BRANCH_CONDITIONAL', dst
    if m in ('ldr','mov','movs','add','adds','sub','subs','ldm','ldmia') and re.match(r'^pc(?:,|$)',op):
        return 'BRANCH_INDIRECT', None
    if m in ('udf','bkpt','svc'):
        return 'TRAP', None
    return 'LINEAR', None


def pc_ref(ins, images):
    try:
        from capstone.arm import ARM_OP_MEM, ARM_REG_PC
        ops = ins.operands
        for x in ops:
            if x.type == ARM_OP_MEM and x.mem.base == ARM_REG_PC:
                cell = ((ins.address + 4) & ~3) + x.mem.disp
                name, val = u32_at(images, cell)
                return cell, name, val
    except (AttributeError, IndexError):
        pass
    return None


def walk_function(md, images, entry):
    lo, hi = entry, entry + MAX_SPAN
    todo = deque([entry]); seen = {}; calls=[]; branches=[]; notes=[]; lits=[]; accesses=[]; exits=[]
    while todo and len(seen) < MAX_INSNS_PER_FUNCTION:
        at = todo.popleft()
        if at in seen: continue
        if not lo <= at < hi:
            notes.append(f'OUTSIDE_LOCAL_SPAN=0x{at:08X}'); continue
        name, blob = image_at(images, at, 4)
        if blob is None:
            # End-of-image final Thumb instruction may be 2 bytes.
            name, blob = image_at(images, at, 2)
        if blob is None:
            notes.append(f'UNMAPPED_INSN=0x{at:08X}'); continue
        ins = next(md.disasm(blob, at, 1),None)
        if ins is None:
            notes.append(f'DECODE_FAILED=0x{at:08X}');continue
        seen[at] = ins
        kind, dst = classify(ins)
        ref = pc_ref(ins, images)
        if ref is not None: lits.append((at, *ref))
        if '[' in ins.op_str or mnemonic_base(ins) in ('str','strh','strb','stm','ldm'):
            accesses.append((at,ins.mnemonic,ins.op_str))
        nxt = at + ins.size
        if kind == 'RETURN': exits.append((at,kind))
        elif kind == 'TRAP': notes.append(f'TRAP=0x{at:08X}')
        elif kind == 'BRANCH_INDIRECT':
            notes.append(f'UNRESOLVED_INDIRECT_BRANCH=0x{at:08X}')
        elif kind.startswith('CALL'):
            calls.append((at,kind,dst))
            todo.append(nxt)
        elif kind == 'BRANCH_UNCONDITIONAL':
            branches.append((at,kind,dst))
            if dst is not None: todo.append(dst & ~1)
            else: notes.append(f'UNRESOLVED_BRANCH=0x{at:08X}')
        elif kind == 'BRANCH_CONDITIONAL':
            branches.append((at,kind,dst))
            if dst is not None: todo.append(dst & ~1)
            else: notes.append(f'UNRESOLVED_BRANCH=0x{at:08X}')
            todo.append(nxt)
        else: todo.append(nxt)
    if todo: notes.append(f'INSTRUCTION_CAP_REACHED={MAX_INSNS_PER_FUNCTION}')
    if not exits: notes.append('NO_RETURN_OBSERVED_WITHIN_BOUND')
    return dict(insns=seen,calls=calls,branches=branches,notes=notes,literals=lits,accesses=accesses,exits=exits)


def generate(a, alice, boot, zimage, boot_path):
    a.check_inputs(alice,boot,zimage)
    images = {'ALICE':(a.ALICE_BASE,alice),'BOOT_ZIMAGE':(a.BOOT_BASE,boot),'ZIMAGE':(a.ZIMAGE_BASE,zimage)}
    from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_LITTLE_ENDIAN
    md = Cs(CS_ARCH_ARM,CS_MODE_THUMB|CS_MODE_LITTLE_ENDIAN);md.detail=True
    caller_ins = a.decode_one(md,boot,0xF020D0AA)
    if caller_ins is None or mnemonic_base(caller_ins) != 'bl' or dest_of(caller_ins) != ENTRY:
        raise RuntimeError('A121_CALLEE_EDGE_MISMATCH')
    first = a.decode_one(md,boot,ENTRY)
    if first is None: raise RuntimeError('ENTRY_UNDECODABLE')
    queue = deque([(ENTRY,0,'0xF020D0AA')]); nodes={}; edges=[]; external=[]; visited=set();total=0
    while queue and len(nodes)<MAX_FUNCTIONS and total<MAX_TOTAL_INSNS:
        ent, depth, provenance = queue.popleft()
        ent &= ~1
        if ent in visited: continue
        visited.add(ent)
        name,_=image_at(images,ent,2)
        if name is None:
            external.append(f'UNMAPPED_CALLEE=0x{ent:08X} FROM={provenance}');continue
        data = walk_function(md,images,ent)
        nodes[ent]=(depth,name,data)
        total+=len(data['insns'])
        if depth >= MAX_DEPTH: continue
        for src,kind,dst in data['calls']:
            if dst is None:
                external.append(f'INDIRECT_CALL=0x{src:08X} OWNER=0x{ent:08X}')
            else:
                nxt=dst & ~1
                dst_name,_=image_at(images,nxt,2)
                edges.append((ent,src,kind,nxt,dst_name))
                if dst_name is not None and nxt not in visited:
                    queue.append((nxt,depth+1,f'0x{src:08X}'))
                elif dst_name is None:
                    external.append(f'OUTSIDE_KNOWN_IMAGES=0x{nxt:08X} FROM=0x{src:08X}')
    lines=[
        'S13.5A.122 — POST-SELECTION BOOT CALLEE: BOUNDED MULTI-FUNCTION AUDIT',
        'STRICTLY_OFFLINE=YES IMAGES_READ_ONLY=YES NO_USB_COM_PHONE_FLASH_PATCH_REPACK=YES',
        'NO_GUEST_EXECUTION=YES NO_REAL_UI_OK_TRACE=YES',
        f'ALICE_GUARD=PASS SIZE=0x{len(alice):X} SHA256={a.ALICE_SHA}',
        f'BOOT_ZIMAGE_GUARD=PASS SIZE=0x{len(boot):X} SHA256={a.BOOT_SHA}',
        f'ZIMAGE_GUARD=PASS SIZE=0x{len(zimage):X} SHA256={a.ZIMAGE_SHA}',
        'A120_LITERAL_GUARD=PASS', 'A121_CALL_EDGE_GUARD=PASS',
        f'BOOT_FILE_USED={boot_path}',
        f'ENTRY=0x{ENTRY:08X} START_IMAGE=BOOT_ZIMAGE DEPTH={MAX_DEPTH} MAX_FUNCTIONS={MAX_FUNCTIONS}',
        f'LIMITS=PER_FUNCTION_{MAX_INSNS_PER_FUNCTION}_INSNS_TOTAL_{MAX_TOTAL_INSNS}_INSNS_LOCAL_SPAN_0x{MAX_SPAN:X}',
        '', '=== A. CALL GRAPH SUMMARY ===',
        f'FUNCTIONS_ANALYZED={len(nodes)} TOTAL_INSTRUCTIONS={total} CALL_EDGES={len(edges)} EXTERNAL_NOTES={len(external)}',
    ]
    for ent,(depth,name,data) in sorted(nodes.items()):
        lines.append(f'FUNCTION=0x{ent:08X} IMAGE={name} DEPTH={depth} INSTRUCTIONS={len(data["insns"])} CALLS={len(data["calls"])} BRANCHES={len(data["branches"])} RETURNS={len(data["exits"])} NOTES={len(data["notes"])}')
    for ent,src,kind,dst,dstname in edges:
        lines.append(f'CALL_EDGE=0x{ent:08X} VIA=0x{src:08X} TYPE={kind} TARGET=0x{dst:08X} IMAGE={dstname or "UNMAPPED"}')
    lines.extend(external)
    for ent,(depth,name,data) in sorted(nodes.items(),key=lambda item:(item[1][0],item[0])):
        lines.extend(['',f'=== B. FUNCTION 0x{ent:08X} / {name} / DEPTH {depth} ===',
                      f'FUNCTION_ENTRY=0x{ent:08X}'])
        for addr,ins in sorted(data['insns'].items()):
            kind,dst=classify(ins)
            lines.append(f'  0x{addr:08X} {ins.bytes.hex():10} {ins.mnemonic:10} {ins.op_str:35} [{kind}]'+(f' -> 0x{dst:08X}' if dst is not None else ''))
        lines.append(f'CALLS={len(data["calls"])}')
        for src,kind,dst in data['calls']:
            lines.append(f'CALL=0x{src:08X} TYPE={kind} TARGET='+ (f'0x{dst:08X}' if dst is not None else 'UNRESOLVED'))
        lines.append(f'BRANCHES={len(data["branches"])}')
        for src,kind,dst in data['branches']:
            lines.append(f'BRANCH=0x{src:08X} TYPE={kind} TARGET='+ (f'0x{dst:08X}' if dst is not None else 'UNRESOLVED'))
        lines.append(f'PC_LITERAL_REFS={len(data["literals"])}')
        for src,cell,loc,val in data['literals']:
            lines.append(f'LITERAL=0x{src:08X} CELL=0x{cell:08X} IMAGE={loc} VALUE='+ (f'0x{val:08X}' if val is not None else 'UNMAPPED'))
        lines.append(f'MEMORY_ACCESS_CANDIDATES={len(data["accesses"])}')
        for src,mnem,op in data['accesses']:
            lines.append(f'MEMORY=0x{src:08X} OP={mnem} OPERANDS={op}')
        for src,kind in data['exits']:lines.append(f'EXIT=0x{src:08X} TYPE={kind}')
        for note in data['notes']:lines.append(f'NOTE={note}')
    lines.extend(['','=== C. PROOF BOUNDARIES / NEXT DECISION ===',
        'MULTIFUNCTION_CFG_PRODUCED=YES',
        'CALL_GRAPH_COMPLETE=NO_BOUNDED_DEPTH_AND_UNRESOLVED_INDIRECT_POSSIBLE',
        'R0_R1_LIVENESS_AND_RUNTIME_MEMORY_VALUES=NOT_PROVEN_STATIC_DISASSEMBLY_ONLY',
        'REAL_OK_TO_AUDIO_8928_DISPATCH=UNPROVEN',
        'AUDIO_8928_PLAYBACK=UNPROVEN',
        'SAFE_ROM_RELOCATION=UNPROVEN',
        'NO_HARDWARE_PATCH_AUTHORIZED=YES',
        'NEXT=REVIEW_CALL_GRAPH_AND_DECIDE_WHETHER_POSTSELECTION_PATH_IS_RELEVANT_TO_AUDIO',
        'A122_RESULT=BOUNDED_CALL_GRAPH_RECORDED_NOT_AUDIO_LAUNCH_PROOF'])
    return '\n'.join(lines)+'\n'


def self_test():
    a=load_a121()
    assert a.TARGET == CALLER and a.BOOT_BASE <= ENTRY < a.ZIMAGE_BASE
    assert image_at({'X':(0x1000,bytes.fromhex('01020304'))},0x1001,2)==('X',bytes.fromhex('0203'))
    assert u32_at({'X':(0x1000,bytes.fromhex('01020304'))},0x1000)==('X',0x04030201)
    md=a.make_decoder()
    ins=next(md.disasm(bytes.fromhex('7047'),0x1000,1))
    assert classify(ins)[0]=='RETURN'
    print('A122_SELF_TEST=PASS_PROVENANCE_HELPERS_AND_THUMB_RET')


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--root',type=Path)
    ap.add_argument('--boot',type=Path)
    ap.add_argument('--out',type=Path)
    ap.add_argument('--self-test',action='store_true')
    args=ap.parse_args()
    try:
        if args.self_test:
            self_test()
            if args.root is None and args.boot is None and args.out is None:return 0
        if not all((args.root,args.boot,args.out)):
            ap.error('--root, --boot, --out required for audit')
        a=load_a121()
        alice=a.assert_canonical(args.root/'research/f2/work/extracted/altice_alice/alice-py.bin','ALICE',a.ALICE_SIZE,a.ALICE_SHA)
        zimage=a.assert_canonical(args.root/'research/f2/work/extracted/altice_platform/zimage.bin','ZIMAGE',a.ZIMAGE_SIZE,a.ZIMAGE_SHA)
        boot=a.assert_canonical(args.boot,'BOOT_ZIMAGE',a.BOOT_SIZE,a.BOOT_SHA)
        content=generate(a,alice,boot,zimage,args.boot.resolve())
        args.out.parent.mkdir(parents=True,exist_ok=True)
        with args.out.open('x',encoding='utf-8',newline='\n') as fp:fp.write(content)
        print('A122_REPORT_CREATED='+str(args.out.resolve()))
        print('A122_RESULT=BOUNDED_CALL_GRAPH_RECORDED_NOT_AUDIO_LAUNCH_PROOF')
        return 0
    except (OSError,RuntimeError,ValueError,AssertionError,ImportError) as e:
        print('A122_ABORT='+repr(e),file=sys.stderr)
        return 1

if __name__=='__main__':sys.exit(main())
