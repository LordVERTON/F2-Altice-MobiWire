#!/usr/bin/env python3
"""S13.5A.92: offline bounded reachable Thumb CFG for 0x102FC624.
No phone connection, flash writes or mutation of firmware bytes.
Requires capstone.
"""
import argparse
import hashlib
from collections import deque
from pathlib import Path
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB
from capstone.arm import ARM_OP_IMM

def num(s): return int(s,0)
def main():
    p=argparse.ArgumentParser()
    p.add_argument('--image',type=Path,required=True)
    p.add_argument('--base',type=num,default=0x1024EC00)
    p.add_argument('--entry',type=num,default=0x102FC624)
    p.add_argument('--span',type=num,default=0x600)
    p.add_argument('--sha256',required=True)
    p.add_argument('--out',type=Path,required=True)
    a=p.parse_args()
    if not 0 < a.span <= 0x4000: p.error('span must be 1..0x4000')
    blob=a.image.read_bytes()
    digest=hashlib.sha256(blob).hexdigest()
    if digest.lower()!=a.sha256.lower(): p.error('ABORT SHA256 mismatch')
    entry=a.entry & ~1
    start=entry
    end=start+a.span
    if start<a.base or end>a.base+len(blob): p.error('ABORT window outside canonical image')
    md=Cs(CS_ARCH_ARM,CS_MODE_THUMB);md.detail=True
    def decode(addr):
        off=addr-a.base
        ins=list(md.disasm(blob[off:off+4],addr,count=1))
        return ins[0] if ins and ins[0].address==addr else None
    queue=deque([entry]); seen=set(); edges=[]; calls=[]; unresolved=[]; exits=[]
    while queue:
        addr=queue.popleft()
        if addr in seen:continue
        if not(start<=addr<end):
            unresolved.append(f'edge outside bounded region: 0x{addr:08X}')
            continue
        ins=decode(addr)
        if ins is None:
            unresolved.append(f'decode failed: 0x{addr:08X}')
            continue
        seen.add(addr)
        m=ins.mnemonic.lower(); op=ins.op_str.lower(); nextpc=addr+ins.size
        target=(ins.operands[0].imm & ~1) if ins.operands and ins.operands[0].type==ARM_OP_IMM else None
        def visit(t,kind):
            edges.append((addr,t,kind)); queue.append(t)
        if m=='pop' and 'pc' in op or m=='bx' and 'lr' in op:
            exits.append(addr);continue
        if m in ('bl','blx'):
            calls.append((addr,m,op));visit(nextpc,'return-assumed');continue
        if m in ('b','b.w'):
            if target is not None:visit(target,'jump')
            else:unresolved.append(f'indirect jump at 0x{addr:08X}: {m} {op}')
            continue
        if m.startswith('b.') or m in ('cbz','cbnz') or (m.startswith('b') and m not in ('bic','bkpt','bl','blx','bx')):
            if target is not None:visit(target,'conditional')
            else:unresolved.append(f'unresolved conditional branch: 0x{addr:08X}: {m} {op}')
            visit(nextpc,'fallthrough');continue
        if m=='bx' or (m=='mov' and op.startswith('pc,')) or (m=='ldr' and op.startswith('pc,')):
            unresolved.append(f'indirect control transfer at 0x{addr:08X}: {m} {op}');continue
        visit(nextpc,'next')
    lines=['S13.5A.92 — bounded reachable Thumb audit (OFFLINE)',
           f'image={a.image}',f'sha256={digest}', 'hash_status=PASS',
           f'base=0x{a.base:08X}',f'entry=0x{entry:08X}',f'window_end=0x{end:08X}',
           'WARNING: static branch traversal, not proof of functional semantics.',
           'WARNING: return from BL/BLX is assumed; indirect targets not resolved.',
           f'reachable_instructions={len(seen)}', '', '=== REACHABLE INSTRUCTIONS ===']
    for addr in sorted(seen):
        ins=decode(addr)
        lines.append(f'{addr:08X} {ins.bytes.hex():<10} {ins.mnemonic:<10} {ins.op_str}')
    lines += ['', '=== CALLS ===']
    lines += [f'{a:08X} {m} {op}' for a,m,op in calls] or ['none']
    lines += ['', '=== NONLINEAR EDGES ===']
    lines += [f'{a:08X} -> {b:08X} {kind}' for a,b,kind in edges if kind not in ('next','return-assumed')] or ['none']
    lines += ['', '=== RETURNS ===']
    lines += [f'{a:08X}' for a in exits] or ['none']
    lines += ['', '=== UNRESOLVED / LIMITATIONS ===']
    lines += unresolved or ['none detected within bound']
    lines += ['', '=== LITERAL AND STRUCTURE QUESTIONS ===',
              'Identify PC-relative literal values and pointer targets manually.',
              'Determine whether arguments r0, r1 point to a dispatch/event struct.',
              'Trace writes and call targets before naming an audio launcher.']
    a.out.parent.mkdir(parents=True,exist_ok=True)
    a.out.write_text('\n'.join(lines)+'\n',encoding='utf-8')
    print(f'Wrote {a.out}; SHA256 PASS; reachable {len(seen)}; unresolved {len(unresolved)}')
if __name__=='__main__':main()
