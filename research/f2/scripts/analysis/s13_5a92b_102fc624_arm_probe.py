#!/usr/bin/env python3
"""Read-only S13.5A.92B: test ARM-mode entry and bounded ARM control flow."""
import argparse, hashlib
from pathlib import Path
from collections import deque
from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_LITTLE_ENDIAN
from capstone.arm import ARM_OP_IMM, ARM_CC_AL, ARM_CC_INVALID

def number(s): return int(s, 0)
p = argparse.ArgumentParser()
p.add_argument('--image', type=Path, required=True)
p.add_argument('--base', type=number, default=0x1024EC00)
p.add_argument('--entry', type=number, default=0x102FC624)
p.add_argument('--span', type=number, default=0x600)
p.add_argument('--sha256', required=True)
p.add_argument('--out', type=Path, required=True)
a = p.parse_args()
if a.entry % 4 or a.span % 4 or not 0 < a.span <= 0x4000:
    p.error('ARM entry/span must be 4-byte aligned; span within 0x4..0x4000')
b = a.image.read_bytes()
h = hashlib.sha256(b).hexdigest()
if h.lower() != a.sha256.lower(): p.error('ABORT: SHA256 mismatch')
if not (a.base <= a.entry < a.entry+a.span <= a.base+len(b)): p.error('ABORT: outside image')
md = Cs(CS_ARCH_ARM, CS_MODE_ARM | CS_MODE_LITTLE_ENDIAN); md.detail=True

def decode(pc):
    off=pc-a.base
    ins=list(md.disasm(b[off:off+4], pc, count=1))
    return ins[0] if ins and ins[0].address==pc and ins[0].size==4 else None

q=deque([a.entry]); seen={}; calls=[]; edges=[]; unresolved=[]; returns=[]
while q:
    pc=q.popleft()
    if pc in seen: continue
    if not (a.entry <= pc < a.entry+a.span):
        unresolved.append(f'out-of-window control-flow edge 0x{pc:08X}'); continue
    ins=decode(pc)
    if ins is None:
        unresolved.append(f'decode failure 0x{pc:08X}, raw={b[pc-a.base:pc-a.base+4].hex()}'); continue
    seen[pc]=ins
    m=ins.mnemonic.lower().split('.')[0]; op=ins.op_str.lower(); nxt=pc+4
    target=ins.operands[0].imm if ins.operands and ins.operands[0].type==ARM_OP_IMM else None
    cond=ins.cc not in (ARM_CC_AL, ARM_CC_INVALID)
    def go(dst, why):
        edges.append((pc,dst,why));q.append(dst)
    if m.startswith('bl'):
        calls.append((pc, ins.mnemonic, op, f'{target:#010x}' if target is not None else 'indirect'))
        go(nxt, 'return-assumed')
    elif (m.startswith('bx') or (m.startswith('mov') and op.startswith('pc,')) or (m.startswith('ldr') and op.startswith('pc,')) or (m.startswith('pop') and 'pc' in op)):
        returns.append(f'0x{pc:08X} {ins.mnemonic} {op} (terminal/indirect; target not resolved)')
        if cond: go(nxt,'conditional fallthrough')
    elif m.startswith('b') and m not in ('bic','bfi','bfc','bkpt'):
        if target is None: unresolved.append(f'unresolved branch at 0x{pc:08X}: {ins.mnemonic} {op}')
        else: go(target,'branch')
        if cond: go(nxt,'conditional fallthrough')
    else:
        if 'pc' in op and m.startswith(('ldm','pop')):
            returns.append(f'0x{pc:08X} {ins.mnemonic} {op} (pc write)')
        else: go(nxt,'next')
lines=[
'S13.5A.92B ARM-mode control-flow probe (OFFLINE; NO WRITES)',
f'image={a.image}', f'sha256={h}', 'hash_status=PASS',
f'base=0x{a.base:08X}',f'entry=0x{a.entry:08X}',f'window_end=0x{a.entry+a.span:08X}',
f'entry_raw={b[a.entry-a.base:a.entry-a.base+32].hex(" ")}',
'WARNING: bounded heuristic CFG, ARM mode assumed based on BLX instruction; not semantic proof.',
'WARNING: branch returns assumed for calls, indirect targets unresolved; possible data decoded as instructions.',
f'reachable_instructions={len(seen)}', '', '=== REACHABLE ARM INSTRUCTIONS ===']
for pc, ins in sorted(seen.items()):
    lines.append(f'{pc:08X} {ins.bytes.hex():<8} {ins.mnemonic:<12} {ins.op_str}')
lines.extend(['','=== CALLS ==='])
lines.extend(f'{pc:08X} {m} {op} -> {target}' for pc,m,op,target in calls) if calls else lines.append('none')
lines.extend(['','=== BRANCH EDGES ==='])
lines.extend(f'{pc:08X} -> {dst:08X} {why}' for pc,dst,why in edges if why not in ('next','return-assumed'))
lines.extend(['','=== EXITS / INDIRECT ==='])
lines.extend(returns or ['none'])
lines.extend(['','=== UNRESOLVED ==='])
lines.extend(unresolved or ['none'])
a.out.parent.mkdir(parents=True,exist_ok=True)
a.out.write_text('\n'.join(lines)+'\n',encoding='utf-8')
print(f'Written {a.out}; SHA256 PASS; ARM reachable={len(seen)}; unresolved={len(unresolved)}')
