#!/usr/bin/env python3
"""S13.5A.91: bounded, offline Thumb disassembly around 0x102EF44C.
No USB, serial, writes or firmware modifications.
Requires: pip install capstone
"""
import argparse, hashlib
from pathlib import Path
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB

def num(s): return int(s, 0)

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument('--image', required=True, type=Path)
    ap.add_argument('--base', required=True, type=num, help='Verified memory address of file offset 0')
    ap.add_argument('--address', type=num, default=0x102EF44C)
    ap.add_argument('--bytes', type=num, default=0x200, dest='length')
    ap.add_argument('--sha256', help='Expected SHA256, required for a controlled PASS')
    ap.add_argument('--out', type=Path, default=Path('s13_5a91_102ef44c_audit.txt'))
    a=ap.parse_args()
    if a.length<=0 or a.length>0x2000: ap.error('--bytes must be between 1 and 0x2000')
    blob=a.image.read_bytes()
    digest=hashlib.sha256(blob).hexdigest()
    if a.sha256 and digest.lower()!=a.sha256.lower():
        ap.error('ABORT: SHA256 mismatch; no analysis performed')
    start=a.address & ~1
    off=start-a.base
    if off<0 or off+a.length>len(blob):
        ap.error('ABORT: target/window outside image. Verify canonical base and image!')
    md=Cs(CS_ARCH_ARM,CS_MODE_THUMB)
    md.detail=True
    lines=[
        'S13.5A.91 — 102EF44C bounded Thumb audit (OFFLINE)',
        f'image={a.image}',f'file_size=0x{len(blob):X}',f'sha256={digest}',
        f'hash_status={"PASS" if a.sha256 else "UNVERIFIED (supply --sha256)"}',
        f'base=0x{a.base:08X}',f'entry=0x{start:08X}',
        f'file_offset=0x{off:X}',f'window_bytes=0x{a.length:X}',
        'WARNING: linear disassembly window, NOT a proven function CFG.',
        'WARNING: data/literal pools may be decoded as code.', '',
        '=== INSTRUCTIONS ==='
    ]
    calls=[]; mem=[]; returns=[]
    for ins in md.disasm(blob[off:off+a.length],start):
        m=ins.mnemonic.lower(); op=ins.op_str
        lines.append(f'{ins.address:08X}  {ins.bytes.hex():<10} {m:<9} {op}')
        if m in ('bl','blx','bx') or m.startswith('b.') or m in ('b','cbz','cbnz'):
            calls.append(f'{ins.address:08X} {m} {op}')
        if '[' in op or m in ('adr','movw','movt'):
            mem.append(f'{ins.address:08X} {m} {op}')
        if m in ('pop','bx') and ('pc' in op or 'lr' in op):
            returns.append(f'{ins.address:08X} {m} {op}')
    for label,items in [('CONTROL TRANSFERS',calls),('MEMORY/ADDRESS OPERANDS',mem),('POSSIBLE RETURNS',returns)]:
        lines.extend(['',f'=== {label} ===',*(items or ['none in window'])])
    lines += ['', '=== MANUAL QUESTIONS ===',
        '1. Which r0/r1/r2 input values are actually dereferenced?',
        '2. Does the function store to descriptor or global state?',
        '3. Are BLX/BX register operations true dispatch calls or returns?',
        '4. Which paths return to 1034529A and with what r0?',
        '5. Does the window include a function boundary or literal pool?',
        '6. Compare a known Radio FM selection path before attributing audio behavior.']
    a.out.parent.mkdir(parents=True,exist_ok=True)
    a.out.write_text('\n'.join(lines)+'\n',encoding='utf-8')
    print(f'Written {a.out} ({len(lines)} lines). SHA256 {digest}; status {"PASS" if a.sha256 else "UNVERIFIED"}')
if __name__=='__main__':main()
