#!/usr/bin/env python3
"""S13.5A.88 — ALICE callsites to the ALREADY KNOWN native ID-dispatch gate.

STRICTLY OFFLINE AND READ-ONLY: no serial, USB, DA, phone, write, erase,
firmware patch, decompression or repacking.

S11 ALREADY PROVED (do not rediscover):
    F0316D74 -> F02CF6E8 -> 1036A900  [58-row ID -> callback lookup]
    1034C7E4       dynamic lookup with static fallback
    10336788       resolves and invokes callbacks
    F00EF124       global dispatcher slot
    102D9DC8(ctx,ID)  delegates to installed global dispatch

NEW QUESTION: which Thumb BL callsites in canonical ALICE call 102D9DC8,
and does nearby code supply an ID from selected visible-menu state rather
than a hard-coded/internal resource? A human-visible FM Radio app is present
under Multimedia, but its exact ID is NOT YET KNOWN. No invented FM ID.

Encoding-matched BL instructions are only CODE-ENCODED CANDIDATES until
function-entry and branch reachability are independently established.
"""
from __future__ import annotations

import argparse
import hashlib
import struct
from dataclasses import dataclass
from pathlib import Path

try:
    from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_LITTLE_ENDIAN, CS_OP_IMM, CS_OP_MEM
    from capstone.arm import ARM_REG_PC
except ImportError as exc:
    raise SystemExit("Capstone must be installed in the local offline venv: " + str(exc))

ALICE_BASE = 0x1024EC00
ALICE_SIZE = 0x157BB4
ALICE_SHA = "7246242b67afae0d13104452bc3257827cb778119b54e7a26fb7fb55993697ea"
ZIMAGE_BASE = 0xF023CA50
ZIMAGE_SIZE = 0x185E98
ZIMAGE_SHA = "85fba8c8ae8161e4c1f8ced7983ec30d48c54ab10e51c69fcdfb900aca220954"
DISPATCH_GATE = 0x102D9DC8
NATIVE_AUDIO_ID = 0x8928
KNOWN_IMAGE_VISIBLE_ID = 0x87ED
FM_RADIO_ID = None  # INDETERMINATE; presence in Multimedia is a user-confirmed UI observation.
RESOLVER_TABLE = 0xF0345E68

@dataclass
class Image:
    name: str
    base: int
    content: bytes
    def owns(self, addr: int, count: int = 1) -> bool:
        return self.base <= addr and addr + count <= self.base + len(self.content)
    def read(self, addr: int, count: int) -> bytes:
        if not self.owns(addr, count):
            raise ValueError(f"Out-of-bounds image read {self.name} 0x{addr:X} size={count}")
        offset = addr - self.base
        return self.content[offset:offset+count]
    def u16(self, addr: int) -> int:
        return struct.unpack('<H', self.read(addr, 2))[0]
    def u32(self, addr: int) -> int:
        return struct.unpack('<I', self.read(addr, 4))[0]

def load(name: str, path: Path, base: int, length: int, required_sha: str) -> Image:
    content = path.read_bytes()
    digest = hashlib.sha256(content).hexdigest()
    ok = len(content) == length and digest == required_sha
    print(f"{name}: path={path} size=0x{len(content):X} sha256={digest} GUARD={'PASS' if ok else 'FAIL'}")
    if not ok:
        raise SystemExit(f"ABORT: {name} canonical hash/size mismatch")
    return Image(name, base, content)

def decode_one(md, img: Image, addr: int):
    if not img.owns(addr, 2):
        return None
    b = img.read(addr, min(4, img.base + len(img.content) - addr))
    r = list(md.disasm(b, addr, count=1))
    return r[0] if r and r[0].address == addr else None

def pc_literal(ins):
    if not ins.mnemonic.startswith('ldr') or len(ins.operands) < 2:
        return None
    o = ins.operands[1]
    if o.type != CS_OP_MEM or o.mem.base != ARM_REG_PC:
        return None
    return ((((ins.address + 4) & ~3) + o.mem.disp) & 0xFFFFFFFF)

def fmt(ins, img):
    lit = pc_literal(ins)
    extra = f" ; PC_CELL=0x{lit:08X} VALUE=0x{img.u32(lit):08X}" if lit is not None and img.owns(lit, 4) else ""
    return f"0x{ins.address:08X} {ins.mnemonic:<9} {ins.op_str:<45} bytes={ins.bytes.hex(' ')}{extra}"

def thumb_bl_candidate(md, img, addr):
    # Only consider aligned 32-bit Thumb encoding beginning with 11110...
    # and second halfword with BL's characteristic high bits. This avoids
    # re-disassembling ALL Thumb halfwords and limits raw/data false positives.
    h1, h2 = img.u16(addr), img.u16(addr + 2)
    if (h1 & 0xF800) != 0xF000 or (h2 & 0xD000) != 0xD000:
        return None
    ins = decode_one(md, img, addr)
    if not ins or ins.size != 4 or ins.mnemonic != 'bl' or not ins.operands:
        return None
    op = ins.operands[0]
    if op.type != CS_OP_IMM or (op.imm & 0xFFFFFFFF) != DISPATCH_GATE:
        return None
    return ins

def find_alice_direct_bl(md, img):
    results = []
    # ALICE-target is far outside ZIMAGE Thumb BL range; restrict to ALICE.
    for off in range(0, len(img.content) - 3, 2):
        ins = thumb_bl_candidate(md, img, img.base + off)
        if ins is not None:
            results.append(ins)
    return results

def bounded_window(md, img, site, instructions=12):
    # A raw linear window is explicitly NOT a proven CFG; no semantic claims
    # about preceding register values across conditional control flow.
    start = max(img.base, (site - 0x22) & ~1)
    end = min(img.base + len(img.content), site + 0xC)
    at = start
    count = 0
    print(f"    WINDOW_RAW_THUMB 0x{start:08X}..0x{end:08X} (NOT CFG, possible data)")
    while at + 2 <= end and count < instructions + 10:
        ins = decode_one(md, img, at)
        if not ins or at + ins.size > end:
            print(f"      STOP_NO_DECODE at=0x{at:08X}")
            break
        lead = '>>>' if at == site else '   '
        print('      ' + lead + ' ' + fmt(ins, img))
        at += ins.size
        count += 1

def run(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--alice', type=Path,
                   default=Path('research/f2/work/extracted/altice_alice/alice-py.bin'))
    p.add_argument('--zimage', type=Path,
                   default=Path('research/f2/work/extracted/altice_platform/zimage.bin'))
    args = p.parse_args(argv)

    print('S13.5A.88 - SELECTED-MENU ID -> KNOWN DISPATCHER CALLSITES')
    print('STRICTLY OFFLINE / READ-ONLY; no hardware/USB/COM/phone or firmware mutation')
    a = load('ALICE', args.alice, ALICE_BASE, ALICE_SIZE, ALICE_SHA)
    z = load('ZIMAGE', args.zimage, ZIMAGE_BASE, ZIMAGE_SIZE, ZIMAGE_SHA)
    md = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_LITTLE_ENDIAN)
    md.detail = True

    print('\n[A] KNOWN S11 RESOLVER/ID-DISPATCH CONTRACT — NOT REAUDITED')
    print('F0316D74 -> F02CF6E8 -> 1036A900; 1034C7E4 -> 10336788; global F00EF124; gateway=102D9DC8')
    print(f'IMAGE_VISIBLE_ID=0x{KNOWN_IMAGE_VISIBLE_ID:04X}; AUDIO_NATIVE_ID=0x{NATIVE_AUDIO_ID:04X}; FM_RADIO_ID=UNKNOWN')
    if not (a.owns(DISPATCH_GATE, 2) and z.owns(RESOLVER_TABLE, 58*8)):
        raise SystemExit('ABORT: known dispatcher/table lies outside pinned images')
    # A87 exact rows, minimal sanity: don't restart lookup analysis.
    for i, ident, callback in ((14, 0x87ED, 0xF02F3F9D), (22, 0x8928, 0x1033D841)):
        addr = RESOLVER_TABLE + i * 8
        ok = z.u16(addr) == ident and z.u32(addr+4) == callback
        print(f'KNOWN_ROW[{i}] id=0x{z.u16(addr):04X} cb=0x{z.u32(addr+4):08X} GUARD={"PASS" if ok else "FAIL"}')
        if not ok:
            raise SystemExit('ABORT: table row guard mismatch')
    print('\n[B] THUMB ENTRY PREVIEW AT KNOWN GATE (NO RE-CLASSIFICATION)')
    bounded_window(md, a, DISPATCH_GATE, instructions=8)

    print('\n[C] EXACT DIRECT THUMB BL -> 102D9DC8 (ALICE ONLY)')
    hits = find_alice_direct_bl(md, a)
    print(f'ALICE_RAW_ENCODING_CANDIDATES={len(hits)}')
    print('ENCODING_MATCH_NOT_CFG_REACHABILITY=YES; indirect callers and veneer aliases not excluded')
    for ins in hits[:35]:
        print('  CALLSITE ' + fmt(ins, a))
        bounded_window(md, a, ins.address, instructions=14)
    if len(hits) > 35:
        print(f'CALLSITE_PRINT_CAPPED=YES omitted={len(hits)-35}; do not claim fully characterized')

    print('\n[D] SPECIFIC MISSING LINK / STOP RULE')
    print('Missing: selected visible-menu record or action event -> ID argument of 102D9DC8/10336788')
    print('Image and FM Radio are user-visible positive controls; FM numeric ID not inferred')
    print('A direct BL with nearby numeric 8928 would NOT alone prove an OK/Select path')
    print('If no reachable menu-sourced callsite emerges, STOP generic dispatcher audits and return to visible menu item construction')
    print('NO_PHONE_ACCESS=YES NO_FIRMWARE_WRITE=YES PATCH_AUTHORIZED=NO')

if __name__ == '__main__':
    run()
