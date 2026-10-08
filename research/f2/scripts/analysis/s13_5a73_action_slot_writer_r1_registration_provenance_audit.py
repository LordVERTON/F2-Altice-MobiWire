#!/usr/bin/env python3
# -*- coding: ascii -*-
"""S13.5A.73 - source-of-r1 audit for the single code-proven action-slot writer.

Firmware and user safety:
- Only reads locally extracted immutable canonical ALICE and ZIMAGE binaries.
- No USB, COM, hardware, mtkclient, packet handling, writeflash, patch or repack.
- Prints a narrow, branch-cautious report. No files written by the script.
- Printed instruction slices are disassemblies, NOT runtime execution proofs.
"""
from __future__ import annotations

import argparse
import hashlib
import struct
from dataclasses import dataclass
from pathlib import Path

try:
    from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_LITTLE_ENDIAN
    from capstone.arm import ARM_OP_IMM, ARM_OP_MEM, ARM_OP_REG, ARM_REG_PC
except ImportError as exc:
    raise SystemExit('ABORT: missing local Python dependency capstone: %s' % exc)

A_BASE, A_SIZE = 0x1024EC00, 0x157BB4
A_SHA = '7246242b67afae0d13104452bc3257827cb778119b54e7a26fb7fb55993697ea'
Z_BASE, Z_SIZE = 0xF023CA50, 0x185E98
Z_SHA = '85fba8c8ae8161e4c1f8ced7983ec30d48c54ab10e51c69fcdfb900aca220954'
SLOT = 0xF009343C
LOAD, STORE = 0xF02ADBAC, 0xF02ADBAE


def bar(title):
    print('\n' + '=' * 108 + '\n' + title + '\n' + '=' * 108)


@dataclass(frozen=True)
class Img:
    name: str
    base: int
    data: bytes

    def within(self, addr, n=1):
        return self.base <= addr and addr + n <= self.base + len(self.data)

    def read(self, addr, n):
        if not self.within(addr, n):
            raise SystemExit('ABORT: invalid image read %s 0x%08X +0x%X' % (self.name, addr, n))
        return self.data[addr - self.base:addr - self.base + n]

    def u32(self, addr):
        return struct.unpack('<I', self.read(addr, 4))[0]


def load_file(path, name, base, size, sha):
    if not path.is_file():
        raise SystemExit('ABORT: canonical image missing: %s' % path)
    data = path.read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    passed = len(data) == size and digest == sha
    print('%s bytes=0x%X sha256=%s GUARD=%s file=%s' % (
        name, len(data), digest, 'PASS' if passed else 'FAIL', path))
    if not passed:
        raise SystemExit('ABORT: canonical byte guard failed')
    return Img(name, base, data)


class Decode:
    def __init__(self, images):
        self.images = images
        self.cs = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_LITTLE_ENDIAN)
        self.cs.detail = True

    def image(self, addr, n=2):
        for img in self.images:
            if img.within(addr, n):
                return img
        return None

    def one(self, addr):
        img = self.image(addr)
        if img is None:
            return None
        available = min(4, img.base + len(img.data) - addr)
        return next(iter(self.cs.disasm(img.read(addr, available), addr, count=1)), None)

    def literal(self, ins):
        if not ins.mnemonic.lower().startswith('ldr') or len(ins.operands) < 2:
            return None
        op = ins.operands[1]
        if op.type != ARM_OP_MEM or op.mem.base != ARM_REG_PC:
            return None
        cell = ((ins.address + 4) & ~3) + op.mem.disp
        img = self.image(ins.address)
        if img is None or not img.within(cell, 4):
            return cell, None
        return cell, img.u32(cell)

    def seq(self, start, stop):
        if (start | stop) & 1 or not 0 < stop - start <= 0x200:
            raise SystemExit('ABORT: disassembly window exceeds bounded limits')
        out = []
        at = start
        while at < stop:
            ins = self.one(at)
            if ins is None or ins.size not in (2, 4) or at + ins.size > stop:
                return out, at
            out.append(ins)
            at += ins.size
        return out, None


def describe(dec, ins):
    lit = dec.literal(ins)
    extra = ''
    if lit is not None:
        cell, value = lit
        extra = ' ; PC_CELL=0x%08X U32=%s' % (
            cell, ('0x%08X' % value) if value is not None else 'UNMAPPED')
        if value == SLOT:
            extra += ' ACTION_CALLBACK_SLOT'
        elif value is not None and dec.image(value & ~1):
            extra += ' IMAGE_CODE_OR_DATA_CANDIDATE'
    if ins.address == STORE:
        extra += ' <-- SINGLE_PROVEN_WRITE_TO_[F009343C]'
    return '  0x%08X: %-10s %-35s%s' % (ins.address, ins.mnemonic, ins.op_str, extra)


def ensure_anchors(dec):
    ld, st = dec.one(LOAD), dec.one(STORE)
    if ld is None or st is None:
        raise SystemExit('ABORT: writer anchors unavailable')
    v = dec.literal(ld)
    if ld.mnemonic.lower().split('.')[0] != 'ldr' or v is None or v[1] != SLOT:
        raise SystemExit('ABORT: slot LDR anchor mismatch: %s %s literal=%s' % (
            ld.mnemonic, ld.op_str, v))
    if (len(ld.operands) < 2 or ld.operands[0].type != ARM_OP_REG
            or ld.reg_name(ld.operands[0].reg) != 'r2'):
        raise SystemExit('ABORT: unexpected global slot register at F02ADBAC')
    if st.mnemonic.lower().split('.')[0] != 'str' or len(st.operands) < 2:
        raise SystemExit('ABORT: global slot writer mnemonic mismatch')
    a, m = st.operands[:2]
    if not (a.type == ARM_OP_REG and st.reg_name(a.reg) == 'r1'
            and m.type == ARM_OP_MEM and st.reg_name(m.mem.base) == 'r2'
            and m.mem.disp == 0):
        raise SystemExit('ABORT: global slot writer registers/memory mismatch: %s %s' % (
            st.mnemonic, st.op_str))
    if ld.address + ld.size != st.address:
        raise SystemExit('ABORT: unexpected gap between slot address load and store')
    print('PASS: 0x%08X loads global slot address 0x%08X into r2' % (LOAD, SLOT))
    print('PASS: 0x%08X stores ENTRY r1 into [r2] = [0x%08X]' % (STORE, SLOT))
    return ld, st


def reg_writes(ins, reg_name):
    try:
        _reads, writes = ins.regs_access()
        return reg_name in [ins.reg_name(r) for r in writes]
    except Exception:
        # Conservative fallback: don't assert the register is untouched.
        return None


def trace_r1(dec, insns):
    prior = [ins for ins in insns if ins.address < STORE]
    defs = []
    calls = []
    for ins in prior:
        key = ins.mnemonic.lower().split('.')[0]
        if key in ('bl', 'blx'):
            calls.append(ins)
        is_def = reg_writes(ins, 'r1')
        if is_def is True or (is_def is None and ins.operands
                and ins.operands[0].type == ARM_OP_REG
                and ins.reg_name(ins.operands[0].reg) == 'r1'):
            defs.append(ins)
    print('Candidate writes/updates of r1 in selected linear decode = %d' % len(defs))
    for ins in defs[-14:]:
        print(describe(dec, ins))
    print('Last direct r1-register touch (linear, path-unverified):')
    if not defs:
        print('  NOT_SEEN: r1 may be passed in from caller, set on another branch, or altered by a call')
        return
    last = defs[-1]
    print(describe(dec, last))
    later_calls = [ins for ins in calls if last.address < ins.address < STORE]
    if later_calls:
        print('  ABI_BARRIER: calls after the last r1 source can clobber r1:')
        for ins in later_calls:
            print(describe(dec, ins))
        print('  CLASSIFICATION=UNRESOLVED (r1 caller-saved across BL/BLX)')
        return
    if last.mnemonic.lower().split('.')[0] == 'ldr':
        lit = dec.literal(last)
        if lit is not None:
            cell, value = lit
            if value is not None:
                print('  DIRECT_LITERAL_CANDIDATE=0x%08X, at U32 cell 0x%08X' % (value, cell))
                print('  WARNING: this is only a linear-path candidate until control flow confirms its reachability')
                if dec.image(value & ~1, 2):
                    preview_target(dec, value)
            else:
                print('  SOURCE_LITERAL_UNAVAILABLE')
        else:
            print('  NON_PC_LDR_SOURCE: source memory depends on runtime register contents')
    elif last.mnemonic.lower().split('.')[0] in ('mov', 'movs'):
        print('  SOURCE_MAY_BE_MOVED_FROM_A_REGISTER: inspect the prior register definition in the slice')
    else:
        print('  SOURCE_HAS_ARITHMETIC_OR_OTHER_REGISTER_UPDATE: inspect full branch path')


def preview_target(dec, value):
    target = value & ~1
    img = dec.image(target, 2)
    if img is None:
        return
    print('  CANDIDATE_TARGET_IN=%s @0x%08X (not confirmed executable)' % (img.name, target))
    if (value & 1) == 0:
        print('  NO_THUMB_BIT in literal: target may be data/ARM or an adjusted pointer')
        return
    insns, stop = dec.seq(target, target + 0x40)
    print('  THUMB_CANDIDATE_ENTRY 0x%08X (only a preview, never called)' % target)
    for ins in insns[:18]:
        print('    0x%08X: %-9s %s' % (ins.address, ins.mnemonic, ins.op_str))
    if stop is not None:
        print('    DECODE_STOP 0x%08X' % stop)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--alice', type=Path, default=Path(r'.\research\f2\work\extracted\altice_alice\alice-py.bin'))
    p.add_argument('--zimage', type=Path, default=Path(r'.\research\f2\work\extracted\altice_platform\zimage.bin'))
    args = p.parse_args()
    print('S13.5A.73 - GLOBAL ACTION SLOT WRITER r1 PROVENANCE')
    print('OFFLINE ONLY: no USB/COM/PHONE/BROM/DA/FLASH_WRITE/ERASE/PATCH/REPACK')
    print('Only 2 SHA-pinned local images read; stdout only; ASCII-safe output')
    bar('A. FAIL-CLOSED CANONICAL IMAGE GUARDS')
    al = load_file(args.alice, 'ALICE', A_BASE, A_SIZE, A_SHA)
    zi = load_file(args.zimage, 'ZIMAGE', Z_BASE, Z_SIZE, Z_SHA)
    dec = Decode((al, zi))
    bar('B. EXACT GLOBAL ACTION SLOT WRITE ANCHORS - NO PROLOGUE ASSUMPTION')
    ld, st = ensure_anchors(dec)
    print(describe(dec, ld))
    print(describe(dec, st))
    bar('C. TIGHT WINDOWS AROUND THE ONLY PROVEN PC-LITERAL ACTION SLOT WRITER')
    print('WARNING: these are linear Thumb slices. A pool, branch, entry mid-instruction, or call may invalidate any apparent source.')
    windows = [
        ('upstream context A', 0xF02ADAF0, 0xF02ADB50),
        ('upstream context B', 0xF02ADB50, 0xF02ADB98),
        ('writer ingress and first uses', 0xF02ADB98, 0xF02ADBC6),
        ('writer egress', 0xF02ADBC6, 0xF02ADBF8),
    ]
    for name, start, end in windows:
        print('\n[%s] 0x%08X..0x%08X' % (name, start, end))
        insns, stop = dec.seq(start, end)
        for ins in insns:
            print(describe(dec, ins))
        if stop is not None:
            print('  DECODE_STOP=0x%08X; no subsequent dataflow claimed' % stop)
    bar('D. EXACT LITERAL CELLS SURROUNDING WRITER - DATA, NOT INFERRED CODE')
    for addr in (0xF02ADC88, 0xF02ADC8C, 0xF02ADC90, 0xF02ADC94, 0xF02ADC98, 0xF02ADC9C, 0xF02ADCA0):
        value = zi.u32(addr)
        tag = ' ACTION_SLOT' if value == SLOT else ''
        if dec.image(value & ~1, 2):
            tag += ' IN_FIRMWARE_IMAGE_NOT_NECESSARILY_CODE'
        print('  U32[0x%08X]=0x%08X%s' % (addr, value, tag))
    bar('E. BOUNDED r1 PROVENANCE BEFORE str r1,[r2]')
    # Prioritize the closest linear context. Its alignment will be checked against the verified sink.
    chosen = None
    for start in (0xF02ADB60, 0xF02ADB70, 0xF02ADB80, 0xF02ADB90, 0xF02ADBA0):
        insns, stop = dec.seq(start, STORE + st.size)
        at_store = [ins for ins in insns if ins.address == STORE]
        at_load = [ins for ins in insns if ins.address == LOAD]
        if stop is None and at_store and at_load:
            chosen = (start, insns)
            break
    if chosen is None:
        print('No contiguous trial decode reached both anchors. SOURCE=UNRESOLVED, no source inference.')
    else:
        start, insns = chosen
        print('Candidate contiguous decoder start 0x%08X reaches both anchors (NOT certified CFG)' % start)
        trace_r1(dec, insns)
    bar('F. DISCRIMINATING DECISION')
    print('KNOWN: F02ADBAC loads 0xF009343C; F02ADBAE stores r1 into [F009343C].')
    print('Unknown until this report is interpreted: r1 provenance, exact installed callback,')
    print('whether callable r2 is an app ID/object pointer; Audio 0x8928 linkage remains unproven.')
    print('Never infer a dynamic/static record-buffer alias from shared stride or nearby references.')
    print('PHONE ACCESSED=NO; FLASH MODIFIED=NO; REPACK=NO; PATCH=NO; WRITE AUTHORIZED=NO')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
