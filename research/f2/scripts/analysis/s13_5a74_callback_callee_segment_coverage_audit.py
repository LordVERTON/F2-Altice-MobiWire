#!/usr/bin/env python3
# -*- coding: ascii -*-
"""S13.5A.74 - identify source bytes for the out-of-extract callback callee.

READ ONLY / OFFLINE. No USB, COM, mtkclient, hardware, patching or writes.
The ONLY content search is for three already validated code signatures from ZIMAGE
inside bounded existing local raw/extracted candidate .bin/.img files.
This does not constitute a general string, firmware, or callback xref sweep.

The exact F022A558 callback target is BEFORE canonical ZIMAGE's base; never
pretend that ZIMAGE supplies those bytes. Only disassemble target if TWO
independent unchanged code anchors validate a uniform file mapping.
"""
from __future__ import annotations

import argparse
import hashlib
import struct
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path

try:
    from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_LITTLE_ENDIAN
    from capstone.arm import ARM_OP_IMM, ARM_OP_MEM, ARM_OP_REG, ARM_REG_PC
except ImportError as exc:
    raise SystemExit('ABORT: capstone not installed in selected Python: %s' % exc)

A_BASE, A_SIZE = 0x1024EC00, 0x157BB4
A_SHA = '7246242b67afae0d13104452bc3257827cb778119b54e7a26fb7fb55993697ea'
Z_BASE, Z_SIZE = 0xF023CA50, 0x185E98
Z_SHA = '85fba8c8ae8161e4c1f8ced7983ec30d48c54ab10e51c69fcdfb900aca220954'
SLOT, HANDLER_PTR, WRAPPER, CALLEE = 0xF009343C, 0xF028877B, 0xF028877A, 0xF022A558
ANCHOR_ADDRS = (0xF028877A, 0xF02ADBA6, 0xF02B7644)
ANCHOR_LEN = 24
MAX_FILES, MAX_FILE_BYTES = 80, 16 * 1024 * 1024


def header(s):
    print('\n' + '=' * 104 + '\n' + s + '\n' + '=' * 104)


@dataclass(frozen=True)
class Image:
    name: str
    base: int
    data: bytes

    def get(self, at: int, size: int) -> bytes:
        off = at - self.base
        if off < 0 or off + size > len(self.data):
            raise SystemExit('ABORT: %s address outside verified extraction: 0x%08X' % (self.name, at))
        return self.data[off:off + size]

    def u32(self, at: int) -> int:
        return struct.unpack('<I', self.get(at, 4))[0]


def read_guarded(path: Path, name: str, base: int, size: int, sha: str) -> Image:
    if not path.is_file():
        raise SystemExit('ABORT: mandatory canonical image not found: %s' % path)
    data = path.read_bytes()
    actual = hashlib.sha256(data).hexdigest()
    status = 'PASS' if len(data) == size and actual == sha else 'FAIL'
    print('%s bytes=0x%X sha256=%s GUARD=%s path=%s' % (name, len(data), actual, status, path))
    if status != 'PASS':
        raise SystemExit('ABORT: canonical SHA/size guard failed')
    return Image(name, base, data)


def decoder():
    cs = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_LITTLE_ENDIAN)
    cs.detail = True
    return cs


def instruction(cs, img, address):
    try:
        return next(iter(cs.disasm(img.get(address, 4), address, count=1)), None)
    except (SystemExit, ValueError):
        return None


def pc_lit(ins, img):
    if not ins or not ins.mnemonic.lower().startswith('ldr') or len(ins.operands) < 2:
        return None
    op = ins.operands[1]
    if op.type != ARM_OP_MEM or op.mem.base != ARM_REG_PC:
        return None
    cell = ((ins.address + 4) & ~3) + op.mem.disp
    return cell, img.u32(cell)


def regname(ins, op):
    return ins.reg_name(op.reg) if op.type == ARM_OP_REG else ''


def verify_registration(cs, z):
    header('B. EXACT REGISTRATION AND THUMB ENTRY - FAIL CLOSED')
    # All three instructions form a straight-line local sequence: the upstream
    # r1 value is a literal function pointer, not a dataflow guess.
    specs = ((0xF02ADBAA, HANDLER_PTR, 'r1'),
             (0xF02ADBAC, SLOT, 'r2'))
    for at, expected, dest in specs:
        ins = instruction(cs, z, at)
        lit = pc_lit(ins, z)
        if lit is None or lit[1] != expected or regname(ins, ins.operands[0]) != dest:
            raise SystemExit('ABORT: registration literal changed at 0x%08X: %s %s lit=%s' % (
                at, ins.mnemonic if ins else '?', ins.op_str if ins else '?', lit))
        print('PASS 0x%08X: %-6s %-23s PC_CELL=0x%08X -> 0x%08X (%s)' % (
            at, ins.mnemonic, ins.op_str, lit[0], lit[1], dest))
    st = instruction(cs, z, 0xF02ADBAE)
    if (st is None or st.mnemonic.lower().split('.')[0] != 'str'
            or len(st.operands) < 2 or regname(st, st.operands[0]) != 'r1'
            or st.operands[1].type != ARM_OP_MEM
            or st.reg_name(st.operands[1].mem.base) != 'r2'
            or st.operands[1].mem.disp != 0):
        raise SystemExit('ABORT: action slot store instruction mismatch')
    print('PASS 0xF02ADBAE: str r1,[r2] => MEM[0xF009343C]=0xF028877B on this path')
    # Detect any control-flow break in the already observed instruction sequence.
    addr = 0xF02ADBAA
    while addr < 0xF02ADBB0:
        ins = instruction(cs, z, addr)
        if not ins or ins.address + ins.size > 0xF02ADBB0:
            raise SystemExit('ABORT: registration sequence decode gap')
        if ins.mnemonic.lower().split('.')[0] in ('b', 'bl', 'blx', 'bx', 'cbz', 'cbnz'):
            raise SystemExit('ABORT: unexpected control-flow break in registration triplet')
        addr += ins.size
    print('LOCAL_SEQUENCE=CONTIGUOUS_NO_BRANCH (does not prove invocation frequency)')
    ins0, ins1, ins2 = [instruction(cs, z, a) for a in (WRAPPER, WRAPPER+2, WRAPPER+6)]
    if any(x is None for x in (ins0, ins1, ins2)):
        raise SystemExit('ABORT: callback wrapper cannot be decoded')
    if ins0.mnemonic.lower().split('.')[0] != 'push' or ins1.mnemonic.lower().split('.')[0] != 'bl' or ins2.mnemonic.lower().split('.')[0] != 'pop':
        raise SystemExit('ABORT: callback wrapper shape mismatch: %s / %s / %s' % (
            ins0.mnemonic, ins1.mnemonic, ins2.mnemonic))
    imm = ins1.operands[0].imm & 0xFFFFFFFF
    if (imm & ~1) != CALLEE:
        raise SystemExit('ABORT: callback wrapper direct target mismatch: raw=0x%08X expected=0x%08X' % (imm, CALLEE))
    for ins in (ins0, ins1, ins2):
        print('PASS 0x%08X: %-7s %s' % (ins.address, ins.mnemonic, ins.op_str))
    print('VERIFIED_GATE: local callback target F028877B (Thumb) -> F028877A -> direct BL F022A558')


def inventory(root):
    candidates = []
    trees = ((root / 'research/f2/work/extracted', True),
             (root / 'research/f2/data/dumps', False))
    for directory, recursive in trees:
        if not directory.is_dir():
            print('  DIR_ABSENT %s' % directory)
            continue
        walker = directory.rglob('*') if recursive else directory.glob('*')
        for p in walker:
            if not p.is_file() or p.suffix.lower() not in ('.bin', '.img'):
                continue
            try:
                n = p.stat().st_size
            except OSError:
                continue
            if n > MAX_FILE_BYTES:
                print('  SKIP_OVER_SIZE size=0x%X %s' % (n, p))
                continue
            candidates.append((p, n))
            if len(candidates) > MAX_FILES:
                print('  ABORT_CANDIDATE_LIMIT=%d - narrow source directories before running' % MAX_FILES)
                return []
    return sorted(candidates, key=lambda x: str(x[0]).lower())


def all_positions(data: bytes, needle: bytes, limit=3):
    pos = 0
    hits = []
    while len(hits) <= limit:
        at = data.find(needle, pos)
        if at < 0:
            break
        hits.append(at)
        pos = at + 1
    return hits


def code_sample(cs, data, file_offset, virtual, nbytes=0x100):
    upper = min(len(data), file_offset + nbytes)
    print('  CALLBACK_CODE_SAMPLE at runtime 0x%08X -> file_off 0x%X (%d bytes)' % (
        virtual, file_offset, upper-file_offset))
    at = virtual
    for ins in cs.disasm(data[file_offset:upper], virtual):
        if ins.address >= virtual + nbytes or ins.address + ins.size > virtual + nbytes:
            break
        print('    0x%08X: %-9s %s' % (ins.address, ins.mnemonic, ins.op_str))
        op = ins.mnemonic.lower().split('.')[0]
        if op == 'bx' and ins.op_str == 'lr':
            print('    FIRST_RETURN_BX_LR (not full CFG coverage)')
            break
        if op == 'pop' and 'pc' in ins.op_str:
            print('    FIRST_RETURN_POP_PC (not full CFG coverage)')
            break


def raw_candidates(cs, z, root):
    header('D. BOUNDED RAW/EXTRACTED BINARY SIGNATURE MAPPING - NOT A GENERAL XREF SEARCH')
    print('SOURCE_DIRS: research/f2/work/extracted and research/f2/data/dumps')
    print('SEARCH_KEYS: exactly 3 code windows x %d bytes, anchored in SHA-pinned ZIMAGE' % ANCHOR_LEN)
    print('REQUIREMENT: >=2 unique signatures in ONE file with identical virtual-address/file-offset delta')
    keys = {address: z.get(address, ANCHOR_LEN) for address in ANCHOR_ADDRS}
    cands = inventory(root)
    print('CANDIDATES=%d; maxfiles=%d maxsize=%d MiB' % (len(cands), MAX_FILES, MAX_FILE_BYTES//(1024*1024)))
    candidates = 0
    mapped = False
    for path, size in cands:
        if path == root / 'research/f2/work/extracted/altice_platform/zimage.bin':
            continue
        # Raw/extracted files only; prevent scanning a large recursively generated corpus.
        buf = path.read_bytes()
        hits = {a: all_positions(buf, pat) for a, pat in keys.items()}
        found = {a: h for a, h in hits.items() if h}
        if not found:
            continue
        candidates += 1
        print('\n  SIGNATURE_CANDIDATE file=%s size=0x%X sha256=%s' % (
            path, size, hashlib.sha256(buf).hexdigest()))
        offsets = defaultdict(set)
        for addr, positions in found.items():
            print('    ZIMAGE_ANCHOR=0x%08X matches=%s' % (
                addr, ','.join('0x%X' % x for x in positions[:4])))
            if len(positions) == 1:
                offsets[addr - positions[0]].add(addr)
        for base, anch in sorted(offsets.items(), key=lambda e:(-len(e[1]),e[0])):
            print('    PROPOSED_RUNTIME_BASE=%s EVIDENCE_ANCHORS=%d %s' % (
                hex(base), len(anch), ','.join('0x%08X' % a for a in sorted(anch))))
            if len(anch) < 2:
                continue
            off = CALLEE - base
            if not 0 <= off <= len(buf) - 0x100:
                print('    TWO_ANCHOR_MAP_TARGET=OUTSIDE_THIS_FILE (callee requires an earlier contiguous segment)')
                continue
            mapped = True
            print('    TWO_ANCHOR_LINEAR_MAPPING=SUPPORTED_FOR_THIS_FILE; TARGET_BYTES_EXIST=YES')
            print('    CAUTION: mapping support does not prove runtime reachability or entry semantics.')
            code_sample(cs, buf, off, CALLEE)
    if candidates == 0:
        print('NO_SIGNATURE_MATCHES_IN_SCANNED_CANDIDATES')
        print('Typical explanation: executable bytes were decompressed/relocated and do not occur verbatim in raw dump.')
    if not mapped:
        print('TARGET_CODE_NOT_RECOVERED: F022A558 still outside both pinned canonical extractions.')
        print('NEXT_REQUIREMENT: a trusted extracted code segment containing virtual address F022A558 plus its base/size/hash.')


def main():
    ap = argparse.ArgumentParser(description='A74 offline signature-based callback target coverage audit')
    ap.add_argument('--alice', type=Path, default=Path('research/f2/work/extracted/altice_alice/alice-py.bin'))
    ap.add_argument('--zimage', type=Path, default=Path('research/f2/work/extracted/altice_platform/zimage.bin'))
    ap.add_argument('--root', type=Path, default=Path('.'), help='repository root for bounded local file search')
    args = ap.parse_args()
    print('S13.5A.74 - ACTION CALLBACK CALLEE F022A558 COVERAGE AND BOUNDED SOURCE RECOVERY')
    print('STRICTLY OFFLINE: NO USB/COM/PHONE/BROM/DA/WRITE/ERASE/PATCH/REPACK; stdout only')
    header('A. CANONICAL SOURCE GUARDS (FAIL CLOSED)')
    a = read_guarded(args.alice, 'ALICE', A_BASE, A_SIZE, A_SHA)
    z = read_guarded(args.zimage, 'ZIMAGE', Z_BASE, Z_SIZE, Z_SHA)
    cs = decoder()
    verify_registration(cs, z)
    header('C. TARGET ADDRESS COVERAGE')
    for img in (a, z):
        inside = img.base <= CALLEE < img.base + len(img.data)
        print('%s range=[0x%08X,0x%08X) contains F022A558 = %s' % (
            img.name, img.base, img.base+len(img.data), inside))
    print('F022A558 is 0x%X bytes BELOW ZIMAGE start. DO NOT disassemble with zimage.bin.' % (Z_BASE-CALLEE))
    raw_candidates(cs, z, args.root)
    header('E. DECISION')
    print('Registration code: STRONGLY CONFIRMED at F02ADBAA/BAC/BAE (three consecutive instructions).')
    print('Callback wrapper: F028877A calls F022A558 directly and returns.')
    print('R2 at callback entry is from STATIC[selected].+0x10 per A72; callee semantics UNKNOWN.')
    print('No proof of Audio app 0x8928 dispatch. No firmware update / no hardware access.')
    print('A74_OFFLINE_COMPLETE=YES')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
