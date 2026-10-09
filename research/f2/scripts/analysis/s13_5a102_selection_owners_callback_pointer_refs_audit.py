#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""S13.5A.102 — exact pointer references to the TWO proven A90 menu owners.

STRICTLY OFFLINE. Two SHA-pinned read-only binary inputs; one new text report.
This is a byte-exact literal census with heuristic nearby Thumb LDR/call hints.
No callback registration, selection event, descriptor alias, or Audio activation
is inferred from a raw pointer hit alone. Missing literals do not prove absence
of dynamic/address-computed registration paths.
"""
from __future__ import annotations

import argparse
import hashlib
import io
import struct
from dataclasses import dataclass
from pathlib import Path

ALICE_BASE = 0x1024EC00
ALICE_SIZE = 0x157BB4
ALICE_SHA = '7246242b67afae0d13104452bc3257827cb778119b54e7a26fb7fb55993697ea'
ZIMAGE_BASE = 0xF023CA50
ZIMAGE_SIZE = 0x185E98
ZIMAGE_SHA = '85fba8c8ae8161e4c1f8ced7983ec30d48c54ab10e51c69fcdfb900aca220954'

# A90 functions; exact odd Thumb entry pointers are first-class hypotheses.
POINTERS = {
    'A90_FIRST_OWNER_THUMB': 0x102ED241,
    'A90_FIRST_OWNER_EVEN': 0x102ED240,
    'A90_SECOND_OWNER_THUMB': 0x10345269,
    'A90_SECOND_OWNER_EVEN': 0x10345268,
    'A10_KNOWN_REGISTERED_CALLBACK_CONTROL': 0x10342FC5,
}
CONTROL_CELL = 0x10340D2C
CONTROL_VALUE = 0x10342FC5
REGISTER_CALLBACK = 0x10317C58  # A11: writes callback into F009605C
# Previously delivered A90/A91/A97 raw anchors, used as byte-exact guards.
ALICE_ANCHORS = {
    0x102ED260: bytes.fromhex('2cf0cafd'),   # BL 10319DF8
    0x10345282: bytes.fromhex('d4f7b9fd'),   # BL 10319DF8
    0x10345296: bytes.fromhex('aaf7d9f8'),   # BL 102EF44C
    0x1034529A: bytes.fromhex('207b'),       # LDRB descriptor+0xC
    0x1034529C: bytes.fromhex('0128'),       # CMP #1
    0x1034529E: bytes.fromhex('07d0'),       # BEQ (skip submenu)
}

@dataclass(frozen=True)
class Image:
    name: str
    base: int
    data: bytes
    @property
    def end(self) -> int:
        return self.base + len(self.data)
    def get(self, addr: int, n: int) -> bytes | None:
        off = addr - self.base
        if off < 0 or off + n > len(self.data):
            return None
        return self.data[off:off+n]


def u32(x: int) -> int:
    return x & 0xFFFFFFFF


def pointer_hits(data: bytes, value: int) -> list[int]:
    needle = struct.pack('<I', value)
    out = []
    start = 0
    while True:
        i = data.find(needle, start)
        if i == -1:
            break
        out.append(i)
        start = i + 1
    return out


def self_test() -> str:
    test = b'_' + struct.pack('<I', POINTERS['A90_SECOND_OWNER_THUMB']) + b'000' + struct.pack('<I', POINTERS['A90_SECOND_OWNER_THUMB'])
    assert pointer_hits(test, 0x10345269) == [1,8]
    assert pointer_hits(test, 0x10345268) == []
    assert ((0x10340C48 + 4) & ~3) + 0xE0 == 0x10340D2C
    assert CONTROL_CELL % 4 == 0
    assert len(ALICE_ANCHORS) == 6
    assert u32(-0xFD2B0A0) == 0xF02D4F60
    return 'A102_SELF_TEST=PASS pointer scan, signed Thumb immediates and literal addressing'


def guarded(path: Path, name: str, base: int, size: int, sha: str) -> Image:
    if not path.is_file():
        raise RuntimeError(f'ABORT {name} missing: {path}')
    raw = path.read_bytes()
    got = hashlib.sha256(raw).hexdigest()
    if len(raw) != size or got != sha:
        raise RuntimeError(f'ABORT {name} SHA/size mismatch size=0x{len(raw):X} sha256={got}')
    return Image(name, base, raw)


def decoder(image: Image):
    from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_LITTLE_ENDIAN
    md = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_LITTLE_ENDIAN)
    md.detail = True
    def dec(addr: int):
        if addr & 1:
            return None
        chunk = image.get(addr, 4)
        if not chunk:
            return None
        ds = list(md.disasm(chunk, addr, count=1))
        return ds[0] if ds and ds[0].address == addr else None
    return dec


def thumb_imm(ins) -> int | None:
    from capstone.arm import ARM_OP_IMM
    for op in reversed(ins.operands):
        if op.type == ARM_OP_IMM:
            return u32(int(op.imm)) & ~1
    return None


def literal_cell(ins) -> int | None:
    from capstone.arm import ARM_OP_MEM, ARM_REG_PC
    if ins.mnemonic.lower().split('.')[0] != 'ldr' or len(ins.operands) < 2:
        return None
    op = ins.operands[1]
    if op.type != ARM_OP_MEM or op.mem.base != ARM_REG_PC or op.mem.index:
        return None
    return u32(((ins.address+4) & ~3) + op.mem.disp)


def near_reference_hints(im: Image, at: int, dec) -> list[str]:
    """Annotate exact PC-relative LDR uses; arbitrary-offset decode is NOT CFG."""
    hints=[]
    lo = max(im.base, at-0x130) & ~1
    hi = min(im.end-4, at+0x10)
    for pc in range(lo, hi+1, 2):
        ins=dec(pc)
        if not ins or literal_cell(ins) != at:
            continue
        desc=f'LDR_LITERAL_AT=0x{pc:08X} {ins.mnemonic} {ins.op_str} -> literal 0x{at:08X}'
        calls=[]
        end=min(im.end-4,pc+0x30)
        for q in range(pc+2,end+1,2):
            ci=dec(q)
            if ci and ci.mnemonic.lower().split('.')[0] in {'bl','blx'} and thumb_imm(ci)==REGISTER_CALLBACK:
                calls.append(f'0x{q:08X}')
        if calls:
            desc+=' POSSIBLE_REGISTER_SETTER_NEAR='+','.join(calls)
        hints.append(desc)
    return hints


def generate(alice: Image, zimage: Image) -> tuple[str, dict[str, int]]:
    assert alice.get(CONTROL_CELL, 4) == struct.pack('<I',CONTROL_VALUE), 'ABORT positive-control literal changed'
    for a,raw in ALICE_ANCHORS.items():
        assert alice.get(a,len(raw)) == raw, f'ABORT A90 raw anchor at 0x{a:08X}'
    w=io.StringIO()
    w.write('S13.5A.102 — TWO A90 SELECTED-MENU OWNER POINTER REFERENCE AUDIT\n')
    w.write('STRICTLY_OFFLINE=YES / TWO CANONICAL FILES READ_ONLY / REPORT_ONLY / NO_NOTEPAD\n')
    w.write(f'ALICE_GUARD=PASS sha256={ALICE_SHA}\nZIMAGE_GUARD=PASS sha256={ZIMAGE_SHA}\n')
    w.write(f'A90_ANCHORS=PASS count={len(ALICE_ANCHORS)}\n')
    w.write(f'KNOWN_CALLBACK_CONTROL=PASS cell=0x{CONTROL_CELL:08X} value=0x{CONTROL_VALUE:08X}\n')
    w.write('SCOPE=exact u32 literals only, both odd Thumb pointers and even numeric addresses; all byte alignments\n')
    w.write('LIMITS=literal reference != handler registration; absence != absence of dynamic/encoded pointer; nearby LDR/BL scan NOT CFG\n')
    summary={}
    for label,ptr in POINTERS.items():
        total=0
        w.write(f'\n=== POINTER {label} = 0x{ptr:08X} ===\n')
        for im in [alice,zimage]:
            hits=pointer_hits(im.data,ptr)
            total += len(hits)
            w.write(f'IMAGE={im.name} HIT_COUNT={len(hits)}\n')
            if len(hits)>70:
                w.write('WARNING >70 hits; showing first 70 only (TOTAL is full exact count)\n')
            dec=decoder(im)
            for off in hits[:70]:
                addr=im.base+off
                lo=max(0,off-16);hi=min(len(im.data),off+20)
                w.write(f'  HIT_CELL=0x{addr:08X} FILE_OFF=0x{off:X} ALIGN_4={off%4==0} RAW_NEIGHBOR={im.data[lo:hi].hex(" ")}\n')
                hints=near_reference_hints(im,addr,dec)
                if hints:
                    for hint in hints[:12]:
                        w.write('    HEURISTIC '+hint+'\n')
                else:
                    w.write('    HEURISTIC no immediate near-PC LDR reference found in local 0x130 window\n')
        summary[label]=total
        w.write(f'TOTAL_EXACT_LITERAL_REFERENCES_{label}={total}\n')
    w.write('\n=== DECISION BOUNDARY ===\n')
    w.write('Control pointer 10342FC5 must occur at proven 10340D2C in ALICE, confirming scanner can find at least one callback literal.\n')
    w.write('A90 selected-ID-to-index mapping and A91 event dispatch are already proven; no re-analysis was performed.\n')
    w.write('Candidate owner pointer literals must be tied to a decoded executable producer/registration path before promotion.\n')
    w.write('If both A90 owner literals have zero hits, STOP: inspect existing local caller/callback table evidence, do not assert lack of callbacks.\n')
    w.write('DESCRIPTOR_PLUS_0C_SET_TO_ONE=UNPROVEN; SELECTED_MULTIMEDIA_ID_TO_CALLBACK=UNPROVEN\n')
    w.write('AUDIO_NATIVE_ID_0x8928_NOT_VISIBLE=UNCHANGED; FM_ROM_ID=UNKNOWN\n')
    w.write('NO_USB_COM_PHONE_FLASH_PATCH_REPACK_FIRMWARE_WRITES=YES\n')
    return w.getvalue(), summary


def main() -> int:
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--alice',type=Path,default=Path('research/f2/work/extracted/altice_alice/alice-py.bin'))
    p.add_argument('--zimage',type=Path,default=Path('research/f2/work/extracted/altice_platform/zimage.bin'))
    p.add_argument('--out',type=Path,default=Path('research/f2/work/reports/s13_5a102_selection_owners_callback_pointer_refs_audit.txt'))
    p.add_argument('--self-test',action='store_true')
    args=p.parse_args()
    if args.self_test:
        print(self_test()); return 0
    try:
        if args.out.exists():
            if not args.out.is_file():
                raise RuntimeError('ABORT output location is not a regular file')
            print(f'REPORT_ALREADY_EXISTS_UNCHANGED={args.out.resolve()}')
            return 0
        alice=guarded(args.alice,'ALICE',ALICE_BASE,ALICE_SIZE,ALICE_SHA)
        zimage=guarded(args.zimage,'ZIMAGE',ZIMAGE_BASE,ZIMAGE_SIZE,ZIMAGE_SHA)
        try:
            import capstone  # noqa: F401
        except ImportError as ex:
            raise RuntimeError(f'ABORT Capstone required in project venv: {ex}') from ex
        content,counts=generate(alice,zimage)
        args.out.parent.mkdir(parents=True,exist_ok=True)
        with args.out.open('x',encoding='utf-8') as f:
            f.write(content)
        print('A102_REPORT_CREATED='+str(args.out.resolve()))
        print('A102_COUNTS='+', '.join(k+':'+str(v) for k,v in counts.items()))
        print('A102_GUARDS=PASS / NO_PHONE_OR_FIRMWARE_WRITES')
        return 0
    except Exception as exc:
        print(str(exc))
        return 1

if __name__=='__main__':
    raise SystemExit(main())
