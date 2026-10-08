#!/usr/bin/env python3
"""S13.5A.87: 58-row native resolver TABLE-BASE consumer audit.

STRICTLY OFFLINE / READ-ONLY. No device / serial / USB, patch, repack or flash.
NOT a re-audit of registration stub semantics, B702 child arrays, the A79-A85
UI detour, or raw callback-value xrefs done in A86.

Objective: establish whether executable instructions reference the *table base*
F0345E68 or related bounded table endpoints, and whether neighboring code
uses a resolver-row or dispatch signature. A syntactically valid Thumb LDR/ADR
in raw bytes is a CANDIDATE, not proof that the instruction is reachable.
"""
from __future__ import annotations

import argparse
import hashlib
import struct
from dataclasses import dataclass
from pathlib import Path

try:
    from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_LITTLE_ENDIAN, CS_OP_IMM, CS_OP_MEM, CS_OP_REG
    from capstone.arm import ARM_REG_PC
except ImportError as e:
    raise SystemExit("Capstone required in user's offline Python venv: " + str(e))

CONFIG = {
    "ALICE": (0x1024EC00, 0x157BB4,
              "7246242b67afae0d13104452bc3257827cb778119b54e7a26fb7fb55993697ea",
              "research/f2/work/extracted/altice_alice/alice-py.bin"),
    "ZIMAGE": (0xF023CA50, 0x185E98,
               "85fba8c8ae8161e4c1f8ced7983ec30d48c54ab10e51c69fcdfb900aca220954",
               "research/f2/work/extracted/altice_platform/zimage.bin"),
}
TABLE_BASE = 0xF0345E68
TABLE_ROWS = 58
ROW_LEN = 8
TABLE_END = TABLE_BASE + ROW_LEN * TABLE_ROWS
# Independent A86 pointer occurrence + documented static table schema.
ROW_CHECKS = {14: (0x87ED, 0xF02F3F9D), 22: (0x8928, 0x1033D841)}
# Literal references to table boundaries or first callback column are examined;
# no wider pointer-ID census is performed.
TABLE_REFS = {
    "TABLE_BASE": TABLE_BASE,
    "CALLBACK_COLUMN_START": TABLE_BASE + 4,
    "TABLE_END_EXCLUSIVE": TABLE_END,
}


@dataclass
class Image:
    label: str
    start: int
    raw: bytes

    def owns(self, address: int, size: int = 1) -> bool:
        return self.start <= address <= self.start + len(self.raw) - size

    def blob(self, address: int, size: int) -> bytes:
        if not self.owns(address, size):
            raise ValueError(f"OUT OF BOUNDS {self.label} addr=0x{address:08X} n=0x{size:X}")
        p = address - self.start
        return self.raw[p:p + size]

    def u32(self, address: int) -> int:
        return struct.unpack('<I', self.blob(address, 4))[0]

    def u16(self, address: int) -> int:
        return struct.unpack('<H', self.blob(address, 2))[0]


def load(label: str, filename: Path) -> Image:
    base, size, good_sha, _ = CONFIG[label]
    raw = filename.read_bytes()
    sha = hashlib.sha256(raw).hexdigest()
    passed = len(raw) == size and sha == good_sha
    print(f"{label}: path={filename} size=0x{len(raw):X} sha256={sha} GUARD={'PASS' if passed else 'FAIL'}")
    if not passed:
        raise SystemExit("ABORT: noncanonical extracted image; no results promoted")
    return Image(label, base, raw)


def one(md: Cs, img: Image, address: int):
    if not img.owns(address, 2):
        return None
    b = img.blob(address, min(4, img.start + len(img.raw) - address))
    seq = list(md.disasm(b, address, count=1))
    return seq[0] if seq and seq[0].address == address else None


def pc_literal(ins):
    if not ins.mnemonic.startswith("ldr") or len(ins.operands) < 2:
        return None
    src = ins.operands[1]
    if src.type != CS_OP_MEM or src.mem.base != ARM_REG_PC:
        return None
    return ((((ins.address + 4) & ~3) + src.mem.disp) & 0xFFFFFFFF)


def raw_u32_cells(img: Image, value: int):
    pat = struct.pack('<I', value)
    pos = 0
    cells = []
    while (pos := img.raw.find(pat, pos)) != -1:
        cells.append(img.start + pos)
        pos += 1
    return cells


def find_pc_ldr_owners(md: Cs, img: Image, cell: int, back: int = 0x1200):
    if not img.owns(cell, 4):
        return []
    lo = max(img.start, (cell - back) & ~1)
    out = []
    for at in range(lo, cell, 2):
        ins = one(md, img, at)
        if ins is not None and pc_literal(ins) == cell:
            out.append(ins)
    return out


def ins_text(ins, img: Image):
    extra = ''
    lit = pc_literal(ins)
    if lit is not None and img.owns(lit, 4):
        extra = f' ; PC_CELL=0x{lit:08X} U32=0x{img.u32(lit):08X}'
    return f"0x{ins.address:08X} {ins.mnemonic:<9} {ins.op_str:<39} bytes={ins.bytes.hex(' ')}{extra}"


def snippet(md: Cs, img: Image, start: int, max_inst: int = 20):
    a = start
    for _ in range(max_inst):
        ins = one(md, img, a)
        if ins is None:
            print(f"      STOP_NO_DECODE 0x{a:08X}")
            return
        print('      ' + ins_text(ins, img))
        a += ins.size
        # Stop before literal-pool bytes following a return/branch.
        if (ins.mnemonic in {'bx', 'b', 'b.w'} or
            (ins.mnemonic == 'pop' and 'pc' in ins.op_str)):
            return


def bounded_adr_candidates(md: Cs, img: Image, target: int, lookback: int = 0x1000):
    # PC-relative ADR is often used for near data; check ZIMAGE bytes immediately
    # preceding the registered table, but do not assume a decodable word is code.
    lo = max(img.start, (target - lookback) & ~1)
    hi = min(target + 2, img.start + len(img.raw))
    hits = []
    for addr in range(lo, hi, 2):
        ins = one(md, img, addr)
        if ins is None or not ins.mnemonic.startswith('adr'):
            continue
        if any(op.type == CS_OP_IMM and (op.imm & 0xFFFFFFFF) == target
               for op in ins.operands):
            hits.append(ins)
    return hits


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--alice', type=Path, default=Path(CONFIG['ALICE'][3]))
    parser.add_argument('--zimage', type=Path, default=Path(CONFIG['ZIMAGE'][3]))
    a = parser.parse_args()
    print("S13.5A.87 - STATIC NATIVE RESOLVER TABLE BASE CONSUMERS")
    print("STRICTLY OFFLINE, READ ONLY; no USB/COM/phone/flash/erase/write/patch/repack")
    images = [load('ALICE', a.alice), load('ZIMAGE', a.zimage)]
    z = images[1]
    md = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_LITTLE_ENDIAN)
    md.detail = True

    print("\n[A] PREEXISTING TABLE SCHEMA / A86 ROW LINK FAIL-CLOSED")
    print(f"TABLE=[0x{TABLE_BASE:08X},0x{TABLE_END:08X}) entries={TABLE_ROWS} stride={ROW_LEN}")
    if not z.owns(TABLE_BASE, TABLE_ROWS * ROW_LEN):
        raise SystemExit("ABORT: table outside canonical ZIMAGE")
    for idx, (expected_id, expected_fn) in ROW_CHECKS.items():
        row = TABLE_BASE + idx * ROW_LEN
        rid, other, callback = z.u16(row), z.u16(row+2), z.u32(row+4)
        valid = rid == expected_id and callback == expected_fn
        print(f"ROW[{idx}]=0x{row:08X} id=0x{rid:04X} field2=0x{other:04X} "
              f"callback=0x{callback:08X} GUARD={'PASS' if valid else 'FAIL'}")
        if not valid:
            raise SystemExit("ABORT: table schema mismatch; inspect prior claim, do not infer consumer")
    for idx in [13, 15, 21, 23]:
        row = TABLE_BASE + idx * ROW_LEN
        print(f"NEIGHBOR_ROW[{idx}] id=0x{z.u16(row):04X} field2=0x{z.u16(row+2):04X} "
              f"callback=0x{z.u32(row+4):08X} (context only)")

    print("\n[B] EXACT TABLE BASE/BOUNDARY POINTER CELLS AND THEIR PC-LDR OWNERS")
    total_verified_code_loads = 0
    for label, value in TABLE_REFS.items():
        print(f"\n  {label}=0x{value:08X}")
        for img in images:
            cells = raw_u32_cells(img, value)
            aligned = [cell for cell in cells if cell % 4 == 0]
            print(f"    {img.label}: RAW_U32_CELLS={len(cells)} U32_ALIGNED={len(aligned)}")
            for cell in cells[:50]:
                if cell % 4:
                    print(f"      RAW_UNALIGNED=0x{cell:08X}; not a PC literal")
                    continue
                owners = find_pc_ldr_owners(md, img, cell)
                print(f"      CELL=0x{cell:08X} SYNTACTIC_PC_LDR_OWNERS={len(owners)}")
                total_verified_code_loads += len(owners)
                for ins in owners[:8]:
                    print(f"      PC_LOAD_CANDIDATE {ins_text(ins,img)}")
                    print("      NEXT_LINEAR_INSTRUCTIONS (NOT CFG/NOT REACHABILITY):")
                    snippet(md, img, ins.address, max_inst=20)
                if len(owners) > 8:
                    print(f"      OWNER_OUTPUT_CAPPED={len(owners)-8}; no exhaustive owner semantics")
            if len(cells) > 50:
                print(f"      RAW_CELL_OUTPUT_CAPPED={len(cells)-50}; do not claim exhaustive CODE owners")

    print("\n[C] BOUNDED NEAR-TABLE ADR CANDIDATES (ZIMAGE ONLY)")
    adr_hits = bounded_adr_candidates(md, z, TABLE_BASE, 0x1000)
    print(f"SYNTACTIC_ADR_TARGETING_TABLE={len(adr_hits)}; raw byte matches are NOT verified executable owners")
    for ins in adr_hits[:20]:
        print("  ADR_CANDIDATE " + ins_text(ins, z))
    if len(adr_hits) > 20:
        print("  ADR_OUTPUT_CAPPED=YES")

    print("\n[D] PROMOTION / STOP RULE")
    print(f"SYNTACTIC_DIRECT_PC_LOAD_TOTAL={total_verified_code_loads}")
    print("A87_SUCCESS=ONLY_IF_A_REACHABLE_TABLE_LOOKUP_TO_ACTIVATION_EDGE_IS_PROVEN")
    print("PC_LDR_SYNTAX_OR_ADR_SYNTAX_ALONE_IS_NOT_REACHABILITY=YES")
    print("ZERO_DIRECT_REFS_DOES_NOT_RULE_OUT_DESCRIPTOR_INDIRECTION=YES")
    print("THIS_IS_NOT_A_MENU_OK_OR_AUDIO_8928_ACTIVATION_PROOF=YES")
    print("NO_PHONE_ACCESS=YES NO_FIRMWARE_MODIFIED=YES NO_WRITE_AUTHORIZED=YES")


if __name__ == '__main__':
    main()
