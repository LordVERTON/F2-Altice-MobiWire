#!/usr/bin/env python3
"""
S13.5A.25 - SELECTOR SWITCH / FILTER BITMAP / ROOT-BRANCH ALIGNMENT AUDIT

STRICTLY OFFLINE / READ-ONLY.

A.24 proved:
  F02D53DC = COUNT_FILTERED_CHILDREN(parent)
  F02AE864 = ENUM_FILTERED_CHILD_IDS(parent, out_u16)
  F02D5458 = bitset-backed CHILD_FILTER_PREDICATE(child)

  F02F9D34(id):
      climb ancestry until direct child of 0xB709 is found,
      then return RAW children[B709] index; failure = 0xFF.

  0x10319094(id):
      idx = F02F9D34(id)
      if idx == 0xFF: return 0x2E
      return F00B7994[idx]

  0x10313998:
      N = COUNT_FILTERED_CHILDREN(0xB709)
      ENUM_FILTERED_CHILD_IDS(0xB709, buf)
      for i in range(N):
          F00B7994[i] = F0316CE0(buf[i], 8)

A.24 also recovered a static table:
  count @ 0xF03AD11C = 18
  table @ 0xF03AD120
  record stride = 0x14
  record key = u16 +0x00

This pass fixes one remaining decoding issue:
F0316CE0 contains an ARM/Thumb compiler switch8 helper followed by INLINE
switch bytes. Linear Capstone disassembly interprets those bytes as code.
A.25 decodes the switch table explicitly and proves selector -> record-field
offsets.

Main goals:
  1. Prove exact selector 0..8 -> record offsets +02..+12.
  2. Dump all 18 records as key/selector fields.
  3. Test, but DO NOT assume, whether selector 1 is parent-like.
  4. Fully dump ALICE 0x10362A14 selector-1 owner path.
  5. Recover F00B796C (selector-5 parallel array) readers/writers.
  6. Audit F00B7994 readers/writers.
  7. Audit F02D5458 bitmap globals F007F04C / F00C1624 and nearby
     initialization/write candidates.
  8. Highlight the RAW-index vs FILTERED-index alignment risk.
  9. Search structural ownership of key selector values (B74A/B747/etc).
 10. Remain strictly offline. No patch generation.

NO USB/COM.
NO PHONE ACCESS.
NO FLASH WRITE.
NO PATCH.
NO REPACK.
"""

from __future__ import annotations

import argparse
import hashlib
import io
import struct
import sys
from dataclasses import dataclass
from pathlib import Path
from collections import defaultdict, Counter

from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_THUMB, CS_MODE_LITTLE_ENDIAN
from capstone.arm import (
    ARM_OP_IMM, ARM_OP_MEM, ARM_OP_REG,
    ARM_REG_PC,
)

# -------------------------------------------------------------------------------------------------
# Canonical images
# -------------------------------------------------------------------------------------------------

ALICE_BASE = 0x1024EC00
ALICE_SIZE = 0x157BB4
ALICE_SHA256 = "7246242b67afae0d13104452bc3257827cb778119b54e7a26fb7fb55993697ea"

ZIMAGE_BASE = 0xF023CA50
ZIMAGE_SIZE = 0x185E98
ZIMAGE_SHA256 = "85fba8c8ae8161e4c1f8ced7983ec30d48c54ab10e51c69fcdfb900aca220954"

# -------------------------------------------------------------------------------------------------
# Known menu / registry infrastructure
# -------------------------------------------------------------------------------------------------

ROOT_B709 = 0xB709

PARENT_TO_INDEX = 0xF02E01B0
GET_PARENT_ID = 0xF02FBC24
ROOT_CHILD_INDEX = 0xF02F9D34

REGISTRY_GLOBAL = 0xF007F044

COUNT_FILTERED = 0xF02D53DC
ENUM_FILTERED = 0xF02AE864
FILTER_PRED = 0xF02D5458

FILTER_BOUND_GLOBAL = 0xF007F04C
FILTER_BITMAP = 0xF00C1624

ALICE_VENEER_COUNT_FILTERED = 0x102FC51C
ALICE_VENEER_ENUM_FILTERED = 0x102FC3CC
ALICE_VENEER_SELECTOR = 0x102FC20C

B709_MATERIALIZER = 0x10313998
RESOURCE_WRAPPER = 0x10319094

ARRAY_SELECTOR8 = 0xF00B7994
ARRAY_SELECTOR5 = ARRAY_SELECTOR8 - 0x28  # F00B796C

# -------------------------------------------------------------------------------------------------
# Selector table
# -------------------------------------------------------------------------------------------------

SELECTOR_FUNC = 0xF0316CE0
SELECTOR_SWITCH_CALL = 0xF0316CF6
SELECTOR_INLINE_TABLE = 0xF0316CFA
SELECTOR_COUNT_ADDR = 0xF03AD11C
SELECTOR_TABLE_ADDR = 0xF03AD120
SELECTOR_RECORD_STRIDE = 0x14
EXPECTED_SELECTOR_COUNT = 18

# ALICE owner using selector 1
SELECTOR1_OWNER_START = 0x10362A14
SELECTOR1_OWNER_END = 0x10362B20

# ALICE owner building selector 8 / selector 5 parallel arrays
B709_PARALLEL_OWNER_START = 0x103647C4
B709_PARALLEL_OWNER_END = 0x10364920

# Resolver table
RESOLVER_BASE = 0xF0345E68
RESOLVER_COUNT = 58
RESOLVER_STRIDE = 8

KNOWN_IDS = {
    0x8313: "IMAGE_A",
    0x8321: "IMAGE_B",
    0x8928: "AUDIO",
    0x87ED: "RESOLVER",
    0x9639: "RESOLVER",
    0xA223: "RESOLVER",
    0xAF2A: "RESOLVER",
    0xBA3C: "RESOLVER",
    0xB6FD: "ROOT_FAMILY",
    0xB6FE: "ROOT_FAMILY",
    0xB6FF: "ROOT_FAMILY",
    0xB700: "ROOT_FAMILY",
    0xB701: "ROOT_FAMILY",
    0xB702: "ROOT_FAMILY",
    0xB703: "ROOT_FAMILY",
    0xB704: "ROOT_FAMILY",
    0xB705: "ROOT_FAMILY",
    0xB706: "ROOT_FAMILY",
    0xB707: "ROOT_FAMILY",
    0xB708: "ROOT_FAMILY",
    0xB709: "ROOT_B709",
}

FOCUS_SELECTOR_VALUES = {
    0xB748, 0xB749, 0xB74A,  # selector1 outputs for 87ED/BA3C/8321
    0xB747,                  # selector5 output for 8321
    0xB709,                  # selector1 output for B701/B707
    0xB719, 0xB739,          # selector5/8 paired outputs for B701/B707
}

md_t = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_LITTLE_ENDIAN)
md_t.detail = True
md_a = Cs(CS_ARCH_ARM, CS_MODE_ARM | CS_MODE_LITTLE_ENDIAN)
md_a.detail = True


class Tee:
    def __init__(self, *streams):
        self.streams = streams

    def write(self, s):
        for st in self.streams:
            st.write(s)
        return len(s)

    def flush(self):
        for st in self.streams:
            st.flush()


@dataclass
class Image:
    name: str
    data: bytes
    base: int

    @property
    def end(self):
        return self.base + len(self.data)

    def contains(self, addr: int) -> bool:
        a = addr & ~1
        return self.base <= a < self.end

    def off(self, addr: int) -> int:
        return (addr & ~1) - self.base


@dataclass
class ResolverRow:
    index: int
    addr: int
    menu_id: int
    field2: int
    callback: int


@dataclass
class SelectorRecord:
    index: int
    addr: int
    fields: tuple[int, ...]

    @property
    def key(self):
        return self.fields[0]

    def field_for_selector(self, selector: int):
        # selector 0 -> +0x02 = fields[1]
        return self.fields[selector + 1]


def banner(s):
    print()
    print("=" * 156)
    print(s)
    print("=" * 156)


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def u8(data: bytes, off: int):
    if off < 0 or off + 1 > len(data):
        return None
    return data[off]


def u16(data: bytes, off: int):
    if off < 0 or off + 2 > len(data):
        return None
    return struct.unpack_from("<H", data, off)[0]


def u32(data: bytes, off: int):
    if off < 0 or off + 4 > len(data):
        return None
    return struct.unpack_from("<I", data, off)[0]


def verify(path: Path, name: str, base: int, expected_size: int, expected_sha: str) -> Image:
    if not path.is_file():
        raise SystemExit(f"ABORT: missing canonical {name}: {path}")
    data = path.read_bytes()
    got = sha256(data)
    print(f"{name} = {path}")
    print(f"  runtime base = 0x{base:08X}")
    print(f"  size         = 0x{len(data):X}")
    print(f"  sha256       = {got}")
    if len(data) != expected_size:
        raise SystemExit(f"ABORT: {name} size mismatch")
    if got.lower() != expected_sha.lower():
        raise SystemExit(f"ABORT: {name} SHA256 mismatch")
    print(f"[PASS] canonical {name}")
    return Image(name, data, base)


def decode1(img: Image, addr: int, mode="THUMB"):
    a = (addr & ~1) if mode == "THUMB" else (addr & ~3)
    if not img.contains(a):
        return None
    md = md_t if mode == "THUMB" else md_a
    xs = list(md.disasm(img.data[img.off(a):img.off(a) + 4], a, count=1))
    return xs[0] if xs else None


def dis(img: Image, start: int, end: int, mode="THUMB"):
    start = (start & ~1) if mode == "THUMB" else (start & ~3)
    if not img.contains(start):
        return []
    md = md_t if mode == "THUMB" else md_a
    end = min(end, img.end)
    return [
        x for x in md.disasm(
            img.data[img.off(start):img.off(start) + (end - start)],
            start
        )
        if x.address < end
    ]


def fmt(x):
    return f"0x{x.address:08X}: {x.bytes.hex(' '):<16} {x.mnemonic:<10} {x.op_str}"


def direct_target(x):
    if x is None or x.mnemonic not in {"b", "bl", "blx"} or not x.operands:
        return None
    op = x.operands[0]
    return (op.imm & 0xFFFFFFFF) if op.type == ARM_OP_IMM else None


def literal_load(img: Image, x, mode="THUMB"):
    if x is None or not x.mnemonic.startswith("ldr") or len(x.operands) < 2:
        return None

    d, s = x.operands[0], x.operands[1]
    if d.type != ARM_OP_REG or s.type != ARM_OP_MEM or s.mem.base != ARM_REG_PC:
        return None

    pc = ((x.address + 4) & ~3) if mode == "THUMB" else x.address + 8
    la = (pc + s.mem.disp) & 0xFFFFFFFF
    if not img.contains(la):
        return None

    return x.reg_name(d.reg), d.reg, la, u32(img.data, img.off(la))


def print_region(img: Image, start: int, end: int, mode="THUMB", marks=None):
    marks = marks or set()
    for x in dis(img, start, end, mode):
        notes = []

        t = direct_target(x)
        if t is not None:
            tag = ""
            if (t & ~1) == PARENT_TO_INDEX:
                tag = "<PARENT_TO_INDEX>"
            elif (t & ~1) == GET_PARENT_ID:
                tag = "<GET_PARENT_ID>"
            elif (t & ~1) == ROOT_CHILD_INDEX:
                tag = "<ROOT_CHILD_INDEX>"
            elif (t & ~1) == FILTER_PRED:
                tag = "<FILTER_PRED>"
            elif (t & ~1) == COUNT_FILTERED:
                tag = "<COUNT_FILTERED>"
            elif (t & ~1) == ENUM_FILTERED:
                tag = "<ENUM_FILTERED>"
            elif (t & ~1) == ALICE_VENEER_COUNT_FILTERED:
                tag = "<VENEER_COUNT_FILTERED>"
            elif (t & ~1) == ALICE_VENEER_ENUM_FILTERED:
                tag = "<VENEER_ENUM_FILTERED>"
            elif (t & ~1) == ALICE_VENEER_SELECTOR:
                tag = "<VENEER_SELECTOR>"
            elif (t & ~1) == RESOURCE_WRAPPER:
                tag = "<RESOURCE_WRAPPER>"
            notes.append(f"target=0x{t:08X}{tag}")

        li = literal_load(img, x, mode)
        if li:
            tags = []
            v = li[3]
            if v == REGISTRY_GLOBAL:
                tags.append("REGISTRY_GLOBAL")
            if v == FILTER_BOUND_GLOBAL:
                tags.append("FILTER_BOUND")
            if v == FILTER_BITMAP:
                tags.append("FILTER_BITMAP")
            if v == ARRAY_SELECTOR8:
                tags.append("SEL8_ARRAY")
            if v == ARRAY_SELECTOR5:
                tags.append("SEL5_ARRAY")
            if v == ROOT_B709:
                tags.append("B709")
            if v == SELECTOR_TABLE_ADDR:
                tags.append("SELECTOR_TABLE")
            if v == SELECTOR_COUNT_ADDR:
                tags.append("SELECTOR_COUNT")
            notes.append(
                f"literal@0x{li[2]:08X}=0x{v:08X}->{li[0]}"
                + (f"<{'|'.join(tags)}>" if tags else "")
            )

        print(
            (">>> " if x.address in marks else "    ")
            + fmt(x)
            + ((" ; " + ", ".join(notes)) if notes else "")
        )


def all_hits(data: bytes, needle: bytes):
    out = []
    pos = 0
    while True:
        pos = data.find(needle, pos)
        if pos < 0:
            return out
        out.append(pos)
        pos += 1


def parse_resolver(zimage: Image):
    rows = []
    off = zimage.off(RESOLVER_BASE)
    for i in range(RESOLVER_COUNT):
        o = off + i * RESOLVER_STRIDE
        rows.append(
            ResolverRow(
                i,
                RESOLVER_BASE + i * RESOLVER_STRIDE,
                u16(zimage.data, o),
                u16(zimage.data, o + 2),
                u32(zimage.data, o + 4),
            )
        )
    return rows


def raw_word_locations(img: Image, value: int):
    return [img.base + o for o in all_hits(img.data, struct.pack("<I", value & 0xFFFFFFFF))]


def real_literal_refs_to_word(img: Image, literal_addr: int, expected_value: int):
    refs = []

    # Thumb PC-literal LDR can usually reach within ~4 KiB, but this firmware's
    # literal pools are much nearer. Use 0x1000 to stay safe.
    lo = max(img.base, literal_addr - 0x1000) & ~1
    hi = min(img.end, literal_addr + 4)

    for a in range(lo, hi, 2):
        x = decode1(img, a, "THUMB")
        if not x:
            continue
        li = literal_load(img, x, "THUMB")
        if li and li[2] == literal_addr and li[3] == expected_value:
            refs.append(("THUMB", x, li))

    lo_arm = max(img.base, literal_addr - 0x2000) & ~3
    for a in range(lo_arm, hi, 4):
        x = decode1(img, a, "ARM")
        if not x:
            continue
        li = literal_load(img, x, "ARM")
        if li and li[2] == literal_addr and li[3] == expected_value:
            refs.append(("ARM", x, li))

    # Deduplicate address/mode.
    seen = set()
    out = []
    for mode, x, li in refs:
        k = (mode, x.address)
        if k not in seen:
            seen.add(k)
            out.append((mode, x, li))
    return out


def real_literal_refs(img: Image, value: int):
    out = []
    for wa in raw_word_locations(img, value):
        for mode, x, li in real_literal_refs_to_word(img, wa, value):
            out.append((wa, mode, x, li))
    return out


def plausible_func_start_thumb(img: Image, addr: int, back=0x140):
    lo = max(img.base, addr - back) & ~1
    best = None
    for a in range(lo, addr + 1, 2):
        x = decode1(img, a, "THUMB")
        if x and x.mnemonic == "push" and "lr" in x.op_str:
            best = a
    return best if best is not None else addr


def first_pop_pc_after(img: Image, start: int, max_len=0x300):
    for x in dis(img, start, min(img.end, start + max_len), "THUMB"):
        if x.mnemonic == "pop" and "pc" in x.op_str:
            return x.address + len(x.bytes)
        if x.mnemonic == "bx" and x.op_str.strip() == "lr":
            return x.address + len(x.bytes)
    return min(img.end, start + max_len)


# -------------------------------------------------------------------------------------------------
# A. Manual switch8 decode
# -------------------------------------------------------------------------------------------------

def selector_switch_audit(zimage: Image):
    banner("B. MANUAL SWITCH8 DECODE — F0316CE0 SELECTOR CONTRACT")

    # Show the meaningful body but explicitly stop linear interpretation at inline data.
    print("Function prefix / key lookup:")
    print_region(
        zimage,
        SELECTOR_FUNC,
        SELECTOR_INLINE_TABLE,
        "THUMB",
        {SELECTOR_FUNC, SELECTOR_SWITCH_CALL}
    )

    table_off = zimage.off(SELECTOR_INLINE_TABLE)
    raw = zimage.data[table_off:table_off + 12]

    print()
    print(f"inline bytes @0x{SELECTOR_INLINE_TABLE:08X} = {raw.hex(' ')}")

    n = raw[0] if len(raw) >= 1 else None
    case_bytes = list(raw[1:1 + n]) if n is not None else []
    default_byte = raw[1 + n] if n is not None and len(raw) > 1 + n else None
    pad = raw[2 + n] if n is not None and len(raw) > 2 + n else None

    print(f"case_count byte = 0x{n:02X} ({n})" if n is not None else "case_count missing")
    print("case offset bytes = " + " ".join(f"{b:02X}" for b in case_bytes))
    print(f"default offset byte = 0x{default_byte:02X}" if default_byte is not None else "default missing")
    if pad is not None:
        print(f"alignment byte = 0x{pad:02X}")

    selector_map = {}
    ok = (n == 9 and len(case_bytes) == 9 and default_byte is not None)

    print()
    print("Decoded branch targets (target = inline_table + 2 * offset_byte):")

    for selector, b in enumerate(case_bytes):
        target = SELECTOR_INLINE_TABLE + 2 * b
        selector_map[selector] = target
        print(f"  selector {selector}: byte=0x{b:02X} -> target=0x{target:08X}")

    default_target = None
    if default_byte is not None:
        default_target = SELECTOR_INLINE_TABLE + 2 * default_byte
        print(f"  default   : byte=0x{default_byte:02X} -> target=0x{default_target:08X}")

    expected_targets = {
        0: 0xF0316D06,
        1: 0xF0316D10,
        2: 0xF0316D1A,
        3: 0xF0316D24,
        4: 0xF0316D2E,
        5: 0xF0316D38,
        6: 0xF0316D42,
        7: 0xF0316D4C,
        8: 0xF0316D56,
    }
    expected_default = 0xF0316D60

    ok = ok and selector_map == expected_targets and default_target == expected_default

    print()
    print(f"target sequence exact = {'PASS' if ok else 'OPEN'}")

    field_map = {}

    for selector, target in selector_map.items():
        xs = dis(zimage, target, target + 10, "THUMB")
        print()
        print(f"selector {selector} target 0x{target:08X}:")
        for x in xs:
            print("    " + fmt(x))

        # Expected shape:
        # movs r0,#0x14
        # muls r0,r2,r0
        # adds r0,r0,r4
        # ldrh r0,[r0,#disp]
        ldrh = next((x for x in xs if x.mnemonic == "ldrh" and x.operands and len(x.operands) >= 2), None)
        disp = None
        if ldrh and ldrh.operands[1].type == ARM_OP_MEM:
            disp = ldrh.operands[1].mem.disp
            field_map[selector] = disp
        print(f"  recovered record field offset = {('0x%X' % disp) if disp is not None else 'OPEN'}")

    expected_fields = {i: 2 + 2 * i for i in range(9)}
    field_ok = field_map == expected_fields

    print()
    print("Selector -> record field:")
    for i in range(9):
        got = field_map.get(i)
        print(f"  selector {i} -> +0x{got:02X}" if got is not None else f"  selector {i} -> OPEN")

    print(f"exact +02..+12 mapping = {'PASS' if field_ok else 'OPEN'}")

    if ok and field_ok:
        print()
        print("[FACT] F0316CE0 is an ID + selector static-field lookup over")
        print("       0x14-byte records at F03AD120.")
        print("[FACT] selector mapping:")
        print("       0:+02  1:+04  2:+06  3:+08  4:+0A")
        print("       5:+0C  6:+0E  7:+10  8:+12")
        print("[FACT] invalid/out-of-range selector falls to the default path at F0316D60.")
        print("[SUPERSEDED] A.23 generic COUNT_LIKE label for F0316CE0.")

    return ok, field_ok, field_map


# -------------------------------------------------------------------------------------------------
# B. Parse selector records
# -------------------------------------------------------------------------------------------------

def parse_selector_records(zimage: Image):
    count = u32(zimage.data, zimage.off(SELECTOR_COUNT_ADDR))
    records = []

    for i in range(count or 0):
        addr = SELECTOR_TABLE_ADDR + i * SELECTOR_RECORD_STRIDE
        off = zimage.off(addr)
        vals = tuple(u16(zimage.data, off + j) for j in range(0, SELECTOR_RECORD_STRIDE, 2))
        records.append(SelectorRecord(i, addr, vals))

    return count, records


def selector_record_audit(zimage: Image, resolver_rows):
    banner("C. EXACT 18 x 0x14 SELECTOR RECORDS")

    count, records = parse_selector_records(zimage)
    print(f"u32[F03AD11C] = 0x{count:08X} ({count})")
    print(f"expected count = {EXPECTED_SELECTOR_COUNT}")
    print(f"count exact = {'PASS' if count == EXPECTED_SELECTOR_COUNT else 'OPEN'}")

    resolver_ids = {r.menu_id for r in resolver_rows}

    print()
    print("idx  address     key   s0/+02 s1/+04 s2/+06 s3/+08 s4/+0A s5/+0C s6/+0E s7/+10 s8/+12")
    print("---  ----------  ----  ------ ------ ------ ------ ------ ------ ------ ------ ------")

    for rec in records:
        tags = []
        if rec.key in resolver_ids:
            tags.append("RES")
        if rec.key in KNOWN_IDS:
            tags.append(KNOWN_IDS[rec.key])
        suffix = f"  <{'|'.join(tags)}>" if tags else ""

        print(
            f"{rec.index:02d}   0x{rec.addr:08X}  "
            + " ".join(f"{v:04X}" for v in rec.fields)
            + suffix
        )

    key_unique = len({r.key for r in records}) == len(records)
    stride_end = SELECTOR_TABLE_ADDR + count * SELECTOR_RECORD_STRIDE if count is not None else 0

    print()
    print(f"unique record keys = {'PASS' if key_unique else 'OPEN'}")
    print(f"table exact extent = 0x{SELECTOR_TABLE_ADDR:08X}..0x{stride_end:08X}")

    print()
    print("Compact key / selector1 / selector5 / selector8:")
    for rec in records:
        print(
            f"  key=0x{rec.key:04X}"
            f"  sel1=0x{rec.field_for_selector(1):04X}"
            f"  sel5=0x{rec.field_for_selector(5):04X}"
            f"  sel8=0x{rec.field_for_selector(8):04X}"
        )

    # Which columns are non-zero in actual data?
    nz = Counter()
    for s in range(9):
        nz[s] = sum(1 for r in records if r.field_for_selector(s) != 0)

    print()
    print("Non-zero entries per selector:")
    for s in range(9):
        print(f"  selector {s}: {nz[s]}/{len(records)}")

    populated = [s for s in range(9) if nz[s]]
    print(f"populated selector columns = {populated}")

    row_8321 = next((r for r in records if r.key == 0x8321), None)
    row_8928 = next((r for r in records if r.key == 0x8928), None)

    print()
    if row_8321:
        print(
            "[FACT] 0x8321 is a selector-table KEY:"
            f" sel1=0x{row_8321.field_for_selector(1):04X}"
            f" sel5=0x{row_8321.field_for_selector(5):04X}"
            f" sel8=0x{row_8321.field_for_selector(8):04X}"
        )
    else:
        print("[OPEN] 0x8321 key not found")

    print(f"[FACT] 0x8928 is {'present' if row_8928 else 'NOT present'} as a selector-table key.")

    print()
    print("IMPORTANT:")
    print("  0x10319094(0x8321) does NOT necessarily equal selector8(0x8321).")
    print("  The wrapper first maps 0x8321 to its RAW direct-child index under B709,")
    print("  then reads F00B7994[index], where F00B7994 was built from selector8 of")
    print("  the FILTERED B709 child branch. Do not conflate those two lookups.")

    return records


# -------------------------------------------------------------------------------------------------
# C. Selector-1 graph / parent-like hypothesis
# -------------------------------------------------------------------------------------------------

def selector1_graph_audit(records):
    banner("D. SELECTOR-1 GRAPH — PARENT-LIKE HYPOTHESIS TEST")

    by_key = {r.key: r for r in records}
    keys = set(by_key)

    internal_edges = []
    terminal_edges = []

    for r in records:
        v = r.field_for_selector(1)
        if v in keys:
            internal_edges.append((r.key, v))
        else:
            terminal_edges.append((r.key, v))

    print(f"records = {len(records)}")
    print(f"selector1 edges landing on another record key = {len(internal_edges)}")
    for a, b in internal_edges:
        print(f"  0x{a:04X} -> 0x{b:04X}")

    print()
    print("selector1 terminal edges:")
    for a, b in terminal_edges:
        tag = ""
        if b == ROOT_B709:
            tag = " <ROOT_B709>"
        print(f"  0x{a:04X} -> 0x{b:04X}{tag}")

    print()
    print("selector1 chains (stop when target is not another record key or loop):")
    root_direct = []

    for start in sorted(keys):
        chain = [start]
        seen = {start}
        cur = start

        while True:
            nxt = by_key[cur].field_for_selector(1)
            chain.append(nxt)
            if nxt == ROOT_B709:
                root_direct.append(cur)
            if nxt not in keys or nxt in seen:
                break
            seen.add(nxt)
            cur = nxt

        print("  " + " -> ".join(f"{x:04X}" for x in chain))

    print()
    print("records whose selector1 value is exactly B709:")
    for k in sorted(set(root_direct)):
        print(f"  0x{k:04X}")

    print()
    print("[HYPOTHESIS] selector1 is parent-like because multiple values form plausible")
    print("hierarchical chains (for example B6FE -> B6FF -> B701 -> B709).")
    print("This is NOT promoted to GET_PARENT_ID semantics here.")
    print("Promotion requires independent caller/consumer semantics.")

    return sorted(set(root_direct))


# -------------------------------------------------------------------------------------------------
# D. Full selector-1 ALICE owner
# -------------------------------------------------------------------------------------------------

def selector1_owner_audit(alice: Image):
    banner("E. ALICE 0x10362A14 — FULL SELECTOR-1 OWNER PATH")

    marks = {
        0x10362A42,
        0x10362A86,
        0x10362A96,
        0x10362AA0,
        0x10362AAA,
    }

    print_region(alice, SELECTOR1_OWNER_START, SELECTOR1_OWNER_END, "THUMB", marks)

    xs = dis(alice, SELECTOR1_OWNER_START, SELECTOR1_OWNER_END, "THUMB")

    print()
    print("Calls of interest:")
    for x in xs:
        t = direct_target(x)
        if x.mnemonic in {"bl", "blx"} and t is not None:
            tag = ""
            if (t & ~1) == ALICE_VENEER_COUNT_FILTERED:
                tag = " <COUNT_FILTERED veneer>"
            elif (t & ~1) == ALICE_VENEER_ENUM_FILTERED:
                tag = " <ENUM_FILTERED veneer>"
            elif (t & ~1) == ALICE_VENEER_SELECTOR:
                tag = " <SELECTOR lookup veneer>"
            elif (t & ~1) == 0x10317C58:
                tag = " <SET_CURRENT_CALLBACK>"
            print(f"  {fmt(x)}{tag}")

    print()
    print("Stack-buffer related memory instructions:")
    for x in xs:
        if "sp" in x.op_str.lower():
            print("  " + fmt(x))

    print()
    print("Selector-1 local contract already visible:")
    print("  - filtered child IDs are written to stack buffer at sp+0x20")
    print("  - each child is looked up with selector=1")
    print("  - selector-1 results are written to a parallel u16 buffer at sp+0x48")
    print("  - callback 0x10365D05 is then installed")
    print("A.25 intentionally prints the whole function so the post-build consumer of")
    print("the sp+0x48 buffer can be classified from exact code instead of guessed.")

    return xs


# -------------------------------------------------------------------------------------------------
# E. Selector 5 / selector 8 parallel arrays
# -------------------------------------------------------------------------------------------------

def classify_literal_ref_uses(img: Image, mode: str, x, base_value: int, max_forward=0x80):
    """
    Lightweight local provenance:
      literal load dst <- base_value
      tracks mov aliases and add/sub immediate aliases
      reports loads/stores through those aliases.
    This is NOT a complete CFG/dataflow engine.
    """
    start = x.address
    end = min(img.end, start + max_forward)
    xs = dis(img, start, end, mode)

    if not xs:
        return []

    li = literal_load(img, xs[0], mode)
    if not li:
        return []

    # register id -> ("CONST", value) or ("DERIVED", base, delta)
    state = {li[1]: ("CONST", base_value)}
    events = []

    for ins in xs[1:]:
        # Memory use before state mutation.
        for opi, op in enumerate(ins.operands):
            if op.type != ARM_OP_MEM:
                continue

            base_reg = op.mem.base
            idx_reg = op.mem.index
            if base_reg in state:
                expr = state[base_reg]
                eff = None
                if expr[0] == "CONST":
                    eff = (expr[1] + op.mem.disp) & 0xFFFFFFFF
                elif expr[0] == "DERIVED":
                    eff = (expr[1] + expr[2] + op.mem.disp) & 0xFFFFFFFF

                kind = "MEM"
                if ins.mnemonic.startswith("str"):
                    kind = "WRITE"
                elif ins.mnemonic.startswith("ldr"):
                    kind = "READ"

                variable = idx_reg != 0
                events.append((kind, ins, eff, variable, expr))

        # Simple aliases / immediate arithmetic.
        if len(ins.operands) >= 2 and ins.operands[0].type == ARM_OP_REG:
            dst = ins.operands[0].reg

            if ins.mnemonic in {"mov", "movs"} and ins.operands[1].type == ARM_OP_REG:
                src = ins.operands[1].reg
                if src in state:
                    state[dst] = state[src]
                else:
                    state.pop(dst, None)

            elif ins.mnemonic in {"add", "adds", "sub", "subs"}:
                # Typical Thumb:
                # adds rX,#imm
                # adds rX,rY,#imm
                ops = ins.operands

                sign = 1 if ins.mnemonic.startswith("add") else -1

                if len(ops) == 2 and ops[1].type == ARM_OP_IMM and dst in state:
                    old = state[dst]
                    delta = sign * ops[1].imm
                    if old[0] == "CONST":
                        state[dst] = ("DERIVED", old[1], delta)
                    else:
                        state[dst] = ("DERIVED", old[1], old[2] + delta)

                elif (
                    len(ops) >= 3
                    and ops[1].type == ARM_OP_REG
                    and ops[2].type == ARM_OP_IMM
                ):
                    src = ops[1].reg
                    if src in state:
                        old = state[src]
                        delta = sign * ops[2].imm
                        if old[0] == "CONST":
                            state[dst] = ("DERIVED", old[1], delta)
                        else:
                            state[dst] = ("DERIVED", old[1], old[2] + delta)
                    else:
                        state.pop(dst, None)

                elif (
                    len(ops) >= 3
                    and ops[1].type == ARM_OP_REG
                    and ops[2].type == ARM_OP_REG
                ):
                    # Variable offset derived from known base.
                    src1 = ops[1].reg
                    src2 = ops[2].reg
                    if src1 in state:
                        old = state[src1]
                        if old[0] == "CONST":
                            state[dst] = ("DERIVED", old[1], 0)
                        else:
                            state[dst] = old
                    elif src2 in state:
                        old = state[src2]
                        if old[0] == "CONST":
                            state[dst] = ("DERIVED", old[1], 0)
                        else:
                            state[dst] = old
                    else:
                        state.pop(dst, None)
                else:
                    state.pop(dst, None)

            else:
                # If instruction writes dst and isn't recognized, invalidate.
                # Do not invalidate on compares/tests.
                if ins.mnemonic not in {"cmp", "tst"}:
                    state.pop(dst, None)

        # Calls clobber r0-r3 in AAPCS. Capstone reg IDs can be resolved by names.
        if ins.mnemonic in {"bl", "blx"}:
            for reg in list(state):
                nm = ins.reg_name(reg)
                if nm in {"r0", "r1", "r2", "r3", "ip", "r12"}:
                    state.pop(reg, None)

    return events


def array_audit(alice: Image):
    banner("F. SELECTOR-8 / SELECTOR-5 PARALLEL ARRAY OWNERSHIP")

    print(f"selector8 array = 0x{ARRAY_SELECTOR8:08X}")
    print(f"selector5 array = 0x{ARRAY_SELECTOR5:08X} (= selector8 - 0x28)")

    print()
    print("Known builder region 0x103647C4:")
    print_region(
        alice,
        B709_PARALLEL_OWNER_START,
        B709_PARALLEL_OWNER_END,
        "THUMB",
        {0x1036481C, 0x1036488A, 0x10364890, 0x10364896, 0x103648A0}
    )

    for value, label in [
        (ARRAY_SELECTOR8, "SEL8_ARRAY"),
        (ARRAY_SELECTOR5, "SEL5_ARRAY"),
    ]:
        print()
        print(f"--- Exact literal references to {label} 0x{value:08X} ---")
        refs = real_literal_refs(alice, value)
        print(f"refs = {len(refs)}")
        for wa, mode, x, li in refs:
            print(f"  {mode} {fmt(x)} ; literal-word@0x{wa:08X}")
            for kind, ins, eff, variable, expr in classify_literal_ref_uses(alice, mode, x, value):
                extra = " +variable" if variable else ""
                ea = f"0x{eff:08X}" if eff is not None else "?"
                print(f"      {kind:<5} {fmt(ins)} ; effective={ea}{extra}")

    print()
    print("--- Derived SEL5 references from SEL8 literals followed by -0x28 ---")
    refs8 = real_literal_refs(alice, ARRAY_SELECTOR8)
    derived = 0

    for wa, mode, x, li in refs8:
        xs = dis(alice, x.address, min(alice.end, x.address + 0x90), mode)
        dst_name = li[0]

        for y in xs[1:]:
            txt = y.op_str.replace(" ", "").lower()
            if y.mnemonic in {"sub", "subs"} and dst_name.lower() in txt and "#0x28" in txt:
                derived += 1
                print(f"  base-ref {fmt(x)}")
                print(f"      DERIVE {fmt(y)} -> 0x{ARRAY_SELECTOR5:08X}")

    print(f"derived -0x28 sites = {derived}")

    print()
    print("[FACT] 0x103647C4 builds parallel arrays from the SAME filtered B709 child list:")
    print("       F00B7994[i] = selector8(child)")
    print("       F00B796C[i] = selector5(child)")
    print("Semantic names of selector5/selector8 remain UNKNOWN until consumers prove them.")


# -------------------------------------------------------------------------------------------------
# F. Filter bitmap / bound global xrefs
# -------------------------------------------------------------------------------------------------

def nearby_runtime_seed_words(images, lo: int, hi: int):
    found = defaultdict(list)

    for img in images:
        # Literal words are normally aligned but scan every byte for completeness.
        for off in range(0, len(img.data) - 3):
            v = u32(img.data, off)
            if v is not None and lo <= v <= hi:
                found[(img.name, v)].append(img.base + off)

    return found


def filter_global_audit(images):
    banner("G. F02D5458 BITMAP GLOBAL / INITIALIZER AUDIT")

    print("Exact predicate contract from A.24:")
    print("  dense = PARENT_TO_INDEX(id)")
    print("  if dense is outside bound -> non-set/default path")
    print("  byte = F00C1624[dense >> 3]")
    print("  bit  = 7 - (dense & 7)")
    print("  return 1 iff that bit is set")
    print("  callers retain only return == 0")
    print()

    targets = [
        (FILTER_BOUND_GLOBAL, "FILTER_BOUND_GLOBAL"),
        (FILTER_BITMAP, "FILTER_BITMAP"),
    ]

    for value, label in targets:
        print()
        print(f"### {label} 0x{value:08X}")

        total = 0
        for img in images:
            words = raw_word_locations(img, value)
            refs = real_literal_refs(img, value)
            print(f"{img.name}: raw u32 words={len(words)} real literal refs={len(refs)}")

            for wa, mode, x, li in refs:
                total += 1
                print(f"  {mode} {fmt(x)} ; literal-word@0x{wa:08X}")
                evs = classify_literal_ref_uses(img, mode, x, value, max_forward=0x120)

                for kind, ins, eff, variable, expr in evs:
                    extra = " +variable-index" if variable else ""
                    ea = f"0x{eff:08X}" if eff is not None else "?"
                    flag = ""
                    if kind == "WRITE":
                        flag = " <WRITE-CANDIDATE>"
                    print(f"      {kind:<5} {fmt(ins)} ; effective={ea}{extra}{flag}")

    print()
    print("### Nearby platform-address literal seeds")

    ranges = [
        (0xF007F040, 0xF007F060, "F007F04x registry/filter globals"),
        (0xF00C1600, 0xF00C1700, "F00C16xx bitmap neighborhood"),
    ]

    for lo, hi, label in ranges:
        print()
        print(f"{label}: 0x{lo:08X}..0x{hi:08X}")

        seeds = nearby_runtime_seed_words(images, lo, hi)
        if not seeds:
            print("  NONE")
            continue

        for (img_name, value), addrs in sorted(seeds.items(), key=lambda q: (q[0][0], q[0][1])):
            img = next(i for i in images if i.name == img_name)
            unique_words = sorted(set(addrs))
            all_refs = []
            for wa in unique_words:
                all_refs.extend(real_literal_refs_to_word(img, wa, value))

            if not all_refs:
                continue

            print(f"  {img_name} value=0x{value:08X} words={len(unique_words)} real_refs={len(all_refs)}")

            for mode, x, li in all_refs:
                print(f"      {mode} {fmt(x)} ; word@0x{li[2]:08X}")
                evs = classify_literal_ref_uses(img, mode, x, value, max_forward=0x100)
                for kind, ins, eff, variable, expr in evs:
                    if kind != "WRITE":
                        continue
                    extra = " +variable-index" if variable else ""
                    ea = f"0x{eff:08X}" if eff is not None else "?"
                    print(f"          WRITE {fmt(ins)} ; effective={ea}{extra}")

    print()
    print("Interpretation rule:")
    print("  A positive WRITE-CANDIDATE tied to the bitmap/base is useful.")
    print("  Zero exact writes is NOT proof that the bitmap is immutable: initialization")
    print("  can use an enclosing object/base pointer, memcpy/memset, relocation, or a")
    print("  platform routine whose address arithmetic is outside this lightweight scan.")


# -------------------------------------------------------------------------------------------------
# G. Focus selector values / xrefs
# -------------------------------------------------------------------------------------------------

def focus_selector_value_audit(images, resolver_rows):
    banner("H. SELECTOR VALUE STRUCTURAL XREFS")

    resolver_ids = {r.menu_id for r in resolver_rows}

    for value in sorted(FOCUS_SELECTOR_VALUES):
        tags = []
        if value in resolver_ids:
            tags.append("RESOLVER_ID")
        if value in KNOWN_IDS:
            tags.append(KNOWN_IDS[value])

        print()
        print(f"0x{value:04X}" + (f" <{'|'.join(tags)}>" if tags else ""))

        for img in images:
            u16_hits = all_hits(img.data, struct.pack("<H", value))
            u32_refs = real_literal_refs(img, value)

            print(f"  {img.name}: raw u16={len(u16_hits)} real u32-literal refs={len(u32_refs)}")

            for wa, mode, x, li in u32_refs[:30]:
                print(f"      {mode} {fmt(x)} ; literal-word@0x{wa:08X}")


# -------------------------------------------------------------------------------------------------
# H. Known 10319094 constant caller examples
# -------------------------------------------------------------------------------------------------

def wrapper_known_input_audit(alice: Image):
    banner("I. 0x10319094 KNOWN IMAGE/AUDIO CALLERS — RETURN USE")

    focus_inputs = {
        0x8321: "IMAGE_B",
        0x8928: "AUDIO",
    }

    xs = dis(alice, alice.base, alice.end, "THUMB")
    by_addr = {x.address: x for x in xs}

    calls = []
    for x in xs:
        if x.mnemonic not in {"bl", "blx"}:
            continue
        t = direct_target(x)
        if t is not None and (t & ~1) == RESOURCE_WRAPPER:
            calls.append(x)

    print(f"direct THUMB callers = {len(calls)}")

    for call in calls:
        lo = max(alice.base, call.address - 0x40)
        pre = [x for x in xs if lo <= x.address < call.address]

        found = []
        for x in reversed(pre):
            li = literal_load(alice, x, "THUMB")
            if li and li[3] in focus_inputs:
                found.append((li[3], x))
                break

        if not found:
            continue

        value, src = found[0]
        label = focus_inputs[value]

        print()
        print(f"{label} 0x{value:04X} caller @0x{call.address:08X}")
        print(f"  source literal: {fmt(src)}")
        print(f"  call          : {fmt(call)}")
        print("  immediate return-use window:")

        after = dis(alice, call.address + len(call.bytes), min(alice.end, call.address + 0x28), "THUMB")
        for y in after[:10]:
            print("    " + fmt(y))

    print()
    print("[FACT] Image 0x8321 and Audio 0x8928 both consume 0x10319094.")
    print("[UNKNOWN] The semantic name of the returned selector8-derived B709-branch")
    print("value is not yet proven (do not call it label/icon/string ID without consumer proof).")


# -------------------------------------------------------------------------------------------------
# J. Alignment analysis
# -------------------------------------------------------------------------------------------------

def alignment_analysis(records):
    banner("J. RAW B709 INDEX vs FILTERED B709 INDEX — ALIGNMENT GATE")

    print("Known facts:")
    print("  F02F9D34(descendant) returns index in RAW children[B709].")
    print("  0x10313998 / 0x103647C4 build selector arrays from FILTERED children[B709].")
    print("  F02D5458 skips any child whose dense-index bit is set in F00C1624.")
    print()
    print("Therefore 0x10319094 is index-safe only if one of the following holds:")
    print("  A. no B709 child before/at relevant branches is filtered out;")
    print("  B. raw children[B709] and filtered enumeration preserve a hidden alignment invariant;")
    print("  C. the bitmap state for this root is all-zero at the time these arrays are built.")
    print()
    print("A.25 does NOT assume any of A/B/C.")
    print("A.25's bitmap xref audit above determines whether static initialization can")
    print("resolve this; otherwise the exact filter state remains runtime-owned.")

    # Useful static observation: selector table is NOT children[B709].
    table_keys = {r.key for r in records}
    print()
    print(f"selector-table keys = {len(table_keys)}")
    print("These 18 keys are static lookup keys, NOT automatically raw/filtered children[B709].")


# -------------------------------------------------------------------------------------------------
# K. Decision
# -------------------------------------------------------------------------------------------------

def decision_gate(
    switch_ok,
    field_ok,
    records,
    selector1_direct_root,
):
    banner("K. DECISION GATE")

    print(f"manual switch8 targets                    = {'PASS' if switch_ok else 'OPEN'}")
    print(f"selector -> +02..+12 fields              = {'PASS' if field_ok else 'OPEN'}")
    print(f"selector records                         = {len(records)}")
    print(f"selector records exact count 18          = {'PASS' if len(records) == 18 else 'OPEN'}")
    print()

    if switch_ok and field_ok and len(records) == 18:
        print("[FACT] F0316CE0 = LOOKUP_STATIC_ID_SELECTOR_FIELD(id, selector)")
        print("       over 18 records of stride 0x14 at F03AD120.")
        print("[FACT] record key = +0x00.")
        print("[FACT] selectors map exactly:")
        print("       0:+02 1:+04 2:+06 3:+08 4:+0A 5:+0C 6:+0E 7:+10 8:+12.")
        print("[FACT] Only selectors 1, 5 and 8 are materially populated in this table.")
        print()

    print("[HYPOTHESIS] selector1 is parent-like; do NOT promote to GET_PARENT_ID yet.")
    if selector1_direct_root:
        print("Rows whose selector1 == B709:")
        for x in selector1_direct_root:
            print(f"  0x{x:04X}")
        print("These are selector-table relations only, NOT yet proven direct menu children.")
    print()

    print("[FACT] F02D5458 is a dense-index bitmap test:")
    print("       bitmap base = F00C1624")
    print("       bound global = F007F04C")
    print("       bit set => caller skips child; bit clear => caller retains child.")
    print()

    print("[FACT] 0x10319094 remains:")
    print("       idx = RAW_DIRECT_CHILD_INDEX_UNDER_B709(id)")
    print("       if idx == FF: return 2E")
    print("       return F00B7994[idx]")
    print()

    print("[NEXT]")
    print("  1. If bitmap initializer/write ownership is recovered above, reconstruct")
    print("     B709 filter state and prove/disprove raw-vs-filtered index alignment.")
    print("  2. Use full 0x10362A14 output-buffer consumption to classify selector1.")
    print("  3. Use F00B796C/F00B7994 consumers to classify selector5/selector8.")
    print("  4. Only then intersect Image 0x8321 / Audio 0x8928 ancestry with candidate")
    print("     B709 root branches to identify the visible Multimedia parent.")
    print()

    print("DO NOT PROMOTE:")
    print("  - B709 itself as Multimedia;")
    print("  - selector1 values as menu parents without independent proof;")
    print("  - selector5/8 values as labels/icons without consumer proof;")
    print("  - 0xB701 or 0xB707 as Multimedia solely because selector1 -> B709;")
    print("  - F03AD120 records as children[B709].")
    print()

    print("STILL UNKNOWN:")
    print("  exact raw children[B709]")
    print("  exact filtered children[B709]")
    print("  exact bitmap runtime state for B709 children")
    print("  selector1 semantic name")
    print("  selector5 semantic name")
    print("  selector8 semantic name")
    print("  numeric visible Multimedia ID")
    print("  FM Radio child ID")
    print("  exact Multimedia children[]")
    print("  whether 0x8928 is absent vs present-but-filtered in Multimedia")
    print()

    print("PHONE ACCESSED       : NO")
    print("FLASH MODIFIED       : NO")
    print("PATCH GENERATED      : NO")
    print("PHYSICAL CANDIDATE   : NO")
    print("HARDWARE WRITE AUTHORIZED: NO")


# -------------------------------------------------------------------------------------------------
# CLI
# -------------------------------------------------------------------------------------------------

def parse_args():
    p = argparse.ArgumentParser()
    p.add_argument(
        "--alice",
        default="research/f2/work/extracted/altice_alice/alice-py.bin",
    )
    p.add_argument(
        "--zimage",
        default="research/f2/work/extracted/altice_platform/zimage.bin",
    )
    p.add_argument(
        "--report",
        default="research/f2/work/reports/s13_5a25_selector_switch_filter_bitmap_root_alignment.txt",
    )
    return p.parse_args()


def resolve(root: Path, s: str):
    p = Path(s)
    return p if p.is_absolute() else root / p


def main():
    args = parse_args()
    root = Path.cwd()
    report_path = resolve(root, args.report)
    report_path.parent.mkdir(parents=True, exist_ok=True)

    cap = io.StringIO()
    old = sys.stdout
    sys.stdout = Tee(old, cap)

    try:
        banner("S13.5A.25 - SELECTOR SWITCH / FILTER BITMAP / ROOT-BRANCH ALIGNMENT AUDIT")
        print("STRICTLY OFFLINE")
        print("PHONE ACCESSED       : NO")
        print("FLASH MODIFIED       : NO")
        print("PATCH GENERATED      : NO")
        print("REPACK               : NO")

        banner("A. CANONICAL INPUTS")
        alice = verify(
            resolve(root, args.alice),
            "ALICE",
            ALICE_BASE,
            ALICE_SIZE,
            ALICE_SHA256,
        )
        zimage = verify(
            resolve(root, args.zimage),
            "ZIMAGE",
            ZIMAGE_BASE,
            ZIMAGE_SIZE,
            ZIMAGE_SHA256,
        )
        images = [alice, zimage]
        resolver_rows = parse_resolver(zimage)

        switch_ok, field_ok, field_map = selector_switch_audit(zimage)
        records = selector_record_audit(zimage, resolver_rows)
        selector1_direct_root = selector1_graph_audit(records)
        selector1_owner_audit(alice)
        array_audit(alice)
        filter_global_audit(images)
        focus_selector_value_audit(images, resolver_rows)
        wrapper_known_input_audit(alice)
        alignment_analysis(records)
        decision_gate(
            switch_ok,
            field_ok,
            records,
            selector1_direct_root,
        )

        print()
        print(f"REPORT = {report_path}")
        return 0

    finally:
        sys.stdout = old
        report_path.write_text(cap.getvalue(), encoding="utf-8")


if __name__ == "__main__":
    raise SystemExit(main())
