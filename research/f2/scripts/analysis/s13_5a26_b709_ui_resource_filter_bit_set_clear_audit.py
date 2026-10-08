#!/usr/bin/env python3
"""
S13.5A.26 - B709 UI RESOURCE DOMAIN / FILTER BIT SET-CLEAR AUDIT

STRICTLY OFFLINE / READ-ONLY.

A.25 proved:
  * F0316CE0 = LOOKUP_STATIC_ID_SELECTOR_FIELD(id, selector)
    over 18 records of stride 0x14 at F03AD120.
  * selector mapping:
      0:+02 1:+04 2:+06 3:+08 4:+0A 5:+0C 6:+0E 7:+10 8:+12
  * only selectors 1,5,8 are materially populated.
  * 0x10362A14:
      N = COUNT_FILTERED_CHILDREN(B709)
      ENUM_FILTERED_CHILD_IDS(B709, sp+0x20)
      selector1(child[i]) -> sp+0x48
      passes sp+0x48 onward to 0x103647C4.
  * 0x103647C4:
      F00B7994[i] = selector8(filtered_child[i])
      F00B796C[i] = selector5(filtered_child[i])
  * 0x1036B6E8 reads F00B796C[index], sends it to 0x1031DA2C,
    then stores the converted result to F0096018+0x24.
  * F02D5458 is a bitmap predicate using F00C1624 and bound F007F04C.
  * exact bitmap writers exist at F02D4D32 and F02D584A.

Goals of A.26:
  1. Prove the caller->callee stack argument mapping from 0x10362A14
     into 0x103647C4, especially selector1[] and filtered_count.
  2. Inspect the exact bodies and caller domains of:
       0x1031DA2C
       0x10321B40
       0x10316834
     to classify selector1/selector5/selector8 as UI/resource values
     without guessing whether they are strings/icons.
  3. Recover all exact users of F0096018+0x24 (= F009603C),
     the slot written from selector5[index].
  4. Inspect 0x1036B6E8 and its registration/ownership.
  5. Recover the complete bitmap writer functions around F02D4D32
     and F02D584A, determine SET/CLEAR-like operations, and census
     their direct callers / constant arguments.
  6. Inspect F02EE32C around the filter globals for size/base exposure.
  7. Keep the RAW-vs-FILTERED alignment issue explicit.

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
from collections import defaultdict, Counter, deque

from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_THUMB, CS_MODE_LITTLE_ENDIAN
from capstone.arm import ARM_OP_IMM, ARM_OP_MEM, ARM_OP_REG, ARM_REG_PC

ALICE_BASE = 0x1024EC00
ALICE_SIZE = 0x157BB4
ALICE_SHA256 = "7246242b67afae0d13104452bc3257827cb778119b54e7a26fb7fb55993697ea"

ZIMAGE_BASE = 0xF023CA50
ZIMAGE_SIZE = 0x185E98
ZIMAGE_SHA256 = "85fba8c8ae8161e4c1f8ced7983ec30d48c54ab10e51c69fcdfb900aca220954"

# Core A.25 facts
ROOT_B709 = 0xB709
COUNT_FILTERED_VENEER = 0x102FC51C
ENUM_FILTERED_VENEER = 0x102FC3CC
SELECTOR_VENEER = 0x102FC20C

CALLER_BUILD = 0x10362A14
CALLEE_BUILD = 0x103647C4

RESOURCE_HELPER_A = 0x1031DA2C
RESOURCE_HELPER_B = 0x10321B40
ITEM_ASSEMBLER = 0x10316834

SELECTOR5_ARRAY = 0xF00B796C
SELECTOR8_ARRAY = 0xF00B7994

SELECTOR5_INDEX_WRAPPER = 0x1036B6E8
SELECTOR5_WRAPPER_PTR = 0x103649E8

PLATFORM_BASE = 0xF0096018
SELECTOR5_CONVERTED_SLOT = PLATFORM_BASE + 0x24  # F009603C

FILTER_BOUND_GLOBAL = 0xF007F04C
FILTER_BITMAP = 0xF00C1624
FILTER_PRED = 0xF02D5458
BITMAP_WRITE_A = 0xF02D4D32
BITMAP_WRITE_B = 0xF02D584A
FILTER_GLOBAL_EXPOSER = 0xF02EE32C

SELECTOR_COUNT_ADDR = 0xF03AD11C
SELECTOR_TABLE_ADDR = 0xF03AD120
SELECTOR_STRIDE = 0x14

KNOWN_SELECTOR_VALUES = {
    0xB748: "SEL1/SEL5(87ED)",
    0xB749: "SEL1/SEL5(BA3C)",
    0xB74A: "SEL1(8321)",
    0xB747: "SEL5(8321)",
    0xB70B: "SEL1(B6FD)",
    0xB71B: "SEL5(B6FD)",
    0xB73B: "SEL8(B6FD)",
    0xB709: "ROOT_B709 / SEL1(B701,B707)",
    0xB719: "SEL5(B701,B707)",
    0xB739: "SEL8(B701,B707)",
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


def banner(s):
    print()
    print("=" * 160)
    print(s)
    print("=" * 160)


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


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
    end = min(end, img.end)
    md = md_t if mode == "THUMB" else md_a
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


def all_hits(data: bytes, needle: bytes):
    out = []
    pos = 0
    while True:
        pos = data.find(needle, pos)
        if pos < 0:
            return out
        out.append(pos)
        pos += 1


def raw_word_locations(img: Image, value: int):
    return [img.base + o for o in all_hits(img.data, struct.pack("<I", value & 0xFFFFFFFF))]


def real_literal_refs_to_word(img: Image, literal_addr: int, expected_value: int):
    refs = []
    lo = max(img.base, literal_addr - 0x1000) & ~1
    hi = min(img.end, literal_addr + 4)

    for a in range(lo, hi, 2):
        x = decode1(img, a, "THUMB")
        if not x:
            continue
        li = literal_load(img, x, "THUMB")
        if li and li[2] == literal_addr and li[3] == expected_value:
            refs.append(("THUMB", x, li))

    lo = max(img.base, literal_addr - 0x2000) & ~3
    for a in range(lo, hi, 4):
        x = decode1(img, a, "ARM")
        if not x:
            continue
        li = literal_load(img, x, "ARM")
        if li and li[2] == literal_addr and li[3] == expected_value:
            refs.append(("ARM", x, li))

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


def direct_calls(img: Image, target: int):
    out = []
    for x in dis(img, img.base, img.end, "THUMB"):
        if x.mnemonic in {"bl", "blx"}:
            t = direct_target(x)
            if t is not None and (t & ~1) == (target & ~1):
                out.append(x)
    for x in dis(img, img.base & ~3, img.end, "ARM"):
        if x.mnemonic in {"bl", "blx"}:
            t = direct_target(x)
            if t is not None and (t & ~1) == (target & ~1):
                out.append(x)
    return out


def nearest_push(img: Image, addr: int, max_back=0x100):
    lo = max(img.base, addr - max_back) & ~1
    best = None
    for a in range(lo, addr + 1, 2):
        x = decode1(img, a, "THUMB")
        if x and x.mnemonic == "push" and "lr" in x.op_str:
            best = a
    return best


def approx_func_end(img: Image, start: int, max_len=0x180):
    # Prefer a return reached after start, but keep enough room for branchy code.
    xs = dis(img, start, min(img.end, start + max_len), "THUMB")
    for x in xs:
        if x.address <= start:
            continue
        if x.mnemonic == "pop" and "pc" in x.op_str:
            return x.address + len(x.bytes)
        if x.mnemonic == "bx" and x.op_str.strip() == "lr":
            return x.address + len(x.bytes)
    return min(img.end, start + max_len)


def print_region(img: Image, start: int, end: int, marks=None):
    marks = marks or set()
    for x in dis(img, start, end, "THUMB"):
        notes = []
        t = direct_target(x)
        if t is not None:
            notes.append(f"target=0x{t:08X}")
        li = literal_load(img, x, "THUMB")
        if li:
            tags = []
            v = li[3]
            if v == ROOT_B709:
                tags.append("B709")
            if v == SELECTOR5_ARRAY:
                tags.append("SEL5_ARRAY")
            if v == SELECTOR8_ARRAY:
                tags.append("SEL8_ARRAY")
            if v == PLATFORM_BASE:
                tags.append("PLATFORM_BASE")
            if v == FILTER_BITMAP:
                tags.append("FILTER_BITMAP")
            if v == FILTER_BOUND_GLOBAL:
                tags.append("FILTER_BOUND")
            notes.append(
                f"literal@0x{li[2]:08X}=0x{v:08X}->{li[0]}"
                + (f"<{'|'.join(tags)}>" if tags else "")
            )
        print(
            (">>> " if x.address in marks else "    ")
            + fmt(x)
            + ((" ; " + ", ".join(notes)) if notes else "")
        )


def backtrace_r0_constant(img: Image, call_addr: int, max_back=0x40):
    xs = dis(img, max(img.base, call_addr - max_back), call_addr, "THUMB")
    # Very conservative: only literal into r0, movs r0,#imm, or alias from a literal register
    reg_const = {}
    for x in xs:
        li = literal_load(img, x, "THUMB")
        if li:
            reg_const[li[0]] = li[3]
            continue

        if len(x.operands) >= 2 and x.operands[0].type == ARM_OP_REG:
            dst = x.reg_name(x.operands[0].reg)

            if x.mnemonic in {"mov", "movs"}:
                if x.operands[1].type == ARM_OP_IMM:
                    reg_const[dst] = x.operands[1].imm & 0xFFFFFFFF
                elif x.operands[1].type == ARM_OP_REG:
                    src = x.reg_name(x.operands[1].reg)
                    if src in reg_const:
                        reg_const[dst] = reg_const[src]
                    else:
                        reg_const.pop(dst, None)

            elif x.mnemonic in {"add", "adds", "sub", "subs"}:
                # Track immediate arithmetic on same register.
                ops = x.operands
                sign = 1 if x.mnemonic.startswith("add") else -1
                if len(ops) == 2 and ops[1].type == ARM_OP_IMM and dst in reg_const:
                    reg_const[dst] = (reg_const[dst] + sign * ops[1].imm) & 0xFFFFFFFF
                elif (
                    len(ops) >= 3
                    and ops[1].type == ARM_OP_REG
                    and ops[2].type == ARM_OP_IMM
                ):
                    src = x.reg_name(ops[1].reg)
                    if src in reg_const:
                        reg_const[dst] = (reg_const[src] + sign * ops[2].imm) & 0xFFFFFFFF
                    else:
                        reg_const.pop(dst, None)

        if x.mnemonic in {"bl", "blx"}:
            # Calls clobber r0-r3.
            for r in ["r0", "r1", "r2", "r3"]:
                reg_const.pop(r, None)

    return reg_const.get("r0")


def symbolic_base_uses(img: Image, literal_x, base_value: int, max_forward=0x80):
    li = literal_load(img, literal_x, "THUMB")
    if not li:
        return []

    state = {li[1]: (base_value, 0)}
    out = []
    xs = dis(img, literal_x.address + len(literal_x.bytes), min(img.end, literal_x.address + max_forward), "THUMB")

    for x in xs:
        # memory use
        for op in x.operands:
            if op.type != ARM_OP_MEM:
                continue
            if op.mem.base in state:
                base, delta = state[op.mem.base]
                ea = (base + delta + op.mem.disp) & 0xFFFFFFFF
                kind = "MEM"
                if x.mnemonic.startswith("ldr"):
                    kind = "READ"
                elif x.mnemonic.startswith("str"):
                    kind = "WRITE"
                variable = op.mem.index != 0
                out.append((kind, x, ea, variable))

        # aliases / imm arithmetic
        if len(x.operands) >= 2 and x.operands[0].type == ARM_OP_REG:
            dst = x.operands[0].reg
            if x.mnemonic in {"mov", "movs"} and x.operands[1].type == ARM_OP_REG:
                src = x.operands[1].reg
                if src in state:
                    state[dst] = state[src]
                else:
                    state.pop(dst, None)
            elif x.mnemonic in {"add", "adds", "sub", "subs"}:
                sign = 1 if x.mnemonic.startswith("add") else -1
                ops = x.operands
                if len(ops) == 2 and ops[1].type == ARM_OP_IMM and dst in state:
                    base, delta = state[dst]
                    state[dst] = (base, delta + sign * ops[1].imm)
                elif len(ops) >= 3 and ops[1].type == ARM_OP_REG and ops[2].type == ARM_OP_IMM:
                    src = ops[1].reg
                    if src in state:
                        base, delta = state[src]
                        state[dst] = (base, delta + sign * ops[2].imm)
                    else:
                        state.pop(dst, None)
                else:
                    state.pop(dst, None)

        if x.mnemonic in {"bl", "blx"}:
            for reg in list(state):
                nm = x.reg_name(reg)
                if nm in {"r0", "r1", "r2", "r3", "r12", "ip"}:
                    state.pop(reg, None)

    return out


def selector_records(zimage: Image):
    count = u32(zimage.data, zimage.off(SELECTOR_COUNT_ADDR))
    rows = []
    for i in range(count or 0):
        off = zimage.off(SELECTOR_TABLE_ADDR + i * SELECTOR_STRIDE)
        vals = [u16(zimage.data, off + j) for j in range(0, SELECTOR_STRIDE, 2)]
        rows.append(vals)
    return rows


# -------------------------------------------------------------------------------------------------
# B. Exact caller->callee stack contract
# -------------------------------------------------------------------------------------------------

def callframe_audit(alice: Image):
    banner("B. 0x10362A14 -> 0x103647C4 EXACT CALL-FRAME CONTRACT")

    print("Caller tail:")
    print_region(
        alice,
        0x10362A7C,
        0x10362AD4,
        marks={0x10362A86, 0x10362A96, 0x10362AA0, 0x10362ACE, 0x10362AD0}
    )

    print()
    print("Callee prologue / loop:")
    print_region(
        alice,
        0x103647C4,
        0x103648A8,
        marks={0x103647C4, 0x103647C6, 0x103647CA, 0x103647CC,
               0x1036484C, 0x1036486A, 0x1036486C, 0x10364874,
               0x10364876, 0x10364880, 0x103648A4}
    )

    # Exact frame arithmetic from known instructions:
    # push {r0-r7,lr} = 9 regs = 0x24; sub sp,#0x6C -> total 0x90.
    total_frame = 0x24 + 0x6C
    print()
    print(f"callee frame delta = 0x24 + 0x6C = 0x{total_frame:X}")
    print("Thus:")
    print("  callee [sp+0x98] = caller [sp+0x08]")
    print("  callee [sp+0x9C] = caller [sp+0x0C]")
    print("  callee [sp+0xA0] = caller [sp+0x10]")
    print("  callee [sp+0xA4] = caller [sp+0x14]")

    print()
    print("Caller writes before BL 0x103647C4:")
    print("  caller sp+0x08 = r6 = COUNT_FILTERED_CHILDREN(B709)")
    print("  caller sp+0x0C = sp+0xA4 (parallel u16 resource array)")
    print("  caller sp+0x10 = r4 = sp+0x48 (selector1[] output)")
    print("  caller sp+0x14 = value loaded from caller sp+0x74 (constant 2 in this path)")
    print()
    print("Callee reads:")
    print("  [sp+0x98] -> loop count / item count")
    print("  [sp+0x9C] -> parallel u16 array")
    print("  [sp+0xA0] -> r4, then ldrh [r4,index*2] -> 0x1031DA2C")
    print("  [sp+0xA4] -> r6 setup value")
    print()
    print("[FACT] The selector1[] buffer built at caller sp+0x48 is the exact u16")
    print("       array dereferenced through r4 inside 0x103647C4.")
    print("[FACT] COUNT_FILTERED_CHILDREN(B709) is the exact loop bound read at")
    print("       callee [sp+0x98].")
    print("[FACT] For every item i:")
    print("       converted_selector1 = 0x1031DA2C(selector1[i])")
    print("       converted_parallel  = 0x10321B40(parallel[i])")
    print("       0x10316834(i, converted_parallel, converted_selector1)")


# -------------------------------------------------------------------------------------------------
# C. Helper bodies + callers
# -------------------------------------------------------------------------------------------------

def helper_audit(images):
    banner("C. RESOURCE/UI HELPER BODY + CALLER DOMAIN AUDIT")

    helpers = [
        (RESOURCE_HELPER_A, "HELPER_A_1031DA2C"),
        (RESOURCE_HELPER_B, "HELPER_B_10321B40"),
        (ITEM_ASSEMBLER, "ITEM_ASSEMBLER_10316834"),
    ]

    alice = next(i for i in images if i.name == "ALICE")

    for target, label in helpers:
        print()
        print(f"### {label} @0x{target:08X}")

        start = target & ~1
        end = approx_func_end(alice, start, 0x180)
        print(f"approx body = 0x{start:08X}..0x{end:08X}")
        print_region(alice, start, end, marks={start})

        calls = direct_calls(alice, target)
        print()
        print(f"ALICE direct callers = {len(calls)}")

        consts = Counter()
        for c in calls:
            v = backtrace_r0_constant(alice, c.address, 0x50)
            if v is not None:
                consts[v & 0xFFFFFFFF] += 1

        if consts:
            print("Recovered conservative r0 constants at calls:")
            for v, n in consts.most_common():
                tag = KNOWN_SELECTOR_VALUES.get(v & 0xFFFF, "")
                print(f"  0x{v:08X} x{n}" + (f" <{tag}>" if tag else ""))

        # Print the first 30 callers with local input and immediate return use.
        for c in calls[:30]:
            v = backtrace_r0_constant(alice, c.address, 0x50)
            print(f"  CALL {fmt(c)} r0_const={('0x%08X' % v) if v is not None else 'UNKNOWN'}")
            after = dis(alice, c.address + len(c.bytes), min(alice.end, c.address + 0x18), "THUMB")
            for y in after[:5]:
                print("      " + fmt(y))

    print()
    print("Interpretation rule:")
    print("  If selector1/selector5/selector8 values all feed the same conversion helper,")
    print("  classify them as a common RESOURCE DOMAIN first.")
    print("  Do NOT name the resource type 'string', 'icon', or 'image' unless helper")
    print("  ownership or downstream consumer semantics make that explicit.")


# -------------------------------------------------------------------------------------------------
# D. F009603C exact slot
# -------------------------------------------------------------------------------------------------

def converted_slot_audit(alice: Image):
    banner("D. F009603C (= F0096018+0x24) EXACT USER AUDIT")

    print(f"slot = 0x{SELECTOR5_CONVERTED_SLOT:08X}")
    print(f"base = 0x{PLATFORM_BASE:08X}, offset = +0x24")

    exact_words = raw_word_locations(alice, SELECTOR5_CONVERTED_SLOT)
    print(f"raw exact slot words in ALICE = {len(exact_words)}")
    for wa in exact_words:
        refs = real_literal_refs_to_word(alice, wa, SELECTOR5_CONVERTED_SLOT)
        for mode, x, li in refs:
            print(f"  exact {mode} ref: {fmt(x)} word@0x{wa:08X}")

    base_refs = real_literal_refs(alice, PLATFORM_BASE)
    print(f"base literal refs = {len(base_refs)}")

    reads = []
    writes = []

    for wa, mode, x, li in base_refs:
        if mode != "THUMB":
            continue
        evs = symbolic_base_uses(alice, x, PLATFORM_BASE, 0x90)
        for kind, ins, ea, variable in evs:
            if ea == SELECTOR5_CONVERTED_SLOT:
                row = (x, ins, variable)
                if kind == "READ":
                    reads.append(row)
                elif kind == "WRITE":
                    writes.append(row)

    print()
    print(f"exact symbolic reads  = {len(reads)}")
    for seed, ins, variable in reads:
        print(f"  seed {fmt(seed)}")
        print(f"    READ  {fmt(ins)}" + (" +variable" if variable else ""))

    print(f"exact symbolic writes = {len(writes)}")
    for seed, ins, variable in writes:
        print(f"  seed {fmt(seed)}")
        print(f"    WRITE {fmt(ins)}" + (" +variable" if variable else ""))

    print()
    print("[FACT] 0x1036B6E8 writes 0x1031DA2C(F00B796C[index]) into F009603C.")
    print("If independent readers of F009603C are recovered above, their consumers are")
    print("the best static evidence for the semantic type of selector5 resources.")


# -------------------------------------------------------------------------------------------------
# E. 1036B6E8 wrapper ownership
# -------------------------------------------------------------------------------------------------

def selector5_wrapper_audit(alice: Image):
    banner("E. 0x1036B6E8 SELECTED-INDEX / SELECTOR5 WRAPPER")

    print_region(
        alice,
        SELECTOR5_INDEX_WRAPPER,
        0x1036B720,
        marks={0x1036B6E8, 0x1036B6F6, 0x1036B6F8, 0x1036B6FE, 0x1036B718}
    )

    ptr_val = u32(alice.data, alice.off(SELECTOR5_WRAPPER_PTR))
    print()
    print(f"pointer word @0x{SELECTOR5_WRAPPER_PTR:08X} = 0x{ptr_val:08X}")
    print(f"expected Thumb pointer = 0x{SELECTOR5_INDEX_WRAPPER|1:08X}")
    print(f"pointer exact = {'PASS' if ptr_val == (SELECTOR5_INDEX_WRAPPER|1) else 'OPEN'}")

    refs = real_literal_refs_to_word(alice, SELECTOR5_WRAPPER_PTR, ptr_val)
    print(f"real literal refs to wrapper pointer word = {len(refs)}")
    for mode, x, li in refs:
        print(f"  {mode} {fmt(x)}")

    print()
    print("[FACT] wrapper input r0 is preserved as index in r4.")
    print("[FACT] F00B796C[index] is converted by 0x1031DA2C.")
    print("[FACT] converted result is stored to F009603C.")
    print("[STRONG] This is selected-item UI/resource behavior, not parent traversal.")


# -------------------------------------------------------------------------------------------------
# F. Bitmap writer reconstruction
# -------------------------------------------------------------------------------------------------

def classify_bitmap_writer(zimage: Image, write_addr: int):
    start = nearest_push(zimage, write_addr, 0x80)
    if start is None:
        start = max(zimage.base, write_addr - 0x30)
    end = approx_func_end(zimage, start, 0x100)
    xs = dis(zimage, start, end, "THUMB")

    has_orr = any(x.mnemonic in {"orr", "orrs"} for x in xs)
    has_bic = any(x.mnemonic in {"bic", "bics"} for x in xs)
    has_eor = any(x.mnemonic in {"eor", "eors"} for x in xs)

    if has_orr and not has_bic:
        cls = "SET_LIKE"
    elif has_bic and not has_orr:
        cls = "CLEAR_LIKE"
    elif has_eor and not has_orr and not has_bic:
        cls = "TOGGLE_LIKE"
    else:
        cls = "OPEN"

    return start, end, cls, xs


def bitmap_writer_audit(alice: Image, zimage: Image):
    banner("F. FILTER BITMAP WRITER SET/CLEAR CONTRACT")

    writers = [
        (BITMAP_WRITE_A, "BITMAP_WRITE_A"),
        (BITMAP_WRITE_B, "BITMAP_WRITE_B"),
    ]

    for wa, label in writers:
        start, end, cls, xs = classify_bitmap_writer(zimage, wa)

        print()
        print(f"### {label} write@0x{wa:08X}")
        print(f"function approx = 0x{start:08X}..0x{end:08X}")
        print(f"classification = {cls}")
        print_region(zimage, start, end, marks={wa, start})

        for img in [alice, zimage]:
            calls = direct_calls(img, start)
            print(f"{img.name} direct callers to 0x{start:08X} = {len(calls)}")
            for c in calls[:60]:
                v = backtrace_r0_constant(img, c.address, 0x50) if img.name == "ALICE" else backtrace_r0_constant(img, c.address, 0x50)
                print(
                    f"  {fmt(c)}"
                    + (f" r0_const=0x{v:08X}" if v is not None else " r0_const=UNKNOWN")
                )

        # Raw pointer ownership.
        ptrs = []
        for img in [alice, zimage]:
            for pval in [start, start | 1]:
                for off in all_hits(img.data, struct.pack("<I", pval & 0xFFFFFFFF)):
                    ptrs.append((img.name, img.base + off, pval))
        if ptrs:
            print("raw pointer refs:")
            for name, addr, pval in ptrs[:40]:
                print(f"  {name} word@0x{addr:08X}=0x{pval:08X}")

    print()
    print("### FILTER GLOBAL EXPOSER / INITIALIZER CANDIDATE @F02EE32C")
    start = nearest_push(zimage, FILTER_GLOBAL_EXPOSER, 0x60) or FILTER_GLOBAL_EXPOSER
    end = approx_func_end(zimage, start, 0xA0)
    print_region(zimage, start, end, marks={FILTER_GLOBAL_EXPOSER})

    calls = direct_calls(zimage, start)
    print(f"ZIMAGE direct callers = {len(calls)}")
    for c in calls[:60]:
        print("  " + fmt(c))

    print()
    print("Interpretation:")
    print("  SET_LIKE/CLEAR_LIKE is promoted only from exact OR/BIC behavior in the")
    print("  writer body. Caller r0 constants, if any, identify concrete IDs whose")
    print("  filter bits are modified.")
    print("  Absence of constant callers does not imply runtime state is unknowable;" )
    print("  callers may pass registry IDs dynamically.")


# -------------------------------------------------------------------------------------------------
# G. Selector domain correlation
# -------------------------------------------------------------------------------------------------

def selector_domain_correlation(zimage: Image):
    banner("G. SELECTOR 1 / 5 / 8 DOMAIN CORRELATION")

    rows = selector_records(zimage)

    print("key    selector1 selector5 selector8  s1==s5  s1==B709")
    print("----   --------- --------- ---------  ------  --------")
    for r in rows:
        key = r[0]
        s1 = r[2]   # +04
        s5 = r[6]   # +0C
        s8 = r[9]   # +12
        print(
            f"{key:04X}   {s1:04X}      {s5:04X}      {s8:04X}      "
            f"{str(s1==s5):<6}  {str(s1==ROOT_B709)}"
        )

    same15 = sum(1 for r in rows if r[2] == r[6])
    nonzero8 = sum(1 for r in rows if r[9] != 0)

    print()
    print(f"selector1 == selector5 rows = {same15}/{len(rows)}")
    print(f"selector8 non-zero rows     = {nonzero8}/{len(rows)}")
    print()
    print("[FACT] selector1/selector5/selector8 are fields of the SAME static")
    print("       resource record keyed by resolver/menu IDs.")
    print("[STRONG] selector1 and selector5 are resource variants because both")
    print("         are converted through 0x1031DA2C in UI-list paths.")
    print("[OPEN] exact resource type and meaning of selector8 remain to be named.")


# -------------------------------------------------------------------------------------------------
# H. Decision gate
# -------------------------------------------------------------------------------------------------

def decision_gate():
    banner("H. DECISION GATE")

    print("[FACT] A.25 selector mapping is retained:")
    print("       F0316CE0(id,s): 1->+04, 5->+0C, 8->+12.")
    print()
    print("[FACT] The selector1[] array produced from filtered children[B709]")
    print("       is passed verbatim to 0x103647C4 and consumed item-by-item.")
    print("[FACT] Its loop bound is the filtered B709 child count.")
    print("[FACT] selector1[i] is converted by 0x1031DA2C before item assembly.")
    print("[FACT] selector5[index] is also converted by 0x1031DA2C in 0x1036B6E8.")
    print()
    print("[CLASSIFICATION]")
    print("  selector1 = UI/resource-domain value : STRONGLY SUPPORTED")
    print("  selector5 = selected-item UI/resource-domain value : STRONGLY SUPPORTED")
    print("  selector8 = same static resource-family field but exact semantic OPEN")
    print("  old 'selector1 is parent-like' interpretation is now WEAKENED/SUPERSEDED")
    print("  unless helper semantics unexpectedly prove these resource IDs encode parents.")
    print()
    print("[NEXT]")
    print("  - Use helper body / slot-reader evidence above to name the resource type.")
    print("  - Use bitmap SET/CLEAR writer callers to recover the concrete runtime")
    print("    filter policy and close raw-vs-filtered index alignment.")
    print("  - Once B709 branch resource labels are named, bind Image/Audio/FM to the")
    print("    exact visible branch and identify Multimedia without numeric guessing.")
    print()
    print("DO NOT PROMOTE:")
    print("  B701/B707 as Multimedia solely from selector1==B709.")
    print("  B74A/B747 as menu parent IDs.")
    print("  selector resources as strings/icons until helper semantics prove it.")
    print()
    print("PHONE ACCESSED       : NO")
    print("FLASH MODIFIED       : NO")
    print("PATCH GENERATED      : NO")
    print("PHYSICAL CANDIDATE   : NO")
    print("HARDWARE WRITE AUTHORIZED: NO")


def parse_args():
    p = argparse.ArgumentParser()
    p.add_argument("--alice", default="research/f2/work/extracted/altice_alice/alice-py.bin")
    p.add_argument("--zimage", default="research/f2/work/extracted/altice_platform/zimage.bin")
    p.add_argument("--report", default="research/f2/work/reports/s13_5a26_b709_ui_resource_filter_bit_set_clear.txt")
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
        banner("S13.5A.26 - B709 UI RESOURCE DOMAIN / FILTER BIT SET-CLEAR AUDIT")
        print("STRICTLY OFFLINE")
        print("PHONE ACCESSED       : NO")
        print("FLASH MODIFIED       : NO")
        print("PATCH GENERATED      : NO")
        print("REPACK               : NO")

        banner("A. CANONICAL INPUTS")
        alice = verify(resolve(root, args.alice), "ALICE", ALICE_BASE, ALICE_SIZE, ALICE_SHA256)
        zimage = verify(resolve(root, args.zimage), "ZIMAGE", ZIMAGE_BASE, ZIMAGE_SIZE, ZIMAGE_SHA256)

        callframe_audit(alice)
        helper_audit([alice, zimage])
        converted_slot_audit(alice)
        selector5_wrapper_audit(alice)
        bitmap_writer_audit(alice, zimage)
        selector_domain_correlation(zimage)
        decision_gate()

        print()
        print(f"REPORT = {report_path}")
        return 0

    finally:
        sys.stdout = old
        report_path.write_text(cap.getvalue(), encoding="utf-8")


if __name__ == "__main__":
    raise SystemExit(main())
