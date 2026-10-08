#!/usr/bin/env python3
"""
S13.5A.27 - RESOURCE IMPORT / ITEM FIELD / FILTER VENEER CALLER AUDIT

STRICTLY OFFLINE / READ-ONLY.

A.26 established:
  - caller 0x10362A14 passes filtered-B709 selector1[] exactly to 0x103647C4.
  - 0x103647C4 per item:
        a = 0x1031DA2C(selector1[i])
        b = 0x10321B40(parallel[i])
        0x10316834(i, b, a)
  - 0x10316834 stores:
        item[i].field_08 = a
        item[i].field_10 = b
    in 0x20-byte records rooted through F004C5AC+8.
  - 0x1036B6E8 converts selector5[index] with 0x1031DA2C and writes F009603C.
  - F02D4D10(id) SETs the filter bit.
  - F02D5828(id) CLEARs the filter bit.
  - ALICE import words:
        0x102FD050 = F02D4D11 (SET)
        0x102FD058 = F02D5829 (CLEAR)
  - A.26's "direct callers = 0" for several helpers is a scanner false-negative:
    explicit BL/BLX sites exist in the same report.

Goals:
  1. Resolve ARM veneers:
       0x102FCF84  -> helper used by 0x1031DA2C
       0x102FD524  -> helper used by 0x10321B40
       0x102FD050  -> SET_FILTER_BIT
       0x102FD058  -> CLEAR_FILTER_BIT
  2. Use a robust every-halfword callsite scan (not whole-image linear decode)
     to recover real BL/BLX callers of all four veneers and of:
       0x1031DA2C, 0x10321B40, 0x10316834.
  3. Classify 0x1031DA2C output by caller behavior:
       byte dereference / string-like use / pointer stores.
  4. Classify 0x10321B40 output by caller behavior:
       halfword dereference / image-like or other resource use.
  5. Recover F004C5AC item-array readers and specifically field +0x08/+0x10
     consumers after 0x20-byte index scaling.
  6. Recover all SET/CLEAR veneer callers and r0 provenance; highlight
     B709-family/Image/Audio IDs and dynamic registry-derived IDs.
  7. Determine whether filter mutation can close RAW vs FILTERED B709 alignment.

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
from collections import Counter, defaultdict

from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_THUMB, CS_MODE_LITTLE_ENDIAN
from capstone.arm import ARM_OP_IMM, ARM_OP_MEM, ARM_OP_REG, ARM_REG_PC

ALICE_BASE = 0x1024EC00
ALICE_SIZE = 0x157BB4
ALICE_SHA256 = "7246242b67afae0d13104452bc3257827cb778119b54e7a26fb7fb55993697ea"

ZIMAGE_BASE = 0xF023CA50
ZIMAGE_SIZE = 0x185E98
ZIMAGE_SHA256 = "85fba8c8ae8161e4c1f8ced7983ec30d48c54ab10e51c69fcdfb900aca220954"

# A.26 helper paths
HELPER_TEXTLIKE = 0x1031DA2C
HELPER_PARALLEL = 0x10321B40
ITEM_INSERT = 0x10316834

# Import veneers used by those helpers
VENEER_A = 0x102FCF84
VENEER_B = 0x102FD524

# Exact bitmap set/clear veneers
VENEER_FILTER_SET = 0x102FD050
VENEER_FILTER_CLEAR = 0x102FD058
TARGET_FILTER_SET = 0xF02D4D10
TARGET_FILTER_CLEAR = 0xF02D5828

# Item backing object
ITEM_STORE_GLOBAL = 0xF004C5AC
ITEM_STRIDE = 0x20
ITEM_FIELD_A = 0x08
ITEM_FIELD_B = 0x10

# Selected selector5 converted slot
PLATFORM_BASE = 0xF0096018
SELECTED_RESOURCE_SLOT = 0xF009603C

KNOWN_IDS = {
    0x8313: "IMAGE_A",
    0x8321: "IMAGE_B",
    0x8928: "AUDIO",
    0xB709: "ROOT_B709",
    0xB6FD: "B709_FAMILY",
    0xB6FE: "B709_FAMILY",
    0xB6FF: "B709_FAMILY",
    0xB700: "B709_FAMILY",
    0xB701: "B709_FAMILY",
    0xB702: "B709_FAMILY",
    0xB703: "B709_FAMILY",
    0xB704: "B709_FAMILY",
    0xB705: "B709_FAMILY",
    0xB707: "B709_FAMILY",
    0xB708: "B709_FAMILY",
    0xB70B: "SEL1(B6FD)",
    0xB71B: "SEL5(B6FD)",
    0xB73B: "SEL8(B6FD)",
    0xB709: "ROOT_B709/SEL1(B701,B707)",
    0xB719: "SEL5(B701,B707)",
    0xB739: "SEL8(B701,B707)",
    0xB74A: "SEL1(IMAGE_B)",
    0xB747: "SEL5(IMAGE_B)",
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

    def contains(self, addr: int):
        a = addr & ~1
        return self.base <= a < self.end

    def off(self, addr: int):
        return (addr & ~1) - self.base


def banner(s):
    print()
    print("=" * 170)
    print(s)
    print("=" * 170)


def sha256(b):
    return hashlib.sha256(b).hexdigest()


def u16(data, off):
    if off < 0 or off + 2 > len(data):
        return None
    return struct.unpack_from("<H", data, off)[0]


def u32(data, off):
    if off < 0 or off + 4 > len(data):
        return None
    return struct.unpack_from("<I", data, off)[0]


def verify(path: Path, name, base, size, expected_sha):
    if not path.is_file():
        raise SystemExit(f"ABORT: missing canonical {name}: {path}")
    b = path.read_bytes()
    got = sha256(b)
    print(f"{name} = {path}")
    print(f"  runtime base = 0x{base:08X}")
    print(f"  size         = 0x{len(b):X}")
    print(f"  sha256       = {got}")
    if len(b) != size:
        raise SystemExit(f"ABORT: {name} size mismatch")
    if got.lower() != expected_sha.lower():
        raise SystemExit(f"ABORT: {name} SHA256 mismatch")
    print(f"[PASS] canonical {name}")
    return Image(name, b, base)


def decode1(img: Image, addr: int, mode="THUMB"):
    if mode == "THUMB":
        a = addr & ~1
        align = 2
        md = md_t
    else:
        a = addr & ~3
        align = 4
        md = md_a
    if not img.contains(a):
        return None
    off = img.off(a)
    xs = list(md.disasm(img.data[off:off + 4], a, count=1))
    return xs[0] if xs else None


def dis(img: Image, start: int, end: int, mode="THUMB"):
    if mode == "THUMB":
        start &= ~1
        md = md_t
    else:
        start &= ~3
        md = md_a
    end = min(end, img.end)
    if start < img.base or start >= end:
        return []
    return [x for x in md.disasm(img.data[img.off(start):img.off(end)], start) if x.address < end]


def fmt(x):
    return f"0x{x.address:08X}: {x.bytes.hex(' '):<16} {x.mnemonic:<10} {x.op_str}"


def direct_target(x):
    if not x or x.mnemonic not in {"b", "bl", "blx"} or not x.operands:
        return None
    op = x.operands[0]
    return (op.imm & 0xFFFFFFFF) if op.type == ARM_OP_IMM else None


def literal_load(img: Image, x, mode="THUMB"):
    if not x or not x.mnemonic.startswith("ldr") or len(x.operands) < 2:
        return None
    d, s = x.operands[0], x.operands[1]
    if d.type != ARM_OP_REG or s.type != ARM_OP_MEM or s.mem.base != ARM_REG_PC:
        return None
    pc = ((x.address + 4) & ~3) if mode == "THUMB" else x.address + 8
    la = (pc + s.mem.disp) & 0xFFFFFFFF
    if not img.contains(la):
        return None
    return x.reg_name(d.reg), d.reg, la, u32(img.data, img.off(la))


def print_region(img, start, end, mode="THUMB", marks=None):
    marks = marks or set()
    for x in dis(img, start, end, mode):
        notes = []
        t = direct_target(x)
        if t is not None:
            notes.append(f"target=0x{t:08X}")
        li = literal_load(img, x, mode)
        if li:
            tags = []
            if li[3] in KNOWN_IDS:
                tags.append(KNOWN_IDS[li[3]])
            if li[3] == ITEM_STORE_GLOBAL:
                tags.append("ITEM_STORE_GLOBAL")
            if li[3] == PLATFORM_BASE:
                tags.append("PLATFORM_BASE")
            notes.append(
                f"literal@0x{li[2]:08X}=0x{li[3]:08X}->{li[0]}"
                + (f"<{'|'.join(tags)}>" if tags else "")
            )
        print((">>> " if x.address in marks else "    ") + fmt(x) + ((" ; " + ", ".join(notes)) if notes else ""))


def resolve_arm_veneer(alice: Image, addr: int):
    x = decode1(alice, addr, "ARM")
    if not x:
        return None
    target_ptr = u32(alice.data, alice.off(addr + 4))
    recognized = (
        x.mnemonic == "ldr"
        and len(x.operands) >= 2
        and x.operands[0].type == ARM_OP_REG
        and x.reg_name(x.operands[0].reg) == "pc"
        and x.operands[1].type == ARM_OP_MEM
        and x.operands[1].mem.base == ARM_REG_PC
    )
    return {
        "insn": x,
        "recognized": recognized,
        "literal_addr": addr + 4,
        "target_ptr": target_ptr,
        "target": (target_ptr & ~1) if target_ptr is not None else None,
        "mode": "THUMB" if (target_ptr or 0) & 1 else "ARM",
    }


_CALL_INDEX_CACHE = {}

def build_call_index(img: Image, modes=("THUMB",)):
    """
    Decode independently at every aligned address ONCE and index all direct BL/BLX
    by target. This keeps A.27 robust against embedded data while avoiding repeated
    full-image scans for each target.
    """
    key = (img.name, img.base, len(img.data), tuple(modes))
    if key in _CALL_INDEX_CACHE:
        return _CALL_INDEX_CACHE[key]

    idx = defaultdict(list)

    if "THUMB" in modes:
        for a in range(img.base & ~1, img.end - 3, 2):
            x = decode1(img, a, "THUMB")
            if not x or x.mnemonic not in {"bl", "blx"}:
                continue
            t = direct_target(x)
            if t is not None:
                idx[t & ~1].append(("THUMB", x))

    if "ARM" in modes:
        start = (img.base + 3) & ~3
        for a in range(start, img.end - 3, 4):
            x = decode1(img, a, "ARM")
            if not x or x.mnemonic not in {"bl", "blx"}:
                continue
            t = direct_target(x)
            if t is not None:
                idx[t & ~1].append(("ARM", x))

    # de-duplicate each target bucket
    for t, rows in list(idx.items()):
        seen = set()
        uniq = []
        for mode, x in rows:
            k = (mode, x.address)
            if k not in seen:
                seen.add(k)
                uniq.append((mode, x))
        idx[t] = uniq

    _CALL_INDEX_CACHE[key] = idx
    return idx


def robust_callers(img: Image, target: int, modes=("THUMB",)):
    return build_call_index(img, modes).get(target & ~1, [])


def nearest_thumb_push(img, addr, max_back=0x100):
    best = None
    lo = max(img.base, addr - max_back) & ~1
    for a in range(lo, addr + 1, 2):
        x = decode1(img, a, "THUMB")
        if x and x.mnemonic == "push" and "lr" in x.op_str:
            best = a
    return best


def conservative_reg_provenance(img: Image, addr: int, reg_name="r0", max_back=0x70):
    """
    Conservative local backwards-ish forward simulation within a nearby push-delimited window.
    Tracks literals/immediates/simple aliases/arithmetic for low registers.
    """
    start = nearest_thumb_push(img, addr, max_back) or max(img.base, addr - max_back)
    xs = dis(img, start, addr, "THUMB")
    vals = {}

    for x in xs:
        li = literal_load(img, x, "THUMB")
        if li:
            vals[li[0]] = ("CONST", li[3], f"literal@0x{li[2]:08X}")
            continue

        ops = x.operands
        if len(ops) >= 2 and ops[0].type == ARM_OP_REG:
            dst = x.reg_name(ops[0].reg)

            if x.mnemonic in {"mov", "movs"}:
                if ops[1].type == ARM_OP_IMM:
                    vals[dst] = ("CONST", ops[1].imm & 0xFFFFFFFF, f"{x.mnemonic}@0x{x.address:08X}")
                elif ops[1].type == ARM_OP_REG:
                    src = x.reg_name(ops[1].reg)
                    if src in vals:
                        vals[dst] = vals[src]
                    else:
                        vals[dst] = ("ALIAS_UNKNOWN", src, f"@0x{x.address:08X}")

            elif x.mnemonic in {"add", "adds", "sub", "subs"}:
                sign = 1 if x.mnemonic.startswith("add") else -1
                if len(ops) == 2 and ops[1].type == ARM_OP_IMM and dst in vals and vals[dst][0] == "CONST":
                    vals[dst] = ("CONST", (vals[dst][1] + sign * ops[1].imm) & 0xFFFFFFFF, f"arith@0x{x.address:08X}")
                elif len(ops) >= 3 and ops[1].type == ARM_OP_REG and ops[2].type == ARM_OP_IMM:
                    src = x.reg_name(ops[1].reg)
                    if src in vals and vals[src][0] == "CONST":
                        vals[dst] = ("CONST", (vals[src][1] + sign * ops[2].imm) & 0xFFFFFFFF, f"arith@0x{x.address:08X}")
                    else:
                        vals[dst] = ("EXPR", x.op_str, f"@0x{x.address:08X}")

            elif x.mnemonic.startswith("ldr") and len(ops) >= 2 and ops[1].type == ARM_OP_MEM:
                base = x.reg_name(ops[1].mem.base) if ops[1].mem.base else "?"
                vals[dst] = ("MEM", f"[{base}{ops[1].mem.disp:+#x}]", f"@0x{x.address:08X}")

        if x.mnemonic in {"bl", "blx"}:
            # Conservative caller-saved clobber.
            for r in ("r0", "r1", "r2", "r3", "r12"):
                vals.pop(r, None)

    return start, vals.get(reg_name, ("UNKNOWN", None, ""))


def post_call_uses(img: Image, call_addr: int, max_bytes=0x28):
    xs = dis(img, call_addr + 4, min(img.end, call_addr + 4 + max_bytes), "THUMB")
    out = []
    for x in xs:
        # Stop at next real call after collecting a few simple uses.
        if x.mnemonic in {"bl", "blx"}:
            out.append(("CALL", x, None))
            break

        # Uses of r0 return value.
        used_r0 = False
        mem_r0 = False
        mem_width = None
        for op in x.operands:
            if op.type == ARM_OP_REG and x.reg_name(op.reg) == "r0":
                used_r0 = True
            elif op.type == ARM_OP_MEM:
                b = x.reg_name(op.mem.base) if op.mem.base else ""
                i = x.reg_name(op.mem.index) if op.mem.index else ""
                if b == "r0" or i == "r0":
                    used_r0 = True
                    mem_r0 = True

        if used_r0:
            if x.mnemonic.startswith("ldrb") or x.mnemonic.startswith("strb"):
                mem_width = 1
            elif x.mnemonic.startswith("ldrh") or x.mnemonic.startswith("strh"):
                mem_width = 2
            elif x.mnemonic.startswith("ldr") or x.mnemonic.startswith("str"):
                mem_width = 4
            out.append(("USE", x, (mem_r0, mem_width)))

        # Alias from r0
        if (
            x.mnemonic in {"mov", "movs"}
            and len(x.operands) >= 2
            and x.operands[1].type == ARM_OP_REG
            and x.reg_name(x.operands[1].reg) == "r0"
        ):
            out.append(("ALIAS", x, x.reg_name(x.operands[0].reg)))
    return out


def raw_word_locations(img: Image, value: int):
    needle = struct.pack("<I", value & 0xFFFFFFFF)
    out = []
    pos = 0
    while True:
        pos = img.data.find(needle, pos)
        if pos < 0:
            break
        out.append(img.base + pos)
        pos += 1
    return out


def real_literal_refs_to_word(img: Image, word_addr: int, value: int):
    out = []
    lo = max(img.base, word_addr - 0x1000) & ~1
    hi = min(img.end, word_addr + 4)
    for a in range(lo, hi, 2):
        x = decode1(img, a, "THUMB")
        li = literal_load(img, x, "THUMB") if x else None
        if li and li[2] == word_addr and li[3] == value:
            out.append(("THUMB", x, li))
    lo = max(img.base, word_addr - 0x2000)
    lo = (lo + 3) & ~3
    for a in range(lo, hi, 4):
        x = decode1(img, a, "ARM")
        li = literal_load(img, x, "ARM") if x else None
        if li and li[2] == word_addr and li[3] == value:
            out.append(("ARM", x, li))
    seen = set()
    uniq = []
    for m, x, li in out:
        k = (m, x.address)
        if k not in seen:
            seen.add(k)
            uniq.append((m, x, li))
    return uniq


def print_veneer_and_target(alice, zimage, veneer, label):
    print()
    print(f"### {label} @0x{veneer:08X}")
    vr = resolve_arm_veneer(alice, veneer)
    if not vr:
        print("decode = FAIL")
        return None

    print(f"ARM instruction = {fmt(vr['insn'])}")
    print(f"recognized      = {vr['recognized']}")
    print(f"literal         = 0x{vr['literal_addr']:08X}")
    print(f"target_ptr      = 0x{vr['target_ptr']:08X}")
    print(f"target          = 0x{vr['target']:08X}")
    print(f"target mode     = {vr['mode']}")

    owner = alice if alice.contains(vr["target"]) else zimage if zimage.contains(vr["target"]) else None
    print(f"target owner    = {owner.name if owner else 'OUTSIDE_CANONICAL_IMAGES'}")

    if owner:
        if vr["mode"] == "THUMB":
            start = vr["target"]
            print_region(owner, start, min(owner.end, start + 0x100), "THUMB", marks={start})
        else:
            start = vr["target"]
            print_region(owner, start, min(owner.end, start + 0x100), "ARM", marks={start})
    return vr


def section_veneer_resolution(alice, zimage):
    banner("B. IMPORT VENEER RESOLUTION")
    results = {}
    for addr, label in [
        (VENEER_A, "RESOURCE_IMPORT_A (used by 1031DA2C)"),
        (VENEER_B, "RESOURCE_IMPORT_B (used by 10321B40)"),
        (VENEER_FILTER_SET, "SET_FILTER_BIT import"),
        (VENEER_FILTER_CLEAR, "CLEAR_FILTER_BIT import"),
    ]:
        results[addr] = print_veneer_and_target(alice, zimage, addr, label)
    return results


def section_robust_callers(alice):
    banner("C. ROBUST EVERY-HALFWORD CALLER RECOVERY")

    targets = [
        (HELPER_TEXTLIKE, "HELPER_A 1031DA2C"),
        (HELPER_PARALLEL, "HELPER_B 10321B40"),
        (ITEM_INSERT, "ITEM_INSERT 10316834"),
        (VENEER_A, "VENEER_A 102FCF84"),
        (VENEER_B, "VENEER_B 102FD524"),
        (VENEER_FILTER_SET, "FILTER_SET_VENEER 102FD050"),
        (VENEER_FILTER_CLEAR, "FILTER_CLEAR_VENEER 102FD058"),
    ]

    all_results = {}
    for target, label in targets:
        calls = robust_callers(alice, target, ("THUMB",))
        all_results[target] = calls
        print()
        print(f"### {label}")
        print(f"robust Thumb callers = {len(calls)}")

        consts = Counter()
        for mode, c in calls:
            st, prov = conservative_reg_provenance(alice, c.address, "r0", 0x80)
            if prov[0] == "CONST":
                consts[prov[1] & 0xFFFFFFFF] += 1

        if consts:
            print("r0 constant census:")
            for v, n in consts.most_common():
                tag = KNOWN_IDS.get(v & 0xFFFF, "")
                print(f"  0x{v:08X} x{n}" + (f" <{tag}>" if tag else ""))

        for mode, c in calls[:120]:
            st, prov = conservative_reg_provenance(alice, c.address, "r0", 0x80)
            ptxt = f"{prov[0]}:{prov[1]}" if prov[1] is not None else prov[0]
            if prov[0] == "CONST":
                tag = KNOWN_IDS.get(prov[1] & 0xFFFF, "")
                ptxt = f"CONST 0x{prov[1]:08X}" + (f" <{tag}>" if tag else "")
            print(f"  {fmt(c)} function≈0x{st:08X} r0={ptxt}")
    return all_results


def section_resource_semantics(alice):
    banner("D. RESOURCE HELPER RETURN-USE SEMANTICS")

    for target, label in [
        (VENEER_A, "RESOURCE_IMPORT_A / return consumed by HELPER_A"),
        (VENEER_B, "RESOURCE_IMPORT_B / return consumed by HELPER_B"),
        (HELPER_TEXTLIKE, "HELPER_A 1031DA2C"),
        (HELPER_PARALLEL, "HELPER_B 10321B40"),
    ]:
        calls = robust_callers(alice, target, ("THUMB",))
        byte_deref = 0
        half_deref = 0
        word_deref = 0
        print()
        print(f"### {label}")
        print(f"callers={len(calls)}")

        for mode, c in calls[:160]:
            uses = post_call_uses(alice, c.address)
            tags = []
            for kind, x, meta in uses:
                if kind == "USE" and meta:
                    mem_r0, width = meta
                    if mem_r0 and width == 1:
                        byte_deref += 1
                        tags.append("BYTE_DEREF")
                    elif mem_r0 and width == 2:
                        half_deref += 1
                        tags.append("HALFWORD_DEREF")
                    elif mem_r0 and width == 4:
                        word_deref += 1
                        tags.append("WORD_DEREF")
                if kind == "ALIAS":
                    tags.append(f"ALIAS->{meta}")
            if tags:
                print(f"  {fmt(c)} => {','.join(sorted(set(tags)))}")
                for kind, x, meta in uses[:6]:
                    print("      " + fmt(x))

        print(f"byte-pointer deref evidence     = {byte_deref}")
        print(f"halfword-pointer deref evidence = {half_deref}")
        print(f"word-pointer deref evidence     = {word_deref}")

    print()
    print("Promotion rule:")
    print("  - byte pointer + explicit non-empty byte check supports C-string/text-like resource.")
    print("  - halfword pointer alone is NOT enough to call the resource an icon/image.")
    print("  - exact UI field consumers below must agree before semantic naming.")


def section_item_store(alice):
    banner("E. F004C5AC 0x20-BYTE ITEM RECORD FIELD +08/+10 CONSUMERS")

    words = raw_word_locations(alice, ITEM_STORE_GLOBAL)
    print(f"raw words for 0x{ITEM_STORE_GLOBAL:08X} = {len(words)}")
    refs = []
    for wa in words:
        rr = real_literal_refs_to_word(alice, wa, ITEM_STORE_GLOBAL)
        for r in rr:
            refs.append((wa,) + r)

    print(f"real literal refs = {len(refs)}")
    for wa, mode, x, li in refs:
        print()
        print(f"{mode} ref {fmt(x)} word@0x{wa:08X}")
        if mode == "THUMB":
            start = nearest_thumb_push(alice, x.address, 0x120) or max(alice.base, x.address - 0x60)
            end = min(alice.end, x.address + 0x140)
            print_region(alice, start, end, "THUMB", marks={x.address})

    # General pattern census: scale-by-5 (x32) and loads at +8/+10 nearby.
    print()
    print("### Generic x32 item-index + field-read pattern census")
    hits = []
    for a in range(alice.base & ~1, alice.end - 3, 2):
        x = decode1(alice, a, "THUMB")
        if not x:
            continue
        if x.mnemonic not in {"lsls", "lsl"} or len(x.operands) < 3:
            continue
        if x.operands[2].type != ARM_OP_IMM or x.operands[2].imm != 5:
            continue

        window = dis(alice, a, min(alice.end, a + 0x34), "THUMB")
        offs = []
        for y in window:
            if y.mnemonic.startswith("ldr") and len(y.operands) >= 2 and y.operands[1].type == ARM_OP_MEM:
                disp = y.operands[1].mem.disp
                if disp in {ITEM_FIELD_A, ITEM_FIELD_B}:
                    offs.append((disp, y))
        if offs:
            hits.append((x, offs))

    print(f"x32 + (+8/+10) candidate windows = {len(hits)}")
    for x, offs in hits[:100]:
        print(f"  SCALE {fmt(x)}")
        for disp, y in offs:
            print(f"    FIELD +0x{disp:X}: {fmt(y)}")

    print()
    print("[FACT from A.26] ITEM_INSERT writes:")
    print("  entry+0x08 = HELPER_A(selector1)")
    print("  entry+0x10 = HELPER_B(parallel)")
    print("A.27 consumer windows above determine whether these are text/icon/other pointers.")


def section_filter_callers(alice):
    banner("F. FILTER SET/CLEAR VENEER CALLERS + ID PROVENANCE")

    summary = {}

    for veneer, label in [
        (VENEER_FILTER_SET, "SET_FILTER_BIT"),
        (VENEER_FILTER_CLEAR, "CLEAR_FILTER_BIT"),
    ]:
        calls = robust_callers(alice, veneer, ("THUMB",))
        summary[veneer] = calls

        print()
        print(f"### {label} via veneer 0x{veneer:08X}")
        print(f"robust callers = {len(calls)}")

        consts = Counter()
        dynamic = 0
        known_hits = []

        for mode, c in calls:
            st, prov = conservative_reg_provenance(alice, c.address, "r0", 0xA0)
            if prov[0] == "CONST":
                v = prov[1] & 0xFFFFFFFF
                consts[v] += 1
                if (v & 0xFFFF) in KNOWN_IDS:
                    known_hits.append((c, v, st))
            else:
                dynamic += 1

        print(f"constant r0 callers = {sum(consts.values())}")
        print(f"dynamic/unknown      = {dynamic}")
        if consts:
            print("constant IDs/values:")
            for v, n in consts.most_common():
                tag = KNOWN_IDS.get(v & 0xFFFF, "")
                print(f"  0x{v:08X} x{n}" + (f" <{tag}>" if tag else ""))

        if known_hits:
            print("known relevant callsites:")
            for c, v, st in known_hits:
                print(f"  function≈0x{st:08X} {fmt(c)} r0=0x{v:08X} <{KNOWN_IDS.get(v & 0xFFFF,'')}>")
                print_region(alice, max(st, c.address - 0x20), min(alice.end, c.address + 0x20), "THUMB", marks={c.address})

        # Print all local contexts, bounded.
        print("all caller contexts:")
        for mode, c in calls[:100]:
            st, prov = conservative_reg_provenance(alice, c.address, "r0", 0xA0)
            if prov[0] == "CONST":
                p = f"CONST 0x{prov[1]:08X} <{KNOWN_IDS.get(prov[1]&0xFFFF,'')}>"
            else:
                p = f"{prov[0]} {prov[1] if prov[1] is not None else ''}"
            print(f"  function≈0x{st:08X} {fmt(c)} r0={p}")

    print()
    set_consts = set()
    clear_consts = set()
    for veneer, dest in [(VENEER_FILTER_SET, set_consts), (VENEER_FILTER_CLEAR, clear_consts)]:
        for mode, c in summary[veneer]:
            st, prov = conservative_reg_provenance(alice, c.address, "r0", 0xA0)
            if prov[0] == "CONST":
                dest.add(prov[1] & 0xFFFF)

    print("SET constant-ID set  =", " ".join(f"{x:04X}" for x in sorted(set_consts)) or "<none>")
    print("CLEAR constant-ID set=", " ".join(f"{x:04X}" for x in sorted(clear_consts)) or "<none>")
    print("intersection          =", " ".join(f"{x:04X}" for x in sorted(set_consts & clear_consts)) or "<none>")

    relevant = sorted((set_consts | clear_consts) & set(KNOWN_IDS.keys()))
    print("known relevant IDs touched =", " ".join(f"{x:04X}<{KNOWN_IDS[x]}>" for x in relevant) or "<none recovered as constants>")

    return summary


def section_selected_slot(alice):
    banner("G. F009603C SELECTED RESOURCE SLOT READER EXTENSION")

    base_words = raw_word_locations(alice, PLATFORM_BASE)
    print(f"base words 0x{PLATFORM_BASE:08X} = {len(base_words)}")

    events = []
    for wa in base_words:
        refs = real_literal_refs_to_word(alice, wa, PLATFORM_BASE)
        for mode, x, li in refs:
            if mode != "THUMB":
                continue
            window = dis(alice, x.address, min(alice.end, x.address + 0x70), "THUMB")
            base_reg = li[0]
            # Lightweight local alias tracking.
            aliases = {base_reg}
            for y in window[1:]:
                if len(y.operands) >= 2 and y.operands[0].type == ARM_OP_REG:
                    dst = y.reg_name(y.operands[0].reg)
                    if y.mnemonic in {"mov", "movs"} and y.operands[1].type == ARM_OP_REG:
                        src = y.reg_name(y.operands[1].reg)
                        if src in aliases:
                            aliases.add(dst)

                for op in y.operands:
                    if op.type == ARM_OP_MEM:
                        b = y.reg_name(op.mem.base) if op.mem.base else ""
                        if b in aliases and op.mem.disp == 0x24:
                            kind = "READ" if y.mnemonic.startswith("ldr") else "WRITE" if y.mnemonic.startswith("str") else "MEM"
                            events.append((x, y, kind))
                if y.mnemonic in {"bl", "blx"}:
                    # stop before aliases become unreliable
                    break

    print(f"local exact +0x24 events = {len(events)}")
    for seed, y, kind in events:
        print(f"  seed {fmt(seed)}")
        print(f"    {kind} {fmt(y)}")

    print()
    print("A.26 already proved the writer at 0x1036B6FE.")
    print("Any independent reader found here should be followed in the next phase only if")
    print("its downstream UI use is unambiguous.")


def section_decision(veneer_results, caller_results):
    banner("H. DECISION GATE")

    print("A.26 invariants retained:")
    print("  selector1[] -> HELPER_A -> item+0x08")
    print("  parallel[]  -> HELPER_B -> item+0x10")
    print("  selector5[index] -> HELPER_A -> F009603C")
    print("  F02D4D10 = SET_FILTER_BIT(id)")
    print("  F02D5828 = CLEAR_FILTER_BIT(id)")
    print()

    va = veneer_results.get(VENEER_A)
    vb = veneer_results.get(VENEER_B)
    vs = veneer_results.get(VENEER_FILTER_SET)
    vc = veneer_results.get(VENEER_FILTER_CLEAR)

    print(f"RESOURCE_IMPORT_A resolved = {'PASS' if va and va['recognized'] else 'OPEN'}")
    print(f"RESOURCE_IMPORT_B resolved = {'PASS' if vb and vb['recognized'] else 'OPEN'}")
    print(f"FILTER_SET veneer resolved = {'PASS' if vs and vs['recognized'] else 'OPEN'}")
    print(f"FILTER_CLR veneer resolved = {'PASS' if vc and vc['recognized'] else 'OPEN'}")
    print(f"robust callers HELPER_A    = {len(caller_results.get(HELPER_TEXTLIKE, []))}")
    print(f"robust callers HELPER_B    = {len(caller_results.get(HELPER_PARALLEL, []))}")
    print(f"robust callers ITEM_INSERT = {len(caller_results.get(ITEM_INSERT, []))}")
    print(f"robust callers SET veneer  = {len(caller_results.get(VENEER_FILTER_SET, []))}")
    print(f"robust callers CLR veneer  = {len(caller_results.get(VENEER_FILTER_CLEAR, []))}")
    print()

    print("Classification policy:")
    print("  If RESOURCE_IMPORT_A returns a pointer repeatedly treated as byte text and")
    print("  item+0x08 consumers agree, promote selector1/selector5/selector8 family")
    print("  to STRING/LABEL RESOURCE IDs.")
    print("  If RESOURCE_IMPORT_B and item+0x10 consumers identify an image/icon object,")
    print("  promote the parallel array to ICON/IMAGE RESOURCE IDs.")
    print("  Otherwise retain neutral RESOURCE_PTR terminology.")
    print()

    print("Filter alignment policy:")
    print("  If SET/CLEAR callers show initialization/mutation for concrete B709 children,")
    print("  reconstruct their runtime filtered state and test raw-vs-filtered index alignment.")
    print("  Do not assume all-zero bitmap state without evidence.")
    print()
    print("DO NOT PROMOTE:")
    print("  numeric Multimedia ID without Image/FM/Audio ownership.")
    print("  B701/B707 solely from selector-table relations.")
    print("  0x8928 as a B709 direct child unless membership is structurally demonstrated.")
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
    p.add_argument("--report", default="research/f2/work/reports/s13_5a27_resource_import_item_filter_veneer_callers.txt")
    return p.parse_args()


def resolve(root: Path, p: str):
    q = Path(p)
    return q if q.is_absolute() else root / q


def main():
    args = parse_args()
    root = Path.cwd()
    report = resolve(root, args.report)
    report.parent.mkdir(parents=True, exist_ok=True)

    cap = io.StringIO()
    old = sys.stdout
    sys.stdout = Tee(old, cap)

    try:
        banner("S13.5A.27 - RESOURCE IMPORT / ITEM FIELD / FILTER VENEER CALLER AUDIT")
        print("STRICTLY OFFLINE")
        print("PHONE ACCESSED       : NO")
        print("FLASH MODIFIED       : NO")
        print("PATCH GENERATED      : NO")
        print("REPACK               : NO")

        banner("A. CANONICAL INPUTS")
        alice = verify(resolve(root, args.alice), "ALICE", ALICE_BASE, ALICE_SIZE, ALICE_SHA256)
        zimage = verify(resolve(root, args.zimage), "ZIMAGE", ZIMAGE_BASE, ZIMAGE_SIZE, ZIMAGE_SHA256)

        veneers = section_veneer_resolution(alice, zimage)
        callers = section_robust_callers(alice)
        section_resource_semantics(alice)
        section_item_store(alice)
        section_filter_callers(alice)
        section_selected_slot(alice)
        section_decision(veneers, callers)

        print()
        print(f"REPORT = {report}")
        return 0
    finally:
        sys.stdout = old
        report.write_text(cap.getvalue(), encoding="utf-8")


if __name__ == "__main__":
    raise SystemExit(main())
