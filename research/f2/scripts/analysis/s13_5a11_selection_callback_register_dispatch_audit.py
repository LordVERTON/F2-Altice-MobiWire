#!/usr/bin/env python3
"""
S13.5A.11 - SELECTION CALLBACK REGISTRATION / DISPATCH AUDIT

STRICTLY OFFLINE / READ-ONLY.

S13.5A.10 proved the following chain:

    0x10315514(index)
        -> validates 0 <= index < descriptor.child_count (+0x48)
        -> returns descriptor.children[index] from +0x40
        -> 0xFFFF when invalid

    0x10342FC4
        -> calls 0x10315514(r0)
        -> stores returned u16 into descriptor+0x18

    0x10387D94
        -> copies descriptor+0x18 to descriptor+0x14
        -> rebuilds the newly entered submenu

The only direct static reference to 0x10342FC4 is:

    0x10340D2C = 0x10342FC5
    0x10340C48 loads that pointer
    0x10340C4A calls 0x10317C58

Therefore the active question is:
    what does 0x10317C58 do with the callback pointer, and what value reaches
    r0 when that callback is eventually invoked?

This audit:
  A. validates canonical ALICE;
  B. dumps the exact 0x10317C58 implementation and one callee level;
  C. inventories all direct callers of 0x10317C58 and the callback pointer
     passed in r0;
  D. proves the 0x10342FC4 registration site;
  E. recovers candidate callback-storage globals/slots touched by 0x10317C58;
  F. searches those slots for readers and indirect BLX dispatch sites;
  G. dumps 0x10340D00..0x10340D40 as RAW WORD DATA (not Thumb code);
  H. re-dumps the two real 0x10387D94 callers for argument semantics;
  I. emits a strict decision gate.

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
from typing import Optional

from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_THUMB, CS_MODE_LITTLE_ENDIAN
from capstone.arm import ARM_OP_IMM, ARM_OP_MEM, ARM_OP_REG, ARM_REG_PC

ALICE_BASE = 0x1024EC00
ALICE_SIZE = 0x157BB4
ALICE_SHA256 = "7246242b67afae0d13104452bc3257827cb778119b54e7a26fb7fb55993697ea"

REGISTER_CB = 0x10317C58
SELECT_CB = 0x10342FC4
SELECT_CB_THUMB = 0x10342FC5

REGISTER_SITE_LOAD = 0x10340C48
REGISTER_SITE_CALL = 0x10340C4A
SELECT_CB_PTR_WORD = 0x10340D2C

ENTER_HANDLER = 0x10387D94
ENTER_CALLER_A = 0x102ED26C
ENTER_CALLER_B = 0x103452AC

CHILD_AT_INDEX = 0x10315514

RAW_TABLE_START = 0x10340D00
RAW_TABLE_END = 0x10340D40

KNOWN_IDS = {
    0x8313: "IMAGE_A",
    0x8321: "IMAGE_B",
    0x8928: "AUDIO",
    0x346C: "FIXED_PARENT_346C",
    0x3473: "FIXED_CHILD_3473",
    0xB0EC: "B0EC_PARENT",
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
    data: bytes
    base: int = ALICE_BASE

    @property
    def end(self):
        return self.base + len(self.data)

    def contains(self, addr: int):
        return self.base <= addr < self.end

    def off(self, addr: int):
        return addr - self.base


def banner(s: str):
    print()
    print("=" * 130)
    print(s)
    print("=" * 130)


def sha256(data: bytes):
    return hashlib.sha256(data).hexdigest()


def u16(data: bytes, off: int):
    if off < 0 or off + 2 > len(data):
        return None
    return struct.unpack_from("<H", data, off)[0]


def u32(data: bytes, off: int):
    if off < 0 or off + 4 > len(data):
        return None
    return struct.unpack_from("<I", data, off)[0]


def validate(path: Path):
    if not path.is_file():
        raise SystemExit(f"ABORT: missing canonical ALICE: {path}")
    data = path.read_bytes()
    h = sha256(data)
    print(f"ALICE = {path}")
    print(f"  size   = 0x{len(data):X}")
    print(f"  sha256 = {h}")
    if len(data) != ALICE_SIZE:
        raise SystemExit("ABORT: canonical ALICE size mismatch")
    if h.lower() != ALICE_SHA256:
        raise SystemExit("ABORT: canonical ALICE SHA256 mismatch")
    print("[PASS] canonical ALICE")
    return Image(data)


def decode1(img: Image, addr: int, mode="THUMB"):
    if not img.contains(addr):
        return None
    md = md_t if mode == "THUMB" else md_a
    xs = list(md.disasm(img.data[img.off(addr):img.off(addr)+4], addr, count=1))
    return xs[0] if xs else None


def dis_thumb(img: Image, start: int, end: int):
    if not img.contains(start):
        return []
    end = min(end, img.end)
    return [
        x for x in md_t.disasm(img.data[img.off(start):img.off(end)], start)
        if x.address < end
    ]


def fmt(x):
    return f"0x{x.address:08X}: {x.bytes.hex(' '):<14} {x.mnemonic:<9} {x.op_str}"


def direct_target(x):
    if x is None or x.mnemonic not in {"b", "bl", "blx"} or not x.operands:
        return None
    op = x.operands[0]
    if op.type == ARM_OP_IMM:
        return op.imm & 0xFFFFFFFF
    return None


def literal_load(img: Image, x):
    if x is None or not x.mnemonic.startswith("ldr") or len(x.operands) < 2:
        return None
    d, s = x.operands[0], x.operands[1]
    if d.type != ARM_OP_REG or s.type != ARM_OP_MEM or s.mem.base != ARM_REG_PC:
        return None
    pc = (x.address + 4) & ~3
    la = (pc + s.mem.disp) & 0xFFFFFFFF
    if not img.contains(la):
        return None
    return x.reg_name(d.reg), la, u32(img.data, img.off(la))


def print_region(img: Image, start: int, end: int, marks=None):
    marks = marks or set()
    for x in dis_thumb(img, start, end):
        tag = ">>>" if x.address in marks else "   "
        notes = []
        t = direct_target(x)
        if t is not None:
            notes.append(f"target=0x{t:08X}")
        lit = literal_load(img, x)
        if lit:
            rn, la, v = lit
            notes.append(f"literal@0x{la:08X}=0x{v:08X}->{rn}")
        if x.mnemonic == "blx" and x.operands and x.operands[0].type == ARM_OP_REG:
            notes.append(f"INDIRECT_CALL via {x.reg_name(x.operands[0].reg)}")
        print(tag, fmt(x) + ((" ; " + ", ".join(notes)) if notes else ""))


def all_hits(data: bytes, needle: bytes):
    out = []
    p = 0
    while True:
        p = data.find(needle, p)
        if p < 0:
            return out
        out.append(p)
        p += 1


def scan_direct_calls(img: Image, target: int):
    out = []

    for off in range(0, len(img.data)-4, 2):
        h1 = u16(img.data, off)
        h2 = u16(img.data, off+2)
        if h1 is None or h2 is None:
            continue
        if (h1 & 0xF800) != 0xF000 or (h2 & 0xC000) != 0xC000:
            continue
        xs = list(md_t.disasm(img.data[off:off+4], img.base+off, count=1))
        if not xs:
            continue
        x = xs[0]
        if x.mnemonic not in {"bl", "blx"}:
            continue
        t = direct_target(x)
        if t is not None and (t & ~1) == (target & ~1):
            out.append(("THUMB", x))

    for off in range(0, len(img.data)-4, 4):
        w = u32(img.data, off)
        if w is None:
            continue
        if not (
            (w & 0x0E000000) == 0x0A000000
            or (w & 0xFE000000) == 0xFA000000
        ):
            continue
        xs = list(md_a.disasm(img.data[off:off+4], img.base+off, count=1))
        if not xs:
            continue
        x = xs[0]
        if x.mnemonic not in {"bl", "blx"}:
            continue
        t = direct_target(x)
        if t is not None and (t & ~1) == (target & ~1):
            out.append(("ARM", x))

    uniq = {(m, x.address): (m, x) for m, x in out}
    return [uniq[k] for k in sorted(uniq, key=lambda q: (q[1], q[0]))]


def raw_pointer_refs(img: Image, target: int):
    vals = {(target & ~1) & 0xFFFFFFFF, (target | 1) & 0xFFFFFFFF}
    hits = []
    for v in vals:
        for off in all_hits(img.data, struct.pack("<I", v)):
            hits.append((img.base+off, v))
    return sorted(set(hits))


def is_prologue(x):
    return bool(x and x.mnemonic == "push" and "lr" in x.op_str)


def enclosing_start(img: Image, addr: int, back=0x500):
    lo = max(img.base, addr-back) & ~1
    starts = []
    for a in range(lo, addr+1, 2):
        x = decode1(img, a)
        if not is_prologue(x):
            continue
        xs = dis_thumb(img, a, min(img.end, a+0x900))
        if any(z.address == addr for z in xs):
            starts.append(a)
    return starts[-1] if starts else None


def reg_written(x):
    if not x.operands:
        return None
    op0 = x.operands[0]
    return op0.reg if op0.type == ARM_OP_REG else None


def reg_id(insns, name):
    for x in insns:
        for op in x.operands:
            if op.type == ARM_OP_REG and x.reg_name(op.reg) == name:
                return op.reg
    return None


def backward_source(img: Image, insns, before_addr: int, name: str, depth=0):
    if depth > 10:
        return "UNKNOWN(depth-limit)"
    hist = [x for x in insns if x.address < before_addr]
    rid = reg_id(hist, name)
    if rid is None:
        return f"UNKNOWN({name} unseen)"

    caller_saved = name in {"r0", "r1", "r2", "r3", "r12", "lr"}

    for i in range(len(hist)-1, -1, -1):
        x = hist[i]

        if x.mnemonic in {"bl", "blx"} and caller_saved:
            return f"UNKNOWN({name} clobbered by call @0x{x.address:08X})"

        if reg_written(x) != rid:
            continue

        lit = literal_load(img, x)
        if lit and lit[0] == name:
            v = lit[2]
            lab = KNOWN_IDS.get(v & 0xFFFF)
            suffix = f" <{lab}>" if lab else ""
            return f"CONST 0x{v:08X}{suffix} via literal @0x{lit[1]:08X}"

        if x.mnemonic in {"mov", "movs"} and len(x.operands) >= 2:
            s = x.operands[1]
            if s.type == ARM_OP_IMM:
                v = s.imm & 0xFFFFFFFF
                lab = KNOWN_IDS.get(v & 0xFFFF)
                suffix = f" <{lab}>" if lab else ""
                return f"CONST 0x{v:08X}{suffix} via {x.mnemonic} @0x{x.address:08X}"
            if s.type == ARM_OP_REG:
                sn = x.reg_name(s.reg)
                return (
                    f"{name} <- {sn} @0x{x.address:08X} <- "
                    + backward_source(img, hist[:i+1], x.address, sn, depth+1)
                )

        if x.mnemonic.startswith("ldr") and len(x.operands) >= 2 and x.operands[1].type == ARM_OP_MEM:
            m = x.operands[1].mem
            bn = x.reg_name(m.base) if m.base else "?"
            return f"MEM {x.mnemonic} [{bn}{m.disp:+#x}] @0x{x.address:08X}"

        if x.mnemonic in {"add", "adds", "sub", "subs", "lsls", "lsrs"}:
            return f"EXPR {x.mnemonic} {x.op_str} @0x{x.address:08X}"

        return f"UNKNOWN(writer {x.mnemonic} {x.op_str} @0x{x.address:08X})"

    return f"ARG/INHERITED {name}"


def scan_real_literal_xrefs_to_word_address(img: Image, word_addr: int):
    out = []
    lo = max(img.base, word_addr - 0x200)
    hi = min(img.end, word_addr + 4)

    for a in range(lo & ~1, hi, 2):
        x = decode1(img, a)
        if x is None:
            continue
        lit = literal_load(img, x)
        if not lit:
            continue
        _, la, v = lit
        if la == word_addr:
            out.append((x, v))
    return out


def scan_real_literal_xrefs_to_value(img: Image, value: int):
    out = []
    raw = all_hits(img.data, struct.pack("<I", value & 0xFFFFFFFF))
    for off in raw:
        la = img.base + off
        lo = max(img.base, la - 0x120)
        for a in range(lo & ~1, la+1, 2):
            x = decode1(img, a)
            if x is None:
                continue
            lit = literal_load(img, x)
            if lit and lit[1] == la and lit[2] == value:
                out.append((x, la))
    uniq = {(x.address, la): (x, la) for x, la in out}
    return [uniq[k] for k in sorted(uniq)]


def classify_ptr(img: Image, v: int):
    p = v & ~1
    if ALICE_BASE <= p < img.end:
        return "ALICE_CODE/DATA"
    if 0xF0000000 <= p <= 0xF0FFFFFF:
        return "F0_REGION"
    if v == 0xFFFFFFFF or v == 0x0000FFFF:
        return "SENTINEL"
    return ""


def symbolic_register_function(img: Image):
    """
    Lightweight symbolic pass over a bounded window from 0x10317C58.
    We only use it to surface obvious callback-pointer stores and constants.
    """
    banner("E. CALLBACK STORAGE / SLOT CANDIDATES INSIDE 0x10317C58")

    xs = dis_thumb(img, REGISTER_CB, REGISTER_CB + 0x90)
    syms = {"r0": ("ARG0_CALLBACK", None)}
    stores = []
    constants = []

    for x in xs:
        # stop at a clear function return after start
        if x.address > REGISTER_CB and (
            (x.mnemonic == "pop" and "pc" in x.op_str)
            or (x.mnemonic == "bx" and x.op_str.strip() == "lr")
        ):
            # include current instruction then stop
            pass

        lit = literal_load(img, x)
        if lit:
            rn, la, val = lit
            syms[rn] = ("CONST", val)
            constants.append((x, la, val))

        if x.mnemonic in {"mov", "movs"} and len(x.operands) >= 2:
            d, s = x.operands[0], x.operands[1]
            if d.type == ARM_OP_REG and s.type == ARM_OP_REG:
                dn = x.reg_name(d.reg)
                sn = x.reg_name(s.reg)
                syms[dn] = syms.get(sn, ("REG", None))

        if x.mnemonic in {"add", "adds", "sub", "subs"} and len(x.operands) >= 2:
            d = x.operands[0]
            if d.type == ARM_OP_REG:
                dn = x.reg_name(d.reg)
                if len(x.operands) == 2 and x.operands[1].type == ARM_OP_IMM:
                    old = syms.get(dn)
                    if old and old[0] == "CONST":
                        delta = x.operands[1].imm
                        val = old[1] + delta if x.mnemonic.startswith("add") else old[1] - delta
                        syms[dn] = ("CONST", val & 0xFFFFFFFF)

        if x.mnemonic.startswith("ldr") and len(x.operands) >= 2:
            d, m = x.operands[0], x.operands[1]
            if d.type == ARM_OP_REG and m.type == ARM_OP_MEM and m.mem.base != ARM_REG_PC:
                dn = x.reg_name(d.reg)
                bn = x.reg_name(m.mem.base) if m.mem.base else "?"
                base = syms.get(bn)
                if base and base[0] == "CONST":
                    syms[dn] = ("MEM_AT", (base[1] + m.mem.disp) & 0xFFFFFFFF)
                else:
                    syms[dn] = ("MEM", None)

        if x.mnemonic.startswith("str") and len(x.operands) >= 2:
            s, m = x.operands[0], x.operands[1]
            if s.type == ARM_OP_REG and m.type == ARM_OP_MEM:
                sn = x.reg_name(s.reg)
                bn = x.reg_name(m.mem.base) if m.mem.base else "?"
                src = syms.get(sn, ("REG", None))
                base = syms.get(bn)
                addr = None
                if base and base[0] == "CONST":
                    addr = (base[1] + m.mem.disp) & 0xFFFFFFFF
                stores.append((x, sn, src, bn, base, addr))

        if x.address > REGISTER_CB and (
            (x.mnemonic == "pop" and "pc" in x.op_str)
            or (x.mnemonic == "bx" and x.op_str.strip() == "lr")
        ):
            break

    print("literal constants in registration function:")
    for x, la, val in constants:
        print(f"  {fmt(x)} | literal@0x{la:08X}=0x{val:08X} {classify_ptr(img,val)}")

    print()
    print("stores in registration function:")
    callback_slots = []
    for x, sn, src, bn, base, addr in stores:
        addr_txt = f"0x{addr:08X}" if addr is not None else "dynamic"
        print(
            f"  {fmt(x)} | src={sn}:{src} base={bn}:{base} "
            f"effective={addr_txt}"
        )
        if src[0] == "ARG0_CALLBACK" and addr is not None:
            callback_slots.append(addr)

    callback_slots = sorted(set(callback_slots))
    if callback_slots:
        print()
        print("[PASS] exact callback slot candidate(s):")
        for a in callback_slots:
            print(f"  0x{a:08X}")
    else:
        print()
        print("[INFO] no exact ARG0->constant-address store recognized by lightweight pass.")
        print("       Use the raw disassembly/callee path below.")

    return callback_slots, constants


def audit_slot_readers(img: Image, slots):
    banner("F. CALLBACK SLOT READERS / DISPATCH CANDIDATES")

    if not slots:
        print("No exact callback slot recovered automatically.")
        return []

    dispatch = []

    for slot in slots:
        print()
        print(f"=== SLOT 0x{slot:08X} ===")
        refs = scan_real_literal_xrefs_to_value(img, slot)
        print(f"real literal xrefs loading slot address = {len(refs)}")

        for x, la in refs:
            fs = enclosing_start(img, x.address)
            print()
            print(f"xref: {fmt(x)} literal@0x{la:08X}")
            if fs is not None:
                lo = max(fs, x.address - 0x30)
                hi = min(img.end, x.address + 0x60)
            else:
                lo = max(img.base, x.address - 0x30)
                hi = min(img.end, x.address + 0x60)
            region = dis_thumb(img, lo, hi)
            print_region(img, lo, hi, {x.address})

            for z in region:
                if z.mnemonic == "blx" and z.operands and z.operands[0].type == ARM_OP_REG:
                    dispatch.append((slot, z, fs))
                    print(f"  [INDIRECT CALL CANDIDATE] {fmt(z)}")

    return dispatch


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument(
        "--alice",
        default="research/f2/work/extracted/altice_alice/alice-py.bin",
    )
    ap.add_argument(
        "--report",
        default="research/f2/work/reports/s13_5a11_selection_callback_register_dispatch.txt",
    )
    args = ap.parse_args()

    root = Path.cwd()
    alice_path = Path(args.alice)
    if not alice_path.is_absolute():
        alice_path = root / alice_path
    report_path = Path(args.report)
    if not report_path.is_absolute():
        report_path = root / report_path
    report_path.parent.mkdir(parents=True, exist_ok=True)

    capture = io.StringIO()
    old = sys.stdout
    sys.stdout = Tee(old, capture)

    try:
        banner("S13.5A.11 - SELECTION CALLBACK REGISTRATION / DISPATCH AUDIT")
        print("STRICTLY OFFLINE")
        print("PHONE ACCESSED       : NO")
        print("FLASH MODIFIED       : NO")
        print("PATCH GENERATED      : NO")
        print("REPACK               : NO")

        banner("A. CANONICAL INPUT")
        img = validate(alice_path)

        banner("B. EXACT 0x10317C58 IMPLEMENTATION")
        print_region(img, REGISTER_CB, REGISTER_CB + 0x90)

        # Follow direct callees one level from the bounded implementation.
        callees = []
        for x in dis_thumb(img, REGISTER_CB, REGISTER_CB + 0x90):
            t = direct_target(x)
            if t is None:
                continue
            if x.mnemonic not in {"bl", "blx"}:
                continue
            if img.contains(t & ~1):
                callees.append(t & ~1)
            if x.address > REGISTER_CB and (
                (x.mnemonic == "pop" and "pc" in x.op_str)
                or (x.mnemonic == "bx" and x.op_str.strip() == "lr")
            ):
                break

        for t in sorted(set(callees)):
            print()
            print(f"--- one-level callee 0x{t:08X} ---")
            print_region(img, t, min(img.end, t + 0x70))

        banner("C. ALL DIRECT CALLERS OF 0x10317C58")
        callers = scan_direct_calls(img, REGISTER_CB)
        print(f"direct callers = {len(callers)}")

        registered = []
        for mode, x in callers:
            print()
            print(f"{mode} {fmt(x)}")
            fs = enclosing_start(img, x.address)
            if fs is None:
                lo = max(img.base, x.address - 0x50)
                hi = min(img.end, x.address + 0x20)
                ins = dis_thumb(img, lo, hi)
            else:
                lo = fs
                hi = min(img.end, fs + 0x700)
                ins = dis_thumb(img, lo, hi)

            src = backward_source(img, ins, x.address, "r0")
            print(f"  r0 callback source: {src}")

            # exact immediate/literal pointer extraction from nearest preceding ldr/mov
            if src.startswith("CONST 0x"):
                try:
                    v = int(src.split()[1], 16)
                    registered.append((x.address, v))
                except Exception:
                    pass

        print()
        print("registered constant pointers recovered:")
        for ca, v in registered:
            marker = ""
            if (v & ~1) == SELECT_CB:
                marker = " <SELECT_CB>"
            print(f"  call@0x{ca:08X}: 0x{v:08X}{marker} {classify_ptr(img,v)}")

        banner("D. EXACT SELECT-CALLBACK REGISTRATION SITE")
        print_region(
            img,
            0x10340C34,
            0x10340C58,
            {REGISTER_SITE_LOAD, REGISTER_SITE_CALL},
        )
        word = u32(img.data, img.off(SELECT_CB_PTR_WORD))
        print()
        print(f"0x{SELECT_CB_PTR_WORD:08X} raw word = 0x{word:08X}")
        print(f"expected Thumb SELECT_CB         = 0x{SELECT_CB_THUMB:08X}")
        print(f"pointer match                    = {'PASS' if word == SELECT_CB_THUMB else 'FAIL'}")

        xrefs = scan_real_literal_xrefs_to_word_address(img, SELECT_CB_PTR_WORD)
        print(f"real PC-literal xrefs to pointer word = {len(xrefs)}")
        for x, val in xrefs:
            print(f"  {fmt(x)} -> word 0x{SELECT_CB_PTR_WORD:08X}=0x{val:08X}")

        callback_slots, constants = symbolic_register_function(img)
        dispatch = audit_slot_readers(img, callback_slots)

        banner("G. RAW WORD DATA 0x10340D00..0x10340D40")
        for a in range(RAW_TABLE_START, RAW_TABLE_END, 4):
            v = u32(img.data, img.off(a))
            tags = []
            if v == SELECT_CB_THUMB:
                tags.append("SELECT_CB_THUMB")
            if v == (0x1034310C | 1):
                tags.append("RESET_CB_THUMB")
            if v == (0x10347432 | 1):
                tags.append("REBUILD_WRAPPER_B_THUMB")
            cp = classify_ptr(img, v)
            if cp:
                tags.append(cp)

            refs = scan_real_literal_xrefs_to_word_address(img, a)
            if refs:
                tags.append(f"LITERAL_XREFS={len(refs)}")

            print(
                f"0x{a:08X}: 0x{v:08X}"
                + (f"  <{'|'.join(tags)}>" if tags else "")
            )
            for x, _ in refs:
                print(f"    <- {fmt(x)}")

        banner("H. ENTER-SUBMENU CALLERS / ARGUMENTS")
        for ca in (ENTER_CALLER_A, ENTER_CALLER_B):
            fs = enclosing_start(img, ca)
            if fs is None:
                print(f"caller 0x{ca:08X}: enclosing function not recovered")
                continue
            ins = dis_thumb(img, fs, min(img.end, fs+0x500))
            print()
            print(f"caller 0x{ca:08X} in function start 0x{fs:08X}")
            print(f"  r0 at ENTER_HANDLER: {backward_source(img, ins, ca, 'r0')}")
            print(f"  r1 at ENTER_HANDLER: {backward_source(img, ins, ca, 'r1')}")
            print_region(
                img,
                max(fs, ca-0x30),
                min(img.end, ca+0x14),
                {ca},
            )

        banner("I. DECISION GATE")
        select_registered = (word == SELECT_CB_THUMB) and any(
            x.address == REGISTER_SITE_LOAD for x, _ in xrefs
        )

        print(f"SELECT_CB raw pointer at 0x10340D2C      = {'PASS' if word == SELECT_CB_THUMB else 'FAIL'}")
        print(f"SELECT_CB registration literal xref       = {'PASS' if select_registered else 'OPEN'}")
        print(f"0x10317C58 direct callers                  = {len(callers)}")
        print(f"exact callback slot candidates             = {len(callback_slots)}")
        print(f"indirect dispatch candidates near slots    = {len(dispatch)}")
        print()

        if callback_slots and dispatch:
            print("[PASS] Registration storage and candidate dispatcher(s) recovered.")
            print("[NEXT] Promote the dispatcher whose loaded callback can equal 0x10342FC5,")
            print("       then trace r0 at its BLX to prove the SELECT_CB argument semantics.")
        elif callback_slots:
            print("[PASS] Callback storage slot recovered.")
            print("[NEXT] Expand only readers of that exact slot until the indirect BLX is found.")
        else:
            print("[NEXT] 0x10317C58 likely delegates registration or stores through an indirection.")
            print("       Use the one-level callee/constants printed above; do not resume broad scanning.")

        print()
        print("INVARIANTS FROM A.10:")
        print("  0x10315514(index) = descriptor.children[index], invalid => 0xFFFF")
        print("  0x10342FC4 stores that child ID to descriptor+0x18")
        print("  0x10387D94 copies descriptor+0x18 -> +0x14 before rebuild")
        print()
        print("STILL UNKNOWN:")
        print("  exact semantic source of r0 passed to 0x10342FC4")
        print("  numeric ID corresponding to visible Multimedia")
        print("  FM Radio child ID")
        print("  exact Multimedia children[]")
        print("  whether 0x8928 is absent vs present-but-filtered")
        print()
        print("PHONE ACCESSED       : NO")
        print("FLASH MODIFIED       : NO")
        print("PATCH GENERATED      : NO")
        print("PHYSICAL CANDIDATE   : NO")
        print("HARDWARE WRITE AUTHORIZED: NO")
        print()
        print(f"REPORT = {report_path}")

        return 0
    finally:
        sys.stdout = old
        report_path.write_text(capture.getvalue(), encoding="utf-8")


if __name__ == "__main__":
    raise SystemExit(main())
