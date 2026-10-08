#!/usr/bin/env python3
"""
S13.5A.9 - SELECTED CHILD PROVENANCE / ENTER-SUBMENU TRANSITION AUDIT

STRICTLY OFFLINE / READ-ONLY.

S13.5A.8 established an exact same-object navigation transition:

    0x10387DB4  ldrh r1,[r0,#0x14]   ; current parent
    0x10387DB6  strh r1,[r0,#0x16]   ; save previous parent
    0x10387DB8  ldrh r1,[r0,#0x18]   ; selected child / next parent
    0x10387DBA  strh r1,[r0,#0x14]   ; enter child
    ...
    0x10387DD4  bl 0x10347432
        -> helper 0x102FD0F4
        -> 0x10340ADC
        -> 0x10343050
        -> ENUM_CHILD_IDS / GET_CHILD_COUNT

This makes +0x18 a proven "selected child / next parent" field on this exact
generic-navigation descriptor path.

The active question is now:
    WHO PRODUCES descriptor+0x18 before the enter-submenu transition?

Primary target:
    0x10342FC4..0x10343038
where A.7/A.8 observed:
    helper 0x102FD0F4 -> descriptor
    r4 = descriptor
    call @0x10342FD8 -> r0
    0x10342FDC strh r0,[r4,#0x18]

This pass:
  1) validates canonical ALICE;
  2) re-proves the exact enter transition and its ownership refs;
  3) resolves the producer call immediately before 0x10342FDC;
  4) audits producer callers / function-pointer refs / argument flow;
  5) audits the secondary +0x18 setter at 0x1034318A;
  6) performs a bounded descriptor-aware scan in 0x10340000..0x10346000 only;
  7) looks for child-array/index -> +0x18 dataflow patterns on the same object;
  8) emits a decision gate only. No patch is generated.

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

HELPER = 0x102FD0F4
CONSUMER = 0x10340ADC
GENERIC_BUILDER = 0x10343050

ENTER_FUNC = 0x10387D94
ENTER_FUNC_THUMB = ENTER_FUNC | 1
ENTER_COPY_LOAD = 0x10387DB8
ENTER_COPY_STORE = 0x10387DBA
ENTER_REBUILD_CALL = 0x10387DD4

WRAPPER_B = 0x10347432

PRIMARY_FUNC = 0x10342FC4
PRIMARY_HELPER_CALL = 0x10342FD0
PRIMARY_ALIAS = 0x10342FD4
PRIMARY_PRODUCER_CALL = 0x10342FD8
PRIMARY_SELECTED_STORE = 0x10342FDC

SECONDARY_FUNC = 0x1034310C
SECONDARY_SELECTED_STORE = 0x1034318A

CLUSTER_START = 0x10340000
CLUSTER_END = 0x10346000

OFF_PARENT = 0x14
OFF_PREV_PARENT = 0x16
OFF_SELECTED = 0x18
OFF_DEPTH = 0x1A
OFF_CHILDREN = 0x40
OFF_AUX = 0x44
OFF_COUNT = 0x48

KNOWN_IDS = {
    0x8313: "IMAGE_A",
    0x8321: "IMAGE_B",
    0x8928: "AUDIO",
    0x346C: "FIXED_PARENT_346C",
    0x3473: "FIXED_CHILD_3473",
    0xB0EC: "B0EC_PARENT",
}

FIELD_NAMES = {
    OFF_PARENT: "CURRENT_PARENT",
    OFF_PREV_PARENT: "PREVIOUS_PARENT",
    OFF_SELECTED: "SELECTED_CHILD",
    OFF_DEPTH: "DEPTH_OR_CURSOR",
    OFF_CHILDREN: "CHILDREN_PTR",
    OFF_AUX: "AUX_44",
    OFF_COUNT: "CHILD_COUNT",
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
    print("=" * 128)
    print(s)
    print("=" * 128)


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
        raise SystemExit(f"ABORT: canonical ALICE missing: {path}")
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


def decode1(img: Image, addr: int, mode: str = "THUMB"):
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


def is_prologue(x):
    return bool(x and x.mnemonic == "push" and "lr" in x.op_str)


def is_return(x):
    return bool(
        x and (
            (x.mnemonic == "pop" and "pc" in x.op_str)
            or (x.mnemonic == "bx" and x.op_str.strip() == "lr")
        )
    )


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
    return d.reg, la, u32(img.data, img.off(la))


def field_notes(x):
    notes = []
    for op in x.operands:
        if op.type == ARM_OP_MEM and op.mem.disp in FIELD_NAMES:
            notes.append(f"{FIELD_NAMES[op.mem.disp]} via {x.reg_name(op.mem.base)}+0x{op.mem.disp:X}")
    return notes


def print_region(img: Image, start: int, end: int, marks=None):
    marks = marks or set()
    for x in dis_thumb(img, start, end):
        tag = ">>>" if x.address in marks else "   "
        notes = field_notes(x)
        t = direct_target(x)
        if t is not None:
            notes.append(f"target=0x{t:08X}")
        print(tag, fmt(x) + ((" ; " + ", ".join(notes)) if notes else ""))


def enclosing_function(img: Image, addr: int, back=0x500, max_len=0x900):
    lo = max(img.base, addr - back) & ~1
    starts = []
    for a in range(lo, addr + 1, 2):
        p = decode1(img, a)
        if not is_prologue(p):
            continue
        xs = dis_thumb(img, a, min(img.end, a + max_len))
        if any(z.address == addr for z in xs):
            starts.append(a)
    if not starts:
        return None, None
    start = starts[-1]
    xs = dis_thumb(img, start, min(img.end, start + max_len))
    for z in xs:
        if z.address >= addr and is_return(z):
            return start, z.address + len(z.bytes)
    return start, min(img.end, start + max_len)


def scan_direct_calls(img: Image, target: int):
    out = []

    # Thumb BL/BLX.
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

    # ARM BL/BLX.
    for off in range(0, len(img.data)-4, 4):
        word = u32(img.data, off)
        if word is None:
            continue
        if not (
            (word & 0x0E000000) == 0x0A000000
            or (word & 0xFE000000) == 0xFA000000
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


def all_hits(data: bytes, needle: bytes):
    out = []
    p = 0
    while True:
        p = data.find(needle, p)
        if p < 0:
            return out
        out.append(p)
        p += 1


def raw_pointer_refs(img: Image, target: int):
    vals = {(target & ~1), (target | 1)}
    hits = []
    for v in vals:
        for off in all_hits(img.data, struct.pack("<I", v & 0xFFFFFFFF)):
            hits.append((img.base + off, v & 0xFFFFFFFF))
    return sorted(set(hits))


def literal_xrefs_to_target(img: Image, target: int):
    """
    Real Thumb PC-relative LDR literal instructions whose literal word equals
    target or target|1.
    """
    wanted = {(target & ~1) & 0xFFFFFFFF, (target | 1) & 0xFFFFFFFF}
    out = []
    for off in range(0, len(img.data)-2, 2):
        a = img.base + off
        x = decode1(img, a)
        if x is None:
            continue
        lit = literal_load(img, x)
        if not lit:
            continue
        reg, la, val = lit
        if val in wanted:
            out.append((x, la, val))
    uniq = {(x.address, la, val): (x, la, val) for x, la, val in out}
    return [uniq[k] for k in sorted(uniq)]


def reg_id_by_name(insns, name: str):
    for x in insns:
        for op in x.operands:
            if op.type == ARM_OP_REG and x.reg_name(op.reg) == name:
                return op.reg
    return None


def written_reg(x):
    if not x.operands:
        return None
    op0 = x.operands[0]
    return op0.reg if op0.type == ARM_OP_REG else None


def backward_source(img: Image, insns, before_addr: int, name: str, depth=0):
    if depth > 10:
        return "UNKNOWN(depth-limit)"
    hist = [x for x in insns if x.address < before_addr]
    rid = reg_id_by_name(hist, name)
    if rid is None:
        return f"UNKNOWN({name} unseen)"

    caller_saved = name in {"r0", "r1", "r2", "r3", "r12", "lr"}

    for i in range(len(hist)-1, -1, -1):
        x = hist[i]

        if x.mnemonic in {"bl", "blx"} and caller_saved:
            return f"UNKNOWN({name} clobbered by call @0x{x.address:08X})"

        if written_reg(x) != rid:
            continue

        lit = literal_load(img, x)
        if lit and lit[0] == rid:
            v = lit[2]
            low = v & 0xFFFF
            lab = f" <{KNOWN_IDS[low]}>" if low in KNOWN_IDS else ""
            return f"CONST 0x{v:08X}{lab} via literal @0x{lit[1]:08X}"

        ops = x.operands
        if x.mnemonic in {"mov", "movs"} and len(ops) >= 2:
            s = ops[1]
            if s.type == ARM_OP_IMM:
                v = s.imm & 0xFFFFFFFF
                low = v & 0xFFFF
                lab = f" <{KNOWN_IDS[low]}>" if low in KNOWN_IDS else ""
                return f"CONST 0x{v:08X}{lab} via {x.mnemonic} @0x{x.address:08X}"
            if s.type == ARM_OP_REG:
                src = x.reg_name(s.reg)
                return (
                    f"{name} <- {src} @0x{x.address:08X} <- "
                    + backward_source(img, hist[:i+1], x.address, src, depth+1)
                )

        if x.mnemonic.startswith("ldr") and len(ops) >= 2 and ops[1].type == ARM_OP_MEM:
            mem = ops[1].mem
            base = x.reg_name(mem.base) if mem.base else "?"
            suffix = f" <{FIELD_NAMES[mem.disp]}>" if mem.disp in FIELD_NAMES else ""
            return f"MEM {x.mnemonic} [{base}{mem.disp:+#x}] @0x{x.address:08X}{suffix}"

        if x.mnemonic in {"add", "adds", "sub", "subs"}:
            return f"EXPR {x.mnemonic} {x.op_str} @0x{x.address:08X}"

        return f"UNKNOWN(writer {x.mnemonic} {x.op_str} @0x{x.address:08X})"

    return f"ARG/INHERITED {name}"


def nearby_known_ids(img: Image, center: int, radius=0x120):
    lo = max(0, img.off(center)-radius)
    hi = min(len(img.data), img.off(center)+radius)
    out = []
    for v, lab in KNOWN_IDS.items():
        pat = struct.pack("<H", v)
        p = img.data.find(pat, lo, hi)
        while p >= 0:
            out.append((img.base+p, v, lab))
            p = img.data.find(pat, p+1, hi)
    return sorted(out)


def print_call_ownership(img: Image, target: int, label: str):
    calls = scan_direct_calls(img, target)
    ptrs = raw_pointer_refs(img, target)
    lx = literal_xrefs_to_target(img, target)

    print(f"{label} = 0x{target:08X}")
    print(f"  direct callers      = {len(calls)}")
    print(f"  raw pointer words   = {len(ptrs)}")
    print(f"  real literal xrefs  = {len(lx)}")

    for mode, x in calls:
        print(f"\n  {mode} caller: {fmt(x)}")
        fs, fe = enclosing_function(img, x.address)
        if fs is not None:
            ins = dis_thumb(img, fs, fe)
            print(f"    function=0x{fs:08X}..0x{fe:08X}")
            for rn in ("r0", "r1", "r2", "r3"):
                print(f"    {rn}: {backward_source(img, ins, x.address, rn)}")
            ids = nearby_known_ids(img, x.address)
            if ids:
                print("    nearby known IDs (supporting only):")
                for a, v, lab in ids[:20]:
                    print(f"      0x{a:08X}: 0x{v:04X} <{lab}>")

    if ptrs:
        print("\n  raw pointer refs:")
        for a, v in ptrs:
            print(f"    0x{a:08X} = 0x{v:08X}")

    if lx:
        print("\n  literal loads of callback pointer:")
        for x, la, val in lx:
            print(f"    {fmt(x)} ; literal@0x{la:08X}=0x{val:08X}")
            fs, fe = enclosing_function(img, x.address)
            if fs is not None:
                print(f"      enclosing=0x{fs:08X}..0x{fe:08X}")

    return calls, ptrs, lx


def helper_aliases_after(img: Image, call_addr: int, max_bytes=0x70):
    """
    Track helper-return aliases forward over a small local window.
    r0 is the helper return. Calls kill r0-r3 aliases but preserve r4-r11.
    """
    aliases = {"r0"}
    events = []
    xs = dis_thumb(img, call_addr+4, min(img.end, call_addr+4+max_bytes))

    for x in xs:
        if is_return(x):
            break

        # alias propagation
        if x.mnemonic in {"mov", "movs"} and len(x.operands) >= 2:
            d, s = x.operands[0], x.operands[1]
            if d.type == ARM_OP_REG and s.type == ARM_OP_REG:
                dn = x.reg_name(d.reg)
                sn = x.reg_name(s.reg)
                if sn in aliases:
                    aliases.add(dn)
                    events.append(("ALIAS", x, f"{dn} <- {sn}"))

        # accesses through known aliases
        for op in x.operands:
            if op.type != ARM_OP_MEM:
                continue
            bn = x.reg_name(op.mem.base) if op.mem.base else "?"
            if bn not in aliases:
                continue
            d = op.mem.disp
            if d in FIELD_NAMES:
                kind = "WRITE" if x.mnemonic.startswith("str") else "READ"
                events.append((f"{kind}_{FIELD_NAMES[d]}", x, f"[{bn}+0x{d:X}]"))

        # call boundary
        if x.mnemonic in {"bl", "blx"}:
            aliases = {a for a in aliases if a in {"r4","r5","r6","r7","r8","r9","r10","r11"}}

    return aliases, events


def audit_primary_selected_setter(img: Image):
    banner("D. PRIMARY SELECTED-CHILD SETTER 0x10342FC4..0x10343038")
    print_region(
        img,
        PRIMARY_FUNC,
        0x10343038,
        {PRIMARY_HELPER_CALL, PRIMARY_ALIAS, PRIMARY_PRODUCER_CALL, PRIMARY_SELECTED_STORE},
    )

    h = decode1(img, PRIMARY_HELPER_CALL)
    producer = decode1(img, PRIMARY_PRODUCER_CALL)

    ht = direct_target(h)
    pt = direct_target(producer)

    print()
    print(f"helper call @0x{PRIMARY_HELPER_CALL:08X} target = "
          f"{('0x%08X' % ht) if ht is not None else 'UNRESOLVED'}")
    print(f"producer call @0x{PRIMARY_PRODUCER_CALL:08X} target = "
          f"{('0x%08X' % pt) if pt is not None else 'UNRESOLVED'}")

    # Structural proof of descriptor alias.
    alias = decode1(img, PRIMARY_ALIAS)
    store = decode1(img, PRIMARY_SELECTED_STORE)
    print(f"alias instruction = {fmt(alias) if alias else 'UNRESOLVED'}")
    print(f"selected store    = {fmt(store) if store else 'UNRESOLVED'}")

    fs, fe = enclosing_function(img, PRIMARY_PRODUCER_CALL)
    if fs is None:
        fs, fe = PRIMARY_FUNC, 0x10343038
    ins = dis_thumb(img, fs, fe)

    print()
    print("producer arguments immediately before call:")
    for rn in ("r0", "r1", "r2", "r3"):
        print(f"  {rn}: {backward_source(img, ins, PRIMARY_PRODUCER_CALL, rn)}")

    if pt is not None:
        banner("E. PRIMARY PRODUCER OWNERSHIP")
        print_call_ownership(img, pt, "SELECTED_ID_PRODUCER")

        pfs, pfe = enclosing_function(img, pt)
        if pfs is not None:
            print()
            print(f"producer implementation candidate: 0x{pfs:08X}..0x{pfe:08X}")
            print_region(img, pfs, min(pfe, pfs+0x240))
        elif img.contains(pt & ~1):
            print()
            print("producer target has no recovered prologue; bounded target window:")
            print_region(img, pt & ~1, min(img.end, (pt & ~1)+0x120))

    return pt


def audit_secondary_setter(img: Image):
    banner("F. SECONDARY +0x18 SETTER 0x1034310C..0x103431AA")
    print_region(
        img,
        SECONDARY_FUNC,
        0x103431AA,
        {SECONDARY_SELECTED_STORE},
    )

    fs, fe = enclosing_function(img, SECONDARY_SELECTED_STORE)
    if fs is None:
        return

    ins = dis_thumb(img, fs, fe)
    x = decode1(img, SECONDARY_SELECTED_STORE)
    if x and x.operands and x.operands[0].type == ARM_OP_REG:
        rn = x.reg_name(x.operands[0].reg)
        print()
        print(f"value source for +0x18 store: {backward_source(img, ins, x.address, rn)}")

    print()
    print_call_ownership(img, fs, "SECONDARY_SETTER_FUNCTION")


def bounded_cluster_descriptor_scan(img: Image):
    banner("G. BOUNDED DESCRIPTOR-AWARE MENU CLUSTER SCAN")
    print(f"cluster = 0x{CLUSTER_START:08X}..0x{CLUSTER_END:08X}")
    print("Only helper-return objects and known menu fields are reported.")

    helper_calls = []
    for x in dis_thumb(img, CLUSTER_START, CLUSTER_END):
        if x.mnemonic not in {"bl", "blx"}:
            continue
        t = direct_target(x)
        if t is not None and (t & ~1) == (HELPER & ~1):
            helper_calls.append(x)

    print(f"helper calls in cluster = {len(helper_calls)}")

    interesting = []
    for call in helper_calls:
        aliases, events = helper_aliases_after(img, call.address, max_bytes=0x90)
        meaningful = [
            e for e in events
            if any(k in e[0] for k in (
                "CURRENT_PARENT",
                "SELECTED_CHILD",
                "CHILDREN_PTR",
                "CHILD_COUNT",
                "PREVIOUS_PARENT",
            ))
        ]
        if meaningful:
            interesting.append((call, aliases, meaningful))

    print(f"descriptor-field helper sites = {len(interesting)}")

    for call, aliases, events in interesting:
        print()
        print(f"helper call {fmt(call)}")
        fs, fe = enclosing_function(img, call.address)
        if fs is not None:
            print(f"  function=0x{fs:08X}..0x{fe:08X}")
        print(f"  surviving aliases={sorted(aliases)}")
        for kind, ev, desc in events:
            print(f"  {kind:<28} {fmt(ev)} | {desc}")


def find_same_object_childarray_to_selected(img: Image):
    """
    Conservative pattern search inside cluster:
      helper return -> callee-saved descriptor alias Rb
      load children pointer [Rb,#0x40]
      ... load halfword child via that pointer ...
      strh child,[Rb,#0x18]

    This does not pretend to perform full SSA; it prints only compact local
    sequences that have both +0x40 and +0x18 on the same descriptor alias.
    """
    banner("H. SAME-OBJECT CHILD-ARRAY -> SELECTED-CHILD CANDIDATES")

    candidates = []

    # Discover helper calls in the cluster and look forward up to 0x180 bytes.
    for x in dis_thumb(img, CLUSTER_START, CLUSTER_END):
        if x.mnemonic not in {"bl", "blx"}:
            continue
        t = direct_target(x)
        if t is None or (t & ~1) != (HELPER & ~1):
            continue

        xs = dis_thumb(img, x.address+4, min(CLUSTER_END, x.address+0x184))
        aliases = {"r0"}
        childptr_seen = []
        selected_writes = []

        for z in xs:
            if is_return(z):
                break

            if z.mnemonic in {"mov", "movs"} and len(z.operands) >= 2:
                d, s = z.operands[0], z.operands[1]
                if d.type == ARM_OP_REG and s.type == ARM_OP_REG:
                    dn = z.reg_name(d.reg)
                    sn = z.reg_name(s.reg)
                    if sn in aliases:
                        aliases.add(dn)

            for op in z.operands:
                if op.type != ARM_OP_MEM:
                    continue
                bn = z.reg_name(op.mem.base) if op.mem.base else "?"
                if bn not in aliases:
                    continue

                if z.mnemonic.startswith("ldr") and op.mem.disp == OFF_CHILDREN:
                    childptr_seen.append(z)
                if z.mnemonic == "strh" and op.mem.disp == OFF_SELECTED:
                    selected_writes.append(z)

            if z.mnemonic in {"bl", "blx"}:
                aliases = {a for a in aliases if a in {"r4","r5","r6","r7","r8","r9","r10","r11"}}

        if childptr_seen and selected_writes:
            candidates.append((x, childptr_seen, selected_writes))

    print(f"candidate sequences = {len(candidates)}")
    for call, loads, stores in candidates:
        print()
        print(f"helper origin @0x{call.address:08X}")
        print("  +0x40 loads:")
        for z in loads:
            print(f"    {fmt(z)}")
        print("  +0x18 stores:")
        for z in stores:
            print(f"    {fmt(z)}")
        lo = max(CLUSTER_START, call.address-0x10) & ~1
        hi = min(CLUSTER_END, max(st.address for st in stores)+0x20)
        print("  bounded context:")
        print_region(img, lo, hi, {call.address, *(z.address for z in loads), *(z.address for z in stores)})


def parse_args():
    p = argparse.ArgumentParser()
    p.add_argument(
        "--alice",
        default="research/f2/work/extracted/altice_alice/alice-py.bin",
    )
    p.add_argument(
        "--report",
        default="research/f2/work/reports/s13_5a9_selected_child_provenance_transition.txt",
    )
    return p.parse_args()


def resolve_path(root: Path, s: str):
    p = Path(s)
    return p if p.is_absolute() else root / p


def main():
    args = parse_args()
    root = Path.cwd()
    alice_path = resolve_path(root, args.alice)
    report_path = resolve_path(root, args.report)
    report_path.parent.mkdir(parents=True, exist_ok=True)

    capture = io.StringIO()
    old = sys.stdout
    sys.stdout = Tee(old, capture)

    try:
        banner("S13.5A.9 - SELECTED CHILD PROVENANCE / ENTER-SUBMENU TRANSITION AUDIT")
        print("STRICTLY OFFLINE")
        print("PHONE ACCESSED       : NO")
        print("FLASH MODIFIED       : NO")
        print("PATCH GENERATED      : NO")
        print("REPACK               : NO")

        banner("A. CANONICAL INPUT")
        img = validate(alice_path)

        banner("B. EXACT SAME-OBJECT ENTER-SUBMENU TRANSITION")
        print_region(
            img,
            ENTER_FUNC,
            0x10387DDA,
            {ENTER_COPY_LOAD, ENTER_COPY_STORE, ENTER_REBUILD_CALL},
        )

        load = decode1(img, ENTER_COPY_LOAD)
        store = decode1(img, ENTER_COPY_STORE)
        rebuild = decode1(img, ENTER_REBUILD_CALL)

        exact_transition = (
            load is not None
            and store is not None
            and load.mnemonic == "ldrh"
            and store.mnemonic == "strh"
        )

        print()
        print(f"same-object +0x18 -> +0x14 transition shape: {'PASS' if exact_transition else 'FAIL'}")
        print(f"rebuild call target: "
              f"{('0x%08X' % direct_target(rebuild)) if rebuild and direct_target(rebuild) is not None else 'UNRESOLVED'}")

        banner("C. ENTER-SUBMENU HANDLER OWNERSHIP")
        enter_calls, enter_ptrs, enter_lx = print_call_ownership(
            img,
            ENTER_FUNC,
            "ENTER_SUBMENU_HANDLER",
        )

        producer_target = audit_primary_selected_setter(img)
        audit_secondary_setter(img)
        bounded_cluster_descriptor_scan(img)
        find_same_object_childarray_to_selected(img)

        banner("I. DECISION GATE")
        pcall = decode1(img, PRIMARY_PRODUCER_CALL)
        pstore = decode1(img, PRIMARY_SELECTED_STORE)
        primary_shape = (
            direct_target(decode1(img, PRIMARY_HELPER_CALL)) is not None
            and decode1(img, PRIMARY_ALIAS) is not None
            and pcall is not None
            and pstore is not None
            and pstore.mnemonic == "strh"
        )

        print(f"enter +0x18 -> +0x14 same-object transition = {'PASS' if exact_transition else 'FAIL'}")
        print(f"enter handler direct callers               = {len(enter_calls)}")
        print(f"enter handler raw pointer refs              = {len(enter_ptrs)}")
        print(f"enter handler real literal xrefs            = {len(enter_lx)}")
        print(f"primary +0x18 producer shape                = {'PASS' if primary_shape else 'FAIL'}")
        print(f"primary producer target                     = "
              f"{('0x%08X' % producer_target) if producer_target is not None else 'UNRESOLVED'}")
        print()

        if exact_transition and primary_shape and producer_target is not None:
            print("[PASS] Selected-child provenance narrowed to a concrete producer function.")
            print("[NEXT] Use producer arguments/callers and enter-handler ownership to bind")
            print("       a concrete selected ID to the visible 'Multimedia' transition.")
            print("       Once that numeric ID is structurally identified, query its real")
            print("       provider-backed child list and test whether 0x8928 is present.")
        elif exact_transition:
            print("[PASS] Enter-submenu semantics are proven, but selected-child producer")
            print("       is still unresolved. Continue only from same-descriptor setter sites.")
        else:
            print("[ABORT LOGIC] Expected same-object transition did not validate.")
            print("Re-check canonical code boundaries before any further inference.")

        print()
        print("FACT:")
        print("  descriptor+0x14 = current parent on provider-backed menu path")
        print("  descriptor+0x18 = selected child / next parent on 0x10387D94 enter path")
        print("  0x10387DB8 -> 0x10387DBA copies +0x18 to +0x14 on the same object")
        print()
        print("STILL UNKNOWN:")
        print("  numeric ID corresponding to visible Multimedia")
        print("  FM Radio child ID")
        print("  exact Multimedia children[]")
        print("  whether 0x8928 is already present/filtered")
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
