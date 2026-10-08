#!/usr/bin/env python3
"""
S13.5A.10 - CHILD-INDEX -> CHILD-ID / SELECTION CALLBACK AUDIT

STRICTLY OFFLINE / READ-ONLY.

A.9 proved:
  - descriptor+0x14 = current parent on the provider-backed menu path.
  - descriptor+0x18 = selected child / next parent on the 0x10387D94 enter path.
  - 0x10342FC4 stores the return value of 0x10315514 into descriptor+0x18.
  - A.9's function-boundary heuristic stopped at the first POP in 0x10315514,
    but the valid branch at 0x10315528 jumps to 0x1031552E, beyond that POP.

This pass therefore answers only:
  1) What does the complete 0x10315514 function return on the valid path?
  2) Who calls or registers 0x10342FC4, and what value reaches its r0 argument?
  3) How is the real enter-submenu handler 0x10387D94 reached?
  4) What callback table surrounds 0x10340D00 / 0x10340D04?

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
from pathlib import Path

from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_THUMB, CS_MODE_LITTLE_ENDIAN
from capstone.arm import ARM_OP_IMM, ARM_OP_MEM, ARM_OP_REG, ARM_REG_PC

ALICE_BASE = 0x1024EC00
ALICE_SIZE = 0x157BB4
ALICE_SHA256 = "7246242b67afae0d13104452bc3257827cb778119b54e7a26fb7fb55993697ea"

HELPER = 0x102FD0F4
GET_CONTEXT = 0x102FD104

CHILD_AT_INDEX = 0x10315514
CHILD_AT_INDEX_END = 0x10315544

SELECT_CALLBACK = 0x10342FC4
SELECT_CALLBACK_THUMB = SELECT_CALLBACK | 1
SELECT_CALLBACK_END = 0x10343038

RESET_CALLBACK = 0x1034310C
RESET_CALLBACK_THUMB = RESET_CALLBACK | 1

ENTER_HANDLER = 0x10387D94
ENTER_HANDLER_THUMB = ENTER_HANDLER | 1

ENTER_CALLER_A_START = 0x102ED240
ENTER_CALLER_A_END = 0x102ED274
ENTER_CALLER_B_START = 0x10345268
ENTER_CALLER_B_END = 0x103452B4

CONSUMER_START = 0x10340ADC
CONSUMER_TABLE_START = 0x10340CE0
CONSUMER_TABLE_END = 0x10340D24

OFF_SELECTED = 0x18
OFF_CHILDREN = 0x40
OFF_COUNT = 0x48

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


class Image:
    def __init__(self, data: bytes, base: int = ALICE_BASE):
        self.data = data
        self.base = base
        self.end = base + len(data)
    def contains(self, addr):
        return self.base <= addr < self.end
    def off(self, addr):
        return addr - self.base


def banner(s):
    print()
    print("=" * 128)
    print(s)
    print("=" * 128)


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def u16(data, off):
    if off < 0 or off + 2 > len(data):
        return None
    return struct.unpack_from("<H", data, off)[0]


def u32(data, off):
    if off < 0 or off + 4 > len(data):
        return None
    return struct.unpack_from("<I", data, off)[0]


def validate(path: Path):
    if not path.is_file():
        raise SystemExit(f"ABORT: ALICE missing: {path}")
    data = path.read_bytes()
    h = sha256(data)
    print(f"ALICE = {path}")
    print(f"  size   = 0x{len(data):X}")
    print(f"  sha256 = {h}")
    if len(data) != ALICE_SIZE:
        raise SystemExit("ABORT: ALICE size mismatch")
    if h.lower() != ALICE_SHA256:
        raise SystemExit("ABORT: ALICE SHA256 mismatch")
    print("[PASS] canonical ALICE")
    return Image(data)


def decode1(img, addr, mode="THUMB"):
    if not img.contains(addr):
        return None
    md = md_t if mode == "THUMB" else md_a
    xs = list(md.disasm(img.data[img.off(addr):img.off(addr)+4], addr, count=1))
    return xs[0] if xs else None


def dis_thumb(img, start, end):
    if not img.contains(start):
        return []
    end = min(end, img.end)
    return [x for x in md_t.disasm(img.data[img.off(start):img.off(end)], start) if x.address < end]


def fmt(x):
    return f"0x{x.address:08X}: {x.bytes.hex(' '):<14} {x.mnemonic:<9} {x.op_str}"


def direct_target(x):
    if x is None or x.mnemonic not in {"b", "bl", "blx"} or not x.operands:
        return None
    op = x.operands[0]
    if op.type == ARM_OP_IMM:
        return op.imm & 0xFFFFFFFF
    return None


def literal_load(img, x):
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


def print_region(img, start, end, marks=None):
    marks = marks or set()
    for x in dis_thumb(img, start, end):
        notes = []
        t = direct_target(x)
        if t is not None:
            notes.append(f"target=0x{t:08X}")
        lit = literal_load(img, x)
        if lit:
            rn, la, val = lit
            notes.append(f"literal@0x{la:08X}=0x{val:08X}->{rn}")
        for op in x.operands:
            if op.type == ARM_OP_MEM:
                bn = x.reg_name(op.mem.base) if op.mem.base else "?"
                if op.mem.disp == OFF_SELECTED:
                    notes.append(f"SELECTED_CHILD via {bn}+0x18")
                elif op.mem.disp == OFF_CHILDREN:
                    notes.append(f"CHILDREN_PTR via {bn}+0x40")
                elif op.mem.disp == OFF_COUNT:
                    notes.append(f"CHILD_COUNT via {bn}+0x48")
        tag = ">>>" if x.address in marks else "   "
        print(tag, fmt(x) + ((" ; " + ", ".join(notes)) if notes else ""))


def scan_direct_calls(img, target):
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
        if not ((w & 0x0E000000) == 0x0A000000 or (w & 0xFE000000) == 0xFA000000):
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


def all_hits(data, needle):
    out = []
    p = 0
    while True:
        p = data.find(needle, p)
        if p < 0:
            return out
        out.append(p)
        p += 1


def raw_pointer_refs(img, target):
    vals = {(target & ~1) & 0xFFFFFFFF, (target | 1) & 0xFFFFFFFF}
    hits = []
    for v in vals:
        for off in all_hits(img.data, struct.pack("<I", v)):
            hits.append((img.base + off, v))
    return sorted(set(hits))


def is_prologue(x):
    return bool(x and x.mnemonic == "push" and "lr" in x.op_str)


def enclosing_start(img, addr, back=0x500):
    lo = max(img.base, addr-back) & ~1
    starts = []
    for a in range(lo, addr+1, 2):
        x = decode1(img, a)
        if not is_prologue(x):
            continue
        # Do not use first POP as end; just require target to be in bounded decode window.
        xs = dis_thumb(img, a, min(img.end, a+0x900))
        if any(z.address == addr for z in xs):
            starts.append(a)
    return starts[-1] if starts else None


def reg_written(x):
    if not x.operands:
        return None
    o = x.operands[0]
    return o.reg if o.type == ARM_OP_REG else None


def reg_id(insns, name):
    for x in insns:
        for op in x.operands:
            if op.type == ARM_OP_REG and x.reg_name(op.reg) == name:
                return op.reg
    return None


def backward_source(img, insns, before_addr, name, depth=0):
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
            return f"CONST 0x{v:08X}" + (f" <{lab}>" if lab else "") + f" via literal @0x{lit[1]:08X}"

        if x.mnemonic in {"mov", "movs"} and len(x.operands) >= 2:
            s = x.operands[1]
            if s.type == ARM_OP_IMM:
                v = s.imm & 0xFFFFFFFF
                lab = KNOWN_IDS.get(v & 0xFFFF)
                return f"CONST 0x{v:08X}" + (f" <{lab}>" if lab else "") + f" via {x.mnemonic} @0x{x.address:08X}"
            if s.type == ARM_OP_REG:
                sn = x.reg_name(s.reg)
                return f"{name} <- {sn} @0x{x.address:08X} <- " + backward_source(img, hist[:i+1], x.address, sn, depth+1)

        if x.mnemonic.startswith("ldr") and len(x.operands) >= 2 and x.operands[1].type == ARM_OP_MEM:
            m = x.operands[1].mem
            bn = x.reg_name(m.base) if m.base else "?"
            return f"MEM {x.mnemonic} [{bn}{m.disp:+#x}] @0x{x.address:08X}"

        if x.mnemonic in {"add", "adds", "sub", "subs", "lsls", "lsrs"}:
            return f"EXPR {x.mnemonic} {x.op_str} @0x{x.address:08X}"

        return f"UNKNOWN(writer {x.mnemonic} {x.op_str} @0x{x.address:08X})"

    return f"ARG/INHERITED {name}"


def dump_pointer_ref_context(img, refs, radius=0x30):
    for a, v in refs:
        print()
        print(f"pointer word @0x{a:08X} = 0x{v:08X}")
        lo = max(img.base, (a-radius) & ~1)
        hi = min(img.end, a+radius)
        print_region(img, lo, hi, {a})


def audit_complete_child_at_index(img):
    banner("B. COMPLETE 0x10315514 CHILD-AT-INDEX CANDIDATE")
    marks = {0x10315520, 0x10315528, 0x1031552A, 0x1031552E}
    print_region(img, CHILD_AT_INDEX, CHILD_AT_INDEX_END, marks)

    xs = dis_thumb(img, CHILD_AT_INDEX, CHILD_AT_INDEX_END)

    # Extract invalid sentinel literal from 0x1031552A.
    inv_ins = decode1(img, 0x1031552A)
    inv_lit = literal_load(img, inv_ins)
    if inv_lit:
        _, la, val = inv_lit
        print()
        print(f"invalid/out-of-range return literal @0x{la:08X} = 0x{val:08X}")
        if (val & 0xFFFF) in KNOWN_IDS:
            print(f"  low16 known ID = {KNOWN_IDS[val & 0xFFFF]}")

    # Conservative semantic recognition of valid path.
    valid = [x for x in xs if x.address >= 0x1031552E]
    children_load = None
    indexed_halfword_load = None
    scale = None

    for x in valid:
        for op in x.operands:
            if op.type != ARM_OP_MEM:
                continue
            if x.mnemonic.startswith("ldr") and op.mem.disp == OFF_CHILDREN:
                children_load = x
            if x.mnemonic == "ldrh":
                indexed_halfword_load = x
        if x.mnemonic == "lsls":
            scale = x

    print()
    print("semantic recognizer:")
    print(f"  +0x40 children pointer load = {fmt(children_load) if children_load else 'NOT FOUND'}")
    print(f"  index scaling              = {fmt(scale) if scale else 'NOT FOUND'}")
    print(f"  indexed halfword load      = {fmt(indexed_halfword_load) if indexed_halfword_load else 'NOT FOUND'}")

    semantic_pass = bool(children_load and indexed_halfword_load)
    if semantic_pass:
        print("[PASS] valid branch dereferences the descriptor child array and returns a u16 child value.")
        print("[STRONGLY SUPPORTED] 0x10315514 is CHILD_ID_AT_INDEX(index).")
    else:
        print("[OPEN] complete valid branch does not yet match a child-array lookup pattern.")

    return semantic_pass


def audit_select_callback_ownership(img):
    banner("C. 0x10342FC4 SELECT-CALLBACK OWNERSHIP")
    calls = scan_direct_calls(img, SELECT_CALLBACK)
    refs = raw_pointer_refs(img, SELECT_CALLBACK)

    print(f"SELECT_CALLBACK = 0x{SELECT_CALLBACK:08X}")
    print(f"direct callers    = {len(calls)}")
    print(f"raw pointer refs  = {len(refs)}")

    for mode, x in calls:
        print()
        print(f"{mode} caller: {fmt(x)}")
        fs = enclosing_start(img, x.address)
        if fs is not None:
            ins = dis_thumb(img, fs, min(img.end, fs+0x500))
            print(f"  enclosing start=0x{fs:08X}")
            for rn in ("r0", "r1", "r2", "r3"):
                print(f"  {rn}: {backward_source(img, ins, x.address, rn)}")
            print_region(img, max(fs, x.address-0x30), min(img.end, x.address+0x30), {x.address})

    if refs:
        dump_pointer_ref_context(img, refs, radius=0x40)

    return calls, refs


def audit_callback_table(img):
    banner("D. CALLBACK TABLE / LITERALS AROUND 0x10340D00")
    print_region(img, CONSUMER_TABLE_START, CONSUMER_TABLE_END)

    print()
    for a in range(CONSUMER_TABLE_START, CONSUMER_TABLE_END, 4):
        if not img.contains(a):
            continue
        v = u32(img.data, img.off(a))
        if v is None:
            continue
        tag = []
        if (v & ~1) == SELECT_CALLBACK:
            tag.append("SELECT_CALLBACK")
        if (v & ~1) == RESET_CALLBACK:
            tag.append("RESET_CALLBACK")
        if (v & ~1) == 0x10347432:
            tag.append("REBUILD_WRAPPER_B")
        if ALICE_BASE <= (v & ~1) < img.end:
            tag.append("ALICE_PTR")
        print(f"0x{a:08X}: 0x{v:08X}" + (f"  <{'|'.join(tag)}>" if tag else ""))


def audit_enter_callers(img):
    banner("E. REAL ENTER-SUBMENU CALLERS")

    for label, start, end in (
        ("CALLER_A", ENTER_CALLER_A_START, ENTER_CALLER_A_END),
        ("CALLER_B", ENTER_CALLER_B_START, ENTER_CALLER_B_END),
    ):
        print()
        print(f"--- {label} 0x{start:08X}..0x{end:08X} ---")
        print_region(img, start, end)

    calls = scan_direct_calls(img, ENTER_HANDLER)
    print()
    print(f"direct calls to 0x{ENTER_HANDLER:08X} = {len(calls)}")
    for mode, x in calls:
        fs = enclosing_start(img, x.address)
        print()
        print(f"{mode} {fmt(x)}")
        if fs is None:
            continue
        ins = dis_thumb(img, fs, min(img.end, fs+0x500))
        print(f"  enclosing start=0x{fs:08X}")
        for rn in ("r0", "r1"):
            print(f"  {rn}: {backward_source(img, ins, x.address, rn)}")


def audit_consumer_child0(img):
    banner("F. GENERIC CONSUMER USE OF 0x10315514")
    # The A.9 report showed call @0x10340C64 with index 0.
    print_region(img, 0x10340C38, 0x10340C90, {0x10340C64})


def parse_args():
    p = argparse.ArgumentParser()
    p.add_argument(
        "--alice",
        default="research/f2/work/extracted/altice_alice/alice-py.bin",
    )
    p.add_argument(
        "--report",
        default="research/f2/work/reports/s13_5a10_child_index_to_id_selection_callback.txt",
    )
    return p.parse_args()


def resolve(root: Path, s: str):
    p = Path(s)
    return p if p.is_absolute() else root / p


def main():
    args = parse_args()
    root = Path.cwd()
    alice_path = resolve(root, args.alice)
    report_path = resolve(root, args.report)
    report_path.parent.mkdir(parents=True, exist_ok=True)

    cap = io.StringIO()
    old = sys.stdout
    sys.stdout = Tee(old, cap)
    try:
        banner("S13.5A.10 - CHILD-INDEX -> CHILD-ID / SELECTION CALLBACK AUDIT")
        print("STRICTLY OFFLINE")
        print("PHONE ACCESSED       : NO")
        print("FLASH MODIFIED       : NO")
        print("PATCH GENERATED      : NO")
        print("REPACK               : NO")

        banner("A. CANONICAL INPUT")
        img = validate(alice_path)

        child_lookup_pass = audit_complete_child_at_index(img)
        calls, refs = audit_select_callback_ownership(img)
        audit_callback_table(img)
        audit_enter_callers(img)
        audit_consumer_child0(img)

        banner("G. DECISION GATE")
        print(f"complete 0x10315514 child-array semantics = {'PASS' if child_lookup_pass else 'OPEN'}")
        print(f"0x10342FC4 direct callers                  = {len(calls)}")
        print(f"0x10342FC4 raw pointer refs                = {len(refs)}")
        print()

        if child_lookup_pass:
            print("[PASS] A.9's producer is no longer just a range checker:")
            print("       the valid path resolves a selected child from the descriptor child array.")
            print("[NEXT] Treat the r0 input of 0x10342FC4 as a selection index candidate,")
            print("       then trace its caller / callback registration to the UI selection source.")
            print("       The returned u16 is stored in descriptor+0x18 and becomes +0x14 on entry.")
        else:
            print("[OPEN] Need one more exact dump of 0x1031552E+ before assigning child-array semantics.")

        print()
        print("DO NOT YET CALL ANY NUMERIC ID 'MULTIMEDIA' unless the callback/caller chain")
        print("structurally binds that child ID to the visible Multimedia selection.")
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
        report_path.write_text(cap.getvalue(), encoding="utf-8")


if __name__ == "__main__":
    raise SystemExit(main())
