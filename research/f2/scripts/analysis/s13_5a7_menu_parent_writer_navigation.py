#!/usr/bin/env python3
"""
S13.5A.7 - MENU DESCRIPTOR +0x14 WRITER / NAVIGATION TRANSITION AUDIT

STRICTLY OFFLINE / READ-ONLY.

S13.5A.6 proved the real generic menu-child builder path:

    0x10340B30 -> 0x10343050
    argument r0 at 0x10340B30 = *(u16 *)(descriptor + 0x14)

and 0x10343050 then uses that value as the parent passed to:
    ENUM_CHILD_IDS
    GET_CHILD_COUNT

Therefore descriptor +0x14 is now CONFIRMED as the current parent/menu ID
on the live provider-backed menu path.

This pass follows only the next causal link:
  1. find the enclosing function around 0x10340B30;
  2. recover the descriptor object's provenance (r4 at the callsite);
  3. find writers of descriptor +0x14 and +0x18;
  4. find the strongest navigation motif:
         ldrh Rx, [descriptor, #0x18]
         ...
         strh Rx, [descriptor, #0x14]
     i.e. selected child -> new parent;
  5. find writers of +0x18 (selected child);
  6. identify the functions containing those transitions and their callers;
  7. correlate only structurally with known IDs 0x8313/0x8321/0x8928.

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

GENERIC_BUILDER = 0x10343050
GENERIC_BUILDER_CALL = 0x10340B30

OFF_PARENT = 0x14
OFF_SELECTED = 0x18
OFF_CHILDREN = 0x40
OFF_COUNT = 0x48

KNOWN_IDS = {
    0x8313: "IMAGE_A",
    0x8321: "IMAGE_B",
    0x8928: "AUDIO",
    0x346C: "FIXED_PARENT_346C",
    0x3473: "FIXED_CHILD_3473",
    0xB0EC: "B0EC",
}

FIELD_LABELS = {
    OFF_PARENT: "CURRENT_PARENT",
    OFF_SELECTED: "SELECTED_CHILD",
    OFF_CHILDREN: "CHILDREN_PTR",
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
        for x in self.streams:
            x.write(s)
        return len(s)

    def flush(self):
        for x in self.streams:
            x.flush()


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


def banner(s):
    print()
    print("=" * 126)
    print(s)
    print("=" * 126)


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


def fmt(x):
    return (
        f"0x{x.address:08X}: {x.bytes.hex(' '):<14} "
        f"{x.mnemonic:<9} {x.op_str}"
    )


def validate(path: Path):
    if not path.is_file():
        raise SystemExit(f"ABORT: missing canonical ALICE: {path}")
    b = path.read_bytes()
    h = sha256(b)
    print(f"ALICE = {path}")
    print(f"  size   = 0x{len(b):X}")
    print(f"  sha256 = {h}")
    if len(b) != ALICE_SIZE or h.lower() != ALICE_SHA256:
        raise SystemExit("ABORT: canonical ALICE identity mismatch")
    print("[PASS] canonical ALICE")
    return Image(b)


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


def direct_target(insn):
    if insn.mnemonic not in {"b", "bl", "blx"} or not insn.operands:
        return None
    op = insn.operands[0]
    if op.type == ARM_OP_IMM:
        return op.imm & 0xFFFFFFFF
    return None


def is_thumb_prologue(x):
    if x is None:
        return False
    return x.mnemonic == "push" and "lr" in x.op_str


def is_thumb_return(x):
    if x is None:
        return False
    return (
        (x.mnemonic == "pop" and "pc" in x.op_str)
        or (x.mnemonic == "bx" and x.op_str.strip() == "lr")
    )


def mem_operand(insn):
    for op in insn.operands:
        if op.type == ARM_OP_MEM:
            return op
    return None


def field_access(insn):
    out = []
    for op in insn.operands:
        if op.type == ARM_OP_MEM and op.mem.disp in FIELD_LABELS:
            out.append((op.mem.disp, FIELD_LABELS[op.mem.disp], op.mem.base))
    return out


def reg_written(insn, reg_id):
    if not insn.operands:
        return False
    op0 = insn.operands[0]
    return op0.type == ARM_OP_REG and op0.reg == reg_id


def literal_load(img: Image, insn):
    if not insn.mnemonic.startswith("ldr") or len(insn.operands) < 2:
        return None
    d, s = insn.operands[0], insn.operands[1]
    if d.type != ARM_OP_REG or s.type != ARM_OP_MEM or s.mem.base != ARM_REG_PC:
        return None
    pc = (insn.address + 4) & ~3
    la = (pc + s.mem.disp) & 0xFFFFFFFF
    if not img.contains(la):
        return None
    val = u32(img.data, img.off(la))
    return (d.reg, la, val)


def print_region(img: Image, start: int, end: int, marks=None):
    marks = marks or set()
    for x in dis_thumb(img, start, end):
        tag = ">>>" if x.address in marks else "   "
        notes = []
        for disp, label, base in field_access(x):
            notes.append(f"{label} via {x.reg_name(base)}+0x{disp:X}")
        tgt = direct_target(x)
        if tgt is not None:
            notes.append(f"target=0x{tgt:08X}")
        print(tag, fmt(x) + ((" ; " + ", ".join(notes)) if notes else ""))


def path_contains(img: Image, start: int, target: int, max_end: Optional[int] = None):
    if not img.contains(start):
        return False, []
    if max_end is None:
        max_end = min(img.end, target + 0x300)
    xs = dis_thumb(img, start, max_end)
    return any(x.address == target for x in xs), xs


def enclosing_prologues(img: Image, target: int, back=0x500):
    lo = max(img.base, target - back) & ~1
    cands = []
    for a in range(lo, target + 1, 2):
        x = decode1(img, a)
        if not is_thumb_prologue(x):
            continue
        ok, xs = path_contains(img, a, target, target + 0x200)
        if ok:
            cands.append((a, xs))
    return cands


def find_end_after(img: Image, start: int, min_addr: int, max_len=0x600):
    xs = dis_thumb(img, start, min(img.end, start + max_len))
    for x in xs:
        if x.address >= min_addr and is_thumb_return(x):
            return x.address + len(x.bytes), xs
    return min(img.end, start + max_len), xs


def scan_direct_calls(img: Image, target: int):
    out = []

    # Thumb BL/BLX
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

    # ARM BL/BLX
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

    uniq = {}
    for mode, x in out:
        uniq[(mode, x.address)] = (mode, x)
    return [uniq[k] for k in sorted(uniq, key=lambda z: (z[1], z[0]))]


def reg_id_by_name(insns, name):
    for x in insns:
        for op in x.operands:
            if op.type == ARM_OP_REG and x.reg_name(op.reg) == name:
                return op.reg
    return None


def backward_reg_source(img: Image, insns, before_addr: int, wanted_name: str, depth=0):
    """
    Callee-saved aware backwards slice.
    Unlike the previous pass, calls only clobber r0-r3/r12/lr.
    This matters for descriptor pointers held in r4-r7.
    """
    if depth > 10:
        return "UNKNOWN(depth-limit)"

    hist = [x for x in insns if x.address < before_addr]
    wanted = reg_id_by_name(hist, wanted_name)
    if wanted is None:
        return f"UNKNOWN({wanted_name} unseen)"

    caller_saved = wanted_name in {"r0", "r1", "r2", "r3", "r12", "lr"}

    for i in range(len(hist)-1, -1, -1):
        x = hist[i]

        if x.mnemonic in {"bl", "blx"} and caller_saved:
            return f"UNKNOWN({wanted_name} clobbered by call @0x{x.address:08X})"

        if not reg_written(x, wanted):
            continue

        lit = literal_load(img, x)
        if lit and lit[0] == wanted:
            v = lit[2]
            low = v & 0xFFFF
            tag = f" <{KNOWN_IDS[low]}>" if low in KNOWN_IDS else ""
            return f"CONST 0x{v:08X}{tag} via literal @0x{lit[1]:08X}"

        ops = x.operands
        m = x.mnemonic

        if m in {"mov", "movs"} and len(ops) >= 2:
            s = ops[1]
            if s.type == ARM_OP_IMM:
                v = s.imm & 0xFFFFFFFF
                low = v & 0xFFFF
                tag = f" <{KNOWN_IDS[low]}>" if low in KNOWN_IDS else ""
                return f"CONST 0x{v:08X}{tag} via {m} @0x{x.address:08X}"
            if s.type == ARM_OP_REG:
                srcn = x.reg_name(s.reg)
                return (
                    f"{wanted_name} <- {srcn} @0x{x.address:08X} <- "
                    + backward_reg_source(img, hist[:i+1], x.address, srcn, depth+1)
                )

        if m.startswith("ldr") and len(ops) >= 2 and ops[1].type == ARM_OP_MEM:
            mem = ops[1].mem
            basen = x.reg_name(mem.base) if mem.base else "?"
            d = mem.disp
            label = FIELD_LABELS.get(d)
            suffix = f" <{label}>" if label else ""
            return f"MEM {m} [{basen}{d:+#x}] @0x{x.address:08X}{suffix}"

        if m in {"add", "adds", "sub", "subs"}:
            return f"EXPR {m} {x.op_str} @0x{x.address:08X}"

        return f"UNKNOWN(writer {m} {x.op_str} @0x{x.address:08X})"

    return f"ARG/INHERITED {wanted_name}"


def scan_field_ops(img: Image, start: int, end: int):
    hits = []
    for x in dis_thumb(img, start, end):
        for op in x.operands:
            if op.type == ARM_OP_MEM and op.mem.disp in FIELD_LABELS:
                rw = (
                    "WRITE" if x.mnemonic.startswith("str")
                    else "READ" if x.mnemonic.startswith("ldr")
                    else "USE"
                )
                hits.append((x, rw, op.mem.disp, FIELD_LABELS[op.mem.disp], op.mem.base))
    return hits


def scan_transition_motifs(img: Image):
    """
    Heuristic-but-strong code motif:
      LDRH Rt,[Rb,#0x18]
      within <= 8 subsequent decoded instructions
      STRH Rt,[Rb,#0x14]

    We decode each even address as a possible Thumb instruction, then validate
    the pair by sequentially decoding forward from the LDRH.
    """
    hits = []

    for off in range(0, len(img.data)-2, 2):
        addr = img.base + off
        x = decode1(img, addr)
        if x is None or x.mnemonic != "ldrh" or len(x.operands) < 2:
            continue
        d, m = x.operands[0], x.operands[1]
        if d.type != ARM_OP_REG or m.type != ARM_OP_MEM or m.mem.disp != OFF_SELECTED:
            continue

        rt = d.reg
        rb = m.mem.base

        seq = dis_thumb(img, addr, min(img.end, addr + 0x30))
        steps = 0
        invalid = False
        for y in seq[1:]:
            steps += 1
            if steps > 8:
                break

            # Value/base overwritten before store => reject.
            if reg_written(y, rt) or reg_written(y, rb):
                invalid = True
                break

            if y.mnemonic == "strh" and len(y.operands) >= 2:
                s, mm = y.operands[0], y.operands[1]
                if (
                    s.type == ARM_OP_REG
                    and mm.type == ARM_OP_MEM
                    and s.reg == rt
                    and mm.mem.base == rb
                    and mm.mem.disp == OFF_PARENT
                ):
                    hits.append((x, y))
                    break

            if y.mnemonic in {"bl", "blx"}:
                # Rt could be caller-saved; be conservative.
                if y.reg_name(rt) in {"r0", "r1", "r2", "r3"}:
                    invalid = True
                    break

        if invalid:
            continue

    # dedupe
    uniq = {}
    for a, b in hits:
        uniq[(a.address, b.address)] = (a, b)
    return [uniq[k] for k in sorted(uniq)]


def scan_selected_writers(img: Image):
    hits = []
    for off in range(0, len(img.data)-2, 2):
        x = decode1(img, img.base+off)
        if x is None or not x.mnemonic.startswith("str"):
            continue
        for op in x.operands:
            if op.type == ARM_OP_MEM and op.mem.disp == OFF_SELECTED:
                hits.append(x)
                break
    # dedupe by address
    return [dict((x.address, x) for x in hits)[k] for k in sorted({x.address for x in hits})]


def find_enclosing_function(img: Image, addr: int, back=0x300):
    cands = enclosing_prologues(img, addr, back=back)
    if not cands:
        return None, None
    start = cands[-1][0]
    end, _ = find_end_after(img, start, addr, max_len=0x500)
    return start, end


def nearby_known_ids(img: Image, center: int, radius=0x100):
    lo = max(0, img.off(center)-radius)
    hi = min(len(img.data), img.off(center)+radius)
    out = []
    for v, name in KNOWN_IDS.items():
        pat = struct.pack("<H", v)
        p = img.data.find(pat, lo, hi)
        while p >= 0:
            out.append((img.base+p, v, name))
            p = img.data.find(pat, p+1, hi)
    return sorted(out)


def parse_args():
    p = argparse.ArgumentParser()
    p.add_argument(
        "--alice",
        default="research/f2/work/extracted/altice_alice/alice-py.bin",
    )
    p.add_argument(
        "--report",
        default="research/f2/work/reports/s13_5a7_menu_parent_writer_navigation.txt",
    )
    return p.parse_args()


def path(root: Path, s: str):
    p = Path(s)
    return p if p.is_absolute() else root / p


def main():
    args = parse_args()
    root = Path.cwd()
    ap = path(root, args.alice)
    rp = path(root, args.report)
    rp.parent.mkdir(parents=True, exist_ok=True)

    capture = io.StringIO()
    old = sys.stdout
    sys.stdout = Tee(old, capture)

    try:
        banner("S13.5A.7 - MENU DESCRIPTOR +0x14 WRITER / NAVIGATION TRANSITION AUDIT")
        print("STRICTLY OFFLINE")
        print("PHONE ACCESSED       : NO")
        print("FLASH MODIFIED       : NO")
        print("PATCH GENERATED      : NO")
        print("REPACK               : NO")

        banner("A. CANONICAL INPUT")
        img = validate(ap)

        banner("B. ENCLOSING FUNCTION AROUND 0x10340B30")
        cands = enclosing_prologues(img, GENERIC_BUILDER_CALL, back=0x600)
        print(f"prologue candidates reaching 0x{GENERIC_BUILDER_CALL:08X} = {len(cands)}")
        for a, _ in cands[-20:]:
            print(f"  0x{a:08X}: {fmt(decode1(img,a))}")

        if not cands:
            print("[FAIL] no enclosing Thumb prologue found")
            return 4

        caller_func = cands[-1][0]
        caller_end, _ = find_end_after(img, caller_func, GENERIC_BUILDER_CALL, max_len=0x800)
        print(f"[PROMOTED FUNCTION CANDIDATE] start=0x{caller_func:08X} end~=0x{caller_end:08X}")

        print()
        print("Function disassembly:")
        print_region(
            img,
            caller_func,
            caller_end,
            {GENERIC_BUILDER_CALL},
        )

        caller_insns = dis_thumb(img, caller_func, caller_end)

        banner("C. DESCRIPTOR POINTER PROVENANCE AT 0x10340B30")
        # r4 is the descriptor base at [r4,#0x14].
        print(f"r4 source at call = {backward_reg_source(img, caller_insns, GENERIC_BUILDER_CALL, 'r4')}")
        print(f"r0 source at call = {backward_reg_source(img, caller_insns, GENERIC_BUILDER_CALL, 'r0')}")
        print()
        print("[FACT from S13.5A.6] r0 at call is ldrh [r4,#0x14].")

        banner("D. FIELD READ/WRITE CENSUS IN CALLER FUNCTION")
        ops = scan_field_ops(img, caller_func, caller_end)
        print(f"field operations = {len(ops)}")
        for x, rw, disp, label, base in ops:
            src = ""
            if rw == "WRITE" and x.operands and x.operands[0].type == ARM_OP_REG:
                srcn = x.reg_name(x.operands[0].reg)
                src = " | source=" + backward_reg_source(
                    img, caller_insns, x.address, srcn
                )
            print(
                f"{rw:<5} 0x{x.address:08X}: {x.mnemonic:<8} {x.op_str:<32} "
                f"<{label}> base={x.reg_name(base)}{src}"
            )

        banner("E. STRONG selected(+0x18) -> parent(+0x14) TRANSITION MOTIFS")
        motifs = scan_transition_motifs(img)
        print(f"strong motifs found = {len(motifs)}")

        motif_funcs = {}
        for load, store in motifs:
            print()
            print(
                f"MOTIF: 0x{load.address:08X} {load.mnemonic} {load.op_str}"
                f"  -> 0x{store.address:08X} {store.mnemonic} {store.op_str}"
            )
            fs, fe = find_enclosing_function(img, load.address, back=0x400)
            print(
                f"  enclosing function = "
                + (f"0x{fs:08X}..0x{fe:08X}" if fs is not None else "UNKNOWN")
            )
            if fs is not None:
                motif_funcs.setdefault(fs, fe)
                callers = scan_direct_calls(img, fs)
                print(f"  direct callers = {len(callers)}")
                for mode, c in callers[:20]:
                    print(f"    {mode} {fmt(c)}")
                ids = nearby_known_ids(img, load.address, 0x180)
                if ids:
                    print("  nearby known IDs (supporting evidence only):")
                    for a, v, n in ids[:30]:
                        print(f"    0x{a:08X}: 0x{v:04X} <{n}>")
                print("  local context:")
                print_region(
                    img,
                    max(img.base, load.address-0x30) & ~1,
                    min(img.end, store.address+0x30),
                    {load.address, store.address},
                )

        banner("F. ALL SELECTED_CHILD (+0x18) WRITERS")
        sel_writers = scan_selected_writers(img)
        print(f"candidate +0x18 writers = {len(sel_writers)}")

        # Keep detailed output focused on code around the generic-menu cluster,
        # transition functions, or sites with known IDs nearby.
        focus_funcs = set(motif_funcs)
        detailed = 0
        for x in sel_writers:
            fs, fe = find_enclosing_function(img, x.address, back=0x300)
            ids = nearby_known_ids(img, x.address, 0x100)
            in_cluster = 0x1033F000 <= x.address <= 0x10345000
            in_motif_func = fs in focus_funcs if fs is not None else False
            if not (in_cluster or in_motif_func or ids):
                continue

            detailed += 1
            print()
            print(f"SELECTED WRITE: {fmt(x)}")
            print(
                "  function = "
                + (f"0x{fs:08X}..0x{fe:08X}" if fs is not None else "UNKNOWN")
            )
            if x.operands and x.operands[0].type == ARM_OP_REG and fs is not None:
                srcn = x.reg_name(x.operands[0].reg)
                insns = dis_thumb(img, fs, fe)
                print(
                    f"  value source = "
                    f"{backward_reg_source(img, insns, x.address, srcn)}"
                )
            if ids:
                print("  nearby known IDs:")
                for a, v, n in ids[:20]:
                    print(f"    0x{a:08X}: 0x{v:04X} <{n}>")

        print(f"\ndetailed selected-writer sites = {detailed}")

        banner("G. DIRECT CALLERS OF 0x10340Bxx FUNCTION")
        callers = scan_direct_calls(img, caller_func)
        print(f"caller function = 0x{caller_func:08X}")
        print(f"direct callers = {len(callers)}")
        for mode, c in callers:
            print()
            print(f"{mode} {fmt(c)}")
            fs, fe = find_enclosing_function(img, c.address, back=0x400)
            print(
                "  enclosing caller = "
                + (f"0x{fs:08X}..0x{fe:08X}" if fs is not None else "UNKNOWN")
            )
            if mode == "THUMB" and fs is not None:
                insns = dis_thumb(img, fs, fe)
                for rn in ("r0", "r1", "r2", "r3", "r4"):
                    print(
                        f"  {rn} @call: "
                        f"{backward_reg_source(img, insns, c.address, rn)}"
                    )
                fops = scan_field_ops(img, fs, fe)
                for x, rw, disp, label, base in fops:
                    if disp in {OFF_PARENT, OFF_SELECTED}:
                        print(
                            f"  {rw} field: 0x{x.address:08X} "
                            f"{x.mnemonic} {x.op_str} <{label}>"
                        )

        banner("H. DECISION GATE")
        parent_writes = [
            (x, rw, disp, label, base)
            for x, rw, disp, label, base in ops
            if rw == "WRITE" and disp == OFF_PARENT
        ]

        print(f"enclosing function around 0x10340B30 = 0x{caller_func:08X}")
        print(f"direct callers of that function       = {len(callers)}")
        print(f"local +0x14 writes                    = {len(parent_writes)}")
        print(f"strong selected->parent motifs        = {len(motifs)}")
        print(f"selected(+0x18) writer candidates     = {len(sel_writers)}")
        print()

        if motifs:
            print("[PASS] navigation selected(+0x18) -> parent(+0x14) motif recovered.")
            print("[NEXT] Trace the selected-child writer feeding that transition.")
            print("       Then identify which selected child corresponds to the visible")
            print("       Multimedia entry in its parent menu.")
        elif parent_writes:
            print("[PASS] direct +0x14 writer exists in the immediate caller.")
            print("[NEXT] Promote its value source and identify the concrete parent ID.")
        else:
            print("[NEXT] +0x14 is inherited/dynamic in this function.")
            print("       Continue through its direct callers and the +0x18 writer path.")
            print("       Do NOT return to raw ID scanning.")

        print()
        print("CONFIRMED:")
        print("  descriptor+0x14 feeds real ENUM_CHILD_IDS + GET_CHILD_COUNT")
        print("  descriptor+0x14 = current parent/menu ID on generic builder path")
        print()
        print("STILL UNKNOWN:")
        print("  numeric Multimedia parent ID")
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
        print(f"REPORT = {rp}")

        return 0
    finally:
        sys.stdout = old
        rp.write_text(capture.getvalue(), encoding="utf-8")


if __name__ == "__main__":
    raise SystemExit(main())
