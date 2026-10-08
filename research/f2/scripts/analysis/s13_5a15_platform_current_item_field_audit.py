#!/usr/bin/env python3
"""
S13.5A.15 - PLATFORM CURRENT-ITEM FIELD READER / GETTER AUDIT

STRICTLY OFFLINE / READ-ONLY.

S13.5A.14 proved:
  - ALICE veneer 0x102FD13C -> ZIMAGE Thumb 0xF02D1E90.
  - F02D1E90(value) writes value to:
        state = *(u32 *)(0xF00BADA8 + 8)
        *(u32 *)(state + 0x264) = value
  - 8/9 dispatcher wrappers call this setter with original_index + 1,
    then dispatch original_index to SELECT_CB.
  - SELECT_CB uses original_index as descriptor.children[index].

Active question:
  Is state+0x264 structurally the platform current/highlighted item field?

This pass:
  A. validates canonical ALICE + ZIMAGE;
  B. dumps the full sibling-function neighborhood around F02D1E90;
  C. finds all real ALICE/ZIMAGE xrefs to F00BADA8;
  D. symbolically identifies effective reads/writes of state+0x264;
  E. looks for getter patterns returning state+0x264;
  F. looks for +/-1 conversions, bounds/count comparisons, and table indexing
     derived from the field;
  G. emits a strict FACT / STRONGLY SUPPORTED gate.

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

from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_THUMB, CS_MODE_LITTLE_ENDIAN
from capstone.arm import ARM_OP_IMM, ARM_OP_MEM, ARM_OP_REG, ARM_REG_PC

ALICE_BASE = 0x1024EC00
ALICE_SIZE = 0x157BB4
ALICE_SHA256 = "7246242b67afae0d13104452bc3257827cb778119b54e7a26fb7fb55993697ea"

ZIMAGE_BASE = 0xF023CA50
ZIMAGE_SIZE = 0x185E98
ZIMAGE_SHA256 = "85fba8c8ae8161e4c1f8ced7983ec30d48c54ab10e51c69fcdfb900aca220954"

STATE_GLOBAL = 0xF00BADA8
STATE_PTR_OFF = 0x08
CURRENT_ITEM_OFF = 0x264

SETTER = 0xF02D1E90

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
        return self.base <= addr < self.end
    def off(self, addr: int):
        return addr - self.base


@dataclass
class Sym:
    kind: str
    value: int | None = None
    desc: str = ""


def banner(s: str):
    print()
    print("=" * 132)
    print(s)
    print("=" * 132)


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


def verify(path: Path, name: str, base: int, size: int, expected_sha: str):
    if not path.is_file():
        raise SystemExit(f"ABORT: missing canonical {name}: {path}")
    data = path.read_bytes()
    got = sha256(data)
    print(f"{name} = {path}")
    print(f"  runtime base = 0x{base:08X}")
    print(f"  size         = 0x{len(data):X}")
    print(f"  sha256       = {got}")
    if len(data) != size:
        raise SystemExit(f"ABORT: {name} size mismatch")
    if got.lower() != expected_sha.lower():
        raise SystemExit(f"ABORT: {name} SHA256 mismatch")
    print(f"[PASS] canonical {name}")
    return Image(name, data, base)


def decode1(img: Image, addr: int, mode="THUMB"):
    if not img.contains(addr):
        return None
    md = md_t if mode == "THUMB" else md_a
    xs = list(md.disasm(img.data[img.off(addr):img.off(addr)+4], addr, count=1))
    return xs[0] if xs else None


def dis(img: Image, start: int, end: int, mode="THUMB"):
    if not img.contains(start):
        return []
    end = min(end, img.end)
    md = md_t if mode == "THUMB" else md_a
    return [x for x in md.disasm(img.data[img.off(start):img.off(end)], start) if x.address < end]


def fmt(x):
    return f"0x{x.address:08X}: {x.bytes.hex(' '):<14} {x.mnemonic:<9} {x.op_str}"


def direct_target(x):
    if x is None or x.mnemonic not in {"b", "bl", "blx"} or not x.operands:
        return None
    if x.operands[0].type == ARM_OP_IMM:
        return x.operands[0].imm & 0xFFFFFFFF
    return None


def literal_load(img: Image, x, mode="THUMB"):
    if x is None or not x.mnemonic.startswith("ldr") or len(x.operands) < 2:
        return None
    d, s = x.operands[0], x.operands[1]
    if d.type != ARM_OP_REG or s.type != ARM_OP_MEM or s.mem.base != ARM_REG_PC:
        return None
    pc = ((x.address + 4) & ~3) if mode == "THUMB" else (x.address + 8)
    la = (pc + s.mem.disp) & 0xFFFFFFFF
    if not img.contains(la):
        return None
    return x.reg_name(d.reg), d.reg, la, u32(img.data, img.off(la))


def all_hits(data: bytes, needle: bytes):
    out = []
    p = 0
    while True:
        p = data.find(needle, p)
        if p < 0:
            return out
        out.append(p)
        p += 1


def real_literal_xrefs_for_value(img: Image, value: int):
    out = []
    for roff in all_hits(img.data, struct.pack("<I", value & 0xFFFFFFFF)):
        la = img.base + roff

        # Thumb
        for off in range(max(0, roff-0x500) & ~1, roff+1, 2):
            a = img.base + off
            x = decode1(img, a, "THUMB")
            li = literal_load(img, x, "THUMB") if x else None
            if li and li[2] == la and li[3] == value:
                out.append(("THUMB", x, la))

        # ARM
        for off in range(max(0, roff-0x1000) & ~3, roff+1, 4):
            a = img.base + off
            x = decode1(img, a, "ARM")
            li = literal_load(img, x, "ARM") if x else None
            if li and li[2] == la and li[3] == value:
                out.append(("ARM", x, la))

    uniq = {(m,x.address,la):(m,x,la) for m,x,la in out}
    return [uniq[k] for k in sorted(uniq)]


def print_region(img: Image, start: int, end: int, mode="THUMB", marks=None):
    marks = marks or set()
    for x in dis(img, start, end, mode):
        notes = []
        t = direct_target(x)
        if t is not None:
            notes.append(f"target=0x{t:08X}")
        li = literal_load(img, x, mode)
        if li:
            rn, _, la, val = li
            tag = " <STATE_GLOBAL>" if val == STATE_GLOBAL else ""
            notes.append(f"literal@0x{la:08X}=0x{val:08X}->{rn}{tag}")
        mark = ">>>" if x.address in marks else "   "
        print(mark, fmt(x) + ((" ; " + ", ".join(notes)) if notes else ""))


def is_prologue(x):
    return bool(x and x.mnemonic == "push" and "lr" in x.op_str)


def candidate_prologues(img: Image, target: int, back=0x300, forward=0x700):
    lo = max(img.base, target-back) & ~1
    out = []
    for a in range(lo, target+1, 2):
        x = decode1(img, a, "THUMB")
        if not is_prologue(x):
            continue
        xs = dis(img, a, min(img.end, a+forward), "THUMB")
        if any(z.address == target for z in xs):
            out.append(a)
    return out


def enclosing_start(img: Image, addr: int):
    c = candidate_prologues(img, addr)
    return c[-1] if c else None


def sym_forward_from_state_seed(img: Image, mode: str, seed_x, max_bytes=0x140):
    """
    Track:
      seed_reg = STATE_GLOBAL
      ldr ptr,[seed_reg,#8]        -> STATE_PTR
      arithmetic on STATE_PTR
      memory access at effective +0x264
      +/-1 transformations of loaded field
      comparisons using loaded/derived field
    """
    md = md_t if mode == "THUMB" else md_a
    start = seed_x.address
    end = min(img.end, start + max_bytes)
    xs = list(md.disasm(img.data[img.off(start):img.off(end)], start))

    regs: dict[int, Sym] = {}
    events = []

    li = literal_load(img, seed_x, mode)
    if not li:
        return xs, events

    regs[li[1]] = Sym("CONST", STATE_GLOBAL, "STATE_GLOBAL")

    for i, x in enumerate(xs):
        if i == 0:
            continue

        # Literal load
        li2 = literal_load(img, x, mode)
        if li2:
            regs[li2[1]] = Sym("CONST", li2[3], f"literal@0x{li2[2]:08X}")
            continue

        ops = x.operands
        dst = ops[0].reg if ops and ops[0].type == ARM_OP_REG else None

        # mov
        if x.mnemonic in {"mov","movs"} and len(ops)>=2 and dst is not None:
            s = ops[1]
            if s.type == ARM_OP_REG:
                regs[dst] = regs.get(s.reg, Sym("UNKNOWN"))
            elif s.type == ARM_OP_IMM:
                regs[dst] = Sym("CONST", s.imm & 0xFFFFFFFF, "mov imm")
            else:
                regs.pop(dst, None)
            continue

        # shifts by imm on constants / offsets
        if x.mnemonic in {"lsls","lsrs"} and len(ops)>=2 and dst is not None:
            # handle Thumb 2-op form: lsls r2,r2,#6 or lsls r2,#6
            src_reg = None
            imm = None
            for op in ops[1:]:
                if op.type == ARM_OP_REG and src_reg is None:
                    src_reg = op.reg
                elif op.type == ARM_OP_IMM:
                    imm = op.imm
            if src_reg is None:
                src_reg = dst
            s = regs.get(src_reg)
            if s and s.kind == "CONST" and s.value is not None and imm is not None:
                if x.mnemonic == "lsls":
                    regs[dst] = Sym("CONST", (s.value << imm) & 0xFFFFFFFF, "shift const")
                else:
                    regs[dst] = Sym("CONST", (s.value >> imm) & 0xFFFFFFFF, "shift const")
            else:
                regs.pop(dst, None)
            continue

        # add/sub
        if x.mnemonic in {"add","adds","sub","subs"} and dst is not None:
            if len(ops) == 2:
                a = regs.get(dst)
                b = ops[1]
                if a and a.kind in {"CONST","STATE_PTR","STATE_DERIVED"}:
                    delta = None
                    if b.type == ARM_OP_IMM:
                        delta = b.imm
                    elif b.type == ARM_OP_REG:
                        sb = regs.get(b.reg)
                        if sb and sb.kind == "CONST":
                            delta = sb.value
                    if delta is not None:
                        sign = 1 if x.mnemonic.startswith("add") else -1
                        if a.kind == "CONST":
                            regs[dst] = Sym("CONST", (a.value + sign*delta) & 0xFFFFFFFF, "arith const")
                        else:
                            off = (a.value or 0) + sign*delta
                            regs[dst] = Sym("STATE_DERIVED", off, f"state+0x{off:X}")
                        continue
            elif len(ops) >= 3:
                aop,bop = ops[1],ops[2]
                if aop.type == ARM_OP_REG:
                    sa = regs.get(aop.reg)
                    delta = None
                    if bop.type == ARM_OP_IMM:
                        delta = bop.imm
                    elif bop.type == ARM_OP_REG:
                        sb = regs.get(bop.reg)
                        if sb and sb.kind == "CONST":
                            delta = sb.value
                    if sa and delta is not None:
                        sign = 1 if x.mnemonic.startswith("add") else -1
                        if sa.kind == "CONST":
                            regs[dst] = Sym("CONST", (sa.value + sign*delta) & 0xFFFFFFFF, "arith const")
                        elif sa.kind in {"STATE_PTR","STATE_DERIVED"}:
                            off = (sa.value or 0) + sign*delta
                            regs[dst] = Sym("STATE_DERIVED", off, f"state+0x{off:X}")
                        continue
            regs.pop(dst, None)
            continue

        # memory loads
        if x.mnemonic.startswith("ldr") and len(ops)>=2 and dst is not None and ops[1].type == ARM_OP_MEM:
            m = ops[1].mem
            bs = regs.get(m.base)

            if bs and bs.kind == "CONST" and bs.value == STATE_GLOBAL and m.disp == STATE_PTR_OFF:
                regs[dst] = Sym("STATE_PTR", 0, "*(STATE_GLOBAL+8)")
                events.append(("STATE_PTR_LOAD", x, dst, regs[dst]))
                continue

            if bs and bs.kind in {"STATE_PTR","STATE_DERIVED"}:
                off = (bs.value or 0) + m.disp
                if off == CURRENT_ITEM_OFF:
                    regs[dst] = Sym("CURRENT_ITEM_VALUE", None, "state+0x264")
                    events.append(("FIELD_READ", x, dst, regs[dst]))
                else:
                    regs[dst] = Sym("STATE_MEM", off, f"state+0x{off:X}")
                continue

            regs[dst] = Sym("MEM", None, "unknown memory")
            continue

        # memory stores
        if x.mnemonic.startswith("str") and len(ops)>=2 and ops[1].type == ARM_OP_MEM:
            m = ops[1].mem
            bs = regs.get(m.base)
            if bs and bs.kind in {"STATE_PTR","STATE_DERIVED"}:
                off = (bs.value or 0) + m.disp
                if off == CURRENT_ITEM_OFF:
                    src = regs.get(ops[0].reg) if ops[0].type == ARM_OP_REG else None
                    events.append(("FIELD_WRITE", x, ops[0].reg if ops[0].type==ARM_OP_REG else None, src))
            continue

        # compare derived/current value
        if x.mnemonic.startswith("cmp"):
            involved = []
            for op in ops:
                if op.type == ARM_OP_REG:
                    s = regs.get(op.reg)
                    if s and s.kind == "CURRENT_ITEM_VALUE":
                        involved.append(x.reg_name(op.reg))
            if involved:
                events.append(("FIELD_COMPARE", x, None, Sym("COMPARE", None, ",".join(involved))))
            continue

        # +/-1 applied directly to current field value
        if x.mnemonic in {"adds","subs"} and dst is not None:
            pass

        # calls clobber caller-saved symbolic regs
        if x.mnemonic in {"bl","blx"}:
            for rid in list(regs):
                rn = x.reg_name(rid)
                if rn in {"r0","r1","r2","r3","r12","ip","lr"}:
                    regs.pop(rid, None)
            continue

        # generic writer invalidates dst
        if dst is not None:
            regs.pop(dst, None)

    # second pass: detect +/-1 from CURRENT_ITEM_VALUE
    # Use a simpler local pattern around reads.
    for idx, x in enumerate(xs):
        if x.mnemonic.startswith("ldr"):
            # does this instruction correspond to a FIELD_READ event?
            ev = next((e for e in events if e[0]=="FIELD_READ" and e[1].address==x.address), None)
            if not ev or not x.operands or x.operands[0].type != ARM_OP_REG:
                continue
            rid = x.operands[0].reg
            for y in xs[idx+1:idx+6]:
                if y.mnemonic in {"adds","subs"} and y.operands:
                    d = y.operands[0]
                    if d.type == ARM_OP_REG and d.reg == rid:
                        if any(op.type==ARM_OP_IMM and op.imm==1 for op in y.operands[1:]):
                            events.append(("PLUSMINUS1", y, rid, Sym("INDEX_CONVERSION", None, f"derived from read@0x{x.address:08X}")))
                if y.mnemonic in {"bl","blx","bx"}:
                    break

    return xs, events


def print_seed_candidate(img: Image, mode: str, seed, events):
    print()
    print("-" * 132)
    print(f"{img.name} {mode} seed: {fmt(seed)}")
    for kind, x, rid, sym in events:
        print(f"  {kind:<18} {fmt(x)} | {sym.desc if sym else ''}")

    if events:
        last = max(x.address for _,x,_,_ in events)
        end = min(img.end, last+0x20)
    else:
        end = min(img.end, seed.address+0x70)
    print("  context:")
    print_region(img, seed.address, end, mode, {x.address for _,x,_,_ in events})


def scan_image(img: Image):
    banner(f"C. STATE_GLOBAL XREF / EFFECTIVE FIELD SCAN — {img.name}")

    refs = real_literal_xrefs_for_value(img, STATE_GLOBAL)
    print(f"real literal xrefs to 0x{STATE_GLOBAL:08X} = {len(refs)}")

    candidates = []
    for mode, seed, la in refs:
        print(f"  {mode} {fmt(seed)} ; literal@0x{la:08X}")
        xs, events = sym_forward_from_state_seed(img, mode, seed)
        relevant = [e for e in events if e[0] in {"FIELD_READ","FIELD_WRITE","FIELD_COMPARE","PLUSMINUS1"}]
        if relevant:
            candidates.append((mode,seed,events))
            print_seed_candidate(img, mode, seed, events)

    reads = []
    writes = []
    converts = []
    compares = []

    for mode,seed,events in candidates:
        for e in events:
            if e[0] == "FIELD_READ":
                reads.append((mode,seed,e))
            elif e[0] == "FIELD_WRITE":
                writes.append((mode,seed,e))
            elif e[0] == "PLUSMINUS1":
                converts.append((mode,seed,e))
            elif e[0] == "FIELD_COMPARE":
                compares.append((mode,seed,e))

    print()
    print(f"effective state+0x264 readers = {len(reads)}")
    print(f"effective state+0x264 writers = {len(writes)}")
    print(f"+/-1 conversions after read   = {len(converts)}")
    print(f"direct compares after read     = {len(compares)}")

    return {
        "refs": refs,
        "candidates": candidates,
        "reads": reads,
        "writes": writes,
        "converts": converts,
        "compares": compares,
    }


def dump_siblings(zimage: Image):
    banner("B. F02D1E90 SIBLING-FUNCTION NEIGHBORHOOD")
    print("Dumping a bounded Thumb neighborhood; data words may appear as bogus instructions.")
    print_region(zimage, 0xF02D1E40, 0xF02D1EE0, "THUMB", {SETTER})

    # Promote likely small functions by local push/bx boundaries around setter.
    print()
    print("Potential nearby function starts:")
    for a in range(0xF02D1E40, 0xF02D1EE0, 2):
        x = decode1(zimage, a, "THUMB")
        if x and (is_prologue(x) or (x.mnemonic == "ldr" and "pc" not in x.op_str)):
            if a in {SETTER} or abs(a-SETTER) <= 0x40:
                print(f"  0x{a:08X}: {fmt(x)}")


def analyze_getter_shapes(results):
    """
    Promote likely getter candidates:
      FIELD_READ and a return within a short forward window,
      with no overwrite of the loaded register before return.
    """
    banner("D. GETTER / INDEX-CONVERSION CANDIDATES")
    total = 0

    for img_name, r in results.items():
        for mode, seed, e in r["reads"]:
            _, read_x, rid, _ = e
            img = next(i for i in IMAGES if i.name == img_name)
            xs = dis(img, read_x.address, min(img.end, read_x.address+0x30), mode)

            returned = False
            overwritten = False
            for x in xs[1:]:
                if x.operands and x.operands[0].type == ARM_OP_REG and x.operands[0].reg == rid:
                    # allow adds/subs #1 as transformation
                    if x.mnemonic not in {"adds","subs"}:
                        overwritten = True
                if x.mnemonic == "bx" and x.op_str.strip() == "lr":
                    returned = not overwritten
                    break
                if x.mnemonic == "pop" and "pc" in x.op_str:
                    returned = not overwritten
                    break

            if returned:
                total += 1
                print()
                print(f"[GETTER-LIKE] {img_name} {mode} read @0x{read_x.address:08X}")
                print_region(img, max(img.base, seed.address), min(img.end, read_x.address+0x24), mode, {read_x.address})

    if total == 0:
        print("No simple getter-like path auto-promoted.")
    print(f"getter-like candidates = {total}")
    return total


def parse_args():
    p = argparse.ArgumentParser()
    p.add_argument("--alice", default="research/f2/work/extracted/altice_alice/alice-py.bin")
    p.add_argument("--zimage", default="research/f2/work/extracted/altice_platform/zimage.bin")
    p.add_argument("--report", default="research/f2/work/reports/s13_5a15_platform_current_item_field_audit.txt")
    return p.parse_args()


def resolve(root: Path, s: str):
    p = Path(s)
    return p if p.is_absolute() else root / p


IMAGES: list[Image] = []


def main():
    global IMAGES
    args = parse_args()
    root = Path.cwd()

    report_path = resolve(root, args.report)
    report_path.parent.mkdir(parents=True, exist_ok=True)

    cap = io.StringIO()
    old = sys.stdout
    sys.stdout = Tee(old, cap)

    try:
        banner("S13.5A.15 - PLATFORM CURRENT-ITEM FIELD READER / GETTER AUDIT")
        print("STRICTLY OFFLINE")
        print("PHONE ACCESSED       : NO")
        print("FLASH MODIFIED       : NO")
        print("PATCH GENERATED      : NO")
        print("REPACK               : NO")
        print()
        print(f"STATE_GLOBAL     = 0x{STATE_GLOBAL:08X}")
        print(f"STATE_PTR_OFF    = 0x{STATE_PTR_OFF:X}")
        print(f"CURRENT_ITEM_OFF = 0x{CURRENT_ITEM_OFF:X}")
        print(f"KNOWN SETTER     = 0x{SETTER:08X}")

        banner("A. CANONICAL INPUTS")
        alice = verify(resolve(root,args.alice),"ALICE",ALICE_BASE,ALICE_SIZE,ALICE_SHA256)
        zimage = verify(resolve(root,args.zimage),"ZIMAGE",ZIMAGE_BASE,ZIMAGE_SIZE,ZIMAGE_SHA256)
        IMAGES = [alice,zimage]

        dump_siblings(zimage)

        results = {}
        for img in IMAGES:
            results[img.name] = scan_image(img)

        getter_count = analyze_getter_shapes(results)

        banner("E. DECISION GATE")
        total_reads = sum(len(r["reads"]) for r in results.values())
        total_writes = sum(len(r["writes"]) for r in results.values())
        total_conv = sum(len(r["converts"]) for r in results.values())
        total_cmp = sum(len(r["compares"]) for r in results.values())

        print(f"effective field readers      = {total_reads}")
        print(f"effective field writers      = {total_writes}")
        print(f"getter-like candidates       = {getter_count}")
        print(f"+/-1 conversions after read  = {total_conv}")
        print(f"direct compares after read    = {total_cmp}")
        print()

        if total_reads and (total_conv or getter_count):
            print("[PASS] The platform state field written by F02D1E90 is also consumed")
            print("       structurally. Inspect promoted reader/getter paths above.")
            if total_conv:
                print("[STRONG EVIDENCE] At least one reader performs +/-1 conversion,")
                print("       consistent with 1-based platform item <-> 0-based callback index.")
        elif total_reads:
            print("[PASS] Exact reader(s) of state+0x264 recovered.")
            print("[NEXT] Follow only those reader functions to determine item/highlight semantics.")
        else:
            print("[OPEN] No exact reader auto-recovered from literal-seeded paths.")
            print("[NEXT] Expand only F00BADA8 object access paths; do not broad-scan menu IDs.")

        print()
        print("INVARIANTS:")
        print("  F02D1E90(value) writes value to (*(F00BADA8+8))+0x264")
        print("  generic wrappers call F02D1E90(index0+1)")
        print("  same wrappers dispatch index0 to SELECT_CB")
        print("  SELECT_CB(index0) returns descriptor.children[index0]")
        print()
        print("CLASSIFICATION BEFORE THIS GATE:")
        print("  dispatcher argument = zero-based UI/list item index : STRONGLY SUPPORTED")
        print()
        print("STILL UNKNOWN:")
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
        report_path.write_text(cap.getvalue(), encoding="utf-8")


if __name__ == "__main__":
    raise SystemExit(main())
