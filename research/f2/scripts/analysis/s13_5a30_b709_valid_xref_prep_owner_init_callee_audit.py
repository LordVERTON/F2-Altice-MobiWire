#!/usr/bin/env python3
"""
S13.5A.30 - B709 REBUILD VALID-XREF / PREP OWNER / INIT-CALLEE AUDIT

STRICTLY OFFLINE / READ-ONLY.

Why A.30 exists
---------------
A.29 proved:
  FACT 0x10365A12:
      CLEAR B700
      CLEAR B702
      CLEAR B6FF
      call 0x10313998
  FACT bit CLEAR => F02D5458 returns 0 => filtered enumeration retains child.
  FACT 0x102FA57C -> ZIMAGE F0319854 (state/flag helper shape).

A.29 also exposed two scanner issues / open ownership questions:
  - 0x10365A12 has no direct BL/BLX caller and no raw 0x10365A13 pointer word.
  - a blind every-halfword scan reports a "call" to 0x10313998 at 0x102D1066,
    but the surrounding bytes do not decode as a plausible Thumb function.
  - the clearly valid rebuild owner 0x1032F2B8 calls 0x10332B88 immediately
    before 0x10313998, so 0x10332B88 may own relevant initialization.

A.30 goals
----------
1. Validate incoming edges with a local Thumb CFG, not blind halfword hits.
2. Search BL / BLX-immediate / B / B.W / conditional branches to:
       0x10365A12  B709 prep
       0x10313998  B709 rebuild
       0x1032F2B8  rebuild wrapper
       0x10332B88  pre-rebuild initializer/helper
3. Explicitly validate/reject A.29's 0x102D1066 candidate.
4. Audit raw pointer refs to target|1 and target in ALICE + ZIMAGE.
5. Decode the reachable CFG of 0x10332B88 and report:
       - calls to SET/CLEAR filter primitives
       - calls to B709 count/enum/rebuild
       - direct constant B709-family IDs
6. Walk ALICE callees from 0x10332B88 to depth 2 and report only functions
   that touch filter primitives, B709 providers/rebuild, or focus IDs.
7. Inspect nearby pointer topology around 0x10365A12 to see whether adjacent
   functions are table-owned while the prep function is not.
8. Preserve uncertainty if no owner is recovered. Absence is not reachability proof.

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
from collections import defaultdict, deque

from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_THUMB, CS_MODE_LITTLE_ENDIAN
from capstone.arm import ARM_OP_IMM, ARM_OP_MEM, ARM_OP_REG, ARM_REG_PC

ALICE_BASE = 0x1024EC00
ALICE_SIZE = 0x157BB4
ALICE_SHA256 = "7246242b67afae0d13104452bc3257827cb778119b54e7a26fb7fb55993697ea"

ZIMAGE_BASE = 0xF023CA50
ZIMAGE_SIZE = 0x185E98
ZIMAGE_SHA256 = "85fba8c8ae8161e4c1f8ced7983ec30d48c54ab10e51c69fcdfb900aca220954"

PREP = 0x10365A12
REBUILD = 0x10313998
REBUILD_WRAPPER = 0x1032F2B8
PRE_REBUILD = 0x10332B88

SET_VENEER = 0x102FD04C
CLEAR_VENEER = 0x102FD054
CHILD_AT_INDEX = 0x102FBA3C

COUNT_FILTERED_VENEER = 0x102FC51C
ENUM_FILTERED_VENEER = 0x102FC3CC
SELECTOR_VENEER = 0x102FC20C

B709 = 0xB709
FOCUS_IDS = {
    0xB709: "ROOT_B709",
    0xB700: "PREP_CLEAR",
    0xB702: "PREP_CLEAR",
    0xB6FF: "PREP_CLEAR",
    0xB701: "SELECTOR_S1_B709",
    0xB707: "SELECTOR_S1_B709",
    0x8321: "IMAGE_B",
    0x8928: "AUDIO",
}

TARGETS = {
    PREP: "B709_PREP",
    REBUILD: "B709_REBUILD",
    REBUILD_WRAPPER: "REBUILD_WRAPPER",
    PRE_REBUILD: "PRE_REBUILD",
}

INTERESTING_CALLS = {
    SET_VENEER: "SET_FILTER",
    CLEAR_VENEER: "CLEAR_FILTER",
    CHILD_AT_INDEX: "CHILD_AT_INDEX",
    COUNT_FILTERED_VENEER: "COUNT_FILTERED_CHILDREN(B709-capable)",
    ENUM_FILTERED_VENEER: "ENUM_FILTERED_CHILD_IDS(B709-capable)",
    SELECTOR_VENEER: "SELECTOR_LOOKUP",
    REBUILD: "B709_REBUILD",
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

    def contains(self, addr):
        a = addr & ~1
        return self.base <= a < self.end

    def off(self, addr):
        return (addr & ~1) - self.base


def banner(s):
    print()
    print("=" * 184)
    print(s)
    print("=" * 184)


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


def decode1(img: Image, addr, mode="THUMB"):
    if mode == "THUMB":
        a = addr & ~1
        md = md_t
    else:
        a = addr & ~3
        md = md_a
    if not img.contains(a):
        return None
    off = img.off(a)
    xs = list(md.disasm(img.data[off:off+4], a, count=1))
    return xs[0] if xs else None


def dis(img: Image, start, end, mode="THUMB"):
    md = md_t if mode == "THUMB" else md_a
    start = (start & ~1) if mode == "THUMB" else (start & ~3)
    start = max(start, img.base)
    end = min(end, img.end)
    if start >= end:
        return []
    return [x for x in md.disasm(img.data[img.off(start):img.off(end)], start) if x.address < end]


def fmt(x):
    return f"0x{x.address:08X}: {x.bytes.hex(' '):<16} {x.mnemonic:<10} {x.op_str}"


def direct_target(x):
    if not x or x.mnemonic not in {
        "b", "b.w", "bl", "blx",
        "beq", "bne", "bge", "bgt", "ble", "blt",
        "bhi", "bhs", "blo", "bls", "bpl", "bmi",
        "bcs", "bcc", "bvs", "bvc"
    }:
        return None
    if not x.operands:
        return None
    op = x.operands[0]
    return (op.imm & 0xFFFFFFFF) if op.type == ARM_OP_IMM else None


def is_call(x):
    return x.mnemonic in {"bl", "blx"} and direct_target(x) is not None


def is_uncond_branch(x):
    return x.mnemonic in {"b", "b.w"} and direct_target(x) is not None


def is_cond_branch(x):
    return x.mnemonic.startswith("b") and not is_call(x) and not is_uncond_branch(x) and direct_target(x) is not None


def is_return(x):
    if x.mnemonic == "bx" and x.op_str.strip() == "lr":
        return True
    if x.mnemonic == "pop" and "pc" in x.op_str:
        return True
    return False


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
    return x.reg_name(d.reg), la, u32(img.data, img.off(la))


def print_region(img, start, end, mode="THUMB", marks=None):
    marks = marks or set()
    for x in dis(img, start, end, mode):
        notes = []
        t = direct_target(x)
        if t is not None:
            nm = TARGETS.get(t & ~1) or INTERESTING_CALLS.get(t & ~1)
            notes.append(f"target=0x{t:08X}" + (f"<{nm}>" if nm else ""))
        li = literal_load(img, x, mode)
        if li:
            low = li[2] & 0xFFFF
            tag = FOCUS_IDS.get(low)
            notes.append(f"literal@0x{li[1]:08X}=0x{li[2]:08X}->{li[0]}" + (f"<{tag}>" if tag else ""))
        print((">>> " if x.address in marks else "    ") + fmt(x) + ((" ; " + ", ".join(notes)) if notes else ""))


def raw_words(img, value):
    needle = struct.pack("<I", value & 0xFFFFFFFF)
    out = []
    p = 0
    while True:
        p = img.data.find(needle, p)
        if p < 0:
            break
        out.append(img.base + p)
        p += 1
    return out


def raw_u16s(img, start, end, values):
    start = max(start, img.base)
    end = min(end, img.end)
    out = []
    for a in range(start, end - 1):
        v = u16(img.data, img.off(a))
        if v in values:
            out.append((a, v))
    return out


def nearest_push(img, addr, max_back=0x300):
    best = None
    lo = max(img.base, addr - max_back) & ~1
    for a in range(lo, addr + 1, 2):
        x = decode1(img, a, "THUMB")
        if x and x.mnemonic == "push" and "lr" in x.op_str:
            best = a
    return best


def cfg_thumb(img: Image, start: int, max_span=0x500, max_insns=1000):
    """
    Reachable Thumb CFG from an exact function entry.
    Calls do not transfer CFG ownership; execution continues at fallthrough.
    Conditional branches add target + fallthrough.
    Unconditional B adds target only.
    """
    start &= ~1
    lo = start
    hi = min(img.end, start + max_span)
    todo = deque([start])
    seen = set()
    order = []

    while todo and len(seen) < max_insns:
        a = todo.popleft() & ~1
        if a in seen or not (lo <= a < hi):
            continue
        x = decode1(img, a, "THUMB")
        if not x:
            continue
        seen.add(a)
        order.append(x)

        nxt = x.address + x.size
        if is_return(x):
            continue
        if is_uncond_branch(x):
            t = direct_target(x)
            if t is not None and lo <= (t & ~1) < hi:
                todo.append(t & ~1)
            continue
        if is_cond_branch(x):
            t = direct_target(x)
            if t is not None and lo <= (t & ~1) < hi:
                todo.append(t & ~1)
            if nxt < hi:
                todo.append(nxt)
            continue

        # BL/BLX immediate: callee separate, fallthrough continues.
        if nxt < hi:
            todo.append(nxt)

    order.sort(key=lambda x: x.address)
    return order, seen


def validate_candidate(img, xaddr):
    st = nearest_push(img, xaddr, 0x400)
    if st is None:
        return False, None, set()
    xs, seen = cfg_thumb(img, st, max_span=0x700)
    return (xaddr in seen), st, seen


def blind_edges_to(img, target):
    out = []
    for a in range(img.base & ~1, img.end - 3, 2):
        x = decode1(img, a, "THUMB")
        if not x:
            continue
        t = direct_target(x)
        if t is not None and (t & ~1) == (target & ~1):
            out.append(x)
    return out


def valid_edges_to(img, target):
    rows = []
    for x in blind_edges_to(img, target):
        ok, st, _ = validate_candidate(img, x.address)
        rows.append((x, ok, st))
    return rows


def function_focus_summary(img, start, max_span=0x600):
    xs, seen = cfg_thumb(img, start, max_span=max_span)
    calls = []
    lits = []
    raw_ids = raw_u16s(img, start, min(img.end, start+max_span), set(FOCUS_IDS))
    for x in xs:
        t = direct_target(x)
        if is_call(x) and t is not None:
            calls.append((x, t & ~1))
        li = literal_load(img, x, "THUMB")
        if li and (li[2] & 0xFFFF) in FOCUS_IDS:
            lits.append((x, li))
    return xs, calls, lits, raw_ids


def section_valid_xrefs(alice, zimage):
    banner("B. VALIDATED INCOMING CONTROL-FLOW EDGES")

    for target, name in TARGETS.items():
        print()
        print(f"### {name} 0x{target:08X}")
        rows = valid_edges_to(alice, target)
        print(f"ALICE blind branch/call hits = {len(rows)}")
        good = 0
        for x, ok, st in rows:
            if ok:
                good += 1
            print(f"  {'VALID' if ok else 'REJECT'} {fmt(x)} owner≈" + (f"0x{st:08X}" if st else "<none>"))
        print(f"ALICE CFG-valid edges = {good}")

        # Cross-image direct branch is unlikely because of range, but audit anyway.
        zrows = blind_edges_to(zimage, target)
        print(f"ZIMAGE blind branch/call hits = {len(zrows)}")
        for x in zrows[:20]:
            print(f"  {fmt(x)}")

    print()
    print("### Explicit A.29 suspicious hit 0x102D1066")
    x = decode1(alice, 0x102D1066, "THUMB")
    if x:
        ok, st, _ = validate_candidate(alice, 0x102D1066)
        print(f"{fmt(x)}")
        print(f"CFG validation = {'VALID' if ok else 'REJECT'} ; nearest push≈" + (f"0x{st:08X}" if st else "<none>"))
        if st:
            print_region(alice, max(alice.base, st), min(alice.end, st+0x90), "THUMB", marks={0x102D1066})
    else:
        print("decode failed")


def section_raw_ptrs(alice, zimage):
    banner("C. RAW POINTER / BODY-WORD OWNERSHIP")
    for target, name in TARGETS.items():
        print()
        print(f"### {name} 0x{target:08X}")
        for img in (alice, zimage):
            p1 = raw_words(img, target | 1)
            p0 = raw_words(img, target)
            print(f"{img.name}: ptr|1={len(p1)} body={len(p0)}")
            for a in p1[:20]:
                print(f"  ThumbPtr@0x{a:08X}=0x{target|1:08X}")
            for a in p0[:20]:
                print(f"  BodyWord@0x{a:08X}=0x{target:08X}")


def section_pre_rebuild(alice):
    banner("D. 0x10332B88 PRE-REBUILD FUNCTION CFG / DIRECT EFFECTS")
    xs, calls, lits, raw_ids = function_focus_summary(alice, PRE_REBUILD, max_span=0x700)
    print(f"reachable instructions = {len(xs)}")
    if xs:
        print(f"reachable range = 0x{min(x.address for x in xs):08X}..0x{max(x.address+x.size for x in xs):08X}")

    interesting_marks = set()
    for x,t in calls:
        if t in INTERESTING_CALLS:
            interesting_marks.add(x.address)
    for x,li in lits:
        interesting_marks.add(x.address)

    print_region(alice, PRE_REBUILD, min(alice.end, PRE_REBUILD+0x220), "THUMB", marks=interesting_marks)

    print()
    print("direct interesting calls:")
    n=0
    for x,t in calls:
        if t in INTERESTING_CALLS:
            n+=1
            print(f"  {fmt(x)} -> {INTERESTING_CALLS[t]}")
    if not n:
        print("  <none>")

    print("reachable literal focus IDs:")
    if lits:
        for x,li in lits:
            v=li[2]&0xFFFF
            print(f"  {fmt(x)} -> 0x{v:04X} <{FOCUS_IDS[v]}>")
    else:
        print("  <none>")

    # Raw u16 is supporting/noisy only.
    uniq=[]
    seen=set()
    for a,v in raw_ids:
        if v not in seen:
            seen.add(v); uniq.append((a,v))
    print("raw u16 focus IDs inside first 0x700 bytes (supporting only):")
    if uniq:
        for a,v in uniq[:30]:
            print(f"  0x{a:08X}: 0x{v:04X} <{FOCUS_IDS[v]}>")
    else:
        print("  <none>")


def section_transitive(alice):
    banner("E. TRANSITIVE ALICE CALLEES FROM 0x10332B88 (DEPTH <= 2)")

    q = deque([(PRE_REBUILD,0,[PRE_REBUILD])])
    visited=set()
    interesting_funcs=[]

    while q:
        st, depth, path = q.popleft()
        st &= ~1
        if st in visited or not alice.contains(st) or depth > 2:
            continue
        visited.add(st)

        xs,calls,lits,raw_ids=function_focus_summary(alice,st,max_span=0x500)
        touches=[]
        for x,t in calls:
            if t in INTERESTING_CALLS:
                touches.append((x,t))
        focus_lits=[(x,li) for x,li in lits]

        if touches or focus_lits:
            interesting_funcs.append((st,depth,path,touches,focus_lits))

        if depth < 2:
            for x,t in calls:
                if alice.contains(t) and t not in {
                    SET_VENEER,CLEAR_VENEER,CHILD_AT_INDEX,
                    COUNT_FILTERED_VENEER,ENUM_FILTERED_VENEER,SELECTOR_VENEER,
                    REBUILD,
                }:
                    # only obvious code-shaped callees
                    first=decode1(alice,t,"THUMB")
                    if first:
                        q.append((t,depth+1,path+[t]))

    print(f"visited ALICE callees = {len(visited)}")
    print(f"interesting functions = {len(interesting_funcs)}")
    for st,depth,path,touches,lits in interesting_funcs:
        print()
        print("path: " + " -> ".join(f"0x{x:08X}" for x in path))
        for x,t in touches:
            print(f"  CALL {fmt(x)} -> {INTERESTING_CALLS[t]}")
        for x,li in lits:
            v=li[2]&0xFFFF
            print(f"  LIT  {fmt(x)} -> 0x{v:04X} <{FOCUS_IDS[v]}>")


def section_wrapper_owner(alice, zimage):
    banner("F. 0x1032F2B8 REBUILD-WRAPPER OWNERSHIP")
    for target,name in [(REBUILD_WRAPPER,"REBUILD_WRAPPER"),(PRE_REBUILD,"PRE_REBUILD")]:
        print()
        print(f"### {name}")
        rows=valid_edges_to(alice,target)
        for x,ok,st in rows:
            print(f"  {'VALID' if ok else 'REJECT'} {fmt(x)} owner≈" + (f"0x{st:08X}" if st else "<none>"))
        for img in (alice,zimage):
            refs=raw_words(img,target|1)
            if refs:
                print(f"  {img.name} raw Thumb pointers:")
                for a in refs[:30]:
                    print(f"    0x{a:08X} -> 0x{target|1:08X}")


def section_prep_neighborhood(alice, zimage):
    banner("G. 0x10365A12 NEIGHBORHOOD POINTER TOPOLOGY")
    lo=PREP-0x180
    hi=PREP+0x180
    print_region(alice,lo,hi,"THUMB",marks={PREP})

    # Gather push-prologue candidates around prep and ask whether any are referenced.
    funcs=[]
    for a in range(lo & ~1, hi, 2):
        x=decode1(alice,a,"THUMB")
        if x and x.mnemonic=="push" and "lr" in x.op_str:
            funcs.append(a)

    print()
    print("nearby push-prologue candidates and ownership evidence:")
    for st in funcs:
        edge_count=sum(1 for x,ok,_ in valid_edges_to(alice,st) if ok)
        ptr_a=len(raw_words(alice,st|1))
        ptr_z=len(raw_words(zimage,st|1))
        mark=" <TARGET_PREP>" if st==PREP else ""
        print(f"  0x{st:08X}{mark}: valid_edges={edge_count} ALICE_ptr={ptr_a} ZIMAGE_ptr={ptr_z}")


def section_decision():
    banner("H. DECISION GATE")
    print("Promotion rules:")
    print("  - Reject blind halfword call hits unless candidate instruction is reachable")
    print("    from a plausible Thumb push-prologue CFG.")
    print("  - 0x10365A12 ownership becomes FACT only from a valid incoming control-flow")
    print("    edge, a structurally consumed pointer/table entry, or equivalent exact evidence.")
    print("  - Do not infer B709 direct-child membership from CLEAR alone.")
    print("  - If 0x10332B88 or a transitive callee establishes bitmap initialization")
    print("    before 0x10313998, use that exact state to revisit raw-vs-filtered alignment.")
    print()
    print("Known retained FACT from A.29:")
    print("  0x10365A12 CLEARs B700, B702, B6FF then calls 0x10313998.")
    print("  bit CLEAR => filtered B709 enumeration retains that ID if encountered.")
    print()
    print("STILL UNKNOWN unless sections B-G close them:")
    print("  invocation owner of 0x10365A12")
    print("  exact complete bitmap state before each B709 rebuild")
    print("  exact raw children[B709]")
    print("  exact filtered children[B709]")
    print("  raw-vs-filtered index alignment invariant")
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


def parse_args():
    p=argparse.ArgumentParser()
    p.add_argument("--alice",default="research/f2/work/extracted/altice_alice/alice-py.bin")
    p.add_argument("--zimage",default="research/f2/work/extracted/altice_platform/zimage.bin")
    p.add_argument("--report",default="research/f2/work/reports/s13_5a30_b709_valid_xref_prep_owner_init_callee.txt")
    return p.parse_args()


def resolve(root,p):
    q=Path(p)
    return q if q.is_absolute() else root/q


def main():
    args=parse_args()
    root=Path.cwd()
    report=resolve(root,args.report)
    report.parent.mkdir(parents=True,exist_ok=True)

    cap=io.StringIO()
    old=sys.stdout
    sys.stdout=Tee(old,cap)
    try:
        banner("S13.5A.30 - B709 REBUILD VALID-XREF / PREP OWNER / INIT-CALLEE AUDIT")
        print("STRICTLY OFFLINE")
        print("PHONE ACCESSED       : NO")
        print("FLASH MODIFIED       : NO")
        print("PATCH GENERATED      : NO")
        print("REPACK               : NO")

        banner("A. CANONICAL INPUTS")
        alice=verify(resolve(root,args.alice),"ALICE",ALICE_BASE,ALICE_SIZE,ALICE_SHA256)
        zimage=verify(resolve(root,args.zimage),"ZIMAGE",ZIMAGE_BASE,ZIMAGE_SIZE,ZIMAGE_SHA256)

        section_valid_xrefs(alice,zimage)
        section_raw_ptrs(alice,zimage)
        section_pre_rebuild(alice)
        section_transitive(alice)
        section_wrapper_owner(alice,zimage)
        section_prep_neighborhood(alice,zimage)
        section_decision()

        print()
        print(f"REPORT = {report}")
        return 0
    finally:
        sys.stdout=old
        report.write_text(cap.getvalue(),encoding="utf-8")


if __name__=="__main__":
    raise SystemExit(main())
