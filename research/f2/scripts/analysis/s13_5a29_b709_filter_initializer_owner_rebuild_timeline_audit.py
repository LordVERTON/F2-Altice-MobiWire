#!/usr/bin/env python3
"""
S13.5A.29 - B709 FILTER INITIALIZER OWNER / REBUILD TIMELINE AUDIT

STRICTLY OFFLINE / READ-ONLY.

A.28 established:
  FACT 0x102FD04C -> F02D4D10 = bitmap SET primitive.
  FACT 0x102FD054 -> F02D5828 = bitmap CLEAR primitive.
  FACT 0x102FBA3C -> F02D8178 returns registry[parent].children[index] (u16).
  FACT F02D5458 returns 1 iff the corresponding F00C1624 bit is SET.
  FACT filtered enumeration retains only predicate == 0 (bit CLEAR).

Critical A.28 sequence:
  0x10365A12:
      ...
      CLEAR B700
      CLEAR B702
      CLEAR B6FF
      call 0x10313998

  0x10313998:
      enumerates FILTERED children[B709]
      transforms selector 8
      writes F00B7994[]

A.29 goals:
  1. Recover ownership/invocation of 0x10365A12:
       - direct calls
       - raw Thumb-pointer refs (0x10365A13)
       - real literal xrefs to those pointer words
       - ARM veneers / callback-table use
  2. Resolve 0x102FA57C and inspect its exact target semantics.
  3. Recover ALL direct callers and raw pointer refs of 0x10313998.
  4. Build an ordered mutation timeline for B709-family/static-selector IDs
     at SET/CLEAR callsites with improved constant propagation:
       MOV/MOVS, literal loads, ADD/SUB, LSL/LSR, aliases.
  5. For every call to 0x10313998, report all preceding SET/CLEAR events
     in the same enclosing function and identify the resulting known
     retained (bit-clear) IDs.
  6. Explicitly classify the 0x10365A12 sequence:
       B700, B702, B6FF -> bit clear -> retained by F02D5458 filter.
     Do NOT promote them to direct children[B709] unless separate structural
     membership evidence exists.
  7. Search for B709/B700/B702/B6FF/B701/B707 around the owner pointer refs
     and callback registration sites.

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
from capstone.arm import ARM_OP_IMM, ARM_OP_MEM, ARM_OP_REG, ARM_REG_PC

ALICE_BASE = 0x1024EC00
ALICE_SIZE = 0x157BB4
ALICE_SHA256 = "7246242b67afae0d13104452bc3257827cb778119b54e7a26fb7fb55993697ea"

ZIMAGE_BASE = 0xF023CA50
ZIMAGE_SIZE = 0x185E98
ZIMAGE_SHA256 = "85fba8c8ae8161e4c1f8ced7983ec30d48c54ab10e51c69fcdfb900aca220954"

SET_VENEER = 0x102FD04C
CLEAR_VENEER = 0x102FD054
FILTER_PRED = 0xF02D5458
FILTER_BITMAP = 0xF00C1624

B709_REBUILD = 0x10313998
B709_PREP = 0x10365A12
B709_PREP_PTR = B709_PREP | 1
PREP_HELPER_VENEER = 0x102FA57C

B709 = 0xB709

# Static selector-table keys seen in A.25/A.26.
SELECTOR_KEYS = {
    0x87ED, 0xBA3C, 0x8321,
    0xB6FD, 0xB6FE, 0xB6FF, 0xB700, 0xB701, 0xB702, 0xB703,
    0xB704, 0xB705, 0xA223, 0x7F67, 0xB708, 0xB707, 0xAF2A, 0x9639,
}

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
    print("=" * 176)
    print(s)
    print("=" * 176)


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
    if mode == "THUMB":
        start &= ~1
        md = md_t
    else:
        start &= ~3
        md = md_a
    start = max(start, img.base)
    end = min(end, img.end)
    if start >= end:
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
    return x.reg_name(d.reg), la, u32(img.data, img.off(la))


def print_region(img, start, end, mode="THUMB", marks=None):
    marks = marks or set()
    for x in dis(img, start, end, mode):
        notes = []
        t = direct_target(x)
        if t is not None:
            notes.append(f"target=0x{t:08X}")
        li = literal_load(img, x, mode)
        if li:
            tag = FOCUS_IDS.get(li[2] & 0xFFFF, "")
            notes.append(f"literal@0x{li[1]:08X}=0x{li[2]:08X}->{li[0]}" + (f"<{tag}>" if tag else ""))
        print((">>> " if x.address in marks else "    ") + fmt(x) + ((" ; " + ", ".join(notes)) if notes else ""))


def resolve_arm_veneer(alice: Image, addr):
    x = decode1(alice, addr, "ARM")
    if not x:
        return None
    ptr = u32(alice.data, alice.off(addr+4)) if alice.contains(addr+4) else None
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
        "literal": addr + 4,
        "ptr": ptr,
        "target": (ptr & ~1) if ptr is not None else None,
        "mode": "THUMB" if (ptr or 0) & 1 else "ARM",
    }


_CALL_INDEX = None
def build_call_index(alice):
    global _CALL_INDEX
    if _CALL_INDEX is not None:
        return _CALL_INDEX
    idx = defaultdict(list)
    for a in range(alice.base & ~1, alice.end - 3, 2):
        x = decode1(alice, a, "THUMB")
        if not x or x.mnemonic not in {"bl", "blx"}:
            continue
        t = direct_target(x)
        if t is not None:
            idx[t & ~1].append(x)
    _CALL_INDEX = idx
    return idx


def callers(alice, target):
    return build_call_index(alice).get(target & ~1, [])


def nearest_push(alice, addr, max_back=0x180):
    best = None
    lo = max(alice.base, addr-max_back) & ~1
    for a in range(lo, addr+1, 2):
        x = decode1(alice, a, "THUMB")
        if x and x.mnemonic == "push" and "lr" in x.op_str:
            best = a
    return best


def function_end(alice, start, max_len=0x300):
    for x in dis(alice, start, min(alice.end, start+max_len), "THUMB"):
        if x.mnemonic == "pop" and "pc" in x.op_str:
            return x.address + x.size
        if x.mnemonic == "bx" and x.op_str.strip() == "lr":
            return x.address + x.size
    return min(alice.end, start+max_len)


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


def raw_u16_near(img, start, end, values):
    start = max(start, img.base)
    end = min(end, img.end)
    out = []
    for a in range(start, end-1):
        v = u16(img.data, img.off(a))
        if v in values:
            out.append((a, v))
    return out


def real_literal_xrefs_to_word(img, word_addr, mode):
    md = md_t if mode == "THUMB" else md_a
    step = 2 if mode == "THUMB" else 4
    out = []
    start = img.base & ~(step-1)
    for a in range(start, img.end-3, step):
        x = decode1(img, a, mode)
        if not x:
            continue
        li = literal_load(img, x, mode)
        if li and li[1] == word_addr:
            out.append(x)
    return out


def all_literal_xrefs(img, word_addr):
    return (
        [("THUMB", x) for x in real_literal_xrefs_to_word(img, word_addr, "THUMB")]
        + [("ARM", x) for x in real_literal_xrefs_to_word(img, word_addr, "ARM")]
    )


def section_prep_ownership(alice, zimage):
    banner("B. 0x10365A12 B709-PREP OWNERSHIP / INDIRECT INVOCATION")

    print(f"direct callers of 0x{B709_PREP:08X} = {len(callers(alice, B709_PREP))}")
    for c in callers(alice, B709_PREP):
        st = nearest_push(alice, c.address) or c.address
        print(f"  {fmt(c)} function≈0x{st:08X}")

    for img in (alice, zimage):
        print()
        print(f"### {img.name}: raw words == Thumb pointer 0x{B709_PREP_PTR:08X}")
        refs = raw_words(img, B709_PREP_PTR)
        print(f"count = {len(refs)}")
        for wa in refs:
            print(f"PTR@0x{wa:08X}=0x{B709_PREP_PTR:08X}")
            xrefs = all_literal_xrefs(img, wa)
            print(f"  real literal xrefs = {len(xrefs)}")
            for mode,x in xrefs:
                print(f"    {mode} {fmt(x)}")
                if img is alice and mode == "THUMB":
                    st = nearest_push(alice, x.address, 0x200) or max(alice.base, x.address-0x60)
                    en = min(alice.end, function_end(alice, st, 0x260))
                    print(f"      owner≈0x{st:08X}..0x{en:08X}")
                    near = raw_u16_near(alice, max(st, x.address-0x80), min(en, x.address+0x120), set(FOCUS_IDS))
                    if near:
                        print("      nearby focus u16:")
                        for a,v in near[:20]:
                            print(f"        0x{a:08X}: 0x{v:04X} <{FOCUS_IDS[v]}>")
                    print_region(alice, max(st,x.address-0x30), min(en,x.address+0x60), "THUMB", marks={x.address})
                elif img is zimage:
                    start = max(zimage.base, x.address-0x40)
                    end = min(zimage.end, x.address+0x80)
                    print_region(zimage, start, end, mode, marks={x.address})

    # also search pointer with low bit clear, in case stored as body address
    for img in (alice, zimage):
        refs = raw_words(img, B709_PREP)
        if refs:
            print()
            print(f"{img.name}: raw words == body 0x{B709_PREP:08X}: {len(refs)}")
            for wa in refs:
                print(f"  0x{wa:08X}")


def section_prep_helper(alice, zimage):
    banner("C. 0x102FA57C PREP HELPER VENEER / REAL TARGET")
    vr = resolve_arm_veneer(alice, PREP_HELPER_VENEER)
    if not vr:
        print("[OPEN] 0x102FA57C is not recognized as standard ARM veneer")
        print_region(alice, PREP_HELPER_VENEER-0x10, PREP_HELPER_VENEER+0x30, "ARM")
        return None

    print(f"instruction = {fmt(vr['insn'])}")
    print(f"recognized  = {vr['recognized']}")
    print(f"literal     = 0x{vr['literal']:08X}")
    print(f"target_ptr  = 0x{vr['ptr']:08X}")
    print(f"target      = 0x{vr['target']:08X}")
    print(f"mode        = {vr['mode']}")
    owner = alice if alice.contains(vr["target"]) else zimage if zimage.contains(vr["target"]) else None
    print(f"owner       = {owner.name if owner else 'OUTSIDE'}")
    if owner:
        print_region(owner, vr["target"], min(owner.end, vr["target"]+0x140), vr["mode"], marks={vr["target"]})
    return vr


def section_rebuild_refs(alice, zimage):
    banner("D. 0x10313998 B709 REBUILD OWNERSHIP")
    cs = callers(alice, B709_REBUILD)
    print(f"direct ALICE callers = {len(cs)}")
    for c in cs:
        st = nearest_push(alice, c.address, 0x180) or c.address
        print(f"  {fmt(c)} function≈0x{st:08X}")

    ptr = B709_REBUILD | 1
    for img in (alice,zimage):
        refs = raw_words(img, ptr)
        print(f"{img.name}: raw Thumb-pointer words 0x{ptr:08X} = {len(refs)}")
        for wa in refs:
            print(f"  PTR@0x{wa:08X}")
            for mode,x in all_literal_xrefs(img,wa):
                print(f"    {mode} {fmt(x)}")


def regn(x, op):
    if op.type != ARM_OP_REG:
        return None
    return x.reg_name(op.reg)


def const_flow_events(alice, start, end):
    """
    Linear constant propagation for mutation census.
    Good for straight-line initializer blocks. Branch-sensitive semantics are
    not claimed from this pass.
    """
    vals = {}
    events = []
    for x in dis(alice, start, end, "THUMB"):
        li = literal_load(alice, x, "THUMB")
        if li:
            vals[li[0]] = li[2] & 0xFFFFFFFF
            continue

        ops = x.operands

        if x.mnemonic in {"mov","movs"} and len(ops)>=2 and ops[0].type==ARM_OP_REG:
            d = regn(x,ops[0])
            if ops[1].type == ARM_OP_IMM:
                vals[d] = ops[1].imm & 0xFFFFFFFF
            elif ops[1].type == ARM_OP_REG:
                s = regn(x,ops[1])
                if s in vals:
                    vals[d] = vals[s]
                else:
                    vals.pop(d,None)
            continue

        if x.mnemonic in {"add","adds","sub","subs"} and len(ops)>=2 and ops[0].type==ARM_OP_REG:
            d = regn(x,ops[0])
            sign = 1 if x.mnemonic.startswith("add") else -1

            if len(ops) >= 3 and ops[1].type == ARM_OP_REG and ops[2].type == ARM_OP_IMM:
                s = regn(x,ops[1])
                if s in vals:
                    vals[d] = (vals[s] + sign*ops[2].imm) & 0xFFFFFFFF
                else:
                    vals.pop(d,None)
            elif len(ops) == 2 and ops[1].type == ARM_OP_IMM:
                if d in vals:
                    vals[d] = (vals[d] + sign*ops[1].imm) & 0xFFFFFFFF
                else:
                    vals.pop(d,None)
            else:
                vals.pop(d,None)
            continue

        if x.mnemonic in {"lsl","lsls","lsr","lsrs"} and len(ops)>=2 and ops[0].type==ARM_OP_REG:
            d = regn(x,ops[0])
            if len(ops)>=3 and ops[1].type==ARM_OP_REG and ops[2].type==ARM_OP_IMM:
                s = regn(x,ops[1])
                if s in vals:
                    sh = ops[2].imm
                    vals[d] = ((vals[s] << sh) if x.mnemonic.startswith("lsl") else (vals[s] >> sh)) & 0xFFFFFFFF
                else:
                    vals.pop(d,None)
            elif len(ops)==2 and ops[1].type==ARM_OP_IMM:
                if d in vals:
                    sh=ops[1].imm
                    vals[d] = ((vals[d] << sh) if x.mnemonic.startswith("lsl") else (vals[d] >> sh)) & 0xFFFFFFFF
                else:
                    vals.pop(d,None)
            continue

        if x.mnemonic in {"bl","blx"}:
            t = direct_target(x)
            if t in {SET_VENEER,CLEAR_VENEER}:
                rid = vals.get("r0")
                events.append({
                    "addr": x.address,
                    "kind": "SET" if t == SET_VENEER else "CLEAR",
                    "id": (rid & 0xFFFF) if rid is not None else None,
                    "r0_full": rid,
                })
            # Normal calls clobber r0-r3.
            for r in ("r0","r1","r2","r3","r12"):
                vals.pop(r,None)
            continue

        # Conservative invalidation for explicit writes to a register.
        if ops and ops[0].type == ARM_OP_REG and x.mnemonic not in {"cmp","cmn","tst"}:
            d = regn(x,ops[0])
            if d and d in vals and x.mnemonic.startswith(("ldr","ldrb","ldrh")):
                vals.pop(d,None)

    return events


def section_mutation_timeline(alice):
    banner("E. B709-FAMILY / SELECTOR-KEY BITMAP MUTATION TIMELINE")

    funcs = set()
    for t in (SET_VENEER,CLEAR_VENEER):
        for c in callers(alice,t):
            st = nearest_push(alice,c.address,0x200)
            if st is not None:
                funcs.add(st)

    interesting = []
    for st in sorted(funcs):
        en = function_end(alice,st,0x300)
        evs = const_flow_events(alice,st,en)
        rel = [e for e in evs if e["id"] in SELECTOR_KEYS or e["id"] in FOCUS_IDS]
        if rel:
            interesting.append((st,en,rel))
            print()
            print(f"function 0x{st:08X}..0x{en:08X}")
            for e in rel:
                tag = FOCUS_IDS.get(e["id"], "")
                print(f"  0x{e['addr']:08X} {e['kind']:<5} 0x{e['id']:04X}" + (f" <{tag}>" if tag else ""))

    print()
    print(f"functions with constant mutations in selector/B709 domain = {len(interesting)}")
    return interesting


def section_rebuild_predecessors(alice):
    banner("F. FILTER MUTATIONS PRECEDING EACH 0x10313998 REBUILD")

    rebuild_calls = callers(alice,B709_REBUILD)
    print(f"direct rebuild calls = {len(rebuild_calls)}")

    for c in rebuild_calls:
        st = nearest_push(alice,c.address,0x220)
        if st is None:
            st=max(alice.base,c.address-0x100)
        print()
        print(f"REBUILD CALL {fmt(c)} owner≈0x{st:08X}")
        evs = const_flow_events(alice,st,c.address)
        if not evs:
            print("  preceding constant SET/CLEAR events = <none>")
        else:
            for e in evs:
                rid = e["id"]
                tag = FOCUS_IDS.get(rid, "") if rid is not None else ""
                print(
                    f"  0x{e['addr']:08X} {e['kind']:<5} "
                    + (f"0x{rid:04X}" if rid is not None else "<dynamic>")
                    + (f" <{tag}>" if tag else "")
                )

        clear_focus = {e["id"] for e in evs if e["kind"]=="CLEAR" and e["id"] in {0xB700,0xB702,0xB6FF}}
        if clear_focus == {0xB700,0xB702,0xB6FF}:
            print("  [PASS] exact prep trio cleared before this rebuild: B700, B702, B6FF")
            print("  [FACT] at this point their predicate bits are 0, therefore each would be retained IF it is enumerated as a B709 child.")
        print_region(alice,max(st,c.address-0x40),min(alice.end,c.address+0x10),"THUMB",marks={c.address})


def section_exact_prep(alice):
    banner("G. EXACT 0x10365A12 PREP CLASSIFICATION")
    print_region(alice,B709_PREP,B709_PREP+0x2A,"THUMB",marks={0x10365A20,0x10365A28,0x10365A30,0x10365A34})

    evs = const_flow_events(alice,B709_PREP,B709_PREP+0x26)
    print("mutation events:")
    for e in evs:
        rid=e["id"]
        print(f"  0x{e['addr']:08X} {e['kind']} " + (f"0x{rid:04X}" if rid is not None else "<dynamic>"))

    ids=[e["id"] for e in evs if e["kind"]=="CLEAR"]
    exact = ids[:3] == [0xB700,0xB702,0xB6FF]
    print(f"exact ordered CLEAR trio B700,B702,B6FF = {'PASS' if exact else 'OPEN'}")
    print("Known predicate semantic:")
    print("  bit SET   -> F02D5458 returns 1 -> filtered enumeration SKIPS child")
    print("  bit CLEAR -> F02D5458 returns 0 -> filtered enumeration RETAINS child")
    if exact:
        print("[FACT] 0x10365A12 deliberately makes B700/B702/B6FF pass the bitmap predicate before calling 0x10313998.")
        print("[CAUTION] This does NOT alone prove that all three are direct children[B709].")


def section_decision(alice):
    banner("H. DECISION GATE")
    print("A.28 retained FACTs:")
    print("  SET/CLEAR veneers are exact bitmap OR/BIC primitives over F00C1624.")
    print("  0x102FBA3C returns registry[parent].children[index] u16.")
    print("  F02D5458: bit set => skipped, bit clear => retained.")
    print()
    print("A.29 promotion targets:")
    print("  0x10365A12 invocation owner recovered via pointer/registration = PASS/OPEN from section B.")
    print("  0x102FA57C semantic classification = PASS/OPEN from section C.")
    print("  B709 rebuild caller census = section D.")
    print("  B709-domain mutation timeline = section E/F.")
    print()
    print("Current safe statement before running A.29:")
    print("  B700/B702/B6FF are explicitly CLEARed immediately before a B709 filtered-child rebuild.")
    print("  Therefore they are guaranteed predicate-retained if encountered by that rebuild.")
    print("  Direct membership in children[B709] remains separate evidence.")
    print()
    print("STILL UNKNOWN:")
    print("  exact raw children[B709]")
    print("  exact complete filtered children[B709]")
    print("  whether any earlier raw B709 child remains SET and causes index compression")
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
    p.add_argument("--report",default="research/f2/work/reports/s13_5a29_b709_filter_initializer_owner_rebuild_timeline.txt")
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
        banner("S13.5A.29 - B709 FILTER INITIALIZER OWNER / REBUILD TIMELINE AUDIT")
        print("STRICTLY OFFLINE")
        print("PHONE ACCESSED       : NO")
        print("FLASH MODIFIED       : NO")
        print("PATCH GENERATED      : NO")
        print("REPACK               : NO")

        banner("A. CANONICAL INPUTS")
        alice=verify(resolve(root,args.alice),"ALICE",ALICE_BASE,ALICE_SIZE,ALICE_SHA256)
        zimage=verify(resolve(root,args.zimage),"ZIMAGE",ZIMAGE_BASE,ZIMAGE_SIZE,ZIMAGE_SHA256)
        build_call_index(alice)

        section_prep_ownership(alice,zimage)
        section_prep_helper(alice,zimage)
        section_rebuild_refs(alice,zimage)
        section_mutation_timeline(alice)
        section_rebuild_predecessors(alice)
        section_exact_prep(alice)
        section_decision(alice)

        print()
        print(f"REPORT = {report}")
        return 0
    finally:
        sys.stdout=old
        report.write_text(cap.getvalue(),encoding="utf-8")


if __name__=="__main__":
    raise SystemExit(main())
