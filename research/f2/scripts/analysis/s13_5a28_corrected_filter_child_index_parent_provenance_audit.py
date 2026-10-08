#!/usr/bin/env python3
"""
S13.5A.28 - CORRECTED FILTER VENEER / CHILD-ID-AT-INDEX / PARENT PROVENANCE AUDIT

STRICTLY OFFLINE / READ-ONLY.

A.27 correction:
  0x102FD050 and 0x102FD058 are pointer literal WORDS, not veneer starts.
  Therefore the standard 8-byte ARM veneers are expected at:
      0x102FD04C -> literal 0x102FD050 = 0xF02D4D11 -> F02D4D10 SET_FILTER_BIT
      0x102FD054 -> literal 0x102FD058 = 0xF02D5829 -> F02D5828 CLEAR_FILTER_BIT

Historical ALICE already shows:
  0x1035E1F0:
      GET_CHILD_COUNT(parent)
      for index=N-1..0:
          id = 0x102FBA3C(parent,index)
          0x102FD054(id)

  0x1036B3C4:
      same structural loop

Goals:
  1. Verify the corrected SET/CLEAR veneers byte-for-byte.
  2. Resolve 0x102FBA3C and classify its real target.
  3. Recover every real ALICE caller of SET/CLEAR.
  4. Recover exact r0 provenance at mutation callsites, especially
     feeder-call returns from 0x102FBA3C.
  5. Detect owner functions containing:
         GET_CHILD_COUNT + CHILD_AT_INDEX + SET/CLEAR
     and recover their direct callers / parent-ID provenance.
  6. Explicitly test whether B709 or known B709-family IDs reach those owners.
  7. Secondary: inspect the two exact F004C5AC item writers
     0x10316834 and 0x1034E3D4 and their real callers, without an
     unanchored global x32 scan.

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

# Corrected filter veneers
SET_VENEER = 0x102FD04C
SET_LITERAL = 0x102FD050
SET_PTR = 0xF02D4D11
SET_TARGET = 0xF02D4D10

CLEAR_VENEER = 0x102FD054
CLEAR_LITERAL = 0x102FD058
CLEAR_PTR = 0xF02D5829
CLEAR_TARGET = 0xF02D5828

# Registry/menu helpers
GET_CHILD_COUNT_VENEER = 0x102FC3EC
CHILD_AT_INDEX_VENEER = 0x102FBA3C

# Historical clear-all owner starts
HIST_CLEAR_OWNER_A = 0x1035E1F0
HIST_CLEAR_OWNER_B = 0x1036B3C4

# Item writers
ITEM_INSERT_SHIFTING = 0x10316834
ITEM_APPEND_RAW = 0x1034E3D4
ITEM_STORE_GLOBAL = 0xF004C5AC
ITEM_COUNT_GLOBAL = 0xF00B8094

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
    0x346C: "FIXED_PARENT_346C",
    0x3473: "FIXED_CHILD_3473",
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
    print("=" * 174)
    print(s)
    print("=" * 174)


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
        md = md_t
    else:
        a = addr & ~3
        md = md_a
    if not img.contains(a):
        return None
    off = img.off(a)
    xs = list(md.disasm(img.data[off:off+4], a, count=1))
    return xs[0] if xs else None


def dis(img: Image, start: int, end: int, mode="THUMB"):
    if mode == "THUMB":
        start &= ~1
        md = md_t
    else:
        start &= ~3
        md = md_a
    if start < img.base:
        start = img.base
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
            tag = KNOWN_IDS.get(li[3] & 0xFFFF, "")
            notes.append(
                f"literal@0x{li[2]:08X}=0x{li[3]:08X}->{li[0]}"
                + (f"<{tag}>" if tag else "")
            )
        print((">>> " if x.address in marks else "    ") + fmt(x) + ((" ; " + ", ".join(notes)) if notes else ""))


def resolve_arm_veneer(alice: Image, addr: int):
    x = decode1(alice, addr, "ARM")
    ptr = u32(alice.data, alice.off(addr + 4)) if alice.contains(addr + 4) else None
    if not x:
        return None
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

def build_call_index(alice: Image):
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


def callers(alice: Image, target: int):
    return build_call_index(alice).get(target & ~1, [])


def nearest_push(alice: Image, addr: int, max_back=0x180):
    best = None
    lo = max(alice.base, addr - max_back) & ~1
    for a in range(lo, addr + 1, 2):
        x = decode1(alice, a, "THUMB")
        if x and x.mnemonic == "push" and "lr" in x.op_str:
            best = a
    return best


def function_end_linear(alice: Image, start: int, max_len=0x220):
    xs = dis(alice, start, min(alice.end, start + max_len), "THUMB")
    for x in xs:
        if x.mnemonic == "pop" and "pc" in x.op_str:
            return x.address + x.size
        if x.mnemonic == "bx" and x.op_str.strip() == "lr":
            return x.address + x.size
    return min(alice.end, start + max_len)


def function_window(alice: Image, addr: int):
    st = nearest_push(alice, addr) or max(alice.base, addr - 0x80)
    en = function_end_linear(alice, st)
    if en <= addr:
        en = min(alice.end, addr + 0x120)
    return st, en


def reg_name_from_op(x, op):
    return x.reg_name(op.reg) if op.type == ARM_OP_REG else None


def provenance(alice: Image, call_addr: int, reg="r0", max_back=0x100):
    """
    Lightweight conservative forward state from nearest push to call.
    Tracks constants, aliases, memory loads, entry arguments, and previous-call return.
    """
    st = nearest_push(alice, call_addr, max_back) or max(alice.base, call_addr-max_back)
    vals = {
        "r0": ("ENTRY_ARG", "r0", st),
        "r1": ("ENTRY_ARG", "r1", st),
        "r2": ("ENTRY_ARG", "r2", st),
        "r3": ("ENTRY_ARG", "r3", st),
    }

    for x in dis(alice, st, call_addr, "THUMB"):
        li = literal_load(alice, x, "THUMB")
        if li:
            vals[li[0]] = ("CONST", li[3], x.address)
            continue

        ops = x.operands
        if x.mnemonic in {"mov", "movs"} and len(ops) >= 2 and ops[0].type == ARM_OP_REG:
            dst = reg_name_from_op(x, ops[0])
            if ops[1].type == ARM_OP_IMM:
                vals[dst] = ("CONST", ops[1].imm & 0xFFFFFFFF, x.address)
            elif ops[1].type == ARM_OP_REG:
                src = reg_name_from_op(x, ops[1])
                vals[dst] = vals.get(src, ("ALIAS_UNKNOWN", src, x.address))
            continue

        if x.mnemonic.startswith("ldr") and len(ops) >= 2 and ops[0].type == ARM_OP_REG and ops[1].type == ARM_OP_MEM:
            dst = reg_name_from_op(x, ops[0])
            base = reg_name_from_op(x, type("O", (), {"type": ARM_OP_REG, "reg": ops[1].mem.base})()) if ops[1].mem.base else "?"
            vals[dst] = ("MEM", f"[{base}{ops[1].mem.disp:+#x}]", x.address)
            continue

        if x.mnemonic in {"add", "adds", "sub", "subs"} and len(ops) >= 2 and ops[0].type == ARM_OP_REG:
            dst = reg_name_from_op(x, ops[0])
            sign = 1 if x.mnemonic.startswith("add") else -1
            if len(ops) >= 3 and ops[1].type == ARM_OP_REG and ops[2].type == ARM_OP_IMM:
                src = reg_name_from_op(x, ops[1])
                sv = vals.get(src)
                if sv and sv[0] == "CONST":
                    vals[dst] = ("CONST", (sv[1] + sign*ops[2].imm) & 0xFFFFFFFF, x.address)
                else:
                    vals[dst] = ("EXPR", x.op_str, x.address)
            elif len(ops) == 2 and ops[1].type == ARM_OP_IMM:
                sv = vals.get(dst)
                if sv and sv[0] == "CONST":
                    vals[dst] = ("CONST", (sv[1] + sign*ops[1].imm) & 0xFFFFFFFF, x.address)
                else:
                    vals[dst] = ("EXPR", x.op_str, x.address)
            continue

        if x.mnemonic in {"bl", "blx"}:
            t = direct_target(x)
            vals["r0"] = ("CALL_RETURN", t if t is not None else x.op_str, x.address)
            for r in ("r1", "r2", "r3", "r12"):
                vals.pop(r, None)

    return st, vals.get(reg, ("UNKNOWN", None, call_addr))


def prov_text(p):
    k, v, at = p
    if k == "CONST":
        tag = KNOWN_IDS.get(v & 0xFFFF, "")
        return f"CONST 0x{v:08X}" + (f" <{tag}>" if tag else "") + f" @0x{at:08X}"
    if k == "CALL_RETURN":
        if isinstance(v, int):
            return f"CALL_RETURN 0x{v:08X} @0x{at:08X}"
        return f"CALL_RETURN {v} @0x{at:08X}"
    return f"{k} {v} @0x{at:08X}"


def preceding_direct_call(alice: Image, addr: int, back=0x18):
    xs = dis(alice, max(alice.base, addr-back), addr, "THUMB")
    for x in reversed(xs):
        if x.mnemonic in {"bl", "blx"}:
            t = direct_target(x)
            if t is not None:
                return x, t
    return None, None


def raw_u16_occurs(img: Image, value: int, start: int, end: int):
    start = max(start, img.base)
    end = min(end, img.end)
    needle = struct.pack("<H", value & 0xFFFF)
    out = []
    off0 = img.off(start)
    off1 = img.off(end)
    pos = off0
    while True:
        pos = img.data.find(needle, pos, off1)
        if pos < 0:
            break
        out.append(img.base + pos)
        pos += 1
    return out


def section_corrected_veneers(alice, zimage):
    banner("B. CORRECTED FILTER VENEER VERIFICATION")
    results = {}
    specs = [
        ("SET_FILTER_BIT", SET_VENEER, SET_LITERAL, SET_PTR, SET_TARGET),
        ("CLEAR_FILTER_BIT", CLEAR_VENEER, CLEAR_LITERAL, CLEAR_PTR, CLEAR_TARGET),
    ]
    for label, va, la, expected_ptr, expected_target in specs:
        print()
        print(f"### {label}")
        vr = resolve_arm_veneer(alice, va)
        results[va] = vr
        if not vr:
            print(f"[FAIL] decode veneer 0x{va:08X}")
            continue
        print(f"veneer       = 0x{va:08X}")
        print(f"instruction  = {fmt(vr['insn'])}")
        print(f"recognized   = {vr['recognized']}")
        print(f"literal      = 0x{vr['literal']:08X}")
        print(f"pointer      = 0x{vr['ptr']:08X}")
        print(f"target       = 0x{vr['target']:08X}")
        print(f"mode         = {vr['mode']}")
        print(f"expected literal = 0x{la:08X}")
        print(f"expected ptr     = 0x{expected_ptr:08X}")
        print(f"expected target  = 0x{expected_target:08X}")
        ok = (
            vr["recognized"]
            and vr["literal"] == la
            and vr["ptr"] == expected_ptr
            and vr["target"] == expected_target
            and vr["mode"] == "THUMB"
        )
        print(f"[{'PASS' if ok else 'FAIL'}] exact corrected veneer contract")
        if zimage.contains(expected_target):
            print_region(zimage, expected_target, expected_target+0x48, "THUMB", marks={expected_target})
    return results


def section_child_at_index(alice, zimage):
    banner("C. 0x102FBA3C CHILD-AT-INDEX VENEER / TARGET")
    vr = resolve_arm_veneer(alice, CHILD_AT_INDEX_VENEER)
    if not vr:
        print("[FAIL] cannot decode 0x102FBA3C as ARM veneer")
        return None

    print(f"veneer instruction = {fmt(vr['insn'])}")
    print(f"recognized         = {vr['recognized']}")
    print(f"literal            = 0x{vr['literal']:08X}")
    print(f"target_ptr         = 0x{vr['ptr']:08X}")
    print(f"target             = 0x{vr['target']:08X}")
    print(f"mode               = {vr['mode']}")

    owner = alice if alice.contains(vr["target"]) else zimage if zimage.contains(vr["target"]) else None
    print(f"target owner       = {owner.name if owner else 'OUTSIDE'}")
    if owner:
        print_region(owner, vr["target"], min(owner.end, vr["target"]+0x120), vr["mode"], marks={vr["target"]})

        body = dis(owner, vr["target"], min(owner.end, vr["target"]+0x120), vr["mode"])
        loads_child_ptr = any(
            x.mnemonic.startswith("ldr")
            and len(x.operands) >= 2
            and x.operands[1].type == ARM_OP_MEM
            and x.operands[1].mem.disp == 0xC
            for x in body
        )
        has_u16_index = any(x.mnemonic.startswith("ldrh") for x in body)
        print()
        print(f"body has +0x0C pointer load = {loads_child_ptr}")
        print(f"body has u16 load           = {has_u16_index}")
        if loads_child_ptr and has_u16_index:
            print("[STRONGLY SUPPORTED] target is child-ID lookup/indexing compatible.")
        else:
            print("[OPEN] child-ID-at-index semantic requires caller structure.")
    return vr


def section_mutation_callers(alice):
    banner("D. REAL SET/CLEAR CALLERS + FEEDER PROVENANCE")
    summary = {}
    for target, label in [(SET_VENEER, "SET"), (CLEAR_VENEER, "CLEAR")]:
        cs = callers(alice, target)
        summary[target] = cs
        print()
        print(f"### {label}_FILTER_BIT veneer 0x{target:08X}")
        print(f"robust callers = {len(cs)}")
        consts = Counter()
        feeder_counts = Counter()

        for c in cs:
            st, p0 = provenance(alice, c.address, "r0", 0x140)
            if p0[0] == "CONST":
                consts[p0[1] & 0xFFFF] += 1
            pc, pt = preceding_direct_call(alice, c.address)
            if pt is not None:
                feeder_counts[pt & ~1] += 1

            print()
            print(f"CALL {fmt(c)} function≈0x{st:08X}")
            print(f"  r0 at mutation = {prov_text(p0)}")
            if pc:
                print(f"  previous call  = {fmt(pc)} target=0x{pt:08X}")
                # Arguments at previous call
                _, fp0 = provenance(alice, pc.address, "r0", 0x140)
                _, fp1 = provenance(alice, pc.address, "r1", 0x140)
                print(f"    feeder r0 = {prov_text(fp0)}")
                print(f"    feeder r1 = {prov_text(fp1)}")
            print_region(alice, max(st, c.address-0x24), min(alice.end, c.address+0x20), "THUMB", marks={c.address})

        if consts:
            print("constant ID census:")
            for v,n in consts.most_common():
                print(f"  0x{v:04X} x{n}" + (f" <{KNOWN_IDS[v]}>" if v in KNOWN_IDS else ""))
        else:
            print("constant ID census: <none>")

        if feeder_counts:
            print("immediate feeder-call census:")
            for t,n in feeder_counts.most_common():
                tag = " <CHILD_AT_INDEX_VENEER>" if t == CHILD_AT_INDEX_VENEER else ""
                print(f"  0x{t:08X} x{n}{tag}")
    return summary


def owner_functions_for_calls(alice, call_list):
    out = defaultdict(list)
    for c in call_list:
        st = nearest_push(alice, c.address, 0x1C0)
        if st is not None:
            out[st].append(c)
    return out


def direct_calls_in_function(alice, start, end):
    rows = []
    for x in dis(alice, start, end, "THUMB"):
        if x.mnemonic in {"bl", "blx"}:
            t = direct_target(x)
            if t is not None:
                rows.append((x, t & ~1))
    return rows


def section_owner_loops(alice, mutation_summary):
    banner("E. GET_CHILD_COUNT -> CHILD_AT_INDEX -> FILTER MUTATION OWNER FUNCTIONS")

    mutation_targets = {
        SET_VENEER: "SET",
        CLEAR_VENEER: "CLEAR",
    }

    owners = {}
    for mut_target, mut_calls in mutation_summary.items():
        for st, calls_here in owner_functions_for_calls(alice, mut_calls).items():
            en = function_end_linear(alice, st, 0x280)
            dcs = direct_calls_in_function(alice, st, en)
            targets = [t for _,t in dcs]
            shape = (
                (GET_CHILD_COUNT_VENEER & ~1) in targets
                and (CHILD_AT_INDEX_VENEER & ~1) in targets
                and (mut_target & ~1) in targets
            )
            owners[st] = {
                "end": en,
                "mutation": mutation_targets[mut_target],
                "shape": shape,
                "calls": dcs,
            }

    # Always include historical known owners even if approximate function finder missed.
    for st in (HIST_CLEAR_OWNER_A, HIST_CLEAR_OWNER_B):
        en = function_end_linear(alice, st, 0x180)
        dcs = direct_calls_in_function(alice, st, en)
        targets = [t for _,t in dcs]
        owners.setdefault(st, {
            "end": en,
            "mutation": "CLEAR",
            "shape": (
                (GET_CHILD_COUNT_VENEER & ~1) in targets
                and (CHILD_AT_INDEX_VENEER & ~1) in targets
                and (CLEAR_VENEER & ~1) in targets
            ),
            "calls": dcs,
        })

    shaped = {k:v for k,v in owners.items() if v["shape"]}
    print(f"candidate mutation owner functions = {len(owners)}")
    print(f"full COUNT+AT_INDEX+MUTATE shapes  = {len(shaped)}")

    for st, info in sorted(owners.items()):
        en = info["end"]
        print()
        print(f"### owner 0x{st:08X}..0x{en:08X} mutation={info['mutation']} full_shape={info['shape']}")
        print("direct call sequence:")
        for x,t in info["calls"]:
            tags = []
            if t == (GET_CHILD_COUNT_VENEER & ~1): tags.append("GET_CHILD_COUNT")
            if t == (CHILD_AT_INDEX_VENEER & ~1): tags.append("CHILD_AT_INDEX")
            if t == (SET_VENEER & ~1): tags.append("SET_FILTER")
            if t == (CLEAR_VENEER & ~1): tags.append("CLEAR_FILTER")
            print(f"  {fmt(x)} -> 0x{t:08X}" + (f" <{'|'.join(tags)}>" if tags else ""))

        b709 = raw_u16_occurs(alice, 0xB709, st, en)
        if b709:
            print("raw u16 B709 in owner:", " ".join(f"0x{x:08X}" for x in b709))

        print_region(alice, st, min(en, st+0x180), "THUMB")

        # Direct callers of owner
        cs = callers(alice, st)
        print(f"direct callers of owner = {len(cs)}")
        parent_consts = Counter()
        for c in cs:
            cst, p0 = provenance(alice, c.address, "r0", 0x160)
            print(f"  {fmt(c)} caller_function≈0x{cst:08X} r0(parent?)={prov_text(p0)}")
            if p0[0] == "CONST":
                parent_consts[p0[1] & 0xFFFF] += 1

        if parent_consts:
            print("owner parent-constant census:")
            for v,n in parent_consts.most_common():
                print(f"  0x{v:04X} x{n}" + (f" <{KNOWN_IDS[v]}>" if v in KNOWN_IDS else ""))

    print()
    print("Historical owners:")
    print(f"  0x{HIST_CLEAR_OWNER_A:08X} present = {HIST_CLEAR_OWNER_A in owners}")
    print(f"  0x{HIST_CLEAR_OWNER_B:08X} present = {HIST_CLEAR_OWNER_B in owners}")
    return shaped


def classify_arg_from_recent_calls(alice, call_addr, reg):
    """
    Extra diagnostic: walk the last ~0x20 bytes and report recent calls plus
    simple move-from-r0 into requested register.
    """
    xs = dis(alice, max(alice.base, call_addr-0x28), call_addr, "THUMB")
    recent = []
    for x in xs:
        if x.mnemonic in {"bl","blx"}:
            t = direct_target(x)
            recent.append(("CALL", x.address, t))
        elif x.mnemonic in {"mov","movs"} and len(x.operands)>=2:
            if x.operands[0].type == ARM_OP_REG and x.operands[1].type == ARM_OP_REG:
                d = x.reg_name(x.operands[0].reg)
                s = x.reg_name(x.operands[1].reg)
                if d == reg:
                    recent.append(("MOVE", x.address, s))
    return recent


def section_item_writers(alice):
    banner("F. ANCHORED F004C5AC+8 ITEM WRITERS / CALLERS")

    for target,label in [
        (ITEM_INSERT_SHIFTING, "ITEM_INSERT_SHIFTING"),
        (ITEM_APPEND_RAW, "ITEM_APPEND_RAW"),
    ]:
        print()
        print(f"### {label} @0x{target:08X}")
        en = function_end_linear(alice, target, 0x100)
        print_region(alice, target, en, "THUMB", marks={target})
        cs = callers(alice, target)
        print(f"robust callers = {len(cs)}")
        for c in cs:
            st,p0 = provenance(alice,c.address,"r0",0x100)
            _,p1 = provenance(alice,c.address,"r1",0x100)
            _,p2 = provenance(alice,c.address,"r2",0x100)
            print(f"  {fmt(c)} function≈0x{st:08X}")
            print(f"    r0 = {prov_text(p0)}")
            print(f"    r1 = {prov_text(p1)}")
            print(f"    r2 = {prov_text(p2)}")
            for ev in classify_arg_from_recent_calls(alice,c.address,"r0")[-5:]:
                print(f"    recent {ev}")

    print()
    print("Known exact field stores:")
    print("  0x10316834: item[index]+0x08 <- arg2 ; +0x10 <- arg1 (A.26 contract)")
    print("  0x1034E3D4: item[next]+0x08 <- r1 ; +0x10 <- r0 ; +0x0C <- 0")
    print("No global unanchored x32 field scan is used in A.28.")


def section_decision(veneers, child_vr, mutation_summary, shaped):
    banner("G. DECISION GATE")

    set_ok = veneers.get(SET_VENEER)
    clear_ok = veneers.get(CLEAR_VENEER)
    set_pass = bool(set_ok and set_ok["recognized"] and set_ok["ptr"] == SET_PTR)
    clr_pass = bool(clear_ok and clear_ok["recognized"] and clear_ok["ptr"] == CLEAR_PTR)

    print(f"corrected SET veneer   = {'PASS' if set_pass else 'OPEN'}")
    print(f"corrected CLEAR veneer = {'PASS' if clr_pass else 'OPEN'}")
    print(f"CHILD_AT_INDEX veneer  = {'PASS' if child_vr and child_vr['recognized'] else 'OPEN'}")
    print(f"SET callers            = {len(mutation_summary.get(SET_VENEER, []))}")
    print(f"CLEAR callers          = {len(mutation_summary.get(CLEAR_VENEER, []))}")
    print(f"COUNT+AT_INDEX+MUTATE owner shapes = {len(shaped)}")
    print()

    print("Promotion rules:")
    print("  FACT SET/CLEAR only if corrected veneers resolve exactly to F02D4D10/F02D5828.")
    print("  Promote 0x102FBA3C to CHILD_ID_AT_INDEX(parent,index) only if its body")
    print("  or the complete owner-loop contract proves returned u16 child-ID semantics.")
    print("  Promote B709 filter initialization only if B709 reaches an owner function")
    print("  through a structurally backed caller/provenance path.")
    print()

    print("A.27 corrections retained:")
    print("  - 0x102FD050/58 are literal words, not veneer starts.")
    print("  - A.27 zero SET/CLEAR callers is SUPERSEDED.")
    print("  - resource helper A/B exact subtype remains OPEN.")
    print("  - generic unanchored item-field scans are not evidence.")
    print()

    print("STILL UNKNOWN until this report closes them:")
    print("  exact B709 runtime filter initialization/mutation path")
    print("  exact raw-vs-filtered B709 alignment invariant")
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
    p = argparse.ArgumentParser()
    p.add_argument("--alice", default="research/f2/work/extracted/altice_alice/alice-py.bin")
    p.add_argument("--zimage", default="research/f2/work/extracted/altice_platform/zimage.bin")
    p.add_argument("--report", default="research/f2/work/reports/s13_5a28_corrected_filter_child_index_parent_provenance.txt")
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
        banner("S13.5A.28 - CORRECTED FILTER VENEER / CHILD-ID-AT-INDEX / PARENT PROVENANCE AUDIT")
        print("STRICTLY OFFLINE")
        print("PHONE ACCESSED       : NO")
        print("FLASH MODIFIED       : NO")
        print("PATCH GENERATED      : NO")
        print("REPACK               : NO")

        banner("A. CANONICAL INPUTS")
        alice = verify(resolve(root,args.alice), "ALICE", ALICE_BASE, ALICE_SIZE, ALICE_SHA256)
        zimage = verify(resolve(root,args.zimage), "ZIMAGE", ZIMAGE_BASE, ZIMAGE_SIZE, ZIMAGE_SHA256)

        # Build once.
        build_call_index(alice)

        veneers = section_corrected_veneers(alice,zimage)
        child_vr = section_child_at_index(alice,zimage)
        mutation_summary = section_mutation_callers(alice)
        shaped = section_owner_loops(alice, mutation_summary)
        section_item_writers(alice)
        section_decision(veneers, child_vr, mutation_summary, shaped)

        print()
        print(f"REPORT = {report}")
        return 0
    finally:
        sys.stdout = old
        report.write_text(cap.getvalue(), encoding="utf-8")


if __name__ == "__main__":
    raise SystemExit(main())
