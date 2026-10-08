#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
S13.5A.32 - FILTER BITMAP PROVENANCE / SEMANTICS / PRE-B709 PATH AUDIT

STRICTLY OFFLINE:
- no USB / COM
- no DA upload
- no D3 / D5 / D6
- no write / erase
- no phone access

Purpose
-------
S13.5A.31 proved that the event-0x7485 initialization chain preceding the
B709 rebuild reaches a ZIMAGE function at 0xF02EE32C which references both:
  * filter bound/global : 0xF007F04C
  * filter bitmap       : 0xF00C1624
but A.31 did not preserve the exact root->callee provenance path nor the
semantics of 0xF02EE32C.

A.32 therefore:
  1. reconstructs the exact pre-B709 call graph from 0x102D100C;
  2. reports every shortest root path reaching 0xF02EE32C;
  3. prints the exact caller/callsite context on those paths;
  4. disassembles 0xF02EE32C and its direct callees;
  5. audits SET/CLEAR/PREDICATE filter primitives for comparison;
  6. finds exact PC-literal xrefs to 0xF00C1624 / 0xF007F04C in both images;
  7. reports focused raw literals for B709/B700/B702/B6FF/8928.

This script intentionally refuses to modify any input and never authorizes
hardware mutation on its own.
"""

from __future__ import annotations

import argparse
import hashlib
import struct
from collections import deque, defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Set, Tuple

try:
    from capstone import (
        Cs,
        CS_ARCH_ARM,
        CS_MODE_ARM,
        CS_MODE_LITTLE_ENDIAN,
        CS_MODE_THUMB,
        CS_GRP_CALL,
        CS_GRP_JUMP,
        CS_OP_IMM,
        CS_OP_MEM,
        CS_OP_REG,
    )
    from capstone.arm import ARM_REG_PC
except Exception as exc:
    raise SystemExit(
        "capstone is required in the project venv. Use the same mtkclient venv "
        "as previous S13.5A scripts.\n"
        f"Import error: {exc}"
    )

TITLE = "S13.5A.32 - FILTER BITMAP PROVENANCE / SEMANTICS / PRE-B709 PATH AUDIT"

ALICE_BASE = 0x1024EC00
ALICE_SIZE = 0x157BB4
ALICE_SHA256 = "7246242b67afae0d13104452bc3257827cb778119b54e7a26fb7fb55993697ea"

ZIMAGE_BASE = 0xF023CA50
ZIMAGE_SIZE = 0x185E98
ZIMAGE_SHA256 = "85fba8c8ae8161e4c1f8ced7983ec30d48c54ab10e51c69fcdfb900aca220954"

EVENT_OWNER = 0x102D100C
EVENT_REBUILD_CALLSITE = 0x102D1066
B709_REBUILD = 0x10313998
BITMAP_HIT = 0xF02EE32C

SET_FILTER_VENEER = 0x102FD04C
CLEAR_FILTER_VENEER = 0x102FD054
SET_FILTER_IMPL = 0xF02D4D10
CLEAR_FILTER_IMPL = 0xF02D5828
FILTER_PREDICATE = 0xF02D5458
FILTER_BITMAP = 0xF00C1624
FILTER_BOUND = 0xF007F04C

FOCUS_IDS = {
    0xB709: "B709",
    0xB700: "B700",
    0xB702: "B702",
    0xB6FF: "B6FF",
    0x8928: "AUDIO_8928",
    0x8313: "IMAGE_8313",
    0x8321: "IMAGE_8321",
}


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def u16(data: bytes, off: int) -> int:
    return struct.unpack_from("<H", data, off)[0]


def u32(data: bytes, off: int) -> int:
    return struct.unpack_from("<I", data, off)[0]


@dataclass(frozen=True)
class Image:
    name: str
    data: bytes
    base: int

    @property
    def end(self) -> int:
        return self.base + len(self.data)

    def contains(self, addr: int, n: int = 1) -> bool:
        return self.base <= addr and addr + n <= self.end

    def off(self, addr: int) -> int:
        if not self.contains(addr):
            raise ValueError(f"{self.name}: address out of range: 0x{addr:08X}")
        return addr - self.base

    def read(self, addr: int, n: int) -> bytes:
        off = self.off(addr)
        return self.data[off:off+n]

    def read_u32(self, addr: int) -> int:
        return u32(self.data, self.off(addr))


@dataclass
class InsnInfo:
    addr: int
    size: int
    mnemonic: str
    op_str: str
    text: str
    target: Optional[int] = None
    is_call: bool = False
    is_jump: bool = False
    literal_addr: Optional[int] = None
    literal_value: Optional[int] = None


@dataclass
class FunctionAudit:
    entry: int
    image: str
    visited: Dict[int, InsnInfo] = field(default_factory=dict)
    calls: List[Tuple[int, int]] = field(default_factory=list)
    literals: List[Tuple[int, int, int]] = field(default_factory=list)
    truncated: bool = False


class Auditor:
    def __init__(self, alice: Image, zimage: Image):
        self.alice = alice
        self.zimage = zimage
        self.images = [alice, zimage]
        self.thumb = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_LITTLE_ENDIAN)
        self.thumb.detail = True
        self.arm = Cs(CS_ARCH_ARM, CS_MODE_ARM | CS_MODE_LITTLE_ENDIAN)
        self.arm.detail = True

    def image_for(self, addr: int) -> Optional[Image]:
        addr &= ~1
        for img in self.images:
            if img.contains(addr):
                return img
        return None

    def decode_one(self, addr: int) -> Optional[InsnInfo]:
        addr &= ~1
        img = self.image_for(addr)
        if not img or not img.contains(addr, 2):
            return None
        blob = img.read(addr, min(4, img.end - addr))
        ds = list(self.thumb.disasm(blob, addr, count=1))
        if not ds:
            return None
        insn = ds[0]
        target = None
        is_call = bool(insn.group(CS_GRP_CALL))
        is_jump = bool(insn.group(CS_GRP_JUMP))
        if (is_call or is_jump) and insn.operands:
            op0 = insn.operands[0]
            if op0.type == CS_OP_IMM:
                target = int(op0.imm) & 0xFFFFFFFF

        literal_addr = None
        literal_value = None
        if insn.mnemonic.startswith("ldr") and len(insn.operands) >= 2:
            op = insn.operands[1]
            if op.type == CS_OP_MEM and op.mem.base == ARM_REG_PC:
                pc = (addr + 4) & ~3
                literal_addr = (pc + int(op.mem.disp)) & 0xFFFFFFFF
                li = self.image_for(literal_addr)
                if li and li.contains(literal_addr, 4):
                    literal_value = li.read_u32(literal_addr)

        return InsnInfo(
            addr=addr,
            size=insn.size,
            mnemonic=insn.mnemonic,
            op_str=insn.op_str,
            text=f"{insn.mnemonic:<9} {insn.op_str}".rstrip(),
            target=target,
            is_call=is_call,
            is_jump=is_jump,
            literal_addr=literal_addr,
            literal_value=literal_value,
        )

    @staticmethod
    def is_conditional_branch(ins: InsnInfo) -> bool:
        m = ins.mnemonic.lower()
        if m in {"b", "b.w", "bx", "bl", "blx"}:
            return False
        return m.startswith("b") or m in {"cbz", "cbnz"}

    @staticmethod
    def is_return(ins: InsnInfo) -> bool:
        s = (ins.mnemonic + " " + ins.op_str).lower()
        if ins.mnemonic.lower() == "bx" and "lr" in ins.op_str.lower():
            return True
        if ins.mnemonic.lower() == "pop" and "pc" in ins.op_str.lower():
            return True
        if ins.mnemonic.lower().startswith("mov") and "pc" in ins.op_str.lower() and "lr" in ins.op_str.lower():
            return True
        return False

    def audit_function(self, entry: int, max_span: int = 0x1200, max_insns: int = 2500) -> FunctionAudit:
        entry &= ~1
        img = self.image_for(entry)
        out = FunctionAudit(entry=entry, image=img.name if img else "OUTSIDE")
        if not img:
            return out

        q = deque([entry])
        seen: Set[int] = set()
        while q and len(seen) < max_insns:
            addr = q.popleft() & ~1
            if addr in seen:
                continue
            if addr < entry - 4 or addr >= entry + max_span:
                out.truncated = True
                continue
            ins = self.decode_one(addr)
            if ins is None:
                continue
            seen.add(addr)
            out.visited[addr] = ins
            if ins.literal_addr is not None and ins.literal_value is not None:
                out.literals.append((addr, ins.literal_addr, ins.literal_value))
            if ins.is_call and ins.target is not None:
                out.calls.append((addr, ins.target))
                q.append(addr + ins.size)
                continue
            if self.is_return(ins):
                continue
            if ins.is_jump:
                if ins.target is not None:
                    q.append(ins.target & ~1)
                if self.is_conditional_branch(ins):
                    q.append(addr + ins.size)
                continue
            q.append(addr + ins.size)

        if q:
            out.truncated = True
        return out

    def resolve_arm_veneer(self, addr: int) -> Optional[int]:
        addr &= ~1
        if not self.alice.contains(addr, 8):
            return None
        w0 = self.alice.read_u32(addr)
        w1 = self.alice.read_u32(addr + 4)
        if w0 in {0xE51FF004, 0xE59FF000}:
            return w1
        blob = self.alice.read(addr, min(12, self.alice.end - addr))
        ds = list(self.arm.disasm(blob, addr, count=2))
        if ds and ds[0].mnemonic == "ldr" and len(ds[0].operands) >= 2:
            try:
                dst = ds[0].operands[0]
                src = ds[0].operands[1]
                if dst.type == CS_OP_REG and dst.reg == ARM_REG_PC and src.type == CS_OP_MEM and src.mem.base == ARM_REG_PC:
                    pc = addr + 8
                    lit = (pc + int(src.mem.disp)) & 0xFFFFFFFF
                    if self.alice.contains(lit, 4):
                        return self.alice.read_u32(lit)
            except Exception:
                pass
        return None

    def normalize_target(self, target: int) -> Tuple[int, Optional[int], int]:
        direct = target & ~1
        resolved = self.resolve_arm_veneer(direct)
        effective = (resolved & ~1) if resolved is not None else direct
        return direct, resolved, effective

    def pointer_occurrences(self, value: int) -> List[Tuple[str, int]]:
        needle = struct.pack("<I", value & 0xFFFFFFFF)
        out: List[Tuple[str, int]] = []
        for img in self.images:
            pos = 0
            while True:
                p = img.data.find(needle, pos)
                if p < 0:
                    break
                out.append((img.name, img.base + p))
                pos = p + 1
        return out

    def literal_xrefs(self, value: int, back: int = 0x100) -> List[Tuple[str, int, int]]:
        """Return (image_name, insn_addr, literal_pool_addr) for exact Thumb PC-literal loads."""
        out: Set[Tuple[str, int, int]] = set()
        for img_name, litaddr in self.pointer_occurrences(value):
            img = self.alice if img_name == "ALICE" else self.zimage
            start = max(img.base, litaddr - back)
            start &= ~1
            for a in range(start, litaddr + 1, 2):
                ins = self.decode_one(a)
                if ins and ins.literal_addr == litaddr and ins.literal_value == value:
                    out.add((img_name, a, litaddr))
        return sorted(out)

    def nearest_push(self, addr: int, back: int = 0x180) -> Optional[int]:
        img = self.image_for(addr)
        if not img:
            return None
        lo = max(img.base, (addr - back) & ~1)
        best = None
        for a in range(lo, addr + 1, 2):
            ins = self.decode_one(a)
            if ins and ins.mnemonic.lower() in {"push", "stmdb"}:
                best = a
        return best


def hdr(s: str) -> None:
    print()
    print("=" * 120)
    print(s)
    print("=" * 120)


def fmt_call(aud: Auditor, site: int, target: int) -> str:
    direct, resolved, effective = aud.normalize_target(target)
    s = f"0x{site:08X} -> 0x{target:08X}"
    if resolved is not None:
        s += f" -> [ARM veneer] 0x{resolved:08X}"
    s += f" ; effective=0x{effective:08X}"
    return s


def print_function(aud: Auditor, fa: FunctionAudit, full: bool = True) -> None:
    print(f"\nFUNCTION 0x{fa.entry:08X} [{fa.image}]")
    print(f"  reachable insns : {len(fa.visited)}")
    print(f"  direct calls    : {len(fa.calls)}")
    print(f"  literals        : {len(fa.literals)}")
    print(f"  truncated       : {fa.truncated}")
    if full:
        for addr in sorted(fa.visited):
            ins = fa.visited[addr]
            ann = []
            if ins.target is not None:
                ann.append(f"target=0x{ins.target:08X}")
            if ins.literal_addr is not None and ins.literal_value is not None:
                ann.append(f"literal@0x{ins.literal_addr:08X}=0x{ins.literal_value:08X}")
                if ins.literal_value == FILTER_BITMAP:
                    ann.append("FILTER_BITMAP")
                if ins.literal_value == FILTER_BOUND:
                    ann.append("FILTER_BOUND")
                if ins.literal_value in FOCUS_IDS:
                    ann.append(FOCUS_IDS[ins.literal_value])
            suffix = " ; " + " ; ".join(ann) if ann else ""
            print(f"    0x{addr:08X}: {ins.text}{suffix}")


def print_context(aud: Auditor, site: int, before: int = 0x18, after: int = 0x14) -> None:
    img = aud.image_for(site)
    if not img:
        print("    <outside images>")
        return
    lo = max(img.base, (site - before) & ~1)
    hi = min(img.end, site + after)
    a = lo
    while a < hi:
        ins = aud.decode_one(a)
        if not ins:
            a += 2
            continue
        marker = " >>>" if a == (site & ~1) else "    "
        ann = ""
        if ins.literal_value is not None and ins.literal_addr is not None:
            ann = f" ; literal@0x{ins.literal_addr:08X}=0x{ins.literal_value:08X}"
        if ins.target is not None:
            ann += f" ; target=0x{ins.target:08X}"
        print(f"{marker} 0x{a:08X}: {ins.text}{ann}")
        a += ins.size


def build_pre_rebuild_roots(aud: Auditor) -> Tuple[FunctionAudit, List[Tuple[int, int, int]]]:
    owner = aud.audit_function(EVENT_OWNER, max_span=0x200)
    roots: List[Tuple[int, int, int]] = []  # event_callsite, raw_target, effective
    for site, target in sorted(owner.calls):
        if site >= EVENT_REBUILD_CALLSITE:
            continue
        _, _, effective = aud.normalize_target(target)
        if aud.image_for(effective):
            roots.append((site, target, effective))
    return owner, roots


def find_paths(aud: Auditor, roots: List[Tuple[int, int, int]], target: int, depth_limit: int):
    results = []
    cache: Dict[int, FunctionAudit] = {}
    for root_site, raw_root, root in roots:
        q = deque([(root, 1)])
        seen = {root}
        parent: Dict[int, Tuple[int, int, int]] = {}
        found_depth = None
        while q:
            node, depth = q.popleft()
            if node == target:
                found_depth = depth
                break
            if depth >= depth_limit:
                continue
            fa = cache.get(node)
            if fa is None:
                fa = aud.audit_function(node, max_span=0x1200)
                cache[node] = fa
            for callsite, raw_t in fa.calls:
                _, _, child = aud.normalize_target(raw_t)
                if not aud.image_for(child):
                    continue
                if child in seen:
                    continue
                seen.add(child)
                parent[child] = (node, callsite, raw_t)
                q.append((child, depth + 1))
        if found_depth is not None:
            chain_nodes = [target]
            chain_edges = []
            cur = target
            while cur != root:
                pnode, callsite, raw_t = parent[cur]
                chain_edges.append((pnode, callsite, raw_t, cur))
                chain_nodes.append(pnode)
                cur = pnode
            chain_nodes.reverse()
            chain_edges.reverse()
            results.append((root_site, raw_root, root, found_depth, chain_nodes, chain_edges))
    return results, cache


def main() -> int:
    ap = argparse.ArgumentParser(description=TITLE)
    ap.add_argument("--alice", default=r".\research\f2\work\extracted\altice_alice\alice-py.bin")
    ap.add_argument("--zimage", default=r".\research\f2\work\extracted\altice_platform\zimage.bin")
    ap.add_argument("--depth", type=int, default=4, help="Callgraph depth from each direct pre-rebuild root (default 4)")
    args = ap.parse_args()

    print("=" * 120)
    print(TITLE)
    print("=" * 120)
    print("STRICTLY OFFLINE")
    print("PHONE ACCESSED       : NO")
    print("FLASH MODIFIED       : NO")
    print("PATCH GENERATED      : NO")
    print("REPACK               : NO")

    apath = Path(args.alice)
    zpath = Path(args.zimage)
    if not apath.is_file():
        raise SystemExit(f"Missing ALICE: {apath}")
    if not zpath.is_file():
        raise SystemExit(f"Missing ZIMAGE: {zpath}")
    ad = apath.read_bytes()
    zd = zpath.read_bytes()

    hdr("A. CANONICAL INPUTS")
    ah = sha256(ad)
    zh = sha256(zd)
    ag = len(ad) == ALICE_SIZE and ah == ALICE_SHA256
    zg = len(zd) == ZIMAGE_SIZE and zh == ZIMAGE_SHA256
    print(f"ALICE  = {apath}")
    print(f"  base   = 0x{ALICE_BASE:08X}")
    print(f"  size   = 0x{len(ad):X}")
    print(f"  sha256 = {ah}")
    print(f"  guard  = {'PASS' if ag else 'FAIL'}")
    print(f"ZIMAGE = {zpath}")
    print(f"  base   = 0x{ZIMAGE_BASE:08X}")
    print(f"  size   = 0x{len(zd):X}")
    print(f"  sha256 = {zh}")
    print(f"  guard  = {'PASS' if zg else 'FAIL'}")
    if not ag:
        raise SystemExit("ABORT: canonical ALICE guard failed")
    if not zg:
        raise SystemExit("ABORT: canonical ZIMAGE guard failed")

    alice = Image("ALICE", ad, ALICE_BASE)
    zimage = Image("ZIMAGE", zd, ZIMAGE_BASE)
    aud = Auditor(alice, zimage)

    hdr("B. EVENT 0x7485 PRE-B709 ROOTS")
    owner, roots = build_pre_rebuild_roots(aud)
    print(f"owner reachable insns = {len(owner.visited)}")
    print(f"direct roots before 0x{EVENT_REBUILD_CALLSITE:08X} = {len(roots)}")
    for site, raw, eff in roots:
        print(f"  event 0x{site:08X}: raw=0x{raw:08X} effective=0x{eff:08X}")

    hdr(f"C. SHORTEST PRE-B709 PATHS TO 0x{BITMAP_HIT:08X} (DEPTH <= {args.depth})")
    paths, cache = find_paths(aud, roots, BITMAP_HIT, args.depth)
    if not paths:
        print("NO PATH FOUND within requested depth")
    else:
        for idx, (root_site, raw_root, root, depth, nodes, edges) in enumerate(paths, 1):
            print(f"\nPATH #{idx}")
            print(f"  event callsite : 0x{root_site:08X}")
            print(f"  raw root       : 0x{raw_root:08X}")
            print(f"  effective root : 0x{root:08X}")
            print(f"  depth          : {depth}")
            print("  nodes          : " + " -> ".join(f"0x{x:08X}" for x in nodes))
            for pnode, callsite, raw_t, child in edges:
                print(f"\n  EDGE 0x{pnode:08X} --[0x{callsite:08X}]--> 0x{child:08X}")
                print("  " + fmt_call(aud, callsite, raw_t))
                print_context(aud, callsite)

    hdr("D. EXACT SEMANTICS TARGET 0xF02EE32C")
    hit = aud.audit_function(BITMAP_HIT, max_span=0x200)
    print_function(aud, hit, full=True)
    print("\nDIRECT CALLEES FROM 0xF02EE32C")
    if not hit.calls:
        print("  <none>")
    for site, raw in hit.calls:
        direct, resolved, eff = aud.normalize_target(raw)
        print("  " + fmt_call(aud, site, raw))
        fa = aud.audit_function(eff, max_span=0x500)
        print_function(aud, fa, full=True)

    hdr("E. FILTER PRIMITIVES - EXACT CFG FOR COMPARISON")
    for entry, name in [
        (SET_FILTER_IMPL, "SET_FILTER_IMPL"),
        (CLEAR_FILTER_IMPL, "CLEAR_FILTER_IMPL"),
        (FILTER_PREDICATE, "FILTER_PREDICATE"),
    ]:
        print(f"\n--- {name} 0x{entry:08X} ---")
        fa = aud.audit_function(entry, max_span=0x400)
        print_function(aud, fa, full=True)

    hdr("F. EXACT FILTER BITMAP / BOUND PC-LITERAL XREF CENSUS")
    for value, name in [(FILTER_BITMAP, "FILTER_BITMAP"), (FILTER_BOUND, "FILTER_BOUND")]:
        print(f"\n{name} = 0x{value:08X}")
        occ = aud.pointer_occurrences(value)
        xrefs = aud.literal_xrefs(value, back=0x180)
        print(f"  raw u32 occurrences = {len(occ)}")
        for img_name, addr in occ:
            print(f"    {img_name} literal@0x{addr:08X}")
        print(f"  exact Thumb PC-literal xrefs = {len(xrefs)}")
        for img_name, insn_addr, litaddr in xrefs:
            owner_guess = aud.nearest_push(insn_addr)
            print(f"\n    {img_name} xref 0x{insn_addr:08X} -> literal@0x{litaddr:08X}")
            print(f"      heuristic nearest push = {('0x%08X' % owner_guess) if owner_guess is not None else 'NONE'}")
            print_context(aud, insn_addr, before=0x20, after=0x20)

    hdr("G. FOCUSED RAW ID LITERAL CENSUS AROUND PATH FUNCTIONS")
    path_functions: Set[int] = {BITMAP_HIT}
    for _, _, root, _, nodes, _ in paths:
        path_functions.update(nodes)
        path_functions.add(root)
    if not path_functions:
        path_functions = {BITMAP_HIT}
    for entry in sorted(path_functions):
        fa = cache.get(entry) or aud.audit_function(entry, max_span=0x1200)
        hits = []
        if fa.visited:
            lo = min(fa.visited)
            hi = max(i.addr + i.size for i in fa.visited.values())
            img = aud.image_for(lo)
            if img and img.contains(lo, hi - lo):
                buf = img.read(lo, hi - lo)
                for ident, nm in FOCUS_IDS.items():
                    needle = struct.pack("<H", ident)
                    pos = 0
                    while True:
                        p = buf.find(needle, pos)
                        if p < 0:
                            break
                        hits.append((lo + p, ident, nm))
                        pos = p + 1
        print(f"\nFUNCTION 0x{entry:08X}: focused raw-u16 hits={len(hits)}")
        for addr, ident, nm in sorted(set(hits)):
            print(f"  0x{addr:08X}: 0x{ident:04X} <{nm}>")

    hdr("H. DECISION GATE")
    bitmap_literal_in_hit = any(v == FILTER_BITMAP for _, _, v in hit.literals)
    bound_literal_in_hit = any(v == FILTER_BOUND for _, _, v in hit.literals)
    print(f"pre-B709 path to 0xF02EE32C found = {'YES' if bool(paths) else 'NO'}")
    print(f"0xF02EE32C has FILTER_BITMAP literal = {'YES' if bitmap_literal_in_hit else 'NO'}")
    print(f"0xF02EE32C has FILTER_BOUND literal  = {'YES' if bound_literal_in_hit else 'NO'}")
    print()
    print("Interpretation rule:")
    print("  - Promote exact bitmap initialization semantics only after the printed CFG/call arguments prove them.")
    print("  - Do not infer individual B709 child membership from bitmap evidence alone.")
    print("  - Next promotion requires raw/filtered B709 alignment + exact Multimedia child relation.")
    print()
    print("PHONE ACCESSED       : NO")
    print("FLASH MODIFIED       : NO")
    print("PATCH GENERATED      : NO")
    print("PHYSICAL CANDIDATE   : NO")
    print("HARDWARE WRITE AUTHORIZED: NO")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
