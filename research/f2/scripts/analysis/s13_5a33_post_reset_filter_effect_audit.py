#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
S13.5A.33 - POST-RESET FILTER EFFECT / MEMZERO SEMANTICS AUDIT

STRICTLY OFFLINE:
- no USB / COM
- no DA upload
- no D3 / D5 / D6
- no write / erase
- no phone access

Purpose
-------
S13.5A.32 proved the exact pre-B709 path:

    0x102D1040 -> 0x1031FD20
    0x1031FD2E -> veneer 0x102F9ED4 -> 0xF02EE32C

and proved that 0xF02EE32C computes:

    r0 = FILTER_BITMAP (0xF00C1624)
    r1 = (*(u32 *)FILTER_BOUND >> 3) + 1
    call 0xF0210588

Only four exact ZIMAGE PC-literal xrefs to FILTER_BITMAP exist:
  - SET filter implementation
  - CLEAR filter implementation
  - filter predicate
  - 0xF02EE32C initializer

A.33 therefore focuses on the state *after* this initializer and *before*
the valid B709 rebuild at 0x102D1066:

  1. dump the complete reachable CFG of 0x1031FD20;
  2. identify all calls after 0x1031FD2E inside that function;
  3. include every subsequent direct root in event-0x7485 owner 0x102D100C;
  4. recursively find executable paths to SET/CLEAR/PREDICATE;
  5. recover constant r0 IDs at final SET/CLEAR callsites when possible;
  6. census CFG-valid direct callsites to external 0xF0210588 and print
     argument contexts to characterize its likely two-argument primitive;
  7. report whether the audited post-reset path contains any filter
     mutation before B709 rebuild.

This audit does not infer B709 membership from bitmap evidence and does not
authorize a flash mutation.
"""

from __future__ import annotations

import argparse
import hashlib
import re
import struct
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

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
        "capstone is required in the project venv. Use "
        r"C:\Users\verto\mtkclient\.venv\Scripts\python.exe"
        "\n"
        f"Import error: {exc}"
    )

TITLE = "S13.5A.33 - POST-RESET FILTER EFFECT / MEMZERO SEMANTICS AUDIT"

ALICE_BASE = 0x1024EC00
ALICE_SIZE = 0x157BB4
ALICE_SHA256 = "7246242b67afae0d13104452bc3257827cb778119b54e7a26fb7fb55993697ea"

ZIMAGE_BASE = 0xF023CA50
ZIMAGE_SIZE = 0x185E98
ZIMAGE_SHA256 = "85fba8c8ae8161e4c1f8ced7983ec30d48c54ab10e51c69fcdfb900aca220954"

EVENT_OWNER = 0x102D100C
B709_REBUILD_CALLSITE = 0x102D1066
B709_REBUILD = 0x10313998

RESET_ROOT = 0x1031FD20
RESET_CALLSITE = 0x1031FD2E
BITMAP_INIT = 0xF02EE32C
EXTERNAL_ZERO_CANDIDATE = 0xF0210588

SET_FILTER_VENEER = 0x102FD04C
CLEAR_FILTER_VENEER = 0x102FD054
SET_FILTER_IMPL = 0xF02D4D10
CLEAR_FILTER_IMPL = 0xF02D5828
FILTER_PREDICATE = 0xF02D5458
FILTER_BITMAP = 0xF00C1624
FILTER_BOUND = 0xF007F04C

TARGETS = {
    SET_FILTER_IMPL: "SET_FILTER",
    CLEAR_FILTER_IMPL: "CLEAR_FILTER",
    FILTER_PREDICATE: "FILTER_PREDICATE",
}

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
        a = addr & ~1
        for img in self.images:
            if img.contains(a):
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
        is_call = bool(insn.group(CS_GRP_CALL))
        is_jump = bool(insn.group(CS_GRP_JUMP))
        target = None

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
        m = ins.mnemonic.lower()
        o = ins.op_str.lower()
        if m == "bx" and "lr" in o:
            return True
        if m == "pop" and "pc" in o:
            return True
        if m.startswith("mov") and "pc" in o and "lr" in o:
            return True
        return False

    def audit_function(
        self,
        entry: int,
        max_span: int = 0x1400,
        max_insns: int = 3000,
    ) -> FunctionAudit:
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
                if (
                    dst.type == CS_OP_REG
                    and dst.reg == ARM_REG_PC
                    and src.type == CS_OP_MEM
                    and src.mem.base == ARM_REG_PC
                ):
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

    def scan_direct_calls_to(self, target: int) -> List[Tuple[str, int, int, Optional[int], bool]]:
        """
        Scan only Thumb-2 call-shaped halfword pairs, then validate with Capstone.
        Return:
          image, callsite, raw_target, nearest_push, cfg_valid
        """
        out = []
        for img in self.images:
            data = img.data
            for off in range(0, len(data) - 4, 2):
                h1 = struct.unpack_from("<H", data, off)[0]
                h2 = struct.unpack_from("<H", data, off + 2)[0]

                # Thumb-2 BL/BLX immediate broad prefilter.
                if (h1 & 0xF800) != 0xF000:
                    continue
                if (h2 & 0xC000) != 0xC000:
                    continue

                site = img.base + off
                ins = self.decode_one(site)
                if not ins or not ins.is_call or ins.target is None:
                    continue

                _, _, eff = self.normalize_target(ins.target)
                if eff != (target & ~1):
                    continue

                owner = self.nearest_push(site)
                valid = False
                if owner is not None:
                    fa = self.audit_function(owner, max_span=0x1000)
                    valid = site in fa.visited and any(s == site for s, _ in fa.calls)

                out.append((img.name, site, ins.target, owner, valid))

        return sorted(set(out), key=lambda x: (x[0], x[1]))


def hdr(s: str) -> None:
    print()
    print("=" * 120)
    print(s)
    print("=" * 120)


def print_function(aud: Auditor, fa: FunctionAudit) -> None:
    print(f"\nFUNCTION 0x{fa.entry:08X} [{fa.image}]")
    print(f"  reachable insns : {len(fa.visited)}")
    print(f"  direct calls    : {len(fa.calls)}")
    print(f"  literals        : {len(fa.literals)}")
    print(f"  truncated       : {fa.truncated}")

    for addr in sorted(fa.visited):
        ins = fa.visited[addr]
        ann = []

        if ins.target is not None:
            d, r, e = aud.normalize_target(ins.target)
            s = f"target=0x{ins.target:08X}"
            if r is not None:
                s += f" veneer->0x{r:08X}"
            if e != (ins.target & ~1):
                s += f" effective=0x{e:08X}"
            ann.append(s)

        if ins.literal_addr is not None and ins.literal_value is not None:
            a = f"literal@0x{ins.literal_addr:08X}=0x{ins.literal_value:08X}"
            if ins.literal_value == FILTER_BITMAP:
                a += " FILTER_BITMAP"
            if ins.literal_value == FILTER_BOUND:
                a += " FILTER_BOUND"
            if ins.literal_value in FOCUS_IDS:
                a += f" {FOCUS_IDS[ins.literal_value]}"
            ann.append(a)

        suffix = " ; " + " ; ".join(ann) if ann else ""
        print(f"    0x{addr:08X}: {ins.text}{suffix}")


def print_context(aud: Auditor, site: int, before: int = 0x20, after: int = 0x10) -> None:
    img = aud.image_for(site)
    if not img:
        print("    <outside canonical images>")
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
        ann = []

        if ins.target is not None:
            _, r, e = aud.normalize_target(ins.target)
            s = f"target=0x{ins.target:08X}"
            if r is not None:
                s += f" veneer->0x{r:08X}"
            if e != (ins.target & ~1):
                s += f" effective=0x{e:08X}"
            ann.append(s)

        if ins.literal_value is not None and ins.literal_addr is not None:
            ann.append(f"literal@0x{ins.literal_addr:08X}=0x{ins.literal_value:08X}")

        suffix = " ; " + " ; ".join(ann) if ann else ""
        print(f"{marker} 0x{a:08X}: {ins.text}{suffix}")
        a += ins.size


def infer_r0_constant(aud: Auditor, callsite: int, back: int = 0x28) -> Optional[Tuple[int, int, str]]:
    """
    Conservative local backward heuristic.
    Returns (value, source_insn_addr, evidence).
    Stops at a prior call or unconditional/control-transfer boundary.
    """
    img = aud.image_for(callsite)
    if not img:
        return None

    lo = max(img.base, (callsite - back) & ~1)
    insns = []
    a = lo
    while a < callsite:
        ins = aud.decode_one(a)
        if ins:
            insns.append(ins)
            a += ins.size
        else:
            a += 2

    # Walk backward through the local straight-line tail.
    for ins in reversed(insns):
        m = ins.mnemonic.lower()
        op = ins.op_str.lower().replace(" ", "")

        if ins.is_call:
            break
        if ins.is_jump and not Auditor.is_conditional_branch(ins):
            break

        # ldr r0, [pc, #...] where the literal itself is the ID/value.
        if m == "ldr" and op.startswith("r0,") and ins.literal_value is not None:
            return ins.literal_value & 0xFFFFFFFF, ins.addr, "PC-literal load into r0"

        # mov/movs r0, #imm
        mm = re.match(r"r0,#(0x[0-9a-f]+|\d+)$", op)
        if m in {"mov", "movs", "mov.w", "movw"} and mm:
            return int(mm.group(1), 0) & 0xFFFFFFFF, ins.addr, f"{m} immediate into r0"

    return None


def build_owner_roots(aud: Auditor) -> Tuple[FunctionAudit, List[Tuple[int, int, int]]]:
    owner = aud.audit_function(EVENT_OWNER, max_span=0x200)
    roots = []
    for site, raw in sorted(owner.calls):
        if site >= B709_REBUILD_CALLSITE:
            continue
        _, _, eff = aud.normalize_target(raw)
        roots.append((site, raw, eff))
    return owner, roots


def find_target_paths(
    aud: Auditor,
    root: int,
    targets: Dict[int, str],
    depth_limit: int,
    cache: Dict[int, FunctionAudit],
) -> List[Tuple[int, List[int], List[Tuple[int, int, int, int]]]]:
    """
    Returns tuples:
      matched_target,
      chain_nodes,
      chain_edges(parent, callsite, raw_target, effective_child)
    """
    root &= ~1
    q = deque([(root, 1)])
    seen = {root}
    parent: Dict[int, Tuple[int, int, int, int]] = {}
    matches = []

    while q:
        node, depth = q.popleft()

        if node in targets:
            nodes = [node]
            edges = []
            cur = node
            while cur != root:
                pnode, site, raw, eff = parent[cur]
                edges.append((pnode, site, raw, eff))
                nodes.append(pnode)
                cur = pnode
            nodes.reverse()
            edges.reverse()
            matches.append((node, nodes, edges))
            continue

        if depth >= depth_limit:
            continue

        fa = cache.get(node)
        if fa is None:
            fa = aud.audit_function(node, max_span=0x1400)
            cache[node] = fa

        for site, raw in fa.calls:
            _, _, child = aud.normalize_target(raw)

            # Keep target functions even if outside normal traversal rules.
            if child in targets:
                if child not in seen:
                    seen.add(child)
                    parent[child] = (node, site, raw, child)
                    q.append((child, depth + 1))
                continue

            if not aud.image_for(child):
                continue

            if child in seen:
                continue
            seen.add(child)
            parent[child] = (node, site, raw, child)
            q.append((child, depth + 1))

    return matches


def main() -> int:
    ap = argparse.ArgumentParser(description=TITLE)
    ap.add_argument(
        "--alice",
        default=r".\research\f2\work\extracted\altice_alice\alice-py.bin",
    )
    ap.add_argument(
        "--zimage",
        default=r".\research\f2\work\extracted\altice_platform\zimage.bin",
    )
    ap.add_argument(
        "--depth",
        type=int,
        default=4,
        help="Callgraph depth for post-reset SET/CLEAR/PREDICATE search (default 4)",
    )
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

    aud = Auditor(
        Image("ALICE", ad, ALICE_BASE),
        Image("ZIMAGE", zd, ZIMAGE_BASE),
    )

    hdr("B. EVENT 0x7485 OWNER / RESET POSITION")
    owner, roots = build_owner_roots(aud)
    print(f"owner reachable insns = {len(owner.visited)}")
    print(f"direct pre-B709 roots = {len(roots)}")
    for site, raw, eff in roots:
        flag = ""
        if site == 0x102D1040:
            flag = " <RESET_ROOT>"
        if site > 0x102D1040:
            flag = " <AFTER_RESET_ROOT>"
        print(f"  0x{site:08X}: raw=0x{raw:08X} effective=0x{eff:08X}{flag}")

    hdr("C. COMPLETE REACHABLE CFG OF 0x1031FD20")
    reset_fa = aud.audit_function(RESET_ROOT, max_span=0x200)
    print_function(aud, reset_fa)

    reset_seen = any(
        site == RESET_CALLSITE and aud.normalize_target(raw)[2] == BITMAP_INIT
        for site, raw in reset_fa.calls
    )
    print()
    print(
        f"RESET CALL 0x{RESET_CALLSITE:08X} -> 0x{BITMAP_INIT:08X}: "
        f"{'CONFIRMED' if reset_seen else 'NOT FOUND'}"
    )

    hdr("D. CALLS AFTER BITMAP INITIALIZER INSIDE 0x1031FD20")
    internal_after = []
    for site, raw in sorted(reset_fa.calls):
        if site <= RESET_CALLSITE:
            continue
        _, resolved, eff = aud.normalize_target(raw)
        internal_after.append((site, raw, eff))
        s = f"  0x{site:08X} -> raw 0x{raw:08X}"
        if resolved is not None:
            s += f" -> veneer 0x{resolved:08X}"
        s += f" -> effective 0x{eff:08X}"
        print(s)

    if not internal_after:
        print("  <none>")

    hdr("E. POST-RESET EXECUTABLE PATHS TO SET / CLEAR / PREDICATE")
    phase_roots: List[Tuple[str, int, int]] = []

    # Calls made inside RESET_ROOT after the bitmap initializer.
    for site, raw, eff in internal_after:
        phase_roots.append((f"RESET_ROOT internal callsite 0x{site:08X}", site, eff))

    # Direct owner roots after 0x102D1040 and before B709 rebuild.
    for site, raw, eff in roots:
        if 0x102D1040 < site < B709_REBUILD_CALLSITE:
            phase_roots.append((f"EVENT owner callsite 0x{site:08X}", site, eff))

    cache: Dict[int, FunctionAudit] = {}
    all_matches = []

    for label, phase_site, root in phase_roots:
        matches = find_target_paths(aud, root, TARGETS, args.depth, cache)
        if not matches:
            continue

        print()
        print(f"{label}: root=0x{root:08X}")
        for matched, nodes, edges in matches:
            print(f"  MATCH {TARGETS[matched]} 0x{matched:08X}")
            print("    nodes: " + " -> ".join(f"0x{x:08X}" for x in nodes))

            for pnode, callsite, raw, eff in edges:
                _, resolved, _ = aud.normalize_target(raw)
                s = f"    edge 0x{pnode:08X} --[0x{callsite:08X}]--> raw 0x{raw:08X}"
                if resolved is not None:
                    s += f" -> veneer 0x{resolved:08X}"
                s += f" -> effective 0x{eff:08X}"
                print(s)

            # Last edge calls the actual primitive.
            if edges:
                final_site = edges[-1][1]
                inferred = infer_r0_constant(aud, final_site)
                if inferred:
                    value, src, evidence = inferred
                    label_id = FOCUS_IDS.get(value, "")
                    extra = f" <{label_id}>" if label_id else ""
                    print(
                        f"    r0 constant candidate: 0x{value:04X}{extra} "
                        f"from 0x{src:08X} ({evidence})"
                    )
                else:
                    print("    r0 constant candidate: UNKNOWN")
                print("    final callsite context:")
                print_context(aud, final_site, before=0x24, after=0x0C)

            all_matches.append((label, phase_site, root, matched, nodes, edges))

    if not all_matches:
        print(
            f"No SET/CLEAR/PREDICATE path found from audited post-reset roots "
            f"within depth <= {args.depth}."
        )

    hdr("F. FILTER MUTATION SUMMARY")
    set_matches = [x for x in all_matches if x[3] == SET_FILTER_IMPL]
    clear_matches = [x for x in all_matches if x[3] == CLEAR_FILTER_IMPL]
    pred_matches = [x for x in all_matches if x[3] == FILTER_PREDICATE]

    print(f"SET paths       = {len(set_matches)}")
    print(f"CLEAR paths     = {len(clear_matches)}")
    print(f"PREDICATE paths = {len(pred_matches)}")

    if set_matches or clear_matches:
        print("POST-RESET FILTER MUTATION EVIDENCE = FOUND")
    else:
        print("POST-RESET FILTER MUTATION EVIDENCE = NOT FOUND IN AUDITED DEPTH")

    hdr("G. CFG-VALID DIRECT CALLS TO EXTERNAL 0xF0210588")
    zero_calls = aud.scan_direct_calls_to(EXTERNAL_ZERO_CANDIDATE)
    print(f"all direct call-shaped hits = {len(zero_calls)}")

    valid_zero_calls = [x for x in zero_calls if x[4]]
    print(f"CFG-valid hits              = {len(valid_zero_calls)}")

    for img_name, site, raw, owner_start, valid in zero_calls:
        print()
        print(
            f"{img_name} callsite 0x{site:08X} -> 0x{raw:08X} "
            f"owner≈{('0x%08X' % owner_start) if owner_start is not None else 'UNKNOWN'} "
            f"cfg_valid={valid}"
        )
        print_context(aud, site, before=0x24, after=0x0C)

    hdr("H. 0xF02EE32C ARGUMENT SHAPE")
    init_fa = aud.audit_function(BITMAP_INIT, max_span=0x80)
    print_function(aud, init_fa)

    print()
    print("Exact caller-visible shape:")
    print(f"  r0 = 0x{FILTER_BITMAP:08X}")
    print(f"  r1 = (*(u32 *)0x{FILTER_BOUND:08X} >> 3) + 1")
    print(f"  call 0x{EXTERNAL_ZERO_CANDIDATE:08X}")
    print()
    print(
        "NOTE: 0xF0210588 is outside canonical ALICE/ZIMAGE, so its body is "
        "not available in this audit. A two-argument zero-fill/memclear role "
        "is only promotable if the callsite census gives consistent supporting "
        "evidence; this script does not silently assume it."
    )

    hdr("I. DECISION GATE")
    print(f"bitmap initializer call confirmed     = {'YES' if reset_seen else 'NO'}")
    print(f"post-reset SET paths                  = {len(set_matches)}")
    print(f"post-reset CLEAR paths                = {len(clear_matches)}")
    print(f"post-reset PREDICATE paths            = {len(pred_matches)}")
    print(f"CFG-valid calls to external 0xF0210588 = {len(valid_zero_calls)}")
    print()
    print("Promotion rules:")
    print("  - Do not infer B709 child membership from bitmap state alone.")
    print("  - Do not call 0xF0210588 memclear unless callsite evidence supports it.")
    print("  - If post-reset SET/CLEAR paths exist, inspect their r0 IDs and branch conditions.")
    print("  - Next logical gate remains exact raw/filtered B709 alignment and Multimedia children.")
    print()
    print("PHONE ACCESSED       : NO")
    print("FLASH MODIFIED       : NO")
    print("PATCH GENERATED      : NO")
    print("PHYSICAL CANDIDATE   : NO")
    print("HARDWARE WRITE AUTHORIZED: NO")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
