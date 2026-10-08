#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
S13.5A.34 - RUNTIME/DUMP MAPPING + F0210588 BODY / COMPACT CALLSITE AUDIT

STRICTLY OFFLINE:
- no USB / COM
- no DA upload
- no D3 / D5 / D6
- no write / erase
- no phone access

Goals
-----
A.33 established:
  - exact path 0x102D1040 -> 0x1031FD20 -> 0xF02EE32C;
  - F02EE32C calls external 0xF0210588 with:
        r0 = 0xF00C1624
        r1 = (*(u32 *)0xF007F04C >> 3) + 1
  - no SET/CLEAR/PREDICATE path was found after this reset point and before
    the valid B709 rebuild within audited callgraph depth <= 4;
  - the verbose F0210588 census was too large (161 call-shaped / 150 CFG-valid).

A.34 therefore:
  1. guards canonical ALICE, ZIMAGE and (when present) the canonical 4 MiB dump;
  2. attempts to PROVE a runtime->physical affine mapping for ZIMAGE using
     several exact non-trivial byte windows, not by assuming F0000000;
  3. only if a consistent mapping is proven, maps and disassembles the real
     bytes at F0210588 and neighboring runtime helper addresses;
  4. performs a compact callsite census for F0210588 and prints clustered
     argument-setup signatures instead of 150 verbose contexts;
  5. never promotes B709 membership and never authorizes hardware mutation.

Default paths follow the project operator workflow.
"""

from __future__ import annotations

import argparse
import hashlib
import struct
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Tuple

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
        "capstone is required in the project venv.\n"
        r'Use: C:\Users\verto\mtkclient\.venv\Scripts\python.exe' "\n"
        f"Import error: {exc}"
    )

TITLE = "S13.5A.34 - RUNTIME/DUMP MAPPING + F0210588 BODY / COMPACT CALLSITE AUDIT"

ALICE_BASE = 0x1024EC00
ALICE_SIZE = 0x157BB4
ALICE_SHA256 = "7246242b67afae0d13104452bc3257827cb778119b54e7a26fb7fb55993697ea"

ZIMAGE_BASE = 0xF023CA50
ZIMAGE_SIZE = 0x185E98
ZIMAGE_SHA256 = "85fba8c8ae8161e4c1f8ced7983ec30d48c54ab10e51c69fcdfb900aca220954"

DUMP_SIZE = 0x400000
DUMP_SHA256 = "2fc100e5704cf3d6fae0817a22ce222397702ffd7351a83763ae1bafd4416922"

TARGET = 0xF0210588
NEIGHBOR_A = 0xF02105B8
SWITCH_HELPER = 0xF02105C8

FILTER_BITMAP = 0xF00C1624
FILTER_BOUND = 0xF007F04C
BITMAP_INIT = 0xF02EE32C
BITMAP_INIT_CALLSITE = 0xF02EE338


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def u32(data: bytes, off: int) -> int:
    return struct.unpack_from("<I", data, off)[0]


def entropyish(chunk: bytes) -> bool:
    if len(chunk) < 32:
        return False
    uniq = len(set(chunk))
    ff = chunk.count(0xFF)
    zz = chunk.count(0x00)
    return uniq >= 12 and ff < len(chunk) * 0.70 and zz < len(chunk) * 0.70


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

    def read(self, addr: int, n: int) -> bytes:
        if not self.contains(addr, n):
            raise ValueError(f"{self.name}: out of range 0x{addr:08X}+0x{n:X}")
        off = addr - self.base
        return self.data[off:off+n]

    def read_u32(self, addr: int) -> int:
        return u32(self.data, addr - self.base)


@dataclass
class Insn:
    addr: int
    size: int
    mnemonic: str
    op_str: str
    target: Optional[int] = None
    is_call: bool = False
    is_jump: bool = False
    literal_addr: Optional[int] = None
    literal_value: Optional[int] = None

    @property
    def text(self) -> str:
        return f"{self.mnemonic:<9} {self.op_str}".rstrip()


class Audit:
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

    def decode_one(self, addr: int) -> Optional[Insn]:
        addr &= ~1
        img = self.image_for(addr)
        if not img or not img.contains(addr, 2):
            return None
        blob = img.read(addr, min(4, img.end - addr))
        ds = list(self.thumb.disasm(blob, addr, count=1))
        if not ds:
            return None

        ci = ds[0]
        is_call = bool(ci.group(CS_GRP_CALL))
        is_jump = bool(ci.group(CS_GRP_JUMP))
        target = None
        if (is_call or is_jump) and ci.operands:
            op0 = ci.operands[0]
            if op0.type == CS_OP_IMM:
                target = int(op0.imm) & 0xFFFFFFFF

        literal_addr = None
        literal_value = None
        if ci.mnemonic.startswith("ldr") and len(ci.operands) >= 2:
            op = ci.operands[1]
            if op.type == CS_OP_MEM and op.mem.base == ARM_REG_PC:
                pc = (addr + 4) & ~3
                literal_addr = (pc + int(op.mem.disp)) & 0xFFFFFFFF
                li = self.image_for(literal_addr)
                if li and li.contains(literal_addr, 4):
                    literal_value = li.read_u32(literal_addr)

        return Insn(
            addr=addr,
            size=ci.size,
            mnemonic=ci.mnemonic,
            op_str=ci.op_str,
            target=target,
            is_call=is_call,
            is_jump=is_jump,
            literal_addr=literal_addr,
            literal_value=literal_value,
        )

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
        if not ds:
            return None
        ci = ds[0]
        if ci.mnemonic != "ldr" or len(ci.operands) < 2:
            return None
        dst, src = ci.operands[0], ci.operands[1]
        if (
            dst.type == CS_OP_REG and dst.reg == ARM_REG_PC
            and src.type == CS_OP_MEM and src.mem.base == ARM_REG_PC
        ):
            lit = (addr + 8 + int(src.mem.disp)) & 0xFFFFFFFF
            if self.alice.contains(lit, 4):
                return self.alice.read_u32(lit)
        return None

    def effective(self, target: int) -> int:
        d = target & ~1
        r = self.resolve_arm_veneer(d)
        return (r & ~1) if r is not None else d

    def nearest_push(self, addr: int, back: int = 0x180) -> Optional[int]:
        img = self.image_for(addr)
        if not img:
            return None
        lo = max(img.base, (addr - back) & ~1)
        best = None
        for a in range(lo, addr + 1, 2):
            ins = self.decode_one(a)
            if ins and ins.mnemonic.lower() == "push":
                best = a
        return best

    def reachable_sites(self, entry: int, max_span: int = 0x1000, max_insns: int = 2500) -> set:
        entry &= ~1
        img = self.image_for(entry)
        if not img:
            return set()

        q = [entry]
        seen = set()
        while q and len(seen) < max_insns:
            a = q.pop()
            a &= ~1
            if a in seen:
                continue
            if a < entry - 4 or a >= entry + max_span:
                continue

            ins = self.decode_one(a)
            if not ins:
                continue
            seen.add(a)

            m = ins.mnemonic.lower()
            o = ins.op_str.lower()
            if (m == "bx" and "lr" in o) or (m == "pop" and "pc" in o):
                continue

            if ins.is_call:
                q.append(a + ins.size)
                continue

            if ins.is_jump:
                if ins.target is not None:
                    q.append(ins.target & ~1)
                # conditional branches keep fallthrough
                if m not in {"b", "b.w", "bx"}:
                    q.append(a + ins.size)
                continue

            q.append(a + ins.size)
        return seen

    def scan_calls_to(self, target: int) -> List[Tuple[str, int, int, Optional[int], bool]]:
        hits = []
        for img in self.images:
            for off in range(0, len(img.data) - 4, 2):
                h1 = struct.unpack_from("<H", img.data, off)[0]
                h2 = struct.unpack_from("<H", img.data, off + 2)[0]
                if (h1 & 0xF800) != 0xF000:
                    continue
                if (h2 & 0xC000) != 0xC000:
                    continue

                site = img.base + off
                ins = self.decode_one(site)
                if not ins or not ins.is_call or ins.target is None:
                    continue

                if self.effective(ins.target) != (target & ~1):
                    continue

                owner = self.nearest_push(site)
                valid = False
                if owner is not None:
                    valid = site in self.reachable_sites(owner)
                hits.append((img.name, site, ins.target, owner, valid))

        # de-dup
        uniq = {}
        for x in hits:
            uniq[(x[0], x[1])] = x
        return [uniq[k] for k in sorted(uniq)]


def hdr(s: str) -> None:
    print()
    print("=" * 120)
    print(s)
    print("=" * 120)


def decode_thumb_blob(data: bytes, runtime_addr: int, max_bytes: int = 0x100) -> List[str]:
    md = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_LITTLE_ENDIAN)
    md.detail = True
    out = []
    blob = data[:max_bytes]
    for ci in md.disasm(blob, runtime_addr):
        out.append(f"0x{ci.address:08X}: {ci.mnemonic:<9} {ci.op_str}".rstrip())
        m = ci.mnemonic.lower()
        o = ci.op_str.lower()
        if (m == "bx" and "lr" in o) or (m == "pop" and "pc" in o):
            break
        if len(out) >= 80:
            break
    return out


def pick_zimage_windows(z: bytes, width: int = 64) -> List[int]:
    candidates = [
        0x0000,
        0x0100,
        0x0800,
        0x2000,
        len(z) // 4,
        len(z) // 2,
        (3 * len(z)) // 4,
        max(0, len(z) - 0x2000),
        max(0, len(z) - 0x100),
    ]

    out = []
    for off in candidates:
        off = max(0, min(off, len(z) - width))
        off &= ~0xF
        chunk = z[off:off+width]
        if entropyish(chunk) and off not in out:
            out.append(off)
    return out[:7]


def find_all(haystack: bytes, needle: bytes, cap: int = 20) -> List[int]:
    out = []
    start = 0
    while len(out) < cap:
        i = haystack.find(needle, start)
        if i < 0:
            break
        out.append(i)
        start = i + 1
    return out


def prove_mapping(dump: bytes, z: bytes) -> Tuple[Optional[int], List[Tuple[int, List[int], List[int]]]]:
    """
    Return (runtime_base_minus_phys_off, evidence rows)
    evidence row = (z_off, physical_occurrences, deltas)
    """
    rows = []
    delta_votes = Counter()

    for zoff in pick_zimage_windows(z):
        chunk = z[zoff:zoff+64]
        occ = find_all(dump, chunk)
        deltas = []
        runtime = ZIMAGE_BASE + zoff
        for phys in occ:
            delta = (runtime - phys) & 0xFFFFFFFF
            deltas.append(delta)
            delta_votes[delta] += 1
        rows.append((zoff, occ, deltas))

    if not delta_votes:
        return None, rows

    delta, votes = delta_votes.most_common(1)[0]

    # Require at least 3 independent windows and no competing tie.
    if votes < 3:
        return None, rows

    if len(delta_votes) > 1:
        second = delta_votes.most_common(2)[1][1]
        if second == votes:
            return None, rows

    # Verify every row that claims this delta really maps exact bytes.
    verified = 0
    for zoff, occ, deltas in rows:
        phys = (ZIMAGE_BASE + zoff - delta) & 0xFFFFFFFF
        if 0 <= phys <= len(dump) - 64:
            if dump[phys:phys+64] == z[zoff:zoff+64]:
                verified += 1

    if verified < 3:
        return None, rows

    return delta, rows


def local_prev_insns(aud: Audit, site: int, count: int = 8) -> List[Insn]:
    img = aud.image_for(site)
    if not img:
        return []

    lo = max(img.base, site - 0x30)
    tmp = []
    a = lo & ~1
    while a < site:
        ins = aud.decode_one(a)
        if not ins:
            a += 2
            continue
        tmp.append(ins)
        a += ins.size

    return tmp[-count:]


def classify_setup(aud: Audit, site: int) -> Tuple[str, Optional[int], Optional[int]]:
    """
    Compact conservative signature of local r0/r1 setup before call.
    Returns signature, r0_literal_or_imm, r1_imm.
    """
    prev = local_prev_insns(aud, site, 10)
    r0 = None
    r1 = None
    r0_kind = "r0=?"
    r1_kind = "r1=?"

    for ins in reversed(prev):
        m = ins.mnemonic.lower()
        op = ins.op_str.lower().replace(" ", "")

        if r0 is None and op.startswith("r0,"):
            if ins.literal_value is not None and m.startswith("ldr"):
                r0 = ins.literal_value
                r0_kind = "r0=literal"
            elif m in {"mov", "movs", "mov.w", "movw"} and "#" in op:
                try:
                    imm = op.split("#", 1)[1]
                    r0 = int(imm, 0)
                    r0_kind = "r0=imm"
                except Exception:
                    r0_kind = "r0=reg/expr"
            else:
                r0_kind = "r0=reg/expr"

        if r1 is None and op.startswith("r1,"):
            if ins.literal_value is not None and m.startswith("ldr"):
                r1 = ins.literal_value
                r1_kind = "r1=literal"
            elif m in {"mov", "movs", "mov.w", "movw"} and "#" in op:
                try:
                    imm = op.split("#", 1)[1]
                    r1 = int(imm, 0)
                    r1_kind = "r1=imm"
                except Exception:
                    r1_kind = "r1=reg/expr"
            else:
                r1_kind = "r1=reg/expr"

        if r0 is not None and r1 is not None:
            break

    sig = f"{r0_kind}; {r1_kind}"
    return sig, r0, r1


def print_context(aud: Audit, site: int, before: int = 0x18, after: int = 0x08) -> None:
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
        mark = " >>>" if a == (site & ~1) else "    "
        ann = []
        if ins.target is not None:
            ann.append(f"target=0x{ins.target:08X} effective=0x{aud.effective(ins.target):08X}")
        if ins.literal_addr is not None and ins.literal_value is not None:
            ann.append(f"literal@0x{ins.literal_addr:08X}=0x{ins.literal_value:08X}")
        suf = " ; " + " ; ".join(ann) if ann else ""
        print(f"{mark} 0x{a:08X}: {ins.text}{suf}")
        a += ins.size


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
        "--dump",
        default=r".\research\f2\data\dumps\mobiwire_dump_2.bin",
        help="Canonical 4 MiB dump; if missing, mapping/body section is skipped.",
    )
    ap.add_argument("--examples", type=int, default=12)
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
    dpath = Path(args.dump)

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
    print(f"  size   = 0x{len(ad):X}")
    print(f"  sha256 = {ah}")
    print(f"  guard  = {'PASS' if ag else 'FAIL'}")

    print(f"ZIMAGE = {zpath}")
    print(f"  runtime base = 0x{ZIMAGE_BASE:08X}")
    print(f"  size         = 0x{len(zd):X}")
    print(f"  sha256       = {zh}")
    print(f"  guard        = {'PASS' if zg else 'FAIL'}")

    if not ag:
        raise SystemExit("ABORT: canonical ALICE guard failed")
    if not zg:
        raise SystemExit("ABORT: canonical ZIMAGE guard failed")

    dump = None
    dg = False
    if dpath.is_file():
        dump = dpath.read_bytes()
        dh = sha256(dump)
        dg = len(dump) == DUMP_SIZE and dh == DUMP_SHA256
        print(f"DUMP   = {dpath}")
        print(f"  size   = 0x{len(dump):X}")
        print(f"  sha256 = {dh}")
        print(f"  guard  = {'PASS' if dg else 'FAIL'}")
    else:
        print(f"DUMP   = {dpath}")
        print("  status = MISSING (mapping/body section will be skipped)")

    aud = Audit(
        Image("ALICE", ad, ALICE_BASE),
        Image("ZIMAGE", zd, ZIMAGE_BASE),
    )

    hdr("B. ZIMAGE RUNTIME -> PHYSICAL DUMP MAPPING PROOF")
    mapping = None

    if dump is None:
        print("SKIP: dump file not present.")
    elif not dg:
        print("SKIP: dump exists but canonical dump guard failed.")
        print("No runtime->physical mapping will be promoted from a non-canonical dump.")
    else:
        mapping, rows = prove_mapping(dump, zd)
        for zoff, occ, deltas in rows:
            print(f"ZIMAGE+0x{zoff:06X} runtime=0x{ZIMAGE_BASE+zoff:08X}")
            print(f"  exact 64-byte dump occurrences = {len(occ)}")
            if occ:
                for phys, delta in zip(occ[:6], deltas[:6]):
                    print(f"    phys=0x{phys:06X}  runtime-phys delta=0x{delta:08X}")

        if mapping is None:
            print()
            print("MAPPING RESULT = NOT PROVEN")
            print("No bytes at F0210588 will be treated as authoritative physical mapping.")
        else:
            print()
            print(f"MAPPING RESULT = PROVEN")
            print(f"runtime_address = physical_offset + 0x{mapping:08X}")
            print(f"candidate target physical offset = 0x{(TARGET-mapping)&0xFFFFFFFF:08X}")

    hdr("C. REAL BODY AT F0210588 IF MAPPING IS PROVEN")
    body_promotable = False

    if dump is None or mapping is None:
        print("SKIP: runtime->physical mapping not proven.")
    else:
        for name, addr in [
            ("TARGET_F0210588", TARGET),
            ("NEIGHBOR_F02105B8", NEIGHBOR_A),
            ("SWITCH_HELPER_F02105C8", SWITCH_HELPER),
        ]:
            phys = addr - mapping
            print()
            print(f"{name}: runtime=0x{addr:08X} -> phys=0x{phys:06X}")
            if not (0 <= phys < len(dump) - 0x100):
                print("  OUTSIDE canonical dump")
                continue

            lines = decode_thumb_blob(dump[phys:phys+0x120], addr, 0x100)
            if not lines:
                print("  Thumb decode: NO INSTRUCTIONS")
                continue
            for line in lines:
                print("  " + line)

            if addr == TARGET:
                body_promotable = True

    hdr("D. COMPACT F0210588 CALLSITE CENSUS")
    hits = aud.scan_calls_to(TARGET)
    valid = [x for x in hits if x[4]]
    print(f"all call-shaped hits = {len(hits)}")
    print(f"CFG-valid hits       = {len(valid)}")

    sigs = Counter()
    r1_imms = Counter()
    r0_literals = Counter()
    samples = defaultdict(list)

    for img_name, site, raw, owner, ok in valid:
        sig, r0, r1 = classify_setup(aud, site)
        sigs[sig] += 1
        if r1 is not None and r1 <= 0x10000:
            r1_imms[r1] += 1
        if r0 is not None and r0 >= 0x10000:
            r0_literals[r0] += 1
        if len(samples[sig]) < 3:
            samples[sig].append((img_name, site, owner, r0, r1))

    print()
    print("Argument setup signatures:")
    for sig, count in sigs.most_common():
        print(f"  {count:3d}  {sig}")

    print()
    print("Most common immediate r1 values:")
    for val, count in r1_imms.most_common(20):
        print(f"  r1=0x{val:X}  count={count}")

    print()
    print("Most common r0 literal values:")
    for val, count in r0_literals.most_common(20):
        suffix = ""
        if val == FILTER_BITMAP:
            suffix = " <FILTER_BITMAP>"
        print(f"  r0=0x{val:08X} count={count}{suffix}")

    hdr("E. REPRESENTATIVE CFG-VALID CALLS")
    printed = 0

    # Always print the known initializer call first when present.
    ordered = sorted(valid, key=lambda x: (0 if x[1] == BITMAP_INIT_CALLSITE else 1, x[0], x[1]))

    seen_sigs = set()
    for img_name, site, raw, owner, ok in ordered:
        sig, r0, r1 = classify_setup(aud, site)

        must = site == BITMAP_INIT_CALLSITE
        novel = sig not in seen_sigs
        if not must and not novel and printed >= args.examples:
            continue
        if not must and not novel:
            continue

        seen_sigs.add(sig)
        printed += 1

        print()
        print(
            f"{img_name} callsite=0x{site:08X} owner≈"
            f"{('0x%08X' % owner) if owner is not None else 'UNKNOWN'}"
        )
        print(f"  signature = {sig}")
        if r0 is not None:
            print(f"  local r0 candidate = 0x{r0:08X}")
        if r1 is not None:
            print(f"  local r1 candidate = 0x{r1:X}")
        print_context(aud, site, before=0x1C, after=0x08)

        if printed >= args.examples and BITMAP_INIT_CALLSITE != site:
            # Continue only until the known callsite has appeared.
            if any(x[1] == BITMAP_INIT_CALLSITE for x in ordered[:ordered.index((img_name,site,raw,owner,ok))+1]):
                break

    hdr("F. KNOWN BITMAP INITIALIZER CALLSITE")
    print(f"initializer function = 0x{BITMAP_INIT:08X}")
    print(f"callsite             = 0x{BITMAP_INIT_CALLSITE:08X}")
    print(f"target               = 0x{TARGET:08X}")
    print(f"r0                   = 0x{FILTER_BITMAP:08X}")
    print(f"r1                   = (*(u32 *)0x{FILTER_BOUND:08X} >> 3) + 1")
    print_context(aud, BITMAP_INIT_CALLSITE, before=0x16, after=0x08)

    hdr("G. DECISION GATE")
    print(f"canonical dump present/guarded = {'YES' if dg else 'NO'}")
    print(f"runtime->physical mapping      = {'PROVEN' if mapping is not None else 'NOT PROVEN'}")
    print(f"F0210588 body decoded          = {'YES' if body_promotable else 'NO'}")
    print(f"CFG-valid calls to F0210588    = {len(valid)}")
    print()
    print("Promotion rules:")
    print("  - If mapping is PROVEN, the printed F0210588 body is authoritative for that canonical dump.")
    print("  - If mapping is NOT PROVEN, do not infer F0210588 body from physical offset guesses.")
    print("  - Callsite clustering alone can support ptr/size calling convention, not exact zero-fill semantics.")
    print("  - Raw/filtered B709 alignment remains gated on exact initializer effect or another structural invariant.")
    print()
    print("PHONE ACCESSED       : NO")
    print("FLASH MODIFIED       : NO")
    print("PATCH GENERATED      : NO")
    print("PHYSICAL CANDIDATE   : NO")
    print("HARDWARE WRITE AUTHORIZED: NO")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
