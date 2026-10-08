#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
S13.5A.50 - B702 FOUR-ID ROLE CLASSIFIER

STRICTLY OFFLINE:
- no USB / COM
- no phone access
- no write / erase
- no patch / repack

A.49 closed facts
-----------------
B702.children = [0x8569, 0x87ED]

record.parent == B702:
    0x86C0
    0x8928

0x8928 is not enumerated by any child array.
Parent-vs-enumeration asymmetry is common globally, so record.parent alone is
not equivalent to visible menu membership.

Registration rows already observed:
    0x8569 -> 0x1033E025
    0x87ED -> 0xF02F3F9D
    0x8928 -> 0x1033D841

A.50 classifies 0x8569 / 0x87ED / 0x86C0 / 0x8928 as a group:
- registry record fields;
- exact parent resolution and B709 root-branch index;
- static selector rows;
- static registration rows;
- registration callback CFGs;
- direct call targets and known registration APIs;
- literal pointers/strings inside callback CFGs;
- exact callsites that feed each ID to 0x10319094;
- structural similarity of callback call-target sets.

Goal:
Determine whether B702.children[] uses visible launcher IDs while 0x86C0/0x8928
are logical/internal IDs, and identify the correct ID to expose/extend rather
than assuming 0x8928 itself must be inserted.

No hardware mutation is produced.
"""

from __future__ import annotations

import argparse
import hashlib
import struct
import sys
from collections import deque
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Set, Tuple

try:
    from capstone import (
        Cs,
        CS_ARCH_ARM,
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
        r"Use C:\Users\verto\mtkclient\.venv\Scripts\python.exe" "\n"
        f"Import error: {exc}"
    )

try:
    sys.stdout.reconfigure(line_buffering=True)
    sys.stderr.reconfigure(line_buffering=True)
except Exception:
    pass

TITLE = "S13.5A.50 - B702 FOUR-ID ROLE CLASSIFIER"

ALICE_BASE = 0x1024EC00
ALICE_SIZE = 0x157BB4
ALICE_SHA256 = "7246242b67afae0d13104452bc3257827cb778119b54e7a26fb7fb55993697ea"

ZIMAGE_BASE = 0xF023CA50
ZIMAGE_SIZE = 0x185E98
ZIMAGE_SHA256 = "85fba8c8ae8161e4c1f8ced7983ec30d48c54ab10e51c69fcdfb900aca220954"

DESC = 0xF037C08C
RECORD_BASE = 0xF0378760
RECORD_COUNT = 895
RECORD_STRIDE = 0x10
RANGE_BASE = 0xF037BF54
RANGE_COUNT = 52
RANGE_STRIDE = 6

SELECTOR_BASE = 0xF03AD120
SELECTOR_COUNT = 18
SELECTOR_STRIDE = 0x14

REGISTRATION_BASE = 0xF0345E68
REGISTRATION_COUNT = 58
REGISTRATION_STRIDE = 8

ROOT = 0xB709
BRANCH = 0xB702

IDS = [0x8569, 0x87ED, 0x86C0, 0x8928]
NAMES = {
    0x8569: "ENUM_8569",
    0x87ED: "ENUM_87ED",
    0x86C0: "PARENTED_86C0",
    0x8928: "AUDIO_8928",
    0xB702: "B702",
    0xB709: "B709",
    0x8321: "IMAGE_8321",
}

RESOURCE_WRAPPER = 0x10319094

KNOWN_FUNCS = {
    0xF02F3F84: "IMAGE_STUB_F02F3F84",
    0x1033D840: "AUDIO_STUB_1033D840",
    0x1033E815 & ~1: "AUDIO_INIT_1033E815",
    0x1033F83C & ~1: "AUDIO_PLAYER_1033F83C",
    0xF02D1928 & ~1: "IMAGE_REG_LIKE_A",
    0xF02D16A0 & ~1: "IMAGE_REG_LIKE_B",
    0x1031F71A & ~1: "AUDIO_REG_A",
    0x1031E120 & ~1: "AUDIO_REG_B",
    0x1031F81C & ~1: "AUDIO_REG_C",
    0x10319094 & ~1: "RESOURCE_WRAPPER_10319094",
}


def hdr(s: str) -> None:
    print()
    print("=" * 120)
    print(s)
    print("=" * 120, flush=True)


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


@dataclass(frozen=True)
class Image:
    name: str
    data: bytes
    base: int

    @property
    def end(self) -> int:
        return self.base + len(self.data)

    def contains(self, addr: int, n: int = 1) -> bool:
        return self.base <= (addr & ~1) and (addr & ~1) + n <= self.end

    def read(self, addr: int, n: int) -> bytes:
        a = addr & ~1
        if not self.contains(a, n):
            raise ValueError(f"{self.name}: out-of-range 0x{a:08X}+0x{n:X}")
        return self.data[a-self.base:a-self.base+n]

    def u16(self, addr: int) -> int:
        return struct.unpack_from("<H", self.read(addr, 2))[0]

    def u32(self, addr: int) -> int:
        return struct.unpack_from("<I", self.read(addr, 4))[0]


@dataclass(frozen=True)
class RangeRec:
    low: int
    high: int
    base: int

    @property
    def width(self) -> int:
        return self.high - self.low + 1

    @property
    def dense_end(self) -> int:
        return self.base + self.width - 1


@dataclass(frozen=True)
class RegistryRec:
    pid: int
    dense: int
    addr: int
    parent: int
    count: int
    f4: int
    f6: int
    f8: int
    fa: int
    child_ptr: int


@dataclass(frozen=True)
class RegistrationRow:
    index: int
    key: int
    field2: int
    callback: int


@dataclass(frozen=True)
class SelectorRow:
    index: int
    key: int
    selectors: Tuple[int, ...]


class Disasm:
    def __init__(self, images: Sequence[Image]):
        self.images = list(images)
        self.cs = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_LITTLE_ENDIAN)
        self.cs.detail = True

    def image_for(self, addr: int) -> Optional[Image]:
        a = addr & ~1
        for img in self.images:
            if img.contains(a):
                return img
        return None

    def one(self, addr: int):
        a = addr & ~1
        img = self.image_for(a)
        if not img:
            return None
        width = min(4, img.end-a)
        xs = list(self.cs.disasm(img.read(a, width), a, count=1))
        return xs[0] if xs else None

    def literal(self, ci) -> Optional[Tuple[int, int]]:
        if not ci.mnemonic.lower().startswith("ldr") or len(ci.operands) < 2:
            return None
        op = ci.operands[1]
        if op.type != CS_OP_MEM or op.mem.base != ARM_REG_PC:
            return None
        lit = (((ci.address + 4) & ~3) + int(op.mem.disp)) & 0xFFFFFFFF
        img = self.image_for(lit)
        if not img or not img.contains(lit, 4):
            return None
        return lit, img.u32(lit)

    @staticmethod
    def is_ret(ci) -> bool:
        m = ci.mnemonic.lower()
        o = ci.op_str.lower().replace(" ", "")
        return (
            (m.startswith("bx") and not m.startswith("blx") and o == "lr")
            or (m == "pop" and "pc" in o)
            or (m.startswith("ldm") and "pc" in o)
        )

    @staticmethod
    def is_uncond_jump(ci) -> bool:
        return ci.mnemonic.lower() in {"b", "b.w", "bx"}

    def cfg(self, entry: int, max_span: int = 0x600) -> Tuple[Dict[int, object], bool]:
        entry &= ~1
        img = self.image_for(entry)
        if not img:
            return {}, True
        lo, hi = entry, min(img.end, entry + max_span)
        q = deque([entry])
        seen = set()
        out = {}
        truncated = False

        while q and len(seen) < 4096:
            a = q.popleft() & ~1
            if a in seen:
                continue
            if not (lo <= a < hi):
                truncated = True
                continue
            ci = self.one(a)
            if not ci:
                continue
            seen.add(a)
            out[a] = ci

            if self.is_ret(ci):
                continue

            if ci.group(CS_GRP_CALL):
                q.append(a + ci.size)
                continue

            if ci.group(CS_GRP_JUMP):
                target = None
                if ci.operands and ci.operands[0].type == CS_OP_IMM:
                    target = int(ci.operands[0].imm) & 0xFFFFFFFF
                    target &= ~1
                if target is not None:
                    if lo <= target < hi:
                        q.append(target)
                    else:
                        truncated = True
                if not self.is_uncond_jump(ci):
                    q.append(a + ci.size)
                continue

            q.append(a + ci.size)

        if q:
            truncated = True
        return out, truncated

    def direct_calls(self, insns: Dict[int, object]) -> List[Tuple[int,int]]:
        out = []
        for a in sorted(insns):
            ci = insns[a]
            if not ci.group(CS_GRP_CALL):
                continue
            if ci.operands and ci.operands[0].type == CS_OP_IMM:
                target = int(ci.operands[0].imm) & 0xFFFFFFFF
                out.append((a, target & ~1))
        return out

    def exact_literal_xrefs(self, value: int) -> List[Tuple[str,int,int]]:
        needle = struct.pack("<I", value & 0xFFFFFFFF)
        out = set()
        for img in self.images:
            pos = 0
            lits = []
            while True:
                off = img.data.find(needle, pos)
                if off < 0:
                    break
                lits.append(img.base + off)
                pos = off + 1
            for lit in lits:
                lo = max(img.base, lit - 0x1000) & ~1
                for a in range(lo, lit, 2):
                    ci = self.one(a)
                    if not ci:
                        continue
                    lv = self.literal(ci)
                    if lv == (lit, value):
                        out.add((img.name, a, lit))
        return sorted(out)


def load_guard(path: Path, size: int, digest: str, name: str) -> bytes:
    print(f"Loading {name}: {path}", flush=True)
    if not path.is_file():
        raise SystemExit(f"Missing {name}: {path}")
    data = path.read_bytes()
    got = sha256(data)
    ok = len(data) == size and got == digest
    print(f"  size   = 0x{len(data):X}")
    print(f"  sha256 = {got}")
    print(f"  guard  = {'PASS' if ok else 'FAIL'}")
    if not ok:
        raise SystemExit(f"ABORT: canonical {name} guard failed")
    return data


def decode_ranges(z: Image) -> List[RangeRec]:
    out = []
    for i in range(RANGE_COUNT):
        a = RANGE_BASE + i*RANGE_STRIDE
        lo, hi, base = struct.unpack("<HHH", z.read(a, 6))
        out.append(RangeRec(lo, hi, base))
    return out


def map_id(ranges: Sequence[RangeRec], pid: int) -> Optional[int]:
    lo, hi = 0, len(ranges)-1
    while lo <= hi:
        mid = (lo+hi)//2
        r = ranges[mid]
        if pid < r.low:
            hi = mid-1
        elif pid > r.high:
            lo = mid+1
        else:
            return r.base + pid - r.low
    return None


def inverse_dense(ranges: Sequence[RangeRec], dense: int) -> Optional[int]:
    for r in ranges:
        if r.base <= dense <= r.dense_end:
            return r.low + dense - r.base
    return None


def decode_record(z: Image, ranges: Sequence[RangeRec], pid: int) -> Optional[RegistryRec]:
    dense = map_id(ranges, pid)
    if dense is None:
        return None
    a = RECORD_BASE + dense*RECORD_STRIDE
    parent, count, f4, f6, f8, fa = struct.unpack("<HHHHHH", z.read(a, 12))
    ptr = z.u32(a+0xC)
    return RegistryRec(pid, dense, a, parent, count, f4, f6, f8, fa, ptr)


def read_children(z: Image, rec: RegistryRec) -> Tuple[List[int], str]:
    if rec.count == 0:
        return [], "EMPTY"
    if rec.child_ptr == 0:
        return [], "NULL"
    n = rec.count*2
    if not z.contains(rec.child_ptr, n):
        return [], "OUT_OF_ZIMAGE"
    return list(struct.unpack("<"+"H"*rec.count, z.read(rec.child_ptr,n))), "OK"


def decode_registrations(z: Image) -> List[RegistrationRow]:
    out = []
    for i in range(REGISTRATION_COUNT):
        a = REGISTRATION_BASE + i*REGISTRATION_STRIDE
        key, f2, cb = struct.unpack("<HHI", z.read(a, 8))
        out.append(RegistrationRow(i,key,f2,cb))
    return out


def decode_selectors(z: Image) -> List[SelectorRow]:
    out = []
    for i in range(SELECTOR_COUNT):
        a = SELECTOR_BASE + i*SELECTOR_STRIDE
        vals = struct.unpack("<"+"H"*10, z.read(a, SELECTOR_STRIDE))
        out.append(SelectorRow(i, vals[0], tuple(vals[1:])))
    return out


def all_records(z: Image, ranges: Sequence[RangeRec]) -> List[Tuple[int,Optional[int],int,int]]:
    out = []
    for dense in range(RECORD_COUNT):
        pid = inverse_dense(ranges, dense)
        a = RECORD_BASE + dense*RECORD_STRIDE
        parent = z.u16(a)
        count = z.u16(a+2)
        out.append((dense,pid,parent,count))
    return out


def parent_of(z: Image, ranges: Sequence[RangeRec], pid: int) -> Tuple[Optional[int],str]:
    rec = decode_record(z,ranges,pid)
    if rec is None:
        return None,"UNMAPPED"
    if rec.parent != 0:
        return rec.parent,"DIRECT_FIELD"

    # fallback: firmware scans owner child arrays in dense order.
    for dense in range(RECORD_COUNT):
        owner_pid = inverse_dense(ranges,dense)
        if owner_pid is None:
            continue
        owner = decode_record(z,ranges,owner_pid)
        if owner is None:
            continue
        kids,status = read_children(z,owner)
        if status != "OK":
            continue
        if pid in kids:
            return owner_pid,"CHILD_SCAN"
    return None,"NONE"


def root_branch_index(z: Image, ranges: Sequence[RangeRec], pid: int) -> Tuple[Optional[int],List[int],str]:
    chain = [pid]
    seen = {pid}
    cur = pid
    for _ in range(16):
        p,src = parent_of(z,ranges,cur)
        if p is None:
            return None,chain,"NO_PARENT"
        chain.append(p)
        if p == ROOT:
            child = cur
            rootrec = decode_record(z,ranges,ROOT)
            if rootrec is None:
                return None,chain,"ROOT_UNMAPPED"
            kids,status = read_children(z,rootrec)
            if status != "OK":
                return None,chain,"ROOT_CHILD_ARRAY_"+status
            try:
                return kids.index(child),chain,"OK"
            except ValueError:
                return None,chain,"DIRECT_BRANCH_NOT_ENUMERATED"
        if p in seen:
            return None,chain,"CYCLE"
        seen.add(p)
        cur = p
    return None,chain,"DEPTH_LIMIT"


def printable_ascii(img: Image, ptr: int, maxlen: int = 120) -> Optional[str]:
    if not img.contains(ptr, 4):
        return None
    b = bytearray()
    for i in range(maxlen):
        if not img.contains(ptr+i,1):
            break
        x = img.read(ptr+i,1)[0]
        if x == 0:
            break
        if x < 0x20 or x > 0x7E:
            return None
        b.append(x)
    if len(b) >= 4:
        return b.decode("ascii","ignore")
    return None


def printable_utf16(img: Image, ptr: int, maxchars: int = 80) -> Optional[str]:
    if not img.contains(ptr, 8):
        return None
    chars = []
    for i in range(maxchars):
        if not img.contains(ptr+2*i,2):
            break
        v = img.u16(ptr+2*i)
        if v == 0:
            break
        if not (0x20 <= v <= 0x7E):
            return None
        chars.append(chr(v))
    if len(chars) >= 4:
        return "".join(chars)
    return None


def pointer_string(images: Sequence[Image], ptr: int) -> Optional[str]:
    for img in images:
        a = printable_ascii(img,ptr)
        if a:
            return f"{img.name}:ASCII:{a!r}"
        u = printable_utf16(img,ptr)
        if u:
            return f"{img.name}:UTF16:{u!r}"
    return None


def owner_by_push(dis: Disasm, site: int, back: int = 0x300) -> int:
    img = dis.image_for(site)
    if not img:
        return site & ~1
    start = max(img.base, (site-back)&~1)
    best = None
    for a in range(start, site+1, 2):
        ci = dis.one(a)
        if not ci:
            continue
        if ci.mnemonic.lower().startswith("push") and "lr" in ci.op_str.lower():
            best = a
    return best if best is not None else site & ~1


def mapper_callsites(dis: Disasm, img: Image, pid: int) -> List[Tuple[int,int]]:
    """
    Conservative local pattern:
      ldr r0, =pid  OR movw/movs immediate pid is intentionally not generalized.
      ... within <= 6 Thumb instructions ...
      bl 10319094
    Exact literal-load pattern only, to avoid heuristic noise.
    """
    out = []
    needle = struct.pack("<I", pid)
    pos = 0
    literal_words = []
    while True:
        off = img.data.find(needle,pos)
        if off < 0:
            break
        literal_words.append(img.base+off)
        pos=off+1

    for lit in literal_words:
        lo = max(img.base,lit-0x800)&~1
        for a in range(lo,lit,2):
            ci = dis.one(a)
            if not ci:
                continue
            lv = dis.literal(ci)
            if lv != (lit,pid):
                continue
            # require destination r0
            if not ci.operands or ci.operands[0].type != CS_OP_REG:
                continue
            if dis.cs.reg_name(ci.operands[0].reg).lower() != "r0":
                continue
            p = a + ci.size
            for _ in range(7):
                cj = dis.one(p)
                if not cj:
                    break
                if cj.group(CS_GRP_CALL) and cj.operands and cj.operands[0].type == CS_OP_IMM:
                    target = int(cj.operands[0].imm)&0xFFFFFFFF
                    if (target&~1) == (RESOURCE_WRAPPER&~1):
                        out.append((a,p))
                    break
                p += cj.size
    return sorted(set(out))


def main() -> int:
    ap = argparse.ArgumentParser(description=TITLE)
    ap.add_argument("--alice", default=r".\research\f2\work\extracted\altice_alice\alice-py.bin")
    ap.add_argument("--zimage", default=r".\research\f2\work\extracted\altice_platform\zimage.bin")
    args = ap.parse_args()

    print("="*120)
    print(TITLE)
    print("="*120)
    print("STRICTLY OFFLINE")
    print("PHONE ACCESSED       : NO")
    print("FLASH MODIFIED       : NO")
    print("PATCH GENERATED      : NO")
    print("REPACK               : NO")

    hdr("A. CANONICAL GUARDS")
    ad = load_guard(Path(args.alice),ALICE_SIZE,ALICE_SHA256,"ALICE")
    zd = load_guard(Path(args.zimage),ZIMAGE_SIZE,ZIMAGE_SHA256,"ZIMAGE")
    alice = Image("ALICE",ad,ALICE_BASE)
    zimg = Image("ZIMAGE",zd,ZIMAGE_BASE)
    images=[alice,zimg]
    dis=Disasm(images)

    hdr("B. DESCRIPTOR / FOUR-ID REGISTRY RECORDS")
    d0=zimg.u32(DESC)
    d4=zimg.u32(DESC+4)
    d8=zimg.u16(DESC+8)
    print(f"descriptor +0=0x{d0:08X} +4=0x{d4:08X} +8={d8}")
    desc_ok=(d0==RECORD_BASE and d4==RANGE_BASE and d8==RANGE_COUNT)
    print(f"descriptor regression={'PASS' if desc_ok else 'FAIL'}")
    if not desc_ok:
        return 2

    ranges=decode_ranges(zimg)

    recs: Dict[int,RegistryRec]={}
    for pid in IDS+[BRANCH,ROOT]:
        r=decode_record(zimg,ranges,pid)
        if r is None:
            print(f"{NAMES.get(pid,hex(pid))}: UNMAPPED")
            continue
        recs[pid]=r
        kids,status=read_children(zimg,r)
        print(
            f"0x{pid:04X}<{NAMES.get(pid,'')}> dense={r.dense} rec=0x{r.addr:08X} "
            f"parent=0x{r.parent:04X} count={r.count} +4=0x{r.f4:04X} "
            f"+6=0x{r.f6:04X} +8=0x{r.f8:04X} +A=0x{r.fa:04X} "
            f"+C=0x{r.child_ptr:08X} children_status={status}"
        )
        if kids:
            print("  children: "+", ".join(f"0x{x:04X}" for x in kids))

    hdr("C. EXACT GET_PARENT / B709 ROOT-BRANCH RESULT")
    for pid in IDS:
        p,src=parent_of(zimg,ranges,pid)
        idx,chain,status=root_branch_index(zimg,ranges,pid)
        print(
            f"0x{pid:04X}<{NAMES[pid]}> parent={('0x%04X'%p) if p is not None else 'NONE'} "
            f"via={src} root_index={idx} status={status}"
        )
        print("  chain: "+" -> ".join(f"0x{x:04X}" for x in chain))

    hdr("D. SELECTOR ROWS")
    selectors=decode_selectors(zimg)
    selector_map={}
    for pid in IDS:
        rows=[r for r in selectors if r.key==pid]
        selector_map[pid]=rows
        print(f"0x{pid:04X}<{NAMES[pid]}> rows={len(rows)}")
        for r in rows:
            print(
                f"  row[{r.index:02d}] "
                +" ".join(f"s{i+1}=0x{v:04X}" for i,v in enumerate(r.selectors))
            )
        if not rows:
            print("  NONE")

    hdr("E. REGISTRATION ROWS")
    regs=decode_registrations(zimg)
    reg_map={}
    callbacks={}
    for pid in IDS:
        rows=[r for r in regs if r.key==pid]
        reg_map[pid]=rows
        print(f"0x{pid:04X}<{NAMES[pid]}> rows={len(rows)}")
        for r in rows:
            print(f"  row[{r.index:02d}] field2=0x{r.field2:04X} callback=0x{r.callback:08X}")
            callbacks.setdefault(pid,[]).append(r.callback)
        if not rows:
            print("  NONE")

    hdr("F. CALLBACK CFG CLASSIFICATION")
    callback_callsets: Dict[int,Set[int]]={}
    for pid in IDS:
        for cb in callbacks.get(pid,[]):
            entry=cb&~1
            img=dis.image_for(entry)
            print()
            print(
                f"ID 0x{pid:04X}<{NAMES[pid]}> callback=0x{cb:08X} "
                f"entry=0x{entry:08X} image={img.name if img else 'UNMAPPED'}"
            )
            if not img:
                continue
            insns,trunc=dis.cfg(entry,0x500)
            calls=dis.direct_calls(insns)
            callset={t for _,t in calls}
            callback_callsets[pid]=callset
            print(f"  cfg_instructions={len(insns)} truncated={trunc}")
            print(f"  direct_calls={len(calls)}")
            for site,target in calls:
                lbl=KNOWN_FUNCS.get(target,"")
                print(f"    0x{site:08X} -> 0x{target:08X} {lbl}")

            lits=[]
            for a in sorted(insns):
                ci=insns[a]
                lv=dis.literal(ci)
                if lv:
                    la,v=lv
                    lits.append((a,la,v))
            print(f"  literal_loads={len(lits)}")
            for site,la,v in lits[:100]:
                tags=[]
                if v in IDS:
                    tags.append(NAMES[v])
                if (v&~1) in KNOWN_FUNCS:
                    tags.append(KNOWN_FUNCS[v&~1])
                s=pointer_string(images,v&~1)
                suffix=""
                if tags:
                    suffix+=" <"+",".join(tags)+">"
                if s:
                    suffix+=" "+s
                print(f"    site=0x{site:08X} lit=0x{la:08X} value=0x{v:08X}{suffix}")

            print("  CFG:")
            for a in sorted(insns):
                ci=insns[a]
                suffix=""
                lv=dis.literal(ci)
                if lv:
                    la,v=lv
                    suffix=f" ; literal@0x{la:08X}=0x{v:08X}"
                print(f"    0x{a:08X}: {ci.mnemonic:<9} {ci.op_str}{suffix}")

    hdr("G. CALLBACK CALLSET SIMILARITY")
    for i,p1 in enumerate(IDS):
        for p2 in IDS[i+1:]:
            s1=callback_callsets.get(p1,set())
            s2=callback_callsets.get(p2,set())
            if not s1 and not s2:
                continue
            inter=s1&s2
            union=s1|s2
            j=(len(inter)/len(union)) if union else 0.0
            print(
                f"0x{p1:04X}<{NAMES[p1]}> vs 0x{p2:04X}<{NAMES[p2]}>: "
                f"calls1={len(s1)} calls2={len(s2)} shared={len(inter)} jaccard={j:.3f}"
            )
            if inter:
                print("  shared: "+", ".join(
                    f"0x{x:08X}<{KNOWN_FUNCS.get(x,'')}>" for x in sorted(inter)
                ))

    hdr("H. KNOWN-STUB DISTANCES / STATIC POINTER RELATIONS")
    for pid in IDS:
        for cb in callbacks.get(pid,[]):
            e=cb&~1
            print(f"0x{pid:04X} callback entry 0x{e:08X}:")
            for known,label in sorted(KNOWN_FUNCS.items()):
                if dis.image_for(e) is not None and dis.image_for(known) is not None:
                    if dis.image_for(e).name == dis.image_for(known).name:
                        delta=e-known
                        if abs(delta) <= 0x2000:
                            print(f"  delta to {label} 0x{known:08X}: {delta:+#x}")

    hdr("I. EXACT 10319094 CALLSITES BY ID")
    for pid in IDS:
        hits=[]
        for img in images:
            hits.extend((img.name,load,call) for load,call in mapper_callsites(dis,img,pid))
        print(f"0x{pid:04X}<{NAMES[pid]}> exact literal->10319094 callsites={len(hits)}")
        for img_name,load,call in hits:
            owner=owner_by_push(dis,load)
            print(
                f"  {img_name:7s} owner~0x{owner:08X} load=0x{load:08X} call=0x{call:08X}"
            )

    hdr("J. RAW CALLBACK POINTER XREFS")
    for pid in IDS:
        for cb in callbacks.get(pid,[]):
            for value,label in [(cb,"THUMB_PTR"),(cb&~1,"ENTRY")]:
                xs=dis.exact_literal_xrefs(value)
                print(
                    f"0x{pid:04X} callback {label}=0x{value:08X} exact_code_xrefs={len(xs)}"
                )
                for img_name,site,lit in xs[:40]:
                    print(f"  {img_name:7s} site=0x{site:08X} literal=0x{lit:08X}")

    hdr("K. DECISION GATE")
    print("Facts to classify:")
    for pid in IDS:
        r=recs.get(pid)
        p,src=parent_of(zimg,ranges,pid)
        idx,chain,status=root_branch_index(zimg,ranges,pid)
        print(
            f"0x{pid:04X}<{NAMES[pid]}> "
            f"record_parent={('0x%04X'%r.parent) if r else 'NONE'} "
            f"resolved_parent={('0x%04X'%p) if p is not None else 'NONE'} "
            f"root_index={idx} selector_rows={len(selector_map.get(pid,[]))} "
            f"registration_rows={len(reg_map.get(pid,[]))}"
        )

    cb8569=(callbacks.get(0x8569) or [None])[0]
    cb8928=(callbacks.get(0x8928) or [None])[0]
    cb87ed=(callbacks.get(0x87ED) or [None])[0]
    cb86c0=(callbacks.get(0x86C0) or [None])[0]

    same_branch=True
    branch_indices=[]
    for pid in IDS:
        idx,_,st=root_branch_index(zimg,ranges,pid)
        branch_indices.append(idx)
        if idx is None:
            same_branch=False
    same_branch = same_branch and len(set(branch_indices))==1

    print()
    print(f"all four IDs resolve to same B709 branch = {'YES' if same_branch else 'NO'}")
    print(f"8569 callback = {('0x%08X'%cb8569) if cb8569 is not None else 'NONE'}")
    print(f"87ED callback = {('0x%08X'%cb87ed) if cb87ed is not None else 'NONE'}")
    print(f"86C0 callback = {('0x%08X'%cb86c0) if cb86c0 is not None else 'NONE'}")
    print(f"8928 callback = {('0x%08X'%cb8928) if cb8928 is not None else 'NONE'}")

    print()
    print("A.50 does NOT choose a patch.")
    print("Promote a launcher/internal-ID pairing only if callback CFG, resources, and")
    print("callsite evidence converge. The next gate should then target the visible")
    print("launcher representation, not blindly insert 0x8928 into B702.children.")

    print()
    print("PHONE ACCESSED       : NO")
    print("FLASH MODIFIED       : NO")
    print("PATCH GENERATED      : NO")
    print("PHYSICAL CANDIDATE   : NO")
    print("HARDWARE WRITE AUTHORIZED: NO")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
