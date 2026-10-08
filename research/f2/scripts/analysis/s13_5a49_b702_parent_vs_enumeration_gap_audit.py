#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
S13.5A.49 - B702 PARENT-vs-ENUMERATION GAP AUDIT

STRICTLY OFFLINE:
- no USB / COM
- no phone access
- no write / erase
- no patch / repack

Context already closed
----------------------
- Audio backend/frontend exists.
- resolver/registration 0x8928 exists.
- Audio is not visible.
- B709 root filtering for the immediate rebuild is already closed by A.38.
- A.48 v2 proved:
    B709.children = [B702, AF2A, B707, 8321, B6FE, B6FD, 9639, B700, B705]
    B702.children = [8569, 87ED]
    8928.parent   = B702
  therefore parent-field ancestry and enumerated child arrays are not reciprocal.

Active question
---------------
Is 0x8928 the unique logically-parented B702 item omitted from B702.children[]?
And is it already present as a latent contiguous third halfword after the two
active B702 child entries?

If yes, that would identify a concrete static exposure mechanism rather than a
generic "visibility gate".

No hardware candidate is produced by this script.
"""

from __future__ import annotations

import argparse
import hashlib
import struct
import sys
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Tuple

try:
    sys.stdout.reconfigure(line_buffering=True)
    sys.stderr.reconfigure(line_buffering=True)
except Exception:
    pass

TITLE = "S13.5A.49 - B702 PARENT-vs-ENUMERATION GAP AUDIT"

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

POOL_START = 0xF03786F0
POOL_END = 0xF0378760

B702 = 0xB702
B709 = 0xB709
AUDIO = 0x8928
KNOWN_B702_ENUM = (0x8569, 0x87ED)

NAMES = {
    0x8569: "B702_CHILD_8569",
    0x87ED: "B702_CHILD_87ED",
    0x8928: "AUDIO_8928",
    0xB702: "B702",
    0xB709: "B709",
    0x8321: "IMAGE_8321",
    0xB700: "B700",
    0xB6FF: "B6FF",
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
    data: bytes
    base: int = ZIMAGE_BASE
    name: str = "ZIMAGE"

    @property
    def end(self) -> int:
        return self.base + len(self.data)

    def contains(self, addr: int, n: int = 1) -> bool:
        return self.base <= addr and addr + n <= self.end

    def read(self, addr: int, n: int) -> bytes:
        if not self.contains(addr, n):
            raise ValueError(f"out-of-range 0x{addr:08X}+0x{n:X}")
        off = addr - self.base
        return self.data[off:off+n]

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
    dense: int
    public_id: Optional[int]
    addr: int
    parent: int
    count: int
    f4: int
    f6: int
    f8: int
    fa: int
    child_ptr: int


@dataclass(frozen=True)
class SelectorRow:
    index: int
    key: int
    selectors: Tuple[int, ...]


@dataclass(frozen=True)
class RegistrationRow:
    index: int
    key: int
    field2: int
    callback: int


def load_guard(path: Path) -> bytes:
    print(f"Loading ZIMAGE: {path}", flush=True)
    if not path.is_file():
        raise SystemExit(f"Missing ZIMAGE: {path}")
    data = path.read_bytes()
    got = sha256(data)
    ok = len(data) == ZIMAGE_SIZE and got == ZIMAGE_SHA256
    print(f"  size   = 0x{len(data):X}")
    print(f"  sha256 = {got}")
    print(f"  guard  = {'PASS' if ok else 'FAIL'}")
    if not ok:
        raise SystemExit("ABORT: canonical ZIMAGE guard failed")
    return data


def decode_ranges(img: Image) -> List[RangeRec]:
    out = []
    for i in range(RANGE_COUNT):
        a = RANGE_BASE + i * RANGE_STRIDE
        lo, hi, base = struct.unpack("<HHH", img.read(a, 6))
        out.append(RangeRec(lo, hi, base))
    return out


def map_id(ranges: Sequence[RangeRec], pid: int) -> Optional[int]:
    lo, hi = 0, len(ranges) - 1
    while lo <= hi:
        mid = (lo + hi) // 2
        r = ranges[mid]
        if pid < r.low:
            hi = mid - 1
        elif pid > r.high:
            lo = mid + 1
        else:
            return r.base + pid - r.low
    return None


def inverse_dense(ranges: Sequence[RangeRec], dense: int) -> Optional[int]:
    for r in ranges:
        if r.base <= dense <= r.dense_end:
            return r.low + dense - r.base
    return None


def decode_record(img: Image, ranges: Sequence[RangeRec], dense: int) -> RegistryRec:
    a = RECORD_BASE + dense * RECORD_STRIDE
    parent, count, f4, f6, f8, fa = struct.unpack("<HHHHHH", img.read(a, 12))
    child_ptr = img.u32(a + 0xC)
    return RegistryRec(
        dense=dense,
        public_id=inverse_dense(ranges, dense),
        addr=a,
        parent=parent,
        count=count,
        f4=f4,
        f6=f6,
        f8=f8,
        fa=fa,
        child_ptr=child_ptr,
    )


def record_for_id(img: Image, ranges: Sequence[RangeRec], pid: int) -> Optional[RegistryRec]:
    dense = map_id(ranges, pid)
    if dense is None:
        return None
    return decode_record(img, ranges, dense)


def read_children(img: Image, rec: RegistryRec) -> Tuple[List[int], str]:
    if rec.count == 0:
        return [], "EMPTY"
    if rec.child_ptr == 0:
        return [], "NULL_PTR"
    n = rec.count * 2
    if not img.contains(rec.child_ptr, n):
        return [], "OUT_OF_ZIMAGE"
    vals = list(struct.unpack("<" + "H" * rec.count, img.read(rec.child_ptr, n)))
    return vals, "OK"


def fmt_id(pid: Optional[int]) -> str:
    if pid is None:
        return "NONE"
    return f"0x{pid:04X}" + (f"<{NAMES[pid]}>" if pid in NAMES else "")


def fmt_rec(r: RegistryRec) -> str:
    return (
        f"dense={r.dense:3d} id={fmt_id(r.public_id):22s} rec=0x{r.addr:08X} "
        f"parent=0x{r.parent:04X} count={r.count:2d} "
        f"+4=0x{r.f4:04X} +6=0x{r.f6:04X} +8=0x{r.f8:04X} +A=0x{r.fa:04X} "
        f"child_ptr=0x{r.child_ptr:08X}"
    )


def decode_selectors(img: Image) -> List[SelectorRow]:
    out = []
    for i in range(SELECTOR_COUNT):
        a = SELECTOR_BASE + i * SELECTOR_STRIDE
        vals = struct.unpack("<" + "H"*10, img.read(a, SELECTOR_STRIDE))
        out.append(SelectorRow(i, vals[0], tuple(vals[1:])))
    return out


def decode_registrations(img: Image) -> List[RegistrationRow]:
    out = []
    for i in range(REGISTRATION_COUNT):
        a = REGISTRATION_BASE + i * REGISTRATION_STRIDE
        key, field2, cb = struct.unpack("<HHI", img.read(a, 8))
        out.append(RegistrationRow(i, key, field2, cb))
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description=TITLE)
    ap.add_argument(
        "--zimage",
        default=r".\research\f2\work\extracted\altice_platform\zimage.bin",
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

    hdr("A. CANONICAL GUARD / DESCRIPTOR REGRESSION")
    data = load_guard(Path(args.zimage))
    img = Image(data)

    d0 = img.u32(DESC+0)
    d4 = img.u32(DESC+4)
    d8 = img.u16(DESC+8)
    desc_ok = (d0 == RECORD_BASE and d4 == RANGE_BASE and d8 == RANGE_COUNT)
    print(f"descriptor +0=0x{d0:08X} +4=0x{d4:08X} +8={d8}")
    print(f"descriptor regression = {'PASS' if desc_ok else 'FAIL'}")
    if not desc_ok:
        return 2

    ranges = decode_ranges(img)
    all_records = [decode_record(img, ranges, d) for d in range(RECORD_COUNT)]

    hdr("B. B702 DECLARED-PARENT SET vs ENUMERATED CHILD SET")
    b702 = record_for_id(img, ranges, B702)
    assert b702 is not None
    enum_children, enum_status = read_children(img, b702)

    declared = sorted(
        r.public_id for r in all_records
        if r.public_id is not None and r.parent == B702
    )
    enumerated = list(enum_children)
    declared_set = set(declared)
    enum_set = set(enumerated)

    missing_from_enum = sorted(declared_set - enum_set)
    extra_in_enum = sorted(enum_set - declared_set)

    print(fmt_rec(b702))
    print(f"child-array status = {enum_status}")
    print("declared by record+0 parent=B702:")
    for pid in declared:
        print(f"  {fmt_id(pid)} dense={map_id(ranges, pid)}")
    print("enumerated B702.children:")
    for i, pid in enumerate(enumerated):
        print(f"  [{i}] {fmt_id(pid)} dense={map_id(ranges, pid)}")
    print("declared-but-not-enumerated:")
    for pid in missing_from_enum:
        print(f"  {fmt_id(pid)}")
    if not missing_from_enum:
        print("  NONE")
    print("enumerated-but-parent-field-differs:")
    for pid in extra_in_enum:
        r = record_for_id(img, ranges, pid)
        p = r.parent if r else None
        print(f"  {fmt_id(pid)} record_parent={fmt_id(p)}")
    if not extra_in_enum:
        print("  NONE")

    unique_audio_omission = (missing_from_enum == [AUDIO])
    print()
    print(f"8928 unique declared-but-not-enumerated item = {'YES' if unique_audio_omission else 'NO'}")

    hdr("C. GLOBAL SEARCH: IS 8928 ENUMERATED ANYWHERE?")
    owners = []
    invalid_arrays = []
    child_owner_map: Dict[int, List[Tuple[int, Optional[int], int]]] = defaultdict(list)

    for r in all_records:
        kids, status = read_children(img, r)
        if r.count and status != "OK":
            invalid_arrays.append((r, status))
            continue
        for idx, cid in enumerate(kids):
            child_owner_map[cid].append((r.dense, r.public_id, idx))
            if cid == AUDIO:
                owners.append((r.dense, r.public_id, idx, r.child_ptr))

    print(f"validity: invalid non-empty child arrays = {len(invalid_arrays)}")
    for r, status in invalid_arrays[:30]:
        print(f"  {fmt_rec(r)} status={status}")
    print(f"global child-array owners of 0x8928 = {len(owners)}")
    for dense, pid, idx, ptr in owners:
        print(
            f"  owner dense={dense} public={fmt_id(pid)} index={idx} "
            f"child_ptr=0x{ptr:08X}"
        )
    if not owners:
        print("  NONE")

    hdr("D. HOW COMMON IS PARENT-vs-ENUMERATION ASYMMETRY?")
    # For every mapped parent, compare IDs whose record+0 names that parent
    # against the parent's explicit child array.
    mismatch_rows = []
    exact_rows = 0
    parents_considered = 0

    for parent_rec in all_records:
        parent_id = parent_rec.public_id
        if parent_id is None:
            continue

        declared_ids = {
            r.public_id for r in all_records
            if r.public_id is not None and r.parent == parent_id
        }
        kids, status = read_children(img, parent_rec)
        enum_ids = set(kids) if status in {"OK", "EMPTY"} else set()

        if not declared_ids and not enum_ids:
            continue

        parents_considered += 1
        miss = sorted(declared_ids - enum_ids)
        extra = sorted(enum_ids - declared_ids)

        if not miss and not extra:
            exact_rows += 1
        else:
            mismatch_rows.append(
                (parent_id, parent_rec.dense, len(declared_ids), len(enum_ids), miss, extra)
            )

    print(f"parents with declared and/or enumerated children = {parents_considered}")
    print(f"exact reciprocal parent sets                  = {exact_rows}")
    print(f"asymmetric parent sets                        = {len(mismatch_rows)}")
    print()

    # Put B702 first, then smallest total mismatch.
    mismatch_rows.sort(
        key=lambda x: (0 if x[0] == B702 else 1, len(x[4]) + len(x[5]), x[0])
    )
    for parent_id, dense, nd, ne, miss, extra in mismatch_rows[:80]:
        print(
            f"parent={fmt_id(parent_id):22s} dense={dense:3d} "
            f"declared={nd:2d} enumerated={ne:2d} "
            f"missing={len(miss):2d} extra={len(extra):2d}"
        )
        if miss:
            print("  missing: " + ", ".join(fmt_id(x) for x in miss))
        if extra:
            print("  extra  : " + ", ".join(fmt_id(x) for x in extra))
    if len(mismatch_rows) > 80:
        print(f"... {len(mismatch_rows)-80} more asymmetric parents omitted ...")

    hdr("E. CHILD-ARRAY POOL OWNERS F03786F0..F0378760")
    pool_owners = []
    for r in all_records:
        if r.count <= 0 or r.child_ptr == 0:
            continue
        if POOL_START <= r.child_ptr < POOL_END:
            pool_owners.append((r.child_ptr, r.child_ptr + r.count*2, r))

    pool_owners.sort(key=lambda x: (x[0], x[1], x[2].dense))
    for start, end, r in pool_owners:
        kids, status = read_children(img, r)
        print(
            f"0x{start:08X}..0x{end-1:08X} owner={fmt_id(r.public_id):22s} "
            f"dense={r.dense:3d} count={r.count:2d} status={status}"
        )
        if status == "OK":
            print("  " + " ".join(f"0x{x:04X}" for x in kids))

    hdr("F. RAW U16 POOL DUMP WITH OWNER-BOUNDARY ANNOTATION")
    starts = defaultdict(list)
    ends = defaultdict(list)
    for start, end, r in pool_owners:
        starts[start].append(r)
        ends[end].append(r)

    for a in range(POOL_START, POOL_END, 2):
        annotations = []
        for r in starts.get(a, []):
            annotations.append(f"START:{fmt_id(r.public_id)}")
        for r in ends.get(a, []):
            annotations.append(f"END:{fmt_id(r.public_id)}")
        v = img.u16(a)
        name = f" <{NAMES[v]}>" if v in NAMES else ""
        note = ("  " + " | ".join(annotations)) if annotations else ""
        print(f"0x{a:08X}: 0x{v:04X}{name}{note}")

    hdr("G. B702 ACTIVE ARRAY + LATENT TAIL TEST")
    active_start = b702.child_ptr
    active_end = b702.child_ptr + b702.count*2
    next_owner_starts = sorted(
        s for s, e, r in pool_owners
        if s > active_start
    )
    next_owner = next_owner_starts[0] if next_owner_starts else POOL_END

    print(f"B702 active start = 0x{active_start:08X}")
    print(f"B702 active count = {b702.count}")
    print(f"B702 active end   = 0x{active_end:08X}")
    print(f"next child-array owner starts at 0x{next_owner:08X}")
    print(f"free/interstitial halfwords before next owner = {(next_owner-active_end)//2}")

    latent_hits = []
    for a in range(active_end, next_owner, 2):
        v = img.u16(a)
        if v == AUDIO:
            latent_hits.append(a)

    for i in range(0, min(16, (next_owner-active_start)//2)):
        a = active_start + i*2
        if a >= next_owner:
            break
        v = img.u16(a)
        state = "ACTIVE" if i < b702.count else "TAIL"
        marker = ""
        if v == AUDIO:
            marker = " <AUDIO_8928>"
        elif v in NAMES:
            marker = f" <{NAMES[v]}>"
        print(f"  [{i:02d}] 0x{a:08X}: 0x{v:04X} {state}{marker}")

    exact_third = (active_end < next_owner and img.u16(active_end) == AUDIO)
    print()
    print(f"latent 8928 hits before next owner = {len(latent_hits)}")
    for a in latent_hits:
        print(f"  0x{a:08X}")
    print(f"immediate third halfword is 8928  = {'YES' if exact_third else 'NO'}")

    hdr("H. 8569 / 87ED / 8928 RECORD DIFFERENTIAL")
    focus = [0x8569, 0x87ED, AUDIO]
    for pid in focus:
        dense = map_id(ranges, pid)
        print()
        print(f"{fmt_id(pid)} mapped_dense={dense}")
        if dense is None:
            print("  NOT MAPPED by ID->dense range table")
            continue
        r = decode_record(img, ranges, dense)
        kids, status = read_children(img, r)
        print("  " + fmt_rec(r))
        print(f"  child-array status={status}")
        if kids:
            print("  children: " + ", ".join(fmt_id(x) for x in kids))
        else:
            print("  children: -")
        print(f"  global child-array owners={len(child_owner_map.get(pid, []))}")
        for owner_dense, owner_pid, idx in child_owner_map.get(pid, []):
            print(
                f"    owner dense={owner_dense:3d} public={fmt_id(owner_pid)} index={idx}"
            )

    hdr("I. SELECTOR TABLE DIFFERENTIAL")
    selectors = decode_selectors(img)
    for pid in focus:
        rows = [r for r in selectors if r.key == pid]
        print(f"{fmt_id(pid)} selector_rows={len(rows)}")
        for r in rows:
            vals = " ".join(f"s{i+1}=0x{v:04X}" for i, v in enumerate(r.selectors))
            print(f"  row[{r.index:02d}] {vals}")
        if not rows:
            print("  NONE")

    hdr("J. REGISTRATION TABLE DIFFERENTIAL")
    regs = decode_registrations(img)
    for pid in focus:
        rows = [r for r in regs if r.key == pid]
        print(f"{fmt_id(pid)} registration_rows={len(rows)}")
        for r in rows:
            print(
                f"  row[{r.index:02d}] field2=0x{r.field2:04X} "
                f"callback=0x{r.callback:08X}"
            )
        if not rows:
            print("  NONE")

    hdr("K. DECISION GATE")
    globally_absent = (len(owners) == 0)

    print(f"declared parent of 8928 is B702         = {'YES' if AUDIO in declared_set else 'NO'}")
    print(f"8928 in B702.children                   = {'YES' if AUDIO in enum_set else 'NO'}")
    print(f"8928 unique omission under B702         = {'YES' if unique_audio_omission else 'NO'}")
    print(f"8928 enumerated by any child array      = {'YES' if owners else 'NO'}")
    print(f"immediate latent third halfword = 8928  = {'YES' if exact_third else 'NO'}")
    print(f"parent asymmetry globally common        = {'YES' if len(mismatch_rows) > 3 else 'NO'}")
    print()

    if unique_audio_omission and globally_absent and exact_third:
        print("EXPOSURE-GAP GATE = STRONG COUNT-TRUNCATION CANDIDATE")
        print("8928 is logically parented to B702, omitted from every active child array,")
        print("and physically sits immediately after B702's two active children.")
        print("Next: prove the third halfword is not owned by another array / metadata field,")
        print("then map decompressed ZIMAGE edit to compressed VIVA physical footprint.")
        print("Do NOT write hardware yet.")
    elif unique_audio_omission and globally_absent:
        print("EXPOSURE-GAP GATE = STRONG OMISSION, NOT SIMPLE COUNT EXTENSION")
        print("8928 is the unique logically-parented B702 item omitted from enumeration,")
        print("but it is not an immediate latent third child.")
        print("Next: locate a safe child-array extension/repoint mechanism and compare metadata.")
    elif AUDIO in declared_set and globally_absent:
        print("EXPOSURE-GAP GATE = LOGICAL-PARENT / ENUMERATION SPLIT CONFIRMED")
        print("8928 is logically assigned to B702 but is not enumerated anywhere.")
        print("Next: determine whether this split is exceptional enough to be the SKU visibility mechanism.")
    else:
        print("EXPOSURE-GAP GATE = PARTIAL")
        print("Use the detailed parent-set and pool output to select the next focused audit.")

    print()
    print("PHONE ACCESSED       : NO")
    print("FLASH MODIFIED       : NO")
    print("PATCH GENERATED      : NO")
    print("PHYSICAL CANDIDATE   : NO")
    print("HARDWARE WRITE AUTHORIZED: NO")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
