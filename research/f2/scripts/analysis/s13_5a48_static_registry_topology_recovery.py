#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
S13.5A.48 - STATIC REGISTRY TOPOLOGY RECOVERY

STRICTLY OFFLINE:
- no USB / COM
- no DA upload
- no phone access
- no write / erase
- no patch / repack

Validated A.47/A.46 structure
-----------------------------
Static descriptor:
    F037C08C +0x00 -> F0378760   registry-record backing candidate
    F037C08C +0x04 -> F037BF54   6-byte public-ID <-> dense range table
    F037C08C +0x08 -> 52         range-record count

Exact geometry:
    895 registry records * 0x10 = 0x37F0
    F0378760 + 0x37F0 = F037BF50
    F037BF54 + 52*6   = F037C08C

Known runtime registry record semantics:
    +0x00 u16 : direct parent / parent hint (GET_PARENT_ID returns it if nonzero)
    +0x02 u16 : child count
    +0x0C u32 : child-array pointer (u16 child IDs)

GET_PARENT_ID fallback:
    if record+0 != 0:
        return record+0
    otherwise scan dense records 0..mapped_max and each child array;
    if target ID is found, convert owning dense index back to public ID.

A.48 applies those exact semantics to the static backing and reconstructs:
- exact B709 child order;
- exact child arrays for B700/B702/B6FF/B0EC;
- all static owners of 8313/8321/8928;
- parent/ancestry chains for key IDs;
- consistency between direct-parent fields and child-array ownership.

No phone mutation is performed.
"""

from __future__ import annotations

import argparse
import hashlib
import struct
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

try:
    sys.stdout.reconfigure(line_buffering=True)
    sys.stderr.reconfigure(line_buffering=True)
except Exception:
    pass

TITLE = "S13.5A.48 - STATIC REGISTRY TOPOLOGY RECOVERY"

ZIMAGE_BASE = 0xF023CA50
ZIMAGE_SIZE = 0x185E98
ZIMAGE_SHA256 = "85fba8c8ae8161e4c1f8ced7983ec30d48c54ab10e51c69fcdfb900aca220954"

DESC = 0xF037C08C
RECORD_BASE = 0xF0378760
RECORD_COUNT = 895
RECORD_STRIDE = 0x10
RECORD_END = RECORD_BASE + RECORD_COUNT * RECORD_STRIDE

INTERSTITIAL = 0xF037BF50

RANGE_BASE = 0xF037BF54
RANGE_COUNT = 52
RANGE_STRIDE = 6
RANGE_END = RANGE_BASE + RANGE_COUNT * RANGE_STRIDE

ANCHORS = {
    0x8313: "IMAGE_8313",
    0x8321: "IMAGE_8321",
    0x8928: "AUDIO_8928",
    0xB0EC: "KNOWN_PARENT_B0EC",
    0xB6FF: "FILTER_B6FF",
    0xB700: "FILTER_B700",
    0xB702: "FILTER_B702",
    0xB709: "B709_ROOT",
}

EXPECTED_DENSE = {
    0x8313: 422,
    0x8321: 436,
    0x8928: 490,
    0xB0EC: 869,
    0xB6FF: 881,
    0xB700: 882,
    0xB702: 884,
    0xB709: 891,
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
            raise ValueError(f"out-of-range read 0x{addr:08X}+0x{n:X}")
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
    addr: int
    parent_hint: int
    child_count: int
    u4: int
    u6: int
    u8: int
    ua: int
    child_ptr: int


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
        low, high, base = struct.unpack("<HHH", img.read(a, 6))
        out.append(RangeRec(low, high, base))
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


def decode_record(img: Image, dense: int) -> RegistryRec:
    if not 0 <= dense < RECORD_COUNT:
        raise ValueError(f"dense out of range: {dense}")
    a = RECORD_BASE + dense * RECORD_STRIDE
    parent_hint, child_count, u4, u6, u8, ua = struct.unpack("<HHHHHH", img.read(a, 12))
    child_ptr = img.u32(a + 0xC)
    return RegistryRec(
        dense=dense,
        addr=a,
        parent_hint=parent_hint,
        child_count=child_count,
        u4=u4,
        u6=u6,
        u8=u8,
        ua=ua,
        child_ptr=child_ptr,
    )


def read_children(img: Image, rec: RegistryRec) -> Tuple[List[int], str]:
    if rec.child_count == 0:
        return [], "EMPTY"

    size = rec.child_count * 2
    if rec.child_ptr == 0:
        return [], "NULL_PTR"
    if not img.contains(rec.child_ptr, size):
        return [], "OUT_OF_ZIMAGE"

    vals = list(struct.unpack("<" + "H" * rec.child_count, img.read(rec.child_ptr, size)))
    return vals, "OK"


def rec_summary(rec: RegistryRec) -> str:
    return (
        f"dense={rec.dense:3d} rec=0x{rec.addr:08X} "
        f"+0(parent)=0x{rec.parent_hint:04X} "
        f"+2(count)={rec.child_count:3d} "
        f"+4=0x{rec.u4:04X} +6=0x{rec.u6:04X} "
        f"+8=0x{rec.u8:04X} +A=0x{rec.ua:04X} "
        f"+C=0x{rec.child_ptr:08X}"
    )


def fmt_id(pid: Optional[int]) -> str:
    if pid is None:
        return "NONE"
    nm = ANCHORS.get(pid)
    return f"0x{pid:04X}" + (f"<{nm}>" if nm else "")


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

    hdr("A. CANONICAL INPUT GUARD")
    data = load_guard(Path(args.zimage))
    img = Image(data)

    hdr("B. DESCRIPTOR / COMPOSITE GEOMETRY")
    d0 = img.u32(DESC + 0)
    d4 = img.u32(DESC + 4)
    d8 = img.u16(DESC + 8)
    da = img.u16(DESC + 0xA)

    print(f"descriptor                = 0x{DESC:08X}")
    print(f"  +0 record array ptr     = 0x{d0:08X}")
    print(f"  +4 range table ptr      = 0x{d4:08X}")
    print(f"  +8 range count          = {d8} / 0x{d8:04X}")
    print(f"  +A                      = 0x{da:04X}")
    print()
    print(f"expected record base      = 0x{RECORD_BASE:08X}")
    print(f"record count/stride       = {RECORD_COUNT} * 0x{RECORD_STRIDE:X}")
    print(f"computed record end       = 0x{RECORD_END:08X}")
    print(f"interstitial              = 0x{INTERSTITIAL:08X}")
    print(f"interstitial u32          = 0x{img.u32(INTERSTITIAL):08X}")
    print(f"expected range base       = 0x{RANGE_BASE:08X}")
    print(f"range count/stride        = {RANGE_COUNT} * {RANGE_STRIDE}")
    print(f"computed range end        = 0x{RANGE_END:08X}")
    print()

    descriptor_ok = (
        d0 == RECORD_BASE
        and d4 == RANGE_BASE
        and d8 == RANGE_COUNT
        and RECORD_END == INTERSTITIAL
        and RANGE_END == DESC
    )
    print(f"COMPOSITE DESCRIPTOR GEOMETRY = {'PASS' if descriptor_ok else 'FAIL'}")
    if not descriptor_ok:
        print("ABORT ANALYTICAL PROMOTION: descriptor geometry mismatch.")
        return 2

    hdr("C. RANGE TABLE / DENSE SPACE REVALIDATION")
    ranges = decode_ranges(img)
    strict = True
    for i, r in enumerate(ranges):
        if r.low > r.high:
            strict = False
        if i:
            p = ranges[i-1]
            if r.low <= p.high or r.base != p.base + p.width:
                strict = False

    first_base = ranges[0].base
    last_dense = ranges[-1].dense_end
    sum_widths = sum(r.width for r in ranges)

    print(f"range records          = {len(ranges)}")
    print(f"strict contiguous      = {'PASS' if strict else 'FAIL'}")
    print(f"first dense base       = {first_base}")
    print(f"last dense index       = {last_dense}")
    print(f"sum mapped public IDs  = {sum_widths}")
    print(f"dense-0 reserved       = {'YES' if first_base == 1 else 'NO'}")
    print(f"record count = max+1   = {'PASS' if RECORD_COUNT == last_dense + 1 else 'FAIL'}")

    anchor_map_ok = True
    for pid, expected in EXPECTED_DENSE.items():
        got = map_id(ranges, pid)
        back = inverse_dense(ranges, got) if got is not None else None
        ok = got == expected and back == pid
        anchor_map_ok &= ok
        print(
            f"  {fmt_id(pid):24s} -> dense {str(got):>4s} -> {fmt_id(back):24s} "
            f"expected={expected} {'PASS' if ok else 'FAIL'}"
        )
    print(f"ANCHOR MAP REVALIDATION = {'PASS' if anchor_map_ok else 'FAIL'}")

    hdr("D. DENSE-0 SENTINEL + ANCHOR RECORDS")
    sentinel = decode_record(img, 0)
    print("dense 0 sentinel:")
    print("  " + rec_summary(sentinel))
    children0, st0 = read_children(img, sentinel)
    print(f"  children_status={st0} children={', '.join(fmt_id(x) for x in children0) or '-'}")
    print()

    records: Dict[int, RegistryRec] = {}
    for pid, dense in EXPECTED_DENSE.items():
        rec = decode_record(img, dense)
        records[pid] = rec
        children, status = read_children(img, rec)
        print(f"{fmt_id(pid)}:")
        print("  " + rec_summary(rec))
        print(f"  children_status={status}")
        for i, cid in enumerate(children):
            cdense = map_id(ranges, cid)
            print(f"    child[{i:02d}] {fmt_id(cid):24s} dense={cdense}")
        if not children:
            print("    children=-")
        print()

    hdr("E. GLOBAL CHILD-ARRAY VALIDITY CENSUS")
    valid_nonempty = 0
    invalid_nonempty = []
    child_owner_map: Dict[int, List[Tuple[int, int, int]]] = {}
    # target_id -> [(owner_dense, owner_public_id_or_-1, child_index), ...]

    for dense in range(RECORD_COUNT):
        rec = decode_record(img, dense)
        children, status = read_children(img, rec)
        if rec.child_count:
            if status == "OK":
                valid_nonempty += 1
            else:
                invalid_nonempty.append((dense, rec.child_count, rec.child_ptr, status))
                continue

        owner_pid = inverse_dense(ranges, dense)
        owner_key = owner_pid if owner_pid is not None else -1
        for idx, cid in enumerate(children):
            child_owner_map.setdefault(cid, []).append((dense, owner_key, idx))

    print(f"records with valid non-empty child arrays = {valid_nonempty}")
    print(f"invalid non-empty child arrays            = {len(invalid_nonempty)}")
    for dense, cnt, ptr, status in invalid_nonempty[:80]:
        print(
            f"  dense={dense} public={fmt_id(inverse_dense(ranges, dense))} "
            f"count={cnt} ptr=0x{ptr:08X} status={status}"
        )
    if len(invalid_nonempty) > 80:
        print(f"  ... {len(invalid_nonempty)-80} additional invalid records omitted ...")

    hdr("F. STATIC GET_PARENT_ID RECONSTRUCTION")
    def static_parent(pid: int) -> Tuple[Optional[int], str, List[Tuple[int,int,int]]]:
        dense = map_id(ranges, pid)
        if dense is None:
            return None, "ID_NOT_MAPPED", []
        rec = decode_record(img, dense)

        if rec.parent_hint != 0:
            owners = child_owner_map.get(pid, [])
            return rec.parent_hint, "DIRECT_PARENT_FIELD", owners

        owners = child_owner_map.get(pid, [])
        if not owners:
            return None, "NO_OWNER_FOUND", []
        # Firmware scans dense ascending; first owner wins.
        owner_dense, owner_pid, child_idx = sorted(owners, key=lambda x: (x[0], x[2]))[0]
        return (None if owner_pid < 0 else owner_pid), "CHILD_ARRAY_SCAN", owners

    targets = [0x8313, 0x8321, 0x8928, 0xB0EC, 0xB6FF, 0xB700, 0xB702, 0xB709]
    for pid in targets:
        parent, source, owners = static_parent(pid)
        print(
            f"{fmt_id(pid):24s} parent={fmt_id(parent):24s} source={source} "
            f"owners_in_child_arrays={len(owners)}"
        )
        for owner_dense, owner_pid, idx in sorted(owners):
            print(
                f"    owner dense={owner_dense:3d} public={fmt_id(None if owner_pid < 0 else owner_pid):24s} "
                f"child_index={idx}"
            )

    hdr("G. PARENT-FIELD <-> CHILD-ARRAY CONSISTENCY")
    consistency_ok = True
    for pid in targets:
        dense = map_id(ranges, pid)
        if dense is None:
            continue
        rec = decode_record(img, dense)
        owners = child_owner_map.get(pid, [])

        if rec.parent_hint:
            matching = [
                x for x in owners
                if x[1] >= 0 and x[1] == rec.parent_hint
            ]
            ok = len(matching) >= 1
            consistency_ok &= ok
            print(
                f"{fmt_id(pid):24s} direct_parent={fmt_id(rec.parent_hint):24s} "
                f"matching_child_owner={'YES' if ok else 'NO'} "
                f"all_owners={len(owners)}"
            )
        else:
            print(
                f"{fmt_id(pid):24s} direct_parent=0 "
                f"fallback_owners={len(owners)}"
            )

    print(f"DIRECT-PARENT CONSISTENCY = {'PASS' if consistency_ok else 'FAIL'}")

    hdr("H. ANCESTRY CHAINS")
    def ancestry(pid: int, max_depth: int = 12) -> Tuple[List[int], str]:
        chain = [pid]
        seen = {pid}
        cur = pid

        for _ in range(max_depth):
            parent, source, _ = static_parent(cur)
            if parent is None:
                return chain, source
            chain.append(parent)
            if parent in seen:
                return chain, "CYCLE"
            seen.add(parent)
            cur = parent

        return chain, "DEPTH_LIMIT"

    for pid in [0x8313, 0x8321, 0x8928, 0xB6FF, 0xB700, 0xB702]:
        chain, stop = ancestry(pid)
        print(
            " -> ".join(fmt_id(x) for x in chain)
            + f"    [stop={stop}]"
        )

    hdr("I. B709 EXACT CHILD ORDER")
    b709 = records[0xB709]
    b709_children, b709_status = read_children(img, b709)
    print(f"B709 record: {rec_summary(b709)}")
    print(f"child-array status = {b709_status}")
    print(f"child count = {len(b709_children)}")

    for i, cid in enumerate(b709_children):
        dense = map_id(ranges, cid)
        parent, source, owners = static_parent(cid)
        rec = decode_record(img, dense) if dense is not None else None
        print(
            f"[{i:02d}] {fmt_id(cid):24s} dense={dense} "
            f"resolved_parent={fmt_id(parent)} via={source}"
        )
        if rec is not None:
            print(
                f"     record parent=0x{rec.parent_hint:04X} "
                f"count={rec.child_count} +8=0x{rec.u8:04X} "
                f"child_ptr=0x{rec.child_ptr:08X}"
            )
            kids, status = read_children(img, rec)
            if kids:
                print(
                    "     children: "
                    + ", ".join(f"[{j}] {fmt_id(x)}" for j, x in enumerate(kids))
                )
            else:
                print(f"     children: - ({status})")

    hdr("J. B700 / B702 / B6FF / B0EC CHILD ARRAYS")
    for pid in [0xB700, 0xB702, 0xB6FF, 0xB0EC]:
        rec = records[pid]
        kids, status = read_children(img, rec)
        print(f"{fmt_id(pid)} {rec_summary(rec)}")
        print(f"  status={status}")
        for i, cid in enumerate(kids):
            print(
                f"  [{i:02d}] {fmt_id(cid):24s} dense={map_id(ranges, cid)} "
                f"owners={len(child_owner_map.get(cid, []))}"
            )
        if not kids:
            print("  children=-")
        print()

    hdr("K. IMAGE/AUDIO OWNERSHIP CROSS-CHECK")
    for pid in [0x8313, 0x8321, 0x8928]:
        rec = records[pid]
        parent, source, owners = static_parent(pid)
        print(f"{fmt_id(pid)}")
        print(f"  dense        = {map_id(ranges, pid)}")
        print(f"  record+0     = 0x{rec.parent_hint:04X}")
        print(f"  resolved     = {fmt_id(parent)} via {source}")
        print(f"  child owners = {len(owners)}")
        for owner_dense, owner_pid, idx in sorted(owners):
            print(
                f"    dense={owner_dense:3d} public={fmt_id(None if owner_pid < 0 else owner_pid)} "
                f"index={idx}"
            )

    hdr("L. DECISION GATE")
    p8928, s8928, _ = static_parent(0x8928)
    pB702, sB702, _ = static_parent(0xB702)
    b702_children, b702_status = read_children(img, records[0xB702])
    b709_children, b709_status = read_children(img, records[0xB709])

    audio_chain_exact = (
        p8928 == 0xB702
        and pB702 == 0xB709
        and 0x8928 in b702_children
        and 0xB702 in b709_children
    )

    image8321_parent, image8321_source, _ = static_parent(0x8321)
    image8313_parent, image8313_source, _ = static_parent(0x8313)

    print(f"composite descriptor geometry      = {'PASS' if descriptor_ok else 'FAIL'}")
    print(f"range table strict                 = {'PASS' if strict else 'FAIL'}")
    print(f"anchor mapping                     = {'PASS' if anchor_map_ok else 'FAIL'}")
    print(f"invalid non-empty child arrays     = {len(invalid_nonempty)}")
    print(f"direct-parent consistency          = {'PASS' if consistency_ok else 'FAIL'}")
    print(f"B709 child-array status            = {b709_status}")
    print(f"B702 child-array status            = {b702_status}")
    print(f"B709 children count                = {len(b709_children)}")
    print(f"B702 children count                = {len(b702_children)}")
    print(f"8928 parent                        = {fmt_id(p8928)} via {s8928}")
    print(f"B702 parent                        = {fmt_id(pB702)} via {sB702}")
    print(f"8321 parent                        = {fmt_id(image8321_parent)} via {image8321_source}")
    print(f"8313 parent                        = {fmt_id(image8313_parent)} via {image8313_source}")
    print(f"AUDIO CHAIN B709->B702->8928       = {'PASS' if audio_chain_exact else 'FAIL'}")
    print()

    if (
        descriptor_ok
        and strict
        and anchor_map_ok
        and len(invalid_nonempty) == 0
        and consistency_ok
        and audio_chain_exact
    ):
        print("STATIC REGISTRY TOPOLOGY GATE = PASS")
        print("The static image is internally consistent with the proven runtime registry ABI.")
        print("B709 direct child ordering and B702->8928 membership are promotable.")
        print("Next: correlate the B709 child list with selector rows and identify the visible")
        print("Multimedia branch / missing-vs-filtered state without broad scans.")
    else:
        print("STATIC REGISTRY TOPOLOGY GATE = PARTIAL")
        print("Do not promote any failed relationship; inspect the failing invariant first.")

    print()
    print("PHONE ACCESSED       : NO")
    print("FLASH MODIFIED       : NO")
    print("PATCH GENERATED      : NO")
    print("PHYSICAL CANDIDATE   : NO")
    print("HARDWARE WRITE AUTHORIZED: NO")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
