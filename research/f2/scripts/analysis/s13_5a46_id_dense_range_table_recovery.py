#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
S13.5A.46 - ID <-> DENSE RANGE TABLE RECOVERY

STRICTLY OFFLINE:
- no USB / COM
- no DA upload
- no phone access
- no write / erase
- no patch / repack

Context
-------
S13.5A.3 already proved that F02E01B0 maps a public u16 ID to a dense
registry index using a range descriptor made of 6-byte records:

    { u16 low_id, u16 high_id, u16 base_index }

On a hit:
    dense = base_index + public_id - low_id

F02FEFB4 uses the same descriptor in the reverse direction and is the
strong inverse dense-index -> public-ID candidate.

S13.5A.45 closed the F007F040/F03492xx detour: that subsystem is a separate
sparse-code dispatcher and is not the F007F044 registry base.

A.46 therefore searches ONLY for structurally valid range tables consistent
with the already-proven mapper semantics, then evaluates focus IDs:

    B709  - root used by F02F9D34
    8313  - Image Viewer alias A
    8321  - Image Viewer alias B
    8928  - Audio Player
    B700, B702, B6FF - filter-clear anchors
    B0EC - known real parent from S13.5A.3

No raw U16 occurrence alone is promoted.
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
    from capstone import (
        Cs,
        CS_ARCH_ARM,
        CS_MODE_LITTLE_ENDIAN,
        CS_MODE_THUMB,
        CS_GRP_CALL,
        CS_GRP_JUMP,
        CS_OP_IMM,
        CS_OP_MEM,
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

TITLE = "S13.5A.46 - ID <-> DENSE RANGE TABLE RECOVERY"

ALICE_BASE = 0x1024EC00
ALICE_SIZE = 0x157BB4
ALICE_SHA256 = "7246242b67afae0d13104452bc3257827cb778119b54e7a26fb7fb55993697ea"

BOOT_BASE = 0xF01F19E4
BOOT_SIZE = 0x4B06C
BOOT_SHA256 = "aa070292e9c1685eddb12080b3f0bbca763102adaf085016b4e503a3930b4c3e"

ZIMAGE_BASE = 0xF023CA50
ZIMAGE_SIZE = 0x185E98
ZIMAGE_SHA256 = "85fba8c8ae8161e4c1f8ced7983ec30d48c54ab10e51c69fcdfb900aca220954"

DUMP_SIZE = 0x400000
DUMP_SHA256 = "2fc100e5704cf3d6fae0817a22ce222397702ffd7351a83763ae1bafd4416922"
PHYSICAL_ROM_BASE = 0x10000000
PHYSICAL_ROM_SIZE = 0x4C20C

ID_TO_DENSE = 0xF02E01B0
DENSE_TO_ID = 0xF02FEFB4

REG_BASE_GLOBAL = 0xF007F044
REG_AUX_GLOBAL = 0xF007F048
REG_BOUND_GLOBAL = 0xF007F04C

PRIMARY_FOCUS = {
    0xB709: "B709_ROOT",
    0x8313: "IMAGE_8313",
    0x8321: "IMAGE_8321",
    0x8928: "AUDIO_8928",
}
SECONDARY_FOCUS = {
    0xB700: "FILTER_B700",
    0xB702: "FILTER_B702",
    0xB6FF: "FILTER_B6FF",
    0xB0EC: "KNOWN_PARENT_B0EC",
}
ALL_FOCUS = {**PRIMARY_FOCUS, **SECONDARY_FOCUS}


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
        return self.base <= addr and addr + n <= self.end

    def read(self, addr: int, n: int) -> bytes:
        if not self.contains(addr, n):
            raise ValueError(f"{self.name}: out of range 0x{addr:08X}+0x{n:X}")
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


@dataclass
class Candidate:
    image: Image
    start: int
    records: List[RangeRec]
    strict_contiguous: bool
    starts_at_zero: bool
    primary_hits: Dict[int, int]
    secondary_hits: Dict[int, int]
    score: int

    @property
    def end(self) -> int:
        return self.start + len(self.records) * 6

    @property
    def mapped_count(self) -> int:
        if not self.records:
            return 0
        return max(r.dense_end for r in self.records) + 1


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
        addr &= ~1
        img = self.image_for(addr)
        if not img:
            return None
        width = min(4, img.end - addr)
        xs = list(self.cs.disasm(img.read(addr, width), addr, count=1))
        return xs[0] if xs else None

    def literal(self, ci) -> Optional[Tuple[int, int]]:
        if not ci.mnemonic.lower().startswith("ldr") or len(ci.operands) < 2:
            return None
        op = ci.operands[1]
        if op.type != CS_OP_MEM or op.mem.base != ARM_REG_PC:
            return None
        lit_addr = (((ci.address + 4) & ~3) + int(op.mem.disp)) & 0xFFFFFFFF
        img = self.image_for(lit_addr)
        if not img or not img.contains(lit_addr, 4):
            return None
        return lit_addr, img.u32(lit_addr)

    @staticmethod
    def is_ret(ci) -> bool:
        m = ci.mnemonic.lower()
        o = ci.op_str.lower().replace(" ", "")
        return (
            (m.startswith("bx") and not m.startswith("blx") and o == "lr")
            or (m == "pop" and "pc" in o)
            or (m.startswith("ldm") and "pc" in o)
            or (m == "mov" and o == "pc,lr")
        )

    @staticmethod
    def is_uncond_jump(ci) -> bool:
        return ci.mnemonic.lower() in {"b", "b.w", "bx"}

    def cfg(self, entry: int, max_span: int = 0x500) -> Tuple[Dict[int, object], bool]:
        from collections import deque
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
            if ci is None:
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

    def exact_literal_xrefs(self, value: int) -> List[Tuple[str, int, int]]:
        needle = struct.pack("<I", value & 0xFFFFFFFF)
        found = set()

        for img in self.images:
            pos = 0
            literals = []
            while True:
                off = img.data.find(needle, pos)
                if off < 0:
                    break
                literals.append(img.base + off)
                pos = off + 1

            for lit in literals:
                lo = max(img.base, lit - 0x1100) & ~1
                for a in range(lo, lit, 2):
                    ci = self.one(a)
                    if not ci:
                        continue
                    lv = self.literal(ci)
                    if lv and lv == (lit, value):
                        found.add((img.name, a, lit))
        return sorted(found)


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


def decode_record(data: bytes, off: int) -> RangeRec:
    lo, hi, base = struct.unpack_from("<HHH", data, off)
    return RangeRec(lo, hi, base)


def rec_plausible(r: RangeRec) -> bool:
    # Public IDs are u16. Reject inverted ranges and absurdly wide single records.
    if r.low > r.high:
        return False
    if r.width > 0x4000:
        return False
    return True


def extend_run(
    img: Image,
    start_off: int,
    max_records: int,
    strict: bool,
) -> List[RangeRec]:
    data = img.data
    records: List[RangeRec] = []
    prev: Optional[RangeRec] = None

    off = start_off
    while off + 6 <= len(data) and len(records) < max_records:
        r = decode_record(data, off)
        if not rec_plausible(r):
            break

        if prev is not None:
            # Public ranges must be strictly sorted and non-overlapping.
            if r.low <= prev.high:
                break

            # Dense bases must move forward.
            if r.base <= prev.base:
                break

            if strict:
                expected = prev.base + prev.width
                if r.base != expected:
                    break
            else:
                # Relaxed mode allows gaps but never overlap in dense space.
                if r.base <= prev.dense_end:
                    break

        records.append(r)
        prev = r
        off += 6

    return records


def map_id(records: Sequence[RangeRec], public_id: int) -> Optional[int]:
    lo, hi = 0, len(records) - 1
    while lo <= hi:
        mid = (lo + hi) // 2
        r = records[mid]
        if public_id < r.low:
            hi = mid - 1
        elif public_id > r.high:
            lo = mid + 1
        else:
            return r.base + public_id - r.low
    return None


def inverse_dense(records: Sequence[RangeRec], dense: int) -> Optional[int]:
    for r in records:
        if r.base <= dense <= r.dense_end:
            return r.low + dense - r.base
    return None


def candidate_score(records: Sequence[RangeRec], strict: bool) -> Tuple[int, Dict[int,int], Dict[int,int]]:
    primary = {}
    secondary = {}

    for x in PRIMARY_FOCUS:
        v = map_id(records, x)
        if v is not None:
            primary[x] = v

    for x in SECONDARY_FOCUS:
        v = map_id(records, x)
        if v is not None:
            secondary[x] = v

    score = len(primary) * 1000 + len(secondary) * 150
    score += min(len(records), 400)
    if strict:
        score += 200

    # Strong bonus if all primary IDs are represented and round-trip.
    if len(primary) == len(PRIMARY_FOCUS):
        if all(inverse_dense(records, d) == pid for pid, d in primary.items()):
            score += 5000

    return score, primary, secondary


def scan_candidates(
    images: Sequence[Image],
    min_records: int,
    max_records: int,
    top_k: int,
) -> List[Candidate]:
    allc: List[Candidate] = []

    for img in images:
        print(f"Scanning structured 6-byte range tables in {img.name} ...", flush=True)
        data = img.data

        # Two-byte starts preserve u16 alignment; a real table may be 0,2,4 mod 6.
        for off in range(0, len(data) - min_records * 6 + 1, 2):
            first = decode_record(data, off)
            if not rec_plausible(first):
                continue

            # The real dense table is expected to begin at base 0 or very near it.
            # Search strict first.
            recs = extend_run(img, off, max_records, strict=True)
            if len(recs) >= min_records:
                score, p, s = candidate_score(recs, True)
                if p or s:
                    allc.append(
                        Candidate(
                            img, img.base + off, recs, True,
                            recs[0].base == 0, p, s, score
                        )
                    )

            # Relaxed run is retained only if it adds anchor coverage beyond strict.
            relaxed = extend_run(img, off, max_records, strict=False)
            if len(relaxed) >= min_records:
                score2, p2, s2 = candidate_score(relaxed, False)
                if p2 or s2:
                    if not recs or len(relaxed) > len(recs) or set(p2) != set(p):
                        allc.append(
                            Candidate(
                                img, img.base + off, relaxed, False,
                                relaxed[0].base == 0, p2, s2, score2
                            )
                        )

    # Deduplicate overlapping descriptions of same maximal table.
    # Keep highest-score / longest candidate for identical image+end and nearby starts.
    allc.sort(key=lambda c: (-c.score, -len(c.records), c.image.name, c.start))
    kept: List[Candidate] = []
    seen_exact = set()

    for c in allc:
        key = (
            c.image.name,
            c.start,
            c.end,
            c.strict_contiguous,
            tuple(sorted(c.primary_hits.items())),
            tuple(sorted(c.secondary_hits.items())),
        )
        if key in seen_exact:
            continue
        seen_exact.add(key)

        # Suppress obvious interior sub-runs with same anchor set.
        interior = False
        for k in kept:
            if (
                k.image.name == c.image.name
                and k.start <= c.start
                and c.end <= k.end
                and k.strict_contiguous == c.strict_contiguous
                and set(k.primary_hits) == set(c.primary_hits)
                and set(k.secondary_hits) == set(c.secondary_hits)
            ):
                interior = True
                break
        if interior:
            continue

        kept.append(c)
        if len(kept) >= top_k:
            break

    return kept


def raw_u32_occurrences(images: Sequence[Image], value: int) -> List[Tuple[str,int]]:
    needle = struct.pack("<I", value & 0xFFFFFFFF)
    out = []
    for img in images:
        pos = 0
        while True:
            off = img.data.find(needle, pos)
            if off < 0:
                break
            out.append((img.name, img.base + off))
            pos = off + 1
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description=TITLE)
    ap.add_argument("--alice", default=r".\research\f2\work\extracted\altice_alice\alice-py.bin")
    ap.add_argument(
        "--boot",
        default=r"C:\Users\verto\mtkclient\research\f2\work\extracted\altice_platform\boot_zimage.bin",
    )
    ap.add_argument("--zimage", default=r".\research\f2\work\extracted\altice_platform\zimage.bin")
    ap.add_argument(
        "--dump",
        default=r"C:\Users\verto\mtkclient\research\f2\data\dumps\mobiwire_dump_2.bin",
    )
    ap.add_argument("--min-records", type=int, default=8)
    ap.add_argument("--max-records", type=int, default=512)
    ap.add_argument("--top-k", type=int, default=40)
    args = ap.parse_args()

    print("=" * 120)
    print(TITLE)
    print("=" * 120)
    print("STRICTLY OFFLINE")
    print("PHONE ACCESSED       : NO")
    print("FLASH MODIFIED       : NO")
    print("PATCH GENERATED      : NO")
    print("REPACK               : NO")

    hdr("A. CANONICAL INPUT GUARDS")
    ad = load_guard(Path(args.alice), ALICE_SIZE, ALICE_SHA256, "ALICE")
    bd = load_guard(Path(args.boot), BOOT_SIZE, BOOT_SHA256, "BOOT_ZIMAGE")
    zd = load_guard(Path(args.zimage), ZIMAGE_SIZE, ZIMAGE_SHA256, "ZIMAGE")
    dd = load_guard(Path(args.dump), DUMP_SIZE, DUMP_SHA256, "DUMP")

    images = [
        Image("ALICE", ad, ALICE_BASE),
        Image("BOOT_ZIMAGE", bd, BOOT_BASE),
        Image("ZIMAGE", zd, ZIMAGE_BASE),
        Image("PHYSICAL_ROM", dd[:PHYSICAL_ROM_SIZE], PHYSICAL_ROM_BASE),
    ]
    dis = Disasm(images)

    hdr("B. KNOWN MAPPER / INVERSE CFG")
    for entry, name in [
        (ID_TO_DENSE, "F02E01B0 ID_TO_DENSE"),
        (DENSE_TO_ID, "F02FEFB4 DENSE_TO_ID"),
    ]:
        insns, trunc = dis.cfg(entry, 0x500)
        print()
        print(f"{name}: entry=0x{entry:08X} instructions={len(insns)} truncated={trunc}")
        for a in sorted(insns):
            ci = insns[a]
            suffix = ""
            lv = dis.literal(ci)
            if lv:
                la, v = lv
                labels = []
                if v == REG_BASE_GLOBAL:
                    labels.append("REG_BASE_GLOBAL")
                if v == REG_AUX_GLOBAL:
                    labels.append("REG_AUX_GLOBAL")
                if v == REG_BOUND_GLOBAL:
                    labels.append("REG_BOUND_GLOBAL")
                suffix = f" ; literal@0x{la:08X}=0x{v:08X}"
                if labels:
                    suffix += "<" + ",".join(labels) + ">"
            print(f"0x{a:08X}: {ci.mnemonic:<9} {ci.op_str}{suffix}")

    hdr("C. GLOBAL XREF CHECK")
    for value, name in [
        (REG_BASE_GLOBAL, "REG_BASE_GLOBAL"),
        (REG_AUX_GLOBAL, "REG_AUX_GLOBAL"),
        (REG_BOUND_GLOBAL, "REG_BOUND_GLOBAL"),
    ]:
        xs = dis.exact_literal_xrefs(value)
        print(f"0x{value:08X} <{name}> exact code xrefs = {len(xs)}")
        for img_name, site, lit in xs:
            mark = ""
            if (ID_TO_DENSE <= site < ID_TO_DENSE + 0x500):
                mark = " <ID_TO_DENSE_SURFACE>"
            if (DENSE_TO_ID <= site < DENSE_TO_ID + 0x500):
                mark += " <DENSE_TO_ID_SURFACE>"
            print(f"  {img_name:12s} site=0x{site:08X} literal=0x{lit:08X}{mark}")

    hdr("D. STRUCTURALLY VALID 6-BYTE RANGE-TABLE SCAN")
    print(f"min records = {args.min_records}")
    print(f"max records = {args.max_records}")
    print("record shape = {u16 low, u16 high, u16 base_index}")
    print("strict rule = sorted non-overlap public ranges + exact contiguous dense bases")
    print("relaxed rule = sorted non-overlap public ranges + non-overlap monotonic dense bases")
    print("promotion rule = structure + focus coverage + inverse round-trip; raw U16 hits alone do not count")

    candidates = scan_candidates(
        images,
        min_records=max(3, args.min_records),
        max_records=max(args.min_records, args.max_records),
        top_k=max(1, args.top_k),
    )

    print()
    print(f"retained ranked candidates = {len(candidates)}")

    hdr("E. RANKED CANDIDATES / FOCUS MAPPING")
    if not candidates:
        print("NO STRUCTURAL CANDIDATE WITH ANY FOCUS-ID COVERAGE")
    else:
        for i, c in enumerate(candidates, 1):
            primary_txt = ", ".join(
                f"0x{k:04X}->{v}<{PRIMARY_FOCUS[k]}>"
                for k, v in sorted(c.primary_hits.items())
            ) or "-"
            secondary_txt = ", ".join(
                f"0x{k:04X}->{v}<{SECONDARY_FOCUS[k]}>"
                for k, v in sorted(c.secondary_hits.items())
            ) or "-"

            print()
            print(
                f"[{i:02d}] score={c.score} {c.image.name} "
                f"start=0x{c.start:08X} end=0x{c.end:08X} "
                f"records={len(c.records)} mapped_count={c.mapped_count} "
                f"strict={c.strict_contiguous} starts_at_zero={c.starts_at_zero}"
            )
            print(f"     primary   : {primary_txt}")
            print(f"     secondary : {secondary_txt}")

            roundtrip_ok = True
            for pid, dense in {**c.primary_hits, **c.secondary_hits}.items():
                back = inverse_dense(c.records, dense)
                if back != pid:
                    roundtrip_ok = False
                print(
                    f"     roundtrip 0x{pid:04X} -> {dense} -> "
                    + (f"0x{back:04X}" if back is not None else "NONE")
                    + (" PASS" if back == pid else " FAIL")
                )
            print(f"     anchor roundtrip = {'PASS' if roundtrip_ok else 'FAIL'}")

            # Print all records for strong all-primary candidates; otherwise a bounded head/tail.
            strong = len(c.primary_hits) == len(PRIMARY_FOCUS)
            if strong or len(c.records) <= 24:
                show = list(enumerate(c.records))
            else:
                head = list(enumerate(c.records[:8]))
                tail_start = max(8, len(c.records)-8)
                tail = list(enumerate(c.records[tail_start:], start=tail_start))
                show = head + tail

            for ri, r in show:
                anchors = []
                for pid, nm in ALL_FOCUS.items():
                    if r.low <= pid <= r.high:
                        anchors.append(f"0x{pid:04X}<{nm}>")
                atxt = " anchors=" + ",".join(anchors) if anchors else ""
                print(
                    f"       rec[{ri:03d}] "
                    f"0x{r.low:04X}..0x{r.high:04X} "
                    f"base={r.base:5d} dense_end={r.dense_end:5d}{atxt}"
                )
            if not strong and len(c.records) > 24:
                print("       ... middle records omitted ...")

    hdr("F. STRONG-CANDIDATE POINTER / XREF SURFACE")
    strongs = [
        c for c in candidates
        if len(c.primary_hits) == len(PRIMARY_FOCUS)
        and all(inverse_dense(c.records, d) == pid for pid, d in c.primary_hits.items())
    ]
    print(f"all-primary roundtrip candidates = {len(strongs)}")

    for i, c in enumerate(strongs[:10], 1):
        print()
        print(
            f"STRONG[{i}] {c.image.name}:0x{c.start:08X} "
            f"records={len(c.records)} mapped_count={c.mapped_count}"
        )
        raw = raw_u32_occurrences(images, c.start)
        print(f"  raw U32 pointers to table start = {len(raw)}")
        for img_name, addr in raw[:40]:
            print(f"    {img_name:12s} 0x{addr:08X}")

        xrefs = dis.exact_literal_xrefs(c.start)
        print(f"  exact code literal xrefs to table start = {len(xrefs)}")
        for img_name, site, lit in xrefs:
            print(
                f"    {img_name:12s} site=0x{site:08X} literal=0x{lit:08X}"
            )

        # Also search one-record-before and small descriptor-neighbor pointers.
        for delta in (-8, -4, 4, 8, 12, 16):
            neighbor = (c.start + delta) & 0xFFFFFFFF
            raw_n = raw_u32_occurrences(images, neighbor)
            if raw_n:
                print(
                    f"  raw pointers to neighbor 0x{neighbor:08X} "
                    f"(delta {delta:+}) = {len(raw_n)}"
                )
                for img_name, addr in raw_n[:12]:
                    print(f"    {img_name:12s} 0x{addr:08X}")

    hdr("G. FOCUS DENSE-INDEX CONSENSUS")
    for pid, name in ALL_FOCUS.items():
        vals = []
        for c in strongs:
            d = map_id(c.records, pid)
            if d is not None:
                vals.append((c.image.name, c.start, d))
        distinct = sorted(set(d for _, _, d in vals))
        print(
            f"0x{pid:04X} <{name}> strong_candidates={len(vals)} "
            f"distinct_dense={distinct}"
        )
        for img_name, start, d in vals[:10]:
            print(f"  {img_name:12s} table=0x{start:08X} dense={d}")

    hdr("H. DECISION GATE")
    print(f"ranked candidates                 = {len(candidates)}")
    print(f"all-primary roundtrip candidates  = {len(strongs)}")

    unique_consensus = {}
    for pid in PRIMARY_FOCUS:
        vals = {map_id(c.records, pid) for c in strongs}
        vals.discard(None)
        if len(vals) == 1:
            unique_consensus[pid] = next(iter(vals))

    print(f"primary IDs with unique dense consensus = {len(unique_consensus)}/{len(PRIMARY_FOCUS)}")
    for pid, dense in sorted(unique_consensus.items()):
        print(f"  0x{pid:04X} <{PRIMARY_FOCUS[pid]}> -> dense {dense}")

    print()
    if len(strongs) == 1 and len(unique_consensus) == len(PRIMARY_FOCUS):
        print("STRUCTURAL TABLE GATE = STRONG UNIQUE CANDIDATE")
        print("Next: audit descriptor/pointer ownership and use recovered dense indices")
        print("      to target registry records / ancestry without broad raw scans.")
    elif strongs and len(unique_consensus) == len(PRIMARY_FOCUS):
        print("STRUCTURAL TABLE GATE = MULTIPLE CANDIDATES, DENSE CONSENSUS EXISTS")
        print("Next: discriminate candidates by descriptor/code ownership before promotion.")
    elif strongs:
        print("STRUCTURAL TABLE GATE = PARTIAL")
        print("Next: use inverse-mapper details / descriptor ownership to discriminate.")
    else:
        print("STRUCTURAL TABLE GATE = NO ALL-PRIMARY STATIC TABLE")
        print("Next: do NOT promote raw tables; inspect exact runtime descriptor provenance")
        print("      of F007F048 / inverse mapper instead.")

    print()
    print("PHONE ACCESSED       : NO")
    print("FLASH MODIFIED       : NO")
    print("PATCH GENERATED      : NO")
    print("PHYSICAL CANDIDATE   : NO")
    print("HARDWARE WRITE AUTHORIZED: NO")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
