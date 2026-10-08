#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
S13.5A.48 v2 - B702 EXPOSURE DIFFERENTIAL

STRICTLY OFFLINE:
- no USB / COM
- no DA upload
- no phone access
- no write / erase
- no patch / repack

This replaces the broader A.48 draft.

Questions already CLOSED and intentionally NOT re-audited:
- native Audio backend/frontend exists;
- resolver/registration row 0x8928 -> 0x1033D841 exists;
- Audio registration callback/init exists;
- no visible Audio Player item is exposed;
- registration/resolution != visible menu exposure;
- immediate event-0x7485 B709 root filtering was already closed by A.38.

Active question:
    What differs between the two children of B702 such that
    one is exposed/usable and 0x8928 is not?

A.47 static structure:
    descriptor  = F037C08C
      +0        = F0378760  registry record array
      +4        = F037BF54  ID<->dense range table
      +8        = 52        range count

    records: 895 * 0x10
    ranges : 52 * 6

Known A.47 dense anchors:
    8928 -> 490
    B702 -> 884
    B709 -> 891

Known record hints:
    record[8928].parent = B702
    record[B702].parent = B709
    record[B702].child_count = 2
    record[B709].child_count = 9

This script:
1. proves only the reciprocal topology needed;
2. enumerates the two exact B702 children;
3. identifies the sibling of 0x8928;
4. compares B702 child records field-by-field;
5. compares static selector-table rows (F03AD120, 18 * 0x14);
6. compares resolver/registration rows (F0345E68, 58 * 8);
7. reports exact raw static occurrences for the two child IDs as supporting evidence only;
8. emits a narrow decision gate for the next visibility audit.

No broad registry scan, no backend audit, no Image redirection work.
"""

from __future__ import annotations

import argparse
import hashlib
import struct
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Tuple

try:
    sys.stdout.reconfigure(line_buffering=True)
    sys.stderr.reconfigure(line_buffering=True)
except Exception:
    pass

TITLE = "S13.5A.48 v2 - B702 EXPOSURE DIFFERENTIAL"

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

AUDIO = 0x8928
B702 = 0xB702
B709 = 0xB709

EXPECTED_DENSE = {
    AUDIO: 490,
    B702: 884,
    B709: 891,
}


def hdr(s: str) -> None:
    print()
    print("=" * 118)
    print(s)
    print("=" * 118, flush=True)


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


@dataclass(frozen=True)
class RegistryRec:
    public_id: int
    dense: int
    addr: int
    parent: int
    child_count: int
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


def load_guard(path: Path, size: int, digest: str, name: str) -> bytes:
    print(f"Loading {name}: {path}")
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
        a = RANGE_BASE + i * RANGE_STRIDE
        lo, hi, base = struct.unpack("<HHH", z.read(a, 6))
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


def decode_record(z: Image, ranges: Sequence[RangeRec], pid: int) -> RegistryRec:
    dense = map_id(ranges, pid)
    if dense is None:
        raise ValueError(f"ID 0x{pid:04X} is not mapped")
    if not (0 <= dense < RECORD_COUNT):
        raise ValueError(f"dense out of range for 0x{pid:04X}: {dense}")
    a = RECORD_BASE + dense * RECORD_STRIDE
    parent, count, f4, f6, f8, fa = struct.unpack("<HHHHHH", z.read(a, 12))
    ptr = z.u32(a + 0xC)
    return RegistryRec(pid, dense, a, parent, count, f4, f6, f8, fa, ptr)


def read_children(z: Image, rec: RegistryRec) -> Tuple[List[int], str]:
    if rec.child_count == 0:
        return [], "EMPTY"
    if rec.child_ptr == 0:
        return [], "NULL_PTR"
    n = rec.child_count * 2
    if not z.contains(rec.child_ptr, n):
        return [], "OUT_OF_ZIMAGE"
    vals = list(struct.unpack("<" + "H" * rec.child_count, z.read(rec.child_ptr, n)))
    return vals, "OK"


def decode_selectors(z: Image) -> List[SelectorRow]:
    rows = []
    for i in range(SELECTOR_COUNT):
        a = SELECTOR_BASE + i * SELECTOR_STRIDE
        vals = struct.unpack("<" + "H" * 10, z.read(a, SELECTOR_STRIDE))
        rows.append(SelectorRow(i, vals[0], tuple(vals[1:])))
    return rows


def selector_rows_for(rows: Sequence[SelectorRow], pid: int) -> List[SelectorRow]:
    return [r for r in rows if r.key == pid]


def decode_registrations(z: Image) -> List[RegistrationRow]:
    rows = []
    for i in range(REGISTRATION_COUNT):
        a = REGISTRATION_BASE + i * REGISTRATION_STRIDE
        key, f2, cb = struct.unpack("<HHI", z.read(a, 8))
        rows.append(RegistrationRow(i, key, f2, cb))
    return rows


def registration_rows_for(rows: Sequence[RegistrationRow], pid: int) -> List[RegistrationRow]:
    return [r for r in rows if r.key == pid]


def raw_occurrences(images: Sequence[Image], pid: int) -> List[Tuple[str, int, str]]:
    """
    Supporting evidence only. Returns aligned U16/U32 encodings.
    Does NOT promote semantics.
    """
    out = []
    n16 = struct.pack("<H", pid)
    n32 = struct.pack("<I", pid)
    for img in images:
        for needle, kind, align in [(n16, "U16", 2), (n32, "U32", 2)]:
            pos = 0
            while True:
                off = img.data.find(needle, pos)
                if off < 0:
                    break
                addr = img.base + off
                if addr % align == 0:
                    out.append((img.name, addr, kind))
                pos = off + 1
    return sorted(out, key=lambda x: (x[0], x[1], x[2]))


def fmt_rec(r: RegistryRec) -> str:
    return (
        f"ID=0x{r.public_id:04X} dense={r.dense:3d} rec=0x{r.addr:08X} "
        f"+0(parent)=0x{r.parent:04X} +2(count)={r.child_count} "
        f"+4=0x{r.f4:04X} +6=0x{r.f6:04X} "
        f"+8=0x{r.f8:04X} +A=0x{r.fa:04X} "
        f"+C=0x{r.child_ptr:08X}"
    )


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
    args = ap.parse_args()

    print("=" * 118)
    print(TITLE)
    print("=" * 118)
    print("STRICTLY OFFLINE")
    print("PHONE ACCESSED       : NO")
    print("FLASH MODIFIED       : NO")
    print("PATCH GENERATED      : NO")
    print("REPACK               : NO")

    hdr("A. CANONICAL GUARDS")
    ad = load_guard(Path(args.alice), ALICE_SIZE, ALICE_SHA256, "ALICE")
    zd = load_guard(Path(args.zimage), ZIMAGE_SIZE, ZIMAGE_SHA256, "ZIMAGE")
    aimg = Image("ALICE", ad, ALICE_BASE)
    zimg = Image("ZIMAGE", zd, ZIMAGE_BASE)

    hdr("B. CLOSED QUESTIONS - REGRESSION ASSERTIONS ONLY")
    print("These are not active research questions.")
    print("Audio backend/frontend exists       : CLOSED")
    print("0x8928 resolver/registration exists : CLOSED")
    print("Audio item not visible              : CLOSED observation")
    print("registration != menu visibility     : CLOSED architecture")
    print("B709 immediate filter gate          : CLOSED by prior A.38 model")
    print("No backend/resolver rediscovery is performed below.")

    hdr("C. DESCRIPTOR + DENSE ANCHOR SANITY")
    d0 = zimg.u32(DESC + 0)
    d4 = zimg.u32(DESC + 4)
    d8 = zimg.u16(DESC + 8)
    print(f"descriptor 0x{DESC:08X}: +0=0x{d0:08X} +4=0x{d4:08X} +8={d8}")
    desc_ok = (d0 == RECORD_BASE and d4 == RANGE_BASE and d8 == RANGE_COUNT)
    print(f"descriptor regression = {'PASS' if desc_ok else 'FAIL'}")
    if not desc_ok:
        return 2

    ranges = decode_ranges(zimg)
    anchor_ok = True
    for pid, expected in EXPECTED_DENSE.items():
        got = map_id(ranges, pid)
        back = inverse_dense(ranges, got) if got is not None else None
        ok = (got == expected and back == pid)
        anchor_ok &= ok
        print(
            f"0x{pid:04X} -> dense={got} -> "
            f"{('0x%04X' % back) if back is not None else 'NONE'} "
            f"expected={expected} {'PASS' if ok else 'FAIL'}"
        )
    if not anchor_ok:
        return 3

    hdr("D. MINIMAL RECIPROCAL TOPOLOGY")
    r_b709 = decode_record(zimg, ranges, B709)
    r_b702 = decode_record(zimg, ranges, B702)
    r_audio = decode_record(zimg, ranges, AUDIO)

    for r in [r_b709, r_b702, r_audio]:
        print(fmt_rec(r))

    b709_children, st709 = read_children(zimg, r_b709)
    b702_children, st702 = read_children(zimg, r_b702)

    print()
    print(f"B709 children status={st709} count={len(b709_children)}")
    print("B709 children:", " ".join(f"0x{x:04X}" for x in b709_children) or "-")
    print(f"B702 children status={st702} count={len(b702_children)}")
    print("B702 children:", " ".join(f"0x{x:04X}" for x in b702_children) or "-")

    topo_ok = (
        st709 == "OK"
        and st702 == "OK"
        and B702 in b709_children
        and AUDIO in b702_children
        and r_b702.parent == B709
        and r_audio.parent == B702
    )

    print()
    print(f"B709 contains B702         = {'PASS' if B702 in b709_children else 'FAIL'}")
    print(f"B702 parent field == B709  = {'PASS' if r_b702.parent == B709 else 'FAIL'}")
    print(f"B702 contains 8928         = {'PASS' if AUDIO in b702_children else 'FAIL'}")
    print(f"8928 parent field == B702  = {'PASS' if r_audio.parent == B702 else 'FAIL'}")
    print(f"RECIPROCAL TOPOLOGY        = {'PASS' if topo_ok else 'FAIL'}")
    if not topo_ok:
        print("Stop: topology mismatch must be resolved before visibility differential.")
        return 4

    siblings = [x for x in b702_children if x != AUDIO]
    print()
    print(f"B702 non-Audio sibling count = {len(siblings)}")
    for i, sid in enumerate(siblings):
        print(f"  sibling[{i}] = 0x{sid:04X}")

    if len(siblings) != 1:
        print("Expected exactly one sibling because B702 child_count was 2.")
        print("Continue report generation, but do not promote a one-vs-one differential.")
    sibling = siblings[0] if len(siblings) == 1 else None

    hdr("E. B702 CHILD RECORD DIFFERENTIAL")
    child_ids = list(b702_children)
    child_records: Dict[int, RegistryRec] = {}
    for pid in child_ids:
        rec = decode_record(zimg, ranges, pid)
        child_records[pid] = rec
        kids, status = read_children(zimg, rec)
        print(fmt_rec(rec))
        print(f"  child-array status={status}")
        print(f"  child IDs={', '.join('0x%04X' % x for x in kids) if kids else '-'}")

    if sibling is not None:
        srec = child_records[sibling]
        arec = child_records[AUDIO]
        print()
        print("FIELD DIFF sibling vs 8928:")
        fields = [
            ("parent", srec.parent, arec.parent),
            ("child_count", srec.child_count, arec.child_count),
            ("+4", srec.f4, arec.f4),
            ("+6", srec.f6, arec.f6),
            ("+8", srec.f8, arec.f8),
            ("+A", srec.fa, arec.fa),
            ("+C child_ptr", srec.child_ptr, arec.child_ptr),
        ]
        for name, sv, av in fields:
            width = 8 if name.startswith("+C") else 4
            print(
                f"  {name:12s}: sibling=0x{sv:0{width}X} "
                f"audio=0x{av:0{width}X} "
                f"{'SAME' if sv == av else 'DIFF'}"
            )

    hdr("F. STATIC SELECTOR / RESOURCE ROW DIFFERENTIAL")
    selector_rows = decode_selectors(zimg)
    for pid in child_ids + [B702]:
        rows = selector_rows_for(selector_rows, pid)
        print(f"ID 0x{pid:04X}: selector rows={len(rows)}")
        for r in rows:
            vals = " ".join(f"s{i}=0x{v:04X}" for i, v in enumerate(r.selectors))
            print(f"  row[{r.index:02d}] {vals}")
        if not rows:
            print("  NONE")

    if sibling is not None:
        srows = selector_rows_for(selector_rows, sibling)
        arows = selector_rows_for(selector_rows, AUDIO)
        print()
        print("SELECTOR DIFFERENTIAL:")
        print(f"  sibling 0x{sibling:04X}: {'PRESENT' if srows else 'ABSENT'}")
        print(f"  audio   0x{AUDIO:04X}: {'PRESENT' if arows else 'ABSENT'}")

    hdr("G. STATIC RESOLVER / REGISTRATION ROW DIFFERENTIAL")
    registrations = decode_registrations(zimg)
    for pid in child_ids + [B702]:
        rows = registration_rows_for(registrations, pid)
        print(f"ID 0x{pid:04X}: registration rows={len(rows)}")
        for r in rows:
            print(
                f"  row[{r.index:02d}] field2=0x{r.field2:04X} "
                f"callback=0x{r.callback:08X}"
            )
        if not rows:
            print("  NONE")

    if sibling is not None:
        srows = registration_rows_for(registrations, sibling)
        arows = registration_rows_for(registrations, AUDIO)
        print()
        print("REGISTRATION DIFFERENTIAL:")
        print(f"  sibling 0x{sibling:04X}: {'PRESENT' if srows else 'ABSENT'}")
        print(f"  audio   0x{AUDIO:04X}: {'PRESENT' if arows else 'ABSENT'}")
        if arows:
            for r in arows:
                print(f"    audio callback=0x{r.callback:08X}")

    hdr("H. RAW STATIC OCCURRENCES - SUPPORTING EVIDENCE ONLY")
    ids_to_show = [AUDIO] + ([sibling] if sibling is not None else [])
    for pid in ids_to_show:
        occ = raw_occurrences([aimg, zimg], pid)
        print(f"0x{pid:04X}: aligned U16/U32 occurrences={len(occ)}")
        for name, addr, kind in occ[:120]:
            print(f"  {name:7s} 0x{addr:08X} {kind}")
        if len(occ) > 120:
            print(f"  ... {len(occ)-120} more omitted ...")
    print()
    print("NOTE: raw occurrences are not semantic proof and are not used by the decision gate.")

    hdr("I. DECISION GATE")
    print(f"reciprocal B709->B702->8928 topology = {'PASS' if topo_ok else 'FAIL'}")
    print(f"exactly one B702 sibling              = {'PASS' if sibling is not None and len(siblings)==1 else 'FAIL'}")

    if sibling is not None:
        s_sel = bool(selector_rows_for(selector_rows, sibling))
        a_sel = bool(selector_rows_for(selector_rows, AUDIO))
        s_reg = bool(registration_rows_for(registrations, sibling))
        a_reg = bool(registration_rows_for(registrations, AUDIO))

        print(f"sibling ID                            = 0x{sibling:04X}")
        print(f"sibling selector row                  = {'YES' if s_sel else 'NO'}")
        print(f"audio selector row                    = {'YES' if a_sel else 'NO'}")
        print(f"sibling registration row              = {'YES' if s_reg else 'NO'}")
        print(f"audio registration row                = {'YES' if a_reg else 'NO'}")
        print()
        if a_reg and not a_sel and s_sel:
            print("HIGH-VALUE DIFFERENTIAL:")
            print("  both children are structurally present under B702, Audio is registered,")
            print("  but only the sibling has a static selector/resource row.")
            print("  Next gate should trace the B702 item builder and selector lookup contract,")
            print("  not registration, backend, or B709 root filtering.")
        elif a_reg and a_sel:
            print("No selector-presence asymmetry.")
            print("Next gate should compare selector field values and B702-specific filter/capability state.")
        elif not a_reg:
            print("Unexpected: Audio registration row missing from canonical table.")
            print("Treat as contradiction and stop before any visibility inference.")
        else:
            print("Topology is proven, but selector-table presence alone does not isolate the gate.")
            print("Next gate: trace B702-specific materialization/filter path using the exact sibling ID.")

    print()
    print("PHONE ACCESSED       : NO")
    print("FLASH MODIFIED       : NO")
    print("PATCH GENERATED      : NO")
    print("PHYSICAL CANDIDATE   : NO")
    print("HARDWARE WRITE AUTHORIZED: NO")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
