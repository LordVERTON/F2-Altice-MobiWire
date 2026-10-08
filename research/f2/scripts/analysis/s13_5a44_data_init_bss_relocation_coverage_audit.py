#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
S13.5A.44 - DATA-INIT / BSS / RELOCATION COVERAGE AUDIT

STRICTLY OFFLINE:
- no USB / COM
- no DA upload
- no write / erase
- no phone access

Validated input from A.43 v2
----------------------------
ALICE + BOOT_ZIMAGE + ZIMAGE contain no direct/indexed/bulk write to the
registry global block F007F040..F007F060 under the validated static model.

Therefore A.44 searches for startup initialization descriptors that can cover
the block WITHOUT containing an exact F007F044 code literal.

Target:
    F007F040 .. F007F060 inclusive
Core interval used for coverage tests:
    [F007F040, F007F064)

Supported descriptor hypotheses
--------------------------------
2-word:
    [dst, size]      -> ZERO/BSS region
    [dst, end]       -> ZERO/BSS range

3-word:
    [src, dst, size]
    [dst, src, size]
    [src, dst, end]
    [dst, end, src]

4-word:
    generic window permutations are reported when one mapped source pointer,
    one destination pointer and one size/end field form a valid covering COPY.

The search is deliberately target-driven: candidates are only emitted when the
derived destination interval covers F007F040..F007F060.

For COPY candidates whose source maps into a known image, A.44 computes the
source bytes corresponding exactly to the registry block and prints the initial
u32 words for:
    F007F040
    F007F044
    F007F048
    F007F04C
    F007F050
    F007F054
    F007F058
    F007F05C
    F007F060

Images searched:
- ALICE
- BOOT_ZIMAGE
- ZIMAGE
- physical ROM prefix from canonical 4 MiB dump (runtime 0x10000000..0x1004C20C)

No patch is generated.
"""

from __future__ import annotations

import argparse
import hashlib
import itertools
import math
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

TITLE = "S13.5A.44 - DATA-INIT / BSS / RELOCATION COVERAGE AUDIT"

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

ROM_BASE = 0x10000000
ROM_END = 0x1004C20C

TARGET_START = 0xF007F040
TARGET_END = 0xF007F064  # exclusive
TARGET_WORDS = [
    0xF007F040,
    0xF007F044,
    0xF007F048,
    0xF007F04C,
    0xF007F050,
    0xF007F054,
    0xF007F058,
    0xF007F05C,
    0xF007F060,
]

RAM_MIN = 0xF0000000
RAM_MAX = 0xF1000000

# Conservative descriptor-size bound. Startup sections can be large, but a
# >32 MiB record on this target is implausible and creates many false matches.
MAX_REGION_SIZE = 0x02000000
MIN_REGION_SIZE = TARGET_END - TARGET_START


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def hdr(title: str) -> None:
    print()
    print("=" * 120)
    print(title)
    print("=" * 120, flush=True)


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
        return struct.unpack_from("<I", self.read(addr, 4))[0]


@dataclass(frozen=True)
class Candidate:
    kind: str
    image: str
    table_addr: int
    words: Tuple[int, ...]
    dst: int
    end: int
    src: Optional[int]
    size: int
    confidence: str
    note: str

    @property
    def span(self) -> int:
        return self.end - self.dst


class Auditor:
    def __init__(self, images: List[Image]):
        self.images = images
        self.thumb = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_LITTLE_ENDIAN)
        self.thumb.detail = True

    def image_for(self, addr: int) -> Optional[Image]:
        a = addr & 0xFFFFFFFF
        for img in self.images:
            if img.contains(a):
                return img
        return None

    def mapped_source(self, addr: int, n: int = 1) -> Optional[Image]:
        a = addr & 0xFFFFFFFF
        for img in self.images:
            if img.contains(a, n):
                return img
        return None

    @staticmethod
    def is_ram_ptr(v: int) -> bool:
        return RAM_MIN <= (v & 0xFFFFFFFF) < RAM_MAX

    @staticmethod
    def covers_target(dst: int, end: int) -> bool:
        dst &= 0xFFFFFFFF
        end &= 0xFFFFFFFF
        return dst <= TARGET_START and end >= TARGET_END and end > dst

    @staticmethod
    def valid_size(size: int) -> bool:
        return MIN_REGION_SIZE <= size <= MAX_REGION_SIZE

    @staticmethod
    def calc_end(dst: int, size: int) -> Optional[int]:
        if size <= 0:
            return None
        end = dst + size
        if end > 0x100000000:
            return None
        return end

    def exact_literal_xrefs(self, value: int) -> List[Tuple[str, int, int]]:
        needle = struct.pack("<I", value & 0xFFFFFFFF)
        out = set()

        for img in self.images:
            start = 0
            lit_addrs = []
            while True:
                off = img.data.find(needle, start)
                if off < 0:
                    break
                lit_addrs.append(img.base + off)
                start = off + 1

            for lit_addr in lit_addrs:
                lo = max(img.base, lit_addr - 0x1100) & ~1
                for a in range(lo, lit_addr, 2):
                    width = min(4, img.end - a)
                    ds = list(self.thumb.disasm(img.read(a, width), a, count=1))
                    if not ds:
                        continue
                    ci = ds[0]
                    if not ci.mnemonic.lower().startswith("ldr") or len(ci.operands) < 2:
                        continue
                    op = ci.operands[1]
                    if op.type != CS_OP_MEM or op.mem.base != ARM_REG_PC:
                        continue
                    pc = (a + 4) & ~3
                    la = (pc + int(op.mem.disp)) & 0xFFFFFFFF
                    if la == lit_addr:
                        out.add((img.name, a, lit_addr))

        return sorted(out)

    def scan_pair_candidates(self) -> List[Candidate]:
        out = []

        for img in self.images:
            print(f"Scanning 2-word descriptors in {img.name} ...", flush=True)
            data = img.data
            for off in range(0, len(data) - 7, 4):
                a, b = struct.unpack_from("<II", data, off)
                table_addr = img.base + off

                # [dst, size]
                if self.is_ram_ptr(a) and self.valid_size(b):
                    end = self.calc_end(a, b)
                    if end is not None and self.covers_target(a, end):
                        out.append(Candidate(
                            "ZERO_DST_SIZE",
                            img.name,
                            table_addr,
                            (a, b),
                            a,
                            end,
                            None,
                            b,
                            "MEDIUM",
                            "[dst,size] covers target",
                        ))

                # [dst, end]
                if self.is_ram_ptr(a) and self.is_ram_ptr(b) and b > a:
                    size = b - a
                    if self.valid_size(size) and self.covers_target(a, b):
                        out.append(Candidate(
                            "ZERO_DST_END",
                            img.name,
                            table_addr,
                            (a, b),
                            a,
                            b,
                            None,
                            size,
                            "MEDIUM",
                            "[dst,end] covers target",
                        ))

        return out

    def _copy_candidate(
        self,
        image: Image,
        table_addr: int,
        words: Tuple[int, ...],
        src: int,
        dst: int,
        size_or_end: int,
        third_is_end: bool,
        shape: str,
    ) -> Optional[Candidate]:
        if not self.is_ram_ptr(dst):
            return None

        if third_is_end:
            end = size_or_end
            if not self.is_ram_ptr(end) or end <= dst:
                return None
            size = end - dst
        else:
            size = size_or_end
            if not self.valid_size(size):
                return None
            end = self.calc_end(dst, size)
            if end is None:
                return None

        if not self.valid_size(size) or not self.covers_target(dst, end):
            return None

        src_img = self.mapped_source(src, 1)
        mapped = src_img is not None

        # A copy candidate whose source is mapped in one of our images is much
        # stronger than an arbitrary source integer.
        confidence = "HIGH" if mapped else "LOW"
        note = f"{shape}; source_mapped={src_img.name if src_img else 'NO'}"

        return Candidate(
            kind="COPY_" + shape,
            image=image.name,
            table_addr=table_addr,
            words=words,
            dst=dst,
            end=end,
            src=src,
            size=size,
            confidence=confidence,
            note=note,
        )

    def scan_triple_candidates(self) -> List[Candidate]:
        out = []

        for img in self.images:
            print(f"Scanning 3-word descriptors in {img.name} ...", flush=True)
            data = img.data
            for off in range(0, len(data) - 11, 4):
                w = struct.unpack_from("<III", data, off)
                table_addr = img.base + off

                shapes = [
                    # src, dst, size
                    (w[0], w[1], w[2], False, "SRC_DST_SIZE"),
                    # dst, src, size
                    (w[1], w[0], w[2], False, "DST_SRC_SIZE"),
                    # src, dst, end
                    (w[0], w[1], w[2], True, "SRC_DST_END"),
                    # dst, end, src
                    (w[2], w[0], w[1], True, "DST_END_SRC"),
                ]

                for src, dst, third, is_end, shape in shapes:
                    c = self._copy_candidate(
                        img,
                        table_addr,
                        w,
                        src,
                        dst,
                        third,
                        is_end,
                        shape,
                    )
                    if c is not None:
                        out.append(c)

        return out

    def scan_quad_candidates(self) -> List[Candidate]:
        """
        Generic 4-word target-driven search.

        For each 4-word aligned window:
        - choose one word as RAM destination;
        - choose one other word as source;
        - choose one remaining word as size OR destination-end.
        This intentionally trades format assumptions for coverage completeness.
        """
        out = []

        for img in self.images:
            print(f"Scanning 4-word generic descriptors in {img.name} ...", flush=True)
            data = img.data
            for off in range(0, len(data) - 15, 4):
                w = struct.unpack_from("<IIII", data, off)
                table_addr = img.base + off

                for dst_i in range(4):
                    dst = w[dst_i]
                    if not self.is_ram_ptr(dst) or dst > TARGET_START:
                        continue

                    for src_i in range(4):
                        if src_i == dst_i:
                            continue
                        src = w[src_i]

                        for meta_i in range(4):
                            if meta_i in {dst_i, src_i}:
                                continue
                            meta = w[meta_i]

                            # size hypothesis
                            if self.valid_size(meta):
                                end = self.calc_end(dst, meta)
                                if end is not None and self.covers_target(dst, end):
                                    mapped = self.mapped_source(src, 1)
                                    if mapped:
                                        out.append(Candidate(
                                            "COPY_QUAD_SIZE",
                                            img.name,
                                            table_addr,
                                            w,
                                            dst,
                                            end,
                                            src,
                                            meta,
                                            "HIGH",
                                            f"quad dst=w{dst_i} src=w{src_i} "
                                            f"size=w{meta_i}; source_mapped={mapped.name}",
                                        ))

                            # destination-end hypothesis
                            if self.is_ram_ptr(meta) and meta > dst:
                                size = meta - dst
                                if self.valid_size(size) and self.covers_target(dst, meta):
                                    mapped = self.mapped_source(src, 1)
                                    if mapped:
                                        out.append(Candidate(
                                            "COPY_QUAD_END",
                                            img.name,
                                            table_addr,
                                            w,
                                            dst,
                                            meta,
                                            src,
                                            size,
                                            "HIGH",
                                            f"quad dst=w{dst_i} src=w{src_i} "
                                            f"end=w{meta_i}; source_mapped={mapped.name}",
                                        ))

        return out

    @staticmethod
    def dedup(cands: Iterable[Candidate]) -> List[Candidate]:
        uniq: Dict[Tuple, Candidate] = {}

        for c in cands:
            key = (
                c.kind,
                c.image,
                c.table_addr,
                c.dst,
                c.end,
                c.src,
                c.size,
            )
            uniq[key] = c

        return sorted(
            uniq.values(),
            key=lambda c: (
                0 if c.confidence == "HIGH" else 1 if c.confidence == "MEDIUM" else 2,
                c.dst,
                c.size,
                c.image,
                c.table_addr,
                c.kind,
            ),
        )

    def source_target_slice(self, c: Candidate) -> Optional[Tuple[Image, int, bytes]]:
        if c.src is None:
            return None

        src_for_target = c.src + (TARGET_START - c.dst)
        img = self.mapped_source(src_for_target, TARGET_END - TARGET_START)
        if img is None:
            return None

        data = img.read(src_for_target, TARGET_END - TARGET_START)
        return img, src_for_target, data


def entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    n = len(data)
    e = 0.0
    for c in counts:
        if not c:
            continue
        p = c / n
        e -= p * math.log2(p)
    return e


def load_guard(path: Path, size: int, digest: str, name: str) -> bytes:
    print(f"Loading {name}: {path}", flush=True)
    if not path.is_file():
        raise SystemExit(f"Missing {name}: {path}")
    data = path.read_bytes()
    got = sha256(data)
    ok = len(data) == size and got == digest
    print(f"  size   = 0x{len(data):X}")
    print(f"  sha256 = {got}")
    print(f"  guard  = {'PASS' if ok else 'FAIL'}", flush=True)
    if not ok:
        raise SystemExit(f"ABORT: canonical {name} guard failed")
    return data


def format_words(words: Sequence[int]) -> str:
    return " ".join(f"0x{x:08X}" for x in words)


def main() -> int:
    ap = argparse.ArgumentParser(description=TITLE)
    ap.add_argument(
        "--alice",
        default=r".\research\f2\work\extracted\altice_alice\alice-py.bin",
    )
    ap.add_argument(
        "--boot",
        default=r"C:\Users\verto\mtkclient\research\f2\work\extracted\altice_platform\boot_zimage.bin",
    )
    ap.add_argument(
        "--zimage",
        default=r".\research\f2\work\extracted\altice_platform\zimage.bin",
    )
    ap.add_argument(
        "--dump",
        default=r"C:\Users\verto\mtkclient\research\f2\data\dumps\mobiwire_dump_2.bin",
    )
    args = ap.parse_args()

    print("=" * 120)
    print(TITLE)
    print("=" * 120)
    print("STRICTLY OFFLINE")
    print("PHONE ACCESSED       : NO")
    print("FLASH MODIFIED       : NO")
    print("PATCH GENERATED      : NO")
    print("REPACK               : NO", flush=True)

    hdr("A. CANONICAL INPUT GUARDS")
    ad = load_guard(Path(args.alice), ALICE_SIZE, ALICE_SHA256, "ALICE")
    bd = load_guard(Path(args.boot), BOOT_SIZE, BOOT_SHA256, "BOOT_ZIMAGE")
    zd = load_guard(Path(args.zimage), ZIMAGE_SIZE, ZIMAGE_SHA256, "ZIMAGE")
    dd = load_guard(Path(args.dump), DUMP_SIZE, DUMP_SHA256, "DUMP")

    images = [
        Image("ALICE", ad, ALICE_BASE),
        Image("BOOT_ZIMAGE", bd, BOOT_BASE),
        Image("ZIMAGE", zd, ZIMAGE_BASE),
        Image("PHYSICAL_ROM", dd[:ROM_END - ROM_BASE], ROM_BASE),
    ]
    aud = Auditor(images)

    hdr("B. SEARCH PARAMETERS / SELF-TEST")
    print(f"target interval = [0x{TARGET_START:08X}, 0x{TARGET_END:08X})")
    print(f"RAM search      = [0x{RAM_MIN:08X}, 0x{RAM_MAX:08X})")
    print(f"max region size = 0x{MAX_REGION_SIZE:X}")

    synthetic_dst = TARGET_START - 0x100
    synthetic_size = 0x200
    synthetic_end = synthetic_dst + synthetic_size
    selftest = (
        aud.is_ram_ptr(synthetic_dst)
        and aud.valid_size(synthetic_size)
        and aud.covers_target(synthetic_dst, synthetic_end)
    )
    print(f"coverage self-test = {'PASS' if selftest else 'FAIL'}")
    if not selftest:
        print("ABORT ANALYTICAL PROMOTION: descriptor coverage self-test failed.")
        return 2

    hdr("C. TARGET-COVERING 2-WORD ZERO/BSS DESCRIPTORS")
    pair = aud.dedup(aud.scan_pair_candidates())
    print(f"2-word candidates = {len(pair)}")

    for c in pair[:300]:
        print(
            f"{c.confidence:6s} {c.kind:14s} {c.image:12s} "
            f"table=0x{c.table_addr:08X} "
            f"dst=0x{c.dst:08X} end=0x{c.end:08X} size=0x{c.size:X} "
            f"words=[{format_words(c.words)}]"
        )
    if len(pair) > 300:
        print(f"... {len(pair)-300} additional 2-word candidates omitted ...")

    hdr("D. TARGET-COVERING 3-WORD COPY DESCRIPTORS")
    triple = aud.dedup(aud.scan_triple_candidates())
    print(f"3-word candidates = {len(triple)}")

    for c in triple[:300]:
        print(
            f"{c.confidence:6s} {c.kind:24s} {c.image:12s} "
            f"table=0x{c.table_addr:08X} "
            f"src=0x{(c.src or 0):08X} dst=0x{c.dst:08X} "
            f"end=0x{c.end:08X} size=0x{c.size:X} "
            f"words=[{format_words(c.words)}] ; {c.note}"
        )
    if len(triple) > 300:
        print(f"... {len(triple)-300} additional 3-word candidates omitted ...")

    hdr("E. TARGET-COVERING 4-WORD GENERIC COPY DESCRIPTORS")
    quad = aud.dedup(aud.scan_quad_candidates())
    print(f"4-word candidates = {len(quad)}")

    for c in quad[:300]:
        print(
            f"{c.confidence:6s} {c.kind:18s} {c.image:12s} "
            f"table=0x{c.table_addr:08X} "
            f"src=0x{(c.src or 0):08X} dst=0x{c.dst:08X} "
            f"end=0x{c.end:08X} size=0x{c.size:X} "
            f"words=[{format_words(c.words)}] ; {c.note}"
        )
    if len(quad) > 300:
        print(f"... {len(quad)-300} additional 4-word candidates omitted ...")

    all_candidates = aud.dedup(pair + triple + quad)

    hdr("F. COPY-SOURCE BYTES FOR TARGET BLOCK")
    copy_with_source = []
    for c in all_candidates:
        if not c.kind.startswith("COPY_"):
            continue
        sl = aud.source_target_slice(c)
        if sl is None:
            continue

        src_img, src_addr, data = sl
        copy_with_source.append((c, src_img, src_addr, data))

        words = struct.unpack("<" + "I" * (len(data) // 4), data)
        zeros = data.count(0)
        ffs = data.count(0xFF)

        print()
        print(
            f"{c.confidence} {c.kind} descriptor={c.image}:0x{c.table_addr:08X}"
        )
        print(
            f"  target source = {src_img.name}:0x{src_addr:08X} "
            f"(src_base=0x{(c.src or 0):08X}, dst_base=0x{c.dst:08X})"
        )
        print(
            f"  bytes={len(data)} entropy={entropy(data):.4f} "
            f"00={zeros}/{len(data)} FF={ffs}/{len(data)}"
        )

        for i, value in enumerate(words):
            target_addr = TARGET_START + i * 4
            print(
                f"  0x{target_addr:08X} <= "
                f"{src_img.name}:0x{src_addr + i*4:08X} "
                f"value=0x{value:08X}"
            )

    print()
    print(f"COPY candidates with fully mapped target source = {len(copy_with_source)}")

    hdr("G. DESCRIPTOR-ADDRESS CODE XREFS")
    # Code xrefs to high/medium candidates can identify the startup consumer.
    high_or_medium = [
        c for c in all_candidates
        if c.confidence in {"HIGH", "MEDIUM"}
    ]

    xref_rows = []
    seen_desc = set()

    for c in high_or_medium[:500]:
        desc_key = (c.image, c.table_addr)
        if desc_key in seen_desc:
            continue
        seen_desc.add(desc_key)

        hits = aud.exact_literal_xrefs(c.table_addr)
        if not hits:
            continue

        xref_rows.append((c, hits))
        print()
        print(
            f"descriptor {c.image}:0x{c.table_addr:08X} "
            f"{c.kind} xrefs={len(hits)}"
        )
        for img_name, site, lit_addr in hits:
            print(
                f"  {img_name:12s} site=0x{site:08X} "
                f"literal_word=0x{lit_addr:08X}"
            )

    print()
    print(f"descriptor addresses with exact code xrefs = {len(xref_rows)}")

    hdr("H. CANDIDATE CLASS SUMMARY")
    counts: Dict[str, int] = {}
    for c in all_candidates:
        key = f"{c.confidence}:{c.kind}"
        counts[key] = counts.get(key, 0) + 1

    for key in sorted(counts):
        print(f"{key:36s} {counts[key]}")

    hdr("I. DECISION GATE")
    high_copy = [c for c in all_candidates if c.confidence == "HIGH" and c.kind.startswith("COPY_")]
    medium_zero = [c for c in all_candidates if c.confidence == "MEDIUM" and c.kind.startswith("ZERO_")]

    print(f"2-word target-covering candidates = {len(pair)}")
    print(f"3-word target-covering candidates = {len(triple)}")
    print(f"4-word target-covering candidates = {len(quad)}")
    print(f"HIGH mapped COPY candidates       = {len(high_copy)}")
    print(f"MEDIUM ZERO/BSS candidates         = {len(medium_zero)}")
    print(f"mapped COPY target-source slices   = {len(copy_with_source)}")
    print(f"descriptor addresses with xrefs    = {len(xref_rows)}")
    print()
    print("Interpretation:")
    print("  - HIGH COPY means the candidate source address maps into one of the known")
    print("    ALICE/BOOT/ZIMAGE/ROM images and the destination interval covers the")
    print("    registry global block.")
    print("  - MEDIUM ZERO/BSS means a plausible [dst,size] or [dst,end] pair covers")
    print("    the block, but consumer-code evidence is still required.")
    print("  - If COPY source bytes are available, the printed word for F007F044 is the")
    print("    startup value that would be copied into REG_BASE_GLOBAL under that")
    print("    descriptor hypothesis.")
    print("  - A code xref to a candidate descriptor is strong evidence for a startup")
    print("    table consumer and should be audited next.")
    print("  - If there are no credible covering descriptors, the next useful step is")
    print("    a read-only runtime RAM observation of F007F040..F007F060, not flash write.")
    print()
    print("PHONE ACCESSED       : NO")
    print("FLASH MODIFIED       : NO")
    print("PATCH GENERATED      : NO")
    print("PHYSICAL CANDIDATE   : NO")
    print("HARDWARE WRITE AUTHORIZED: NO", flush=True)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
