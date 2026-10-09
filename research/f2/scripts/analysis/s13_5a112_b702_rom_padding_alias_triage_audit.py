#!/usr/bin/env python3
"""S13.5A.112 — B702 read-only ROM padding/reference triage.

Shows padding-LIKE runs near canonical static tables, NOT safe code caves and
NOT a location recommendation. A112 is only a shortlist for manual evidence;
no binary patch is produced, no ROM address is ever certified as free.

No phone/USB/COM, flash, patch, repack, emulator edits, or Notepad.
"""
from __future__ import annotations

import argparse
from bisect import bisect_right
from collections import Counter
import hashlib
from pathlib import Path
import struct

ALICE_SIZE = 0x157BB4
ALICE_SHA = "7246242b67afae0d13104452bc3257827cb778119b54e7a26fb7fb55993697ea"
ZIMAGE_BASE = 0xF023CA50
ZIMAGE_SIZE = 0x185E98
ZIMAGE_END = ZIMAGE_BASE + ZIMAGE_SIZE
ZIMAGE_SHA = "85fba8c8ae8161e4c1f8ced7983ec30d48c54ab10e51c69fcdfb900aca220954"
RECORD_BASE = 0xF0378760
RECORD_COUNT = 895
RECORD_STRIDE = 0x10
DESCRIPTOR = 0xF037C08C
RANGE_BASE = 0xF037BF54
RANGE_COUNT = 52
B702_INDEX = 884
B703_INDEX = 885
AUDIO_INDEX = 490
B702_CHILD_PTR = 0xF0378720
REPORT_NAME = "s13_5a112_b702_rom_padding_alias_triage_audit.txt"
# Deliberately restricted neighborhoods; full-ROM byte scanning would only
# create many misleading false-positive 'free space' entries.
PROBES = (
    ("CHILD_POOL_NEIGHBORHOOD", 0xF0378000, 0xF0378760),
    ("DESCRIPTOR_NEIGHBORHOOD", 0xF037C098, 0xF037C800),
    ("ZIMAGE_TAIL_4K", ZIMAGE_END - 0x1000, ZIMAGE_END),
)


def abort(reason: str) -> None:
    raise RuntimeError("ABORT: " + reason)


def take(blob: bytes, address: int, size: int) -> bytes:
    off = address - ZIMAGE_BASE
    if off < 0 or size < 0 or off + size > len(blob):
        abort(f"outside ZIMAGE address=0x{address:08X} bytes={size}")
    return blob[off:off + size]


def u16(blob: bytes, address: int) -> int:
    return int.from_bytes(take(blob, address, 2), "little")


def u32(blob: bytes, address: int) -> int:
    return int.from_bytes(take(blob, address, 4), "little")


def guard(path: Path, name: str, expect_size: int, expect_sha: str) -> tuple[bytes, str]:
    if not path.is_file():
        abort(f"missing {name}: {path}")
    blob = path.read_bytes()
    sha = hashlib.sha256(blob).hexdigest()
    if len(blob) != expect_size or sha != expect_sha:
        abort(f"{name} guard failed: size=0x{len(blob):X} sha256={sha}")
    return blob, f"{name}_GUARD=PASS SIZE=0x{len(blob):X} SHA256={sha}"


def interval_overlap(a: int, b: int, c: int, d: int) -> bool:
    return a < d and c < b


def merge_intervals(items: list[tuple[int, int]]) -> list[tuple[int, int]]:
    merged: list[tuple[int, int]] = []
    for start, stop in sorted(items):
        if start >= stop:
            abort(f"invalid protected interval 0x{start:X}..0x{stop:X}")
        if merged and start <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(stop, merged[-1][1]))
        else:
            merged.append((start, stop))
    return merged


def intersects_protected(start: int, stop: int, regions: list[tuple[int, int]]) -> bool:
    # regions are merged and sorted; bisect against ends isn't necessary for
    # these small canonical record sets.
    return any(interval_overlap(start, stop, a, b) for a, b in regions)


def pads(blob: bytes, start: int, stop: int, protected: list[tuple[int, int]], min_bytes: int = 8) -> list[tuple[int, int, int]]:
    """Return maximal *4-aligned subranges* consisting solely of 00 or FF.

    Each tuple is start/end/padbyte.  No interpretation as unused memory.
    """
    out: list[tuple[int, int, int]] = []
    a = start
    while a < stop:
        v = blob[a - ZIMAGE_BASE]
        if v not in (0x00, 0xFF):
            a += 1
            continue
        b = a + 1
        while b < stop and blob[b - ZIMAGE_BASE] == v:
            b += 1
        aligned_start = (a + 3) & ~3
        aligned_end = b & ~3
        if aligned_end - aligned_start >= min_bytes and not intersects_protected(aligned_start, aligned_end, protected):
            out.append((aligned_start, aligned_end, v))
        a = b
    return out


def pointer_ref_counts(images: tuple[tuple[str, bytes], ...], probes: tuple[tuple[str, int, int], ...]) -> Counter[int]:
    """Count alignment-4 raw u32 values landing within a screened region.

    This does NOT exclude refs encoded with other alignments, ADR/ADD, relative
    tables, compressed pointers, runtime code, or computed addresses.
    """
    c: Counter[int] = Counter()
    for _, blob in images:
        for offset in range(0, len(blob) - 3, 4):
            v = struct.unpack_from("<I", blob, offset)[0]
            if any(lo <= v < hi for _, lo, hi in probes):
                c[v] += 1
    return c


def refs_in_interval(ref_values: list[int], ref_counts: Counter[int], begin: int, stop: int) -> int:
    idx = bisect_right(ref_values, begin - 1)
    total = 0
    while idx < len(ref_values) and ref_values[idx] < stop:
        total += ref_counts[ref_values[idx]]
        idx += 1
    return total


def self_test() -> None:
    assert B702_CHILD_PTR + 4 == 0xF0378724
    assert RECORD_BASE + B702_INDEX * RECORD_STRIDE == 0xF037BEA0
    assert RECORD_BASE + B703_INDEX * RECORD_STRIDE == 0xF037BEB0
    assert RECORD_BASE + AUDIO_INDEX * RECORD_STRIDE == 0xF037A600
    assert ZIMAGE_END == 0xF03C28E8
    assert merge_intervals([(0x10, 0x14), (0x14, 0x18), (0x30, 0x34)]) == [(0x10, 0x18), (0x30, 0x34)]
    assert intersects_protected(0x17, 0x19, [(0x10, 0x18)])
    assert not intersects_protected(0x18, 0x1C, [(0x10, 0x18)])
    # Synthetic candidate: one 8-byte pad at 0x...20, adjacent occupied 8 bytes.
    test = bytearray(b"\x01" * 64)
    test[0x20:0x28] = b"\xff" * 8
    test[0x28:0x30] = b"\x00" * 8
    base = ZIMAGE_BASE
    candidates = pads(test, base, base + 64, [(base + 0x28, base + 0x30)])
    assert candidates == [(base + 0x20, base + 0x28, 0xFF)]
    assert refs_in_interval([base + 0x24, base + 0x30], Counter({base + 0x24: 2, base + 0x30: 4}), base + 0x20, base + 0x28) == 2
    print("A112_SELF_TEST=PASS INDEX_INTERVAL_PROTECTION_PADDING_AND_POINTER_COUNTS")


def evaluate(alice: bytes, zimage: bytes, alice_line: str, zimage_line: str) -> str:
    lines = [
        "S13.5A.112 — B702 ROM PADDING/REFERENCE TRIAGE; UNVERIFIED CANDIDATES ONLY",
        "STRICTLY_OFFLINE=YES INPUTS_READ_ONLY=YES NO_BINARY_PATCH_OR_PHONE=YES",
        "NO_NOTEPAD=YES NO_USB_COM_FLASH_REPACK_EMULATOR_EDIT=YES",
        alice_line, zimage_line,
        "SCOPE=THREE_NARROW_ZIMAGE_WINDOWS; NOT_AN_ALL_ROM_FREE_SPACE_PROOF",
        "KNOWN=A111_B702_APPEND_COLLIDES_WITH_B703; NO_COUNT_ONLY_PATCH",
        "IMPORTANT=padding_00_FF_and_no_aligned_literal_refs_DO_NOT_PROVE_UNUSED_MEMORY",
        "",
    ]
    if u32(zimage, DESCRIPTOR) != RECORD_BASE or u32(zimage, DESCRIPTOR + 4) != RANGE_BASE or u16(zimage, DESCRIPTOR + 8) != RANGE_COUNT:
        abort("descriptor layout differs from A111")
    for idx, ident, parent, num, ptr in (
        (B702_INDEX, "B702", 0xB709, 2, B702_CHILD_PTR),
        (B703_INDEX, "B703", 0x0000, 2, B702_CHILD_PTR + 4),
    ):
        ra = RECORD_BASE + idx * RECORD_STRIDE
        if (u16(zimage, ra), u16(zimage, ra + 2), u32(zimage, ra + 12)) != (parent, num, ptr):
            abort(f"{ident} count/parent/pointer guard mismatch")
    if tuple(u16(zimage, B702_CHILD_PTR + 2 * i) for i in range(3)) != (0x8569, 0x87ED, 0xA07B):
        abort("B702 children / B703 first child changed")
    if u16(zimage, RECORD_BASE + AUDIO_INDEX * RECORD_STRIDE) != 0xB702:
        abort("Audio record parent no longer B702")
    lines += [
        "=== A. EXACT STATIC POSITIVE CONTROLS ===",
        "A111_CANONICAL_DESCRIPTOR_AND_B702_B703_AUDIO_METADATA=PASS",
        "B702_CHILD_PTR=0xF0378720 B702_CHILDREN=8569,87ED B703_NEXT=0xA07B",
        "B702_PLUS_8928_REQUIRES_RELOCATION=YES MIN_BYTES=6 ALIGNED_SURVEY_THRESHOLD=8",
        "",
    ]
    protected = [
        (RECORD_BASE, RECORD_BASE + RECORD_COUNT * RECORD_STRIDE),
        (RANGE_BASE, DESCRIPTOR + 12),
        (0xF0345E68, 0xF0346038),  # 58 * 8 native resolver rows, historical S11/A87.
    ]
    arrays = 0
    unknown = 0
    for index in range(RECORD_COUNT):
        addr = RECORD_BASE + index * RECORD_STRIDE
        count = u16(zimage, addr + 2)
        ptr = u32(zimage, addr + 12)
        if count == 0:
            continue
        end = ptr + count * 2
        if ptr & 1 or end > ZIMAGE_END or ptr < ZIMAGE_BASE or end < ptr:
            unknown += 1
            continue
        protected.append((ptr, end))
        arrays += 1
    if arrays != 245 or unknown != 0:
        abort(f"A111 ownership census drifted nonempty={arrays} unclassified={unknown}")
    merged = merge_intervals(protected)
    lines += [
        "=== B. RESERVED INTERVALS ===",
        f"RECORDS={RECORD_COUNT} NONEMPTY_CHILD_ARRAYS={arrays} UNCLASSIFIED={unknown}",
        f"PROTECTED_INTERIOR_INTERVALS_MERGED={len(merged)}",
        "PROTECTION_SCOPE=CHILD_ARRAYS_PLUS_REGISTRY_RECORDS_RANGES_DESCRIPTOR_NATIVE_RESOLVER",
        "NOT_PROTECTED=CODE_LITERALS_COMPRESSED_DATA_RUNTIME_ALIASES_SECTION_MAP_UNDECODED_POINTERS",
        "",
    ]
    ref_counts = pointer_ref_counts((("ALICE", alice), ("ZIMAGE", zimage)), PROBES)
    keys = sorted(ref_counts)
    grand_total = 0
    top_rows: list[tuple[str, int, int, int, int]] = []
    for label, start, end in PROBES:
        if not ZIMAGE_BASE <= start < end <= ZIMAGE_END:
            abort(f"bad probe {label} 0x{start:X}..0x{end:X}")
        candidates = pads(zimage, start, end, merged)
        lines += [f"=== C. WINDOW {label} [0x{start:08X},0x{end:08X}) ===",
                  f"ALL_ALIGNED_PADDING_LIKE_RUNS_8PLUS_EXCLUDING_KNOWN_DATA={len(candidates)}"]
        if not candidates:
            lines.append("NO_CANDIDATE_IN_THIS_RESTRICTED_WINDOW")
        for a,b,v in sorted(candidates, key=lambda item: (-(item[1] - item[0]), item[0]))[:20]:
            refs = refs_in_interval(keys, ref_counts, a, b)
            lines.append(f"  UNVERIFIED_PADDING_RUN=[0x{a:08X},0x{b:08X}) BYTES={b-a} PATTERN={v:02X} ALIGNED_U32_REFS={refs} STATUS=NOT_SAFE_NOT_APPROVED")
            top_rows.append((label,a,b,v,refs))
        grand_total += len(candidates)
        lines.append("COUNT_MAX_20_DISPLAYED=YES; not all padding runs necessarily shown")
        lines.append("")
    lines += [
        "=== D. EXIT CONDITIONS ===",
        f"PAD_LIKE_RUNS_TOTAL_ACROSS_PROBES={grand_total}",
        "VERIFIED_UNUSED_ROM_SLOTS=0 (cannot be inferred from pattern and literal census)",
        "B702_RELOCATION_STORAGE_CONFIRMED=NO",
        "RUNTIME_CHILD_POINTER_TRANSLATION_AND_BOOT_IMAGE_LAYOUT_CONFIRMED=NO",
        "B702_VISIBLE_LEAF_ACTION_TO_AUDIO_8928_PROVEN=NO",
        "NO_FREE_ADDRESS_ENDORSED=YES; NOT_A_PATCH_PLAN=YES",
        "NEXT_IF_REVIEW_WARRANTED=section/loader map + executable CFG reachability + full alias provenance for a SINGLE candidate",
        "NEXT_IF_NO_TRUSTWORTHY_STORAGE=stop ROM pad heuristic; return to UI selected ID -> native callback provenance",
        "NO_PHONE_USB_COM_FLASH_PATCH_REPACK=YES",
    ]
    return "\n".join(lines) + "\n"


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--root", type=Path, default=Path(r"C:\Users\verto\F2-Altice-MobiWire"))
    ap.add_argument("--out", type=Path)
    ap.add_argument("--self-test", action="store_true")
    args = ap.parse_args()
    self_test()
    if args.self_test:
        return
    root: Path = args.root
    out = args.out or (root / "research/f2/work/reports" / REPORT_NAME)
    alice, alice_line = guard(root / "research/f2/work/extracted/altice_alice/alice-py.bin", "ALICE", ALICE_SIZE, ALICE_SHA)
    zimage, zimage_line = guard(root / "research/f2/work/extracted/altice_platform/zimage.bin", "ZIMAGE", ZIMAGE_SIZE, ZIMAGE_SHA)
    result = evaluate(alice, zimage, alice_line, zimage_line)
    if not out.parent.is_dir():
        abort("reports directory is missing: " + str(out.parent))
    with out.open("x", encoding="utf-8", newline="\n") as fp:
        fp.write(result)
    print(f"A112_REPORT_CREATED={out} BYTES={out.stat().st_size}")
    print("A112_RESULT=REVIEW_UNVERIFIED_PADDING_ONLY_NO_PATCH_GENERATED")


if __name__ == "__main__":
    main()
