#!/usr/bin/env python3
"""S13.5A.113 — read-only STRUCTURAL CONFLICT check for A112 B702 storage candidates.

Only tests existing six A112 padding-like intervals, their nearest record/row
context and all-alignment exact pointer references. It does not allocate ROM,
patch firmware, prove pointer provenance/section maps, or connect to a phone.
"""
from __future__ import annotations

import argparse
import hashlib
from pathlib import Path
import struct
from collections import Counter

ALICE_BASE = 0x1024EC00
ALICE_SIZE = 0x157BB4
ALICE_SHA = "7246242b67afae0d13104452bc3257827cb778119b54e7a26fb7fb55993697ea"
ZIMAGE_BASE = 0xF023CA50
ZIMAGE_SIZE = 0x185E98
ZIMAGE_END = ZIMAGE_BASE + ZIMAGE_SIZE
ZIMAGE_SHA = "85fba8c8ae8161e4c1f8ced7983ec30d48c54ab10e51c69fcdfb900aca220954"
DESCRIPTOR = 0xF037C08C
RECORDS = 0xF0378760
RECORD_COUNT = 895
STRIDE = 16
RANGES = 0xF037BF54
B702 = 884
B703 = 885
AUDIO = 490
B702_LIST = 0xF0378720
ROW_START = 0xF037C468
ROW_STRIDE = 0x30
ROW_COUNT = 7
REPORT = "s13_5a113_b702_candidate_structural_conflict_audit.txt"

# Six EXPLICIT A112 PAD runs. Pattern/value checks fail closed if they drift.
CANDIDATES = (
    ("STRUCT_ZERO_A", 0xF037C530, 0xF037C53C, 0x00),
    ("STRUCT_ZERO_B", 0xF037C54C, 0xF037C558, 0x00),
    ("STRUCT_ZERO_C", 0xF037C588, 0xF037C590, 0x00),
    ("TAIL_ZERO", 0xF03C27D4, 0xF03C27F0, 0x00),
    ("TAIL_FF_A", 0xF03C2800, 0xF03C2808, 0xFF),
    ("TAIL_FF_B", 0xF03C2810, 0xF03C2818, 0xFF),
)


def fail(reason: str) -> None:
    raise RuntimeError("A113_ABORT: " + reason)


def get(blob: bytes, base: int, va: int, length: int) -> bytes:
    start = va - base
    if length < 0 or start < 0 or start + length > len(blob):
        fail(f"out of bounds base={base:08X} addr={va:08X} length={length}")
    return blob[start:start + length]


def u16(blob: bytes, base: int, va: int) -> int:
    return int.from_bytes(get(blob, base, va, 2), "little")


def u32(blob: bytes, base: int, va: int) -> int:
    return int.from_bytes(get(blob, base, va, 4), "little")


def guarded(path: Path, label: str, size: int, sha: str) -> bytes:
    if not path.is_file():
        fail(f"{label} not found: {path}")
    data = path.read_bytes()
    h = hashlib.sha256(data).hexdigest()
    if len(data) != size or h != sha:
        fail(f"{label} mismatch: len={len(data)} sha={h}")
    return data


def overlap(a: int, b: int, c: int, d: int) -> bool:
    return a < d and c < b


def exact_refs_every_alignment(images: tuple[tuple[str, bytes, int], ...], targets: set[int], candidates: tuple[tuple[str, int, int, int], ...]) -> tuple[dict[int, Counter[str]], dict[str, list[tuple[str, int, int]]]]:
    """Raw u32 values in two images, offset at every byte alignment.

    References to candidate interiors are reported as raw little-endian values,
    not executable instructions or proven pointers. Small input total (<3 MB).
    """
    roots: dict[int, Counter[str]] = {v: Counter() for v in sorted(targets)}
    candidate_hits: dict[str, list[tuple[str, int, int]]] = {row[0]: [] for row in candidates}
    for image_name, blob, base in images:
        for off in range(len(blob) - 3):
            value = struct.unpack_from("<I", blob, off)[0]
            if value in roots:
                roots[value][image_name] += 1
            for name, start, stop, _pad in candidates:
                if start <= value < stop:
                    if len(candidate_hits[name]) < 30:
                        candidate_hits[name].append((image_name, base + off, value))
    return roots, candidate_hits


def row_for(addr: int) -> tuple[int, int] | None:
    if addr < ROW_START or addr >= ROW_START + ROW_COUNT * ROW_STRIDE:
        return None
    idx = (addr - ROW_START) // ROW_STRIDE
    return ROW_START + idx * ROW_STRIDE, idx


def format_hex(blob: bytes, base: int, start: int, end: int) -> list[str]:
    lines = []
    for a in range(start, end, 16):
        bb = get(blob, base, a, min(16, end - a))
        lines.append(f"  {a:08X}  {bb.hex(' ')}")
    return lines


def self_test() -> None:
    assert ZIMAGE_END == 0xF03C28E8
    assert row_for(0xF037C530) == (0xF037C528, 4)
    assert row_for(0xF037C54C) == (0xF037C528, 4)
    assert row_for(0xF037C588) == (0xF037C588, 6)
    assert row_for(0xF03C27D4) is None
    assert overlap(0, 8, 7, 11) and not overlap(0, 8, 8, 11)
    sample = bytearray(b"\xAA" * 40)
    struct.pack_into("<I", sample, 1, 0xF037C528)  # unaligned exact pointer
    struct.pack_into("<I", sample, 13, 0xF037C531)  # candidate interior
    roots, hits = exact_refs_every_alignment(
        (("TEST", bytes(sample), 0x1000),),
        {0xF037C528},
        (("STRUCT_ZERO_A", 0xF037C530, 0xF037C53C, 0),),
    )
    assert roots[0xF037C528]["TEST"] == 1
    assert hits["STRUCT_ZERO_A"] == [("TEST", 0x100D, 0xF037C531)]
    assert len(CANDIDATES) == 6
    print("A113_SELF_TEST=PASS ROW_STRIDE_AND_EVERY_ALIGNMENT_POINTER_CENSUS")


def analyze(alice: bytes, zimage: bytes) -> str:
    lines = [
        "S13.5A.113 — A112 SIX PAD-LIKE SLOTS: EXISTING STRUCTURE/REFERENCE CONFLICT AUDIT",
        "STRICTLY_OFFLINE=YES SOURCE_IMAGES_READ_ONLY=YES NO_PHONE_USB_COM_FLASH_PATCH_REPACK=YES",
        "METHOD=ONLY_SIX_A112_RUNS_PLUS_SEVEN_0x30_PITCHED_ROW_NEIGHBORS_AND_UNALIGNED_RAW_U32_REFS",
        "WARNING=ROW_BOUNDARIES_ARE_HYPOTHESES; NO_VERIFIED_FREE_ROM_SLOT_OR_IMAGE_RELOCATION_MODEL",
        f"ALICE_GUARD=PASS SIZE=0x{len(alice):X} SHA256={ALICE_SHA}",
        f"ZIMAGE_GUARD=PASS SIZE=0x{len(zimage):X} SHA256={ZIMAGE_SHA}",
    ]
    if (u32(zimage, ZIMAGE_BASE, DESCRIPTOR), u32(zimage, ZIMAGE_BASE, DESCRIPTOR + 4), u16(zimage, ZIMAGE_BASE, DESCRIPTOR + 8)) != (RECORDS, RANGES, 52):
        fail("static registry descriptor drift")
    if (u16(zimage, ZIMAGE_BASE, RECORDS + B702 * STRIDE + 2), u32(zimage, ZIMAGE_BASE, RECORDS + B702 * STRIDE + 12)) != (2, B702_LIST):
        fail("B702 structure drift")
    if (u16(zimage, ZIMAGE_BASE, RECORDS + B703 * STRIDE + 2), u32(zimage, ZIMAGE_BASE, RECORDS + B703 * STRIDE + 12)) != (2, B702_LIST + 4):
        fail("B703 structure drift")
    if tuple(u16(zimage, ZIMAGE_BASE, B702_LIST + 2 * i) for i in range(3)) != (0x8569, 0x87ED, 0xA07B):
        fail("B702/B703 contents drift")
    if u16(zimage, ZIMAGE_BASE, RECORDS + AUDIO * STRIDE) != 0xB702:
        fail("Audio logical parent drift")
    for name, start, stop, pad in CANDIDATES:
        if (start & 3) or (stop & 3) or not (ZIMAGE_BASE <= start < stop <= ZIMAGE_END):
            fail("candidate range invalid: " + name)
        if get(zimage, ZIMAGE_BASE, start, stop - start) != bytes([pad]) * (stop - start):
            fail("A112 padding bytes drift: " + name)
    lines += [
        "A111_AND_A112_STATIC_BYTES_GUARD=PASS",
        "B702_CHILDREN=8569,87ED B703_FIRST=A07B AUDIO_LOGICAL_PARENT=B702",
        "",
        "=== A. HISTORICAL 0x30-PITCHED DATA-ROW HYPOTHESIS ===",
        "CONTEXT=S11 reports descriptor-like records F037C468,F037C498,F037C4C8,F037C4F8,F037C558",
        "HYPOTHESIS_ONLY=0x30-pitched slot rows, not validated as entire record family",
    ]
    row_starts = [ROW_START + i * ROW_STRIDE for i in range(ROW_COUNT)]
    for i, start in enumerate(row_starts):
        words = [u32(zimage, ZIMAGE_BASE, start + 4 * n) for n in range(12)]
        lines.append(f"ROW_HYPOTHESIS index={i} start=0x{start:08X} U32_WORDS=" + ",".join(f"{v:08X}" for v in words))
    roots, inside_hits = exact_refs_every_alignment(
        (("ALICE", alice, ALICE_BASE), ("ZIMAGE", zimage, ZIMAGE_BASE)), set(row_starts), CANDIDATES
    )
    lines += ["", "=== B. EXACT RAW U32 REFERENCES TO ROW STARTS (ALL BYTE ALIGNMENTS) ==="]
    for root in row_starts:
        counts = roots[root]
        lines.append(f"ROW_BASE=0x{root:08X} ALICE={counts['ALICE']} ZIMAGE={counts['ZIMAGE']} STATUS=RAW_VALUE_ONLY")
    lines += ["", "=== C. A112 CANDIDATES / PUTATIVE ROW OVERLAPS / RAW POINTER INTERIORS ==="]
    for name, start, stop, pad in CANDIDATES:
        row = row_for(start)
        row_text = f"0x{row[0]:08X}/index={row[1]} offsets=+0x{start-row[0]:X}..+0x{stop-row[0]:X}" if row else "NONE_IN_TESTED_0x30_ROW_WINDOW"
        hits = inside_hits[name]
        lines.append(f"RUN={name} RANGE=[0x{start:08X},0x{stop:08X}) LEN={stop-start} PAD={pad:02X} ROW_OVERLAP_HYPOTHESIS={row_text}")
        lines.append(f"  EXACT_RAW_U32_VALUES_POINTING_INSIDE_RUN_COUNT_SHOWN={len(hits)} LIMIT=30")
        for image_name, source, ptr in hits:
            lines.append(f"  RAW_U32_AT={image_name}:0x{source:08X} TARGET=0x{ptr:08X}")
        if name.startswith("STRUCT"):
            lines.append("  CAUTION=NEAR_HISTORIC_STRUCTURED_METADATA_NO_FREE_SPACE_INFERENCE")
        else:
            lines.append("  CAUTION=IMAGE_TAIL_PADDING_MAY_BE_IN_SECTION_OR_IMAGE_INTEGRITY_SCOPE")
        lo = max(ZIMAGE_BASE, start - 0x20) & ~0xF
        hi = min(ZIMAGE_END, stop + 0x20)
        lines.extend(format_hex(zimage, ZIMAGE_BASE, lo, hi))
    lines += [
        "", "=== D. DECISION GATE ===",
        "STRUCT_PAD_ROWS_CONFIRMED_UNUSED=NO",
        "TAIL_PAD_CONFIRMED_UNUSED=NO",
        "ROM_RELOCATION_STORAGE_VALIDATED=NO",
        "MENU_VISIBLE_SELECTED_ID_TO_AUDIO_CALLBACK_PROVEN=NO",
        "NO_BINARY_EDIT_OR_PATCH_EMITTED=YES",
        "NEXT=STOP_PAD_HEURISTICS_UNLESS_LOADER_SECTION_MAP_AND_ALL_ALIAS_PROVENANCE_AVAILABLE",
        "NEXT=INDEPENDENTLY_PROVE_B702_VISIBLE_SELECTION_TO_NATIVE_AUDIO_DISPATCH_BEFORE_PATCH",
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
    root = args.root
    alice = guarded(root / "research/f2/work/extracted/altice_alice/alice-py.bin", "ALICE", ALICE_SIZE, ALICE_SHA)
    zimage = guarded(root / "research/f2/work/extracted/altice_platform/zimage.bin", "ZIMAGE", ZIMAGE_SIZE, ZIMAGE_SHA)
    report = analyze(alice, zimage)
    dest = args.out or root / "research/f2/work/reports" / REPORT
    if not dest.parent.is_dir():
        fail("report folder missing: " + str(dest.parent))
    with dest.open("x", encoding="utf-8", newline="\n") as f:
        f.write(report)
    print(f"A113_REPORT_CREATED={dest} BYTES={dest.stat().st_size}")
    print("A113_RESULT=UNVERIFIED_STRUCTURAL_CONFLICT_TRIAGE_NO_PATCH")


if __name__ == "__main__":
    main()
