#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""S13.5A.103 — A90 owner direct-relative caller census (STRICTLY OFFLINE).

Purpose: A102 found no exact u32 pointers to 102ED240 or 10345268.
Search just Thumb BL and unconditional B.W relative *candidates* which land
on those two entries. Never interpret a raw match as proven code execution.

Pure stdlib. Reads SHA-pinned ALICE and ZIMAGE only. Writes one new text report
under research/f2/work/reports. No Notepad / hardware / flash / patch / network.
"""
from __future__ import annotations

import argparse
import hashlib
from pathlib import Path
import struct
import sys

ALICE_BASE = 0x1024EC00
ALICE_SIZE = 0x157BB4
ALICE_HASH = "7246242b67afae0d13104452bc3257827cb778119b54e7a26fb7fb55993697ea"
ZIMAGE_BASE = 0xF023CA50
ZIMAGE_SIZE = 0x185E98
ZIMAGE_HASH = "85fba8c8ae8161e4c1f8ced7983ec30d48c54ab10e51c69fcdfb900aca220954"

OWNERS = {0x102ED240: "A90_FIRST_OWNER", 0x10345268: "A90_SECOND_OWNER"}
# Exact on-firmware anchors from A90 / A97, tested *after* canonical SHA pins.
ALICE_ANCHORS = {
    0x102ED240: "10b5",
    0x102ED260: "2cf0cafd",  # -> 10319DF8
    0x102ED26C: "9af092fd",  # -> 10387D94
    0x10345268: "f8b5",
    0x10345282: "d4f7b9fd",  # -> 10319DF8
    0x10345296: "aaf7d9f8",  # -> 102EF44C
    0x103452AC: "42f072fd",  # -> 10387D94
    0x10340D2C: "c52f3410",  # A10 control callback literal
}
POSITIVE_BLS = {
    0x102ED260: 0x10319DF8,
    0x102ED26C: 0x10387D94,
    0x10345282: 0x10319DF8,
    0x10345296: 0x102EF44C,
    0x103452AC: 0x10387D94,
}


def abort(reason: str) -> None:
    raise SystemExit("ABORT: " + reason)


def branch_at(addr: int, hw1: int, hw2: int):
    """Decode Thumb-2 T1 BL and T4 unconditional B.W signed PC-relative.

    Returns (kind, target) or None. It cannot establish code/data boundaries.
    The search deliberately excludes BLX-imm and conditional B.W.
    """
    if (hw1 & 0xF800) != 0xF000:
        return None
    t = hw2 & 0xD000
    if t == 0xD000:
        kind = "BL"
    elif t == 0x9000:
        kind = "B.W"
    else:
        return None
    s = (hw1 >> 10) & 1
    j1 = (hw2 >> 13) & 1
    j2 = (hw2 >> 11) & 1
    i1 = 1 ^ (j1 ^ s)
    i2 = 1 ^ (j2 ^ s)
    disp = ((s << 24) | (i1 << 23) | (i2 << 22)
            | ((hw1 & 0x3FF) << 12) | ((hw2 & 0x7FF) << 1))
    if disp & (1 << 24):
        disp -= 1 << 25
    return kind, (addr + 4 + disp) & 0xFFFFFFFF


def self_test() -> None:
    checks = {
        0x102ED260: ("2cf0cafd", "BL", 0x10319DF8),
        0x102ED26C: ("9af092fd", "BL", 0x10387D94),
        0x10345282: ("d4f7b9fd", "BL", 0x10319DF8),
        0x10345296: ("aaf7d9f8", "BL", 0x102EF44C),
        0x103452AC: ("42f072fd", "BL", 0x10387D94),
        0x102ED000: ("00f002b8", "B.W", 0x102ED008),
    }
    for addr, (hx, kind, expect) in checks.items():
        h1, h2 = struct.unpack("<HH", bytes.fromhex(hx))
        found = branch_at(addr, h1, h2)
        assert found == (kind, expect), (hex(addr), found, kind, hex(expect))
    assert branch_at(0x102ED000, 0xB510, 0xBD10) is None
    print("A103_SELF_TEST=PASS count=7; signed Thumb BL/B.W targets and negative guard")


def load(path: Path, name: str, size: int, digest: str) -> bytes:
    if not path.is_file():
        abort(f"missing {name} input: {path}")
    data = path.read_bytes()
    actual = hashlib.sha256(data).hexdigest()
    if len(data) != size or actual != digest:
        abort(f"{name} source guard FAIL size=0x{len(data):X} sha256={actual}")
    return data


def verify_anchor(data: bytes, base: int) -> None:
    for addr, hx in ALICE_ANCHORS.items():
        raw = bytes.fromhex(hx)
        off = addr - base
        if data[off:off+len(raw)] != raw:
            abort(f"A90/A97 exact anchor mismatch @0x{addr:08X}")
    for addr, expected in POSITIVE_BLS.items():
        off = addr - base
        pair = struct.unpack_from("<HH", data, off)
        found = branch_at(addr, *pair)
        if found != ("BL", expected):
            abort(f"A90 positive direct BL mismatch @0x{addr:08X}: {found}")


def census(data: bytes, base: int) -> tuple[list[tuple[int, str, int]], int, int]:
    hits = []
    likely32 = 0
    scan_n = 0
    target_set = set(OWNERS)
    for off in range(0, len(data)-3, 2):
        h1 = data[off] | (data[off+1] << 8)
        if (h1 & 0xF800) != 0xF000:
            continue
        h2 = data[off+2] | (data[off+3] << 8)
        decoded = branch_at(base+off, h1, h2)
        if not decoded:
            continue
        likely32 += 1
        kind, tgt = decoded
        if tgt in target_set:
            hits.append((base+off, kind, tgt))
        scan_n += 1
    return hits, likely32, scan_n


def raw_neighbor(data: bytes, base: int, at: int, before=0x18, after=0x18) -> str:
    off = at - base
    low = max(0, off-before)
    high = min(len(data), off+after)
    return f"0x{base+low:08X}..0x{base+high:08X} " + data[low:high].hex(" ")


def run(alice: bytes, zimage: bytes) -> str:
    verify_anchor(alice, ALICE_BASE)
    result = [
        "S13.5A.103 — A90 SELECTED OWNER RELATIVE CALLER CENSUS (STRICTLY OFFLINE)",
        f"ALICE_GUARD=PASS sha256={ALICE_HASH}",
        f"ZIMAGE_GUARD=PASS sha256={ZIMAGE_HASH}",
        f"A90_A97_ANCHORS=PASS count={len(ALICE_ANCHORS)}",
        f"POSITIVE_DIRECT_BL_CONTROL=PASS count={len(POSITIVE_BLS)}",
        "A102_PREVIOUS_RESULT=both owner 32-bit literal refs absent, control 10342FC5 present",
        "SCOPE=all halfword positions in canonical ALICE and ZIMAGE; Thumb BL/B.W PC-relative ONLY",
        "LIMIT=raw instruction-pattern matches may be DATA; no CFG or caller ownership proof",
        "LIMIT=zero hits cannot exclude BLX via veneer, 16-bit branch, conditional wide B, ARM-mode, indirect or computed pointers",
        "NO_USB_COM_PHONE_FLASH_PATCH_REPACK=YES; INPUT_IMAGES_READ_ONLY=YES; NO_NOTEPAD=YES",
    ]
    allhits = []
    for name, blob, base in [("ALICE", alice, ALICE_BASE),("ZIMAGE",zimage,ZIMAGE_BASE)]:
        matches, count, _ = census(blob, base)
        result.append(f"\n=== {name} SEARCH ===")
        result.append(f"IMAGE_BASE=0x{base:08X} FILE_BYTES=0x{len(blob):X} RAW_THUMB_WIDE_BRANCH_CANDIDATES={count}")
        for owner, label in OWNERS.items():
            subset = [(site,kind) for site,kind,target in matches if target==owner]
            result.append(f"TARGET=0x{owner:08X} {label} RAW_MATCH_COUNT={len(subset)}")
            for site, kind in subset:
                result.append(f"  RAW_SITE=0x{site:08X} MODE={kind} TARGET=0x{owner:08X} OFFSET=0x{site-base:X}")
                result.append(f"    RAW_NEIGHBOR={raw_neighbor(blob,base,site)}")
        allhits.extend([(name,*row) for row in matches])
    result.extend([
        "\n=== DECISION GATE ===",
        f"TOTAL_OWNER_BRANCH_CANDIDATES={len(allhits)}",
        "If hits exist: decode bounded real owner function CFG at each candidate, verify executable paths and r0 event arguments.",
        "If zero: no DIRECT RELATIVE BL/B.W found in this deliberately limited subset; pivot to concrete dispatch registration/indirection using existing A10–A16 results.",
        "NO_ASSERTION=selected leaf Audio 0x8928, visible Multimedia, FM numeric ID or descriptor+0x0C setter",
        "RAW_ZERO_HITS_NOT_PROOF_OF_UNREACHABILITY=YES",
    ])
    return "\n".join(result)+"\n"


def infer_repo_root() -> Path:
    # Works both with the user research folder and isolated self-test folders.
    for parent in Path(__file__).resolve().parents:
        if (parent / "research" / "f2").is_dir():
            return parent
    return Path.cwd()


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--root", type=Path, default=infer_repo_root())
    ap.add_argument("--alice", type=Path)
    ap.add_argument("--zimage", type=Path)
    ap.add_argument("--out", type=Path)
    ap.add_argument("--self-test", action="store_true")
    args = ap.parse_args()
    self_test()
    if args.self_test:
        return 0
    root = args.root.resolve()
    alice_path = args.alice or root / "research/f2/work/extracted/altice_alice/alice-py.bin"
    zimage_path = args.zimage or root / "research/f2/work/extracted/altice_platform/zimage.bin"
    outfile = args.out or root / "research/f2/work/reports/s13_5a103_selection_owner_relative_callers_audit.txt"
    if outfile.is_file():
        print(f"REPORT_ALREADY_EXISTS_UNCHANGED={outfile.resolve()}")
        return 0
    alice = load(alice_path, "ALICE", ALICE_SIZE, ALICE_HASH)
    zimage = load(zimage_path, "ZIMAGE", ZIMAGE_SIZE, ZIMAGE_HASH)
    report = run(alice, zimage)
    outfile.parent.mkdir(parents=True, exist_ok=True)
    try:
        with outfile.open("x", encoding="utf-8", newline="\n") as f:
            f.write(report)
    except FileExistsError:
        print(f"REPORT_ALREADY_EXISTS_UNCHANGED={outfile.resolve()}")
        return 0
    print(f"A103_GUARDS=PASS A103_REPORT_CREATED={outfile.resolve()} SIZE={outfile.stat().st_size}")
    print("A103_RESULT=" + next(x for x in report.splitlines() if x.startswith("TOTAL_OWNER_BRANCH_CANDIDATES=")))
    return 0


if __name__ == "__main__":
    sys.exit(main())
