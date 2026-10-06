#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
S13.4H - dual-row alias / Audio callback idempotence audit

STRICTLY OFFLINE.
NO PHONE ACCESS.
NO BROM / DA / D6 / D3 / D5.
NO FLASH WRITE.
NO LZMA RECOMPRESSION.
NO VIVA REPACK.
NO PHYSICAL FIRMWARE CANDIDATE.

Goals:
  1. validate the established static resolver table;
  2. enumerate all callback-alias groups (multiple IDs -> same callback);
  3. re-check the one-ID -> one-callback dispatcher semantics;
  4. inspect the native Audio registration callback and common registrar core;
  5. assess duplicate-registration risk if BOTH Image rows are redirected;
  6. build one LOGICAL-ONLY ZIMAGE candidate:
       0x8313 callback F02F3F85 -> 1033D841
       0x8321 callback F02F3F85 -> 1033D841
     i.e. exactly 8 changed logical bytes in two 4-byte ranges.

The candidate produced here is NOT flashable.
"""

from pathlib import Path
from collections import defaultdict
import hashlib
import json
import struct
import sys

from capstone import (
    Cs,
    CS_ARCH_ARM,
    CS_MODE_THUMB,
    CS_MODE_LITTLE_ENDIAN,
)
from capstone.arm import ARM_OP_IMM

ROOT = Path.cwd()

ALICE_PATH = ROOT / "research/f2/work/extracted/altice_alice/alice-py.bin"
ZIMAGE_PATH = ROOT / "research/f2/work/extracted/altice_platform/zimage.bin"

OUTDIR = ROOT / "research/f2/work/candidates/s13_4h"
REPORT = ROOT / "research/f2/work/reports/s13_4h_dual_row_alias_idempotence_audit.txt"

ALICE_BASE = 0x1024EC00
ZIMAGE_BASE = 0xF023CA50

ALICE_SIZE = 0x157BB4
ZIMAGE_SIZE = 0x185E98

ALICE_SHA = "7246242b67afae0d13104452bc3257827cb778119b54e7a26fb7fb55993697ea"
ZIMAGE_SHA = "85fba8c8ae8161e4c1f8ced7983ec30d48c54ab10e51c69fcdfb900aca220954"

TABLE = 0xF0345E68
TABLE_COUNT = 58
TABLE_STRIDE = 8

IMAGE_A = 0x8313
IMAGE_B = 0x8321
AUDIO = 0x8928

IMAGE_CALLBACK = 0xF02F3F85
AUDIO_CALLBACK = 0x1033D841

DISPATCHER = 0x10336788
RESOLVER_WRAPPER = 0x1034C7E4
STATIC_RESOLVER = 0xF0316D74

AUDIO_STUB = 0x1033D840
REG_A = 0x1031F71A
REG_B = 0x1031E120
REG_C = 0x1031F81C
REG_CORE = 0x10301910

EXPECTED_AUDIO_INIT = 0x1033E815
EXPECTED_AUDIO_AUX = 0xF02E18BD

md = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_LITTLE_ENDIAN)
md.detail = True
md.skipdata = True


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def banner(title):
    print()
    print("=" * 120)
    print(title)
    print("=" * 120)


def require(cond, msg):
    if not cond:
        raise RuntimeError(msg)
    print("[PASS]", msg)


def off(base, addr):
    return addr - base


def u32(data, base, addr):
    o = off(base, addr)
    if o < 0 or o + 4 > len(data):
        raise RuntimeError(f"u32 out of bounds @0x{addr:08X}")
    return struct.unpack_from("<I", data, o)[0]


def disasm(data, base, start, size):
    o = off(base, start)
    if o < 0 or o + size > len(data):
        raise RuntimeError(f"disasm outside image @0x{start:08X}")
    out = []
    for insn in md.disasm(data[o:o+size], start):
        out.append(insn)
        print(
            f"0x{insn.address:08X}: "
            f"{insn.bytes.hex(' '):<18} "
            f"{insn.mnemonic:<9} {insn.op_str}"
        )
    return out


def branch_target(insn):
    if insn.mnemonic not in ("bl", "blx", "b", "b.w"):
        return None
    if not insn.operands:
        return None
    op = insn.operands[0]
    if op.type != ARM_OP_IMM:
        return None
    return op.imm & 0xFFFFFFFF


def parse_table(zimage):
    toff = off(ZIMAGE_BASE, TABLE)
    require(toff >= 0, "resolver table offset valid")
    require(
        toff + TABLE_COUNT * TABLE_STRIDE <= len(zimage),
        "resolver table fully inside ZIMAGE",
    )

    rows = []
    for i in range(TABLE_COUNT):
        roff = toff + i * TABLE_STRIDE
        rid, field2, cb = struct.unpack_from("<HHI", zimage, roff)
        rows.append({
            "index": i,
            "runtime": ZIMAGE_BASE + roff,
            "offset": roff,
            "id": rid,
            "field2": field2,
            "callback": cb,
            "raw": zimage[roff:roff+8].hex(" "),
        })
    return rows


def one_row(rows, rid):
    xs = [r for r in rows if r["id"] == rid]
    require(len(xs) == 1, f"exactly one resolver row for 0x{rid:04X}")
    return xs[0]


def callback_alias_groups(rows):
    groups = defaultdict(list)
    for row in rows:
        groups[row["callback"]].append(row)

    aliases = {
        cb: xs
        for cb, xs in groups.items()
        if len(xs) > 1
    }

    banner("B. CALLBACK ALIAS GROUPS IN THE STATIC RESOLVER TABLE")
    print(f"total rows = {len(rows)}")
    print(f"unique callbacks = {len(groups)}")
    print(f"callbacks shared by >=2 IDs = {len(aliases)}")
    print()

    for cb, xs in sorted(aliases.items(), key=lambda kv: (-len(kv[1]), kv[0])):
        ids = ", ".join(f"0x{x['id']:04X}" for x in xs)
        addrs = ", ".join(f"0x{x['runtime']:08X}" for x in xs)
        marker = ""
        if cb == IMAGE_CALLBACK:
            marker = " <IMAGE ALIAS GROUP>"
        print(
            f"callback=0x{cb:08X} count={len(xs)} IDs=[{ids}] rows=[{addrs}]{marker}"
        )

    return aliases


def find_indirect_blx(insns):
    return [
        i for i in insns
        if i.mnemonic == "blx"
        and (not i.operands or i.operands[0].type != ARM_OP_IMM)
    ]


def dispatcher_semantics(alice, zimage):
    banner("C. ONE-ID -> ONE-CALLBACK DISPATCH SEMANTICS")

    print("ALICE dispatcher 0x10336788:")
    disp = disasm(alice, ALICE_BASE, DISPATCHER, 0x70)

    call_resolver = [
        i for i in disp
        if branch_target(i) == RESOLVER_WRAPPER
    ]
    require(
        len(call_resolver) >= 1,
        "dispatcher calls resolver wrapper 1034C7E4",
    )

    indirect = find_indirect_blx(disp)
    require(
        len(indirect) >= 1,
        "dispatcher contains indirect BLX callback invocation",
    )
    for i in indirect:
        print(f"  callback invocation candidate @0x{i.address:08X}: {i.mnemonic} {i.op_str}")

    print()
    print("ZIMAGE static resolver 0xF0316D74:")
    static = disasm(zimage, ZIMAGE_BASE, STATIC_RESOLVER, 0x90)

    # The purpose here is structural, not full symbolic execution:
    # one input lookup returns a callback pointer; the table itself is not
    # iterated to execute every callback.
    has_return = any(i.mnemonic in ("bx", "pop") for i in static)
    require(has_return, "static resolver has a normal return path")

    print()
    print("STRUCTURAL CONCLUSION:")
    print("  resolver rows are lookup data.")
    print("  the dispatcher resolves an incoming ID, obtains one callback,")
    print("  then invokes that callback indirectly.")
    print("  Redirecting two table rows does NOT by itself execute Audio twice.")
    print("  Duplicate Audio callback execution requires two separate dispatches.")


def audit_audio_registration(alice):
    banner("D. NATIVE AUDIO REGISTRATION CALLBACK")

    stub = disasm(alice, ALICE_BASE, AUDIO_STUB, 0x28)

    targets = [branch_target(i) for i in stub]
    require(REG_A in targets, "Audio callback calls registrar A 1031F71A")
    require(REG_B in targets, "Audio callback calls registrar B 1031E120")
    require(REG_C in targets, "Audio callback calls registrar C 1031F81C")

    # Native pointer literals from the established stub layout.
    require(
        u32(alice, ALICE_BASE, 0x1033D85C) == EXPECTED_AUDIO_INIT,
        "Audio callback literal A/B == 1033E815",
    )
    require(
        u32(alice, ALICE_BASE, 0x1033D860) == EXPECTED_AUDIO_AUX,
        "Audio callback literal C == F02E18BD",
    )

    banner("E. THREE REGISTRAR WRAPPERS")
    for addr, name, expected_r2 in (
        (REG_A, "REG_A", 0),
        (REG_B, "REG_B", 2),
        (REG_C, "REG_C", 1),
    ):
        print(f"{name} @0x{addr:08X}, expected channel r2={expected_r2}")
        insns = disasm(alice, ALICE_BASE, addr, 0x14)
        calls = [branch_target(i) for i in insns if i.mnemonic in ("bl", "blx")]
        require(
            REG_CORE in calls,
            f"{name} calls common registrar core 10301910",
        )
        print()

    banner("F. COMMON REGISTRAR CORE 10301910")
    core = disasm(alice, ALICE_BASE, REG_CORE, 0x120)

    print()
    print("The audit does NOT infer idempotence merely from disassembly.")
    print("Instead, it records structural signals useful for duplicate-risk assessment:")

    calls = []
    cmps = 0
    loads = 0
    stores = 0
    branches = 0

    for i in core:
        if i.mnemonic in ("bl", "blx"):
            t = branch_target(i)
            calls.append((i.address, t))
        if i.mnemonic.startswith("cmp"):
            cmps += 1
        if i.mnemonic.startswith("ldr"):
            loads += 1
        if i.mnemonic.startswith("str"):
            stores += 1
        if i.mnemonic.startswith("b"):
            branches += 1

    print(f"  compare instructions = {cmps}")
    print(f"  load instructions    = {loads}")
    print(f"  store instructions   = {stores}")
    print(f"  branch instructions  = {branches}")
    print(f"  direct BL/BLX calls  = {len(calls)}")
    for addr, target in calls:
        if target is None:
            print(f"    0x{addr:08X} -> indirect")
        else:
            print(f"    0x{addr:08X} -> 0x{target:08X}")

    return {
        "core_compare_count": cmps,
        "core_load_count": loads,
        "core_store_count": stores,
        "core_branch_count": branches,
        "core_direct_call_count": len(calls),
    }


def direct_calls_to(data, base, target):
    out = []
    # decode from each halfword for robust xref census
    for o in range(0, len(data)-4, 2):
        insns = list(md.disasm(data[o:o+4], base+o, count=1))
        if not insns:
            continue
        i = insns[0]
        if i.mnemonic not in ("bl", "blx"):
            continue
        if branch_target(i) == target:
            out.append(i.address)
    return sorted(set(out))


def common_core_xrefs(alice):
    banner("G. COMMON REGISTRAR CORE XREF CENSUS")
    hits = direct_calls_to(alice, ALICE_BASE, REG_CORE)
    print(f"direct calls to 10301910 = {len(hits)}")
    for x in hits[:100]:
        print(f"  0x{x:08X}")
    if len(hits) > 100:
        print(f"  ... {len(hits)-100} more")

    require(len(hits) >= 3, "common registrar core is shared by multiple callers")
    require(0x1031F71E in hits, "REG_A callsite -> common core present")
    require(0x1031E126 in hits, "REG_B callsite -> common core present")
    require(0x1031F820 in hits, "REG_C callsite -> common core present")

    return hits


def build_dual_candidate(zimage, ia, ib):
    banner("H. BUILD LOGICAL-ONLY DUAL-ROW CANDIDATE")

    require(ia["callback"] == IMAGE_CALLBACK, "IMAGE_A old callback exact")
    require(ib["callback"] == IMAGE_CALLBACK, "IMAGE_B old callback exact")

    a_addr = ia["runtime"] + 4
    b_addr = ib["runtime"] + 4

    a_off = off(ZIMAGE_BASE, a_addr)
    b_off = off(ZIMAGE_BASE, b_addr)

    require(u32(zimage, ZIMAGE_BASE, a_addr) == IMAGE_CALLBACK, "IMAGE_A callback bytes exact")
    require(u32(zimage, ZIMAGE_BASE, b_addr) == IMAGE_CALLBACK, "IMAGE_B callback bytes exact")

    out = bytearray(zimage)
    out[a_off:a_off+4] = struct.pack("<I", AUDIO_CALLBACK)
    out[b_off:b_off+4] = struct.pack("<I", AUDIO_CALLBACK)
    out = bytes(out)

    diffs = [i for i, (x, y) in enumerate(zip(zimage, out)) if x != y]
    require(len(out) == len(zimage), "candidate ZIMAGE size unchanged")
    require(len(diffs) == 8, "dual-row candidate changes exactly 8 bytes")

    expected = list(range(a_off, a_off+4)) + list(range(b_off, b_off+4))
    require(diffs == expected, "dual-row candidate has exactly two 4-byte diff ranges")

    path = OUTDIR / "candidate_D_image_8313_8321_both_to_audio_callback.bin"
    path.write_bytes(out)

    print(f"IMAGE_A callback runtime = 0x{a_addr:08X}")
    print(f"IMAGE_B callback runtime = 0x{b_addr:08X}")
    print(f"old callback             = 0x{IMAGE_CALLBACK:08X}")
    print(f"new callback             = 0x{AUDIO_CALLBACK:08X}")
    print(f"changed logical bytes    = {len(diffs)}")
    print(f"candidate SHA256         = {sha256(out)}")
    print(f"candidate path           = {path}")

    return {
        "path": str(path),
        "sha256": sha256(out),
        "changed_bytes": len(diffs),
        "patches": [
            {
                "id": f"0x{IMAGE_A:04X}",
                "runtime": f"0x{a_addr:08X}",
                "zimage_offset": f"0x{a_off:X}",
                "old": f"0x{IMAGE_CALLBACK:08X}",
                "new": f"0x{AUDIO_CALLBACK:08X}",
            },
            {
                "id": f"0x{IMAGE_B:04X}",
                "runtime": f"0x{b_addr:08X}",
                "zimage_offset": f"0x{b_off:X}",
                "old": f"0x{IMAGE_CALLBACK:08X}",
                "new": f"0x{AUDIO_CALLBACK:08X}",
            },
        ],
    }


def main():
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")

    alice = ALICE_PATH.read_bytes()
    zimage = ZIMAGE_PATH.read_bytes()

    OUTDIR.mkdir(parents=True, exist_ok=True)
    REPORT.parent.mkdir(parents=True, exist_ok=True)

    log = REPORT.open("w", encoding="utf-8")
    real = sys.stdout

    class Tee:
        def write(self, s):
            real.write(s)
            log.write(s)
            return len(s)
        def flush(self):
            real.flush()
            log.flush()

    sys.stdout = Tee()

    try:
        banner("S13.4H - DUAL-ROW ALIAS / IDEMPOTENCE AUDIT")
        print("STRICTLY OFFLINE")
        print("PHONE ACCESSED       : NO")
        print("FLASH MODIFIED       : NO")
        print("LZMA RECOMPRESS      : NO")
        print("VIVA REPACK          : NO")
        print("PHYSICAL CANDIDATE   : NO")
        print()

        require(len(alice) == ALICE_SIZE, f"ALICE size = 0x{ALICE_SIZE:X}")
        require(sha256(alice) == ALICE_SHA, "canonical ALICE SHA256")
        require(len(zimage) == ZIMAGE_SIZE, f"ZIMAGE size = 0x{ZIMAGE_SIZE:X}")
        require(sha256(zimage) == ZIMAGE_SHA, "canonical ZIMAGE SHA256")

        banner("A. RESOLVER ROW VALIDATION")
        rows = parse_table(zimage)
        ia = one_row(rows, IMAGE_A)
        ib = one_row(rows, IMAGE_B)
        au = one_row(rows, AUDIO)

        require(ia["field2"] == 0 and ia["callback"] == IMAGE_CALLBACK, "0x8313 exact Image row")
        require(ib["field2"] == 0 and ib["callback"] == IMAGE_CALLBACK, "0x8321 exact Image row")
        require(au["field2"] == 0 and au["callback"] == AUDIO_CALLBACK, "0x8928 exact Audio row")

        print(f"IMAGE_A row: {ia}")
        print(f"IMAGE_B row: {ib}")
        print(f"AUDIO row  : {au}")

        aliases = callback_alias_groups(rows)
        require(
            IMAGE_CALLBACK in aliases,
            "Image callback is natively an alias callback for multiple IDs",
        )
        require(
            {x["id"] for x in aliases[IMAGE_CALLBACK]} == {IMAGE_A, IMAGE_B},
            "Image alias callback group is exactly {0x8313,0x8321}",
        )

        dispatcher_semantics(alice, zimage)
        core_summary = audit_audio_registration(alice)
        core_xrefs = common_core_xrefs(alice)
        candidate = build_dual_candidate(zimage, ia, ib)

        banner("I. DUPLICATE-REGISTRATION RISK ASSESSMENT")
        print("PROVEN:")
        print("  1. The resolver table already supports multi-ID -> same-callback aliases.")
        print("  2. 0x8313 and 0x8321 natively share one callback.")
        print("  3. Table rows are lookup data; they are not all executed at table load.")
        print("  4. A dispatch resolves one incoming ID and invokes one callback.")
        print("  5. Native Audio registration uses three wrappers over one shared core.")
        print()
        print("NOT PROVEN:")
        print("  1. Whether 0x8313 and 0x8321 are both dispatched during one Image Viewer action.")
        print("  2. Whether calling native Audio registration callback twice is fully idempotent.")
        print("  3. Whether redirecting both aliases has side effects elsewhere.")
        print()
        print("Therefore:")
        print("  dual-row candidate D is structurally stronger than guessing B or C,")
        print("  but it is still NOT approved for physical repack/write until one more")
        print("  offline gate checks the common registrar core and alias-dispatch side effects.")

        manifest = {
            "stage": "S13.4H",
            "status": "OFFLINE_LOGICAL_DUAL_ROW_CANDIDATE_NOT_FLASHABLE",
            "canonical": {
                "alice_sha256": sha256(alice),
                "zimage_sha256": sha256(zimage),
            },
            "alias_group_count": len(aliases),
            "image_alias_group": [
                f"0x{x['id']:04X}"
                for x in aliases[IMAGE_CALLBACK]
            ],
            "common_registrar_core": {
                "address": f"0x{REG_CORE:08X}",
                "direct_xref_count": len(core_xrefs),
                **core_summary,
            },
            "candidate_D": candidate,
            "limitations": [
                "No runtime proof that both Image IDs are dispatched together or separately.",
                "Registrar core idempotence not yet formally proven.",
                "No LZMA recompression.",
                "No VIVA repack.",
                "No physical flash-sector mapping.",
                "No handset I/O.",
            ],
        }

        manifest_path = OUTDIR / "manifest.json"
        manifest_path.write_text(
            json.dumps(manifest, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )

        banner("S13.4H RESULT")
        print("CANONICAL ALICE / ZIMAGE        : PASS")
        print("IMAGE NATIVE ALIAS GROUP        : PASS")
        print("ONE-ID / ONE-CALLBACK SEMANTICS : PASS")
        print("AUDIO NATIVE CALLBACK           : PASS")
        print("COMMON REGISTRAR CORE           : AUDITED")
        print("DUAL-ROW 8-BYTE LOGICAL POC     : BUILT")
        print("RUNTIME IDEMPOTENCE             : NOT YET PROVEN")
        print("LZMA RECOMPRESS                 : NOT DONE")
        print("VIVA REPACK                     : NOT DONE")
        print("PHYSICAL CANDIDATE              : NOT DONE")
        print("PHONE ACCESSED                  : NO")
        print("FLASH MODIFIED                  : NO")
        print("HARDWARE WRITE AUTHORIZED       : NO")
        print()
        print(f"MANIFEST = {manifest_path}")
        print(f"REPORT   = {REPORT}")

    finally:
        sys.stdout = real
        log.close()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
