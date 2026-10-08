#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
S13.5A - Multimedia menu provider / registry audit

STRICTLY OFFLINE.
NO PHONE ACCESS.
NO BROM / DA / D6 / D3 / D5.
NO FLASH WRITE.
NO PATCH GENERATION.
NO LZMA RECOMPRESSION.
NO VIVA REPACK.

Historical menu work stopped because ALICE eventually reached F02D8870 and
F032ACDC, outside the then-mapped ROM+ALICE images. We now have canonical
ZIMAGE mapped at F023CA50, and BOTH providers are inside it.
"""

from pathlib import Path
from collections import deque
import hashlib
import struct
import sys

from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_LITTLE_ENDIAN
from capstone.arm import ARM_OP_IMM, ARM_OP_MEM, ARM_REG_PC

ROOT = Path.cwd()
ALICE_PATH = ROOT / "research/f2/work/extracted/altice_alice/alice-py.bin"
ZIMAGE_PATH = ROOT / "research/f2/work/extracted/altice_platform/zimage.bin"
REPORT = ROOT / "research/f2/work/reports/s13_5a_menu_provider_registry_audit.txt"

ALICE_BASE = 0x1024EC00
ZIMAGE_BASE = 0xF023CA50
ALICE_SIZE = 0x157BB4
ZIMAGE_SIZE = 0x185E98
ALICE_SHA = "7246242b67afae0d13104452bc3257827cb778119b54e7a26fb7fb55993697ea"
ZIMAGE_SHA = "85fba8c8ae8161e4c1f8ced7983ec30d48c54ab10e51c69fcdfb900aca220954"

GET_CHILD_COUNT = 0xF02D8870
ENUM_CHILD_IDS  = 0xF032ACDC
GET_CHILD_META  = 0xF02F9CCC

ALICE_PREPARE_CHILDREN = 0x10275714
ALICE_ENUM_VENEER = 0x1022EA20
ALICE_COUNT_VENEER = 0x1022EAB0

IMAGE_A = 0x8313
IMAGE_B = 0x8321
AUDIO = 0x8928

STATIC_RESOLVER_TABLE = 0xF0345E68
STATIC_RESOLVER_COUNT = 58
STATIC_RESOLVER_STRIDE = 8

TARGETS = {
    GET_CHILD_COUNT: "GET_CHILD_COUNT F02D8870",
    ENUM_CHILD_IDS: "ENUM_CHILD_IDS F032ACDC",
    GET_CHILD_META: "GET_CHILD_META F02F9CCC",
}

md = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_LITTLE_ENDIAN)
md.detail = True
md.skipdata = True


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def banner(title):
    print()
    print("=" * 124)
    print(title)
    print("=" * 124)


def require(cond, msg):
    if not cond:
        raise RuntimeError(msg)
    print("[PASS]", msg)


def inside(data, base, addr, size=1):
    o = addr - base
    return 0 <= o and o + size <= len(data)


def u32(data, base, addr):
    if not inside(data, base, addr, 4):
        return None
    return struct.unpack_from("<I", data, addr - base)[0]


def classify_addr(addr):
    a = addr & ~1
    if ZIMAGE_BASE <= a < ZIMAGE_BASE + ZIMAGE_SIZE:
        return "ZIMAGE"
    if ALICE_BASE <= a < ALICE_BASE + ALICE_SIZE:
        return "ALICE"
    if 0x10000000 <= addr < 0x10100000:
        return "RAM/BSS_100x"
    if 0xF0000000 <= addr < 0xF1000000:
        return "F0_OTHER"
    if addr < 0x10000:
        return "SMALL"
    return "OTHER"


def branch_target(insn):
    if insn.mnemonic not in (
        "bl", "blx", "b", "b.w", "beq", "bne", "bcc", "bcs", "bhi", "bls",
        "bgt", "blt", "bge", "ble", "bmi", "bpl"
    ):
        return None
    if not insn.operands or insn.operands[0].type != ARM_OP_IMM:
        return None
    return insn.operands[0].imm & 0xFFFFFFFF


def pc_literal(insn, data, base):
    if not insn.mnemonic.startswith("ldr") or len(insn.operands) < 2:
        return None
    src = insn.operands[1]
    if src.type != ARM_OP_MEM or src.mem.base != ARM_REG_PC:
        return None
    pc = (insn.address + 4) & ~3
    lit_addr = (pc + src.mem.disp) & 0xFFFFFFFF
    value = u32(data, base, lit_addr)
    if value is None:
        return None
    return lit_addr, value


def fmt_insn(insn, data, base):
    notes = []
    bt = branch_target(insn)
    if bt is not None:
        notes.append(f"TARGET=0x{bt:08X} {classify_addr(bt)}")
    lit = pc_literal(insn, data, base)
    if lit:
        la, value = lit
        s = f"LITERAL[0x{la:08X}]=0x{value:08X} {classify_addr(value)}"
        if value in (IMAGE_A, IMAGE_B, AUDIO):
            s += " <KNOWN_APP_ID>"
        notes.append(s)
    suffix = "" if not notes else " ; " + " ; ".join(notes)
    return (
        f"0x{insn.address:08X}: {insn.bytes.hex(' '):<18} "
        f"{insn.mnemonic:<9} {insn.op_str:<35}{suffix}"
    )


def disasm_window(title, data, base, start, size):
    banner(title)
    require(inside(data, base, start, 2), f"0x{start:08X} is inside image")
    end = min(base + len(data), start + size)
    out = list(md.disasm(data[start-base:end-base], start))
    for i in out:
        print(fmt_insn(i, data, base))
    return out


def direct_calls(insns):
    out = []
    for i in insns:
        if i.mnemonic not in ("bl", "blx"):
            continue
        t = branch_target(i)
        if t is not None:
            out.append((i.address, t))
    return out


def literal_refs(insns, data, base):
    out = []
    for i in insns:
        lit = pc_literal(i, data, base)
        if lit:
            out.append((i.address, lit[0], lit[1]))
    return out


def recursive_provider_trace(zimage, entry, name, max_depth=2):
    banner(f"PROVIDER TRACE — {name}")
    queue = deque([(entry & ~1, 0)])
    seen = set()
    all_literals = []

    while queue:
        addr, depth = queue.popleft()
        if addr in seen or not inside(zimage, ZIMAGE_BASE, addr, 2):
            continue
        seen.add(addr)

        print()
        print(f"--- depth={depth} window @0x{addr:08X} ---")
        size = 0x180 if depth == 0 else 0xC0
        end = min(ZIMAGE_BASE + len(zimage), addr + size)
        insns = list(md.disasm(zimage[addr-ZIMAGE_BASE:end-ZIMAGE_BASE], addr))
        for i in insns:
            print(fmt_insn(i, zimage, ZIMAGE_BASE))

        calls = direct_calls(insns)
        lits = literal_refs(insns, zimage, ZIMAGE_BASE)
        all_literals.extend(v for _, _, v in lits)

        print("  [SUMMARY]")
        for site, target in calls:
            print(f"    CALL 0x{site:08X} -> 0x{target:08X} {classify_addr(target)}")
        for site, la, value in lits:
            print(
                f"    LIT  insn=0x{site:08X} @0x{la:08X} "
                f"=0x{value:08X} {classify_addr(value)}"
            )

        if depth < max_depth:
            for _, target in calls:
                nt = target & ~1
                if ZIMAGE_BASE <= nt < ZIMAGE_BASE + len(zimage):
                    queue.append((nt, depth + 1))

    print(f"TRACE UNIQUE WINDOWS = {len(seen)}")
    return all_literals


def parse_resolver_ids(zimage):
    o = STATIC_RESOLVER_TABLE - ZIMAGE_BASE
    require(o >= 0, "resolver table offset valid")
    require(
        o + STATIC_RESOLVER_COUNT * STATIC_RESOLVER_STRIDE <= len(zimage),
        "resolver table fully inside ZIMAGE",
    )
    rows = []
    for i in range(STATIC_RESOLVER_COUNT):
        roff = o + i * STATIC_RESOLVER_STRIDE
        rid, field2, cb = struct.unpack_from("<HHI", zimage, roff)
        rows.append((rid, field2, cb, ZIMAGE_BASE + roff))
    return rows


def raw_occurrences(data, pattern):
    out = []
    pos = 0
    while True:
        k = data.find(pattern, pos)
        if k < 0:
            break
        out.append(k)
        pos = k + 1
    return out


def show_data_window(zimage, addr, radius=0x60):
    addr &= ~1
    if not inside(zimage, ZIMAGE_BASE, addr, 1):
        return
    start = max(ZIMAGE_BASE, addr - radius) & ~1
    end = min(ZIMAGE_BASE + len(zimage), addr + radius)
    for line in range(start, end, 0x10):
        chunk = zimage[line-ZIMAGE_BASE:min(line-ZIMAGE_BASE+0x10, len(zimage))]
        ascii_ = "".join(chr(b) if 32 <= b <= 126 else "." for b in chunk)
        mark = " <==" if line <= addr < line + 0x10 else ""
        print(f"    0x{line:08X}: {chunk.hex(' '):<47} {ascii_}{mark}")


def provider_reachable_id_correlation(zimage, resolver_ids, pointer_values):
    banner("PROVIDER-REACHABLE DATA / RESOLVER-ID CORRELATION")
    ptrs = sorted({v & ~1 for v in pointer_values if classify_addr(v) == "ZIMAGE"})
    print(f"unique provider-reachable ZIMAGE pointers = {len(ptrs)}")

    for ptr in ptrs:
        lo = max(0, ptr - ZIMAGE_BASE - 0x300)
        hi = min(len(zimage), ptr - ZIMAGE_BASE + 0x300)
        blob = zimage[lo:hi]
        hits = []
        for rid in resolver_ids:
            for k in raw_occurrences(blob, struct.pack("<H", rid)):
                hits.append((ZIMAGE_BASE + lo + k, rid))
        if not hits:
            continue
        print()
        print(f"POINTER 0x{ptr:08X}: resolver IDs within +-0x300")
        for a, rid in sorted(hits)[:80]:
            tag = ""
            if rid == IMAGE_A:
                tag = " IMAGE_A"
            elif rid == IMAGE_B:
                tag = " IMAGE_B"
            elif rid == AUDIO:
                tag = " AUDIO"
            print(f"  0x{a:08X}: 0x{rid:04X}{tag}")
        show_data_window(zimage, ptr, 0x80)


def scan_candidate_child_lists(zimage, resolver_ids):
    banner("WHOLE-ZIMAGE CANDIDATE CHILD-ID NEIGHBORHOODS")
    r0 = STATIC_RESOLVER_TABLE - ZIMAGE_BASE
    r1 = r0 + STATIC_RESOLVER_COUNT * STATIC_RESOLVER_STRIDE
    candidates = []

    for rid in (IMAGE_A, IMAGE_B):
        for pos in raw_occurrences(zimage, struct.pack("<H", rid)):
            if r0 <= pos < r1:
                continue
            start = max(0, (pos - 0x20) & ~1)
            end = min(len(zimage), pos + 0x22)
            vals = [(o, struct.unpack_from("<H", zimage, o)[0]) for o in range(start, end, 2)]
            hits = [(o, v) for o, v in vals if v in resolver_ids]
            distinct = {v for _, v in hits}
            if len(distinct) < 2:
                continue
            audio_here = AUDIO in distinct
            both_images = IMAGE_A in distinct and IMAGE_B in distinct
            score = len(distinct) + (5 if audio_here else 0) + (3 if both_images else 0)
            candidates.append((score, pos, rid, hits, start, end))

    candidates.sort(reverse=True)
    print(f"candidate neighborhoods = {len(candidates)}")
    for n, (score, pos, rid, hits, start, end) in enumerate(candidates[:50], 1):
        print(
            f"#{n:02d} score={score} anchor=0x{ZIMAGE_BASE+pos:08X} "
            f"{'IMAGE_A' if rid == IMAGE_A else 'IMAGE_B'}"
        )
        print("  " + ", ".join(f"0x{v:04X}@0x{ZIMAGE_BASE+o:08X}" for o, v in hits))
        print(f"  raw = {zimage[start:end].hex(' ')}")
    return candidates


def direct_xrefs_to_target(data, base, target):
    hits = []
    for o in range(0, len(data)-4, 2):
        insns = list(md.disasm(data[o:o+4], base+o, count=1))
        if not insns:
            continue
        i = insns[0]
        if i.mnemonic in ("bl", "blx") and branch_target(i) == target:
            hits.append(i.address)
    return sorted(set(hits))


def xref_census(alice, zimage):
    banner("DIRECT XREF CENSUS TO MENU PROVIDERS")
    for target, name in TARGETS.items():
        a = direct_xrefs_to_target(alice, ALICE_BASE, target)
        z = direct_xrefs_to_target(zimage, ZIMAGE_BASE, target)
        print(name)
        print(f"  ALICE direct calls  = {len(a)}")
        for x in a[:60]:
            print(f"    0x{x:08X}")
        print(f"  ZIMAGE direct calls = {len(z)}")
        for x in z[:60]:
            print(f"    0x{x:08X}")
        print()


def alice_pipeline_check(alice):
    banner("ALICE MENU PIPELINE CROSS-CHECK")
    require(inside(alice, ALICE_BASE, ALICE_PREPARE_CHILDREN, 2), "10275714 present")
    disasm_window("ALICE 10275714", alice, ALICE_BASE, ALICE_PREPARE_CHILDREN, 0xB0)

    for veneer, target, label in (
        (ALICE_ENUM_VENEER, ENUM_CHILD_IDS | 1, "child enumeration veneer"),
        (ALICE_COUNT_VENEER, GET_CHILD_COUNT | 1, "child count veneer"),
    ):
        o = veneer - ALICE_BASE
        require(0 <= o <= len(alice)-8, f"{label} inside ALICE")
        op, ptr = struct.unpack_from("<II", alice, o)
        require(op == 0xE51FF004, f"{label}: ARM LDR pc,[pc,#-4]")
        require(ptr == target, f"{label}: target literal == 0x{target:08X}")
        print(f"  0x{veneer:08X} -> 0x{ptr:08X}")


def main():
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")

    alice = ALICE_PATH.read_bytes()
    zimage = ZIMAGE_PATH.read_bytes()

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
        banner("S13.5A - MULTIMEDIA MENU PROVIDER / REGISTRY AUDIT")
        print("STRICTLY OFFLINE")
        print("PHONE ACCESSED       : NO")
        print("FLASH MODIFIED       : NO")
        print("PATCH GENERATED      : NO")
        print("LZMA RECOMPRESS      : NO")
        print("VIVA REPACK          : NO")
        print()

        require(len(alice) == ALICE_SIZE, f"ALICE size = 0x{ALICE_SIZE:X}")
        require(sha256(alice) == ALICE_SHA, "canonical ALICE SHA256")
        require(len(zimage) == ZIMAGE_SIZE, f"ZIMAGE size = 0x{ZIMAGE_SIZE:X}")
        require(sha256(zimage) == ZIMAGE_SHA, "canonical ZIMAGE SHA256")

        banner("A. HISTORICAL MENU BLOCKER IS NOW MAPPED")
        for addr, name in TARGETS.items():
            require(inside(zimage, ZIMAGE_BASE, addr, 2), f"{name} is inside ZIMAGE")
            print(f"  {name}: ZIMAGE+0x{addr-ZIMAGE_BASE:X}")

        alice_pipeline_check(alice)
        xref_census(alice, zimage)

        provider_literals = []
        for addr, name in TARGETS.items():
            provider_literals.extend(recursive_provider_trace(zimage, addr, name, max_depth=2))

        rows = parse_resolver_ids(zimage)
        resolver_ids = {rid for rid, _, _, _ in rows}

        provider_reachable_id_correlation(zimage, resolver_ids, provider_literals)
        candidates = scan_candidate_child_lists(zimage, resolver_ids)

        banner("S13.5A DECISION GATE")
        print("Q1. F02D8870: thin wrapper, table lookup, or dynamic registry walk?")
        print("Q2. F032ACDC: table copy or filtered registry enumeration?")
        print("Q3. Which ZIMAGE/RAM globals back the providers?")
        print("Q4. Do provider-backed regions contain 0x8313 / 0x8321?")
        print("Q5. Is 0x8928 already in the same registry structure?")
        print("Q6. Can parent -> [Image Viewer, FM Radio] be recovered?")
        print()
        print("Do NOT promote a raw ID neighborhood without provider-backed dataflow.")
        print(f"raw candidate neighborhoods emitted = {len(candidates)}")
        print()
        print("PHONE ACCESSED       : NO")
        print("FLASH MODIFIED       : NO")
        print("PATCH GENERATED      : NO")
        print("PHYSICAL CANDIDATE   : NO")
        print("HARDWARE WRITE AUTHORIZED: NO")
        print()
        print(f"REPORT = {REPORT}")

    finally:
        sys.stdout = real
        log.close()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
