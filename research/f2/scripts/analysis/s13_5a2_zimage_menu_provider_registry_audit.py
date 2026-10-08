#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
S13.5A.2 - ZIMAGE-only Multimedia menu provider / registry audit

STRICTLY OFFLINE.
NO PHONE ACCESS.
NO BROM / DA / D6 / D3 / D5.
NO FLASH WRITE.
NO PATCH GENERATION.
NO LZMA RECOMPRESSION.
NO VIVA REPACK.

This replaces S13.5A v1, which mixed legacy ALICE runtime addresses
(base 0x101812C4) with the canonical S13 ALICE mapping (base 0x1024EC00).

We no longer need legacy ALICE addresses for this gate.

Targets already proven to lie inside canonical decompressed ZIMAGE:
    F02D8870  historical GetChildCount provider
    F032ACDC  historical EnumerateChildIDs provider
    F02F9CCC  historical per-child metadata/resource provider

Goal:
    recover the provider call graph, globals and candidate backing data,
    then correlate those data regions with known resolver IDs:
        0x8313 / 0x8321 = Image Viewer aliases
        0x8928          = Audio Player

No candidate is promoted to Multimedia unless it is provider-backed.
"""

from pathlib import Path
from collections import deque, defaultdict
import hashlib
import struct
import sys

from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_LITTLE_ENDIAN
from capstone.arm import ARM_OP_IMM, ARM_OP_MEM, ARM_OP_REG, ARM_REG_PC

ROOT = Path.cwd()

ZIMAGE_PATH = ROOT / "research/f2/work/extracted/altice_platform/zimage.bin"
REPORT = ROOT / "research/f2/work/reports/s13_5a2_zimage_menu_provider_registry_audit.txt"

ZIMAGE_BASE = 0xF023CA50
ZIMAGE_SIZE = 0x185E98
ZIMAGE_SHA = "85fba8c8ae8161e4c1f8ced7983ec30d48c54ab10e51c69fcdfb900aca220954"

GET_CHILD_COUNT = 0xF02D8870
ENUM_CHILD_IDS  = 0xF032ACDC
GET_CHILD_META  = 0xF02F9CCC

PROVIDERS = {
    GET_CHILD_COUNT: "GET_CHILD_COUNT",
    ENUM_CHILD_IDS: "ENUM_CHILD_IDS",
    GET_CHILD_META: "GET_CHILD_META",
}

IMAGE_A = 0x8313
IMAGE_B = 0x8321
AUDIO = 0x8928

STATIC_RESOLVER_TABLE = 0xF0345E68
STATIC_RESOLVER_COUNT = 58
STATIC_RESOLVER_STRIDE = 8

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


def inside(addr, size=1):
    off = (addr & ~1) - ZIMAGE_BASE
    return 0 <= off and off + size <= len(Z)


def zoff(addr):
    return (addr & ~1) - ZIMAGE_BASE


def u16_at(addr):
    a = addr & ~1
    if not inside(a, 2):
        return None
    return struct.unpack_from("<H", Z, a - ZIMAGE_BASE)[0]


def u32_at(addr):
    a = addr & ~1
    if not inside(a, 4):
        return None
    return struct.unpack_from("<I", Z, a - ZIMAGE_BASE)[0]


def classify(value):
    nv = value & ~1
    if ZIMAGE_BASE <= nv < ZIMAGE_BASE + len(Z):
        return "ZIMAGE"
    if 0x10000000 <= value < 0x10100000:
        return "RAM/BSS_100x"
    if 0x10100000 <= value < 0x11000000:
        return "OTHER_FW_RUNTIME"
    if 0xF0000000 <= value < 0xF1000000:
        return "F0_REGION"
    if value < 0x10000:
        return "SMALL"
    return "OTHER"


def branch_target(insn):
    if insn.mnemonic not in (
        "bl", "blx", "b", "b.w",
        "beq", "bne", "bcc", "bcs", "bhi", "bls",
        "bgt", "blt", "bge", "ble", "bmi", "bpl"
    ):
        return None
    if not insn.operands:
        return None
    op = insn.operands[0]
    if op.type != ARM_OP_IMM:
        return None
    return op.imm & 0xFFFFFFFF


def pc_literal(insn):
    if not insn.mnemonic.startswith("ldr"):
        return None
    if len(insn.operands) < 2:
        return None
    src = insn.operands[1]
    if src.type != ARM_OP_MEM or src.mem.base != ARM_REG_PC:
        return None

    pc = (insn.address + 4) & ~3
    lit_addr = (pc + src.mem.disp) & 0xFFFFFFFF
    if not inside(lit_addr, 4):
        return None

    value = struct.unpack_from("<I", Z, (lit_addr & ~1) - ZIMAGE_BASE)[0]
    dst = None
    if insn.operands[0].type == ARM_OP_REG:
        dst = insn.reg_name(insn.operands[0].reg)
    return dst, lit_addr, value


def is_strong_return(insn):
    if insn.mnemonic == "bx" and insn.op_str.strip() == "lr":
        return True
    if insn.mnemonic == "pop" and "pc" in insn.op_str:
        return True
    return False


def disasm_functionish(entry, max_bytes=0x300, min_insns=5):
    """
    Bounded Thumb disassembly. Stop at the first strong return after a few
    instructions, but retain a small tail when the entry is a tiny wrapper.
    This is heuristic evidence, not a function-boundary oracle.
    """
    entry &= ~1
    require(inside(entry, 2), f"entry 0x{entry:08X} inside ZIMAGE")

    blob = Z[zoff(entry):min(len(Z), zoff(entry)+max_bytes)]
    out = []

    for insn in md.disasm(blob, entry):
        out.append(insn)
        if len(out) >= min_insns and is_strong_return(insn):
            break

    return out


def fmt(insn):
    notes = []

    bt = branch_target(insn)
    if bt is not None:
        notes.append(f"TARGET=0x{bt:08X} {classify(bt)}")

    lit = pc_literal(insn)
    if lit:
        dst, la, value = lit
        s = f"LITERAL[0x{la:08X}]=0x{value:08X} {classify(value)}"
        if dst:
            s += f" -> {dst}"
        if value in (IMAGE_A, IMAGE_B, AUDIO):
            s += " <KNOWN_APP_ID>"
        notes.append(s)

    suffix = " ; " + " ; ".join(notes) if notes else ""

    return (
        f"0x{insn.address:08X}: "
        f"{insn.bytes.hex(' '):<18} "
        f"{insn.mnemonic:<9} {insn.op_str:<36}"
        f"{suffix}"
    )


def summarize_function(entry, name):
    banner(f"{name} @0x{entry:08X}")

    insns = disasm_functionish(entry)
    for i in insns:
        print(fmt(i))

    calls = []
    literals = []

    for i in insns:
        if i.mnemonic in ("bl", "blx"):
            t = branch_target(i)
            if t is not None:
                calls.append((i.address, t))

        lit = pc_literal(i)
        if lit:
            literals.append((i.address, *lit))

    print()
    print("[SUMMARY]")
    print(f"instructions = {len(insns)}")
    print(f"direct calls = {len(calls)}")
    for site, target in calls:
        print(f"  call 0x{site:08X} -> 0x{target:08X} {classify(target)}")
    print(f"PC literals  = {len(literals)}")
    for site, dst, la, value in literals:
        print(
            f"  0x{site:08X}: {dst or '?'} <- "
            f"[0x{la:08X}] = 0x{value:08X} {classify(value)}"
        )

    return insns, calls, literals


def recursive_trace(root, root_name, max_depth=3):
    banner(f"RECURSIVE CALL TRACE FROM {root_name}")

    q = deque([(root & ~1, 0, root_name)])
    seen = set()
    nodes = {}
    collected_values = []

    while q:
        addr, depth, name = q.popleft()
        if addr in seen or not inside(addr, 2):
            continue
        seen.add(addr)

        try:
            insns = disasm_functionish(addr, max_bytes=0x280)
        except Exception as e:
            print(f"[WARN] cannot decode 0x{addr:08X}: {e}")
            continue

        calls = []
        literals = []

        for i in insns:
            if i.mnemonic in ("bl", "blx"):
                t = branch_target(i)
                if t is not None:
                    calls.append((i.address, t))
            lit = pc_literal(i)
            if lit:
                literals.append((i.address, *lit))
                collected_values.append(lit[2])

        nodes[addr] = {
            "depth": depth,
            "calls": calls,
            "literals": literals,
            "insn_count": len(insns),
        }

        print()
        print(f"[depth {depth}] 0x{addr:08X}  insns={len(insns)}")
        for site, t in calls:
            print(f"  CALL 0x{site:08X} -> 0x{t:08X} {classify(t)}")
        for site, dst, la, value in literals:
            print(
                f"  LIT  0x{site:08X}: {dst or '?'} "
                f"@0x{la:08X} = 0x{value:08X} {classify(value)}"
            )

        if depth < max_depth:
            for _, t in calls:
                nt = t & ~1
                if inside(nt, 2) and nt not in seen:
                    q.append((nt, depth + 1, f"callee_of_{addr:08X}"))

    print()
    print(f"unique ZIMAGE callgraph nodes = {len(nodes)}")
    return nodes, collected_values


def parse_resolver():
    off = STATIC_RESOLVER_TABLE - ZIMAGE_BASE
    require(off >= 0, "resolver table offset valid")
    require(
        off + STATIC_RESOLVER_COUNT * STATIC_RESOLVER_STRIDE <= len(Z),
        "resolver table fully inside ZIMAGE",
    )

    rows = []
    for i in range(STATIC_RESOLVER_COUNT):
        roff = off + i * STATIC_RESOLVER_STRIDE
        rid, field2, callback = struct.unpack_from("<HHI", Z, roff)
        rows.append({
            "index": i,
            "id": rid,
            "field2": field2,
            "callback": callback,
            "runtime": ZIMAGE_BASE + roff,
        })
    return rows


def bytes_window(addr, radius=0x80):
    addr &= ~1
    if not inside(addr, 1):
        return
    start = max(ZIMAGE_BASE, addr - radius)
    end = min(ZIMAGE_BASE + len(Z), addr + radius)

    for line in range(start & ~0xF, end, 0x10):
        o = line - ZIMAGE_BASE
        chunk = Z[o:min(o+0x10, len(Z))]
        printable = "".join(chr(b) if 32 <= b <= 126 else "." for b in chunk)
        mark = " <==" if line <= addr < line+0x10 else ""
        print(f"  0x{line:08X}: {chunk.hex(' '):<47} {printable}{mark}")


def pointer_backing_scan(values, resolver_ids):
    banner("PROVIDER-REACHABLE POINTER / BACKING-DATA SCAN")

    candidates = []

    direct_ptrs = sorted({
        v & ~1 for v in values if classify(v) == "ZIMAGE"
    })

    print(f"direct ZIMAGE pointer literals = {len(direct_ptrs)}")

    # Add one dereference level for pointer-to-pointer/global structures.
    ptrs = set(direct_ptrs)

    for p in direct_ptrs:
        v = u32_at(p)
        if v is not None and classify(v) == "ZIMAGE":
            ptrs.add(v & ~1)

    ptrs = sorted(ptrs)
    print(f"with one dereference level      = {len(ptrs)}")
    print()

    for p in ptrs:
        poff = p - ZIMAGE_BASE
        lo = max(0, poff - 0x400)
        hi = min(len(Z), poff + 0x400)
        blob = Z[lo:hi]

        hits = []
        for rid in resolver_ids:
            pat = struct.pack("<H", rid)
            pos = 0
            while True:
                k = blob.find(pat, pos)
                if k < 0:
                    break
                hits.append((ZIMAGE_BASE + lo + k, rid))
                pos = k + 1

        known = [(a, rid) for a, rid in hits if rid in (IMAGE_A, IMAGE_B, AUDIO)]
        distinct = len({rid for _, rid in hits})

        # Report strong regions, or anything containing known IDs.
        if known or distinct >= 4:
            score = distinct + 8 * len(known)
            candidates.append((score, p, hits, known))

    candidates.sort(reverse=True)

    for rank, (score, p, hits, known) in enumerate(candidates[:40], 1):
        print()
        print(f"#{rank:02d} pointer=0x{p:08X} score={score}")
        print(
            "  known: " +
            (", ".join(
                f"0x{rid:04X}@0x{a:08X}" for a, rid in known
            ) if known else "none")
        )
        uniq = []
        seen = set()
        for a, rid in sorted(hits):
            key = (a, rid)
            if key not in seen:
                seen.add(key)
                uniq.append((a, rid))
        print("  nearby resolver IDs:")
        for a, rid in uniq[:50]:
            tag = ""
            if rid == IMAGE_A:
                tag = " IMAGE_A"
            elif rid == IMAGE_B:
                tag = " IMAGE_B"
            elif rid == AUDIO:
                tag = " AUDIO"
            print(f"    0x{a:08X}: 0x{rid:04X}{tag}")
        bytes_window(p, 0x60)

    return candidates


def scan_u16_runs(resolver_ids):
    banner("RAW U16 RESOLVER-ID RUNS OUTSIDE THE RESOLVER TABLE")

    table_lo = STATIC_RESOLVER_TABLE - ZIMAGE_BASE
    table_hi = table_lo + STATIC_RESOLVER_COUNT * STATIC_RESOLVER_STRIDE

    runs = []
    n = len(Z) // 2

    i = 0
    while i < n:
        o = i * 2
        if table_lo <= o < table_hi:
            i += 1
            continue

        value = struct.unpack_from("<H", Z, o)[0]
        if value not in resolver_ids:
            i += 1
            continue

        start_i = i
        vals = []

        # Allow occasional zero/small metadata words but stop on sustained noise.
        misses = 0
        while i < n and (i - start_i) < 32:
            oo = i * 2
            if table_lo <= oo < table_hi:
                break
            v = struct.unpack_from("<H", Z, oo)[0]
            if v in resolver_ids:
                vals.append((oo, v))
                misses = 0
            elif v in (0, 1, 2, 3, 4):
                misses += 1
                if misses > 2:
                    break
            else:
                break
            i += 1

        distinct = {v for _, v in vals}
        if len(vals) >= 2:
            contains_known = bool(distinct & {IMAGE_A, IMAGE_B, AUDIO})
            score = len(distinct) + (8 if contains_known else 0)
            runs.append((score, vals))

        if i == start_i:
            i += 1

    runs.sort(reverse=True, key=lambda x: x[0])

    print(f"candidate runs = {len(runs)}")
    for rank, (score, vals) in enumerate(runs[:50], 1):
        ids = [v for _, v in vals]
        print(
            f"#{rank:02d} score={score} "
            f"start=0x{ZIMAGE_BASE+vals[0][0]:08X} "
            f"count={len(vals)} "
            f"ids=[{', '.join(f'0x{x:04X}' for x in ids)}]"
        )

    return runs


def direct_xrefs(target):
    hits = []
    for o in range(0, len(Z)-4, 2):
        insns = list(md.disasm(Z[o:o+4], ZIMAGE_BASE+o, count=1))
        if not insns:
            continue
        i = insns[0]
        if i.mnemonic not in ("bl", "blx"):
            continue
        if branch_target(i) == target:
            hits.append(i.address)
    return sorted(set(hits))


def xref_census():
    banner("DIRECT CALL XREF CENSUS")
    for addr, name in PROVIDERS.items():
        hits = direct_xrefs(addr)
        print(f"{name} 0x{addr:08X}: {len(hits)} direct call(s)")
        for h in hits[:100]:
            print(f"  0x{h:08X}")
        if len(hits) > 100:
            print(f"  ... {len(hits)-100} more")
        print()


def known_id_raw_context():
    banner("KNOWN ID RAW OCCURRENCE SUMMARY")
    for rid, name in (
        (IMAGE_A, "IMAGE_A"),
        (IMAGE_B, "IMAGE_B"),
        (AUDIO, "AUDIO"),
    ):
        pat = struct.pack("<H", rid)
        positions = []
        pos = 0
        while True:
            k = Z.find(pat, pos)
            if k < 0:
                break
            positions.append(k)
            pos = k + 1

        print(f"{name} 0x{rid:04X}: {len(positions)} raw U16 occurrence(s)")
        for k in positions[:50]:
            print(f"  ZIMAGE+0x{k:X} runtime=0x{ZIMAGE_BASE+k:08X}")
        if len(positions) > 50:
            print(f"  ... {len(positions)-50} more")
        print()


def main():
    global Z

    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")

    Z = ZIMAGE_PATH.read_bytes()

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
        banner("S13.5A.2 - ZIMAGE-ONLY MULTIMEDIA MENU PROVIDER / REGISTRY AUDIT")
        print("STRICTLY OFFLINE")
        print("PHONE ACCESSED       : NO")
        print("FLASH MODIFIED       : NO")
        print("PATCH GENERATED      : NO")
        print("LZMA RECOMPRESS      : NO")
        print("VIVA REPACK          : NO")
        print()

        require(len(Z) == ZIMAGE_SIZE, f"ZIMAGE size = 0x{ZIMAGE_SIZE:X}")
        require(sha256(Z) == ZIMAGE_SHA, "canonical ZIMAGE SHA256")

        banner("A. TARGET PROVIDERS ARE PHYSICALLY PRESENT IN CANONICAL ZIMAGE")
        for addr, name in PROVIDERS.items():
            require(inside(addr, 2), f"{name} 0x{addr:08X} inside ZIMAGE")
            print(f"  {name}: ZIMAGE+0x{addr-ZIMAGE_BASE:X}")

        rows = parse_resolver()
        resolver_ids = {r["id"] for r in rows}

        for rid, label in ((IMAGE_A, "IMAGE_A"), (IMAGE_B, "IMAGE_B"), (AUDIO, "AUDIO")):
            rr = [r for r in rows if r["id"] == rid]
            require(len(rr) == 1, f"{label} has exactly one resolver row")
            print(
                f"  {label} 0x{rid:04X} -> callback=0x{rr[0]['callback']:08X} "
                f"row@0x{rr[0]['runtime']:08X}"
            )

        all_values = []

        for addr, name in PROVIDERS.items():
            insns, calls, literals = summarize_function(addr, name)
            all_values.extend(v for _, _, _, v in literals)

        xref_census()

        for addr, name in PROVIDERS.items():
            nodes, values = recursive_trace(addr, name, max_depth=3)
            all_values.extend(values)

        pointer_candidates = pointer_backing_scan(all_values, resolver_ids)
        runs = scan_u16_runs(resolver_ids)
        known_id_raw_context()

        banner("S13.5A.2 DECISION GATE")
        print("Interpret the report in this order:")
        print("  1. Determine whether F02D8870 and F032ACDC converge on the same helper/global.")
        print("  2. Promote only globals/tables that are reachable from those providers.")
        print("  3. Search those provider-backed regions for 0x8313 / 0x8321 and other resolver IDs.")
        print("  4. Identify the concrete parent -> children relation before calling anything Multimedia.")
        print("  5. Check whether 0x8928 is already in the same structure but filtered/disabled.")
        print()
        print("Raw U16 runs are supporting evidence only; they are NOT sufficient alone.")
        print()
        print(f"provider-backed pointer candidates = {len(pointer_candidates)}")
        print(f"raw resolver-ID runs              = {len(runs)}")
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
