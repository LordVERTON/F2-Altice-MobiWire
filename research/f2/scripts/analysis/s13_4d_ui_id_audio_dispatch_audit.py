#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
S13.4D - UI ID / static resolver comparison
READ-ONLY / OFFLINE ONLY.

Purpose:
  - compare known Image Viewer IDs 0x8313 / 0x8321 with Audio ID 0x8928
  - inspect the established static resolver table at F0345E68
  - compare Image callback F02F3F85 with Audio callback 1033D841
  - find real code sites materializing these IDs (MOVW / PC literal)
  - show nearby calls, especially the established dispatcher path

No handset access.
No firmware write.
No patch generation.
"""

from pathlib import Path
import hashlib
import struct
import sys

from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_LITTLE_ENDIAN
from capstone.arm import ARM_OP_IMM, ARM_OP_MEM, ARM_OP_REG, ARM_REG_PC

ROOT = Path.cwd()

ALICE = ROOT / "research/f2/work/extracted/altice_alice/alice-py.bin"
ZIMAGE = ROOT / "research/f2/work/extracted/altice_platform/zimage.bin"

ALICE_BASE = 0x1024EC00
ZIMAGE_BASE = 0xF023CA50

ALICE_SIZE = 0x157BB4
ALICE_SHA = "7246242b67afae0d13104452bc3257827cb778119b54e7a26fb7fb55993697ea"
ZIMAGE_SHA = "85fba8c8ae8161e4c1f8ced7983ec30d48c54ab10e51c69fcdfb900aca220954"

TABLE = 0xF0345E68
TABLE_COUNT = 58
TABLE_STRIDE = 8

IDS = {
    0x8313: "IMAGE_A",
    0x8321: "IMAGE_B",
    0x8928: "AUDIO",
}

KNOWN = {
    0xF02F3F84: "Image Viewer callback",
    0xF02F3F85: "Image Viewer callback Thumb",
    0x1033D840: "Audio registration callback",
    0x1033D841: "Audio registration callback Thumb",
    0x1033E814: "Audio init wrapper",
    0x1033E815: "Audio init wrapper Thumb",
    0x10336788: "ID resolver/callback dispatcher",
    0x10336789: "ID resolver/callback dispatcher Thumb",
    0x1034C7E4: "dynamic/static resolver",
    0x102D9DC8: "global dispatcher bridge",
    0xF0316D74: "static resolver",
    0xF0316D75: "static resolver Thumb",
}

INTERESTING_CALLS = {
    0x10336788,
    0x10336789,
    0x1034C7E4,
    0x102D9DC8,
    0xF0316D74,
    0xF0316D75,
    0xF02F3F84,
    0xF02F3F85,
    0x1033D840,
    0x1033D841,
}

OUT = ROOT / "research/f2/work/reports/s13_4d_ui_id_audio_dispatch_audit.txt"

md = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_LITTLE_ENDIAN)
md.detail = True


def sha256(b):
    return hashlib.sha256(b).hexdigest()


def banner(s):
    print()
    print("=" * 120)
    print(s)
    print("=" * 120)


def norm(x):
    return x & ~1


def known(x):
    return KNOWN.get(x) or KNOWN.get(norm(x))


def inside(data, base, addr, size=1):
    off = addr - base
    return 0 <= off and off + size <= len(data)


def u32(data, base, addr):
    if not inside(data, base, addr, 4):
        return None
    return struct.unpack_from("<I", data, addr - base)[0]


def branch_target(insn):
    if insn.mnemonic not in (
        "bl", "blx", "b", "b.w", "beq", "bne",
        "bcc", "bcs", "bhi", "bls", "bgt", "blt", "bge", "ble"
    ):
        return None
    if not insn.operands or insn.operands[0].type != ARM_OP_IMM:
        return None
    return insn.operands[0].imm & 0xFFFFFFFF


def pc_literal(insn, data, base):
    if not insn.mnemonic.startswith("ldr"):
        return None
    if len(insn.operands) < 2:
        return None
    src = insn.operands[1]
    if src.type != ARM_OP_MEM or src.mem.base != ARM_REG_PC:
        return None
    pc = (insn.address + 4) & ~3
    addr = (pc + src.mem.disp) & 0xFFFFFFFF
    value = u32(data, base, addr)
    if value is None:
        return None
    dst = None
    if insn.operands[0].type == ARM_OP_REG:
        dst = insn.reg_name(insn.operands[0].reg)
    return dst, addr, value


def fmt(insn, data, base):
    comments = []

    bt = branch_target(insn)
    if bt is not None:
        s = f"TARGET=0x{bt:08X}"
        n = known(bt)
        if n:
            s += f" <{n}>"
        comments.append(s)

    lit = pc_literal(insn, data, base)
    if lit:
        dst, addr, value = lit
        s = f"LITERAL[0x{addr:08X}]=0x{value:08X}"
        if dst:
            s += f" -> {dst}"
        if value in IDS:
            s += f" <ID {IDS[value]}>"
        n = known(value)
        if n:
            s += f" <{n}>"
        comments.append(s)

    if insn.mnemonic == "movw" and len(insn.operands) >= 2:
        op = insn.operands[1]
        if op.type == ARM_OP_IMM:
            v = op.imm & 0xFFFF
            if v in IDS:
                comments.append(f"IMM=0x{v:04X} <ID {IDS[v]}>")

    suffix = ""
    if comments:
        suffix = " ; " + " ; ".join(comments)

    return (
        f"0x{insn.address:08X}: "
        f"{insn.bytes.hex(' '):<16} "
        f"{insn.mnemonic:<9} "
        f"{insn.op_str:<36}"
        f"{suffix}"
    )


def disasm_window(title, data, base, center, before=0x30, after=0x70):
    banner(title)
    start = max(base, center - before)
    start &= ~1
    end = min(base + len(data), center + after)
    blob = data[start - base:end - base]
    for insn in md.disasm(blob, start):
        marker = ">>> " if insn.address == center else "    "
        print(marker + fmt(insn, data, base))


def decode_one(data, base, off):
    if off < 0 or off + 2 > len(data):
        return None
    items = list(md.disasm(data[off:off + 4], base + off, count=1))
    return items[0] if items else None


def scan_id_materializers(label, data, base):
    hits = []

    for off in range(0, len(data) - 4, 2):
        insn = decode_one(data, base, off)
        if insn is None:
            continue

        if insn.mnemonic == "movw" and len(insn.operands) >= 2:
            op = insn.operands[1]
            if op.type == ARM_OP_IMM:
                v = op.imm & 0xFFFF
                if v in IDS:
                    hits.append((insn.address, "MOVW", v, None))

        lit = pc_literal(insn, data, base)
        if lit is not None:
            dst, addr, value = lit
            if value in IDS:
                hits.append((insn.address, "LDR_LITERAL", value, addr))

    uniq = []
    seen = set()
    for x in hits:
        k = (x[0], x[1], x[2])
        if k not in seen:
            seen.add(k)
            uniq.append(x)

    banner(f"{label} - REAL CODE MATERIALIZERS OF IMAGE/AUDIO IDs")
    for target_id, name in IDS.items():
        subset = [x for x in uniq if x[2] == target_id]
        print()
        print(f"{name} 0x{target_id:04X}: {len(subset)} code materializer(s)")
        for addr, kind, _, litaddr in subset:
            extra = f" literal@0x{litaddr:08X}" if litaddr is not None else ""
            print(f"  0x{addr:08X} {kind}{extra}")

    return uniq


def nearby_calls(data, base, start_addr, length=0x70):
    start = start_addr & ~1
    if not inside(data, base, start, 2):
        return []
    end = min(base + len(data), start + length)
    out = []
    for insn in md.disasm(data[start-base:end-base], start):
        if insn.mnemonic not in ("bl", "blx"):
            continue
        t = branch_target(insn)
        if t is None:
            continue
        out.append((insn.address, t))
    return out


def report_materializer_context(label, data, base, hits):
    interesting_norm = {norm(x) for x in INTERESTING_CALLS}
    for addr, kind, target_id, litaddr in hits:
        name = IDS[target_id]
        banner(
            f"{label} {name} 0x{target_id:04X} MATERIALIZER "
            f"@0x{addr:08X} ({kind})"
        )

        start = max(base, (addr - 0x28) & ~1)
        end = min(base + len(data), addr + 0x70)

        for insn in md.disasm(data[start-base:end-base], start):
            marker = ">>> " if insn.address == addr else "    "
            print(marker + fmt(insn, data, base))

        calls = nearby_calls(data, base, addr, 0x70)
        if calls:
            print("  Calls after materializer:")
            for ca, dst in calls:
                tag = known(dst)
                flag = " <INTERESTING>" if norm(dst) in interesting_norm else ""
                print(
                    f"    0x{ca:08X} -> 0x{dst:08X}"
                    + (f" <{tag}>" if tag else "")
                    + flag
                )


def static_table(zimage):
    banner("STATIC RESOLVER TABLE @ F0345E68")

    off = TABLE - ZIMAGE_BASE
    if off < 0 or off + TABLE_COUNT * TABLE_STRIDE > len(zimage):
        raise RuntimeError("static table outside ZIMAGE")

    target_rows = {}

    print("Assumed record view: <u16 id, u16 field2, u32 callback>")
    print(f"COUNT={TABLE_COUNT} STRIDE={TABLE_STRIDE}")
    print()

    for i in range(TABLE_COUNT):
        roff = off + i * TABLE_STRIDE
        rid, field2, cb = struct.unpack_from("<HHI", zimage, roff)
        runtime = ZIMAGE_BASE + roff
        if rid in IDS:
            target_rows.setdefault(rid, []).append((i, runtime, field2, cb))

    for rid, name in IDS.items():
        rows = target_rows.get(rid, [])
        print(f"{name} 0x{rid:04X}: {len(rows)} row(s)")
        for i, runtime, field2, cb in rows:
            print(
                f"  row={i:02d} addr=0x{runtime:08X} "
                f"field2=0x{field2:04X} callback=0x{cb:08X}"
                + (f" <{known(cb)}>" if known(cb) else "")
            )
            raw = zimage[runtime-ZIMAGE_BASE:runtime-ZIMAGE_BASE+8]
            print(f"  raw={raw.hex(' ')}")
        print()

    print("Exact callback pointer positions inside table:")
    for cb in (0xF02F3F85, 0x1033D841):
        positions = []
        p = struct.pack("<I", cb)
        region = zimage[off:off + TABLE_COUNT * TABLE_STRIDE]
        pos = 0
        while True:
            k = region.find(p, pos)
            if k < 0:
                break
            positions.append(TABLE + k)
            pos = k + 1
        print(
            f"  0x{cb:08X} <{known(cb)}> count={len(positions)} "
            + " ".join(f"@0x{x:08X}" for x in positions)
        )

    return target_rows


def callback_compare(alice, zimage):
    disasm_window(
        "IMAGE CALLBACK F02F3F84",
        zimage, ZIMAGE_BASE, 0xF02F3F84, 0x10, 0x70
    )
    disasm_window(
        "AUDIO CALLBACK 1033D840",
        alice, ALICE_BASE, 0x1033D840, 0x10, 0x70
    )
    disasm_window(
        "AUDIO INIT WRAPPER 1033E814",
        alice, ALICE_BASE, 0x1033E814, 0x10, 0x60
    )


def raw_id_occurrences(label, data, base):
    banner(f"{label} - RAW U16 OCCURRENCES (lead only)")
    for rid, name in IDS.items():
        p = struct.pack("<H", rid)
        pos = 0
        arr = []
        while True:
            pos = data.find(p, pos)
            if pos < 0:
                break
            arr.append(pos)
            pos += 1
        print(f"{name} 0x{rid:04X}: {len(arr)} raw U16 occurrence(s)")
        for x in arr[:30]:
            print(f"  FILE+0x{x:06X} runtime=0x{base+x:08X}")
        if len(arr) > 30:
            print(f"  ... {len(arr)-30} more")


def main():
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")

    alice = ALICE.read_bytes()
    zimage = ZIMAGE.read_bytes()

    OUT.parent.mkdir(parents=True, exist_ok=True)
    f = OUT.open("w", encoding="utf-8")
    old = sys.stdout

    class Tee:
        def __init__(self, *streams):
            self.streams = streams
        def write(self, s):
            for x in self.streams:
                x.write(s)
            return len(s)
        def flush(self):
            for x in self.streams:
                x.flush()

    sys.stdout = Tee(old, f)

    try:
        banner("S13.4D - UI ID / AUDIO DISPATCH AUDIT")
        print("READ-ONLY / OFFLINE")
        print("PHONE ACCESSED : NO")
        print("FLASH MODIFIED : NO")
        print()

        print(f"ALICE size=0x{len(alice):X} sha256={sha256(alice)}")
        print(f"ZIMAGE size=0x{len(zimage):X} sha256={sha256(zimage)}")

        if len(alice) != ALICE_SIZE:
            raise RuntimeError("ALICE size mismatch")
        if sha256(alice) != ALICE_SHA:
            raise RuntimeError("ALICE SHA mismatch")
        if sha256(zimage) != ZIMAGE_SHA:
            raise RuntimeError("ZIMAGE SHA mismatch")

        print("[PASS] canonical ALICE + ZIMAGE")

        rows = static_table(zimage)
        callback_compare(alice, zimage)

        ahits = scan_id_materializers("ALICE", alice, ALICE_BASE)
        zhits = scan_id_materializers("ZIMAGE", zimage, ZIMAGE_BASE)

        report_materializer_context("ALICE", alice, ALICE_BASE, ahits)
        report_materializer_context("ZIMAGE", zimage, ZIMAGE_BASE, zhits)

        raw_id_occurrences("ALICE", alice, ALICE_BASE)
        raw_id_occurrences("ZIMAGE", zimage, ZIMAGE_BASE)

        banner("S13.4D DECISION INPUTS")

        for rid, name in IDS.items():
            r = rows.get(rid, [])
            if not r:
                print(f"{name}: no row under <HHI> table interpretation")
            else:
                cbs = ", ".join(f"0x{x[3]:08X}" for x in r)
                print(f"{name}: table callback(s) {cbs}")

        print()
        print("Questions to answer from this output:")
        print("Q1. Do 0x8313/0x8321 and 0x8928 share the same 8-byte resolver-record format?")
        print("Q2. Which Image ID maps to F02F3F85, and does 0x8928 map to 1033D841?")
        print("Q3. Is there a real code site that materializes an Image ID immediately before the known dispatcher?")
        print("Q4. Can that producer be used as a user-trigger POC instead of the disproven 10355888 hook?")
        print()
        print("NO PATCH GENERATED.")
        print("NO HANDSET I/O.")
        print(f"REPORT = {OUT}")

    finally:
        sys.stdout = old
        f.close()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
