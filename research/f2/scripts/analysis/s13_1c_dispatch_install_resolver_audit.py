#!/usr/bin/env python3

from pathlib import Path
import hashlib
import struct

from capstone import (
    Cs,
    CS_ARCH_ARM,
    CS_MODE_THUMB,
    CS_MODE_LITTLE_ENDIAN,
)
from capstone.arm import (
    ARM_OP_IMM,
    ARM_OP_MEM,
    ARM_OP_REG,
    ARM_REG_PC,
)

BASE = 0x1024EC00

ALICE = (
    Path.cwd()
    / "research/f2/work/extracted/altice_alice/alice-py.bin"
)

EXPECTED_SHA = (
    "7246242b67afae0d13104452bc3257827"
    "cb778119b54e7a26fb7fb55993697ea"
)

EXPECTED_SIZE = 0x157BB4

FOCUS = [
    (
        "A - 10336F84 suspected global dispatcher installer",
        0x10336F60,
        0x90,
    ),
    (
        "B - second F00EF124 consumer around 1036B3C0",
        0x1036B390,
        0x90,
    ),
    (
        "C - 1034C7E4 dynamic/static resolver",
        0x1034C780,
        0x180,
    ),
    (
        "D - F0316D75 static resolver pointer owner",
        0x102FA4C0,
        0xC0,
    ),
    (
        "E - dispatcher installer caller",
        0x10332AE0,
        0x60,
    ),
]

TARGETS = {
    0x10336F84: "dispatcher setter",
    0x1034C7E4: "dynamic/static resolver",
    0xF0316D74: "static resolver",
    0xF0316D75: "static resolver Thumb",
    0xF00EF124: "global dispatcher slot",
    0x10336788: "dispatcher",
    0x10336789: "dispatcher Thumb",
}

md = Cs(
    CS_ARCH_ARM,
    CS_MODE_THUMB | CS_MODE_LITTLE_ENDIAN,
)
md.detail = True


def sha256(b):
    return hashlib.sha256(b).hexdigest()


def u32(data, addr):
    off = addr - BASE

    if off < 0 or off + 4 > len(data):
        return None

    return struct.unpack_from("<I", data, off)[0]


def branch_target(insn):
    if insn.mnemonic not in ("bl", "blx", "b", "b.w"):
        return None

    if not insn.operands:
        return None

    if insn.operands[0].type != ARM_OP_IMM:
        return None

    return insn.operands[0].imm & 0xFFFFFFFF


def literal(insn, data):
    if not insn.mnemonic.startswith("ldr"):
        return None

    if len(insn.operands) < 2:
        return None

    op = insn.operands[1]

    if op.type != ARM_OP_MEM:
        return None

    if op.mem.base != ARM_REG_PC:
        return None

    pc = (insn.address + 4) & ~3
    addr = (pc + op.mem.disp) & 0xFFFFFFFF
    value = u32(data, addr)

    if value is None:
        return None

    dst = None

    if insn.operands[0].type == ARM_OP_REG:
        dst = insn.reg_name(insn.operands[0].reg)

    return dst, addr, value


def name(v):
    return TARGETS.get(v) or TARGETS.get(v & ~1)


def fmt(insn, data):
    comments = []

    target = branch_target(insn)

    if target is not None:
        s = f"TARGET=0x{target:08X}"
        n = name(target)

        if n:
            s += f" <{n}>"

        comments.append(s)

    lit = literal(insn, data)

    if lit:
        dst, addr, value = lit

        s = (
            f"LITERAL[0x{addr:08X}]"
            f"=0x{value:08X}"
        )

        if dst:
            s += f" -> {dst}"

        n = name(value)

        if n:
            s += f" <{n}>"

        comments.append(s)

    suffix = ""

    if comments:
        suffix = " ; " + " ; ".join(comments)

    return (
        f"0x{insn.address:08X}: "
        f"{insn.bytes.hex(' '):<14} "
        f"{insn.mnemonic:<9} "
        f"{insn.op_str:<32}"
        f"{suffix}"
    )


def disasm(data, title, start, size):
    print()
    print("=" * 118)
    print(title)
    print("=" * 118)

    off = start - BASE

    blob = data[off:off + size]

    for insn in md.disasm(blob, start):
        print(fmt(insn, data))


def decode_at(data, off):
    blob = data[off:off + 4]

    x = list(
        md.disasm(
            blob,
            BASE + off,
            count=1,
        )
    )

    return x[0] if x else None


def direct_callers(data, target):
    target &= ~1
    hits = []
    seen = set()

    for off in range(0, len(data) - 4, 2):
        insn = decode_at(data, off)

        if insn is None:
            continue

        if insn.mnemonic not in ("bl", "blx"):
            continue

        dst = branch_target(insn)

        if dst is None:
            continue

        if (dst & ~1) != target:
            continue

        if insn.address in seen:
            continue

        seen.add(insn.address)
        hits.append(insn.address)

    return hits


def pointer_hits(data, value):
    p = struct.pack("<I", value)
    out = []
    pos = 0

    while True:
        pos = data.find(p, pos)

        if pos < 0:
            break

        out.append(pos)
        pos += 1

    return out


def main():
    data = ALICE.read_bytes()

    digest = sha256(data)

    print("=" * 118)
    print("S13.1c - DISPATCH INSTALL + RESOLVER AUDIT")
    print("=" * 118)

    print(f"ALICE  = {ALICE}")
    print(f"SIZE   = 0x{len(data):X}")
    print(f"SHA256 = {digest}")

    if len(data) != EXPECTED_SIZE:
        raise SystemExit("ABORT: ALICE size mismatch")

    if digest != EXPECTED_SHA:
        raise SystemExit("ABORT: ALICE hash mismatch")

    print("[PASS] canonical ALICE")

    for title, start, size in FOCUS:
        disasm(
            data,
            title,
            start,
            size,
        )

    print()
    print("=" * 118)
    print("DIRECT CALLERS")
    print("=" * 118)

    for target in (
        0x10336F84,
        0x1034C7E4,
    ):
        hits = direct_callers(
            data,
            target,
        )

        print()
        print(
            f"0x{target:08X} "
            f"<{name(target)}>"
        )
        print(f"COUNT = {len(hits)}")

        for addr in hits:
            print(
                f"  runtime=0x{addr:08X} "
                f"FILE+0x{addr - BASE:X}"
            )

    print()
    print("=" * 118)
    print("EXACT POINTER REFERENCES")
    print("=" * 118)

    for value in (
        0xF00EF124,
        0x10336789,
        0xF0316D75,
    ):
        print()
        print(
            f"0x{value:08X} "
            f"<{name(value)}>"
        )

        for off in pointer_hits(data, value):
            print(
                f"  FILE+0x{off:06X} "
                f"runtime=0x{BASE + off:08X}"
            )

    print()
    print("=" * 118)
    print("S13.1c QUESTIONS")
    print("=" * 118)

    print(
        "Q1: Does 0x10336F84 perform "
        "[F00EF124] = r0 ?"
    )
    print(
        "Q2: Does 0x10332AF8 therefore install "
        "0x10336789 as the global dispatcher?"
    )
    print(
        "Q3: What exact lookup key does "
        "0x1034C7E4 consume?"
    )
    print(
        "Q4: Where does 0x1034C7E4 obtain its "
        "static fallback?"
    )
    print(
        "Q5: Does its return value represent "
        "the callable application callback?"
    )

    print()
    print("No patch generated.")
    print("No handset I/O performed.")


if __name__ == "__main__":
    main()
