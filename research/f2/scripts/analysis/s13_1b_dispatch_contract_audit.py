#!/usr/bin/env python3

"""
S13.1b - dispatcher / launcher call-contract audit

READ-ONLY / OFFLINE.

Focus:
    0x10336788  ID resolver / callback dispatcher
    0x10332AF8  dispatcher-global installer
    0x102D9DC8  ctx/ID global-dispatch bridge
    0x1037E21E  only direct caller of 0x102D9DC8 found by S13.1
    0x102F37D6  other direct caller of 0x1034C7E4
    0x10319094  consumer of literal 0x8928 in the now-classified ALICE cluster

Goals:
  - recover exact register/stack contract around 102D9DC8
  - recover exact behavior of 10336788
  - verify how 10336789 is installed
  - recover r0/r1/r2/r3 immediately before 1037E21E -> 102D9DC8
  - classify 10319094 enough to close the 103661xx branch
  - find literal references to F00EF124 / 10336789 / dispatcher targets

No patching.
No handset I/O.
"""

from pathlib import Path
import hashlib
import struct
import sys

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

ROOT = Path.cwd()

ALICE = (
    ROOT
    / "research/f2/work/extracted/altice_alice/alice-py.bin"
)

BASE = 0x1024EC00

EXPECTED_SHA = (
    "7246242b67afae0d13104452bc3257827"
    "cb778119b54e7a26fb7fb55993697ea"
)

EXPECTED_SIZE = 0x157BB4

KNOWN = {
    0x102D9DC8: "global dispatcher bridge",
    0x10336788: "ID resolver/callback dispatcher",
    0x10336789: "ID resolver/callback dispatcher Thumb",
    0x10332AF8: "dispatcher-global installer",
    0x1034C7E4: "dynamic lookup + static fallback",
    0xF0316D74: "static registration resolver",
    0xF0316D75: "static registration resolver Thumb",
    0xF00EF124: "dispatcher global slot",
    0x1037E21E: "known direct callsite -> 102D9DC8",
    0x102F37D6: "resolver caller",
    0x10319094: "0x8928 consumer",
    0x10366100: "0x8928 xref",
    0x10366122: "0x8928-derived +0x1E path",
    0x10366136: "0x8928-derived -0x0D path",
}

FOCUS_RANGES = [
    (
        "A — 102D9DC8 global dispatcher bridge",
        0x102D9D80,
        0x140,
    ),
    (
        "B — 10336788 resolver/callback dispatcher",
        0x10336760,
        0x100,
    ),
    (
        "C — 10332AF8 dispatcher installer",
        0x10332AC0,
        0xA0,
    ),
    (
        "D — 1037E21E caller of 102D9DC8",
        0x1037E1B0,
        0x100,
    ),
    (
        "E — 102F37D6 caller of 1034C7E4",
        0x102F3780,
        0xC0,
    ),
    (
        "F — 10319094 0x8928 consumer",
        0x10319060,
        0xC0,
    ),
    (
        "G — 103660C8 0x8928-family owner",
        0x103660C8,
        0xA0,
    ),
]

CALL_TARGETS = {
    0x102D9DC8,
    0x10336788,
    0x1034C7E4,
    0x10319094,
}

RAW_POINTER_TARGETS = [
    0x10336788,
    0x10336789,
    0x102D9DC8,
    0x1034C7E4,
    0xF0316D74,
    0xF0316D75,
    0xF00EF124,
]

md = Cs(
    CS_ARCH_ARM,
    CS_MODE_THUMB | CS_MODE_LITTLE_ENDIAN,
)
md.detail = True


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def norm(x):
    return x & ~1


def name(addr):
    a = norm(addr)

    for k, v in KNOWN.items():
        if norm(k) == a:
            return v

    return None


def inside(data, addr, size=1):
    off = addr - BASE
    return 0 <= off and off + size <= len(data)


def u32(data, addr):
    if not inside(data, addr, 4):
        return None

    return struct.unpack_from(
        "<I",
        data,
        addr - BASE,
    )[0]


def banner(title):
    print()
    print("=" * 120)
    print(title)
    print("=" * 120)


def branch_target(insn):
    if insn.mnemonic not in (
        "bl",
        "blx",
        "b",
        "b.w",
        "beq",
        "bne",
        "bcc",
        "bcs",
        "bhi",
        "bls",
        "bgt",
        "blt",
        "bge",
        "ble",
    ):
        return None

    if not insn.operands:
        return None

    if insn.operands[0].type != ARM_OP_IMM:
        return None

    return insn.operands[0].imm & 0xFFFFFFFF


def pc_literal(insn, data):
    if not insn.mnemonic.startswith("ldr"):
        return None

    if len(insn.operands) < 2:
        return None

    src = insn.operands[1]

    if src.type != ARM_OP_MEM:
        return None

    if src.mem.base != ARM_REG_PC:
        return None

    pc = (insn.address + 4) & ~3
    addr = (pc + src.mem.disp) & 0xFFFFFFFF

    value = u32(data, addr)

    if value is None:
        return None

    dst = None

    if insn.operands[0].type == ARM_OP_REG:
        dst = insn.reg_name(
            insn.operands[0].reg
        )

    return dst, addr, value


def fmt(insn, data):
    comments = []

    target = branch_target(insn)

    if target is not None:
        txt = f"TARGET=0x{target:08X}"

        n = name(target)
        if n:
            txt += f" <{n}>"

        comments.append(txt)

    lit = pc_literal(insn, data)

    if lit is not None:
        dst, addr, value = lit

        txt = (
            f"LITERAL[0x{addr:08X}]"
            f"=0x{value:08X}"
        )

        if dst:
            txt += f" -> {dst}"

        n = name(value)
        if n:
            txt += f" <{n}>"

        if value == 0x8928:
            txt += " <0x8928>"

        comments.append(txt)

    suffix = ""

    if comments:
        suffix = " ; " + " ; ".join(comments)

    return (
        f"0x{insn.address:08X}: "
        f"{insn.bytes.hex(' '):<14} "
        f"{insn.mnemonic:<9} "
        f"{insn.op_str:<35}"
        f"{suffix}"
    )


def disasm_range(data, title, start, size):
    banner(title)

    off = start - BASE

    if off < 0 or off + size > len(data):
        print("ERROR: range outside ALICE")
        return

    blob = data[off:off + size]

    for insn in md.disasm(blob, start):
        marker = "   "

        if insn.address in KNOWN:
            marker = ">>>"

        print(
            marker,
            fmt(insn, data),
        )


def decode_one(data, off):
    if off < 0 or off + 2 > len(data):
        return None

    blob = data[off:off + 4]

    items = list(
        md.disasm(
            blob,
            BASE + off,
            count=1,
        )
    )

    return items[0] if items else None


def direct_call_xrefs(data, target):
    wanted = norm(target)
    hits = []
    seen = set()

    for off in range(
        0,
        len(data) - 4,
        2,
    ):
        insn = decode_one(data, off)

        if insn is None:
            continue

        if insn.mnemonic not in ("bl", "blx"):
            continue

        dest = branch_target(insn)

        if dest is None:
            continue

        if norm(dest) != wanted:
            continue

        if insn.address in seen:
            continue

        seen.add(insn.address)
        hits.append(insn)

    return hits


def context_around(data, address, before=0x30, after=0x30):
    start = max(
        BASE,
        (address - before) & ~1,
    )

    end = min(
        BASE + len(data),
        address + after,
    )

    blob = data[
        start - BASE:
        end - BASE
    ]

    for insn in md.disasm(blob, start):
        marker = ">>> " if insn.address == address else "    "

        print(
            marker
            + fmt(insn, data)
        )


def raw_pointer_hits(data, value):
    pattern = struct.pack("<I", value)

    hits = []
    pos = 0

    while True:
        pos = data.find(pattern, pos)

        if pos < 0:
            break

        hits.append(pos)
        pos += 1

    return hits


def find_blx_registers(data, start, size):
    banner(
        f"INDIRECT BLX REGISTER CALLS "
        f"0x{start:08X}..0x{start+size:08X}"
    )

    off = start - BASE
    blob = data[off:off + size]

    for insn in md.disasm(blob, start):
        if insn.mnemonic != "blx":
            continue

        if not insn.operands:
            continue

        if insn.operands[0].type != ARM_OP_REG:
            continue

        print(
            ">>>",
            fmt(insn, data),
        )


def main():
    banner(
        "S13.1b — DISPATCH CONTRACT AUDIT"
    )

    if not ALICE.exists():
        print("ERROR: missing", ALICE)
        return 2

    data = ALICE.read_bytes()

    digest = sha256(data)

    print(f"FILE   = {ALICE}")
    print(f"SIZE   = 0x{len(data):X}")
    print(f"SHA256 = {digest}")

    if len(data) != EXPECTED_SIZE:
        print("ERROR: ALICE size mismatch")
        return 3

    if digest != EXPECTED_SHA:
        print("ERROR: ALICE SHA mismatch")
        return 4

    print("[PASS] canonical ALICE")

    #
    # Exact focused disassembly.
    #
    for title, start, size in FOCUS_RANGES:
        disasm_range(
            data,
            title,
            start,
            size,
        )

    #
    # Direct call xrefs.
    #
    banner("DIRECT CALLERS OF TARGET FUNCTIONS")

    for target in sorted(CALL_TARGETS):
        hits = direct_call_xrefs(
            data,
            target,
        )

        print()
        print(
            f"TARGET 0x{target:08X} "
            f"<{name(target) or 'unknown'}>"
        )

        print(f"CALLERS = {len(hits)}")

        for insn in hits:
            print(
                f"  0x{insn.address:08X} "
                f"FILE+0x{insn.address - BASE:X}"
            )

    #
    # Detailed contexts for each direct caller.
    #
    for target in (
        0x102D9DC8,
        0x1034C7E4,
        0x10319094,
    ):
        hits = direct_call_xrefs(
            data,
            target,
        )

        for insn in hits:
            banner(
                f"CALLSITE CONTEXT "
                f"0x{insn.address:08X} "
                f"-> 0x{target:08X}"
            )

            context_around(
                data,
                insn.address,
                before=0x40,
                after=0x30,
            )

    #
    # Raw pointer literals.
    #
    banner("RAW 32-BIT POINTER REFERENCES")

    for value in RAW_POINTER_TARGETS:
        hits = raw_pointer_hits(
            data,
            value,
        )

        print()
        print(
            f"0x{value:08X} "
            f"<{name(value) or 'target'}>"
        )

        if not hits:
            print("  none")
            continue

        for off in hits:
            print(
                f"  FILE+0x{off:06X} "
                f"runtime=0x{BASE + off:08X}"
            )

    #
    # Function pointer / register calls around the global dispatcher.
    #
    find_blx_registers(
        data,
        0x102D9D80,
        0x140,
    )

    find_blx_registers(
        data,
        0x10336760,
        0x100,
    )

    find_blx_registers(
        data,
        0x1037E1B0,
        0x100,
    )

    banner("S13.1b DECISION CHECKLIST")

    print(
        "Questions to answer from this report:"
    )
    print(
        "  Q1. At 0x1037E21E, which register carries the ID?"
    )
    print(
        "  Q2. Which register carries ctx into 0x102D9DC8?"
    )
    print(
        "  Q3. Does 0x102D9DC8 load F00EF124 and BLX it?"
    )
    print(
        "  Q4. Does 0x10336788 accept the ID in r0 or another register?"
    )
    print(
        "  Q5. What value is forwarded to 0x1034C7E4?"
    )
    print(
        "  Q6. Which register is used for the final callback BLX?"
    )
    print(
        "  Q7. Is 0x10319094 merely a mapping/query function rather than launch?"
    )

    print()
    print(
        "No patch generated."
    )
    print(
        "No handset I/O performed."
    )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
