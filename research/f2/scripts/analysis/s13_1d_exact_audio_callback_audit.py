#!/usr/bin/env python3

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

ALICE_PATH = (
    ROOT /
    "research/f2/work/extracted/altice_alice/alice-py.bin"
)

ZIMAGE_PATH = (
    ROOT /
    "research/f2/work/extracted/altice_platform/zimage.bin"
)

ALICE_BASE = 0x1024EC00
ZIMAGE_BASE = 0xF023CA50

ALICE_SHA = (
    "7246242b67afae0d13104452bc3257827"
    "cb778119b54e7a26fb7fb55993697ea"
)

ZIMAGE_SHA = (
    "85fba8c8ae8161e4c1f8ced7983ec30"
    "d48c54ab10e51c69fcdfb900aca220954"
)

ALICE_SIZE = 0x157BB4

TARGET_ID = 0x8928

KNOWN = {
    0x10336F84: "dispatcher setter",
    0xF00EF124: "dispatcher global slot",
    0x10336789: "dispatcher Thumb",

    0x1034C7E4: "dynamic/static resolver",
    0x1036A900: "dynamic resolver helper",
    0x102FA4FC: "static fallback thunk",
    0xF0316D74: "static resolver",
    0xF0316D75: "static resolver Thumb",
    0xF0345E68: "static registration table",

    0x1033D840: "Audio registration callback",
    0x1033D841: "Audio registration callback Thumb",
    0x1033E814: "Audio init wrapper",
    0x1033E815: "Audio init wrapper Thumb",
    0x1033F83C: "Audio Player init",

    0x8928: "Audio Player ID",
}

md = Cs(
    CS_ARCH_ARM,
    CS_MODE_THUMB | CS_MODE_LITTLE_ENDIAN,
)
md.detail = True


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def banner(title):
    print()
    print("=" * 120)
    print(title)
    print("=" * 120)


def known_name(value):
    return (
        KNOWN.get(value)
        or KNOWN.get(value & ~1)
    )


def u32(data, base, addr):
    off = addr - base

    if off < 0 or off + 4 > len(data):
        return None

    return struct.unpack_from(
        "<I",
        data,
        off,
    )[0]


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

    op = insn.operands[0]

    if op.type != ARM_OP_IMM:
        return None

    return op.imm & 0xFFFFFFFF


def pc_literal(insn, data, base):
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

    value = u32(
        data,
        base,
        addr,
    )

    if value is None:
        return None

    dst = None

    if insn.operands[0].type == ARM_OP_REG:
        dst = insn.reg_name(
            insn.operands[0].reg
        )

    return dst, addr, value


def format_insn(insn, data, base):
    comments = []

    target = branch_target(insn)

    if target is not None:
        text = f"TARGET=0x{target:08X}"

        n = known_name(target)

        if n:
            text += f" <{n}>"

        comments.append(text)

    lit = pc_literal(
        insn,
        data,
        base,
    )

    if lit:
        dst, addr, value = lit

        text = (
            f"LITERAL[0x{addr:08X}]"
            f"=0x{value:08X}"
        )

        if dst:
            text += f" -> {dst}"

        n = known_name(value)

        if n:
            text += f" <{n}>"

        comments.append(text)

    suffix = ""

    if comments:
        suffix = " ; " + " ; ".join(comments)

    return (
        f"0x{insn.address:08X}: "
        f"{insn.bytes.hex(' '):<16} "
        f"{insn.mnemonic:<9} "
        f"{insn.op_str:<34}"
        f"{suffix}"
    )


def raw_bytes(data, base, addr, length):
    off = addr - base

    blob = data[
        off:
        off + length
    ]

    print(
        f"RAW @ 0x{addr:08X}: "
        f"{blob.hex(' ')}"
    )


def exact_disasm(
    title,
    data,
    base,
    addr,
    size,
):
    banner(title)

    raw_bytes(
        data,
        base,
        addr,
        min(size, 0x40),
    )

    off = addr - base

    blob = data[
        off:
        off + size
    ]

    for insn in md.disasm(
        blob,
        addr,
    ):
        print(
            format_insn(
                insn,
                data,
                base,
            )
        )


def all_positions(data, pattern):
    out = []
    pos = 0

    while True:
        pos = data.find(
            pattern,
            pos,
        )

        if pos < 0:
            break

        out.append(pos)
        pos += 1

    return out


def static_registration_census(zimage):
    banner(
        "ZIMAGE STATIC REGISTRATION "
        "CORRELATION FOR 0x8928"
    )

    table_addr = 0xF0345E68
    table_off = table_addr - ZIMAGE_BASE

    print(
        f"TABLE runtime = 0x{table_addr:08X}"
    )
    print(
        f"TABLE FILE+   = 0x{table_off:X}"
    )

    if table_off < 0 or table_off >= len(zimage):
        print("ERROR: table outside ZIMAGE")
        return

    id_pattern = struct.pack(
        "<H",
        TARGET_ID,
    )

    callback_values = [
        0x1033D840,
        0x1033D841,
    ]

    id_hits = all_positions(
        zimage,
        id_pattern,
    )

    callback_hits = []

    for value in callback_values:
        p = struct.pack(
            "<I",
            value,
        )

        for off in all_positions(zimage, p):
            callback_hits.append(
                (
                    off,
                    value,
                )
            )

    print()
    print(
        f"all U16 0x8928 hits = "
        f"{len(id_hits)}"
    )

    near_table_ids = []

    for off in id_hits:
        runtime = ZIMAGE_BASE + off

        distance = abs(
            runtime - table_addr
        )

        if distance <= 0x1000:
            near_table_ids.append(off)

            print(
                f"  ID hit FILE+0x{off:X} "
                f"runtime=0x{runtime:08X} "
                f"delta_table={runtime-table_addr:+#x}"
            )

    print()
    print(
        "callback pointer hits near table:"
    )

    near_callbacks = []

    for off, value in callback_hits:
        runtime = ZIMAGE_BASE + off

        if abs(runtime - table_addr) <= 0x1000:
            near_callbacks.append(
                (
                    off,
                    value,
                )
            )

            print(
                f"  0x{value:08X} "
                f"FILE+0x{off:X} "
                f"runtime=0x{runtime:08X}"
            )

    print()
    print(
        "ID/callback proximity pairs "
        "(<= 0x40 bytes):"
    )

    pair_count = 0

    for id_off in near_table_ids:
        for cb_off, value in near_callbacks:

            delta = cb_off - id_off

            if abs(delta) <= 0x40:
                pair_count += 1

                print(
                    f"  ID FILE+0x{id_off:X}"
                    f" -> callback "
                    f"0x{value:08X} "
                    f"FILE+0x{cb_off:X} "
                    f"delta={delta:+#x}"
                )

                start = max(
                    0,
                    min(id_off, cb_off) - 0x20,
                )

                end = min(
                    len(zimage),
                    max(id_off, cb_off) + 0x30,
                )

                blob = zimage[
                    start:
                    end
                ]

                print(
                    "    RAW:",
                    blob.hex(" "),
                )

    print(
        f"PAIR COUNT = {pair_count}"
    )


def register_use_summary(
    title,
    data,
    base,
    addr,
    size,
):
    banner(title)

    off = addr - base

    blob = data[
        off:
        off + size
    ]

    count = 0

    for insn in md.disasm(
        blob,
        addr,
    ):
        print(
            format_insn(
                insn,
                data,
                base,
            )
        )

        count += 1

        if count >= 24:
            break


def main():
    alice = ALICE_PATH.read_bytes()
    zimage = ZIMAGE_PATH.read_bytes()

    print("=" * 120)
    print(
        "S13.1d - EXACT AUDIO CALLBACK / "
        "STATIC FALLBACK AUDIT"
    )
    print("=" * 120)

    print()
    print("ALICE")
    print(
        f"  SIZE   = 0x{len(alice):X}"
    )
    print(
        f"  SHA256 = {sha256(alice)}"
    )

    print()
    print("ZIMAGE")
    print(
        f"  SIZE   = 0x{len(zimage):X}"
    )
    print(
        f"  SHA256 = {sha256(zimage)}"
    )

    if len(alice) != ALICE_SIZE:
        print(
            "ABORT: wrong ALICE size"
        )
        return 2

    if sha256(alice) != ALICE_SHA:
        print(
            "ABORT: wrong ALICE SHA"
        )
        return 3

    if sha256(zimage) != ZIMAGE_SHA:
        print(
            "ABORT: wrong ZIMAGE SHA"
        )
        return 4

    print()
    print(
        "[PASS] canonical ALICE + ZIMAGE"
    )

    exact_disasm(
        "A - EXACT ENTRY 0x10336F84 "
        "dispatcher setter",
        alice,
        ALICE_BASE,
        0x10336F84,
        0x30,
    )

    exact_disasm(
        "B - EXACT ENTRY 0x102FA4FC "
        "static fallback thunk",
        alice,
        ALICE_BASE,
        0x102FA4FC,
        0x24,
    )

    exact_disasm(
        "C - EXACT ENTRY 0x1034C7E4 "
        "resolver",
        alice,
        ALICE_BASE,
        0x1034C7E4,
        0x40,
    )

    exact_disasm(
        "D - EXACT AUDIO CALLBACK "
        "0x1033D840",
        alice,
        ALICE_BASE,
        0x1033D840,
        0x60,
    )

    exact_disasm(
        "E - EXACT AUDIO INIT WRAPPER "
        "0x1033E814",
        alice,
        ALICE_BASE,
        0x1033E814,
        0x60,
    )

    exact_disasm(
        "F - AUDIO PLAYER INIT "
        "0x1033F83C",
        alice,
        ALICE_BASE,
        0x1033F83C,
        0x80,
    )

    exact_disasm(
        "G - EXACT STATIC RESOLVER "
        "F0316D74",
        zimage,
        ZIMAGE_BASE,
        0xF0316D74,
        0x80,
    )

    static_registration_census(
        zimage
    )

    register_use_summary(
        "AUDIO CALLBACK FIRST-INSTRUCTION "
        "REGISTER CONTRACT",
        alice,
        ALICE_BASE,
        0x1033D840,
        0x40,
    )

    banner(
        "S13.1d DECISION"
    )

    print(
        "Q1. Does 10336F84 store "
        "r0=10336789 into F00EF124?"
    )

    print(
        "Q2. Is 102FA4FC a direct "
        "Thumb trampoline to F0316D75?"
    )

    print(
        "Q3. Does F0316D74/75 resolve "
        "ID 0x8928 to 1033D841?"
    )

    print(
        "Q4. Does 1033D840 use any "
        "incoming r0/r1/r2/r3 before "
        "launching the Audio init chain?"
    )

    print(
        "Q5. Is the minimal offline "
        "launch target therefore "
        "1033D841 / 1033D840?"
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
