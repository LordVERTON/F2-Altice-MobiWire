#!/usr/bin/env python3
"""
S13.1 - 0x8928 callsite / direct-launch contract audit

READ-ONLY / OFFLINE.

Goals:
  1. Reconfirm the real LDR-literal xrefs to 0x8928.
  2. Classify the still-unresolved ALICE cluster:
       FILE+0x117500
       FILE+0x117522
       FILE+0x117536
  3. Show surrounding Thumb code and direct calls.
  4. Search for direct BL/BLX callers of already-known resolver/dispatcher
     functions.
  5. Search for literal pointers to those functions.

No firmware file is modified.
No handset access is performed.
"""

from pathlib import Path
import hashlib
import struct
import sys

try:
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
except Exception as exc:
    print("ERROR: capstone import failed:", exc)
    sys.exit(2)


ROOT = Path.cwd()

ALICE_PATH = (
    ROOT
    / "research/f2/work/extracted/altice_alice/alice-py.bin"
)

ZIMAGE_PATH = (
    ROOT
    / "research/f2/work/extracted/altice_platform/zimage.bin"
)

ALICE_BASE = 0x1024EC00
ZIMAGE_BASE = 0xF023CA50

EXPECTED = {
    "ALICE": {
        "sha256":
            "7246242b67afae0d13104452bc3257827cb778119b54e7a26fb7fb55993697ea",
        "size": 0x157BB4,
        "pool_off": 0x117574,
        "expected_xref_offs": {
            0x117500,
            0x117522,
            0x117536,
        },
    },

    "ZIMAGE": {
        "sha256":
            "85fba8c8ae8161e4c1f8ced7983ec30d48c54ab10e51c69fcdfb900aca220954",
        "pool_off": 0x792F0,
        "expected_xref_count": 11,
    },
}

TARGET_VALUE = 0x00008928


KNOWN = {
    # Static registration / Audio Player
    0x1033D840: "Audio registration stub",
    0x1033D841: "Audio registration stub Thumb",
    0x1033E814: "Audio app init wrapper",
    0x1033E815: "Audio app init wrapper Thumb",
    0x1033F83C: "Audio Player app init",
    0x10341550: "Audio init downstream",
    0x10343A64: "Audio frontend downstream A",
    0x10343ADC: "Audio frontend downstream B",

    # Resolver / dispatch path already established
    0xF0316D74: "static registration resolver",
    0x1034C7E4: "dynamic lookup + static fallback",
    0x10336788: "ID resolver/callback dispatcher",
    0x10336789: "ID resolver/callback dispatcher Thumb",
    0x10332AF8: "dispatcher-global installer",
    0x102D9DC8: "ctx/ID global dispatcher bridge",

    # Active 0x8928-family path already established
    0xF02B5C60: "audio ID-family consumer",
    0xF02D1900: "audio ID path wrapper",
    0x1031F2D2: "audio ID path ALICE stage",
    0x102FD524: "audio ID path ALICE stage",
    0xF02E266C: "ID descriptor/resolver path",

    # Bootstrap
    0xF02B3C04: "native Audio Player bootstrap",
}


INTERESTING_CALL_TARGETS = {
    0x10336788,
    0x10336789,
    0x102D9DC8,
    0x1034C7E4,
    0xF0316D74,
    0xF02D1900,
    0xF02E266C,
    0x1033D840,
    0x1033D841,
}


md = Cs(
    CS_ARCH_ARM,
    CS_MODE_THUMB | CS_MODE_LITTLE_ENDIAN,
)
md.detail = True


def banner(title):
    print()
    print("=" * 118)
    print(title)
    print("=" * 118)


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def norm(addr):
    return addr & ~1


def known_name(addr):
    a = norm(addr)

    for k, v in KNOWN.items():
        if norm(k) == a:
            return v

    return None


def read_u32(data, base, addr):
    off = addr - base

    if off < 0 or off + 4 > len(data):
        return None

    return struct.unpack_from("<I", data, off)[0]


def decode_one(data, base, off):
    if off < 0 or off >= len(data):
        return None

    blob = data[off:off + 4]

    items = list(
        md.disasm(
            blob,
            base + off,
            count=1,
        )
    )

    if not items:
        return None

    return items[0]


def direct_target(insn):
    if insn.mnemonic not in (
        "bl",
        "blx",
        "b",
        "b.w",
        "beq",
        "bne",
        "bhi",
        "bls",
        "bcc",
        "bcs",
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


def literal_load(insn, data, base):
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
    literal_addr = (pc + op.mem.disp) & 0xFFFFFFFF

    value = read_u32(
        data,
        base,
        literal_addr,
    )

    if value is None:
        return None

    dst = None

    if (
        insn.operands
        and insn.operands[0].type == ARM_OP_REG
    ):
        dst = insn.reg_name(
            insn.operands[0].reg
        )

    return {
        "address": literal_addr,
        "value": value,
        "dst": dst,
    }


def format_insn(insn, data, base):
    comments = []

    tgt = direct_target(insn)

    if tgt is not None:
        txt = f"TARGET=0x{tgt:08X}"

        name = known_name(tgt)

        if name:
            txt += f" <{name}>"

        comments.append(txt)

    lit = literal_load(
        insn,
        data,
        base,
    )

    if lit is not None:
        txt = (
            f"LITERAL[0x{lit['address']:08X}]"
            f"=0x{lit['value']:08X}"
        )

        if lit["dst"]:
            txt += f" -> {lit['dst']}"

        if lit["value"] == TARGET_VALUE:
            txt += " <=== 0x8928"

        name = known_name(lit["value"])

        if name:
            txt += f" <{name}>"

        comments.append(txt)

    suffix = ""

    if comments:
        suffix = " ; " + " ; ".join(comments)

    return (
        f"0x{insn.address:08X}: "
        f"{insn.bytes.hex(' '):<14} "
        f"{insn.mnemonic:<8} "
        f"{insn.op_str:<34}"
        f"{suffix}"
    )


def disasm_window(
    label,
    data,
    base,
    center_off,
    before=0x60,
    after=0x90,
):
    start_off = max(
        0,
        (center_off - before) & ~1,
    )

    end_off = min(
        len(data),
        center_off + after,
    )

    banner(
        f"{label} window "
        f"FILE+0x{center_off:X} "
        f"runtime=0x{base + center_off:08X}"
    )

    blob = data[start_off:end_off]

    for insn in md.disasm(
        blob,
        base + start_off,
    ):
        marker = "   "

        if insn.address == base + center_off:
            marker = ">>>"

        print(
            marker,
            format_insn(
                insn,
                data,
                base,
            )
        )


def find_pool_xrefs(
    label,
    data,
    base,
    pool_off,
):
    pool_addr = base + pool_off

    hits = []

    for off in range(
        0,
        max(0, len(data) - 4),
        2,
    ):
        insn = decode_one(
            data,
            base,
            off,
        )

        if insn is None:
            continue

        lit = literal_load(
            insn,
            data,
            base,
        )

        if lit is None:
            continue

        if (
            lit["address"] == pool_addr
            and lit["value"] == TARGET_VALUE
        ):
            hits.append(
                (
                    off,
                    insn,
                    lit,
                )
            )

    banner(
        f"{label} — REAL LDR-LITERAL XREFS "
        f"TO 0x8928 POOL"
    )

    print(
        f"pool FILE+0x{pool_off:X} "
        f"runtime=0x{pool_addr:08X}"
    )

    print(
        f"pool value = "
        f"0x{read_u32(data, base, pool_addr):08X}"
    )

    print(
        f"xref count = {len(hits)}"
    )

    for off, insn, lit in hits:
        print(
            f"FILE+0x{off:06X} "
            f"runtime=0x{base + off:08X} "
            f"dst={lit['dst']} "
            f"{insn.mnemonic} {insn.op_str}"
        )

    return hits


def scan_direct_calls(
    label,
    data,
    base,
):
    banner(
        f"{label} — DIRECT BL/BLX TO KNOWN "
        f"RESOLVER / DISPATCH TARGETS"
    )

    hits = []

    normalized_targets = {
        norm(x)
        for x in INTERESTING_CALL_TARGETS
    }

    seen = set()

    for off in range(
        0,
        max(0, len(data) - 4),
        2,
    ):
        insn = decode_one(
            data,
            base,
            off,
        )

        if insn is None:
            continue

        if insn.mnemonic not in (
            "bl",
            "blx",
        ):
            continue

        tgt = direct_target(insn)

        if tgt is None:
            continue

        if norm(tgt) not in normalized_targets:
            continue

        key = (
            insn.address,
            norm(tgt),
        )

        if key in seen:
            continue

        seen.add(key)

        hits.append(
            (
                off,
                insn,
                tgt,
            )
        )

    if not hits:
        print(
            "No direct BL/BLX hit found "
            "(indirect calls / veneers remain possible)."
        )

    for off, insn, tgt in hits:
        print(
            f"FILE+0x{off:06X} "
            f"runtime=0x{insn.address:08X} "
            f"{insn.mnemonic} "
            f"0x{tgt:08X} "
            f"<{known_name(tgt) or 'known target'}>"
        )

    return hits


def scan_literal_pointers(
    label,
    data,
    base,
):
    banner(
        f"{label} — EXACT 32-BIT POINTER LITERALS "
        f"TO KNOWN DISPATCH TARGETS"
    )

    targets = [
        0x10336788,
        0x10336789,
        0x102D9DC8,
        0x1034C7E4,
        0xF0316D74,
        0xF0316D75,
        0x1033D840,
        0x1033D841,
    ]

    any_hit = False

    for target in targets:
        pattern = struct.pack(
            "<I",
            target,
        )

        positions = []
        pos = 0

        while True:
            pos = data.find(
                pattern,
                pos,
            )

            if pos < 0:
                break

            positions.append(pos)
            pos += 1

        if not positions:
            continue

        any_hit = True

        print()
        print(
            f"0x{target:08X} "
            f"<{known_name(target) or 'target'}>"
        )

        for pos in positions[:40]:
            print(
                f"  FILE+0x{pos:06X} "
                f"runtime=0x{base + pos:08X}"
            )

        if len(positions) > 40:
            print(
                f"  ... {len(positions) - 40} more"
            )

    if not any_hit:
        print("No exact pointer literals found.")


def immediate_calls_after_xref(
    label,
    data,
    base,
    xref_off,
    limit=0x60,
):
    banner(
        f"{label} — calls following "
        f"FILE+0x{xref_off:X}"
    )

    end = min(
        len(data),
        xref_off + limit,
    )

    blob = data[xref_off:end]

    for insn in md.disasm(
        blob,
        base + xref_off,
    ):
        lit = literal_load(
            insn,
            data,
            base,
        )

        if lit is not None:
            if lit["value"] == TARGET_VALUE:
                print(
                    format_insn(
                        insn,
                        data,
                        base,
                    )
                )

        if insn.mnemonic in (
            "bl",
            "blx",
        ):
            print(
                format_insn(
                    insn,
                    data,
                    base,
                )
            )

        if insn.mnemonic == "pop":
            if "pc" in insn.op_str:
                print(
                    format_insn(
                        insn,
                        data,
                        base,
                    )
                )
                break


def main():
    banner(
        "S13.1 — 0x8928 CALLSITE / "
        "DIRECT-LAUNCH CONTRACT AUDIT"
    )

    paths = {
        "ALICE": ALICE_PATH,
        "ZIMAGE": ZIMAGE_PATH,
    }

    images = {}

    for label, path in paths.items():
        if not path.exists():
            print(
                f"ERROR: missing {label}: {path}"
            )
            return 2

        data = path.read_bytes()
        digest = sha256(data)

        print()
        print(label)
        print(f"  PATH   = {path}")
        print(f"  SIZE   = 0x{len(data):X}")
        print(f"  SHA256 = {digest}")

        expected = EXPECTED[label]

        if digest != expected["sha256"]:
            print()
            print(
                f"ERROR: unexpected {label} SHA256."
            )
            print(
                "This audit intentionally refuses "
                "to mix firmware baselines."
            )
            return 3

        if (
            "size" in expected
            and len(data) != expected["size"]
        ):
            print(
                f"ERROR: unexpected {label} size"
            )
            return 4

        images[label] = data

    alice = images["ALICE"]
    zimage = images["ZIMAGE"]

    alice_pool = EXPECTED["ALICE"]["pool_off"]
    z_pool = EXPECTED["ZIMAGE"]["pool_off"]

    alice_pool_value = struct.unpack_from(
        "<I",
        alice,
        alice_pool,
    )[0]

    z_pool_value = struct.unpack_from(
        "<I",
        zimage,
        z_pool,
    )[0]

    if alice_pool_value != TARGET_VALUE:
        print(
            "ERROR: ALICE 0x8928 pool mismatch"
        )
        return 5

    if z_pool_value != TARGET_VALUE:
        print(
            "ERROR: ZIMAGE 0x8928 pool mismatch"
        )
        return 6

    alice_hits = find_pool_xrefs(
        "ALICE",
        alice,
        ALICE_BASE,
        alice_pool,
    )

    z_hits = find_pool_xrefs(
        "ZIMAGE",
        zimage,
        ZIMAGE_BASE,
        z_pool,
    )

    alice_hit_offs = {
        off
        for off, _, _ in alice_hits
    }

    expected_alice = (
        EXPECTED["ALICE"]
        ["expected_xref_offs"]
    )

    banner("S11.298 REPRODUCTION CHECK")

    print(
        "ALICE expected:",
        ", ".join(
            f"+0x{x:X}"
            for x in sorted(expected_alice)
        ),
    )

    print(
        "ALICE found   :",
        ", ".join(
            f"+0x{x:X}"
            for x in sorted(alice_hit_offs)
        ),
    )

    if alice_hit_offs == expected_alice:
        print(
            "[PASS] ALICE S11.298 xrefs "
            "reproduced exactly."
        )
    else:
        print(
            "[WARN] ALICE xref set differs "
            "from documented S11.298."
        )

    if (
        len(z_hits)
        == EXPECTED["ZIMAGE"]
        ["expected_xref_count"]
    ):
        print(
            "[PASS] ZIMAGE S11.298 xref count = 11."
        )
    else:
        print(
            "[WARN] ZIMAGE xref count differs: "
            f"{len(z_hits)}"
        )

    #
    # Focus on the still-unclassified ALICE cluster.
    #
    for off in sorted(alice_hit_offs):
        disasm_window(
            "ALICE 0x8928 xref",
            alice,
            ALICE_BASE,
            off,
            before=0x80,
            after=0xA0,
        )

        immediate_calls_after_xref(
            "ALICE",
            alice,
            ALICE_BASE,
            off,
            limit=0x80,
        )

    #
    # zImage xrefs: show compact contexts too, to prove that
    # they converge on the already-known F02B5C60 family.
    #
    for off, _, _ in z_hits:
        disasm_window(
            "ZIMAGE 0x8928 xref",
            zimage,
            ZIMAGE_BASE,
            off,
            before=0x30,
            after=0x50,
        )

    #
    # Look for concrete direct callers of the known dispatcher
    # functions in each code image.
    #
    alice_calls = scan_direct_calls(
        "ALICE",
        alice,
        ALICE_BASE,
    )

    z_calls = scan_direct_calls(
        "ZIMAGE",
        zimage,
        ZIMAGE_BASE,
    )

    #
    # Exact function-pointer literals can reveal indirect dispatch
    # paths not expressed as direct BL.
    #
    scan_literal_pointers(
        "ALICE",
        alice,
        ALICE_BASE,
    )

    scan_literal_pointers(
        "ZIMAGE",
        zimage,
        ZIMAGE_BASE,
    )

    banner("S13.1 MACHINE SUMMARY")

    print(
        f"ALICE 0x8928 LDR xrefs : "
        f"{len(alice_hits)}"
    )

    print(
        f"ZIMAGE 0x8928 LDR xrefs: "
        f"{len(z_hits)}"
    )

    print(
        f"ALICE direct interesting calls: "
        f"{len(alice_calls)}"
    )

    print(
        f"ZIMAGE direct interesting calls: "
        f"{len(z_calls)}"
    )

    print()
    print(
        "Important:"
    )
    print(
        "- ZIMAGE 0x8928 xrefs are expected "
        "to belong to the already-known "
        "F02B5C60 audio-ID family path."
    )
    print(
        "- The decision point for S13 is the "
        "ALICE 0x10366100/22/36 cluster and "
        "the concrete callers of "
        "10336788 / 102D9DC8."
    )
    print(
        "- No patch is produced by this audit."
    )
    print(
        "- No handset I/O is performed."
    )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
