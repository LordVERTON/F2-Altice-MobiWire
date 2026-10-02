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

ROOT = Path.cwd()

SOURCE = (
    ROOT /
    "research/f2/work/extracted/altice_alice/alice-py.bin"
)

OUTPUT = (
    ROOT /
    "research/f2/work/candidates/s13_2a/"
    "alice-s13_2a-image-activation-audio-poc.bin"
)

BASE = 0x1024EC00

EXPECTED_SHA = (
    "7246242b67afae0d13104452bc3257827"
    "cb778119b54e7a26fb7fb55993697ea"
)

EXPECTED_SIZE = 0x157BB4

HOOK_FUNCTION = 0x1035578C
HOOK_LITERAL  = 0x10355888

OLD_POINTER = 0xF0301C8D
NEW_POINTER = 0x1033E815

AUDIO_WRAPPER = 0x1033E814
AUDIO_INIT    = 0x1033F83C

md = Cs(
    CS_ARCH_ARM,
    CS_MODE_THUMB | CS_MODE_LITTLE_ENDIAN,
)

md.detail = True


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def banner(title):
    print()
    print("=" * 118)
    print(title)
    print("=" * 118)


def off(addr):
    return addr - BASE


def u32(data, addr):
    pos = off(addr)

    if pos < 0 or pos + 4 > len(data):
        raise ValueError(
            f"address outside ALICE: 0x{addr:08X}"
        )

    return struct.unpack_from(
        "<I",
        data,
        pos,
    )[0]


def disasm(data, addr, size):
    pos = off(addr)

    blob = data[
        pos:
        pos + size
    ]

    for insn in md.disasm(
        blob,
        addr,
    ):
        print(
            f"0x{insn.address:08X}: "
            f"{insn.bytes.hex(' '):<15} "
            f"{insn.mnemonic:<9} "
            f"{insn.op_str}"
        )


def positions(data, value):
    pattern = struct.pack(
        "<I",
        value,
    )

    result = []
    p = 0

    while True:
        p = data.find(
            pattern,
            p,
        )

        if p < 0:
            break

        result.append(p)
        p += 1

    return result


def main():

    banner(
        "S13.2A - IMAGE ACTIVATION -> AUDIO "
        "OFFLINE POC CANDIDATE"
    )

    if not SOURCE.exists():
        print(
            f"ABORT: missing ALICE: {SOURCE}"
        )
        return 2

    original = SOURCE.read_bytes()

    print(f"SOURCE = {SOURCE}")
    print(f"SIZE   = 0x{len(original):X}")
    print(f"SHA256 = {sha256(original)}")

    if len(original) != EXPECTED_SIZE:
        print(
            "ABORT: ALICE size mismatch"
        )
        return 3

    if sha256(original) != EXPECTED_SHA:
        print(
            "ABORT: ALICE SHA mismatch"
        )
        return 4

    print(
        "[PASS] canonical ALICE"
    )

    banner(
        "1. VERIFY DOCUMENTED IMAGE VIEWER HOOK"
    )

    literal_value = u32(
        original,
        HOOK_LITERAL,
    )

    print(
        f"HOOK FUNCTION = "
        f"0x{HOOK_FUNCTION:08X}"
    )

    print(
        f"HOOK LITERAL  = "
        f"0x{HOOK_LITERAL:08X}"
    )

    print(
        f"FILE OFFSET   = "
        f"0x{off(HOOK_LITERAL):X}"
    )

    print(
        f"CURRENT VALUE = "
        f"0x{literal_value:08X}"
    )

    if literal_value != OLD_POINTER:
        print(
            "ABORT: documented Image Viewer "
            "pointer is not present."
        )
        return 5

    print(
        "[PASS] hook literal is exactly "
        "F0301C8D"
    )

    banner(
        "2. ORIGINAL HOOK CONTEXT"
    )

    disasm(
        original,
        HOOK_FUNCTION,
        0x130,
    )

    banner(
        "3. POINTER CENSUS"
    )

    old_hits = positions(
        original,
        OLD_POINTER,
    )

    new_hits = positions(
        original,
        NEW_POINTER,
    )

    print(
        f"F0301C8D occurrences in ALICE = "
        f"{len(old_hits)}"
    )

    for p in old_hits:
        print(
            f"  FILE+0x{p:X} "
            f"runtime=0x{BASE+p:08X}"
        )

    print()
    print(
        f"1033E815 occurrences in ALICE = "
        f"{len(new_hits)}"
    )

    for p in new_hits:
        print(
            f"  FILE+0x{p:X} "
            f"runtime=0x{BASE+p:08X}"
        )

    if off(HOOK_LITERAL) not in old_hits:
        print(
            "ABORT: selected literal missing "
            "from census."
        )
        return 6

    banner(
        "4. VERIFY AUDIO DIRECT ENTRY"
    )

    print(
        f"AUDIO WRAPPER = "
        f"0x{AUDIO_WRAPPER:08X}"
    )

    print(
        f"THUMB POINTER = "
        f"0x{NEW_POINTER:08X}"
    )

    print(
        f"AUDIO INIT    = "
        f"0x{AUDIO_INIT:08X}"
    )

    disasm(
        original,
        AUDIO_WRAPPER,
        0x10,
    )

    #
    # Build COPY ONLY.
    #
    candidate = bytearray(
        original
    )

    struct.pack_into(
        "<I",
        candidate,
        off(HOOK_LITERAL),
        NEW_POINTER,
    )

    candidate = bytes(
        candidate
    )

    banner(
        "5. BUILD OFFLINE CANDIDATE"
    )

    OUTPUT.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    OUTPUT.write_bytes(
        candidate
    )

    print(
        f"OUTPUT = {OUTPUT}"
    )

    print(
        f"SIZE   = 0x{len(candidate):X}"
    )

    print(
        f"SHA256 = {sha256(candidate)}"
    )

    banner(
        "6. EXACT BYTE DIFF"
    )

    diffs = [
        i
        for i, (a, b)
        in enumerate(
            zip(
                original,
                candidate,
            )
        )
        if a != b
    ]

    print(
        f"CHANGED BYTE COUNT = "
        f"{len(diffs)}"
    )

    if diffs:
        print(
            f"FIRST = FILE+0x{diffs[0]:X} "
            f"runtime=0x{BASE+diffs[0]:08X}"
        )

        print(
            f"LAST  = FILE+0x{diffs[-1]:X} "
            f"runtime=0x{BASE+diffs[-1]:08X}"
        )

    for p in diffs:
        print(
            f"  FILE+0x{p:X} "
            f"runtime=0x{BASE+p:08X}: "
            f"{original[p]:02X} -> "
            f"{candidate[p]:02X}"
        )

    expected_old = struct.pack(
        "<I",
        OLD_POINTER,
    )

    expected_new = struct.pack(
        "<I",
        NEW_POINTER,
    )

    actual_old = original[
        off(HOOK_LITERAL):
        off(HOOK_LITERAL)+4
    ]

    actual_new = candidate[
        off(HOOK_LITERAL):
        off(HOOK_LITERAL)+4
    ]

    print()
    print(
        "ORIGINAL POINTER BYTES =",
        actual_old.hex(" "),
    )

    print(
        "PATCHED POINTER BYTES  =",
        actual_new.hex(" "),
    )

    if actual_old != expected_old:
        print(
            "ABORT: original pointer bytes "
            "unexpected."
        )
        return 7

    if actual_new != expected_new:
        print(
            "ABORT: patched pointer bytes "
            "unexpected."
        )
        return 8

    #
    # A 32-bit pointer can differ in fewer
    # than four byte positions because some
    # bytes may coincidentally be equal.
    #
    expected_changed_positions = [
        i
        for i, (a, b)
        in enumerate(
            zip(
                expected_old,
                expected_new,
            )
        )
        if a != b
    ]

    expected_diff_count = len(
        expected_changed_positions
    )

    if len(diffs) != expected_diff_count:
        print(
            "ABORT: changes exist outside the "
            "single intended pointer."
        )
        print(
            f"Expected differing bytes = "
            f"{expected_diff_count}"
        )
        return 9

    allowed = {
        off(HOOK_LITERAL) + x
        for x in expected_changed_positions
    }

    if set(diffs) != allowed:
        print(
            "ABORT: diff positions do not match "
            "the intended pointer."
        )
        return 10

    banner(
        "7. CANDIDATE HOOK SEMANTICS"
    )

    print(
        "ORIGINAL:"
    )
    print(
        "  bitmap activation path"
    )
    print(
        "      -> F0301C8D "
        "(Image Viewer init)"
    )

    print()
    print(
        "CANDIDATE:"
    )
    print(
        "  same bitmap activation path"
    )
    print(
        "      -> 1033E815 "
        "(Audio Player init wrapper)"
    )

    print()
    print(
        "[PASS] source ALICE untouched"
    )
    print(
        "[PASS] candidate differs only at "
        "the selected function pointer"
    )
    print(
        "[PASS] NO firmware repack performed"
    )
    print(
        "[PASS] NO handset I/O performed"
    )

    print()
    print(
        "This candidate is NOT authorized "
        "for flashing."
    )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
