from pathlib import Path
import struct

from capstone import (
    Cs,
    CS_ARCH_ARM,
    CS_MODE_ARM,
    CS_MODE_THUMB,
    CS_MODE_LITTLE_ENDIAN,
)

BASE = 0x1024EC00

ALICE = Path(
    r"research/f2/work/extracted/altice_alice/alice-py.bin"
)

data = ALICE.read_bytes()

targets = {
    "candidate_PcmSink_TerminateSound": 0x102FCFBC,
    "candidate_KT_StopAndWait": 0x102FCB2C,
    "candidate_TONE_StopAndWait": 0x102FC564,
    "candidate_mhdlRefillAndUpdateVideoBuffer": 0x102FCFDC,
    "candidate_Media_SetAudioFormat": 0x102FBB1C,
    "candidate_AudioDrain_Start": 0x102FCD5C,
}

md_arm = Cs(
    CS_ARCH_ARM,
    CS_MODE_ARM | CS_MODE_LITTLE_ENDIAN,
)

md_thumb = Cs(
    CS_ARCH_ARM,
    CS_MODE_THUMB | CS_MODE_LITTLE_ENDIAN,
)

md_arm.detail = True
md_thumb.detail = True


def inside(addr, size=1):
    off = addr - BASE
    return 0 <= off and off + size <= len(data)


def read_u32(addr):
    if not inside(addr, 4):
        return None

    off = addr - BASE
    return struct.unpack_from("<I", data, off)[0]


def dump_disasm(md, addr, size):
    if not inside(addr, size):
        print("  OUTSIDE ALICE")
        return

    off = addr - BASE
    blob = data[off:off + size]

    for insn in md.disasm(blob, addr):
        print(
            f"  0x{insn.address:08X}: "
            f"{insn.bytes.hex(' '):<18} "
            f"{insn.mnemonic:<8} "
            f"{insn.op_str}"
        )


print("S03 AUDIO DRAIN / VENEER PROBE")
print()

print(f"ALICE base : 0x{BASE:08X}")
print(f"ALICE size : {len(data)}")
print()

resolved = {}

for name, addr in targets.items():

    print("=" * 100)
    print(name)
    print(f"veneer address = 0x{addr:08X}")
    print("=" * 100)

    if not inside(addr, 16):
        print("OUTSIDE ALICE")
        print()
        continue

    off = addr - BASE
    blob = data[off:off + 16]

    print("raw:", blob.hex(" "))
    print()

    print("ARM disassembly:")

    dump_disasm(
        md_arm,
        addr,
        16,
    )

    first = read_u32(addr)
    second = read_u32(addr + 4)

    print()

    if first is not None:
        print(
            f"word[+0] = "
            f"0x{first:08X}"
        )

    if second is not None:
        print(
            f"word[+4] = "
            f"0x{second:08X}"
        )

    #
    # MTK veneers commonly look like:
    #
    #   LDR PC,[PC,#-4]
    #   <target | Thumb bit>
    #
    if first == 0xE51FF004 and second is not None:

        target_raw = second
        target = target_raw & ~1
        thumb = target_raw & 1

        resolved[name] = target_raw

        print()
        print("MTK VENEER DETECTED")
        print(
            f"possible target = "
            f"0x{target:08X}"
        )
        print(
            f"target Thumb bit = "
            f"{thumb}"
        )
        print(
            f"target in ALICE = "
            f"{inside(target)}"
        )

        if inside(target, 64):

            print()
            print("Target disassembly:")

            if thumb:
                dump_disasm(
                    md_thumb,
                    target,
                    64,
                )
            else:
                dump_disasm(
                    md_arm,
                    target,
                    64,
                )

    else:
        print()
        print(
            "No canonical "
            "LDR PC,[PC,#-4] veneer detected."
        )

    print()


print("=" * 100)
print("SUMMARY")
print("=" * 100)

for name, addr in targets.items():

    print()

    print(
        f"{name}"
    )

    print(
        f"  call target : "
        f"0x{addr:08X}"
    )

    if name in resolved:

        raw = resolved[name]

        print(
            f"  real target : "
            f"0x{raw & ~1:08X}"
        )

        print(
            f"  Thumb       : "
            f"{raw & 1}"
        )

    else:
        print(
            "  real target : unresolved"
        )


print()
print("END S03 AUDIO DRAIN / VENEER PROBE")
