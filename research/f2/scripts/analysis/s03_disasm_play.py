from pathlib import Path
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
    ARM_REG_PC,
)

BASE = 0x1024EC00

ALICE = Path(
    r"research/f2/work/extracted/altice_alice/alice-py.bin"
)

MEDIA_PLAY = 0x1028D394
MHDL_PLAY = 0x1035FB00

KNOWN = {
    0x1028D394: "aud_player_media.Play",
    0x1028D4C0: "aud_player_media.Stop",
    0x1028D378: "aud_player_media.Pause",
    0x1028D41C: "aud_player_media.Resume",

    0x10358254: "DAF_Open",

    0x1035FB00: "MHdl.Play",

    0x103162A8: "DPMGR_Load_Internal",
    0x103162BC: "DPMGR_Unload_Internal",

    0x10321808: "DCM_Load_wrapper",
    0x103217C0: "DCM_Unload_wrapper",

    0x10368B0C: "DafDec_GetMemSize",
    0x10368B44: "DafDec_Init",

    0x1036C410: "DAF_Process",
    0x1036C4C0: "DAF_SetParameter",
    0x1036C4E0: "DAF_Start",
    0x1036C526: "DAF_Stop",

    0x10370AE4: "DAF_frame_processing",
    0x10372008: "dafDec_ResetMem",
}

data = ALICE.read_bytes()

md = Cs(
    CS_ARCH_ARM,
    CS_MODE_THUMB | CS_MODE_LITTLE_ENDIAN,
)

md.detail = True


def inside(addr, size=1):
    off = addr - BASE
    return 0 <= off and off + size <= len(data)


def read_u32(addr):
    if not inside(addr, 4):
        return None

    off = addr - BASE
    return struct.unpack_from("<I", data, off)[0]


def known_name(addr):
    normalized = addr & ~1

    for target, name in KNOWN.items():
        if (target & ~1) == normalized:
            return name

    return None


def print_disasm(start, size, title):
    print()
    print("=" * 110)
    print(title)
    print(
        f"0x{start:08X} .. "
        f"0x{start + size:08X}"
    )
    print("=" * 110)

    if not inside(start, size):
        print("ERROR: requested range outside ALICE")
        return

    offset = start - BASE
    blob = data[offset:offset + size]

    for insn in md.disasm(blob, start):
        comments = []

        #
        # Direct branch/call target
        #
        if (
            insn.mnemonic in ("bl", "blx", "b", "beq", "bne")
            and len(insn.operands) >= 1
            and insn.operands[0].type == ARM_OP_IMM
        ):
            target = insn.operands[0].imm & 0xFFFFFFFF

            txt = f"TARGET=0x{target:08X}"

            name = known_name(target)

            if name:
                txt += f" <{name}>"

            comments.append(txt)

        #
        # PC-relative literal load
        #
        if (
            insn.mnemonic.startswith("ldr")
            and len(insn.operands) >= 2
            and insn.operands[1].type == ARM_OP_MEM
            and insn.operands[1].mem.base == ARM_REG_PC
        ):
            pc = (insn.address + 4) & ~3
            literal_addr = pc + insn.operands[1].mem.disp

            value = read_u32(literal_addr)

            if value is not None:
                txt = (
                    f"LITERAL[0x{literal_addr:08X}]"
                    f"=0x{value:08X}"
                )

                name = known_name(value)

                if name:
                    txt += f" <{name}>"

                comments.append(txt)

        suffix = ""

        if comments:
            suffix = " ; " + " ; ".join(comments)

        print(
            f"0x{insn.address:08X}: "
            f"{insn.bytes.hex(' '):<20} "
            f"{insn.mnemonic:<8} "
            f"{insn.op_str:<32}"
            f"{suffix}"
        )


print("S03 PLAY PROBE")
print()

print(f"ALICE base : 0x{BASE:08X}")
print(f"ALICE size : {len(data)}")
print()

print(f"aud_player_media.Play : 0x{MEDIA_PLAY:08X}")
print(f"MHdl.Play             : 0x{MHDL_PLAY:08X}")
print()

print_disasm(
    MEDIA_PLAY,
    0x180,
    "A — aud_player_media.Play"
)

print_disasm(
    MHDL_PLAY,
    0x300,
    "B — MHdl.Play"
)

print()
print("=" * 110)
print("C — LITERAL POINTER REFERENCES TO MHdl.Play")
print("=" * 110)

for value in (
    MHDL_PLAY,
    MHDL_PLAY | 1,
):
    pattern = struct.pack("<I", value)

    pos = 0
    found = False

    while True:
        pos = data.find(pattern, pos)

        if pos < 0:
            break

        found = True

        print(
            f"0x{BASE + pos:08X}"
            f" -> 0x{value:08X}"
        )

        pos += 1

    if not found:
        print(
            f"No literal pointer for "
            f"0x{value:08X}"
        )

print()
print("=" * 110)
print("D — LITERAL POINTERS TO KNOWN DAF/DPMGR FUNCTIONS")
print("=" * 110)

targets = {
    "DPMGR_Load_Internal": 0x103162A8,
    "DPMGR_Unload_Internal": 0x103162BC,
    "DAF_Start": 0x1036C4E0,
    "DAF_Process": 0x1036C410,
    "DAF_Stop": 0x1036C526,
    "DAF_SetParameter": 0x1036C4C0,
}

for name, addr in targets.items():
    hits = set()

    for value in (
        addr,
        addr | 1,
        addr & ~1,
    ):
        pattern = struct.pack("<I", value)

        pos = 0

        while True:
            pos = data.find(pattern, pos)

            if pos < 0:
                break

            hits.add(
                (
                    BASE + pos,
                    value,
                )
            )

            pos += 1

    print()
    print(
        f"{name} "
        f"0x{addr:08X}"
    )

    if hits:
        for location, value in sorted(hits):
            print(
                f"  literal @ 0x{location:08X}"
                f" = 0x{value:08X}"
            )
    else:
        print("  no literal pointer")

print()
print("END S03 PLAY PROBE")
