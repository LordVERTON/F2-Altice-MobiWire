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


ROOT = Path(r"C:\Users\verto\F2-Altice-MobiWire")
MTK  = Path(r"C:\Users\verto\mtkclient")

PKG = (
    MTK
    / "research"
    / "f2"
    / "data"
    / "firmware-packages"
    / "altice-service"
    / "altice_service_package"
)

OUT = ROOT / "research" / "f2" / "work" / "repro"
REPORT = OUT / "s12_9j_rom_dispatch_focus.txt"

EXPECTED_ROM_SIZE = 0x41E0C
EXPECTED_ROM_SHA = (
    "dbebc45c8e4334e61fd85bdab8988d4"
    "f271599263ce209520e36f571f3f4e37c"
)

TARGETS = {
    0x3DBB8: 0xD3,
    0x3DBC4: 0xD4,
    0x3DBD0: 0xD5,
    0x3DBDC: 0xD6,
}

WIN_START = 0x3DB80
WIN_END   = 0x3DC20


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def u16(data, off):
    return struct.unpack_from("<H", data, off)[0]


def sign_extend(v, bits):
    sign = 1 << (bits - 1)
    return (v & (sign - 1)) - (v & sign)


def decode_cmp_imm(hw):
    # Thumb16 CMP Rn, #imm8
    #
    # 00101 Rn imm8
    #
    # 0x2800 | (Rn << 8) | imm8

    if (hw & 0xF800) != 0x2800:
        return None

    rn = (hw >> 8) & 7
    imm = hw & 0xFF

    return rn, imm


def decode_cond_branch(hw, off):
    # Thumb16 conditional branch:
    #
    # 1101 cond imm8
    #
    # target = PC + 4 + sign_extend(imm8 << 1, 9)

    if (hw & 0xF000) != 0xD000:
        return None

    cond = (hw >> 8) & 0xF

    # 0xE = undefined/reserved in this encoding
    # 0xF = SVC
    if cond >= 0xE:
        return None

    imm8 = hw & 0xFF

    delta = sign_extend(
        imm8 << 1,
        9,
    )

    target = off + 4 + delta

    names = {
        0x0: "BEQ",
        0x1: "BNE",
        0x2: "BCS/BHS",
        0x3: "BCC/BLO",
        0x4: "BMI",
        0x5: "BPL",
        0x6: "BVS",
        0x7: "BVC",
        0x8: "BHI",
        0x9: "BLS",
        0xA: "BGE",
        0xB: "BLT",
        0xC: "BGT",
        0xD: "BLE",
    }

    return (
        names.get(cond, f"COND_{cond:X}"),
        target,
    )


def decode_uncond_branch(hw, off):
    # Thumb16 unconditional B:
    #
    # 11100 imm11

    if (hw & 0xF800) != 0xE000:
        return None

    imm11 = hw & 0x7FF

    delta = sign_extend(
        imm11 << 1,
        12,
    )

    return off + 4 + delta


def dump_hex(data, start, end):
    for off in range(start, end, 16):

        b = data[off:min(off + 16, end)]

        hx = " ".join(
            f"{x:02X}"
            for x in b
        )

        asc = "".join(
            chr(x)
            if 32 <= x <= 126
            else "."
            for x in b
        )

        print(
            f"{off:08X}  "
            f"{hx:<47}  "
            f"{asc}"
        )


roms = list(PKG.rglob("ROM"))

assert len(roms) == 1, (
    f"Expected exactly one ROM, got {len(roms)}"
)

ROM = roms[0]
data = ROM.read_bytes()

print("=" * 120)
print("S12.9J - TARGETED ROM D3/D4/D5/D6 DISPATCH AUDIT")
print("=" * 120)

print()
print("NO DEVICE ACCESS")
print("NO BROM")
print("NO WRITE")
print("NO ERASE")

print()
print("ROM")
print("-" * 120)
print("path   :", ROM)
print(f"size   : 0x{len(data):X}")
print("sha256 :", sha256(data))

assert len(data) == EXPECTED_ROM_SIZE, (
    "Unexpected ROM size"
)

assert sha256(data) == EXPECTED_ROM_SHA, (
    "Unexpected ROM SHA256"
)

print("canonical ROM identity : PASS")


# ==================================================================
# A. RAW WINDOW
# ==================================================================

print()
print("=" * 120)
print("A. RAW WINDOW 0x3DB80..0x3DC1F")
print("=" * 120)

dump_hex(
    data,
    WIN_START,
    WIN_END,
)


# ==================================================================
# B. EXACT EXPECTED HALFWORDS
# ==================================================================

print()
print("=" * 120)
print("B. EXPECTED D3/D4/D5/D6 SLOTS")
print("=" * 120)

all_exact = True

for off, command in TARGETS.items():

    hw = u16(
        data,
        off,
    )

    dec = decode_cmp_imm(hw)

    expected_hw = (
        0x2800
        | (1 << 8)
        | command
    )

    print()
    print(
        f"offset 0x{off:05X}"
    )

    print(
        f"raw halfword = 0x{hw:04X}"
    )

    print(
        f"expected cmp r1,#0x{command:02X} "
        f"halfword = 0x{expected_hw:04X}"
    )

    print(
        "raw bytes = "
        + data[
            off:off + 2
        ].hex(" ").upper()
    )

    if dec is None:

        print(
            "decode = NOT CMP immediate"
        )

        exact = False

    else:

        rn, imm = dec

        print(
            f"decode = CMP r{rn}, #0x{imm:02X}"
        )

        exact = (
            rn == 1
            and imm == command
        )

    print(
        "exact expected instruction :",
        "PASS" if exact else "FAIL",
    )

    all_exact &= exact


# ==================================================================
# C. LOCAL CMP CENSUS
# ==================================================================

print()
print("=" * 120)
print("C. EXACT THUMB16 CMP-IMMEDIATE CENSUS IN WINDOW")
print("=" * 120)

cmp_hits = []

for off in range(
    WIN_START,
    WIN_END,
    2,
):

    hw = u16(
        data,
        off,
    )

    dec = decode_cmp_imm(hw)

    if dec is None:
        continue

    rn, imm = dec

    cmp_hits.append(
        (
            off,
            rn,
            imm,
            hw,
        )
    )

    marker = ""

    if imm in (
        0xD3,
        0xD4,
        0xD5,
        0xD6,
    ):
        marker = "  <<< DA COMMAND"

    print(
        f"0x{off:05X}: "
        f"CMP r{rn}, #0x{imm:02X} "
        f"[0x{hw:04X}]"
        f"{marker}"
    )


# ==================================================================
# D. TEST THE 0x0C-STRIDE HYPOTHESIS
# ==================================================================

print()
print("=" * 120)
print("D. D3 -> D4 -> D5 -> D6 STRIDE TEST")
print("=" * 120)

observed = []

for i, cmd in enumerate(
    (
        0xD3,
        0xD4,
        0xD5,
        0xD6,
    )
):

    off = 0x3DBB8 + i * 0x0C

    hw = u16(
        data,
        off,
    )

    dec = decode_cmp_imm(hw)

    if dec:
        rn, imm = dec
    else:
        rn, imm = None, None

    observed.append(
        (
            off,
            rn,
            imm,
        )
    )

    print(
        f"[{i}] "
        f"0x{off:05X}: "
        f"r{rn if rn is not None else '?'} "
        f"imm={f'0x{imm:02X}' if imm is not None else '?'} "
        f"expected=0x{cmd:02X}"
    )

stride_pass = all(
    rn == 1
    and imm == cmd
    for (
        (off, rn, imm),
        cmd,
    ) in zip(
        observed,
        (
            0xD3,
            0xD4,
            0xD5,
            0xD6,
        ),
    )
)

print()
print(
    "same-register r1 + exact 0x0C stride :",
    "PASS" if stride_pass else "FAIL",
)


# ==================================================================
# E. BRANCHES FOLLOWING EACH CMP
# ==================================================================

print()
print("=" * 120)
print("E. BRANCHES FOLLOWING EACH COMMAND COMPARE")
print("=" * 120)

branch_results = {}

for off, cmd in TARGETS.items():

    print()
    print(
        f"COMMAND 0x{cmd:02X} "
        f"CMP @ 0x{off:05X}"
    )

    found = []

    # Inspect the following 10 bytes / five Thumb halfwords.
    for q in range(
        off + 2,
        min(
            off + 12,
            len(data) - 1,
        ),
        2,
    ):

        hw = u16(
            data,
            q,
        )

        cb = decode_cond_branch(
            hw,
            q,
        )

        ub = decode_uncond_branch(
            hw,
            q,
        )

        if cb:

            name, target = cb

            print(
                f"  0x{q:05X}: "
                f"{name} -> 0x{target:05X} "
                f"[0x{hw:04X}]"
            )

            found.append(
                (
                    q,
                    name,
                    target,
                    hw,
                )
            )

        elif ub is not None:

            print(
                f"  0x{q:05X}: "
                f"B -> 0x{ub:05X} "
                f"[0x{hw:04X}]"
            )

            found.append(
                (
                    q,
                    "B",
                    ub,
                    hw,
                )
            )

    if not found:

        print(
            "  no Thumb16 branch in next 10 bytes"
        )

    branch_results[
        cmd
    ] = found


# ==================================================================
# F. TARGETED CAPSTONE DISASSEMBLY
# ==================================================================

print()
print("=" * 120)
print("F. TARGETED THUMB DISASSEMBLY")
print("=" * 120)

md = Cs(
    CS_ARCH_ARM,
    CS_MODE_THUMB
    | CS_MODE_LITTLE_ENDIAN,
)

md.detail = False
md.skipdata = True

for ins in md.disasm(
    data[
        WIN_START:WIN_END
    ],
    WIN_START,
):

    marker = ""

    if ins.address in TARGETS:

        marker = (
            f"  <<< EXPECT CMD "
            f"0x{TARGETS[ins.address]:02X}"
        )

    print(
        f"{ins.address:08X}: "
        f"{ins.mnemonic:<10} "
        f"{ins.op_str}"
        f"{marker}"
    )


# ==================================================================
# G. GLOBAL EXACT CMP PATTERN SEARCH
# ==================================================================

print()
print("=" * 120)
print("G. GLOBAL EXACT CMP r1,#D3/D4/D5/D6 LOCATIONS")
print("=" * 120)

global_hits = {
    cmd: []
    for cmd in (
        0xD3,
        0xD4,
        0xD5,
        0xD6,
    )
}

for off in range(
    0,
    len(data) - 1,
    2,
):

    hw = u16(
        data,
        off,
    )

    dec = decode_cmp_imm(
        hw,
    )

    if dec is None:
        continue

    rn, imm = dec

    if (
        rn == 1
        and imm in global_hits
    ):

        global_hits[
            imm
        ].append(
            off
        )

for cmd in (
    0xD3,
    0xD4,
    0xD5,
    0xD6,
):

    print(
        f"0x{cmd:02X}: "
        + ", ".join(
            f"0x{x:X}"
            for x in global_hits[
                cmd
            ]
        )
    )


# ==================================================================
# H. COMPLETE STRIDE CHAINS ANYWHERE IN ROM
# ==================================================================

print()
print("=" * 120)
print("H. COMPLETE D3/D4/D5/D6 CHAINS WITH STRIDE 0x0C")
print("=" * 120)

chains = []

d3_set = set(
    global_hits[0xD3]
)

d4_set = set(
    global_hits[0xD4]
)

d5_set = set(
    global_hits[0xD5]
)

d6_set = set(
    global_hits[0xD6]
)

for start in sorted(
    d3_set
):

    if (
        start + 0x0C
        in d4_set
        and
        start + 0x18
        in d5_set
        and
        start + 0x24
        in d6_set
    ):

        chains.append(
            start
        )

        print(
            f"CHAIN @ 0x{start:X}: "
            f"D3=0x{start:X} "
            f"D4=0x{start+0x0C:X} "
            f"D5=0x{start+0x18:X} "
            f"D6=0x{start+0x24:X}"
        )

if not chains:

    print(
        "NONE"
    )


# ==================================================================
# I. CLASSIFICATION
# ==================================================================

print()
print("=" * 120)
print("S12.9J RESULT")
print("=" * 120)

target_chain = (
    0x3DBB8
    in chains
)

print(
    "D3 slot exact CMP r1,#D3 :",
    "PASS"
    if decode_cmp_imm(
        u16(data, 0x3DBB8)
    ) == (1, 0xD3)
    else "FAIL",
)

print(
    "D4 slot exact CMP r1,#D4 :",
    "PASS"
    if decode_cmp_imm(
        u16(data, 0x3DBC4)
    ) == (1, 0xD4)
    else "FAIL",
)

print(
    "D5 slot exact CMP r1,#D5 :",
    "PASS"
    if decode_cmp_imm(
        u16(data, 0x3DBD0)
    ) == (1, 0xD5)
    else "FAIL",
)

print(
    "D6 slot exact CMP r1,#D6 :",
    "PASS"
    if decode_cmp_imm(
        u16(data, 0x3DBDC)
    ) == (1, 0xD6)
    else "FAIL",
)

print(
    "complete regular chain       :",
    "PASS"
    if target_chain
    else "FAIL",
)

print()

if target_chain:

    print(
        "FACT: ROM contains an exact Thumb16 "
        "CMP r1,#D3/D4/D5/D6 chain."
    )

    print(
        "FACT: command compares are spaced "
        "by exactly 0x0C bytes."
    )

    print(
        "STRONGLY SUPPORTED: this is a genuine "
        "DA command-dispatch region."
    )

    print(
        "NEXT: resolve the branch destinations "
        "for D5 and D6 and audit their handlers."
    )

else:

    print(
        "RESULT: the proposed exact D3-D6 "
        "dispatch chain is NOT proven."
    )

    print(
        "Do not infer handlers from S12.9I "
        "proximity alone."
    )

print()
print(
    "FLASH AUTHORIZED: NO"
)


# Write the same output via a second deterministic run is unnecessary;
# PowerShell Tee captures stdout. Create a compact marker file too.

REPORT.write_text(
    "\n".join([
        "S12.9J targeted ROM dispatch audit",
        f"ROM SHA256={sha256(data)}",
        f"target_chain={'PASS' if target_chain else 'FAIL'}",
        f"chains={','.join(hex(x) for x in chains) if chains else 'NONE'}",
        "FLASH AUTHORIZED=NO",
        "",
    ]),
    encoding="utf-8",
)

print()
print(
    "Summary report:",
    REPORT,
)
