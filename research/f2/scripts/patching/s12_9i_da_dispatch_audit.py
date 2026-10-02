#!/usr/bin/env python3

from pathlib import Path
from collections import defaultdict
import re

from capstone import (
    Cs,
    CS_ARCH_ARM,
    CS_MODE_ARM,
    CS_MODE_THUMB,
    CS_MODE_LITTLE_ENDIAN,
)

from capstone.arm import ARM_OP_IMM


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

OUT = (
    ROOT
    / "research"
    / "f2"
    / "work"
    / "repro"
)

REPORT = (
    OUT
    / "s12_9i_da_dispatch_audit.txt"
)


COMMANDS = {
    0x62: "SDMMC_WRITE_DATA",
    0xAB: "NOR_WRITE_PTB",
    0xB2: "NOR_WRITE_DATA",
    0xB8: "SF_WRITE_IMAGE",

    0xD3: "MEM",
    0xD4: "FORMAT",
    0xD5: "WRITE",
    0xD6: "READ",
}


KEYWORDS = (
    "write",
    "read",
    "erase",
    "format",
    "flash",
    "nor",
    "serial",
    "download",
    "checksum",
    "packet",
)


def find_all(data, needle):
    out = []
    p = 0

    while True:
        p = data.find(needle, p)

        if p < 0:
            return out

        out.append(p)
        p += 1


def hexdump(data, base=0):
    out = []

    for i in range(0, len(data), 16):

        b = data[i:i+16]

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

        out.append(
            f"{base+i:08X}  "
            f"{hx:<47}  "
            f"{asc}"
        )

    return out


def ascii_strings(data, minimum=5):
    for m in re.finditer(
        rb"[ -~]{%d,}" % minimum,
        data,
    ):
        yield (
            m.start(),
            m.group().decode(
                "ascii",
                errors="replace",
            ),
        )


def make_disassembler(mode):
    md = Cs(
        CS_ARCH_ARM,
        mode | CS_MODE_LITTLE_ENDIAN,
    )

    md.detail = True
    md.skipdata = True

    return md


def instruction_command_refs(data, mode):
    md = make_disassembler(mode)

    hits = []

    for ins in md.disasm(data, 0):

        # Ignore capstone skipdata pseudo-insns.
        if ins.id == 0:
            continue

        immediates = []

        try:
            for op in ins.operands:

                if op.type == ARM_OP_IMM:
                    immediates.append(
                        op.imm & 0xFFFFFFFF
                    )

        except Exception:
            continue

        for value in immediates:

            if value in COMMANDS:

                hits.append({
                    "address": ins.address,
                    "size": ins.size,
                    "mnemonic": ins.mnemonic,
                    "op_str": ins.op_str,
                    "command": value,
                    "name": COMMANDS[value],
                })

    return hits


def clusters(hits, distance=0x100):
    if not hits:
        return []

    sh = sorted(
        hits,
        key=lambda x: x["address"],
    )

    groups = []
    cur = [sh[0]]

    for h in sh[1:]:

        if (
            h["address"]
            - cur[-1]["address"]
            <= distance
        ):
            cur.append(h)

        else:
            groups.append(cur)
            cur = [h]

    groups.append(cur)

    return groups


def disasm_window(
    data,
    mode,
    start,
    end,
):
    if mode == CS_MODE_THUMB:
        start &= ~1
    else:
        start &= ~3

    md = make_disassembler(mode)

    return list(
        md.disasm(
            data[start:end],
            start,
        )
    )


def analyze(name, path):
    data = path.read_bytes()

    print()
    print("=" * 120)
    print(name)
    print("=" * 120)

    print(
        f"path = {path}"
    )

    print(
        f"size = 0x{len(data):X}"
    )


    # --------------------------------------------------------------
    # A. Raw command-byte census
    # --------------------------------------------------------------

    print()
    print("A. RAW COMMAND BYTE CENSUS")
    print("-" * 120)

    raw = {}

    for cmd, cname in COMMANDS.items():

        hits = find_all(
            data,
            bytes([cmd]),
        )

        raw[cmd] = hits

        print(
            f"0x{cmd:02X} "
            f"{cname:<20} "
            f"count={len(hits):5d} "
            f"first={[hex(x) for x in hits[:20]]}"
        )


    # Search contiguous classic command family.
    print()
    print("CLASSIC D3 D4 D5 D6 RAW SEQUENCE")
    print("-" * 120)

    seq = bytes(
        [0xD3, 0xD4, 0xD5, 0xD6]
    )

    seq_hits = find_all(
        data,
        seq,
    )

    print(
        f"hits={len(seq_hits)} "
        f"{[hex(x) for x in seq_hits[:50]]}"
    )


    # --------------------------------------------------------------
    # B. Instruction-immediate census
    # --------------------------------------------------------------

    all_mode_hits = {}

    for mode_name, mode in (
        ("THUMB", CS_MODE_THUMB),
        ("ARM", CS_MODE_ARM),
    ):

        print()
        print(
            f"B. {mode_name} COMMAND IMMEDIATE REFERENCES"
        )
        print("-" * 120)

        hits = instruction_command_refs(
            data,
            mode,
        )

        all_mode_hits[
            mode_name
        ] = hits

        by_cmd = defaultdict(list)

        for h in hits:
            by_cmd[
                h["command"]
            ].append(h)

        for cmd, cname in COMMANDS.items():

            hs = by_cmd.get(
                cmd,
                [],
            )

            print(
                f"0x{cmd:02X} "
                f"{cname:<20} "
                f"refs={len(hs)}"
            )

            for h in hs[:50]:

                print(
                    f"  0x{h['address']:08X}: "
                    f"{h['mnemonic']:<8} "
                    f"{h['op_str']}"
                )


        # ----------------------------------------------------------
        # C. Dispatch-like clusters
        # ----------------------------------------------------------

        print()
        print(
            f"C. {mode_name} DISPATCH-LIKE CLUSTERS"
        )
        print("-" * 120)

        good_clusters = []

        for group in clusters(
            hits,
            distance=0x100,
        ):

            cmds = sorted(
                set(
                    h["command"]
                    for h in group
                )
            )

            # Interesting if multiple command values occur together,
            # especially the D4/D5/D6 family.
            if (
                len(cmds) >= 2
                or (
                    0xD5 in cmds
                    and 0xD6 in cmds
                )
            ):
                good_clusters.append(
                    (
                        group,
                        cmds,
                    )
                )

        print(
            f"candidate clusters = "
            f"{len(good_clusters)}"
        )

        for ci, (
            group,
            cmds,
        ) in enumerate(
            good_clusters[:50]
        ):

            start = max(
                0,
                min(
                    h["address"]
                    for h in group
                ) - 0x40,
            )

            end = min(
                len(data),
                max(
                    h["address"]
                    + h["size"]
                    for h in group
                ) + 0x80,
            )

            print()
            print(
                f"CLUSTER {ci}"
            )

            print(
                "commands = "
                + ", ".join(
                    f"0x{x:02X}/"
                    f"{COMMANDS[x]}"
                    for x in cmds
                )
            )

            print(
                f"range = "
                f"0x{start:X}..0x{end-1:X}"
            )

            print()
            print(
                "instruction hits:"
            )

            for h in group:

                print(
                    f"  0x{h['address']:08X}: "
                    f"{h['mnemonic']:<8} "
                    f"{h['op_str']:<30} "
                    f"; {h['name']}"
                )

            print()
            print(
                "disassembly window:"
            )

            insns = disasm_window(
                data,
                mode,
                start,
                end,
            )

            for ins in insns[:160]:

                marker = ""

                for h in group:

                    if (
                        h["address"]
                        == ins.address
                    ):
                        marker = (
                            "  <<< "
                            + h["name"]
                        )
                        break

                print(
                    f"  {ins.address:08X}: "
                    f"{ins.mnemonic:<8} "
                    f"{ins.op_str}"
                    f"{marker}"
                )


    # --------------------------------------------------------------
    # D. D5/D6 proximity
    # --------------------------------------------------------------

    print()
    print("D. D5 WRITE / D6 READ PROXIMITY")
    print("-" * 120)

    for mode_name, hits in (
        all_mode_hits.items()
    ):

        writes = [
            h
            for h in hits
            if h["command"] == 0xD5
        ]

        reads = [
            h
            for h in hits
            if h["command"] == 0xD6
        ]

        pairs = []

        for w in writes:

            for r in reads:

                delta = abs(
                    w["address"]
                    - r["address"]
                )

                if delta <= 0x200:

                    pairs.append(
                        (
                            delta,
                            w,
                            r,
                        )
                    )

        pairs.sort(
            key=lambda x: x[0]
        )

        print()
        print(
            f"{mode_name}: "
            f"{len(pairs)} pair(s) "
            f"within 0x200"
        )

        for delta, w, r in pairs[:50]:

            print(
                f"  delta=0x{delta:X} "
                f"WRITE@0x{w['address']:X} "
                f"READ@0x{r['address']:X}"
            )


    # --------------------------------------------------------------
    # E. Strings
    # --------------------------------------------------------------

    print()
    print("E. RELEVANT ASCII STRINGS")
    print("-" * 120)

    string_hits = []

    for off, s in ascii_strings(
        data,
        5,
    ):

        low = s.lower()

        if any(
            k in low
            for k in KEYWORDS
        ):
            string_hits.append(
                (
                    off,
                    s,
                )
            )

    print(
        f"matches={len(string_hits)}"
    )

    for off, s in string_hits[:500]:

        print(
            f"0x{off:08X}: "
            f"{s[:300]}"
        )


    return {
        "data": data,
        "raw": raw,
        "mode_hits": all_mode_hits,
    }


ext = list(
    PKG.rglob("EXT_BOOTLOADER")
)

rom = list(
    PKG.rglob("ROM")
)

assert len(ext) == 1
assert len(rom) == 1


import contextlib
import io

capture = io.StringIO()

with contextlib.redirect_stdout(
    capture
):

    ext_result = analyze(
        "EXT_BOOTLOADER",
        ext[0],
    )

    rom_result = analyze(
        "ROM",
        rom[0],
    )


    # --------------------------------------------------------------
    # F. Cross-copy candidate matching
    # --------------------------------------------------------------

    print()
    print("=" * 120)
    print("F. CROSS-COPY COMMAND-REFERENCE MATCHING")
    print("=" * 120)

    for mode_name in (
        "THUMB",
        "ARM",
    ):

        eh = ext_result[
            "mode_hits"
        ][mode_name]

        rh = rom_result[
            "mode_hits"
        ][mode_name]

        print()
        print(
            f"{mode_name}"
        )

        for cmd in (
            0xD4,
            0xD5,
            0xD6,
            0xB2,
            0xB8,
        ):

            epos = [
                h["address"]
                for h in eh
                if h["command"] == cmd
            ]

            rpos = [
                h["address"]
                for h in rh
                if h["command"] == cmd
            ]

            print(
                f"0x{cmd:02X} "
                f"{COMMANDS[cmd]:<18} "
                f"EXT={len(epos):3d} "
                f"ROM={len(rpos):3d}"
            )


    print()
    print("=" * 120)
    print("S12.9I CLASSIFICATION")
    print("=" * 120)

    print(
        "FACT: mtkclient generic 0x62 write "
        "does not mirror the NOR-IoT D6 framing."
    )

    print(
        "HYPOTHESIS: DA_WRITE_CMD 0xD5 is the "
        "natural write counterpart of READ_CMD 0xD6."
    )

    print(
        "GOAL OF THIS AUDIT: locate D5/D6 dispatch "
        "inside the exact F2 service loader."
    )

    print(
        "FLASH AUTHORIZED: NO"
    )


result = capture.getvalue()

print(
    result,
    end="",
)

REPORT.write_text(
    result,
    encoding="utf-8",
)

print()
print(
    "Report:",
    REPORT,
)
