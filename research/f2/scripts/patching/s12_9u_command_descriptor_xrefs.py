#!/usr/bin/env python3

from pathlib import Path
from collections import defaultdict, Counter
import hashlib
import struct

from capstone import (
    Cs,
    CS_ARCH_ARM,
    CS_MODE_THUMB,
    CS_MODE_LITTLE_ENDIAN,
)


ROOT = Path(r"C:\Users\verto\F2-Altice-MobiWire")
MTK = Path(r"C:\Users\verto\mtkclient")

LOADER = (
    MTK
    / "mtkclient"
    / "Loader"
    / "MTK_AllInOne_DA_iot.bin"
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
    / "s12_9u_command_descriptor_xrefs.txt"
)

DADA = 0x2718
DESC_SIZE = 0x24

COMMANDS = {
    0xD2: "SPEED",
    0xD3: "MEM",
    0xD4: "FORMAT",
    0xD5: "WRITE",
    0xD6: "READ",
    0xD7: "WRITE_REG16",
    0xD8: "CMD_D8",
    0xD9: "CMD_D9",
}


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def u16(data, off):
    return struct.unpack_from(
        "<H",
        data,
        off,
    )[0]


def u32(data, off):
    return struct.unpack_from(
        "<I",
        data,
        off,
    )[0]


def find_all(data, needle):
    out = []
    pos = 0

    while True:

        pos = data.find(
            needle,
            pos,
        )

        if pos < 0:
            return out

        out.append(pos)
        pos += 1


def parse_entry(data):

    vals = struct.unpack_from(
        "<10H",
        data,
        DADA,
    )

    region_index = vals[8]
    region_count = vals[9]

    regions = []

    base = DADA + 20

    for i in range(region_count):

        fields = struct.unpack_from(
            "<5I",
            data,
            base + i * 20,
        )

        regions.append({
            "index": i,
            "buf": fields[0],
            "len": fields[1],
            "addr": fields[2],
            "start_offset": fields[3],
            "sig": fields[4],
        })

    return {
        "hw": vals[1],
        "region_index": region_index,
        "regions": regions,
    }


def region_blob(data, r):
    return data[
        r["buf"]:
        r["buf"] + r["len"]
    ]


def classify_addr(v, base, end):

    if v == 0:
        return "ZERO"

    if v <= 0xFFFF:
        return "SMALL"

    if base <= v < end:
        return "DA2_FILE_BACKED"

    # Conservative RAM window immediately after DA2.
    if end <= v < base + 0x40000:
        return "POST_DA2_RAM/BSS"

    if 0x10000000 <= v < 0x10100000:
        return "OTHER_0x100xxxxx"

    return "OTHER"


data = LOADER.read_bytes()

entry = parse_entry(
    data
)

assert entry["hw"] == 0x6261
assert entry["region_index"] == 2

r3 = entry["regions"][3]
r4 = entry["regions"][4]

DA2_FULL = region_blob(
    data,
    r3,
)

DA2 = DA2_FULL[
    :len(DA2_FULL) - r3["sig"]
]

DA3 = region_blob(
    data,
    r4,
)

DA2_BASE = r3["addr"]
DA2_END = (
    DA2_BASE
    + len(DA2)
)


lines = []


def log(s=""):
    print(s)
    lines.append(s)


log("=" * 120)
log("S12.9U - D5/D6 COMMAND-DESCRIPTOR FIELD / XREF AUDIT")
log("=" * 120)

log()
log("NO DEVICE ACCESS")
log("NO BROM")
log("NO DA UPLOAD")
log("NO JUMP DA")
log("NO WRITE")
log("NO ERASE")

log()
log(f"LOADER SHA256 = {sha256(data)}")
log(f"DA2 SHA256    = {sha256(DA2)}")
log(f"DA3 SHA256    = {sha256(DA3)}")

log()
log(
    f"DA2 runtime file-backed range = "
    f"0x{DA2_BASE:08X}..0x{DA2_END-1:08X}"
)

log(
    f"DA3 size = 0x{len(DA3):X}, "
    f"records = {len(DA3)//DESC_SIZE}"
)

assert len(DA3) % DESC_SIZE == 0


# =================================================================
# A. Parse all descriptors
# =================================================================

log()
log("=" * 120)
log("A. DA3 DESCRIPTOR TABLE")
log("=" * 120)

records = []

for i in range(
    len(DA3) // DESC_SIZE
):

    off = i * DESC_SIZE

    vals = struct.unpack_from(
        "<9I",
        DA3,
        off,
    )

    records.append({
        "index": i,
        "offset": off,
        "values": vals,
        "cmd": vals[0],
    })


cmd_map = {
    r["cmd"]: r
    for r in records
}


for cmd in range(
    0xD2,
    0xDA,
):

    if cmd not in cmd_map:
        log(
            f"0x{cmd:02X}: NOT FOUND"
        )
        continue

    r = cmd_map[cmd]

    log()
    log(
        f"0x{cmd:02X} "
        f"{COMMANDS.get(cmd, 'UNKNOWN')} "
        f"chunk={r['index']} "
        f"off=0x{r['offset']:04X}"
    )

    for col, v in enumerate(
        r["values"]
    ):

        off = col * 4

        cls = classify_addr(
            v,
            DA2_BASE,
            DA2_END,
        )

        log(
            f"  +0x{off:02X} "
            f"0x{v:08X} "
            f"{cls}"
        )


# =================================================================
# B. Explicit D5/D6 comparison
# =================================================================

log()
log("=" * 120)
log("B. D5 / D6 FIELD COMPARISON")
log("=" * 120)

d5 = cmd_map[0xD5]["values"]
d6 = cmd_map[0xD6]["values"]

for col in range(9):

    off = col * 4

    a = d5[col]
    b = d6[col]

    log(
        f"+0x{off:02X}: "
        f"D5=0x{a:08X} "
        f"D6=0x{b:08X} "
        f"{'SAME' if a == b else 'DIFF'}"
    )


# =================================================================
# C. Split likely packed fields
# =================================================================

log()
log("=" * 120)
log("C. D2-D9 +0x14 / +0x10 FIELD SPLIT")
log("=" * 120)

for cmd in range(
    0xD2,
    0xDA,
):

    if cmd not in cmd_map:
        continue

    vals = cmd_map[
        cmd
    ]["values"]

    v10 = vals[4]
    v14 = vals[5]

    log(
        f"0x{cmd:02X} "
        f"{COMMANDS.get(cmd,'UNKNOWN'):<12} "
        f"+10=0x{v10:08X} "
        f"[lo=0x{v10 & 0xFFFF:04X} "
        f"hi=0x{v10 >> 16:04X}] "
        f"+14=0x{v14:08X} "
        f"[lo=0x{v14 & 0xFFFF:04X} "
        f"hi=0x{v14 >> 16:04X}]"
    )


# =================================================================
# D. Which commands share D5/D6 field values?
# =================================================================

log()
log("=" * 120)
log("D. FIELD-VALUE SHARING ACROSS ALL 264 DESCRIPTORS")
log("=" * 120)

for label, values in (
    ("D5", d5),
    ("D6", d6),
):

    log()
    log(
        f"### {label}"
    )

    for col in range(
        1,
        9,
    ):

        value = values[col]

        shared = [
            r["cmd"]
            for r in records
            if r["values"][col]
            == value
        ]

        log(
            f"+0x{col*4:02X} "
            f"0x{value:08X}: "
            f"shared_by={len(shared)} "
            + ", ".join(
                f"0x{x:X}"
                for x in shared[:40]
            )
        )


# =================================================================
# E. Unique address-like values in D2-D9
# =================================================================

log()
log("=" * 120)
log("E. ADDRESS-LIKE FIELD TARGETS")
log("=" * 120)

targets = defaultdict(
    list
)

for cmd in range(
    0xD2,
    0xDA,
):

    if cmd not in cmd_map:
        continue

    vals = cmd_map[
        cmd
    ]["values"]

    for col in range(
        1,
        9,
    ):

        v = vals[col]

        cls = classify_addr(
            v,
            DA2_BASE,
            DA2_END,
        )

        if cls in (
            "DA2_FILE_BACKED",
            "POST_DA2_RAM/BSS",
            "OTHER_0x100xxxxx",
        ):

            targets[v].append(
                (
                    cmd,
                    col * 4,
                    cls,
                )
            )


for value in sorted(
    targets
):

    refs = targets[value]

    log()
    log(
        f"0x{value:08X}"
    )

    for cmd, field, cls in refs:

        log(
            f"  cmd=0x{cmd:02X} "
            f"{COMMANDS.get(cmd,'UNKNOWN'):<12} "
            f"field=+0x{field:02X} "
            f"{cls}"
        )


# =================================================================
# F. Exact literal words in DA2
# =================================================================

log()
log("=" * 120)
log("F. DA2 LITERAL-WORD OCCURRENCES")
log("=" * 120)

literal_offsets = defaultdict(
    list
)

for value in sorted(
    targets
):

    needle = struct.pack(
        "<I",
        value,
    )

    hits = find_all(
        DA2,
        needle,
    )

    literal_offsets[
        value
    ] = hits

    log(
        f"0x{value:08X}: "
        f"{len(hits)} hit(s) "
        + (
            ", ".join(
                f"+0x{x:X}"
                for x in hits[:40]
            )
            if hits
            else ""
        )
    )


# =================================================================
# G. Thumb16 LDR-literal -> descriptor-address xrefs
# =================================================================

log()
log("=" * 120)
log("G. THUMB16 LDR-LITERAL XREFS")
log("=" * 120)

literal_off_to_value = defaultdict(
    list
)

for value, offsets in literal_offsets.items():

    for off in offsets:

        literal_off_to_value[
            off
        ].append(
            value
        )


xrefs = []

for off in range(
    0,
    len(DA2) - 1,
    2,
):

    hw = u16(
        DA2,
        off,
    )

    # Thumb16 LDR Rt,[PC,#imm8*4]
    if (
        hw & 0xF800
    ) != 0x4800:
        continue

    rt = (
        hw >> 8
    ) & 7

    imm8 = (
        hw
        & 0xFF
    )

    runtime = (
        DA2_BASE
        + off
    )

    literal_runtime = (
        (
            runtime + 4
        )
        & ~3
    ) + imm8 * 4

    literal_off = (
        literal_runtime
        - DA2_BASE
    )

    if literal_off not in literal_off_to_value:
        continue

    for value in literal_off_to_value[
        literal_off
    ]:

        xrefs.append({
            "off": off,
            "runtime": runtime,
            "rt": rt,
            "literal_off": literal_off,
            "value": value,
        })


log(
    f"xref count = {len(xrefs)}"
)

for x in xrefs:

    refs = targets[
        x["value"]
    ]

    who = "; ".join(
        f"cmd 0x{cmd:02X} +0x{field:02X}"
        for cmd, field, cls
        in refs
    )

    log(
        f"DA2+0x{x['off']:05X} "
        f"runtime=0x{x['runtime']:08X} "
        f"LDR r{x['rt']} "
        f"literal=+0x{x['literal_off']:05X} "
        f"value=0x{x['value']:08X} "
        f"[{who}]"
    )


# =================================================================
# H. Xrefs specifically touching D5 / D6
# =================================================================

log()
log("=" * 120)
log("H. D5/D6-RELEVANT XREFS")
log("=" * 120)

d5d6_values = set()

for vals in (
    d5,
    d6,
):

    for col in range(
        1,
        9,
    ):

        v = vals[col]

        if classify_addr(
            v,
            DA2_BASE,
            DA2_END,
        ) in (
            "DA2_FILE_BACKED",
            "POST_DA2_RAM/BSS",
            "OTHER_0x100xxxxx",
        ):

            d5d6_values.add(v)


relevant_xrefs = [
    x
    for x in xrefs
    if x["value"]
    in d5d6_values
]

for x in relevant_xrefs:

    log(
        f"DA2+0x{x['off']:05X} "
        f"0x{x['runtime']:08X} "
        f"-> 0x{x['value']:08X}"
    )


# =================================================================
# I. Targeted disassembly
# =================================================================

log()
log("=" * 120)
log("I. TARGETED DISASSEMBLY AROUND D5/D6 XREFS")
log("=" * 120)

md = Cs(
    CS_ARCH_ARM,
    CS_MODE_THUMB
    | CS_MODE_LITTLE_ENDIAN,
)

md.skipdata = True

windows = set()

for x in relevant_xrefs[:60]:

    center = x["off"]

    start = max(
        0,
        center - 0x40,
    ) & ~1

    end = min(
        len(DA2),
        center + 0x60,
    )

    key = (
        start,
        end,
    )

    if key in windows:
        continue

    windows.add(key)

    log()
    log(
        f"WINDOW DA2+0x{start:X} "
        f"runtime=0x{DA2_BASE+start:08X}"
    )

    for ins in md.disasm(
        DA2[start:end],
        DA2_BASE + start,
    ):

        marker = ""

        if any(
            ins.address
            == y["runtime"]
            for y in relevant_xrefs
        ):
            marker = (
                "  <<< DESCRIPTOR GLOBAL XREF"
            )

        log(
            f"  {ins.address:08X}: "
            f"{ins.mnemonic:<9} "
            f"{ins.op_str}"
            f"{marker}"
        )


# =================================================================
# J. Address range / BSS assessment
# =================================================================

log()
log("=" * 120)
log("J. DA2 FILE-END vs DESCRIPTOR ADDRESSES")
log("=" * 120)

log(
    f"DA2 file-backed end = "
    f"0x{DA2_END:08X}"
)

for value in sorted(
    d5d6_values
):

    if value >= DA2_END:

        delta = (
            value
            - DA2_END
        )

        log(
            f"0x{value:08X} "
            f"is +0x{delta:X} "
            f"after DA2 file-backed end"
        )

    else:

        log(
            f"0x{value:08X} "
            f"is inside DA2 payload"
        )


# =================================================================
# K. Conclusion
# =================================================================

log()
log("=" * 120)
log("S12.9U RESULT")
log("=" * 120)

log(
    "D2-D9 0x24 DESCRIPTORS       : PASS"
)

log(
    "D5/D6 FIELD MAP              : PASS"
)

log(
    f"ADDRESS-LIKE VALUES           : "
    f"{len(targets)}"
)

log(
    f"DA2 LITERAL XREFS             : "
    f"{len(xrefs)}"
)

log(
    f"D5/D6 RELEVANT XREFS          : "
    f"{len(relevant_xrefs)}"
)

post_bss = [
    v
    for v in d5d6_values
    if v >= DA2_END
]

log(
    f"D5/D6 VALUES AFTER FILE END   : "
    f"{len(post_bss)}"
)

if post_bss:

    log(
        "STRONGLY SUPPORTED: at least part "
        "of the D5/D6 descriptor references "
        "post-image RAM/BSS rather than "
        "file-backed handler code."
    )

if relevant_xrefs:

    log(
        "RESULT: DA2 code contains direct "
        "literal-based references to D5/D6 "
        "descriptor RAM objects."
    )

else:

    log(
        "RESULT: no Thumb16 literal xrefs "
        "to D5/D6 descriptor addresses found."
    )

log()
log(
    "DEVICE ACCESS              : NO"
)

log(
    "DA UPLOAD                  : NO"
)

log(
    "DEVICE WRITE               : NO"
)

log(
    "DEVICE ERASE               : NO"
)

log(
    "FLASH AUTHORIZED           : NO"
)


REPORT.write_text(
    "\n".join(lines) + "\n",
    encoding="utf-8",
)

print()
print(
    "Report:",
    REPORT,
)
