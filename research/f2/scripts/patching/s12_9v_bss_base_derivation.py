#!/usr/bin/env python3

from pathlib import Path
from collections import defaultdict
from math import gcd
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
    / "s12_9v_bss_base_derivation.txt"
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
    p = 0

    while True:

        p = data.find(
            needle,
            p,
        )

        if p < 0:
            return out

        out.append(p)
        p += 1


def parse_entry(data):

    vals = struct.unpack_from(
        "<10H",
        data,
        DADA,
    )

    region_count = vals[9]

    regions = []

    p = DADA + 20

    for i in range(region_count):

        fields = struct.unpack_from(
            "<5I",
            data,
            p + i * 20,
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
        "region_index": vals[8],
        "regions": regions,
    }


def blob(data, r):
    return data[
        r["buf"]:
        r["buf"] + r["len"]
    ]


data = LOADER.read_bytes()
entry = parse_entry(data)

assert entry["hw"] == 0x6261
assert entry["region_index"] == 2

r3 = entry["regions"][3]
r4 = entry["regions"][4]

DA2_FULL = blob(
    data,
    r3,
)

DA2 = DA2_FULL[
    :len(DA2_FULL) - r3["sig"]
]

DA3 = blob(
    data,
    r4,
)

DA2_BASE = r3["addr"]
DA2_END = DA2_BASE + len(DA2)

# Conservative post-image RAM window.
BSS_START = DA2_END
BSS_END = 0x10050000


records = {}

for i in range(
    len(DA3) // DESC_SIZE
):

    vals = struct.unpack_from(
        "<9I",
        DA3,
        i * DESC_SIZE,
    )

    records[
        vals[0]
    ] = vals


targets = {
    "COMMON_08": 0x10043318,
    "COMMON_1C": 0x1004491C,
    "D5_SLOT":   0x10044950,
    "D6_SLOT":   0x10044990,
    "D3_SLOT":   0x100449D0,
    "D4_SLOT":   0x10044A10,
}


lines = []


def log(s=""):
    print(s)
    lines.append(s)


log("=" * 120)
log("S12.9V - DA2 POST-IMAGE RAM/BSS BASE DERIVATION")
log("=" * 120)

log()
log("NO DEVICE ACCESS")
log("NO BROM")
log("NO DA UPLOAD")
log("NO JUMP DA")
log("NO WRITE")
log("NO ERASE")

log()
log(f"loader SHA = {sha256(data)}")
log(f"DA2 SHA    = {sha256(DA2)}")
log(f"DA3 SHA    = {sha256(DA3)}")

log()
log(
    f"DA2 file-backed = "
    f"0x{DA2_BASE:08X}..0x{DA2_END-1:08X}"
)

log(
    f"BSS search      = "
    f"0x{BSS_START:08X}..0x{BSS_END-1:08X}"
)


# ================================================================
# A. +04 slot pattern
# ================================================================

log()
log("=" * 120)
log("A. D2-D8 +0x04 SLOT PATTERN")
log("=" * 120)

slot_cmds = []

for cmd in range(
    0xD2,
    0xD9,
):

    vals = records[cmd]

    ptr = vals[1]

    slot_cmds.append(
        (
            cmd,
            ptr,
        )
    )

    log(
        f"0x{cmd:02X} "
        f"{COMMANDS[cmd]:<12} "
        f"+04=0x{ptr:08X}"
    )


unique_slots = sorted(
    set(
        ptr
        for cmd, ptr
        in slot_cmds
    )
)

log()
log(
    "unique +04 pointers:"
)

for p in unique_slots:
    log(
        f"  0x{p:08X}"
    )


deltas = [
    unique_slots[i + 1]
    - unique_slots[i]
    for i in range(
        len(unique_slots) - 1
    )
]

if deltas:

    stride = deltas[0]

    for d in deltas[1:]:
        stride = gcd(
            stride,
            d,
        )

else:
    stride = 0


log()
log(
    f"GCD stride = 0x{stride:X}"
)


slot_base = min(
    unique_slots
)

log(
    f"slot base  = 0x{slot_base:08X}"
)

for cmd, ptr in slot_cmds:

    if stride:

        slot = (
            ptr - slot_base
        ) // stride

    else:
        slot = -1

    log(
        f"  cmd 0x{cmd:02X} "
        f"{COMMANDS[cmd]:<12} "
        f"slot={slot}"
    )


# ================================================================
# B. Four-halfword metadata
# ================================================================

log()
log("=" * 120)
log("B. D2-D9 HALFWORD METADATA")
log("=" * 120)

for cmd in range(
    0xD2,
    0xDA,
):

    vals = records[cmd]

    raw = struct.pack(
        "<II",
        vals[4],
        vals[5],
    )

    h = struct.unpack(
        "<4H",
        raw,
    )

    log(
        f"0x{cmd:02X} "
        f"{COMMANDS[cmd]:<12} "
        f"{h[0]:04X} "
        f"{h[1]:04X} "
        f"{h[2]:04X} "
        f"{h[3]:04X}"
    )


# ================================================================
# C. All literal words into post-image RAM/BSS
# ================================================================

log()
log("=" * 120)
log("C. POST-IMAGE RAM/BSS LITERAL WORDS IN DA2")
log("=" * 120)

bss_literals = defaultdict(
    list
)

for off in range(
    0,
    len(DA2) - 3,
    4,
):

    v = u32(
        DA2,
        off,
    )

    if (
        BSS_START
        <= v
        < BSS_END
    ):

        bss_literals[
            v
        ].append(
            off
        )


log(
    f"unique BSS-like literal values = "
    f"{len(bss_literals)}"
)

log(
    f"literal word occurrences       = "
    f"{sum(len(x) for x in bss_literals.values())}"
)


# ================================================================
# D. Nearest literal bases to target addresses
# ================================================================

log()
log("=" * 120)
log("D. NEAREST BSS LITERAL BASES")
log("=" * 120)

literal_values = sorted(
    bss_literals
)

for name, target in targets.items():

    log()
    log(
        f"{name}: 0x{target:08X}"
    )

    candidates = []

    for v in literal_values:

        delta = (
            target - v
        )

        if abs(delta) <= 0x2000:

            candidates.append(
                (
                    abs(delta),
                    delta,
                    v,
                )
            )

    candidates.sort()

    if not candidates:
        log(
            "  no BSS literal within +/-0x2000"
        )
        continue

    for _, delta, v in candidates[:20]:

        log(
            f"  base=0x{v:08X} "
            f"delta={delta:+#x} "
            f"literal_offs="
            + ",".join(
                f"0x{x:X}"
                for x in bss_literals[v][:12]
            )
        )


# ================================================================
# E. Explicit page/base candidates
# ================================================================

log()
log("=" * 120)
log("E. ALIGNED BASE-CANDIDATE SEARCH")
log("=" * 120)

candidate_bases = set()

for target in targets.values():

    for alignment in (
        0x10,
        0x20,
        0x40,
        0x80,
        0x100,
        0x200,
        0x400,
        0x800,
        0x1000,
        0x2000,
        0x4000,
    ):

        base = (
            target
            & ~(alignment - 1)
        )

        candidate_bases.add(
            base
        )


for base in sorted(
    candidate_bases
):

    hits = find_all(
        DA2,
        struct.pack(
            "<I",
            base,
        ),
    )

    if not hits:
        continue

    log(
        f"0x{base:08X}: "
        f"{len(hits)} hit(s) "
        + ", ".join(
            f"+0x{x:X}"
            for x in hits[:40]
        )
    )


# ================================================================
# F. Resolve Thumb16 LDR-literal xrefs to all BSS literals
# ================================================================

log()
log("=" * 120)
log("F. THUMB16 XREFS TO BSS-BASE LITERALS")
log("=" * 120)

off_to_values = defaultdict(
    list
)

for value, offs in bss_literals.items():

    for off in offs:

        off_to_values[
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

    # Thumb16 LDR literal.
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

    lit_runtime = (
        (
            runtime + 4
        )
        & ~3
    ) + imm8 * 4

    lit_off = (
        lit_runtime
        - DA2_BASE
    )

    if lit_off not in off_to_values:
        continue

    for value in off_to_values[
        lit_off
    ]:

        xrefs.append({
            "off": off,
            "runtime": runtime,
            "rt": rt,
            "literal_off": lit_off,
            "value": value,
        })


log(
    f"xref count = {len(xrefs)}"
)

for x in xrefs[:300]:

    interesting = []

    for name, target in targets.items():

        delta = (
            target
            - x["value"]
        )

        if abs(delta) <= 0x1000:

            interesting.append(
                f"{name}:{delta:+#x}"
            )

    suffix = ""

    if interesting:

        suffix = (
            " <<< "
            + ", ".join(
                interesting
            )
        )

    log(
        f"DA2+0x{x['off']:05X} "
        f"runtime=0x{x['runtime']:08X} "
        f"LDR r{x['rt']} "
        f"literal=+0x{x['literal_off']:05X} "
        f"value=0x{x['value']:08X}"
        f"{suffix}"
    )


# ================================================================
# G. Targeted disassembly around useful BSS-base xrefs
# ================================================================

log()
log("=" * 120)
log("G. DISASSEMBLY AROUND NEAR-TARGET BSS XREFS")
log("=" * 120)

md = Cs(
    CS_ARCH_ARM,
    CS_MODE_THUMB
    | CS_MODE_LITTLE_ENDIAN,
)

md.skipdata = True

useful = []

for x in xrefs:

    if any(
        abs(
            target - x["value"]
        )
        <= 0x1000
        for target
        in targets.values()
    ):

        useful.append(
            x
        )


log(
    f"useful xrefs = {len(useful)}"
)


seen = set()

for x in useful[:80]:

    start = max(
        0,
        x["off"] - 0x30,
    ) & ~1

    end = min(
        len(DA2),
        x["off"] + 0x60,
    )

    key = (
        start,
        end,
    )

    if key in seen:
        continue

    seen.add(key)

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
            for y in useful
        ):

            marker = (
                "  <<< BSS BASE LITERAL XREF"
            )

        log(
            f"  {ins.address:08X}: "
            f"{ins.mnemonic:<9} "
            f"{ins.op_str}"
            f"{marker}"
        )


# ================================================================
# H. Slot-array structural test
# ================================================================

log()
log("=" * 120)
log("H. SLOT-ARRAY STRUCTURAL TEST")
log("=" * 120)

expected = {
    0xD5: 0,
    0xD2: 1,
    0xD6: 1,
    0xD3: 2,
    0xD7: 2,
    0xD4: 3,
    0xD8: 3,
}

slot_pass = True

for cmd, expected_slot in expected.items():

    ptr = records[
        cmd
    ][1]

    actual = (
        ptr - 0x10044950
    ) // 0x40

    ok = (
        ptr
        == 0x10044950
        + expected_slot * 0x40
    )

    slot_pass &= ok

    log(
        f"cmd 0x{cmd:02X} "
        f"{COMMANDS[cmd]:<12} "
        f"slot={actual} "
        f"{'PASS' if ok else 'FAIL'}"
    )


log()
log(
    "0x40 SLOT ARRAY MODEL : "
    + (
        "PASS"
        if slot_pass
        else "FAIL"
    )
)


# ================================================================
# I. Final status
# ================================================================

log()
log("=" * 120)
log("S12.9V RESULT")
log("=" * 120)

log(
    f"BSS LITERAL VALUES FOUND      : "
    f"{len(bss_literals)}"
)

log(
    f"BSS LITERAL XREFS FOUND       : "
    f"{len(xrefs)}"
)

log(
    f"NEAR-TARGET USEFUL XREFS      : "
    f"{len(useful)}"
)

log(
    "D2-D8 0x40 SLOT MODEL         : "
    + (
        "PASS"
        if slot_pass
        else "FAIL"
    )
)

log()

if slot_pass:

    log(
        "STRONGLY SUPPORTED: "
        "+0x04 is a pointer into a "
        "0x40-stride post-image RAM slot array."
    )

if useful:

    log(
        "RESULT: DA2 contains code references "
        "to nearby BSS bases from which "
        "descriptor addresses may be derived."
    )

else:

    log(
        "RESULT: no nearby literal-base xrefs "
        "were resolved with this Thumb16 method."
    )

log()
log("DEVICE ACCESS              : NO")
log("DA UPLOAD                  : NO")
log("DEVICE WRITE               : NO")
log("DEVICE ERASE               : NO")
log("FLASH AUTHORIZED           : NO")


REPORT.write_text(
    "\n".join(lines) + "\n",
    encoding="utf-8",
)

print()
print(
    "Report:",
    REPORT,
)
