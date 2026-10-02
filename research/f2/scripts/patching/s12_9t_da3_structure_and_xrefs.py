#!/usr/bin/env python3

from pathlib import Path
import hashlib
import struct
import re

from capstone import (
    Cs,
    CS_ARCH_ARM,
    CS_MODE_THUMB,
    CS_MODE_LITTLE_ENDIAN,
)


ROOT = Path(r"C:\Users\verto\F2-Altice-MobiWire")
MTK  = Path(r"C:\Users\verto\mtkclient")

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
    / "s12_9t_da3_structure_and_xrefs.txt"
)

DADA = 0x2718
CHUNK = 0x24

CMDS = {
    0xD3: "MEM",
    0xD4: "FORMAT",
    0xD5: "WRITE",
    0xD6: "READ",
    0xD7: "CMD_D7",
}

IDS = {
    "C22536": bytes.fromhex("C2 25 36"),
    "EF4016": bytes.fromhex("EF 40 16"),
    "C22016": bytes.fromhex("C2 20 16"),
    "EF7016": bytes.fromhex("EF 70 16"),
    "C86016": bytes.fromhex("C8 60 16"),
    "C22538": bytes.fromhex("C2 25 38"),
}

KEY_STRINGS = [
    b"S_DA_FLASH_RECOVERY_BUF_NOT_ENOUGH",
    b"backup data(): 0x%x, erase_blk_len(0x%x)",
    b"UpdateFlashBySectorBoundary()",
    b"S_SF_FLASH_BOOT",
    b"GFH_CMEM_ID_INFO_v1 flash id is not match with target SF !!",
    b"GFH_CMEM_ID_INFO_v1 flash id is not match with target SF2 !!",
]


def sha256(b):
    return hashlib.sha256(b).hexdigest()


def find_all(data, needle):
    out = []
    p = 0

    while True:
        p = data.find(needle, p)

        if p < 0:
            return out

        out.append(p)
        p += 1


def u32(data, off):
    return struct.unpack_from("<I", data, off)[0]


def parse_entry(data):
    vals = struct.unpack_from(
        "<10H",
        data,
        DADA,
    )

    region_index = vals[8]
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
        "region_index": region_index,
        "region_count": region_count,
        "regions": regions,
    }


def get_blob(data, region):
    return data[
        region["buf"]:
        region["buf"] + region["len"]
    ]


def jedec_variants(raw):
    """
    Generate plausible encodings of:
        manufacturer byte + 16-bit device ID.
    """

    mfr = raw[0]
    dev_be = (
        raw[1] << 8
        | raw[2]
    )

    variants = {}

    def add(name, b):
        if b not in variants.values():
            variants[name] = b

    add("raw-u24", raw)
    add("reverse-u24", raw[::-1])

    add(
        "00+raw",
        b"\x00" + raw,
    )

    add(
        "raw+00",
        raw + b"\x00",
    )

    add(
        "00+reverse",
        b"\x00" + raw[::-1],
    )

    add(
        "reverse+00",
        raw[::-1] + b"\x00",
    )

    add(
        "u32-le-id",
        struct.pack(
            "<I",
            int.from_bytes(
                raw,
                "big",
            ),
        ),
    )

    add(
        "u32-be-id",
        struct.pack(
            ">I",
            int.from_bytes(
                raw,
                "big",
            ),
        ),
    )

    # Manufacturer represented as uint16,
    # device represented as uint16.
    add(
        "mfrLE-devLE",
        struct.pack("<H", mfr)
        + struct.pack("<H", dev_be),
    )

    add(
        "mfrBE-devBE",
        struct.pack(">H", mfr)
        + struct.pack(">H", dev_be),
    )

    add(
        "mfrLE-devBE",
        struct.pack("<H", mfr)
        + struct.pack(">H", dev_be),
    )

    add(
        "mfrBE-devLE",
        struct.pack(">H", mfr)
        + struct.pack("<H", dev_be),
    )

    # Common 3-byte mixed layouts.
    add(
        "mfr-devLE",
        bytes([
            mfr,
            raw[2],
            raw[1],
        ]),
    )

    add(
        "devBE-mfr",
        bytes([
            raw[1],
            raw[2],
            mfr,
        ]),
    )

    add(
        "devLE-mfr",
        bytes([
            raw[2],
            raw[1],
            mfr,
        ]),
    )

    return variants


def hexdump(data):
    return " ".join(
        f"{x:02X}"
        for x in data
    )


data = LOADER.read_bytes()
entry = parse_entry(data)

assert entry["hw"] == 0x6261
assert entry["region_index"] == 2

r2 = entry["regions"][2]
r3 = entry["regions"][3]
r4 = entry["regions"][4]
r5 = entry["regions"][5]

DA1 = get_blob(data, r2)
DA2 = get_blob(data, r3)
DA3 = get_blob(data, r4)
R5  = get_blob(data, r5)

# Remove signatures only from DA1/DA2.
DA1_PAY = DA1[:-r2["sig"]]
DA2_PAY = DA2[:-r3["sig"]]


lines = []


def log(s=""):
    print(s)
    lines.append(s)


log("=" * 120)
log("S12.9T - DA3 STRUCTURE / JEDEC ENCODING / DA2 XREF AUDIT")
log("=" * 120)

log()
log("NO DEVICE ACCESS")
log("NO BROM")
log("NO DA UPLOAD")
log("NO JUMP DA")
log("NO WRITE")
log("NO ERASE")


# ==================================================================
# A. Identity
# ==================================================================

log()
log("=" * 120)
log("A. INPUT IDENTITY")
log("=" * 120)

log(f"loader SHA256 = {sha256(data)}")
log(f"DA1 payload   = {sha256(DA1_PAY)}")
log(f"DA2 payload   = {sha256(DA2_PAY)}")
log(f"DA3           = {sha256(DA3)}")
log(f"R5            = {sha256(R5)}")

log()
log(f"DA3 size      = 0x{len(DA3):X}")
log(f"chunk size    = 0x{CHUNK:X}")
log(f"chunk count   = {len(DA3) // CHUNK}")
log(f"remainder     = 0x{len(DA3) % CHUNK:X}")

assert len(DA3) % CHUNK == 0


# ==================================================================
# B. Exact D3-D7 dword locations in DA3
# ==================================================================

log()
log("=" * 120)
log("B. DA3 D3-D7 DWORD LOCATIONS")
log("=" * 120)

cmd_locations = {}

for cmd, name in CMDS.items():

    needle = struct.pack(
        "<I",
        cmd,
    )

    hits = find_all(
        DA3,
        needle,
    )

    cmd_locations[cmd] = hits

    log()
    log(
        f"0x{cmd:02X} {name}: "
        f"{len(hits)} hit(s)"
    )

    for off in hits:

        chunk = off // CHUNK
        intra = off % CHUNK

        log(
            f"  DA3+0x{off:04X} "
            f"chunk={chunk:03d} "
            f"intra=0x{intra:02X}"
        )


# ==================================================================
# C. Dump chunks containing commands
# ==================================================================

log()
log("=" * 120)
log("C. COMMAND-CONTAINING 0x24 CHUNKS")
log("=" * 120)

interesting_chunks = sorted(
    set(
        off // CHUNK
        for hits in cmd_locations.values()
        for off in hits
    )
)

for ci in interesting_chunks:

    start = ci * CHUNK
    chunk = DA3[
        start:
        start + CHUNK
    ]

    dwords = struct.unpack(
        "<9I",
        chunk,
    )

    log()
    log(
        f"CHUNK {ci:03d} "
        f"DA3+0x{start:04X}"
    )

    log(
        "  raw : "
        + hexdump(chunk)
    )

    for i, v in enumerate(dwords):

        marker = ""

        if v in CMDS:
            marker = (
                f" <<< {CMDS[v]}"
            )

        log(
            f"  +0x{i*4:02X}: "
            f"0x{v:08X}"
            f"{marker}"
        )


# ==================================================================
# D. Neighbor chunks around command structures
# ==================================================================

log()
log("=" * 120)
log("D. COMMAND NEIGHBORHOOD")
log("=" * 120)

neighbors = sorted(
    set(
        n
        for ci in interesting_chunks
        for n in range(
            max(0, ci - 2),
            min(
                len(DA3) // CHUNK,
                ci + 3,
            ),
        )
    )
)

for ci in neighbors:

    start = ci * CHUNK
    chunk = DA3[
        start:
        start + CHUNK
    ]

    vals = struct.unpack(
        "<9I",
        chunk,
    )

    log(
        f"chunk {ci:03d} "
        f"+0x{start:04X}: "
        + " ".join(
            f"{x:08X}"
            for x in vals
        )
    )


# ==================================================================
# E. Column statistics across all 0x24 chunks
# ==================================================================

log()
log("=" * 120)
log("E. DA3 0x24-CHUNK COLUMN STATISTICS")
log("=" * 120)

columns = [
    []
    for _ in range(9)
]

for ci in range(
    len(DA3) // CHUNK
):

    chunk = DA3[
        ci * CHUNK:
        (ci + 1) * CHUNK
    ]

    vals = struct.unpack(
        "<9I",
        chunk,
    )

    for col, v in enumerate(vals):
        columns[col].append(v)


from collections import Counter

for col, vals in enumerate(columns):

    counter = Counter(vals)

    small = [
        (v, n)
        for v, n in counter.items()
        if v <= 0xFFFF
    ]

    small.sort(
        key=lambda x: (
            -x[1],
            x[0],
        )
    )

    log()
    log(
        f"column +0x{col*4:02X}: "
        f"unique={len(counter)} "
        f"small<=FFFF={len(small)}"
    )

    for v, n in small[:20]:

        marker = (
            f" {CMDS[v]}"
            if v in CMDS
            else ""
        )

        log(
            f"  0x{v:08X} "
            f"x{n}{marker}"
        )


# ==================================================================
# F. Multi-encoding JEDEC search
# ==================================================================

log()
log("=" * 120)
log("F. MULTI-ENCODING JEDEC SEARCH")
log("=" * 120)

targets = {
    "DA1": DA1_PAY,
    "DA2": DA2_PAY,
    "DA3": DA3,
    "R5": R5,
}

jedec_matches = []

for label, raw in IDS.items():

    log()
    log(
        f"### {label} ({raw.hex().upper()})"
    )

    variants = jedec_variants(
        raw
    )

    found_for_id = 0

    for vname, pattern in variants.items():

        hits_any = []

        for target_name, blob in targets.items():

            hits = find_all(
                blob,
                pattern,
            )

            if not hits:
                continue

            found_for_id += len(hits)

            for off in hits:

                extra = ""

                if target_name == "DA3":

                    extra = (
                        f" chunk={off//CHUNK}"
                        f" intra=0x{off%CHUNK:X}"
                    )

                hits_any.append(
                    (
                        target_name,
                        off,
                        extra,
                    )
                )

                jedec_matches.append({
                    "id": label,
                    "variant": vname,
                    "target": target_name,
                    "offset": off,
                })

        if hits_any:

            log(
                f"  {vname:<16} "
                f"{pattern.hex(' ').upper()}"
            )

            for (
                target_name,
                off,
                extra,
            ) in hits_any[:40]:

                log(
                    f"    {target_name}"
                    f"+0x{off:X}"
                    f"{extra}"
                )

    if found_for_id == 0:

        log(
            "  no supported encoding found"
        )


# ==================================================================
# G. DA2 key strings + runtime addresses
# ==================================================================

log()
log("=" * 120)
log("G. DA2 RECOVERY/SF STRING MAP")
log("=" * 120)

DA2_BASE = r3["addr"]

string_info = []

for needle in KEY_STRINGS:

    hits = find_all(
        DA2_PAY,
        needle,
    )

    log()
    log(
        needle.decode(
            "ascii",
            errors="replace",
        )
    )

    if not hits:

        log("  NOT FOUND")
        continue

    for off in hits:

        runtime = (
            DA2_BASE + off
        )

        ptr_bytes = struct.pack(
            "<I",
            runtime,
        )

        ptr_hits = find_all(
            DA2_PAY,
            ptr_bytes,
        )

        log(
            f"  string off=0x{off:X} "
            f"runtime=0x{runtime:08X}"
        )

        log(
            "  literal pointer words: "
            + (
                ", ".join(
                    f"+0x{x:X}"
                    for x in ptr_hits
                )
                if ptr_hits
                else "NONE"
            )
        )

        string_info.append({
            "needle": needle,
            "string_off": off,
            "runtime": runtime,
            "ptr_hits": ptr_hits,
        })


# ==================================================================
# H. Thumb16 LDR-literal xrefs to those string pointers
# ==================================================================

log()
log("=" * 120)
log("H. THUMB16 LDR-LITERAL XREFS")
log("=" * 120)

pointer_word_offsets = {}

for item in string_info:

    for p in item["ptr_hits"]:

        pointer_word_offsets.setdefault(
            p,
            [],
        ).append(item)


xrefs = []

for off in range(
    0,
    len(DA2_PAY) - 1,
    2,
):

    hw = struct.unpack_from(
        "<H",
        DA2_PAY,
        off,
    )[0]

    # Thumb16 LDR literal:
    # 01001 Rt imm8
    if (
        hw & 0xF800
    ) != 0x4800:
        continue

    rt = (
        hw >> 8
    ) & 7

    imm8 = hw & 0xFF

    ins_runtime = (
        DA2_BASE + off
    )

    literal_runtime = (
        (
            ins_runtime + 4
        )
        & ~3
    ) + imm8 * 4

    literal_off = (
        literal_runtime
        - DA2_BASE
    )

    if literal_off not in pointer_word_offsets:
        continue

    for item in pointer_word_offsets[
        literal_off
    ]:

        xrefs.append({
            "ins_off": off,
            "ins_runtime": ins_runtime,
            "rt": rt,
            "literal_off": literal_off,
            "string": item,
        })


log(
    f"xref count = {len(xrefs)}"
)

for x in xrefs:

    text = x["string"]["needle"].decode(
        "ascii",
        errors="replace",
    )

    log(
        f"DA2+0x{x['ins_off']:05X} "
        f"runtime=0x{x['ins_runtime']:08X} "
        f"LDR r{x['rt']} -> literal "
        f"+0x{x['literal_off']:05X} -> "
        f"{text}"
    )


# ==================================================================
# I. Targeted disassembly around xrefs
# ==================================================================

log()
log("=" * 120)
log("I. TARGETED DISASSEMBLY AROUND RECOVERY/SF XREFS")
log("=" * 120)

md = Cs(
    CS_ARCH_ARM,
    CS_MODE_THUMB
    | CS_MODE_LITTLE_ENDIAN,
)

md.skipdata = True

seen_windows = set()

for x in xrefs[:40]:

    center = x["ins_off"]

    start = max(
        0,
        center - 0x40,
    ) & ~1

    end = min(
        len(DA2_PAY),
        center + 0x60,
    )

    key = (
        start,
        end,
    )

    if key in seen_windows:
        continue

    seen_windows.add(key)

    log()
    log(
        f"WINDOW DA2+0x{start:X} "
        f"runtime=0x{DA2_BASE+start:08X}"
    )

    for ins in md.disasm(
        DA2_PAY[start:end],
        DA2_BASE + start,
    ):

        marker = ""

        if ins.address == x["ins_runtime"]:
            marker = "  <<< STRING XREF"

        log(
            f"  {ins.address:08X}: "
            f"{ins.mnemonic:<9} "
            f"{ins.op_str}"
            f"{marker}"
        )


# ==================================================================
# J. Classification
# ==================================================================

log()
log("=" * 120)
log("S12.9T RESULT")
log("=" * 120)

log(
    f"DA3 0x24 CHUNKS            : "
    f"{len(DA3)//CHUNK}"
)

log(
    f"D3-D7 DWORD UNIQUE         : "
    + (
        "PASS"
        if all(
            len(cmd_locations[c]) == 1
            for c in CMDS
        )
        else "NO"
    )
)

log(
    f"JEDEC TRANSFORM MATCHES    : "
    f"{len(jedec_matches)}"
)

log(
    f"RECOVERY/SF STRING XREFS   : "
    f"{len(xrefs)}"
)

log()

if all(
    len(cmd_locations[c]) == 1
    for c in CMDS
):

    log(
        "FACT: DA3 contains exactly one "
        "32-bit occurrence of each D3-D7 command value."
    )

if jedec_matches:

    log(
        "RESULT: at least one Altice JEDEC ID "
        "has a non-trivial encoded representation "
        "inside DA1/DA2/DA3/R5."
    )

else:

    log(
        "RESULT: no tested JEDEC encoding was found."
    )

if xrefs:

    log(
        "RESULT: DA2 code references recovery/SF "
        "diagnostic strings through resolved Thumb literals."
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
