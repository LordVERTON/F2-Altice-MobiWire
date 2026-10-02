#!/usr/bin/env python3

from pathlib import Path
import hashlib
import json
import re
import struct

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

OUTDIR = (
    ROOT
    / "research"
    / "f2"
    / "work"
    / "repro"
    / "s12_9s_mt6261_da"
)

REPORT = (
    ROOT
    / "research"
    / "f2"
    / "work"
    / "repro"
    / "s12_9s_mt6261_da_audit.txt"
)

MANIFEST = OUTDIR / "manifest.json"

DADA_OFFSET = 0x2718

ALTICE_IDS = [
    ("C22536", bytes.fromhex("C2 25 36")),
    ("EF4016", bytes.fromhex("EF 40 16")),
    ("C22016", bytes.fromhex("C2 20 16")),
    ("EF7016", bytes.fromhex("EF 70 16")),
    ("C86016", bytes.fromhex("C8 60 16")),
    ("C22538", bytes.fromhex("C2 25 38")),
]

COMMANDS = {
    0xD3: "MEM",
    0xD4: "FORMAT",
    0xD5: "WRITE",
    0xD6: "READ",
    0xD7: "CMD_D7",
}

KEYWORDS = (
    "nor",
    "nand",
    "emmc",
    "flash",
    "serial",
    "sector",
    "erase",
    "write",
    "read",
    "fat",
    "nvd",
)


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def find_all(data, needle):
    result = []
    pos = 0

    while True:
        pos = data.find(needle, pos)

        if pos < 0:
            return result

        result.append(pos)
        pos += 1


def ascii_strings(data, minimum=5):
    rx = rb"[ -~]{%d,}" % minimum

    for m in re.finditer(rx, data):
        yield (
            m.start(),
            m.group().decode(
                "ascii",
                errors="replace",
            ),
        )


def parse_da_entry(data, off):
    vals = struct.unpack_from(
        "<10H",
        data,
        off,
    )

    (
        magic,
        hw_code,
        hw_sub,
        hw_ver,
        sw_ver,
        reserved1,
        pagesize,
        reserved3,
        region_index,
        region_count,
    ) = vals

    regions = []

    p = off + 20

    for i in range(region_count):

        (
            m_buf,
            m_len,
            m_start_addr,
            m_start_offset,
            m_sig_len,
        ) = struct.unpack_from(
            "<5I",
            data,
            p + i * 20,
        )

        regions.append({
            "index": i,
            "m_buf": m_buf,
            "m_len": m_len,
            "m_start_addr": m_start_addr,
            "m_start_offset": m_start_offset,
            "m_sig_len": m_sig_len,
        })

    return {
        "magic": magic,
        "hw_code": hw_code,
        "hw_sub": hw_sub,
        "hw_ver": hw_ver,
        "sw_ver": sw_ver,
        "pagesize": pagesize,
        "region_index": region_index,
        "region_count": region_count,
        "regions": regions,
    }


def thumb_cmp_hits(data):
    hits = []

    # Thumb16:
    # CMP Rn,#imm8
    # 00101 Rn imm8

    for off in range(
        0,
        len(data) - 1,
        2,
    ):

        hw = struct.unpack_from(
            "<H",
            data,
            off,
        )[0]

        if (hw & 0xF800) != 0x2800:
            continue

        rn = (
            hw >> 8
        ) & 7

        imm = hw & 0xFF

        if imm in COMMANDS:

            hits.append({
                "offset": off,
                "rn": rn,
                "imm": imm,
                "name": COMMANDS[imm],
                "halfword": hw,
            })

    return hits


def command_clusters(hits):
    clusters = []

    by_reg = {}

    for h in hits:
        by_reg.setdefault(
            h["rn"],
            [],
        ).append(h)

    for rn, hs in by_reg.items():

        hs.sort(
            key=lambda x: x["offset"]
        )

        for i in range(len(hs)):

            group = [
                hs[i]
            ]

            for j in range(
                i + 1,
                len(hs),
            ):

                if (
                    hs[j]["offset"]
                    - group[-1]["offset"]
                    > 0x40
                ):
                    break

                group.append(
                    hs[j]
                )

            values = {
                h["imm"]
                for h in group
            }

            if (
                0xD5 in values
                and 0xD6 in values
            ):

                clusters.append({
                    "rn": rn,
                    "hits": group,
                })

    # Deduplicate equivalent starts.
    unique = []
    seen = set()

    for c in clusters:

        key = (
            c["rn"],
            tuple(
                (
                    x["offset"],
                    x["imm"],
                )
                for x in c["hits"]
            ),
        )

        if key in seen:
            continue

        seen.add(key)
        unique.append(c)

    return unique


OUTDIR.mkdir(
    parents=True,
    exist_ok=True,
)

data = LOADER.read_bytes()

entry = parse_da_entry(
    data,
    DADA_OFFSET,
)


lines = []


def log(s=""):
    print(s)
    lines.append(s)


log("=" * 120)
log("S12.9S - EXTRACT + AUDIT EXACT LOCAL MT6261 DA")
log("=" * 120)

log()
log("NO DEVICE ACCESS")
log("NO BROM")
log("NO DA UPLOAD")
log("NO JUMP DA")
log("NO WRITE")
log("NO ERASE")

log()
log("LOADER")
log("-" * 120)
log(f"path   = {LOADER}")
log(f"size   = 0x{len(data):X}")
log(f"sha256 = {sha256(data)}")


# ================================================================
# A. Exact DADA validation
# ================================================================

log()
log("=" * 120)
log("A. MT6261 DADA ENTRY")
log("=" * 120)

log(
    f"offset = 0x{DADA_OFFSET:X}"
)

log(
    f"magic  = 0x{entry['magic']:04X}"
)

log(
    f"hw     = 0x{entry['hw_code']:04X}"
)

log(
    f"sub    = 0x{entry['hw_sub']:04X}"
)

log(
    f"hwver  = 0x{entry['hw_ver']:04X}"
)

log(
    f"swver  = 0x{entry['sw_ver']:04X}"
)

log(
    f"pagesize field = 0x{entry['pagesize']:X}"
)

log(
    f"entry_region_index = "
    f"{entry['region_index']}"
)

log(
    f"entry_region_count = "
    f"{entry['region_count']}"
)

assert entry["magic"] == 0xDADA
assert entry["hw_code"] == 0x6261
assert entry["region_index"] == 2
assert entry["region_count"] == 6

log("MT6261 entry identity : PASS")


# ================================================================
# B. Extract regions
# ================================================================

log()
log("=" * 120)
log("B. REGION EXTRACTION")
log("=" * 120)

extracted = {}

for r in entry["regions"]:

    start = r["m_buf"]
    end = start + r["m_len"]

    valid = (
        r["m_len"] > 0
        and start < len(data)
        and end <= len(data)
    )

    log()
    log(
        f"region[{r['index']}]"
    )

    log(
        f"  buf          = 0x{start:08X}"
    )

    log(
        f"  len          = 0x{r['m_len']:08X}"
    )

    log(
        f"  load address = 0x{r['m_start_addr']:08X}"
    )

    log(
        f"  start_offset = 0x{r['m_start_offset']:08X}"
    )

    log(
        f"  sig_len      = 0x{r['m_sig_len']:X}"
    )

    log(
        f"  file valid   = "
        f"{'YES' if valid else 'NO'}"
    )

    if not valid:
        continue

    blob = data[start:end]

    name = (
        f"region{r['index']}_"
        f"{r['m_start_addr']:08X}.bin"
    )

    path = OUTDIR / name
    path.write_bytes(blob)

    payload_len = (
        len(blob)
        - r["m_sig_len"]
    )

    payload = blob[
        :payload_len
    ]

    sig = blob[
        payload_len:
    ]

    payload_path = (
        OUTDIR
        / (
            f"region{r['index']}_"
            f"{r['m_start_addr']:08X}_payload.bin"
        )
    )

    payload_path.write_bytes(
        payload
    )

    if sig:

        sig_path = (
            OUTDIR
            / (
                f"region{r['index']}_"
                f"{r['m_start_addr']:08X}_signature.bin"
            )
        )

        sig_path.write_bytes(
            sig
        )

    extracted[
        r["index"]
    ] = {
        "meta": r,
        "blob": blob,
        "payload": payload,
        "signature": sig,
        "path": path,
    }

    log(
        f"  SHA256 full    = "
        f"{sha256(blob)}"
    )

    log(
        f"  payload length = "
        f"0x{len(payload):X}"
    )

    log(
        f"  SHA256 payload = "
        f"{sha256(payload)}"
    )

    if sig:

        log(
            f"  SHA256 sig     = "
            f"{sha256(sig)}"
        )

    if r["m_sig_len"]:

        expected_unsigned = (
            r["m_len"]
            - r["m_sig_len"]
        )

        log(
            "  start_offset == len-sig : "
            + (
                "PASS"
                if r["m_start_offset"]
                == expected_unsigned
                else "NO"
            )
        )


# ================================================================
# C. Stage classification
# ================================================================

log()
log("=" * 120)
log("C. MT6261 STAGE CLASSIFICATION")
log("=" * 120)

stage1 = entry["region_index"]
stage2 = stage1 + 1
stage3 = stage1 + 2
stage4 = stage1 + 3

for idx, label in (
    (stage1, "DA1"),
    (stage2, "DA2"),
    (stage3, "DA3 / CHIP DATA"),
    (stage4, "REGION5 / AUX DATA"),
):

    r = entry["regions"][idx]

    log(
        f"{label:<22} "
        f"region={idx} "
        f"load=0x{r['m_start_addr']:08X} "
        f"len=0x{r['m_len']:X} "
        f"sig=0x{r['m_sig_len']:X}"
    )


# ================================================================
# D. Exact Altice JEDEC-ID search
# ================================================================

log()
log("=" * 120)
log("D. ALTICE F2 SIX-JEDEC-ID SEARCH")
log("=" * 120)

jedec_results = {}

targets = {
    "FULL_LOADER": data,
}

for idx, info in extracted.items():

    targets[
        f"REGION{idx}"
    ] = info["blob"]


for target_name, blob in targets.items():

    log()
    log(
        f"### {target_name}"
    )

    present = 0
    per_target = {}

    for label, chip_id in ALTICE_IDS:

        direct = find_all(
            blob,
            chip_id,
        )

        reverse = find_all(
            blob,
            chip_id[::-1],
        )

        if direct:
            present += 1

        per_target[label] = {
            "direct": direct,
            "reverse": reverse,
        }

        log(
            f"{label}: "
            f"direct={len(direct):3d} "
            f"{[hex(x) for x in direct[:20]]} "
            f"reverse={len(reverse):3d} "
            f"{[hex(x) for x in reverse[:10]]}"
        )

    jedec_results[
        target_name
    ] = per_target

    log(
        f"direct coverage = "
        f"{present}/6"
    )


# ================================================================
# E. Search local JEDEC clusters
# ================================================================

log()
log("=" * 120)
log("E. JEDEC CLUSTER WINDOWS")
log("=" * 120)

for target_name, blob in targets.items():

    occurrences = []

    for label, chip_id in ALTICE_IDS:

        for pos in find_all(
            blob,
            chip_id,
        ):

            occurrences.append(
                (
                    pos,
                    label,
                )
            )

    occurrences.sort()

    clusters = []

    for i in range(
        len(occurrences)
    ):

        start = occurrences[i][0]

        group = [
            occurrences[i]
        ]

        for j in range(
            i + 1,
            len(occurrences),
        ):

            if (
                occurrences[j][0]
                - start
                > 0x400
            ):
                break

            group.append(
                occurrences[j]
            )

        labels = {
            x[1]
            for x in group
        }

        if len(labels) >= 4:

            clusters.append(
                (
                    start,
                    group,
                )
            )

    # Dedup starts/sets.
    dedup = []

    seen = set()

    for start, group in clusters:

        key = tuple(
            group
        )

        if key in seen:
            continue

        seen.add(key)
        dedup.append(
            (
                start,
                group,
            )
        )

    log()
    log(
        f"{target_name}: "
        f"{len(dedup)} cluster(s)"
    )

    for ci, (
        start,
        group,
    ) in enumerate(
        dedup[:20]
    ):

        labels = sorted(
            set(
                x[1]
                for x in group
            )
        )

        log(
            f"  cluster {ci}: "
            f"start=0x{start:X} "
            f"coverage={len(labels)}/6 "
            f"{labels}"
        )

        for pos, label in group:

            log(
                f"    0x{pos:X} "
                f"{label}"
            )


# ================================================================
# F. Relevant ASCII strings
# ================================================================

log()
log("=" * 120)
log("F. RELEVANT ASCII STRINGS")
log("=" * 120)

for idx in (
    stage1,
    stage2,
    stage3,
    stage4,
):

    if idx not in extracted:
        continue

    blob = extracted[
        idx
    ]["payload"]

    hits = []

    for off, text in ascii_strings(
        blob,
        5,
    ):

        low = text.lower()

        if any(
            key in low
            for key in KEYWORDS
        ):

            hits.append(
                (
                    off,
                    text,
                )
            )

    log()
    log(
        f"REGION{idx}: "
        f"{len(hits)} relevant string(s)"
    )

    for off, text in hits[:200]:

        log(
            f"  0x{off:06X}: "
            f"{text[:240]}"
        )


# ================================================================
# G. Thumb D3-D7 CMP census
# ================================================================

log()
log("=" * 120)
log("G. THUMB CMP rN,#D3..D7 CENSUS")
log("=" * 120)

cmp_results = {}

for idx in (
    stage1,
    stage2,
    stage3,
):

    if idx not in extracted:
        continue

    blob = extracted[
        idx
    ]["payload"]

    hits = thumb_cmp_hits(
        blob
    )

    cmp_results[
        idx
    ] = hits

    log()
    log(
        f"REGION{idx}: "
        f"{len(hits)} hit(s)"
    )

    for h in hits[:300]:

        log(
            f"  +0x{h['offset']:06X}: "
            f"CMP r{h['rn']}, "
            f"#0x{h['imm']:02X} "
            f"({h['name']}) "
            f"[0x{h['halfword']:04X}]"
        )


# ================================================================
# H. D5/D6 same-register proximity
# ================================================================

log()
log("=" * 120)
log("H. D5/D6 SAME-REGISTER PROXIMITY")
log("=" * 120)

strong_clusters = []

for idx, hits in cmp_results.items():

    clusters = command_clusters(
        hits
    )

    log()
    log(
        f"REGION{idx}: "
        f"{len(clusters)} candidate cluster(s)"
    )

    for ci, c in enumerate(
        clusters[:50]
    ):

        log(
            f"  cluster {ci}: "
            f"r{c['rn']}"
        )

        for h in c["hits"]:

            log(
                f"    +0x{h['offset']:06X}: "
                f"0x{h['imm']:02X} "
                f"{h['name']}"
            )

        strong_clusters.append({
            "region": idx,
            "register": c["rn"],
            "hits": c["hits"],
        })


# ================================================================
# I. Targeted disassembly around D5/D6 clusters
# ================================================================

log()
log("=" * 120)
log("I. TARGETED THUMB DISASSEMBLY")
log("=" * 120)

md = Cs(
    CS_ARCH_ARM,
    CS_MODE_THUMB
    | CS_MODE_LITTLE_ENDIAN,
)

md.skipdata = True


for ci, c in enumerate(
    strong_clusters[:20]
):

    idx = c["region"]

    blob = extracted[
        idx
    ]["payload"]

    load = entry[
        "regions"
    ][idx]["m_start_addr"]

    first = min(
        h["offset"]
        for h in c["hits"]
    )

    last = max(
        h["offset"]
        for h in c["hits"]
    )

    start = max(
        0,
        first - 0x20,
    ) & ~1

    end = min(
        len(blob),
        last + 0x40,
    )

    log()
    log(
        f"CLUSTER {ci} "
        f"REGION{idx} "
        f"file+0x{start:X} "
        f"runtime=0x{load+start:08X}"
    )

    for ins in md.disasm(
        blob[start:end],
        load + start,
    ):

        log(
            f"  {ins.address:08X}: "
            f"{ins.mnemonic:<9} "
            f"{ins.op_str}"
        )


# ================================================================
# J. Raw command constant census
# ================================================================

log()
log("=" * 120)
log("J. RAW D3-D7 BYTE / DWORD CENSUS")
log("=" * 120)

for idx in (
    stage1,
    stage2,
    stage3,
):

    if idx not in extracted:
        continue

    blob = extracted[
        idx
    ]["payload"]

    log()
    log(
        f"REGION{idx}"
    )

    for cmd, name in COMMANDS.items():

        byte_hits = find_all(
            blob,
            bytes([cmd]),
        )

        dword_hits = find_all(
            blob,
            struct.pack(
                "<I",
                cmd,
            ),
        )

        log(
            f"  0x{cmd:02X} "
            f"{name:<8} "
            f"byte={len(byte_hits):5d} "
            f"dword={len(dword_hits):4d}"
        )


# ================================================================
# K. Classification
# ================================================================

full_loader_coverage = sum(
    1
    for label, chip_id
    in ALTICE_IDS
    if find_all(
        data,
        chip_id,
    )
)

region_coverage = {}

for idx, info in extracted.items():

    region_coverage[
        idx
    ] = sum(
        1
        for label, chip_id
        in ALTICE_IDS
        if find_all(
            info["blob"],
            chip_id,
        )
    )


log()
log("=" * 120)
log("S12.9S RESULT")
log("=" * 120)

log(
    "MT6261 DADA ENTRY            : PASS"
)

log(
    "DA1 EXTRACTED                : "
    + (
        "PASS"
        if stage1 in extracted
        else "FAIL"
    )
)

log(
    "DA2 EXTRACTED                : "
    + (
        "PASS"
        if stage2 in extracted
        else "FAIL"
    )
)

log(
    "DA3 / CHIP DATA EXTRACTED    : "
    + (
        "PASS"
        if stage3 in extracted
        else "FAIL"
    )
)

log(
    f"ALTICE JEDEC COVERAGE LOADER : "
    f"{full_loader_coverage}/6"
)

for idx in sorted(
    region_coverage
):

    log(
        f"ALTICE JEDEC COVERAGE R{idx:<2}: "
        f"{region_coverage[idx]}/6"
    )

log(
    f"D5/D6 THUMB CLUSTERS         : "
    f"{len(strong_clusters)}"
)

log()

if (
    max(
        region_coverage.values(),
        default=0,
    )
    == 6
):

    log(
        "STRONGLY SUPPORTED: "
        "local MT6261 DA directly contains "
        "all six Serial-Flash IDs accepted "
        "by the Altice F2 service package."
    )

else:

    log(
        "All six Altice IDs were not found "
        "inside one extracted DA region."
    )

log()
log(
    "DA UPLOAD TESTED             : NO"
)

log(
    "DA READ-ONLY HANDSHAKE TESTED: NO"
)

log(
    "DEVICE WRITE TESTED          : NO"
)

log(
    "DEVICE ERASE TESTED          : NO"
)

log(
    "FLASH AUTHORIZED             : NO"
)


manifest = {
    "schema":
        "S12.9S-mt6261-da-static-audit-v1",

    "loader": {
        "path": str(LOADER),
        "size": len(data),
        "sha256": sha256(data),
    },

    "dada_entry":
        entry,

    "regions": {
        str(idx): {
            "full_sha256":
                sha256(info["blob"]),

            "payload_sha256":
                sha256(info["payload"]),

            "signature_sha256":
                (
                    sha256(info["signature"])
                    if info["signature"]
                    else None
                ),

            "jedec_coverage":
                region_coverage.get(
                    idx,
                    0,
                ),
        }
        for idx, info
        in extracted.items()
    },

    "loader_jedec_coverage":
        full_loader_coverage,

    "d5_d6_thumb_cluster_count":
        len(strong_clusters),

    "device_access": False,
    "da_uploaded": False,
    "da_jump": False,
    "flash_write": False,
    "flash_erase": False,
    "flash_authorized": False,
}

MANIFEST.write_text(
    json.dumps(
        manifest,
        indent=2,
    )
    + "\n",
    encoding="utf-8",
)

REPORT.write_text(
    "\n".join(lines)
    + "\n",
    encoding="utf-8",
)

print()
print("Report  :", REPORT)
print("Manifest:", MANIFEST)
print("Extract :", OUTDIR)
