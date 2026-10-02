#!/usr/bin/env python3

from pathlib import Path
import hashlib
import json


ROOT = Path(r"C:\Users\verto\F2-Altice-MobiWire")
MTK  = Path(r"C:\Users\verto\mtkclient")

REPRO = ROOT / "research" / "f2" / "work" / "repro"

SECTOR = 0x1000

CANDIDATE_END = 0x296448
LIVE_TAIL_START = 0x2C0000

SACRIFICIAL = 0x2A0000


EXPECTED_LIVE_SHA = (
    "c571f3852f4a70d1845cc79abaa95007"
    "f8826ec858a1db1ad501c4a2a7b35ce6"
)

EXPECTED_CAND_SHA = (
    "47b41c572d7d9f09ac5b9562dff5977e"
    "9ea99a16b9f8e126247992b493144fd4"
)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def first_existing(*paths):
    for p in paths:
        if p.is_file():
            return p

    raise FileNotFoundError(
        "\n".join(str(x) for x in paths)
    )


LIVE_A = first_existing(
    REPRO / "s12_8_serial_readback_A.bin",
    MTK / "research" / "f2" / "work" / "repro"
        / "s12_8_serial_readback_A.bin",
)

LIVE_B = first_existing(
    REPRO / "s12_8_serial_readback_B.bin",
    MTK / "research" / "f2" / "work" / "repro"
        / "s12_8_serial_readback_B.bin",
)

CAND = first_existing(
    REPRO / "s12_8e_live_preserving_candidate_NOT_FOR_FLASH.bin",
    MTK / "research" / "f2" / "work" / "repro"
        / "s12_8e_live_preserving_candidate_NOT_FOR_FLASH.bin",
)

OUTDIR = REPRO / "s12_9q_recovery_bundle"
OUTDIR.mkdir(
    parents=True,
    exist_ok=True,
)

REPORT = REPRO / "s12_9q_recovery_sector_gate.txt"
MANIFEST = OUTDIR / "manifest.json"


a = LIVE_A.read_bytes()
b = LIVE_B.read_bytes()
c = CAND.read_bytes()

assert len(a) == 0x400000
assert len(b) == 0x400000
assert len(c) == 0x400000

assert sha(a) == EXPECTED_LIVE_SHA
assert sha(b) == EXPECTED_LIVE_SHA
assert sha(c) == EXPECTED_CAND_SHA

assert a == b


lines = []


def log(s=""):
    print(s)
    lines.append(s)


log("=" * 120)
log("S12.9Q - OFFLINE RECOVERY-SECTOR GATE")
log("=" * 120)

log()
log("NO DEVICE ACCESS")
log("NO BROM")
log("NO WRITE")
log("NO ERASE")

log()
log("INPUTS")
log("-" * 120)
log(f"LIVE A : {LIVE_A}")
log(f"LIVE B : {LIVE_B}")
log(f"CAND   : {CAND}")
log()
log(f"LIVE SHA : {sha(a)}")
log(f"CAND SHA : {sha(c)}")
log("LIVE A == LIVE B : PASS")


# --------------------------------------------------------------
# A. Exact changed bytes / sectors
# --------------------------------------------------------------

changed_offsets = [
    i
    for i, (x, y)
    in enumerate(zip(a, c))
    if x != y
]

changed_sectors = sorted(
    set(
        off // SECTOR
        for off in changed_offsets
    )
)

log()
log("=" * 120)
log("A. CANDIDATE FOOTPRINT")
log("=" * 120)

log(
    f"changed bytes   = {len(changed_offsets)}"
)

log(
    f"changed sectors = {len(changed_sectors)}"
)

log(
    "first change    = "
    f"0x{changed_offsets[0]:06X}"
)

log(
    "last change     = "
    f"0x{changed_offsets[-1]:06X}"
)

assert len(changed_offsets) == 62429
assert len(changed_sectors) == 23
assert changed_offsets[-1] < LIVE_TAIL_START

log(
    "expected 62429 bytes : PASS"
)

log(
    "expected 23 x 4K sectors : PASS"
)

log(
    "all changes < 0x2C0000 : PASS"
)


# --------------------------------------------------------------
# B. NOR bit transition analysis
# --------------------------------------------------------------

log()
log("=" * 120)
log("B. NOR BIT-TRANSITION ANALYSIS")
log("=" * 120)

total_0_to_1 = 0
total_1_to_0 = 0

sector_manifest = []


for sec in changed_sectors:

    start = sec * SECTOR
    end = start + SECTOR

    old = a[start:end]
    new = c[start:end]

    byte_changes = 0
    bits_0_to_1 = 0
    bits_1_to_0 = 0

    for x, y in zip(old, new):

        if x != y:
            byte_changes += 1

        # NOR erased state is 1.
        # Direct program can do 1 -> 0.
        # 0 -> 1 requires erase.
        bits_0_to_1 += (
            ((~x) & y & 0xFF)
            .bit_count()
        )

        bits_1_to_0 += (
            (x & (~y) & 0xFF)
            .bit_count()
        )

    total_0_to_1 += bits_0_to_1
    total_1_to_0 += bits_1_to_0

    old_path = (
        OUTDIR
        / f"live_sector_{start:06X}.bin"
    )

    new_path = (
        OUTDIR
        / f"candidate_sector_{start:06X}.bin"
    )

    old_path.write_bytes(old)
    new_path.write_bytes(new)

    entry = {
        "start": start,
        "end": end,
        "changed_bytes": byte_changes,
        "zero_to_one_bits": bits_0_to_1,
        "one_to_zero_bits": bits_1_to_0,
        "live_sha256": sha(old),
        "candidate_sha256": sha(new),
        "live_file": old_path.name,
        "candidate_file": new_path.name,
    }

    sector_manifest.append(entry)

    log(
        f"0x{start:06X}..0x{end-1:06X} "
        f"bytes={byte_changes:5d} "
        f"0->1={bits_0_to_1:7d} "
        f"1->0={bits_1_to_0:7d}"
    )


log()
log(
    f"TOTAL 0->1 bits = {total_0_to_1}"
)

log(
    f"TOTAL 1->0 bits = {total_1_to_0}"
)

erase_required = (
    total_0_to_1 > 0
)

log(
    "ERASE REQUIRED BY CANDIDATE BIT TRANSITIONS : "
    + (
        "YES / PASS"
        if erase_required
        else "NO"
    )
)

assert erase_required


# --------------------------------------------------------------
# C. Find completely unused 4K sectors in safe gap
# --------------------------------------------------------------

log()
log("=" * 120)
log("C. ALL-FF SAFE-GAP SECTOR CENSUS")
log("=" * 120)

gap_start = (
    (CANDIDATE_END + SECTOR - 1)
    // SECTOR
    * SECTOR
)

gap_end = LIVE_TAIL_START

ff_sectors = []


for start in range(
    gap_start,
    gap_end,
    SECTOR,
):

    end = start + SECTOR

    sa = a[start:end]
    sb = b[start:end]
    sc = c[start:end]

    if (
        sa == sb
        and sa == sc
        and sa == b"\xFF" * SECTOR
    ):
        ff_sectors.append(start)


log(
    f"gap checked : "
    f"0x{gap_start:06X}..0x{gap_end-1:06X}"
)

log(
    f"fully-FF 4K sectors = "
    f"{len(ff_sectors)}"
)

for start in ff_sectors:
    log(
        f"  0x{start:06X}"
    )


# --------------------------------------------------------------
# D. Fixed sacrificial sector gate
# --------------------------------------------------------------

log()
log("=" * 120)
log("D. SACRIFICIAL SECTOR 0x2A0000")
log("=" * 120)

s0 = SACRIFICIAL
s1 = s0 + SECTOR

sa = a[s0:s1]
sb = b[s0:s1]
sc = c[s0:s1]

sacrificial_pass = (
    sa == sb
    and sa == sc
    and sa == b"\xFF" * SECTOR
    and s0 >= gap_start
    and s1 <= LIVE_TAIL_START
    and (s0 // SECTOR) not in changed_sectors
)

log(
    "LIVE A == LIVE B      : "
    + ("PASS" if sa == sb else "FAIL")
)

log(
    "LIVE == CANDIDATE     : "
    + ("PASS" if sa == sc else "FAIL")
)

log(
    "ALL BYTES == FF       : "
    + (
        "PASS"
        if sa == b"\xFF" * SECTOR
        else "FAIL"
    )
)

log(
    "OUTSIDE PATCH FOOTPRINT: "
    + (
        "PASS"
        if (s0 // SECTOR)
        not in changed_sectors
        else "FAIL"
    )
)

log(
    "BELOW LIVE TAIL 0x2C0000: "
    + (
        "PASS"
        if s1 <= LIVE_TAIL_START
        else "FAIL"
    )
)

log(
    "SACRIFICIAL SECTOR OFFLINE GATE: "
    + (
        "PASS"
        if sacrificial_pass
        else "FAIL"
    )
)

assert sacrificial_pass

sac_file = (
    OUTDIR
    / "sacrificial_sector_2A0000_original.bin"
)

sac_file.write_bytes(sa)


# --------------------------------------------------------------
# E. Local donor protocol evidence
# --------------------------------------------------------------

log()
log("=" * 120)
log("E. LOCAL DONOR D5 / ERASE WORKFLOW EVIDENCE")
log("=" * 120)

DA_CMD = (
    MTK
    / "research" / "f2"
    / "work" / "donor_repos"
    / "MT2503-2"
    / "hal" / "system"
    / "bootloader" / "src"
    / "gps_fota"
    / "da_cmd.c"
)

protocol_checks = {}

if DA_CMD.is_file():

    txt = DA_CMD.read_text(
        encoding="utf-8",
        errors="replace",
    )

    needles = {
        "DA_WRITE_CMD":
            "DA_WRITE_CMD",

        "packet_length_be":
            "m_packet_length>>24",

        "save_unchanged":
            "save unchanged data",

        "first_sector_erase":
            "1st sector erase done",

        "unchanged_recovery":
            "unchanged data recovery",
    }

    for key, needle in needles.items():

        ok = needle in txt

        protocol_checks[key] = ok

        log(
            f"{key:<24}: "
            f"{'PASS' if ok else 'FAIL'}"
        )

else:

    log(
        "local donor da_cmd.c : NOT FOUND"
    )


# --------------------------------------------------------------
# F. Manifest
# --------------------------------------------------------------

manifest = {
    "schema": "S12.9Q-recovery-sector-gate-v1",

    "live_sha256": sha(a),
    "candidate_sha256": sha(c),

    "sector_size": SECTOR,

    "changed_byte_count":
        len(changed_offsets),

    "changed_sector_count":
        len(changed_sectors),

    "zero_to_one_bits":
        total_0_to_1,

    "one_to_zero_bits":
        total_1_to_0,

    "erase_required":
        erase_required,

    "candidate_end":
        CANDIDATE_END,

    "live_tail_start":
        LIVE_TAIL_START,

    "sacrificial_sector": {
        "start": SACRIFICIAL,
        "end": SACRIFICIAL + SECTOR,
        "sha256": sha(sa),
        "all_ff": (
            sa == b"\xFF" * SECTOR
        ),
        "offline_gate_pass":
            sacrificial_pass,
    },

    "all_ff_safe_gap_sectors":
        ff_sectors,

    "changed_sectors":
        sector_manifest,

    "local_protocol_checks":
        protocol_checks,

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


# --------------------------------------------------------------
# G. Final status
# --------------------------------------------------------------

log()
log("=" * 120)
log("S12.9Q RESULT")
log("=" * 120)

log(
    "RECOVERY 4K SECTOR BUNDLE      : PASS"
)

log(
    "CANDIDATE REQUIRES ERASE       : PASS"
)

log(
    "SAFE FF GAP EXISTS             : PASS"
)

log(
    "SACRIFICIAL 0x2A0000 OFFLINE   : PASS"
)

log(
    "ACTUAL DEVICE WRITE TESTED     : NO"
)

log(
    "ACTUAL DEVICE ERASE TESTED     : NO"
)

log(
    "EXACT F2 DA BINARY IDENTIFIED  : NO"
)

log(
    "FLASH AUTHORIZED               : NO"
)


REPORT.write_text(
    "\n".join(lines) + "\n",
    encoding="utf-8",
)

print()
print("Report  :", REPORT)
print("Manifest:", MANIFEST)
print("Bundle  :", OUTDIR)
