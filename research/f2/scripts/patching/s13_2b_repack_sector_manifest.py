#!/usr/bin/env python3

"""
S13.2B
======

OFFLINE ONLY.

Take the 4-byte logical S13.2A ALICE modification and:

  1. Validate all canonical inputs.
  2. Reuse the already-validated S12.3 ALICE compressor.
  3. Require byte-perfect repack of the ORIGINAL ALICE first.
  4. Repack the S13.2A decompressed ALICE.
  5. Exact-decode it back and require byte equality.
  6. Embed the repacked ALICE at its original physical location.
  7. Adjust ONLY VIVA FILE_INFO.file_len if physical ALICE length changed.
  8. Preserve all runtime-size metadata because decompressed size is unchanged.
  9. Preserve 0x2C0000..EOF exactly if a validated live readback is available.
 10. Compute exhaustive physical diff.
 11. Produce exact 4 KiB sector before/after bundles and hashes.

NO DEVICE ACCESS.
NO ERASE.
NO WRITE.
NOT FLASH APPROVED.
"""

from pathlib import Path
import hashlib
import importlib.util
import json
import struct
import sys


# =====================================================================
# PATHS
# =====================================================================

ROOT = Path.cwd()

MTK = Path(
    r"C:\Users\verto\mtkclient"
)

PROBE_PATH = (
    ROOT
    / "research/f2/scripts/patching"
    / "s12_alice_repack_probe.py"
)

OLD_U_REPO = (
    ROOT
    / "research/f2/work/extracted/altice_alice"
    / "alice-py.bin"
)

PATCHED_U = (
    ROOT
    / "research/f2/work/candidates/s13_2a"
    / "alice-s13_2a-image-activation-audio-poc.bin"
)

OUT_DIR = (
    ROOT
    / "research/f2/work/candidates/s13_2b"
)

SECTOR_DIR = (
    OUT_DIR
    / "sector_bundle_NOT_FOR_WRITE_YET"
)

OUT_A = (
    OUT_DIR
    / "alice-s13_2b-repacked.bin"
)

OUT_VIVA = (
    OUT_DIR
    / "viva-s13_2b-repacked.bin"
)

OUT_DUMP = (
    OUT_DIR
    / "s13_2b_diff_only_NOT_FOR_FLASH.bin"
)

OUT_JSON = (
    OUT_DIR
    / "s13_2b_manifest.json"
)

OUT_DIFF = (
    OUT_DIR
    / "s13_2b_diff_ranges.txt"
)

OUT_SECTORS = (
    OUT_DIR
    / "s13_2b_sector_manifest.txt"
)

NOT_FOR_FLASH = (
    OUT_DIR
    / "NOT_FOR_FLASH.txt"
)


# =====================================================================
# CANONICAL CONSTANTS
# =====================================================================

FLASH_SIZE = 0x400000

LIVE_BOUNDARY = 0x2C0000

SECTOR_SIZE = 0x1000

VIVA_START = 0x04C20C

VIVA_LEN_FIELD = 0x04C22C

ALICE_START = 0x18129C

NEXT_REGION = 0x2C0000

OLD_VIVA_LEN = 0x248EBC

OLD_VIVA_END = (
    VIVA_START
    + OLD_VIVA_LEN
)

OLD_A_SIZE = 0x113E2C

U_SIZE = 0x157BB4

ALICE_MAX_PHYSICAL_SIZE = (
    NEXT_REGION
    - ALICE_START
)

ALICE_RUNTIME_BASE = 0x1024EC00

HOOK_U_OFFSET = 0x106C88


EXPECTED_DUMP_SHA = (
    "2fc100e5704cf3d6fae0817a22ce2223"
    "97702ffd7351a83763ae1bafd4416922"
)

EXPECTED_OLD_U_SHA = (
    "7246242b67afae0d13104452bc3257827"
    "cb778119b54e7a26fb7fb55993697ea"
)

EXPECTED_PATCHED_U_SHA = (
    "b12f67211e1a55263af6a75e65b7caa"
    "471c15df381ae39757f179dda7a84332d"
)

EXPECTED_OLD_A_SHA = (
    "8a06970667c6af37f7a6b1fb28dde062"
    "2e396fccd5c2a0b450bd795a0257988f"
)

EXPECTED_LIVE_SHA = (
    "c571f3852f4a70d1845cc79abaa95007"
    "f8826ec858a1db1ad501c4a2a7b35ce6"
)

EXPECTED_STATIC_SHA = (
    "ac4cc8816e9463e617271ac259f55d5d"
    "3480f003333036691b1dd24f92ca2f1f"
)


OLD_POINTER_BYTES = bytes.fromhex(
    "8D 1C 30 F0"
)

NEW_POINTER_BYTES = bytes.fromhex(
    "15 E8 33 10"
)


# =====================================================================
# HELPERS
# =====================================================================

def sha(data):
    return hashlib.sha256(
        data
    ).hexdigest()


def banner(title):
    print()
    print("=" * 116)
    print(title)
    print("=" * 116)


def u32(data, offset):
    return struct.unpack_from(
        "<I",
        data,
        offset,
    )[0]


def put_u32(data, offset, value):
    struct.pack_into(
        "<I",
        data,
        offset,
        value,
    )


def locate_exact(
    description,
    paths,
    expected_sha,
    expected_size=None,
):
    print()
    print(description)

    for path in paths:

        print(
            f"  checking: {path}"
        )

        if not path.is_file():
            print(
                "    MISS"
            )
            continue

        data = path.read_bytes()

        digest = sha(data)

        print(
            f"    SIZE   = 0x{len(data):X}"
        )
        print(
            f"    SHA256 = {digest}"
        )

        if (
            expected_size is not None
            and len(data) != expected_size
        ):
            print(
                "    REJECT: size mismatch"
            )
            continue

        if digest != expected_sha:
            print(
                "    REJECT: hash mismatch"
            )
            continue

        print(
            "    PASS"
        )

        return path, data

    raise SystemExit(
        f"ERROR: unable to locate exact {description}"
    )


def load_probe():
    spec = importlib.util.spec_from_file_location(
        "s12probe",
        PROBE_PATH,
    )

    if (
        spec is None
        or spec.loader is None
    ):
        raise RuntimeError(
            "unable to import S12 repacker"
        )

    module = importlib.util.module_from_spec(
        spec
    )

    spec.loader.exec_module(
        module
    )

    return module


def diff_ranges(a, b):

    if len(a) != len(b):
        raise RuntimeError(
            "diff requires equal-size inputs"
        )

    ranges = []

    changed = 0

    start = None

    for i, (x, y) in enumerate(
        zip(a, b)
    ):

        if x != y:

            changed += 1

            if start is None:
                start = i

        elif start is not None:

            ranges.append(
                (
                    start,
                    i,
                )
            )

            start = None

    if start is not None:
        ranges.append(
            (
                start,
                len(a),
            )
        )

    return changed, ranges


def changed_positions(a, b):

    return [
        i
        for i, (x, y)
        in enumerate(
            zip(a, b)
        )
        if x != y
    ]


def range_string(start, end):

    return (
        f"0x{start:06X}-"
        f"0x{end-1:06X} "
        f"len=0x{end-start:X}"
    )


# =====================================================================
# START
# =====================================================================

banner(
    "S13.2B - REPACK + PHYSICAL 4K SECTOR MANIFEST"
)

print()
print("NO DEVICE ACCESS")
print("NO FLASH WRITE")
print("NO FLASH ERASE")
print("NOT FLASH APPROVED")


if not PROBE_PATH.is_file():
    raise SystemExit(
        f"ERROR missing validated repacker: {PROBE_PATH}"
    )


# =====================================================================
# 1. CANONICAL DUMP
# =====================================================================

banner(
    "1. LOCATE CANONICAL 4 MiB DUMP"
)

dump_path, canonical = locate_exact(
    "canonical mobiwire_dump_2.bin",
    [
        (
            ROOT
            / "research/f2/data/dumps"
            / "mobiwire_dump_2.bin"
        ),
        (
            MTK
            / "research/f2/data/dumps"
            / "mobiwire_dump_2.bin"
        ),
    ],
    EXPECTED_DUMP_SHA,
    FLASH_SIZE,
)


# =====================================================================
# 2. ORIGINAL DECOMPRESSED ALICE
# =====================================================================

banner(
    "2. LOCATE ORIGINAL DECOMPRESSED ALICE"
)

old_u_path, old_u = locate_exact(
    "canonical alice-py.bin",
    [
        OLD_U_REPO,
        (
            MTK
            / "research/f2/work/extracted"
            / "altice_alice/alice-py.bin"
        ),
    ],
    EXPECTED_OLD_U_SHA,
    U_SIZE,
)


# =====================================================================
# 3. REFERENCE COMPRESSED ALICE
# =====================================================================

banner(
    "3. LOCATE REFERENCE ALICE_2"
)

ref_a_path, ref_a = locate_exact(
    "canonical altice_ALICE_2.bin",
    [
        (
            ROOT
            / "research/f2/work/extracted"
            / "altice_alice/altice_ALICE_2.bin"
        ),
        (
            MTK
            / "research/f2/work/extracted"
            / "altice_alice/altice_ALICE_2.bin"
        ),
    ],
    EXPECTED_OLD_A_SHA,
    OLD_A_SIZE,
)


# =====================================================================
# 4. S13.2A INPUT
# =====================================================================

banner(
    "4. VALIDATE S13.2A DECOMPRESSED CANDIDATE"
)

if not PATCHED_U.is_file():
    raise SystemExit(
        f"ERROR missing S13.2A candidate: {PATCHED_U}"
    )

patched_u = PATCHED_U.read_bytes()

print(
    f"FILE   = {PATCHED_U}"
)

print(
    f"SIZE   = 0x{len(patched_u):X}"
)

print(
    f"SHA256 = {sha(patched_u)}"
)

if len(patched_u) != U_SIZE:
    raise RuntimeError(
        "S13.2A decompressed size mismatch"
    )

if sha(patched_u) != EXPECTED_PATCHED_U_SHA:
    raise RuntimeError(
        "S13.2A SHA mismatch"
    )


logical_changed, logical_ranges = (
    diff_ranges(
        old_u,
        patched_u,
    )
)

print()
print(
    f"logical changed bytes = "
    f"{logical_changed}"
)

print(
    f"logical diff ranges   = "
    f"{len(logical_ranges)}"
)

for start, end in logical_ranges:

    print(
        "  ",
        range_string(
            start,
            end,
        ),
    )


if logical_changed != 4:
    raise RuntimeError(
        "logical ALICE change is not exactly 4 bytes"
    )

if logical_ranges != [
    (
        HOOK_U_OFFSET,
        HOOK_U_OFFSET + 4,
    )
]:
    raise RuntimeError(
        "logical diff is not exactly the expected pointer"
    )

if (
    old_u[
        HOOK_U_OFFSET:
        HOOK_U_OFFSET + 4
    ]
    != OLD_POINTER_BYTES
):
    raise RuntimeError(
        "original hook bytes mismatch"
    )

if (
    patched_u[
        HOOK_U_OFFSET:
        HOOK_U_OFFSET + 4
    ]
    != NEW_POINTER_BYTES
):
    raise RuntimeError(
        "new hook bytes mismatch"
    )

print()
print(
    "[PASS] S13.2A logical diff exactly validated"
)


# =====================================================================
# 5. CROSS-CHECK REFERENCE AGAINST PHYSICAL DUMP
# =====================================================================

banner(
    "5. PHYSICAL BASELINE CROSS-CHECK"
)

if (
    canonical[
        ALICE_START:
        ALICE_START + OLD_A_SIZE
    ]
    != ref_a
):
    raise RuntimeError(
        "reference ALICE_2 != physical dump ALICE"
    )

print(
    "[PASS] physical dump ALICE == canonical ALICE_2"
)


old_viva_len = u32(
    canonical,
    VIVA_LEN_FIELD,
)

print(
    f"VIVA file_len = "
    f"0x{old_viva_len:X}"
)

if old_viva_len != OLD_VIVA_LEN:
    raise RuntimeError(
        "canonical VIVA file_len mismatch"
    )


if (
    VIVA_START
    + OLD_VIVA_LEN
    != OLD_VIVA_END
):
    raise RuntimeError(
        "old VIVA geometry mismatch"
    )

if (
    ALICE_START
    + OLD_A_SIZE
    != OLD_VIVA_END
):
    raise RuntimeError(
        "ALICE is not exact final VIVA component"
    )

print(
    "[PASS] ALICE is exact final VIVA component"
)


# =====================================================================
# 6. LOAD VALIDATED S12 REPACKER
# =====================================================================

banner(
    "6. LOAD VALIDATED S12.3 ALICE REPACKER"
)

probe = load_probe()

print(
    f"MODULE = {PROBE_PATH}"
)

print(
    "[PASS] S12 repacker imported"
)


# =====================================================================
# 7. BYTE-PERFECT ORIGINAL REPACK GATE
# =====================================================================

banner(
    "7. ORIGINAL BYTE-PERFECT REPACK GATE"
)

repacked_original, original_stats = (
    probe.repack(
        old_u,
        ref_a,
    )
)

print(
    f"reference size = 0x{len(ref_a):X}"
)

print(
    f"repacked size  = 0x{len(repacked_original):X}"
)

print(
    f"reference SHA  = {sha(ref_a)}"
)

print(
    f"repacked SHA   = {sha(repacked_original)}"
)

if repacked_original != ref_a:
    raise RuntimeError(
        "validated repacker no longer reproduces original byte-perfectly"
    )

decoded_original = probe.decode_exact(
    repacked_original,
    U_SIZE,
)

if decoded_original != old_u:
    raise RuntimeError(
        "original ALICE round-trip failed"
    )

print()
print(
    "[PASS] original compressed ALICE byte-perfect"
)

print(
    "[PASS] original exact decode"
)


# =====================================================================
# 8. REPACK S13.2A
# =====================================================================

banner(
    "8. REPACK S13.2A ALICE"
)

new_a, new_stats = probe.repack(
    patched_u,
    ref_a,
)

new_a_sha = sha(
    new_a
)

print(
    f"old ALICE size = 0x{len(ref_a):X}"
)

print(
    f"new ALICE size = 0x{len(new_a):X}"
)

print(
    f"size delta     = "
    f"{len(new_a)-len(ref_a):+#x}"
)

print(
    f"new SHA256     = {new_a_sha}"
)

print(
    f"stream size    = "
    f"0x{new_stats['stream_size']:X}"
)

print(
    f"mapping entries= "
    f"{new_stats['mapping_entries']}"
)

print(
    f"mapping addr   = "
    f"0x{new_stats['new_map_addr']:08X}"
)

print(
    f"dictionary addr= "
    f"0x{new_stats['new_dict_addr']:08X}"
)

print(
    f"encoded words  = "
    f"{new_stats['encoded_words']}"
)

print(
    f"raw words      = "
    f"{new_stats['raw_words']}"
)


if len(new_a) > ALICE_MAX_PHYSICAL_SIZE:
    raise RuntimeError(
        "repacked ALICE exceeds physical VIVA headroom"
    )


new_profile = probe.parse_container(
    new_a
)

old_profile = probe.parse_container(
    ref_a
)

if (
    new_profile["dictionary"]
    != old_profile["dictionary"]
):
    raise RuntimeError(
        "dictionary changed unexpectedly"
    )

if (
    new_profile["base"]
    != old_profile["base"]
):
    raise RuntimeError(
        "ALICE compressed stream base changed"
    )

if (
    new_stats["mapping_entries"]
    != original_stats["mapping_entries"]
):
    raise RuntimeError(
        "mapping entry count changed despite identical runtime size"
    )

print()
print(
    "[PASS] dictionary preserved"
)

print(
    "[PASS] stream base preserved"
)

print(
    "[PASS] mapping count preserved"
)


# =====================================================================
# 9. EXACT ROUND-TRIP OF PATCHED ALICE
# =====================================================================

banner(
    "9. S13.2A EXACT DECODE ROUND-TRIP"
)

decoded_new = probe.decode_exact(
    new_a,
    U_SIZE,
)

if decoded_new != patched_u:
    raise RuntimeError(
        "S13.2A repacked ALICE round-trip failed"
    )

decoded_changed, decoded_ranges = (
    diff_ranges(
        old_u,
        decoded_new,
    )
)

if decoded_changed != 4:
    raise RuntimeError(
        "decoded candidate no longer has exact logical diff"
    )

if decoded_ranges != logical_ranges:
    raise RuntimeError(
        "decoded logical range differs"
    )

print(
    "[PASS] repacked candidate decodes exactly to S13.2A"
)

print(
    "[PASS] decoded logical diff remains exactly 4 bytes"
)


# =====================================================================
# 10. VIVA GEOMETRY
# =====================================================================

banner(
    "10. BUILD NEW VIVA GEOMETRY"
)

viva_prefix = canonical[
    VIVA_START:
    ALICE_START
]

new_viva = (
    viva_prefix
    + new_a
)

new_viva_len = len(
    new_viva
)

new_viva_end = (
    VIVA_START
    + new_viva_len
)

print(
    f"old VIVA len = 0x{OLD_VIVA_LEN:X}"
)

print(
    f"new VIVA len = 0x{new_viva_len:X}"
)

print(
    f"VIVA delta   = "
    f"{new_viva_len-OLD_VIVA_LEN:+#x}"
)

print(
    f"new VIVA end = "
    f"0x{new_viva_end:06X}"
)

print(
    f"next region  = "
    f"0x{NEXT_REGION:06X}"
)

print(
    f"headroom     = "
    f"0x{NEXT_REGION-new_viva_end:X}"
)

if new_viva_end > NEXT_REGION:
    raise RuntimeError(
        "new VIVA overlaps next physical region"
    )

print(
    "[PASS] new VIVA remains below 0x2C0000"
)


# =====================================================================
# 11. SELECT OFFLINE PHYSICAL BASE
# =====================================================================

banner(
    "11. SELECT OFFLINE PHYSICAL BASE"
)

live_candidates_a = [
    (
        ROOT
        / "research/f2/work/repro"
        / "s12_8_serial_readback_A.bin"
    ),
    (
        MTK
        / "research/f2/work/repro"
        / "s12_8_serial_readback_A.bin"
    ),
]

live_candidates_b = [
    (
        ROOT
        / "research/f2/work/repro"
        / "s12_8_serial_readback_B.bin"
    ),
    (
        MTK
        / "research/f2/work/repro"
        / "s12_8_serial_readback_B.bin"
    ),
]


def find_live(paths):

    for path in paths:

        if not path.is_file():
            continue

        data = path.read_bytes()

        if (
            len(data) == FLASH_SIZE
            and sha(data) == EXPECTED_LIVE_SHA
        ):
            return path, data

    return None, None


live_a_path, live_a = find_live(
    live_candidates_a
)

live_b_path, live_b = find_live(
    live_candidates_b
)


base_kind = "canonical-diff-only"

base_path = dump_path

base = canonical


if (
    live_a is not None
    and live_b is not None
):

    if live_a != live_b:
        raise RuntimeError(
            "validated live A/B no longer identical"
        )

    if (
        live_a[:LIVE_BOUNDARY]
        != canonical[:LIVE_BOUNDARY]
    ):
        raise RuntimeError(
            "validated live static prefix differs from canonical"
        )

    if (
        sha(
            live_a[
                :LIVE_BOUNDARY
            ]
        )
        != EXPECTED_STATIC_SHA
    ):
        raise RuntimeError(
            "validated live static SHA mismatch"
        )

    base_kind = "validated-live-preserving"

    base_path = live_a_path

    base = live_a

    print(
        f"LIVE A = {live_a_path}"
    )

    print(
        f"LIVE B = {live_b_path}"
    )

    print(
        f"LIVE SHA = {sha(live_a)}"
    )

    print(
        "[PASS] live A == B"
    )

    print(
        "[PASS] live static prefix == canonical"
    )

else:

    print(
        "[INFO] validated live A/B pair not locally available."
    )

    print(
        "[INFO] using canonical dump ONLY as an offline diff base."
    )

    print(
        "[INFO] resulting whole image remains NOT FOR FLASH."
    )


print()
print(
    f"BASE KIND = {base_kind}"
)

print(
    f"BASE FILE = {base_path}"
)

print(
    f"BASE SHA  = {sha(base)}"
)


# =====================================================================
# 12. BUILD PHYSICAL OFFLINE CANDIDATE
# =====================================================================

banner(
    "12. BUILD PHYSICAL OFFLINE CANDIDATE"
)

candidate = bytearray(
    base
)


# Update physical VIVA file length only if necessary.
put_u32(
    candidate,
    VIVA_LEN_FIELD,
    new_viva_len,
)


# Write the newly packed ALICE.
candidate[
    ALICE_START:
    ALICE_START + len(new_a)
] = new_a


candidate = bytes(
    candidate
)


if len(candidate) != FLASH_SIZE:
    raise RuntimeError(
        "candidate flash size changed"
    )


# Live region must be absolutely untouched.
if (
    candidate[
        LIVE_BOUNDARY:
    ]
    != base[
        LIVE_BOUNDARY:
    ]
):
    raise RuntimeError(
        "candidate changed bytes at/above 0x2C0000"
    )


print(
    "[PASS] physical candidate remains exactly 4 MiB"
)

print(
    "[PASS] 0x2C0000..EOF unchanged"
)


# =====================================================================
# 13. RE-EXTRACT AND VERIFY CANDIDATE VIVA / ALICE
# =====================================================================

banner(
    "13. RE-EXTRACT PHYSICAL CANDIDATE"
)

field_len = u32(
    candidate,
    VIVA_LEN_FIELD,
)

print(
    f"candidate VIVA field = "
    f"0x{field_len:X}"
)

if field_len != new_viva_len:
    raise RuntimeError(
        "candidate VIVA file_len field incorrect"
    )


physical_viva = candidate[
    VIVA_START:
    VIVA_START + new_viva_len
]

if physical_viva != new_viva:
    raise RuntimeError(
        "physical candidate VIVA != generated VIVA"
    )


physical_a = candidate[
    ALICE_START:
    ALICE_START + len(new_a)
]

if physical_a != new_a:
    raise RuntimeError(
        "physical candidate ALICE != generated ALICE"
    )


physical_decoded = probe.decode_exact(
    physical_a,
    U_SIZE,
)

if physical_decoded != patched_u:
    raise RuntimeError(
        "physical candidate ALICE exact decode mismatch"
    )


print(
    "[PASS] physical VIVA extraction"
)

print(
    "[PASS] physical ALICE extraction"
)

print(
    "[PASS] physical ALICE exact decode"
)


# =====================================================================
# 14. RUNTIME SIZE METADATA MUST REMAIN ORIGINAL
# =====================================================================

banner(
    "14. RUNTIME SIZE METADATA KEEP GATE"
)

keep_u32 = {
    0x00B918: 0x00157BB4,
    0x00C18C: 0x103A67B4,
    0x00EC54: 0x00157BB4,
    0x00ECC8: 0x00157BB4,
    0x00FBAC: 0x00157BB4,
    0x0110DC: 0x103A67B4,
}


for pos, expected in keep_u32.items():

    got = u32(
        candidate,
        pos,
    )

    print(
        f"D+0x{pos:06X} "
        f"=0x{got:08X}"
    )

    if got != expected:
        raise RuntimeError(
            f"runtime metadata unexpectedly changed at 0x{pos:X}"
        )


print(
    "[PASS] runtime/decompressed size remains original"
)


# =====================================================================
# 15. EXHAUSTIVE PHYSICAL DIFF
# =====================================================================

banner(
    "15. EXHAUSTIVE PHYSICAL DIFF"
)

physical_changed, physical_ranges = (
    diff_ranges(
        base,
        candidate,
    )
)


print(
    f"changed bytes = "
    f"{physical_changed}"
)

print(
    f"diff ranges   = "
    f"{len(physical_ranges)}"
)


for start, end in physical_ranges:

    print(
        "  ",
        range_string(
            start,
            end,
        ),
    )


if physical_changed == 0:
    raise RuntimeError(
        "physical candidate unexpectedly identical"
    )


for start, end in physical_ranges:

    if end > LIVE_BOUNDARY:
        raise RuntimeError(
            "physical diff reaches live-data region"
        )


# Only these physical areas are allowed:
#   - VIVA file_len u32
#   - repacked ALICE bytes
#
for pos in changed_positions(
    base,
    candidate,
):

    allowed = False

    if (
        VIVA_LEN_FIELD
        <= pos
        < VIVA_LEN_FIELD + 4
    ):
        allowed = True

    if (
        ALICE_START
        <= pos
        < ALICE_START + len(new_a)
    ):
        allowed = True

    if not allowed:
        raise RuntimeError(
            f"unauthorized physical diff at 0x{pos:06X}"
        )


print()
print(
    "[PASS] exhaustive physical diff stays in allowed locations"
)

print(
    "[PASS] changed bytes >=0x2C0000 = 0"
)


# =====================================================================
# 16. EXACT 4K SECTOR MANIFEST
# =====================================================================

banner(
    "16. EXACT 4 KiB SECTOR MANIFEST"
)

positions = changed_positions(
    base,
    candidate,
)

sector_starts = sorted(
    {
        (
            pos // SECTOR_SIZE
        )
        * SECTOR_SIZE
        for pos in positions
    }
)


if not sector_starts:
    raise RuntimeError(
        "no changed sectors"
    )


for start in sector_starts:

    if start >= LIVE_BOUNDARY:
        raise RuntimeError(
            "changed sector begins in live region"
        )

    if (
        start + SECTOR_SIZE
        > LIVE_BOUNDARY
    ):
        raise RuntimeError(
            "changed sector crosses live boundary"
        )


print(
    f"changed sector count = "
    f"{len(sector_starts)}"
)


SECTOR_DIR.mkdir(
    parents=True,
    exist_ok=True,
)


sector_manifest = []


for index, start in enumerate(
    sector_starts,
    1,
):

    end = (
        start
        + SECTOR_SIZE
    )

    before = base[
        start:end
    ]

    after = candidate[
        start:end
    ]

    count = sum(
        1
        for a, b
        in zip(
            before,
            after,
        )
        if a != b
    )

    before_sha = sha(
        before
    )

    after_sha = sha(
        after
    )

    before_name = (
        f"sector_{start:06X}_before.bin"
    )

    after_name = (
        f"sector_{start:06X}_after.bin"
    )

    (
        SECTOR_DIR
        / before_name
    ).write_bytes(
        before
    )

    (
        SECTOR_DIR
        / after_name
    ).write_bytes(
        after
    )


    item = {
        "index": index,
        "start": start,
        "end": end,
        "size": SECTOR_SIZE,
        "changed_bytes": count,
        "before_sha256": before_sha,
        "after_sha256": after_sha,
        "before_file": before_name,
        "after_file": after_name,
    }

    sector_manifest.append(
        item
    )


    print()
    print(
        f"SECTOR #{index}"
    )

    print(
        f"  range   = "
        f"0x{start:06X}-0x{end-1:06X}"
    )

    print(
        f"  changed = "
        f"{count}"
    )

    print(
        f"  BEFORE  = "
        f"{before_sha}"
    )

    print(
        f"  AFTER   = "
        f"{after_sha}"
    )


print()
print(
    "[PASS] every changed sector is strictly below 0x2C0000"
)


# =====================================================================
# 17. WRITE OUTPUTS
# =====================================================================

banner(
    "17. WRITE OFFLINE OUTPUTS"
)

OUT_DIR.mkdir(
    parents=True,
    exist_ok=True,
)


OUT_A.write_bytes(
    new_a
)

OUT_VIVA.write_bytes(
    new_viva
)

OUT_DUMP.write_bytes(
    candidate
)


with OUT_DIFF.open(
    "w",
    encoding="utf-8",
) as f:

    for start, end in physical_ranges:

        f.write(
            range_string(
                start,
                end,
            )
            + "\n"
        )


with OUT_SECTORS.open(
    "w",
    encoding="utf-8",
) as f:

    f.write(
        "S13.2B 4 KiB SECTOR MANIFEST\n"
    )

    f.write(
        "NOT FOR WRITE YET\n\n"
    )

    for item in sector_manifest:

        f.write(
            f"0x{item['start']:06X}-"
            f"0x{item['end']-1:06X}\n"
        )

        f.write(
            f"  changed bytes : "
            f"{item['changed_bytes']}\n"
        )

        f.write(
            f"  before SHA256 : "
            f"{item['before_sha256']}\n"
        )

        f.write(
            f"  after SHA256  : "
            f"{item['after_sha256']}\n"
        )

        f.write(
            "\n"
        )


manifest = {
    "stage": "S13.2B",
    "description": (
        "Audio Player Image-Viewer activation "
        "offline repack + physical sector manifest"
    ),
    "flash_authorized": False,
    "device_access": False,
    "base_kind": base_kind,
    "flash_size": FLASH_SIZE,
    "live_boundary": LIVE_BOUNDARY,
    "sector_size": SECTOR_SIZE,
    "inputs": {
        "canonical_dump_path": str(
            dump_path
        ),
        "canonical_dump_sha256": sha(
            canonical
        ),
        "old_u_path": str(
            old_u_path
        ),
        "old_u_sha256": sha(
            old_u
        ),
        "reference_alice_path": str(
            ref_a_path
        ),
        "reference_alice_sha256": sha(
            ref_a
        ),
        "s13_2a_u_path": str(
            PATCHED_U
        ),
        "s13_2a_u_sha256": sha(
            patched_u
        ),
    },
    "logical_patch": {
        "runtime_address": (
            ALICE_RUNTIME_BASE
            + HOOK_U_OFFSET
        ),
        "u_offset": HOOK_U_OFFSET,
        "old_bytes": (
            OLD_POINTER_BYTES.hex()
        ),
        "new_bytes": (
            NEW_POINTER_BYTES.hex()
        ),
        "old_pointer": "0xF0301C8D",
        "new_pointer": "0x1033E815",
    },
    "repacked_alice": {
        "size": len(new_a),
        "size_delta": (
            len(new_a)
            - len(ref_a)
        ),
        "sha256": new_a_sha,
        "mapping_entries": (
            new_stats[
                "mapping_entries"
            ]
        ),
        "mapping_addr": (
            new_stats[
                "new_map_addr"
            ]
        ),
        "dictionary_addr": (
            new_stats[
                "new_dict_addr"
            ]
        ),
    },
    "viva": {
        "old_length": OLD_VIVA_LEN,
        "new_length": new_viva_len,
        "new_end": new_viva_end,
        "headroom": (
            NEXT_REGION
            - new_viva_end
        ),
        "sha256": sha(
            new_viva
        ),
    },
    "physical_candidate": {
        "path": str(
            OUT_DUMP
        ),
        "sha256": sha(
            candidate
        ),
        "changed_bytes": physical_changed,
        "diff_ranges": len(
            physical_ranges
        ),
        "changed_sector_count": len(
            sector_starts
        ),
        "changed_bytes_at_or_above_live_boundary": 0,
    },
    "sectors": sector_manifest,
    "status": (
        "OFFLINE ONLY - "
        "NOT FLASH APPROVED - "
        "PRE-WRITE D6 GATE REQUIRED"
    ),
}


OUT_JSON.write_text(
    json.dumps(
        manifest,
        indent=2,
    )
    + "\n",
    encoding="utf-8",
)


NOT_FOR_FLASH.write_text(
    (
        "S13.2B OFFLINE ANALYSIS ARTIFACT\n"
        "\n"
        "DO NOT FLASH THIS WHOLE IMAGE.\n"
        "DO NOT WRITE ANY SECTOR YET.\n"
        "\n"
        "Before any future firmware-sector write:\n"
        "1. D6-read every exact target 4 KiB sector.\n"
        "2. Require byte-exact equality to BEFORE sector.\n"
        "3. Save fresh rollback sectors and SHA256.\n"
        "4. Abort on any mismatch.\n"
        "\n"
        "0x2C0000..0x3FFFFF MUST NEVER BE WRITTEN.\n"
    ),
    encoding="utf-8",
)


# =====================================================================
# 18. READ-BACK LOCAL OUTPUT CHECKS
# =====================================================================

banner(
    "18. LOCAL OUTPUT READ-BACK CHECK"
)

if OUT_A.read_bytes() != new_a:
    raise RuntimeError(
        "saved ALICE mismatch"
    )

if OUT_VIVA.read_bytes() != new_viva:
    raise RuntimeError(
        "saved VIVA mismatch"
    )

if OUT_DUMP.read_bytes() != candidate:
    raise RuntimeError(
        "saved dump mismatch"
    )


print(
    "[PASS] saved ALICE exact"
)

print(
    "[PASS] saved VIVA exact"
)

print(
    "[PASS] saved 4 MiB diff artifact exact"
)


# =====================================================================
# FINAL
# =====================================================================

banner(
    "S13.2B RESULT"
)

print(
    f"LOGICAL PATCH BYTES         : "
    f"{logical_changed} PASS"
)

print(
    f"REPACKED ALICE SIZE         : "
    f"0x{len(new_a):X}"
)

print(
    f"REPACKED ALICE DELTA        : "
    f"{len(new_a)-len(ref_a):+#x}"
)

print(
    f"REPACKED ALICE SHA256       : "
    f"{new_a_sha}"
)

print(
    f"NEW VIVA LENGTH             : "
    f"0x{new_viva_len:X}"
)

print(
    f"NEW VIVA END                : "
    f"0x{new_viva_end:06X}"
)

print(
    f"PHYSICAL CHANGED BYTES      : "
    f"{physical_changed}"
)

print(
    f"PHYSICAL DIFF RANGES        : "
    f"{len(physical_ranges)}"
)

print(
    f"CHANGED 4K SECTORS          : "
    f"{len(sector_starts)}"
)

print(
    "CHANGED >= 0x2C0000        : "
    "0 PASS"
)

print(
    "ORIGINAL REPACK            : "
    "BYTE-PERFECT PASS"
)

print(
    "S13.2A REPACK ROUNDTRIP    : "
    "EXACT PASS"
)

print(
    "RUNTIME SIZE METADATA      : "
    "UNCHANGED PASS"
)

print(
    "LIVE TAIL                  : "
    "UNCHANGED PASS"
)

print()
print(
    f"BASE KIND                   : "
    f"{base_kind}"
)

print()
print(
    f"OUTPUT SHA256               : "
    f"{sha(candidate)}"
)

print()
print(
    f"MANIFEST                    : "
    f"{OUT_JSON}"
)

print(
    f"SECTOR MANIFEST             : "
    f"{OUT_SECTORS}"
)

print(
    f"SECTOR BUNDLE               : "
    f"{SECTOR_DIR}"
)

print()
print(
    "STATUS:"
)

print(
    "OFFLINE CANDIDATE ONLY"
)

print(
    "NOT FLASH APPROVED"
)

print(
    "NO DEVICE ACCESS PERFORMED"
)

print()
print(
    "NEXT GATE:"
)

print(
    "Review physical sector count / diff locality."
)

print(
    "Only after that: design exact D6 pre-read "
    "rollback gate for those sectors."
)

