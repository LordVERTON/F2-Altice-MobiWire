#!/usr/bin/env python3
"""
S12.6 - Build and audit an OFFLINE Altice F2 candidate dump.

This script:
  - rebuilds the deterministic +0x1000 ALICE from S12.3;
  - patches only the S12.5-approved metadata fields;
  - keeps the LZMA preset bound unchanged;
  - inserts the new ALICE_2 in the existing physical gap;
  - rejects ANY byte difference outside the explicit allow-list;
  - emits candidate dump/VIVA + JSON/TXT manifests.

NO DEVICE ACCESS.
NOT FLASH APPROVED.
"""

from pathlib import Path
import hashlib
import importlib.util
import json
import struct


REPO = Path(r"C:\Users\verto\F2-Altice-MobiWire")
MTK  = Path(r"C:\Users\verto\mtkclient")

F2 = MTK / "research" / "f2"

DUMP_PATH = (
    F2 / "data" / "dumps"
    / "mobiwire_dump_2.bin"
)

ALICE_DIR = (
    F2 / "work" / "extracted"
    / "altice_alice"
)

A_PATH = ALICE_DIR / "altice_ALICE_2.bin"
U_PATH = ALICE_DIR / "alice-py.bin"
VIVA_PATH = ALICE_DIR / "altice_VIVA.bin"

PROBE_PATH = (
    REPO / "research" / "f2"
    / "scripts" / "patching"
    / "s12_alice_repack_probe.py"
)

OUT_DIR = (
    REPO / "research" / "f2"
    / "work" / "repro"
)

OUT_DUMP = (
    OUT_DIR
    / "s12_6_candidate_dump_NOT_FOR_FLASH.bin"
)

OUT_VIVA = (
    OUT_DIR
    / "s12_6_candidate_viva_NOT_FOR_FLASH.bin"
)

OUT_JSON = (
    OUT_DIR
    / "s12_6_candidate_manifest.json"
)

OUT_DIFF = (
    OUT_DIR
    / "s12_6_diff_ranges.txt"
)


# ---------------------------------------------------------------------------
# CANONICAL VALUES
# ---------------------------------------------------------------------------

EXPECTED_DUMP_SHA = (
    "2fc100e5704cf3d6fae0817a22ce2223"
    "97702ffd7351a83763ae1bafd4416922"
)

EXPECTED_A_SHA = (
    "8a06970667c6af37f7a6b1fb28dde062"
    "2e396fccd5c2a0b450bd795a0257988f"
)

EXPECTED_U_SHA = (
    "7246242b67afae0d13104452bc325782"
    "7cb778119b54e7a26fb7fb55993697ea"
)

EXPECTED_NEW_A_SHA = (
    "3f55d808d834076865c992200b1294fb"
    "84d1dd5be83f9d39cb917e79da12424b"
)

EXPECTED_NEW_U_SHA = (
    "c2fedce8a8f6621dcd617e8750292203"
    "1ffa6574e01d2539b67fa56f9fdc3a31"
)


DUMP_SIZE = 0x400000

VIVA_START = 0x04C20C
ALICE_START = 0x18129C
NEXT_REGION = 0x2C0000

OLD_VIVA_LEN = 0x248EBC
NEW_VIVA_LEN = 0x24A23C

OLD_VIVA_END = 0x2950C8
NEW_VIVA_END = 0x296448

OLD_A_SIZE = 0x113E2C
NEW_A_SIZE = 0x1151AC

OLD_RUNTIME_BASE = 0x1024EC00
OLD_RUNTIME_SIZE = 0x157BB4
NEW_RUNTIME_SIZE = 0x158BB4

OLD_RUNTIME_END = 0x103A67B4
NEW_RUNTIME_END = 0x103A77B4

NEW_MAP_ADDR = 0x10288084
NEW_DICT_ADDR = 0x10292CE8

EXPECTED_MAPPING_ENTRIES = 11033

EXPECTED_HEADROOM = 0x29BB8


# ---------------------------------------------------------------------------
# APPROVED PATCH MATRIX
# ---------------------------------------------------------------------------

PATCHES = {
    # offset: (old, new, role)

    0x00B918: (
        0x00157BB4,
        0x00158BB4,
        "general ALICE size getter",
    ),

    0x00EC54: (
        0x00157BB4,
        0x00158BB4,
        "ALICE configuration size",
    ),

    0x00ECC8: (
        0x00157BB4,
        0x00158BB4,
        "ALICE hardware/window size",
    ),

    0x00FBAC: (
        0x00157BB4,
        0x00158BB4,
        "address-range recognition size",
    ),

    0x0110DC: (
        0x103A67B4,
        0x103A77B4,
        "general region descriptor end",
    ),

    0x04C22C: (
        0x00248EBC,
        0x0024A23C,
        "VIVA FILE_INFO.file_len",
    ),
}


# These values MUST NOT move/change.
KEEP_U32 = {
    0x00B910: (
        0x1024EC00,
        "ALICE base getter",
    ),

    0x00C188: (
        0x1024EC00,
        "LZMA preset base",
    ),

    0x00C18C: (
        0x103A67B4,
        "LZMA preset end",
    ),

    0x00EC50: (
        0x1024EC00,
        "ALICE config base",
    ),

    0x00ECC4: (
        0x1024EC00,
        "ALICE HW base",
    ),

    0x00FBA8: (
        0x1024EC00,
        "address-range base",
    ),

    0x0110D8: (
        0x1024EC00,
        "region descriptor base",
    ),

    0x04C254: (
        0x1018129C,
        "VIVAInfo alice_base",
    ),

    0x1812A4: (
        0x101812C4,
        "ALICE compressed stream base",
    ),
}


def sha(data):
    return hashlib.sha256(data).hexdigest()


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


def load_probe():
    spec = importlib.util.spec_from_file_location(
        "s12probe",
        PROBE_PATH,
    )

    module = importlib.util.module_from_spec(
        spec
    )

    spec.loader.exec_module(
        module
    )

    return module


def in_range(pos, start, end):
    return start <= pos < end


def allowed_byte(pos):
    # Repacked ALICE region.
    if in_range(
        pos,
        ALICE_START,
        NEW_VIVA_END,
    ):
        return True

    # Approved metadata u32s.
    for offset in PATCHES:
        if in_range(
            pos,
            offset,
            offset + 4,
        ):
            return True

    return False


def diff_ranges(old, new):
    if len(old) != len(new):
        raise ValueError(
            "diff requires equal-size buffers"
        )

    ranges = []

    start = None

    for i, (a, b) in enumerate(
        zip(old, new)
    ):
        if a != b:
            if start is None:
                start = i
        elif start is not None:
            ranges.append(
                (start, i)
            )
            start = None

    if start is not None:
        ranges.append(
            (start, len(old))
        )

    return ranges


def changed_bytes(old, new):
    return sum(
        1
        for a, b in zip(old, new)
        if a != b
    )


def fmt_range(start, end):
    return (
        f"0x{start:06X}-0x{end - 1:06X}"
        f" len=0x{end - start:X}"
    )


# ---------------------------------------------------------------------------
# INPUT VALIDATION
# ---------------------------------------------------------------------------

for p in (
    DUMP_PATH,
    A_PATH,
    U_PATH,
    VIVA_PATH,
    PROBE_PATH,
):
    if not p.is_file():
        raise SystemExit(
            f"ERROR: missing {p}"
        )


original = DUMP_PATH.read_bytes()
old_a = A_PATH.read_bytes()
old_u = U_PATH.read_bytes()
old_viva = VIVA_PATH.read_bytes()


assert len(original) == DUMP_SIZE
assert sha(original) == EXPECTED_DUMP_SHA

assert len(old_a) == OLD_A_SIZE
assert sha(old_a) == EXPECTED_A_SHA

assert len(old_u) == OLD_RUNTIME_SIZE
assert sha(old_u) == EXPECTED_U_SHA

assert len(old_viva) == OLD_VIVA_LEN

assert (
    original[
        VIVA_START:
        VIVA_START + OLD_VIVA_LEN
    ]
    == old_viva
)

assert (
    original[
        ALICE_START:
        ALICE_START + OLD_A_SIZE
    ]
    == old_a
)


print("=" * 118)
print(
    "S12.6 - OFFLINE CANDIDATE BUILD "
    "+ EXHAUSTIVE DIFF ALLOW-LIST"
)
print("=" * 118)

print()
print("INPUT VALIDATION")
print("-" * 118)

print(
    f"original dump  "
    f"size=0x{len(original):X} "
    f"sha={sha(original)}"
)

print(
    f"original ALICE "
    f"size=0x{len(old_a):X} "
    f"sha={sha(old_a)}"
)

print(
    f"original U     "
    f"size=0x{len(old_u):X} "
    f"sha={sha(old_u)}"
)

print(
    "canonical inputs : PASS"
)


# ---------------------------------------------------------------------------
# REBUILD EXTENDED ALICE
# ---------------------------------------------------------------------------

probe = load_probe()

profile = probe.parse_container(
    old_a
)

payload = probe.build_extension(
    old_u,
    profile["dictionary"],
)

new_u = (
    old_u
    + payload
)

new_a, stats = probe.repack(
    new_u,
    old_a,
)

decoded = probe.decode_exact(
    new_a,
    len(new_u),
)


assert decoded == new_u

assert len(new_u) == NEW_RUNTIME_SIZE
assert sha(new_u) == EXPECTED_NEW_U_SHA

assert len(new_a) == NEW_A_SIZE
assert sha(new_a) == EXPECTED_NEW_A_SHA

assert (
    stats["mapping_entries"]
    == EXPECTED_MAPPING_ENTRIES
)

assert (
    stats["new_map_addr"]
    == NEW_MAP_ADDR
)

assert (
    stats["new_dict_addr"]
    == NEW_DICT_ADDR
)

# Critical LZMA property:
# the original preset window is byte-for-byte
# the PREFIX of the extended ALICE runtime image.
assert (
    new_u[:OLD_RUNTIME_SIZE]
    == old_u
)


print()
print("EXTENDED ALICE")
print("-" * 118)

print(
    f"new U size       = "
    f"0x{len(new_u):X}"
)

print(
    f"new U sha256     = "
    f"{sha(new_u)}"
)

print(
    f"new ALICE size   = "
    f"0x{len(new_a):X}"
)

print(
    f"new ALICE sha256 = "
    f"{sha(new_a)}"
)

print(
    f"mapping entries  = "
    f"{stats['mapping_entries']}"
)

print(
    f"mapping addr     = "
    f"0x{stats['new_map_addr']:08X}"
)

print(
    f"dictionary addr  = "
    f"0x{stats['new_dict_addr']:08X}"
)

print(
    "old LZMA preset prefix preserved : PASS"
)


# ---------------------------------------------------------------------------
# EXTRA STRUCTURAL CHECKS INSIDE ALICE_2
# ---------------------------------------------------------------------------

old_profile = probe.parse_container(
    old_a
)

new_profile = probe.parse_container(
    new_a
)

# Only the COMPLETE groups before the final
# partially-filled original group are required
# to remain byte-identical.
#
# Original exact U ends at 0x157BB4.
# Its final 0x80-byte group starts at 0x157B80:
#
#   real bytes = 0x34
#   old padding = 0x4C
#
# With the +0x1000 extension, those old padding
# bytes become actual payload bytes. Therefore
# the final old compressed group is EXPECTED to
# change.
#
# Derive the compressed boundary dynamically
# from the mapping entry for the final original
# data group.

old_stream = old_a[
    0x28:
    old_profile["map_off"]
]

new_stream = new_a[
    0x28:
    new_profile["map_off"]
]


old_group_count = (
    len(old_profile["mapping"])
    - 1
)

assert old_group_count == 11000


last_old_group_index = (
    old_group_count
    - 1
)

last_old_group_u_start = (
    last_old_group_index
    * 0x80
)

assert (
    last_old_group_u_start
    == 0x157B80
)


old_real_tail = (
    len(old_u)
    - last_old_group_u_start
)

old_padding_tail = (
    0x80
    - old_real_tail
)

assert old_real_tail == 0x34
assert old_padding_tail == 0x4C


# Mapping entry [-2] is the final data-group
# mapping; [-1] is the sentinel.
last_old_group_map = (
    old_profile["mapping"][-2]
)

stable_stream_len = (
    (
        last_old_group_map
        & 0x00FFFFFF
    )
    -
    (
        old_profile["base"]
        & 0x00FFFFFF
    )
) & 0x00FFFFFF


assert (
    0
    < stable_stream_len
    < len(old_stream)
)


# Every compressed byte preceding the final
# original group must remain identical.
assert (
    new_stream[
        :stable_stream_len
    ]
    ==
    old_stream[
        :stable_stream_len
    ]
)


# Original mapping:
#
#   11000 data entries
#   + 1 sentinel
#
# The final data entry may legitimately change
# because its first half-block now contains new
# bytes instead of old zero padding.
# The sentinel necessarily changes because the
# stream grows.
#
# Therefore entries 0..10998 must remain exact.
stable_mapping_count = (
    len(old_profile["mapping"])
    - 2
)

assert stable_mapping_count == 10999

assert (
    tuple(
        new_profile["mapping"][
            :stable_mapping_count
        ]
    )
    ==
    tuple(
        old_profile["mapping"][
            :stable_mapping_count
        ]
    )
)


# Sanity: new image gained exactly 32 complete
# 0x80-byte mapping groups.
assert (
    (
        len(new_profile["mapping"])
        - len(old_profile["mapping"])
    )
    == 32
)


# Codebook/dictionary strictly preserved.
assert (
    new_profile["dictionary"]
    == old_profile["dictionary"]
)

assert (
    new_profile["dict_blob"]
    == old_profile["dict_blob"]
)


print()
print("ALICE INTERNAL INVARIANTS")
print("-" * 118)

print(
    "stable stream prefix   : PASS"
)

print(
    f"stable stream bytes    = "
    f"0x{stable_stream_len:X}"
)

print(
    f"stable mapping entries = "
    f"{stable_mapping_count}"
)

print(
    f"last old group U start = "
    f"0x{last_old_group_u_start:X}"
)

print(
    f"last old real bytes    = "
    f"0x{old_real_tail:X}"
)

print(
    f"replaced old padding   = "
    f"0x{old_padding_tail:X}"
)

print(
    "stable mappings        : PASS"
)

print(
    "dictionary/codebook    : PASS"
)


# ---------------------------------------------------------------------------
# PRE-PATCH GUARDS
# ---------------------------------------------------------------------------

print()
print("PRE-PATCH MATRIX")
print("-" * 118)

for offset, (
    expected_old,
    expected_new,
    role,
) in PATCHES.items():

    actual = u32(
        original,
        offset,
    )

    print(
        f"D+0x{offset:06X} "
        f"{role:<38} "
        f"0x{actual:08X}"
    )

    if actual != expected_old:
        raise AssertionError(
            f"{role}: original mismatch "
            f"at 0x{offset:X}"
        )


for offset, (
    expected,
    role,
) in KEEP_U32.items():

    actual = u32(
        original,
        offset,
    )

    if actual != expected:
        raise AssertionError(
            f"KEEP field {role}: "
            f"0x{actual:08X} != "
            f"0x{expected:08X}"
        )


print(
    "all original patch guards : PASS"
)


# ---------------------------------------------------------------------------
# BUILD CANDIDATE IN MEMORY
# ---------------------------------------------------------------------------

candidate = bytearray(
    original
)

# Apply approved scalar fields only.
for offset, (
    old_value,
    new_value,
    role,
) in PATCHES.items():

    assert (
        u32(candidate, offset)
        == old_value
    )

    put_u32(
        candidate,
        offset,
        new_value,
    )


# Insert the rebuilt ALICE_2.
candidate[
    ALICE_START:
    ALICE_START + len(new_a)
] = new_a


# Candidate must remain the exact flash size.
assert len(candidate) == DUMP_SIZE


# ---------------------------------------------------------------------------
# POST-PATCH GUARDS
# ---------------------------------------------------------------------------

print()
print("POST-PATCH MATRIX")
print("-" * 118)

for offset, (
    old_value,
    new_value,
    role,
) in PATCHES.items():

    actual = u32(
        candidate,
        offset,
    )

    print(
        f"D+0x{offset:06X} "
        f"{role:<38} "
        f"0x{old_value:08X}"
        f" -> 0x{actual:08X}"
    )

    if actual != new_value:
        raise AssertionError(
            f"{role}: patch failed"
        )


for offset, (
    expected,
    role,
) in KEEP_U32.items():

    actual = u32(
        candidate,
        offset,
    )

    if actual != expected:
        raise AssertionError(
            f"KEEP field changed: "
            f"{role}"
        )


# Explicitly prove the LZMA bound is untouched.
assert (
    u32(candidate, 0xC188)
    == OLD_RUNTIME_BASE
)

assert (
    u32(candidate, 0xC18C)
    == OLD_RUNTIME_END
)


print()
print(
    "LZMA preset base/end untouched : PASS"
)


# ---------------------------------------------------------------------------
# PHYSICAL LAYOUT CHECKS
# ---------------------------------------------------------------------------

assert (
    ALICE_START
    + len(new_a)
    == NEW_VIVA_END
)

assert (
    VIVA_START
    + NEW_VIVA_LEN
    == NEW_VIVA_END
)

assert (
    NEXT_REGION
    - NEW_VIVA_END
    == EXPECTED_HEADROOM
)


# Everything after the candidate VIVA,
# through the next occupied region, must remain
# exactly what was in the original dump.
assert (
    bytes(
        candidate[
            NEW_VIVA_END:
            NEXT_REGION
        ]
    )
    ==
    original[
        NEW_VIVA_END:
        NEXT_REGION
    ]
)

# Everything from the next region to EOF must
# be byte-identical.
assert (
    bytes(
        candidate[NEXT_REGION:]
    )
    ==
    original[NEXT_REGION:]
)


# ZIMAGE / BOOT_ZIMAGE / DCM physical region
# must remain byte-identical.
assert (
    bytes(
        candidate[
            VIVA_START + 0x4C:
            ALICE_START
        ]
    )
    ==
    original[
        VIVA_START + 0x4C:
        ALICE_START
    ]
)


print()
print("PHYSICAL LAYOUT")
print("-" * 118)

print(
    f"new VIVA end       = "
    f"0x{NEW_VIVA_END:08X}"
)

print(
    f"next region        = "
    f"0x{NEXT_REGION:08X}"
)

print(
    f"remaining headroom = "
    f"0x{NEXT_REGION - NEW_VIVA_END:X}"
)

print(
    "ZIMAGE/BOOT/DCM payload unchanged : PASS"
)

print(
    "post-VIVA free space unchanged     : PASS"
)

print(
    "next region -> EOF unchanged       : PASS"
)


# ---------------------------------------------------------------------------
# EXHAUSTIVE BYTE DIFF
# ---------------------------------------------------------------------------

candidate_bytes = bytes(
    candidate
)

ranges = diff_ranges(
    original,
    candidate_bytes,
)

bad_positions = []

for start, end in ranges:
    for pos in range(start, end):
        if (
            original[pos]
            != candidate_bytes[pos]
            and not allowed_byte(pos)
        ):
            bad_positions.append(pos)

            if len(bad_positions) >= 32:
                break

    if bad_positions:
        break


if bad_positions:
    print()
    print(
        "UNAUTHORIZED BYTE DIFFERENCES:"
    )

    for pos in bad_positions:
        print(
            f"  0x{pos:06X}: "
            f"{original[pos]:02X}"
            f" -> "
            f"{candidate_bytes[pos]:02X}"
        )

    raise AssertionError(
        "candidate modifies bytes "
        "outside allow-list"
    )


# Every scalar field expected to CHANGE
# must actually differ.
for offset, (
    old_value,
    new_value,
    role,
) in PATCHES.items():

    if old_value == new_value:
        raise AssertionError(
            f"invalid patch matrix: {role}"
        )

    if (
        original[
            offset:
            offset + 4
        ]
        ==
        candidate_bytes[
            offset:
            offset + 4
        ]
    ):
        raise AssertionError(
            f"approved patch produced no diff: "
            f"{role}"
        )


# No modifications are allowed between the
# metadata/VIVA header and ALICE except those
# explicit scalar fields.
for i in range(
    VIVA_START,
    ALICE_START,
):
    if (
        original[i]
        != candidate_bytes[i]
        and not allowed_byte(i)
    ):
        raise AssertionError(
            f"unexpected pre-ALICE VIVA diff "
            f"at 0x{i:X}"
        )


changed_count = changed_bytes(
    original,
    candidate_bytes,
)


print()
print("=" * 118)
print("EXHAUSTIVE DIFF AUDIT")
print("=" * 118)

print(
    f"changed bytes = "
    f"{changed_count}"
)

print(
    f"diff ranges   = "
    f"{len(ranges)}"
)

print()

for start, end in ranges:
    label = (
        "ALLOWED"
        if all(
            allowed_byte(i)
            for i in range(start, end)
        )
        else "ERROR"
    )

    print(
        f"{fmt_range(start, end):<36} "
        f"{label}"
    )

print()
print(
    "unauthorized changed bytes = 0"
)


# ---------------------------------------------------------------------------
# EXTRACT CANDIDATE VIVA AND VALIDATE IT
# ---------------------------------------------------------------------------

candidate_viva = (
    candidate_bytes[
        VIVA_START:
        VIVA_START + NEW_VIVA_LEN
    ]
)

assert (
    len(candidate_viva)
    == NEW_VIVA_LEN
)

assert (
    u32(candidate_viva, 0x20)
    == NEW_VIVA_LEN
)

# ALICE position relative to VIVA.
alice_relative = (
    ALICE_START
    - VIVA_START
)

assert (
    candidate_viva[
        alice_relative:
        alice_relative + len(new_a)
    ]
    == new_a
)


# Re-decode ALICE directly from candidate dump.
candidate_a = (
    candidate_bytes[
        ALICE_START:
        NEW_VIVA_END
    ]
)

assert candidate_a == new_a

candidate_decoded = probe.decode_exact(
    candidate_a,
    NEW_RUNTIME_SIZE,
)

assert (
    candidate_decoded
    == new_u
)


print()
print("CANDIDATE SELF-CHECK")
print("-" * 118)

print(
    "candidate VIVA file_len : PASS"
)

print(
    "candidate ALICE extract : PASS"
)

print(
    "candidate ALICE decode  : PASS"
)


# ---------------------------------------------------------------------------
# WRITE OFFLINE ARTIFACTS
# ---------------------------------------------------------------------------

OUT_DIR.mkdir(
    parents=True,
    exist_ok=True,
)

OUT_DUMP.write_bytes(
    candidate_bytes
)

OUT_VIVA.write_bytes(
    candidate_viva
)


manifest = {
    "status": "OFFLINE_CANDIDATE_NOT_FLASH_APPROVED",

    "flash_authorized": False,

    "source": {
        "dump": str(DUMP_PATH),
        "sha256": sha(original),
        "size": len(original),
    },

    "candidate": {
        "dump": str(OUT_DUMP),
        "sha256": sha(candidate_bytes),
        "size": len(candidate_bytes),

        "viva": str(OUT_VIVA),
        "viva_sha256": sha(candidate_viva),
        "viva_size": len(candidate_viva),
    },

    "alice": {
        "runtime_base": f"0x{OLD_RUNTIME_BASE:08X}",
        "old_size": f"0x{OLD_RUNTIME_SIZE:X}",
        "new_size": f"0x{NEW_RUNTIME_SIZE:X}",
        "new_runtime_end": f"0x{NEW_RUNTIME_END:08X}",

        "container_start": f"0x{ALICE_START:X}",
        "container_size": f"0x{len(new_a):X}",
        "container_end": f"0x{NEW_VIVA_END:X}",

        "container_sha256": sha(new_a),
        "decompressed_sha256": sha(new_u),

        "mapping_entries": stats["mapping_entries"],
        "mapping_addr": f"0x{stats['new_map_addr']:08X}",
        "dictionary_addr": f"0x{stats['new_dict_addr']:08X}",
    },

    "lzma_preset": {
        "decision": "KEEP_ORIGINAL_WINDOW",
        "base": "0x1024EC00",
        "end": "0x103A67B4",
        "size": "0x157BB4",
    },

    "physical": {
        "viva_start": f"0x{VIVA_START:X}",
        "viva_file_len": f"0x{NEW_VIVA_LEN:X}",
        "viva_end": f"0x{NEW_VIVA_END:X}",
        "next_region": f"0x{NEXT_REGION:X}",
        "headroom": f"0x{NEXT_REGION - NEW_VIVA_END:X}",
    },

    "patches": [
        {
            "offset": f"0x{offset:X}",
            "old": f"0x{old:08X}",
            "new": f"0x{new:08X}",
            "role": role,
        }
        for offset, (
            old,
            new,
            role,
        ) in PATCHES.items()
    ],

    "diff": {
        "changed_bytes": changed_count,
        "range_count": len(ranges),

        "ranges": [
            {
                "start": f"0x{start:X}",
                "end_exclusive": f"0x{end:X}",
                "length": end - start,
            }
            for start, end in ranges
        ],

        "unauthorized_bytes": 0,
    },
}


OUT_JSON.write_text(
    json.dumps(
        manifest,
        indent=2,
    ),
    encoding="utf-8",
)


diff_lines = [
    "S12.6 exhaustive diff ranges",
    "",
    "STATUS: OFFLINE CANDIDATE - NOT FLASH APPROVED",
    "",
    f"original_sha256 = {sha(original)}",
    f"candidate_sha256 = {sha(candidate_bytes)}",
    f"changed_bytes = {changed_count}",
    f"range_count = {len(ranges)}",
    "",
]

for start, end in ranges:
    diff_lines.append(
        fmt_range(
            start,
            end,
        )
    )

OUT_DIFF.write_text(
    "\n".join(diff_lines) + "\n",
    encoding="utf-8",
)


# ---------------------------------------------------------------------------
# FINAL RESULT
# ---------------------------------------------------------------------------

print()
print("=" * 118)
print("S12.6 RESULT")
print("=" * 118)

print(
    "CANONICAL INPUTS             : PASS"
)

print(
    "DETERMINISTIC +0x1000 ALICE  : PASS"
)

print(
    "STABLE STREAM PREFIX         : PASS"
)

print(
    "STABLE MAPPINGS              : PASS"
)

print(
    "DICTIONARY PRESERVED         : PASS"
)

print(
    "APPROVED METADATA PATCHES    : PASS"
)

print(
    "LZMA PRESET BOUND UNCHANGED  : PASS"
)

print(
    "PHYSICAL GAP / NEXT REGION   : PASS"
)

print(
    "EXHAUSTIVE DIFF ALLOW-LIST   : PASS"
)

print(
    "CANDIDATE SELF-DECODE        : PASS"
)

print()
print(
    f"candidate dump SHA256 = "
    f"{sha(candidate_bytes)}"
)

print(
    f"candidate VIVA SHA256 = "
    f"{sha(candidate_viva)}"
)

print()
print(
    f"candidate dump = {OUT_DUMP}"
)

print(
    f"manifest       = {OUT_JSON}"
)

print(
    f"diff report    = {OUT_DIFF}"
)

print()
print(
    "STATUS: OFFLINE CANDIDATE "
    "- NOT FLASH APPROVED"
)

print()
print(
    "NEXT GATE: recovery/read-back "
    "validation and independent candidate "
    "audit before any handset write."
)
