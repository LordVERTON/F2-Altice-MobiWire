#!/usr/bin/env python3

from pathlib import Path
import hashlib
import json


ROOT = Path(r"C:\Users\verto\F2-Altice-MobiWire")
MTK  = Path(r"C:\Users\verto\mtkclient")

OUT = (
    ROOT
    / "research"
    / "f2"
    / "work"
    / "repro"
)

CANON = (
    MTK
    / "research"
    / "f2"
    / "data"
    / "dumps"
    / "mobiwire_dump_2.bin"
)

S12_6 = (
    OUT
    / "s12_6_candidate_dump_NOT_FOR_FLASH.bin"
)

READBACK_A = (
    OUT
    / "s12_8_serial_readback_A.bin"
)

READBACK_B = (
    OUT
    / "s12_8_serial_readback_B.bin"
)

OUTPUT = (
    OUT
    / "s12_8e_live_preserving_candidate_NOT_FOR_FLASH.bin"
)

MANIFEST = (
    OUT
    / "s12_8e_live_preserving_manifest.json"
)

DIFF_REPORT = (
    OUT
    / "s12_8e_live_preserving_diff_ranges.txt"
)


FLASH_SIZE = 0x400000
LIVE_BOUNDARY = 0x2C0000

EXPECTED_CANON_SHA = (
    "2fc100e5704cf3d6fae0817a22ce2223"
    "97702ffd7351a83763ae1bafd4416922"
)

EXPECTED_S12_6_SHA = (
    "15299fe668390f5d14dc110b5c1f9444"
    "fad2c9be09c2ee86a245ad3c853c5298"
)

EXPECTED_LIVE_SHA = (
    "c571f3852f4a70d1845cc79abaa95007"
    "f8826ec858a1db1ad501c4a2a7b35ce6"
)

EXPECTED_STATIC_SHA = (
    "ac4cc8816e9463e617271ac259f55d5d"
    "3480f003333036691b1dd24f92ca2f1f"
)

EXPECTED_LIVE_TAIL_SHA = (
    "8b9ba9c3dab9e8cfa83181659a64c869"
    "ee25603f487dae5e8ef23db58b676478"
)

EXPECTED_PATCH_CHANGED_BYTES = 62429
EXPECTED_PATCH_RANGES = 792

EXPECTED_HISTORICAL_TAIL_DIFF_BYTES = 80828
EXPECTED_HISTORICAL_TAIL_DIFF_RANGES = 2788


def sha(data):
    return hashlib.sha256(data).hexdigest()


def require(path):
    if not path.is_file():
        raise SystemExit(
            f"ERROR missing file:\n{path}"
        )

    data = path.read_bytes()

    if len(data) != FLASH_SIZE:
        raise SystemExit(
            f"ERROR bad size for {path.name}: "
            f"0x{len(data):X}"
        )

    return data


def diff_ranges(a, b):
    assert len(a) == len(b)

    ranges = []
    changed = 0
    start = None

    for i, (x, y) in enumerate(zip(a, b)):

        if x != y:

            changed += 1

            if start is None:
                start = i

        elif start is not None:

            ranges.append(
                (start, i)
            )

            start = None

    if start is not None:
        ranges.append(
            (start, len(a))
        )

    return changed, ranges


print("=" * 108)
print("S12.8E - BUILD LIVE-PRESERVING OFFLINE CANDIDATE")
print("=" * 108)
print()
print("NO DEVICE ACCESS")
print("NO FLASH WRITE")
print("NO FLASH ERASE")
print()


canon = require(CANON)
s12 = require(S12_6)
live_a = require(READBACK_A)
live_b = require(READBACK_B)


# ------------------------------------------------------------------
# INPUT HASHES
# ------------------------------------------------------------------

print("1. INPUT VALIDATION")
print("-" * 108)

assert sha(canon) == EXPECTED_CANON_SHA
assert sha(s12) == EXPECTED_S12_6_SHA

assert sha(live_a) == EXPECTED_LIVE_SHA
assert sha(live_b) == EXPECTED_LIVE_SHA

assert live_a == live_b

print(
    f"canonical SHA256 : "
    f"{sha(canon)} PASS"
)

print(
    f"S12.6 SHA256     : "
    f"{sha(s12)} PASS"
)

print(
    f"live A SHA256    : "
    f"{sha(live_a)} PASS"
)

print(
    f"live B SHA256    : "
    f"{sha(live_b)} PASS"
)

print(
    "live A == live B : PASS"
)


# ------------------------------------------------------------------
# STATIC/LIVE BOUNDARY
# ------------------------------------------------------------------

print()
print("2. STATIC / LIVE BOUNDARY")
print("-" * 108)

canon_static = canon[
    :LIVE_BOUNDARY
]

live_static = live_a[
    :LIVE_BOUNDARY
]

canon_tail = canon[
    LIVE_BOUNDARY:
]

live_tail = live_a[
    LIVE_BOUNDARY:
]


assert sha(canon_static) == EXPECTED_STATIC_SHA
assert sha(live_static) == EXPECTED_STATIC_SHA

assert canon_static == live_static

assert sha(live_tail) == EXPECTED_LIVE_TAIL_SHA


tail_changed, tail_ranges = diff_ranges(
    canon_tail,
    live_tail,
)

assert (
    tail_changed
    == EXPECTED_HISTORICAL_TAIL_DIFF_BYTES
)

assert (
    len(tail_ranges)
    == EXPECTED_HISTORICAL_TAIL_DIFF_RANGES
)


print(
    f"static SHA256    : "
    f"{sha(live_static)} PASS"
)

print(
    "live static == canonical : PASS"
)

print(
    f"live tail SHA256 : "
    f"{sha(live_tail)} PASS"
)

print(
    f"historical tail changed bytes : "
    f"{tail_changed} PASS"
)

print(
    f"historical tail diff ranges   : "
    f"{len(tail_ranges)} PASS"
)


# ------------------------------------------------------------------
# RE-AUDIT S12.6 DIFF
# ------------------------------------------------------------------

print()
print("3. RE-AUDIT S12.6 PATCH SET")
print("-" * 108)

patch_changed, patch_ranges = diff_ranges(
    canon,
    s12,
)

assert (
    patch_changed
    == EXPECTED_PATCH_CHANGED_BYTES
)

assert (
    len(patch_ranges)
    == EXPECTED_PATCH_RANGES
)


# Absolutely no S12.6 change may touch live data.
for start, end in patch_ranges:

    if end > LIVE_BOUNDARY:
        raise RuntimeError(
            "S12.6 patch reaches live region: "
            f"0x{start:06X}-0x{end-1:06X}"
        )


# Historical S12.6 candidate must have retained the historical tail.
assert (
    s12[LIVE_BOUNDARY:]
    == canon[LIVE_BOUNDARY:]
)


print(
    f"S12.6 changed bytes : "
    f"{patch_changed} PASS"
)

print(
    f"S12.6 diff ranges   : "
    f"{len(patch_ranges)} PASS"
)

print(
    "S12.6 changes below 0x2C0000 only : PASS"
)

print(
    "historical candidate tail unchanged : PASS"
)


# ------------------------------------------------------------------
# BUILD
# ------------------------------------------------------------------

print()
print("4. BUILD LIVE-PRESERVING CANDIDATE")
print("-" * 108)


candidate = bytearray(
    live_a
)


# Apply ONLY the audited canonical -> S12.6 changed ranges.
for start, end in patch_ranges:

    candidate[
        start:end
    ] = s12[
        start:end
    ]


candidate = bytes(
    candidate
)


# ------------------------------------------------------------------
# STRUCTURAL INVARIANTS
# ------------------------------------------------------------------

print()
print("5. STRUCTURAL INVARIANTS")
print("-" * 108)


# Firmware area must be exactly the audited S12.6 candidate.
assert (
    candidate[
        :LIVE_BOUNDARY
    ]
    ==
    s12[
        :LIVE_BOUNDARY
    ]
)


# Live area must be exactly the fresh phone readback.
assert (
    candidate[
        LIVE_BOUNDARY:
    ]
    ==
    live_a[
        LIVE_BOUNDARY:
    ]
)


# Live tail must not have a single changed byte.
assert (
    candidate[
        LIVE_BOUNDARY:
    ]
    ==
    live_b[
        LIVE_BOUNDARY:
    ]
)


print(
    "0x000000..0x2BFFFF "
    "== audited S12.6 : PASS"
)

print(
    "0x2C0000..0x3FFFFF "
    "== live readback A : PASS"
)

print(
    "0x2C0000..0x3FFFFF "
    "== live readback B : PASS"
)


# ------------------------------------------------------------------
# DIFF AGAINST LIVE BASE
# ------------------------------------------------------------------

print()
print("6. LIVE-BASE DIFF AUDIT")
print("-" * 108)


live_changed, live_ranges = diff_ranges(
    live_a,
    candidate,
)

assert (
    live_changed
    == EXPECTED_PATCH_CHANGED_BYTES
)

assert (
    len(live_ranges)
    == EXPECTED_PATCH_RANGES
)


for start, end in live_ranges:

    if end > LIVE_BOUNDARY:
        raise RuntimeError(
            "live candidate changed live-data region"
        )


assert (
    live_ranges
    == patch_ranges
)


print(
    f"changed bytes vs live base : "
    f"{live_changed} PASS"
)

print(
    f"diff ranges vs live base   : "
    f"{len(live_ranges)} PASS"
)

print(
    "range set identical to S12.6 : PASS"
)

print(
    "changed bytes >= 0x2C0000    : 0 PASS"
)


# ------------------------------------------------------------------
# IMPORTANT S12 FIELDS
# ------------------------------------------------------------------

print()
print("7. S12 PATCHED FIELDS")
print("-" * 108)


expected_fields = {
    0x00B918: bytes.fromhex("B48B1500"),
    0x00EC54: bytes.fromhex("B48B1500"),
    0x00ECC8: bytes.fromhex("B48B1500"),
    0x00FBAC: bytes.fromhex("B48B1500"),
    0x0110DC: bytes.fromhex("B4773A10"),
    0x04C22C: bytes.fromhex("3CA22400"),
}


for off, expected in expected_fields.items():

    got = candidate[
        off:off+4
    ]

    assert got == expected

    print(
        f"D+0x{off:06X} "
        f"{got.hex(' ').upper()} PASS"
    )


# LZMA preset end must remain OLD.
assert (
    candidate[
        0x00C18C:
        0x00C190
    ]
    == bytes.fromhex(
        "B4673A10"
    )
)

print(
    "D+0x00C18C "
    "B4 67 3A 10 KEEP PASS"
)


# ------------------------------------------------------------------
# WRITE OUTPUTS
# ------------------------------------------------------------------

print()
print("8. OUTPUT")
print("-" * 108)


OUTPUT.write_bytes(
    candidate
)


with DIFF_REPORT.open(
    "w",
    encoding="utf-8",
) as f:

    for start, end in live_ranges:

        f.write(
            f"0x{start:06X}-"
            f"0x{end-1:06X} "
            f"len=0x{end-start:X}\n"
        )


manifest = {
    "stage": "S12.8E",
    "description": (
        "live-preserving offline candidate"
    ),
    "flash_authorized": False,
    "flash_size": FLASH_SIZE,
    "live_boundary": LIVE_BOUNDARY,
    "inputs": {
        "canonical_sha256": sha(canon),
        "s12_6_candidate_sha256": sha(s12),
        "live_readback_A_sha256": sha(live_a),
        "live_readback_B_sha256": sha(live_b),
    },
    "output": {
        "path": str(OUTPUT),
        "sha256": sha(candidate),
    },
    "patch": {
        "changed_bytes": live_changed,
        "range_count": len(live_ranges),
        "max_changed_address": max(
            end - 1
            for _, end in live_ranges
        ),
    },
    "preserved_live_tail": {
        "start": LIVE_BOUNDARY,
        "end": FLASH_SIZE,
        "sha256": sha(
            candidate[
                LIVE_BOUNDARY:
            ]
        ),
        "matches_readback_A": (
            candidate[
                LIVE_BOUNDARY:
            ]
            ==
            live_a[
                LIVE_BOUNDARY:
            ]
        ),
    },
    "status": (
        "OFFLINE CANDIDATE - "
        "NOT FLASH APPROVED"
    ),
}


MANIFEST.write_text(
    json.dumps(
        manifest,
        indent=2,
    )
    + "\n",
    encoding="utf-8",
)


assert (
    OUTPUT.read_bytes()
    == candidate
)


print(
    f"output SHA256 : "
    f"{sha(candidate)}"
)

print(
    f"output file   : "
    f"{OUTPUT}"
)

print(
    f"manifest      : "
    f"{MANIFEST}"
)

print(
    f"diff report   : "
    f"{DIFF_REPORT}"
)


# ------------------------------------------------------------------
# FINAL
# ------------------------------------------------------------------

print()
print("=" * 108)
print("S12.8E RESULT")
print("=" * 108)

print(
    "CANONICAL INPUT             : PASS"
)

print(
    "LIVE READBACK A == B        : PASS"
)

print(
    "STATIC REGION VALIDATED     : PASS"
)

print(
    "S12.6 PATCH RE-AUDIT        : PASS"
)

print(
    "PATCH SET IDENTICAL         : PASS"
)

print(
    "LIVE TAIL PRESERVED         : PASS"
)

print(
    "LIVE-REGION CHANGED BYTES   : 0 PASS"
)

print()
print(
    "VERDICT:"
)

print(
    "LIVE-PRESERVING OFFLINE "
    "CANDIDATE BUILT AND AUDITED"
)

print()
print(
    "STATUS:"
)

print(
    "NOT FLASH APPROVED"
)

print()
print(
    "NEXT GATE:"
)

print(
    "S12.9 RECOVERY / RESTORE "
    "DESIGN AND VALIDATION"
)
