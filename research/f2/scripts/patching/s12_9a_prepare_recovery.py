#!/usr/bin/env python3

from pathlib import Path
import hashlib
import json


ROOT = Path(r"C:\Users\verto\F2-Altice-MobiWire")

OUT = (
    ROOT
    / "research"
    / "f2"
    / "work"
    / "repro"
)

LIVE_A = (
    OUT
    / "s12_8_serial_readback_A.bin"
)

LIVE_B = (
    OUT
    / "s12_8_serial_readback_B.bin"
)

CANDIDATE = (
    OUT
    / "s12_8e_live_preserving_candidate_NOT_FOR_FLASH.bin"
)

RECOVERY = (
    OUT
    / "s12_9_recovery"
)

MANIFEST = (
    RECOVERY
    / "s12_9a_recovery_manifest.json"
)

REPORT = (
    RECOVERY
    / "s12_9a_recovery_report.txt"
)


FLASH_SIZE = 0x400000
LIVE_BOUNDARY = 0x2C0000

EXPECTED_LIVE_SHA = (
    "c571f3852f4a70d1845cc79abaa95007"
    "f8826ec858a1db1ad501c4a2a7b35ce6"
)

EXPECTED_CANDIDATE_SHA = (
    "47b41c572d7d9f09ac5b9562dff5977e"
    "9ea99a16b9f8e126247992b493144fd4"
)

EXPECTED_CHANGED_BYTES = 62429
EXPECTED_DIFF_RANGES = 792


def sha(data):
    return hashlib.sha256(data).hexdigest()


def require(path):
    if not path.is_file():
        raise SystemExit(
            f"ERROR missing:\n{path}"
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


def touched_sectors(ranges, size):
    sectors = set()

    for start, end in ranges:

        first = start // size
        last = (end - 1) // size

        for s in range(
            first,
            last + 1,
        ):
            sectors.add(s)

    return sorted(sectors)


def sector_union_size(sectors, size):
    return len(sectors) * size


RECOVERY.mkdir(
    parents=True,
    exist_ok=True,
)

live_a = require(LIVE_A)
live_b = require(LIVE_B)
candidate = require(CANDIDATE)


print("=" * 112)
print("S12.9A - OFFLINE RECOVERY / ROLLBACK PREPARATION")
print("=" * 112)
print()
print("NO DEVICE ACCESS")
print("NO FLASH WRITE")
print("NO ERASE")
print()


# ------------------------------------------------------------------
# 1. INPUTS
# ------------------------------------------------------------------

print("1. INPUT VALIDATION")
print("-" * 112)

assert sha(live_a) == EXPECTED_LIVE_SHA
assert sha(live_b) == EXPECTED_LIVE_SHA
assert live_a == live_b

assert (
    sha(candidate)
    == EXPECTED_CANDIDATE_SHA
)

assert (
    candidate[LIVE_BOUNDARY:]
    == live_a[LIVE_BOUNDARY:]
)

print(
    f"live A SHA256 : {sha(live_a)} PASS"
)

print(
    f"live B SHA256 : {sha(live_b)} PASS"
)

print(
    f"candidate     : {sha(candidate)} PASS"
)

print(
    "live A == live B : PASS"
)

print(
    "live tail preserved in candidate : PASS"
)


# ------------------------------------------------------------------
# 2. EXACT PATCH DIFF
# ------------------------------------------------------------------

print()
print("2. EXACT PATCH FOOTPRINT")
print("-" * 112)

changed, ranges = diff_ranges(
    live_a,
    candidate,
)

assert changed == EXPECTED_CHANGED_BYTES
assert len(ranges) == EXPECTED_DIFF_RANGES

assert all(
    end <= LIVE_BOUNDARY
    for start, end in ranges
)

print(
    f"changed bytes : {changed} PASS"
)

print(
    f"diff ranges   : {len(ranges)} PASS"
)

print(
    "all changes < 0x2C0000 : PASS"
)

print(
    f"first change : 0x{ranges[0][0]:06X}"
)

print(
    f"last change  : 0x{ranges[-1][1]-1:06X}"
)


# ------------------------------------------------------------------
# 3. ERASE-GRANULARITY HYPOTHESES
# ------------------------------------------------------------------

print()
print("3. ERASE-GRANULARITY HYPOTHESES")
print("-" * 112)

hypotheses = (
    ("4K", 0x1000),
    ("64K", 0x10000),
)

manifest_hypotheses = {}


for label, sector_size in hypotheses:

    sectors = touched_sectors(
        ranges,
        sector_size,
    )

    print()
    print(
        f"{label} HYPOTHESIS "
        f"(sector=0x{sector_size:X})"
    )

    print(
        f"touched sectors : "
        f"{len(sectors)}"
    )

    print(
        f"total erase span: "
        f"0x{sector_union_size(sectors, sector_size):X}"
    )

    directory = (
        RECOVERY
        / f"hypothesis_{label.lower()}"
    )

    directory.mkdir(
        parents=True,
        exist_ok=True,
    )

    entries = []

    for index in sectors:

        start = (
            index
            * sector_size
        )

        end = min(
            start + sector_size,
            FLASH_SIZE,
        )

        restore = live_a[
            start:end
        ]

        patched = candidate[
            start:end
        ]

        restore_name = (
            f"restore_"
            f"{start:06X}_"
            f"{end-1:06X}.bin"
        )

        patched_name = (
            f"patched_"
            f"{start:06X}_"
            f"{end-1:06X}.bin"
        )

        restore_path = (
            directory
            / restore_name
        )

        patched_path = (
            directory
            / patched_name
        )

        restore_path.write_bytes(
            restore
        )

        patched_path.write_bytes(
            patched
        )

        assert (
            restore_path.read_bytes()
            == live_a[start:end]
        )

        assert (
            patched_path.read_bytes()
            == candidate[start:end]
        )

        sector_changed = sum(
            x != y
            for x, y in zip(
                restore,
                patched,
            )
        )

        entries.append({
            "start": start,
            "end": end,
            "size": end - start,
            "changed_bytes": sector_changed,
            "restore_sha256": sha(restore),
            "patched_sha256": sha(patched),
            "restore_file": str(restore_path),
            "patched_file": str(patched_path),
        })

    manifest_hypotheses[
        label
    ] = {
        "sector_size": sector_size,
        "sector_count": len(sectors),
        "total_erase_span": (
            sector_union_size(
                sectors,
                sector_size,
            )
        ),
        "sectors": entries,
    }


# ------------------------------------------------------------------
# 4. BYTE-EXACT RESTORE SIMULATION
# ------------------------------------------------------------------

print()
print("4. OFFLINE RESTORE SIMULATION")
print("-" * 112)


for label, sector_size in hypotheses:

    sectors = touched_sectors(
        ranges,
        sector_size,
    )

    # Start from patched candidate.
    restored = bytearray(
        candidate
    )

    # Simulate restoring every possibly erased sector
    # with the exact fresh handset contents.
    for index in sectors:

        start = (
            index
            * sector_size
        )

        end = min(
            start + sector_size,
            FLASH_SIZE,
        )

        restored[
            start:end
        ] = live_a[
            start:end
        ]

    restored = bytes(
        restored
    )

    assert restored == live_a

    print(
        f"{label} sector rollback "
        f"candidate -> live readback : PASS"
    )


# ------------------------------------------------------------------
# 5. PATCH RECONSTRUCTION SIMULATION
# ------------------------------------------------------------------

print()
print("5. OFFLINE PATCH SIMULATION")
print("-" * 112)


for label, sector_size in hypotheses:

    sectors = touched_sectors(
        ranges,
        sector_size,
    )

    rebuilt = bytearray(
        live_a
    )

    for index in sectors:

        start = (
            index
            * sector_size
        )

        end = min(
            start + sector_size,
            FLASH_SIZE,
        )

        rebuilt[
            start:end
        ] = candidate[
            start:end
        ]

    rebuilt = bytes(
        rebuilt
    )

    assert rebuilt == candidate

    assert (
        rebuilt[LIVE_BOUNDARY:]
        == live_a[LIVE_BOUNDARY:]
    )

    print(
        f"{label} sector patch "
        f"live -> candidate : PASS"
    )


# ------------------------------------------------------------------
# 6. WRITE MANIFEST
# ------------------------------------------------------------------

manifest = {
    "stage": "S12.9A",
    "status": (
        "OFFLINE RECOVERY PACKAGE - "
        "NO WRITE AUTHORIZED"
    ),
    "flash_authorized": False,
    "flash_size": FLASH_SIZE,
    "live_boundary": LIVE_BOUNDARY,
    "live_readback_sha256": sha(live_a),
    "candidate_sha256": sha(candidate),
    "patch": {
        "changed_bytes": changed,
        "range_count": len(ranges),
        "first_change": ranges[0][0],
        "last_change": ranges[-1][1] - 1,
    },
    "erase_geometry": {
        "status": "UNKNOWN",
        "note": (
            "4K and 64K are offline hypotheses only; "
            "actual NOR erase geometry must be proven "
            "before device writes."
        ),
    },
    "hypotheses": manifest_hypotheses,
}


MANIFEST.write_text(
    json.dumps(
        manifest,
        indent=2,
    )
    + "\n",
    encoding="utf-8",
)


report_lines = [
    "S12.9A - OFFLINE RECOVERY PACKAGE",
    "",
    f"LIVE SHA256      = {sha(live_a)}",
    f"CANDIDATE SHA256 = {sha(candidate)}",
    "",
    f"PATCH BYTES      = {changed}",
    f"PATCH RANGES     = {len(ranges)}",
    "",
]

for label, sector_size in hypotheses:

    h = manifest_hypotheses[
        label
    ]

    report_lines += [
        f"{label}:",
        (
            f"  sector size      = "
            f"0x{sector_size:X}"
        ),
        (
            f"  sectors touched  = "
            f"{h['sector_count']}"
        ),
        (
            f"  erase span total = "
            f"0x{h['total_erase_span']:X}"
        ),
        (
            "  rollback sim     = PASS"
        ),
        (
            "  patch sim        = PASS"
        ),
        "",
    ]

report_lines += [
    "ERASE GEOMETRY = UNKNOWN",
    "WRITE PRIMITIVE = UNKNOWN",
    "FLASH AUTHORIZED = NO",
    "",
    (
        "NEXT: prove actual NOR/DA write+erase "
        "capability before any handset write."
    ),
]


REPORT.write_text(
    "\n".join(report_lines)
    + "\n",
    encoding="utf-8",
)


print()
print("=" * 112)
print("S12.9A RESULT")
print("=" * 112)

print(
    "LIVE RESTORE BASE            : PASS"
)

print(
    "PATCH FOOTPRINT              : PASS"
)

print(
    "4K ROLLBACK SIMULATION       : PASS"
)

print(
    "64K ROLLBACK SIMULATION      : PASS"
)

print(
    "4K PATCH SIMULATION          : PASS"
)

print(
    "64K PATCH SIMULATION         : PASS"
)

print(
    "LIVE TAIL PRESERVATION       : PASS"
)

print()
print(
    "ERASE GEOMETRY               : UNKNOWN"
)

print(
    "DEVICE WRITE PRIMITIVE       : UNKNOWN"
)

print(
    "FLASH AUTHORIZED             : NO"
)

print()
print(
    f"manifest: {MANIFEST}"
)

print(
    f"report  : {REPORT}"
)
