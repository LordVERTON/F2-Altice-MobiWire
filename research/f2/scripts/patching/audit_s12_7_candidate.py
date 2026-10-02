#!/usr/bin/env python3

"""
S12.7 - Independent offline audit of the S12.6 candidate.

IMPORTANT:
- does NOT import build_s12_6_candidate.py
- does NOT import s12_alice_repack_probe.py
- independently parses and decodes ALICE_2
- independently reconstructs mapping
- independently checks the byte-diff allow-list

NO DEVICE ACCESS.
NO FLASH.
"""

from pathlib import Path
import hashlib
import json
import struct


REPO = Path(r"C:\Users\verto\F2-Altice-MobiWire")
MTK  = Path(r"C:\Users\verto\mtkclient")

ORIGINAL = (
    MTK
    / "research" / "f2"
    / "data" / "dumps"
    / "mobiwire_dump_2.bin"
)

ORIGINAL_U = (
    MTK
    / "research" / "f2"
    / "work" / "extracted"
    / "altice_alice"
    / "alice-py.bin"
)

ORIGINAL_A = (
    MTK
    / "research" / "f2"
    / "work" / "extracted"
    / "altice_alice"
    / "altice_ALICE_2.bin"
)

OUT = (
    REPO
    / "research" / "f2"
    / "work" / "repro"
)

CANDIDATE = (
    OUT
    / "s12_6_candidate_dump_NOT_FOR_FLASH.bin"
)

CANDIDATE_VIVA = (
    OUT
    / "s12_6_candidate_viva_NOT_FOR_FLASH.bin"
)

MANIFEST = (
    OUT
    / "s12_6_candidate_manifest.json"
)

REPORT = (
    OUT
    / "s12_7_independent_audit.txt"
)


EXPECTED_ORIGINAL_SHA = (
    "2fc100e5704cf3d6fae0817a22ce2223"
    "97702ffd7351a83763ae1bafd4416922"
)

EXPECTED_CANDIDATE_SHA = (
    "15299fe668390f5d14dc110b5c1f9444"
    "fad2c9be09c2ee86a245ad3c853c5298"
)

EXPECTED_CANDIDATE_VIVA_SHA = (
    "f2f7edad0f2e20160df81d3b4bec37d"
    "8f308f0d78aada6ba1480deac98dd4a2a"
)

EXPECTED_OLD_U_SHA = (
    "7246242b67afae0d13104452bc325782"
    "7cb778119b54e7a26fb7fb55993697ea"
)

EXPECTED_NEW_U_SHA = (
    "c2fedce8a8f6621dcd617e8750292203"
    "1ffa6574e01d2539b67fa56f9fdc3a31"
)

EXPECTED_PAYLOAD_SHA = (
    "4a13f2510b13cf1fb3353a16f2314197"
    "144e5f4241807b0f3d969468115bfe88"
)

EXPECTED_OLD_A_SHA = (
    "8a06970667c6af37f7a6b1fb28dde062"
    "2e396fccd5c2a0b450bd795a0257988f"
)

EXPECTED_NEW_A_SHA = (
    "3f55d808d834076865c992200b1294fb"
    "84d1dd5be83f9d39cb917e79da12424b"
)


FLASH_SIZE = 0x400000

VIVA_START = 0x04C20C
ALICE_START = 0x18129C

OLD_VIVA_END = 0x2950C8
NEW_VIVA_END = 0x296448

NEXT_REGION = 0x2C0000

OLD_VIVA_SIZE = 0x248EBC
NEW_VIVA_SIZE = 0x24A23C

OLD_A_SIZE = 0x113E2C
NEW_A_SIZE = 0x1151AC

OLD_U_SIZE = 0x157BB4
NEW_U_SIZE = 0x158BB4

RUNTIME_BASE = 0x1024EC00
OLD_RUNTIME_END = 0x103A67B4
NEW_RUNTIME_END = 0x103A77B4

STREAM_BASE = 0x101812C4

NEW_MAP_ADDR = 0x10288084
NEW_DICT_ADDR = 0x10292CE8

EXPECTED_OLD_MAP_COUNT = 11001
EXPECTED_NEW_MAP_COUNT = 11033

EXPECTED_CHANGED_BYTES = 62429
EXPECTED_DIFF_RANGES = 792

EXPECTED_STABLE_STREAM = 0x105A6E
EXPECTED_STABLE_MAPPINGS = 10999


PATCHES = {
    0x00B918: (0x00157BB4, 0x00158BB4),
    0x00EC54: (0x00157BB4, 0x00158BB4),
    0x00ECC8: (0x00157BB4, 0x00158BB4),
    0x00FBAC: (0x00157BB4, 0x00158BB4),
    0x0110DC: (0x103A67B4, 0x103A77B4),
    0x04C22C: (0x00248EBC, 0x0024A23C),
}


KEEP = {
    0x00B910: 0x1024EC00,
    0x00C188: 0x1024EC00,
    0x00C18C: 0x103A67B4,
    0x00EC50: 0x1024EC00,
    0x00ECC4: 0x1024EC00,
    0x00FBA8: 0x1024EC00,
    0x0110D8: 0x1024EC00,
    0x04C254: 0x1018129C,
    0x1812A4: 0x101812C4,
}


HEADER_SIZE = 0x28
HALF_BLOCK_WORDS = 32
HALF_BLOCK_BYTES = 0x40
GROUP_BYTES = 0x80

ADDR_MASK = 0x03FFFFFF
HINT_BIAS = 13


def sha(data):
    return hashlib.sha256(data).hexdigest()


def u32(data, off):
    return struct.unpack_from("<I", data, off)[0]


def align_up(v, a):
    return (v + a - 1) & ~(a - 1)


class BitReader:
    def __init__(self, data):
        self.data = data
        self.bit = 0

    def read(self, n):
        if self.bit + n > len(self.data) * 8:
            raise RuntimeError(
                "compressed stream truncated"
            )

        v = 0

        for _ in range(n):
            b = self.data[self.bit >> 3]
            shift = 7 - (self.bit & 7)

            v = (
                (v << 1)
                | ((b >> shift) & 1)
            )

            self.bit += 1

        return v

    def byte_align(self):
        self.bit = (
            self.bit + 7
        ) & ~7

    @property
    def bytepos(self):
        return self.bit >> 3


def parse_alice(blob):
    if blob[:8] != b"ALICE_2\x00":
        raise RuntimeError(
            "bad ALICE_2 magic"
        )

    base = u32(blob, 0x08)
    map_addr = u32(blob, 0x0C)
    dict_addr = u32(blob, 0x10)

    ranges = struct.unpack_from(
        "<7H",
        blob,
        0x14,
    )

    src_bank = blob[0x22]
    dst_bank = blob[0x23]

    group_words = struct.unpack_from(
        "<H",
        blob,
        0x24,
    )[0]

    map_off = (
        map_addr
        - base
        + HEADER_SIZE
    )

    dict_off = (
        dict_addr
        - base
        + HEADER_SIZE
    )

    if not (
        HEADER_SIZE
        <= map_off
        <= dict_off
        <= len(blob)
    ):
        raise RuntimeError(
            "invalid ALICE geometry"
        )

    stream = blob[
        HEADER_SIZE:
        map_off
    ]

    map_blob = blob[
        map_off:
        dict_off
    ]

    dict_blob = blob[
        dict_off:
    ]

    if len(map_blob) % 4:
        raise RuntimeError(
            "mapping not u32 aligned"
        )

    if len(dict_blob) % 2:
        raise RuntimeError(
            "dictionary not u16 aligned"
        )

    mapping = struct.unpack(
        "<%dI"
        % (len(map_blob) // 4),
        map_blob,
    )

    dictionary = struct.unpack(
        "<%dH"
        % (len(dict_blob) // 2),
        dict_blob,
    )

    expected_dict = sum(
        1 << n
        for n in ranges
    )

    if len(dictionary) != expected_dict:
        raise RuntimeError(
            "dictionary/ranges mismatch"
        )

    if group_words != 0x40:
        raise RuntimeError(
            f"unexpected group size "
            f"0x{group_words:X}"
        )

    return {
        "base": base,
        "map_addr": map_addr,
        "dict_addr": dict_addr,
        "ranges": ranges,
        "src_bank": src_bank,
        "dst_bank": dst_bank,
        "group_words": group_words,
        "map_off": map_off,
        "dict_off": dict_off,
        "stream": stream,
        "mapping": mapping,
        "dictionary": dictionary,
        "dict_blob": dict_blob,
    }


def untranslate_bl_blx(data):
    """
    Independent inverse of ALICE BL/BLX transformation.
    """

    if len(data) & 1:
        raise RuntimeError(
            "odd decompressed length"
        )

    buff = bytearray(data)

    ptr = 0
    count = len(buff) // 2

    while ptr < count - 1:

        if (ptr + 1) % 32 == 0:
            ptr += 1
            continue

        instr, instr2 = struct.unpack_from(
            "<HH",
            buff,
            ptr * 2,
        )

        if (
            instr & 0xF800
        ) != 0xF000:
            ptr += 1
            continue

        if (
            instr2 & 0xF800
        ) == 0xF800:
            upbits = 0xF800

        elif (
            instr2 & 0xF800
        ) == 0xE800:
            upbits = 0xE800

        else:
            ptr += 1
            continue

        combined = (
            (
                (instr & 0x7FF)
                << 12
            )
            +
            (
                (instr2 & 0x7FF)
                << 1
            )
        ) // 2

        if instr & 0x400:
            value = (
                combined
                - (ptr - 1)
                + 0x7FFFFFFE
            )
        else:
            value = (
                combined
                - (ptr - 1)
                - 2
            )

        out1 = (
            ((value >> 11) & 0x7FF)
            | 0xF000
        )

        out2 = (
            (value & 0x7FF)
            | upbits
        )

        struct.pack_into(
            "<HH",
            buff,
            ptr * 2,
            out1,
            out2,
        )

        ptr += 2

    return bytes(buff)


def decode_alice_exact(blob, exact_size):
    p = parse_alice(blob)

    padded = align_up(
        exact_size,
        GROUP_BYTES,
    )

    halfblocks = (
        padded
        // HALF_BLOCK_BYTES
    )

    expected_maps = (
        padded
        // GROUP_BYTES
        + 1
    )

    if (
        len(p["mapping"])
        != expected_maps
    ):
        raise RuntimeError(
            "mapping count mismatch "
            f"{len(p['mapping'])} "
            f"!= {expected_maps}"
        )

    lows = []
    low = 0

    for bits in p["ranges"]:
        lows.append(low)
        low += 1 << bits

    br = BitReader(
        p["stream"]
    )

    translated = bytearray()

    starts = []
    lengths = []

    for hb in range(halfblocks):

        start = br.bytepos
        starts.append(start)

        for _ in range(
            HALF_BLOCK_WORDS
        ):
            prefix = br.read(3)

            if prefix == 7:
                word = br.read(16)

            else:
                if prefix >= 7:
                    raise RuntimeError(
                        "invalid dictionary prefix"
                    )

                bits = p["ranges"][
                    prefix
                ]

                payload = br.read(bits)

                idx = (
                    lows[prefix]
                    + payload
                )

                if idx >= len(
                    p["dictionary"]
                ):
                    raise RuntimeError(
                        "dictionary overflow"
                    )

                word = p["dictionary"][
                    idx
                ]

            translated.extend(
                struct.pack(
                    "<H",
                    word,
                )
            )

        br.byte_align()

        lengths.append(
            br.bytepos - start
        )

    if (
        br.bytepos
        != len(p["stream"])
    ):
        raise RuntimeError(
            "stream was not consumed "
            "exactly "
            f"0x{br.bytepos:X} "
            f"!= 0x{len(p['stream']):X}"
        )

    # Reconstruct mapping independently.
    expected_mapping = []

    for i in range(
        0,
        len(starts),
        2,
    ):

        hint = (
            lengths[i]
            - HINT_BIAS
        )

        if not 0 <= hint <= 0x3F:
            raise RuntimeError(
                f"mapping hint overflow "
                f"at {i}"
            )

        word = (
            (
                p["base"]
                + starts[i]
            )
            & ADDR_MASK
        ) | (
            hint << 26
        )

        expected_mapping.append(
            word
        )

    expected_mapping.append(
        (
            p["base"]
            + len(p["stream"])
        )
        & ADDR_MASK
    )

    if (
        tuple(expected_mapping)
        != tuple(p["mapping"])
    ):
        for i, (
            got,
            expected,
        ) in enumerate(
            zip(
                p["mapping"],
                expected_mapping,
            )
        ):
            if got != expected:
                raise RuntimeError(
                    "mapping mismatch "
                    f"#{i}: "
                    f"got=0x{got:08X} "
                    f"expected=0x{expected:08X}"
                )

        raise RuntimeError(
            "mapping mismatch"
        )

    raw = bytes(
        translated[
            :exact_size
        ]
    )

    return (
        untranslate_bl_blx(raw),
        p,
        tuple(starts),
        tuple(lengths),
    )


def diff_ranges(a, b):
    if len(a) != len(b):
        raise RuntimeError(
            "different flash sizes"
        )

    ranges = []

    start = None
    changed = 0

    for i, (
        x,
        y,
    ) in enumerate(
        zip(a, b)
    ):
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
            (
                start,
                len(a),
            )
        )

    return changed, ranges


def allowed(pos):
    if (
        ALICE_START
        <= pos
        < NEW_VIVA_END
    ):
        return True

    for off in PATCHES:
        if (
            off
            <= pos
            < off + 4
        ):
            return True

    return False


def require_file(p):
    if not p.is_file():
        raise SystemExit(
            f"ERROR missing file:\n{p}"
        )

    return p.read_bytes()


print("=" * 112)
print(
    "S12.7 - INDEPENDENT OFFLINE "
    "CANDIDATE AUDIT"
)
print("=" * 112)


original = require_file(
    ORIGINAL
)

old_u = require_file(
    ORIGINAL_U
)

old_a = require_file(
    ORIGINAL_A
)

candidate = require_file(
    CANDIDATE
)

candidate_viva_file = require_file(
    CANDIDATE_VIVA
)


# ------------------------------------------------------------------
# HASH / SIZE GATE
# ------------------------------------------------------------------

print()
print("1. CANONICAL HASHES")
print("-" * 112)

assert len(original) == FLASH_SIZE
assert len(candidate) == FLASH_SIZE

assert (
    sha(original)
    == EXPECTED_ORIGINAL_SHA
)

assert (
    sha(candidate)
    == EXPECTED_CANDIDATE_SHA
)

assert (
    sha(candidate_viva_file)
    == EXPECTED_CANDIDATE_VIVA_SHA
)

assert (
    sha(old_u)
    == EXPECTED_OLD_U_SHA
)

assert (
    sha(old_a)
    == EXPECTED_OLD_A_SHA
)

print(
    f"original       : "
    f"{sha(original)} PASS"
)

print(
    f"candidate      : "
    f"{sha(candidate)} PASS"
)

print(
    f"candidate VIVA : "
    f"{sha(candidate_viva_file)} PASS"
)


# ------------------------------------------------------------------
# SCALAR PATCHES
# ------------------------------------------------------------------

print()
print("2. SCALAR PATCH MATRIX")
print("-" * 112)

for off, (
    old_value,
    new_value,
) in PATCHES.items():

    got_old = u32(
        original,
        off,
    )

    got_new = u32(
        candidate,
        off,
    )

    assert got_old == old_value
    assert got_new == new_value

    print(
        f"D+0x{off:06X} "
        f"0x{got_old:08X}"
        f" -> "
        f"0x{got_new:08X} PASS"
    )


print()
print("3. KEEP MATRIX")
print("-" * 112)

for off, expected in KEEP.items():

    a = u32(
        original,
        off,
    )

    b = u32(
        candidate,
        off,
    )

    assert a == expected
    assert b == expected

    print(
        f"D+0x{off:06X} "
        f"0x{expected:08X} KEEP PASS"
    )


# ------------------------------------------------------------------
# VIVA / PHYSICAL LAYOUT
# ------------------------------------------------------------------

print()
print("4. VIVA / PHYSICAL LAYOUT")
print("-" * 112)

candidate_viva = candidate[
    VIVA_START:
    VIVA_START
    + NEW_VIVA_SIZE
]

assert (
    candidate_viva
    == candidate_viva_file
)

assert (
    len(candidate_viva)
    == NEW_VIVA_SIZE
)

assert (
    u32(candidate, 0x04C22C)
    == NEW_VIVA_SIZE
)

assert (
    VIVA_START
    + NEW_VIVA_SIZE
    == NEW_VIVA_END
)

assert (
    candidate[
        NEW_VIVA_END:
        NEXT_REGION
    ]
    ==
    original[
        NEW_VIVA_END:
        NEXT_REGION
    ]
)

assert (
    candidate[
        NEXT_REGION:
    ]
    ==
    original[
        NEXT_REGION:
    ]
)

print(
    "candidate VIVA slice      : PASS"
)

print(
    "VIVA file_len             : PASS"
)

print(
    f"new VIVA end              : "
    f"0x{NEW_VIVA_END:X}"
)

print(
    f"headroom                  : "
    f"0x{NEXT_REGION - NEW_VIVA_END:X}"
)

print(
    "post-VIVA gap unchanged   : PASS"
)

print(
    "next region -> EOF        : PASS"
)


# ------------------------------------------------------------------
# EXHAUSTIVE DIFF
# ------------------------------------------------------------------

print()
print("5. EXHAUSTIVE DIFF")
print("-" * 112)

changed, ranges = diff_ranges(
    original,
    candidate,
)

assert (
    changed
    == EXPECTED_CHANGED_BYTES
)

assert (
    len(ranges)
    == EXPECTED_DIFF_RANGES
)

bad = []

for start, end in ranges:
    for pos in range(
        start,
        end,
    ):
        if (
            original[pos]
            != candidate[pos]
            and not allowed(pos)
        ):
            bad.append(pos)

            if len(bad) >= 16:
                break

    if bad:
        break


if bad:
    for pos in bad:
        print(
            f"UNAUTHORIZED "
            f"0x{pos:06X}: "
            f"{original[pos]:02X}"
            f" -> "
            f"{candidate[pos]:02X}"
        )

    raise RuntimeError(
        "unauthorized diff detected"
    )


print(
    f"changed bytes             : "
    f"{changed} PASS"
)

print(
    f"diff ranges               : "
    f"{len(ranges)} PASS"
)

print(
    "unauthorized changed bytes: "
    "0 PASS"
)


# ------------------------------------------------------------------
# ALICE CONTAINERS
# ------------------------------------------------------------------

print()
print("6. ALICE CONTAINER")
print("-" * 112)

candidate_a = candidate[
    ALICE_START:
    NEW_VIVA_END
]

assert len(candidate_a) == NEW_A_SIZE

assert (
    sha(candidate_a)
    == EXPECTED_NEW_A_SHA
)

old_profile = parse_alice(
    old_a
)

new_profile = parse_alice(
    candidate_a
)

assert (
    old_profile["base"]
    == STREAM_BASE
)

assert (
    new_profile["base"]
    == STREAM_BASE
)

assert (
    new_profile["map_addr"]
    == NEW_MAP_ADDR
)

assert (
    new_profile["dict_addr"]
    == NEW_DICT_ADDR
)

assert (
    len(old_profile["mapping"])
    == EXPECTED_OLD_MAP_COUNT
)

assert (
    len(new_profile["mapping"])
    == EXPECTED_NEW_MAP_COUNT
)

assert (
    old_profile["dict_blob"]
    == new_profile["dict_blob"]
)

assert (
    old_profile["dictionary"]
    == new_profile["dictionary"]
)

print(
    f"new ALICE SHA256          : "
    f"{sha(candidate_a)} PASS"
)

print(
    f"mapping addr              : "
    f"0x{new_profile['map_addr']:08X} PASS"
)

print(
    f"dictionary addr           : "
    f"0x{new_profile['dict_addr']:08X} PASS"
)

print(
    f"mapping entries           : "
    f"{len(new_profile['mapping'])} PASS"
)

print(
    "dictionary exact equality : PASS"
)


# ------------------------------------------------------------------
# STABLE PREFIX / MAPPINGS
# ------------------------------------------------------------------

print()
print("7. STABLE ORIGINAL PREFIX")
print("-" * 112)

last_old_group_map = (
    old_profile["mapping"][-2]
)

stable_stream = (
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
    stable_stream
    == EXPECTED_STABLE_STREAM
)

assert (
    old_profile["stream"][
        :stable_stream
    ]
    ==
    new_profile["stream"][
        :stable_stream
    ]
)

stable_mapping_count = (
    len(old_profile["mapping"])
    - 2
)

assert (
    stable_mapping_count
    == EXPECTED_STABLE_MAPPINGS
)

assert (
    tuple(
        old_profile["mapping"][
            :stable_mapping_count
        ]
    )
    ==
    tuple(
        new_profile["mapping"][
            :stable_mapping_count
        ]
    )
)

print(
    f"stable stream bytes       : "
    f"0x{stable_stream:X} PASS"
)

print(
    f"stable mapping entries    : "
    f"{stable_mapping_count} PASS"
)


# ------------------------------------------------------------------
# INDEPENDENT EXACT DECODE
# ------------------------------------------------------------------

print()
print("8. INDEPENDENT ALICE DECODE")
print("-" * 112)

decoded, decoded_profile, starts, lengths = (
    decode_alice_exact(
        candidate_a,
        NEW_U_SIZE,
    )
)

assert len(decoded) == NEW_U_SIZE

assert (
    sha(decoded)
    == EXPECTED_NEW_U_SHA
)

assert (
    decoded[
        :OLD_U_SIZE
    ]
    == old_u
)

payload = decoded[
    OLD_U_SIZE:
]

assert len(payload) == 0x1000

assert (
    sha(payload)
    == EXPECTED_PAYLOAD_SHA
)

print(
    f"decoded U size            : "
    f"0x{len(decoded):X} PASS"
)

print(
    f"decoded U SHA256          : "
    f"{sha(decoded)} PASS"
)

print(
    "original U prefix        : PASS"
)

print(
    f"payload size              : "
    f"0x{len(payload):X} PASS"
)

print(
    f"payload SHA256            : "
    f"{sha(payload)} PASS"
)

print(
    "mapping reconstructed    : PASS"
)


# ------------------------------------------------------------------
# MANIFEST CROSS-CHECK
# ------------------------------------------------------------------

print()
print("9. MANIFEST CROSS-CHECK")
print("-" * 112)

if MANIFEST.is_file():
    manifest = json.loads(
        MANIFEST.read_text(
            encoding="utf-8"
        )
    )

    assert (
        manifest[
            "candidate"
        ][
            "sha256"
        ]
        == EXPECTED_CANDIDATE_SHA
    )

    assert (
        manifest[
            "candidate"
        ][
            "viva_sha256"
        ]
        == EXPECTED_CANDIDATE_VIVA_SHA
    )

    assert (
        manifest[
            "diff"
        ][
            "changed_bytes"
        ]
        == EXPECTED_CHANGED_BYTES
    )

    assert (
        manifest[
            "diff"
        ][
            "range_count"
        ]
        == EXPECTED_DIFF_RANGES
    )

    assert (
        manifest[
            "diff"
        ][
            "unauthorized_bytes"
        ]
        == 0
    )

    assert (
        manifest[
            "flash_authorized"
        ]
        is False
    )

    print(
        "manifest hashes         : PASS"
    )

    print(
        "manifest diff counts    : PASS"
    )

    print(
        "flash_authorized=False  : PASS"
    )

else:
    print(
        "manifest not present - "
        "non-fatal"
    )


# ------------------------------------------------------------------
# FINAL
# ------------------------------------------------------------------

print()
print("=" * 112)
print("S12.7 RESULT")
print("=" * 112)

print(
    "SOURCE HASHES                 : PASS"
)

print(
    "PATCH MATRIX                  : PASS"
)

print(
    "KEEP MATRIX                   : PASS"
)

print(
    "VIVA PHYSICAL LAYOUT          : PASS"
)

print(
    "EXHAUSTIVE INDEPENDENT DIFF   : PASS"
)

print(
    "ALICE HEADER / TABLES         : PASS"
)

print(
    "STABLE ORIGINAL PREFIX        : PASS"
)

print(
    "INDEPENDENT EXACT DECODE      : PASS"
)

print(
    "INDEPENDENT MAPPING REBUILD   : PASS"
)

print(
    "ORIGINAL U PREFIX             : PASS"
)

print(
    "APPENDED PAYLOAD              : PASS"
)

print()
print(
    f"CANDIDATE SHA256 = "
    f"{sha(candidate)}"
)

print()
print(
    "VERDICT:"
)

print(
    "S12.6 OFFLINE CANDIDATE "
    "INDEPENDENTLY VERIFIED"
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
    "READ-ONLY recovery/read-back "
    "validation before any write."
)
