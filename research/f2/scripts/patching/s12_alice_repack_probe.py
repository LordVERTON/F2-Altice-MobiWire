#!/usr/bin/env python3
"""
S12.3 - Altice F2 ALICE_2 fixed-codebook repack probe

OFFLINE ONLY.

Tests:
  A. Original alice-py.bin -> repack -> exact original ALICE_2
  B. Explicit-length decode -> exact original alice-py.bin
  C. Append deterministic +0x1000 test payload
  D. Repack extended image
  E. Explicit-length decode -> exact extended image
  F. Validate mapping/table geometry and physical size ceiling

No firmware is flashed.
No phone/device access.
No output binary is written.
"""

from pathlib import Path
import hashlib
import struct
import sys


HEADER_SIZE = 0x28

HALF_BLOCK_WORDS = 32
HALF_BLOCK_BYTES = 64

GROUP_WORDS = 64
GROUP_BYTES = 128

MAPPING_HINT_BIAS = 13
MAPPING_ADDR_MASK = 0x00FFFFFF

CURRENT_DECOMP_SIZE = 0x157BB4
EXTENSION_SIZE = 0x1000
EXPECTED_EXTENDED_SIZE = 0x158BB4

EXPECTED_ORIGINAL_MAPPING_ENTRIES = 11001
EXPECTED_EXTENDED_MAPPING_ENTRIES = 11033

ALICE_MAX_PHYSICAL_SIZE = 0x13ED64

EXPECTED_U_SHA = (
    "7246242b67afae0d13104452bc3257827"
    "cb778119b54e7a26fb7fb55993697ea"
)

EXPECTED_A_SHA = (
    "8a06970667c6af37f7a6b1fb28dde062"
    "2e396fccd5c2a0b450bd795a0257988f"
)


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def locate_artifacts():
    here = Path(__file__).resolve()

    candidates = [
        # If canonical binaries are restored locally in this repo
        here.parents[2] / "work" / "extracted" / "altice_alice",

        # Normal user layout:
        # C:\Users\verto\F2-Altice-MobiWire
        # C:\Users\verto\mtkclient
        here.parents[5] / "mtkclient" / "research" / "f2"
        / "work" / "extracted" / "altice_alice",
    ]

    for base in candidates:
        a = base / "altice_ALICE_2.bin"
        u = base / "alice-py.bin"

        if a.is_file() and u.is_file():
            return a, u

    print("ERROR: canonical ALICE artifacts not found.")
    print()
    print("Expected one of:")
    for base in candidates:
        print(" ", base)
    sys.exit(2)


class FormatError(RuntimeError):
    pass


class BitReader:
    def __init__(self, data):
        self.data = data
        self.bitpos = 0

    def read(self, count):
        if self.bitpos + count > len(self.data) * 8:
            raise FormatError("compressed stream ended unexpectedly")

        value = 0

        for _ in range(count):
            b = self.data[self.bitpos >> 3]
            bit = (b >> (7 - (self.bitpos & 7))) & 1
            value = (value << 1) | bit
            self.bitpos += 1

        return value

    def align_byte(self):
        self.bitpos = (self.bitpos + 7) & ~7

    @property
    def bytepos(self):
        return self.bitpos >> 3


def align_up(value, alignment):
    return (value + alignment - 1) & ~(alignment - 1)


def parse_container(data):
    if data[:8] != b"ALICE_2\x00":
        raise FormatError("not ALICE_2")

    base_stream, map_addr, dict_addr = struct.unpack_from(
        "<III", data, 8
    )

    map_off = map_addr - base_stream + HEADER_SIZE
    dict_off = dict_addr - base_stream + HEADER_SIZE

    if not (
        HEADER_SIZE <= map_off <= dict_off <= len(data)
    ):
        raise FormatError(
            "invalid geometry "
            f"map_off=0x{map_off:X} "
            f"dict_off=0x{dict_off:X}"
        )

    ranges = struct.unpack_from("<7H", data, 0x14)

    src_bank = data[0x22]
    dst_bank = data[0x23]

    blocksize = struct.unpack_from("<H", data, 0x24)[0]

    if blocksize != 0x40:
        raise FormatError(
            f"unsupported mapping blocksize 0x{blocksize:X}"
        )

    dict_blob = data[dict_off:]

    if len(dict_blob) % 2:
        raise FormatError("dictionary has odd size")

    dictionary = struct.unpack(
        "<%dH" % (len(dict_blob) // 2),
        dict_blob,
    )

    expected_dict = sum(1 << r for r in ranges)

    if len(dictionary) != expected_dict:
        raise FormatError(
            f"dictionary entries {len(dictionary)} "
            f"!= expected {expected_dict}"
        )

    map_blob = data[map_off:dict_off]

    if len(map_blob) % 4:
        raise FormatError("mapping table is not u32 aligned")

    mapping = struct.unpack(
        "<%dI" % (len(map_blob) // 4),
        map_blob,
    )

    return {
        "header": data[:HEADER_SIZE],
        "base": base_stream,
        "map_addr": map_addr,
        "dict_addr": dict_addr,
        "map_off": map_off,
        "dict_off": dict_off,
        "ranges": ranges,
        "src_bank": src_bank,
        "dst_bank": dst_bank,
        "blocksize": blocksize,
        "dictionary": dictionary,
        "dict_blob": dict_blob,
        "mapping": mapping,
    }


def translate_bl_blx(data):
    """
    Exact transformation from the historical alice.py logic.
    """

    if len(data) & 1:
        raise FormatError("ALICE image length must be even")

    buff = bytearray(data)

    ptr = 0
    words = len(buff) // 2

    while ptr < words - 1:

        # ALICE deliberately refuses pairs spanning this boundary.
        if (ptr + 1) % 32 == 0:
            ptr += 1
            continue

        instr, instr2 = struct.unpack_from(
            "<HH", buff, ptr * 2
        )

        if (instr & 0xF800) != 0xF000:
            ptr += 1
            continue

        if (instr2 & 0xF800) == 0xF800:
            upbits = 0xF800
        elif (instr2 & 0xF800) == 0xE800:
            upbits = 0xE800
        else:
            ptr += 1
            continue

        if instr & 0x400:
            value = (
                2 * (
                    ptr
                    + ((instr & 0x7FF) << 11)
                    + (instr2 & 0x7FF)
                )
                - 0x7FFFFFFE
            )
        else:
            value = (
                2 * (
                    ptr
                    + ((instr & 0x7FF) << 11)
                    + (instr2 & 0x7FF)
                )
                + 2
            )

        new1 = ((value >> 12) & 0x7FF) | 0xF000
        new2 = ((value >> 1) & 0x7FF) | upbits

        struct.pack_into(
            "<HH", buff, ptr * 2, new1, new2
        )

        ptr += 2

    return bytes(buff)


def untranslate_bl_blx(data):
    """
    Exact inverse transformation from historical unalice.py logic.
    """

    if len(data) & 1:
        raise FormatError("translated ALICE length must be even")

    buff = bytearray(data)

    ptr = 0
    words = len(buff) // 2

    while ptr < words - 1:

        if (ptr + 1) % 32 == 0:
            ptr += 1
            continue

        instr, instr2 = struct.unpack_from(
            "<HH", buff, ptr * 2
        )

        if (instr & 0xF800) != 0xF000:
            ptr += 1
            continue

        if (instr2 & 0xF800) == 0xF800:
            upbits = 0xF800
        elif (instr2 & 0xF800) == 0xE800:
            upbits = 0xE800
        else:
            ptr += 1
            continue

        combined = (
            ((instr & 0x7FF) << 12)
            + ((instr2 & 0x7FF) << 1)
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

        new1 = ((value >> 11) & 0x7FF) | 0xF000
        new2 = (value & 0x7FF) | upbits

        struct.pack_into(
            "<HH", buff, ptr * 2, new1, new2
        )

        ptr += 2

    return bytes(buff)


def build_encode_table(profile):
    """
    value -> shortest code from original fixed dictionary.
    """

    result = {}

    low = 0

    for prefix, bits in enumerate(profile["ranges"]):

        count = 1 << bits

        for payload in range(count):

            word = profile["dictionary"][low + payload]

            # Preserve first/shortest occurrence.
            if word not in result:
                result[word] = (
                    f"{prefix:03b}"
                    + format(payload, f"0{bits}b")
                )

        low += count

    return result


def pack_bits(bitstring):
    bitstring += "0" * (-len(bitstring) % 8)

    return bytes(
        int(bitstring[i:i + 8], 2)
        for i in range(0, len(bitstring), 8)
    )


def encode_halfblock(words, table):
    chunks = []

    encoded = 0
    raw = 0

    for word in words:

        code = table.get(word)

        if code is None:
            code = "111" + format(word, "016b")
            raw += 1
        else:
            encoded += 1

        chunks.append(code)

    return (
        pack_bits("".join(chunks)),
        encoded,
        raw,
    )


def repack(image, reference):
    p = parse_container(reference)

    translated = translate_bl_blx(image)

    padded_size = align_up(
        len(translated),
        GROUP_BYTES,
    )

    translated += b"\x00" * (
        padded_size - len(translated)
    )

    table = build_encode_table(p)

    stream = bytearray()

    starts = []
    lengths = []

    encoded_count = 0
    raw_count = 0

    for off in range(
        0,
        len(translated),
        HALF_BLOCK_BYTES,
    ):

        words = struct.unpack_from(
            "<32H", translated, off
        )

        blob, encoded, raw = encode_halfblock(
            words,
            table,
        )

        starts.append(len(stream))
        lengths.append(len(blob))

        stream.extend(blob)

        encoded_count += encoded
        raw_count += raw

    if len(starts) & 1:
        raise FormatError(
            "odd number of half-blocks after padding"
        )

    mapping = []

    for i in range(0, len(starts), 2):

        hint = (
            lengths[i]
            - MAPPING_HINT_BIAS
        )

        if not 0 <= hint <= 0x3F:
            raise FormatError(
                f"mapping hint overflow "
                f"at half-block {i}: {hint}"
            )

        word = (
            (
                p["base"]
                + starts[i]
            )
            & MAPPING_ADDR_MASK
        ) | (hint << 26)

        mapping.append(word)

    # Terminal sentinel.
    mapping.append(
        (
            p["base"]
            + len(stream)
        )
        & MAPPING_ADDR_MASK
    )

    map_blob = struct.pack(
        "<%dI" % len(mapping),
        *mapping,
    )

    header = bytearray(
        p["header"]
    )

    new_map_addr = (
        p["base"]
        + len(stream)
    )

    new_dict_addr = (
        new_map_addr
        + len(map_blob)
    )

    struct.pack_into(
        "<II",
        header,
        0x0C,
        new_map_addr,
        new_dict_addr,
    )

    container = (
        bytes(header)
        + bytes(stream)
        + map_blob
        + p["dict_blob"]
    )

    stats = {
        "input_size": len(image),
        "padded_size": padded_size,
        "stream_size": len(stream),
        "mapping_entries": len(mapping),
        "mapping_size": len(map_blob),
        "dict_size": len(p["dict_blob"]),
        "container_size": len(container),
        "encoded_words": encoded_count,
        "raw_words": raw_count,
        "new_map_addr": new_map_addr,
        "new_dict_addr": new_dict_addr,
    }

    return container, stats


def decode_exact(container, exact_length):
    """
    Decoder with explicit expected decompressed size.

    This intentionally does NOT use the historical unalice EOF heuristic.
    """

    if exact_length & 1:
        raise FormatError(
            "expected length must be even"
        )

    p = parse_container(container)

    stream = container[
        HEADER_SIZE:p["map_off"]
    ]

    padded_size = align_up(
        exact_length,
        GROUP_BYTES,
    )

    halfblocks = (
        padded_size
        // HALF_BLOCK_BYTES
    )

    expected_maps = (
        padded_size
        // GROUP_BYTES
        + 1
    )

    if len(p["mapping"]) != expected_maps:
        raise FormatError(
            "mapping count mismatch: "
            f"{len(p['mapping'])} != "
            f"{expected_maps}"
        )

    # Range starting dictionary index.
    lows = []

    low = 0

    for bits in p["ranges"]:
        lows.append(low)
        low += 1 << bits

    br = BitReader(stream)

    out = bytearray()

    starts = []
    lengths = []

    for hb in range(halfblocks):

        start = br.bytepos

        starts.append(start)

        for _ in range(32):

            prefix = br.read(3)

            if prefix == 7:
                word = br.read(16)

            else:
                bits = p["ranges"][prefix]

                payload = br.read(bits)

                idx = (
                    lows[prefix]
                    + payload
                )

                word = p["dictionary"][idx]

            out.extend(
                struct.pack("<H", word)
            )

        br.align_byte()

        lengths.append(
            br.bytepos - start
        )

    if br.bytepos != len(stream):
        raise FormatError(
            "stream not consumed exactly: "
            f"0x{br.bytepos:X} != "
            f"0x{len(stream):X}"
        )

    # Reconstruct mapping from decoded stream.
    expected_mapping = []

    for i in range(0, len(starts), 2):

        hint = (
            lengths[i]
            - MAPPING_HINT_BIAS
        )

        word = (
            (
                p["base"]
                + starts[i]
            )
            & MAPPING_ADDR_MASK
        ) | (hint << 26)

        expected_mapping.append(word)

    expected_mapping.append(
        (
            p["base"]
            + len(stream)
        )
        & MAPPING_ADDR_MASK
    )

    if tuple(expected_mapping) != tuple(
        p["mapping"]
    ):
        for i, (got, exp) in enumerate(
            zip(
                p["mapping"],
                expected_mapping,
            )
        ):
            if got != exp:
                raise FormatError(
                    f"mapping mismatch #{i}: "
                    f"0x{got:08X} != "
                    f"0x{exp:08X}"
                )

        raise FormatError(
            "mapping table mismatch"
        )

    translated = bytes(
        out[:exact_length]
    )

    return untranslate_bl_blx(
        translated
    )


def absent_words(dictionary, count):
    have = set(dictionary)

    result = []

    for word in range(0x10000):

        if word not in have:
            result.append(word)

            if len(result) == count:
                return result

    raise RuntimeError(
        "not enough values absent from dictionary"
    )


def find_mod(start_word, count, mod, begin=0):
    for rel in range(begin, count - 1):

        if (
            start_word + rel
        ) % 32 == mod:
            return rel

    raise RuntimeError(
        f"unable to find word mod32={mod}"
    )


def build_extension(image, dictionary):
    """
    Deterministic DATA payload.

    It intentionally contains:
      - values absent from dictionary => raw 111 encoding
      - BL-looking pair normally translated
      - BL pair crossing ALICE 32-word boundary => must be skipped
      - BLX-looking pair
    """

    count = EXTENSION_SIZE // 2

    missing = absent_words(
        dictionary,
        257,
    )

    words = [
        missing[i % len(missing)]
        for i in range(count)
    ]

    start_word = len(image) // 2

    # Normal BL-like pair.
    p1 = find_mod(
        start_word,
        count,
        0,
        0,
    )

    words[p1] = 0xF001
    words[p1 + 1] = 0xF802

    # Pair beginning at word %32 == 31:
    # translator must skip it.
    p2 = find_mod(
        start_word,
        count,
        31,
        p1 + 64,
    )

    words[p2] = 0xF003
    words[p2 + 1] = 0xF804

    # BLX-like pair.
    p3 = find_mod(
        start_word,
        count,
        30,
        p2 + 64,
    )

    words[p3] = 0xF005
    words[p3 + 1] = 0xE806

    return struct.pack(
        "<%dH" % len(words),
        *words,
    )


def line():
    print("=" * 100)


def main():
    alice_path, image_path = (
        locate_artifacts()
    )

    reference = (
        alice_path.read_bytes()
    )

    image = (
        image_path.read_bytes()
    )

    line()
    print(
        "S12.3 - ALICE_2 FIXED-CODEBOOK "
        "REPACK + 0x1000 TEST"
    )
    line()

    print()
    print("INPUTS")
    print("-" * 100)

    print(
        f"ALICE_2 : {alice_path}"
    )
    print(
        f"  size   = 0x{len(reference):X}"
    )
    print(
        f"  sha256 = {sha256(reference)}"
    )

    print(
        f"U       : {image_path}"
    )
    print(
        f"  size   = 0x{len(image):X}"
    )
    print(
        f"  sha256 = {sha256(image)}"
    )

    assert len(image) == CURRENT_DECOMP_SIZE
    assert sha256(image) == EXPECTED_U_SHA
    assert sha256(reference) == EXPECTED_A_SHA

    profile = parse_container(
        reference
    )

    print()
    print("PROFILE")
    print("-" * 100)

    print(
        f"base_stream      = "
        f"0x{profile['base']:08X}"
    )
    print(
        f"mapping_addr     = "
        f"0x{profile['map_addr']:08X}"
    )
    print(
        f"dictionary_addr  = "
        f"0x{profile['dict_addr']:08X}"
    )
    print(
        f"mapping entries  = "
        f"{len(profile['mapping'])}"
    )
    print(
        f"dictionary words = "
        f"{len(profile['dictionary'])}"
    )
    print(
        f"ranges           = "
        f"{profile['ranges']}"
    )

    assert (
        len(profile["mapping"])
        == EXPECTED_ORIGINAL_MAPPING_ENTRIES
    )

    # ------------------------------------------------------------
    # TEST A
    # ------------------------------------------------------------

    print()
    line()
    print("TEST A - ORIGINAL BYTE-PERFECT REPACK")
    line()

    packed, stats = repack(
        image,
        reference,
    )

    print(
        f"container size   = "
        f"0x{len(packed):X}"
    )
    print(
        f"container sha256 = "
        f"{sha256(packed)}"
    )
    print(
        f"stream size      = "
        f"0x{stats['stream_size']:X}"
    )
    print(
        f"mapping entries  = "
        f"{stats['mapping_entries']}"
    )
    print(
        f"raw words        = "
        f"{stats['raw_words']}"
    )

    if packed != reference:
        raise AssertionError(
            "ORIGINAL REPACK IS NOT "
            "BYTE-IDENTICAL"
        )

    decoded = decode_exact(
        packed,
        len(image),
    )

    if decoded != image:
        raise AssertionError(
            "ORIGINAL EXPLICIT-LENGTH "
            "ROUNDTRIP FAILED"
        )

    print("BYTE-PERFECT CONTAINER : PASS")
    print("EXACT DECODE           : PASS")

    # ------------------------------------------------------------
    # TEST B
    # ------------------------------------------------------------

    print()
    line()
    print("TEST B - +0x1000 CONTROLLED EXTENSION")
    line()

    payload = build_extension(
        image,
        profile["dictionary"],
    )

    extended = (
        image + payload
    )

    assert (
        len(extended)
        == EXPECTED_EXTENDED_SIZE
    )

    print(
        f"payload size      = "
        f"0x{len(payload):X}"
    )
    print(
        f"payload sha256    = "
        f"{sha256(payload)}"
    )
    print(
        f"extended size     = "
        f"0x{len(extended):X}"
    )
    print(
        f"extended sha256   = "
        f"{sha256(extended)}"
    )

    packed2, stats2 = repack(
        extended,
        reference,
    )

    p2 = parse_container(
        packed2
    )

    print()
    print(
        f"stream size       = "
        f"0x{stats2['stream_size']:X}"
    )
    print(
        f"mapping entries   = "
        f"{stats2['mapping_entries']}"
    )
    print(
        f"mapping size      = "
        f"0x{stats2['mapping_size']:X}"
    )
    print(
        f"dictionary size   = "
        f"0x{stats2['dict_size']:X}"
    )
    print(
        f"container size    = "
        f"0x{stats2['container_size']:X}"
    )
    print(
        f"container sha256  = "
        f"{sha256(packed2)}"
    )
    print(
        f"new mapping addr  = "
        f"0x{stats2['new_map_addr']:08X}"
    )
    print(
        f"new dict addr     = "
        f"0x{stats2['new_dict_addr']:08X}"
    )
    print(
        f"encoded words     = "
        f"{stats2['encoded_words']}"
    )
    print(
        f"raw words         = "
        f"{stats2['raw_words']}"
    )

    assert (
        stats2["mapping_entries"]
        == EXPECTED_EXTENDED_MAPPING_ENTRIES
    )

    assert (
        stats2["container_size"]
        <= ALICE_MAX_PHYSICAL_SIZE
    )

    assert (
        stats2["raw_words"] > 0
    )

    assert (
        p2["dictionary"]
        == profile["dictionary"]
    )

    assert (
        p2["base"]
        == profile["base"]
    )

    decoded2 = decode_exact(
        packed2,
        len(extended),
    )

    if decoded2 != extended:
        raise AssertionError(
            "EXTENDED ROUNDTRIP FAILED"
        )

    if (
        decoded2[:len(image)]
        != image
    ):
        raise AssertionError(
            "ORIGINAL PREFIX CHANGED"
        )

    if (
        decoded2[len(image):]
        != payload
    ):
        raise AssertionError(
            "EXTENSION PAYLOAD CHANGED"
        )

    headroom = (
        ALICE_MAX_PHYSICAL_SIZE
        - len(packed2)
    )

    print()
    print("EXTENDED EXACT DECODE : PASS")
    print("ORIGINAL PREFIX       : PASS")
    print("APPENDED PAYLOAD      : PASS")
    print("DICTIONARY PRESERVED  : PASS")
    print(
        f"PHYSICAL HEADROOM     : "
        f"0x{headroom:X}"
    )

    print()
    line()
    print("S12.3 RESULT")
    line()

    print(
        "ORIGINAL REPACK       : PASS"
    )
    print(
        "ORIGINAL ROUNDTRIP    : PASS"
    )
    print(
        "+0x1000 REPACK        : PASS"
    )
    print(
        "+0x1000 ROUNDTRIP     : PASS"
    )
    print(
        "PHYSICAL SIZE CHECK   : PASS"
    )

    print()
    print(
        "NEXT GATE: validate ZIMAGE / "
        "BOOT_ZIMAGE preset semantics "
        "before constructing any "
        "flashable firmware."
    )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
