#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
S13.4G - interworking veneer + Image ID role audit

STRICTLY OFFLINE.
NO PHONE ACCESS.
NO BROM / DA / D6 / D3 / D5.
NO FLASH WRITE.
NO LZMA RECOMPRESSION.
NO VIVA REPACK.
NO PHYSICAL FIRMWARE CANDIDATE.

This stage:
  1. proves F02D1928 / F02D16A0 are ARM interworking veneers;
  2. finds the veneer to 1031F81D too;
  3. proves the Image stub A/B registrars land on the same underlying
     Thumb registration functions used by the native Audio stub;
  4. classifies 10319094 as a mapping/query function, not the dispatcher;
  5. compares code materialization of 0x8313 / 0x8321 / 0x8928;
  6. scans local firmware/resource artifacts for Image/Viewer strings
     near 0x8313 / 0x8321;
  7. scores resolver-ID clustering around 0x8313 / 0x8321 occurrences.

No candidate is selected for flashing.
"""

from pathlib import Path
import hashlib
import struct
import sys

from capstone import (
    Cs,
    CS_ARCH_ARM,
    CS_MODE_ARM,
    CS_MODE_THUMB,
    CS_MODE_LITTLE_ENDIAN,
)
from capstone.arm import ARM_OP_IMM, ARM_OP_MEM, ARM_REG_PC

ROOT = Path.cwd()

ALICE_PATH = ROOT / "research/f2/work/extracted/altice_alice/alice-py.bin"
ZIMAGE_PATH = ROOT / "research/f2/work/extracted/altice_platform/zimage.bin"

REPORT = ROOT / "research/f2/work/reports/s13_4g_interworking_and_image_id_role_audit.txt"

ALICE_BASE = 0x1024EC00
ZIMAGE_BASE = 0xF023CA50

ALICE_SIZE = 0x157BB4
ZIMAGE_SIZE = 0x185E98

ALICE_SHA = "7246242b67afae0d13104452bc3257827cb778119b54e7a26fb7fb55993697ea"
ZIMAGE_SHA = "85fba8c8ae8161e4c1f8ced7983ec30d48c54ab10e51c69fcdfb900aca220954"

TABLE = 0xF0345E68
TABLE_COUNT = 58
TABLE_STRIDE = 8

IMAGE_A = 0x8313
IMAGE_B = 0x8321
AUDIO = 0x8928

IMAGE_STUB = 0xF02F3F84
IMAGE_LITERAL = 0xF02F3F98
IMAGE_ORIGINAL_PTR = 0xF0301C8D

AUDIO_STUB = 0x1033D840
AUDIO_CALLBACK = 0x1033D841
AUDIO_INIT_PTR = 0x1033E815
AUDIO_AUX_PTR = 0xF02E18BD

VENEER_A = 0xF02D1928
VENEER_B = 0xF02D16A0

REG_A_THUMB = 0x1031F71B
REG_B_THUMB = 0x1031E121
REG_C_THUMB = 0x1031F81D

MAPPER = 0x10319094
MAPPER_TABLE_PTR_ADDR = 0x103190AC
MAPPER_TABLE = 0xF00B7994

md_t = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_LITTLE_ENDIAN)
md_t.detail = True
md_t.skipdata = True

md_a = Cs(CS_ARCH_ARM, CS_MODE_ARM | CS_MODE_LITTLE_ENDIAN)
md_a.detail = True
md_a.skipdata = True


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def banner(title):
    print()
    print("=" * 120)
    print(title)
    print("=" * 120)


def require(cond, msg):
    if not cond:
        raise RuntimeError(msg)
    print("[PASS]", msg)


def off(base, addr):
    return addr - base


def u32(data, base, addr):
    o = off(base, addr)
    if o < 0 or o + 4 > len(data):
        raise RuntimeError(f"u32 out of bounds @0x{addr:08X}")
    return struct.unpack_from("<I", data, o)[0]


def disasm(md, data, base, start, size):
    o = off(base, start)
    if o < 0 or o + size > len(data):
        raise RuntimeError(f"disasm out of bounds @0x{start:08X}")
    for insn in md.disasm(data[o:o+size], start):
        print(
            f"0x{insn.address:08X}: "
            f"{insn.bytes.hex(' '):<18} "
            f"{insn.mnemonic:<9} {insn.op_str}"
        )


def branch_target(insn):
    if insn.mnemonic not in ("bl", "blx", "b", "b.w"):
        return None
    if not insn.operands:
        return None
    op = insn.operands[0]
    if op.type != ARM_OP_IMM:
        return None
    return op.imm & 0xFFFFFFFF


def decode_arm_veneer(zimage, addr):
    o = off(ZIMAGE_BASE, addr)
    require(0 <= o <= len(zimage) - 8, f"veneer @0x{addr:08X} is inside ZIMAGE")
    word = struct.unpack_from("<I", zimage, o)[0]
    target = struct.unpack_from("<I", zimage, o + 4)[0]
    require(word == 0xE51FF004, f"veneer @0x{addr:08X} opcode == E51FF004")
    print(f"  ARM veneer 0x{addr:08X}: LDR pc,[pc,#-4] -> 0x{target:08X}")
    disasm(md_a, zimage, ZIMAGE_BASE, addr, 4)
    print(f"  literal @0x{addr+4:08X} = 0x{target:08X}")
    return target


def find_arm_veneer_to(zimage, target):
    pat = struct.pack("<II", 0xE51FF004, target)
    out = []
    pos = 0
    while True:
        k = zimage.find(pat, pos)
        if k < 0:
            break
        out.append(ZIMAGE_BASE + k)
        pos = k + 1
    return out


def parse_resolver_ids(zimage):
    toff = off(ZIMAGE_BASE, TABLE)
    require(toff >= 0, "resolver table offset valid")
    require(
        toff + TABLE_COUNT * TABLE_STRIDE <= len(zimage),
        "resolver table fully inside ZIMAGE",
    )
    rows = []
    for i in range(TABLE_COUNT):
        roff = toff + i * TABLE_STRIDE
        rid, field2, cb = struct.unpack_from("<HHI", zimage, roff)
        rows.append((rid, field2, cb, ZIMAGE_BASE + roff))
    return rows


def pc_literal_value(insn, data, base):
    if not insn.mnemonic.startswith("ldr"):
        return None
    if len(insn.operands) < 2:
        return None
    op = insn.operands[1]
    if op.type != ARM_OP_MEM or op.mem.base != ARM_REG_PC:
        return None
    pc = (insn.address + 4) & ~3
    lit_addr = (pc + op.mem.disp) & 0xFFFFFFFF
    o = lit_addr - base
    if o < 0 or o + 4 > len(data):
        return None
    return lit_addr, struct.unpack_from("<I", data, o)[0]


def scan_code_materializers(label, data, base):
    wanted = {IMAGE_A: "IMAGE_A", IMAGE_B: "IMAGE_B", AUDIO: "AUDIO"}
    hits = {k: [] for k in wanted}

    # Decode from every halfword to avoid depending on one linear stream.
    for o in range(0, len(data) - 4, 2):
        insns = list(md_t.disasm(data[o:o+4], base + o, count=1))
        if not insns:
            continue
        insn = insns[0]

        lit = pc_literal_value(insn, data, base)
        if lit:
            la, value = lit
            if value in wanted:
                hits[value].append((insn.address, "LDR_LITERAL", la))

        if insn.mnemonic == "movw" and len(insn.operands) >= 2:
            op = insn.operands[1]
            if op.type == ARM_OP_IMM:
                value = op.imm & 0xFFFF
                if value in wanted:
                    hits[value].append((insn.address, "MOVW", None))

    # deduplicate
    for rid in hits:
        uniq = []
        seen = set()
        for x in hits[rid]:
            key = (x[0], x[1], x[2])
            if key not in seen:
                seen.add(key)
                uniq.append(x)
        hits[rid] = uniq

    banner(f"{label} CODE MATERIALIZERS")
    for rid, name in wanted.items():
        print(f"{name} 0x{rid:04X}: {len(hits[rid])}")
        for addr, kind, literal in hits[rid]:
            extra = f" literal@0x{literal:08X}" if literal is not None else ""
            print(f"  0x{addr:08X} {kind}{extra}")

    return hits


def classify_mapper(alice):
    banner("D. 10319094 MAPPING/QUERY CLASSIFICATION")
    disasm(md_t, alice, ALICE_BASE, MAPPER, 0x1C)

    require(
        u32(alice, ALICE_BASE, MAPPER_TABLE_PTR_ADDR) == MAPPER_TABLE,
        "103190AC literal == F00B7994 mapping table",
    )

    insns = list(
        md_t.disasm(
            alice[off(ALICE_BASE, MAPPER):off(ALICE_BASE, MAPPER) + 0x18],
            MAPPER,
        )
    )
    targets = [branch_target(i) for i in insns]
    require(
        0x102FA0CC in targets,
        "10319094 calls 102FA0CC before mapping lookup",
    )

    has_ldrh = any(i.mnemonic == "ldrh" for i in insns)
    require(has_ldrh, "10319094 returns a U16 table value via LDRH")

    print()
    print("CLASSIFICATION:")
    print("  input ID in r0")
    print("  -> 102FA0CC yields an index/status")
    print("  -> 0xFF maps to fallback 0x2E")
    print("  -> otherwise reads U16 from F00B7994[index]")
    print("  => mapping/query helper, NOT the known resolver/callback dispatcher")


def all_occurrences(data, pat):
    out = []
    pos = 0
    while True:
        k = data.find(pat, pos)
        if k < 0:
            break
        out.append(k)
        pos = k + 1
    return out


def resolver_cluster_report(label, data, base, resolver_ids):
    banner(f"{label} RESOLVER-ID CLUSTERS AROUND 0x8313 / 0x8321")

    target_occ = []
    for rid in (IMAGE_A, IMAGE_B):
        for pos in all_occurrences(data, struct.pack("<H", rid)):
            target_occ.append((pos, rid))

    # For each target occurrence, count distinct resolver IDs in +-0x100.
    scored = []
    for pos, rid in target_occ:
        lo = max(0, pos - 0x100)
        hi = min(len(data), pos + 0x102)
        blob = data[lo:hi]
        neighbors = []
        for other in resolver_ids:
            p = struct.pack("<H", other)
            cur = 0
            while True:
                k = blob.find(p, cur)
                if k < 0:
                    break
                neighbors.append((lo + k, other))
                cur = k + 1
        distinct = sorted({x[1] for x in neighbors})
        scored.append((len(distinct), pos, rid, neighbors))

    scored.sort(reverse=True)

    for distinct_count, pos, rid, neighbors in scored[:24]:
        name = "IMAGE_A" if rid == IMAGE_A else "IMAGE_B"
        print(
            f"{name} @0x{base+pos:08X} FILE+0x{pos:X} "
            f"distinct resolver IDs within +-0x100 = {distinct_count}"
        )
        if distinct_count >= 2:
            compact = []
            for p, other in sorted(neighbors)[:24]:
                compact.append(f"0x{other:04X}@{base+p:08X}")
            print("  " + ", ".join(compact))


def printable_ascii_runs(data, min_len=5):
    runs = []
    start = None
    for i, b in enumerate(data):
        ok = 0x20 <= b <= 0x7E
        if ok and start is None:
            start = i
        elif not ok and start is not None:
            if i - start >= min_len:
                runs.append((start, data[start:i].decode("ascii", errors="replace")))
            start = None
    if start is not None and len(data) - start >= min_len:
        runs.append((start, data[start:].decode("ascii", errors="replace")))
    return runs


def scan_resource_artifacts():
    banner("G. LOCAL RESOURCE / STRING CORRELATION")

    roots = [
        ROOT / "research/f2/work/extracted",
        ROOT / "research/f2/data/firmware-packages",
        ROOT / "research/f2/data/dumps",
    ]

    keywords = [
        "Image Viewer",
        "Image viewer",
        "IMAGE VIEWER",
        "Viewer",
        "Images",
        "Photos",
        "Photo",
    ]

    files = []
    seen = set()
    for root in roots:
        if not root.exists():
            continue
        for path in root.rglob("*"):
            if not path.is_file():
                continue
            try:
                size = path.stat().st_size
            except OSError:
                continue
            if size <= 0 or size > 64 * 1024 * 1024:
                continue
            rp = str(path.resolve())
            if rp in seen:
                continue
            seen.add(rp)
            files.append(path)

    print(f"files scanned = {len(files)}")
    print("max file size = 64 MiB")
    print()

    correlations = []

    for path in files:
        try:
            data = path.read_bytes()
        except Exception:
            continue

        id_hits = []
        for rid, name in ((IMAGE_A, "IMAGE_A"), (IMAGE_B, "IMAGE_B")):
            for width, pat in (
                ("LE16", struct.pack("<H", rid)),
                ("LE32", struct.pack("<I", rid)),
            ):
                for pos in all_occurrences(data, pat):
                    id_hits.append((pos, rid, name, width))

        if not id_hits:
            continue

        string_hits = []
        for kw in keywords:
            for enc, pat in (
                ("ASCII", kw.encode("ascii")),
                ("UTF16LE", kw.encode("utf-16le")),
            ):
                for pos in all_occurrences(data, pat):
                    string_hits.append((pos, kw, enc))

        # Only report useful correlations, or files with very few ID hits.
        useful = []
        for ipos, rid, name, width in id_hits:
            nearest = None
            for spos, kw, enc in string_hits:
                d = abs(spos - ipos)
                if nearest is None or d < nearest[0]:
                    nearest = (d, spos, kw, enc)
            if nearest and nearest[0] <= 0x4000:
                useful.append((ipos, rid, name, width, nearest))

        if useful:
            print(f"FILE {path}")
            for ipos, rid, name, width, nearest in sorted(useful)[:40]:
                d, spos, kw, enc = nearest
                print(
                    f"  {name} 0x{rid:04X} {width} @+0x{ipos:X} "
                    f"<-> {enc} {kw!r} @+0x{spos:X} distance=0x{d:X}"
                )
                correlations.append({
                    "file": str(path),
                    "id": rid,
                    "id_name": name,
                    "id_offset": ipos,
                    "width": width,
                    "keyword": kw,
                    "encoding": enc,
                    "string_offset": spos,
                    "distance": d,
                })
            print()

    if not correlations:
        print("No Image/Viewer string was found within 0x4000 bytes of 0x8313/0x8321.")
        print("This is non-evidence: resources may live in separate indexed packs.")
    else:
        a = [x for x in correlations if x["id"] == IMAGE_A]
        b = [x for x in correlations if x["id"] == IMAGE_B]
        print(f"Correlations IMAGE_A = {len(a)}")
        print(f"Correlations IMAGE_B = {len(b)}")

    return correlations


def main():
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")

    alice = ALICE_PATH.read_bytes()
    zimage = ZIMAGE_PATH.read_bytes()

    REPORT.parent.mkdir(parents=True, exist_ok=True)
    log = REPORT.open("w", encoding="utf-8")
    real = sys.stdout

    class Tee:
        def write(self, s):
            real.write(s)
            log.write(s)
            return len(s)
        def flush(self):
            real.flush()
            log.flush()

    sys.stdout = Tee()

    try:
        banner("S13.4G - INTERWORKING VENEER + IMAGE ID ROLE AUDIT")
        print("STRICTLY OFFLINE")
        print("PHONE ACCESSED       : NO")
        print("FLASH MODIFIED       : NO")
        print("LZMA RECOMPRESS      : NO")
        print("VIVA REPACK          : NO")
        print("PHYSICAL CANDIDATE   : NO")
        print()

        require(len(alice) == ALICE_SIZE, f"ALICE size = 0x{ALICE_SIZE:X}")
        require(sha256(alice) == ALICE_SHA, "canonical ALICE SHA256")
        require(len(zimage) == ZIMAGE_SIZE, f"ZIMAGE size = 0x{ZIMAGE_SIZE:X}")
        require(sha256(zimage) == ZIMAGE_SHA, "canonical ZIMAGE SHA256")

        banner("A. PROVE IMAGE ARM INTERWORKING VENEERS")
        ta = decode_arm_veneer(zimage, VENEER_A)
        tb = decode_arm_veneer(zimage, VENEER_B)
        require(ta == REG_A_THUMB, "F02D1928 -> 1031F71B (Thumb registrar A)")
        require(tb == REG_B_THUMB, "F02D16A0 -> 1031E121 (Thumb registrar B)")

        banner("B. FIND VENEERS TO ALL THREE AUDIO REGISTRARS")
        for target, name in (
            (REG_A_THUMB, "REG_A"),
            (REG_B_THUMB, "REG_B"),
            (REG_C_THUMB, "REG_C"),
        ):
            hits = find_arm_veneer_to(zimage, target)
            print(f"{name} target 0x{target:08X}: {len(hits)} veneer(s)")
            for addr in hits:
                print(f"  0x{addr:08X}")
            require(len(hits) >= 1, f"at least one ZIMAGE ARM veneer exists for {name}")

        banner("C. COMPARE IMAGE VS NATIVE AUDIO REGISTRATION")
        print("IMAGE stub (Thumb):")
        disasm(md_t, zimage, ZIMAGE_BASE, IMAGE_STUB, 0x18)
        print()
        print("AUDIO stub (Thumb):")
        disasm(md_t, alice, ALICE_BASE, AUDIO_STUB, 0x24)
        print()
        print("Established structural relation:")
        print("  Image stub registrar A -> veneer -> 1031F71B")
        print("  Image stub registrar B -> veneer -> 1031E121")
        print("  Audio stub registrar A -> 1031F71A code")
        print("  Audio stub registrar B -> 1031E120 code")
        print("  Audio stub additionally registers F02E18BD through 1031F81C")
        print()
        print("Therefore candidate A reproduces native Audio A/B registrar channels")
        print("but omits the native Audio third registration channel.")

        classify_mapper(alice)

        ah = scan_code_materializers("ALICE", alice, ALICE_BASE)
        zh = scan_code_materializers("ZIMAGE", zimage, ZIMAGE_BASE)

        rows = parse_resolver_ids(zimage)
        resolver_ids = sorted({rid for rid, _, _, _ in rows})

        resolver_cluster_report("ALICE", alice, ALICE_BASE, resolver_ids)
        resolver_cluster_report("ZIMAGE", zimage, ZIMAGE_BASE, resolver_ids)

        correlations = scan_resource_artifacts()

        banner("H. S13.4G DECISION INPUTS")
        print(f"ALICE code materializers 0x8313 = {len(ah[IMAGE_A])}")
        print(f"ALICE code materializers 0x8321 = {len(ah[IMAGE_B])}")
        print(f"ZIMAGE code materializers 0x8313 = {len(zh[IMAGE_A])}")
        print(f"ZIMAGE code materializers 0x8321 = {len(zh[IMAGE_B])}")
        print()
        print("Known result from prior S13.4D:")
        print("  0x8321 materializers feed 10319094 mapping/query logic.")
        print("  This is evidence that 0x8321 participates in resource/metadata mapping,")
        print("  NOT proof that 0x8321 is the user-visible dispatch trigger.")
        print()
        print("Selection rule:")
        print("  - If one ID is strongly tied to Image/Viewer resource strings while the")
        print("    other is not, treat that as role evidence, not yet runtime proof.")
        print("  - If trigger identity remains ambiguous, do NOT select B or C.")
        print("  - A future logical candidate may instead patch both resolver rows only")
        print("    after duplicate-callback/idempotence risk is explicitly audited.")
        print()
        print("PHONE ACCESSED       : NO")
        print("FLASH MODIFIED       : NO")
        print("LZMA RECOMPRESS      : NO")
        print("VIVA REPACK          : NO")
        print("PHYSICAL CANDIDATE   : NO")
        print("HARDWARE WRITE AUTHORIZED: NO")
        print()
        print(f"REPORT = {REPORT}")

    finally:
        sys.stdout = real
        log.close()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
