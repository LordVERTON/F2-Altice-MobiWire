#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
S13.4F - registration contract + resolver-route selector audit

STRICTLY OFFLINE.

Goals:
  1. validate the canonical ALICE/ZIMAGE inputs and resolver rows;
  2. compare the native Image and Audio registration stubs/APIs;
  3. enumerate direct xrefs to those registration APIs;
  4. inspect dispatcher/resolver direct xrefs for nearby Image/Audio IDs;
  5. compare three LOGICAL-ONLY POC strategies:
       A) Image stub literal -> Audio init pointer
       B) resolver row 0x8313 callback -> native Audio callback
       C) resolver row 0x8321 callback -> native Audio callback
  6. prove all candidates are tiny logical ZIMAGE diffs.

NO PHONE ACCESS.
NO BROM / DA / D6 / D3 / D5.
NO FLASH WRITE.
NO LZMA RECOMPRESSION.
NO VIVA REPACK.
NO PHYSICAL FIRMWARE CANDIDATE.
"""

from pathlib import Path
import hashlib
import json
import struct
import sys

from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_LITTLE_ENDIAN
from capstone.arm import ARM_OP_IMM

ROOT = Path.cwd()

ALICE_PATH = ROOT / "research/f2/work/extracted/altice_alice/alice-py.bin"
ZIMAGE_PATH = ROOT / "research/f2/work/extracted/altice_platform/zimage.bin"

OUTDIR = ROOT / "research/f2/work/candidates/s13_4f"
REPORT = ROOT / "research/f2/work/reports/s13_4f_registration_contract_and_route_selector_audit.txt"

ALICE_BASE = 0x1024EC00
ZIMAGE_BASE = 0xF023CA50

ALICE_SIZE = 0x157BB4
ZIMAGE_SIZE = 0x185E98

ALICE_SHA = "7246242b67afae0d13104452bc3257827cb778119b54e7a26fb7fb55993697ea"
ZIMAGE_SHA = "85fba8c8ae8161e4c1f8ced7983ec30d48c54ab10e51c69fcdfb900aca220954"

TABLE = 0xF0345E68
TABLE_COUNT = 58
TABLE_STRIDE = 8

IMAGE_ID_A = 0x8313
IMAGE_ID_B = 0x8321
AUDIO_ID = 0x8928

IMAGE_CALLBACK = 0xF02F3F85
AUDIO_CALLBACK = 0x1033D841

IMAGE_STUB = 0xF02F3F84
IMAGE_LITERAL = 0xF02F3F98
IMAGE_ORIGINAL_PTR = 0xF0301C8D

AUDIO_STUB = 0x1033D840
AUDIO_INIT_PTR = 0x1033E815

IMAGE_REG_A = 0xF02D1928
IMAGE_REG_B = 0xF02D16A0

AUDIO_REG_A = 0x1031F71A
AUDIO_REG_B = 0x1031E120
AUDIO_REG_C = 0x1031F81C
AUDIO_THIRD_PTR = 0xF02E18BD

DISPATCH_TARGETS = {
    0x10336788: "dispatcher",
    0x1034C7E4: "dynamic/static resolver wrapper",
    0xF0316D74: "static resolver",
    0x102D9DC8: "global dispatcher bridge",
}

REG_TARGETS = {
    IMAGE_REG_A & ~1: "IMAGE_REG_A F02D1928",
    IMAGE_REG_B & ~1: "IMAGE_REG_B F02D16A0",
    AUDIO_REG_A & ~1: "AUDIO_REG_A 1031F71A",
    AUDIO_REG_B & ~1: "AUDIO_REG_B 1031E120",
    AUDIO_REG_C & ~1: "AUDIO_REG_C 1031F81C",
}

md = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_LITTLE_ENDIAN)
md.detail = True
md.skipdata = True


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


def disasm_window(data, base, start, size):
    o = off(base, start)
    if o < 0 or o + size > len(data):
        raise RuntimeError(f"window outside image @0x{start:08X}")
    for insn in md.disasm(data[o:o+size], start):
        print(
            f"0x{insn.address:08X}: "
            f"{insn.bytes.hex(' '):<16} "
            f"{insn.mnemonic:<9} {insn.op_str}"
        )


def branch_target(insn):
    if insn.mnemonic not in (
        "bl", "blx", "b", "b.w", "beq", "bne", "bcc", "bcs",
        "bhi", "bls", "bgt", "blt", "bge", "ble"
    ):
        return None
    if not insn.operands:
        return None
    op = insn.operands[0]
    if op.type != ARM_OP_IMM:
        return None
    return op.imm & 0xFFFFFFFF


def all_instructions(data, base):
    return list(md.disasm(data, base))


def direct_xrefs(instructions, targets):
    out = {t: [] for t in targets}
    for insn in instructions:
        if insn.mnemonic not in ("bl", "blx"):
            continue
        dst = branch_target(insn)
        if dst is None:
            continue
        ndst = dst & ~1
        if ndst in out:
            out[ndst].append(insn.address)
    return out


def nearby_id_bytes(data, base, addr, radius=0x80):
    start = max(0, off(base, addr) - radius)
    end = min(len(data), off(base, addr) + radius)
    blob = data[start:end]
    found = []
    for rid, label in (
        (IMAGE_ID_A, "IMAGE_A"),
        (IMAGE_ID_B, "IMAGE_B"),
        (AUDIO_ID, "AUDIO"),
    ):
        for width, pat in (
            ("u16", struct.pack("<H", rid)),
            ("u32", struct.pack("<I", rid)),
        ):
            pos = 0
            while True:
                k = blob.find(pat, pos)
                if k < 0:
                    break
                found.append((base + start + k, width, rid, label))
                pos = k + 1
    return sorted(set(found))


def show_xrefs(label, data, base, instructions, targets):
    banner(label)
    xr = direct_xrefs(instructions, targets)
    for target, name in targets.items():
        nt = target & ~1
        sites = xr.get(nt, [])
        print(f"{name} 0x{target:08X}: {len(sites)} direct call(s)")
        for site in sites[:80]:
            ids = nearby_id_bytes(data, base, site)
            suffix = ""
            if ids:
                suffix = " | nearby IDs: " + ", ".join(
                    f"{name2}=0x{rid:04X}@0x{a:08X}/{w}"
                    for a, w, rid, name2 in ids[:12]
                )
            print(f"  0x{site:08X}{suffix}")
        if len(sites) > 80:
            print(f"  ... {len(sites)-80} more")
        print()
    return xr


def parse_table(zimage):
    toff = off(ZIMAGE_BASE, TABLE)
    require(toff >= 0, "resolver table offset valid")
    require(toff + TABLE_COUNT * TABLE_STRIDE <= len(zimage), "resolver table fully inside ZIMAGE")
    rows = []
    for i in range(TABLE_COUNT):
        roff = toff + i * TABLE_STRIDE
        rid, field2, cb = struct.unpack_from("<HHI", zimage, roff)
        rows.append({
            "index": i,
            "runtime": ZIMAGE_BASE + roff,
            "offset": roff,
            "id": rid,
            "field2": field2,
            "callback": cb,
            "raw": zimage[roff:roff+8].hex(" "),
        })
    return rows


def row_for(rows, rid):
    m = [r for r in rows if r["id"] == rid]
    require(len(m) == 1, f"exactly one resolver row for 0x{rid:04X}")
    return m[0]


def diff_positions(a, b):
    require(len(a) == len(b), "candidate size unchanged")
    return [i for i, (x, y) in enumerate(zip(a, b)) if x != y]


def make_candidate(zimage, name, runtime_addr, old_value, new_value):
    o = off(ZIMAGE_BASE, runtime_addr)
    require(0 <= o <= len(zimage)-4, f"{name}: patch offset in ZIMAGE")
    require(u32(zimage, ZIMAGE_BASE, runtime_addr) == old_value, f"{name}: exact old u32")

    out = bytearray(zimage)
    out[o:o+4] = struct.pack("<I", new_value)
    out = bytes(out)

    pos = diff_positions(zimage, out)
    require(len(pos) == 4, f"{name}: exactly 4 changed logical bytes")
    require(pos == list(range(o, o+4)), f"{name}: one contiguous 4-byte diff")

    path = OUTDIR / f"{name}.bin"
    path.write_bytes(out)

    return {
        "name": name,
        "path": str(path),
        "runtime_addr": f"0x{runtime_addr:08X}",
        "zimage_offset": f"0x{o:X}",
        "old_value": f"0x{old_value:08X}",
        "new_value": f"0x{new_value:08X}",
        "old_bytes": struct.pack("<I", old_value).hex(" "),
        "new_bytes": struct.pack("<I", new_value).hex(" "),
        "changed_bytes": len(pos),
        "sha256": sha256(out),
    }


def show_table_neighborhood(rows):
    banner("A. STATIC RESOLVER TABLE NEIGHBORHOOD")
    for r in rows:
        marker = ""
        if r["id"] == IMAGE_ID_A:
            marker = " <IMAGE_A>"
        elif r["id"] == IMAGE_ID_B:
            marker = " <IMAGE_B>"
        elif r["id"] == AUDIO_ID:
            marker = " <AUDIO>"
        if 6 <= r["index"] <= 25:
            print(
                f"row={r['index']:02d} addr=0x{r['runtime']:08X} "
                f"id=0x{r['id']:04X} field2=0x{r['field2']:04X} "
                f"callback=0x{r['callback']:08X}{marker}"
            )


def main():
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")

    alice = ALICE_PATH.read_bytes()
    zimage = ZIMAGE_PATH.read_bytes()

    OUTDIR.mkdir(parents=True, exist_ok=True)
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
        banner("S13.4F - REGISTRATION CONTRACT + ROUTE SELECTOR AUDIT")
        print("STRICTLY OFFLINE")
        print("PHONE ACCESSED       : NO")
        print("FLASH MODIFIED       : NO")
        print("LZMA RECOMPRESS      : NO")
        print("VIVA REPACK          : NO")
        print("PHYSICAL CANDIDATE   : NO")
        print()

        require(len(alice) == ALICE_SIZE, f"ALICE size 0x{ALICE_SIZE:X}")
        require(sha256(alice) == ALICE_SHA, "canonical ALICE SHA256")
        require(len(zimage) == ZIMAGE_SIZE, f"ZIMAGE size 0x{ZIMAGE_SIZE:X}")
        require(sha256(zimage) == ZIMAGE_SHA, "canonical ZIMAGE SHA256")

        rows = parse_table(zimage)
        ia = row_for(rows, IMAGE_ID_A)
        ib = row_for(rows, IMAGE_ID_B)
        au = row_for(rows, AUDIO_ID)

        require(ia["field2"] == 0 and ia["callback"] == IMAGE_CALLBACK, "IMAGE_A exact resolver row")
        require(ib["field2"] == 0 and ib["callback"] == IMAGE_CALLBACK, "IMAGE_B exact resolver row")
        require(au["field2"] == 0 and au["callback"] == AUDIO_CALLBACK, "AUDIO exact resolver row")

        show_table_neighborhood(rows)

        banner("B. NATIVE REGISTRATION STUBS")
        require(u32(zimage, ZIMAGE_BASE, IMAGE_LITERAL) == IMAGE_ORIGINAL_PTR, "Image stub literal exact")
        print("IMAGE native stub:")
        disasm_window(zimage, ZIMAGE_BASE, IMAGE_STUB, 0x18)
        print()
        print("AUDIO native stub:")
        disasm_window(alice, ALICE_BASE, AUDIO_STUB, 0x24)

        banner("C. REGISTRATION API BODIES")
        print("IMAGE_REG_A F02D1928")
        disasm_window(zimage, ZIMAGE_BASE, IMAGE_REG_A & ~1, 0x60)
        print()
        print("IMAGE_REG_B F02D16A0")
        disasm_window(zimage, ZIMAGE_BASE, IMAGE_REG_B & ~1, 0x60)
        print()
        print("AUDIO_REG_A 1031F71A")
        disasm_window(alice, ALICE_BASE, AUDIO_REG_A & ~1, 0x60)
        print()
        print("AUDIO_REG_B 1031E120")
        disasm_window(alice, ALICE_BASE, AUDIO_REG_B & ~1, 0x60)
        print()
        print("AUDIO_REG_C 1031F81C")
        disasm_window(alice, ALICE_BASE, AUDIO_REG_C & ~1, 0x60)

        banner("D. DIRECT XREF CENSUS")
        print("Disassembling canonical images once...")
        alice_ins = all_instructions(alice, ALICE_BASE)
        zimage_ins = all_instructions(zimage, ZIMAGE_BASE)
        print(f"ALICE instructions/skipdata items = {len(alice_ins)}")
        print(f"ZIMAGE instructions/skipdata items = {len(zimage_ins)}")

        ax = show_xrefs(
            "ALICE DIRECT CALLS TO IMAGE/AUDIO REGISTRATION APIS",
            alice, ALICE_BASE, alice_ins, REG_TARGETS,
        )
        zx = show_xrefs(
            "ZIMAGE DIRECT CALLS TO IMAGE/AUDIO REGISTRATION APIS",
            zimage, ZIMAGE_BASE, zimage_ins, REG_TARGETS,
        )

        disp_a = show_xrefs(
            "ALICE DIRECT CALLS TO KNOWN DISPATCH/RESOLVER TARGETS",
            alice, ALICE_BASE, alice_ins, DISPATCH_TARGETS,
        )
        disp_z = show_xrefs(
            "ZIMAGE DIRECT CALLS TO KNOWN DISPATCH/RESOLVER TARGETS",
            zimage, ZIMAGE_BASE, zimage_ins, DISPATCH_TARGETS,
        )

        banner("E. STRUCTURAL SAFETY OBSERVATIONS")
        audio_cb_positions = []
        pat = struct.pack("<I", AUDIO_CALLBACK)
        pos = 0
        while True:
            k = zimage.find(pat, pos)
            if k < 0:
                break
            audio_cb_positions.append(k)
            pos = k + 1

        require(
            au["offset"] + 4 in audio_cb_positions,
            "native Audio callback pointer already exists in ZIMAGE resolver table",
        )
        print(f"Audio callback 0x{AUDIO_CALLBACK:08X} ZIMAGE u32 occurrence(s): {len(audio_cb_positions)}")
        for x in audio_cb_positions:
            print(f"  ZIMAGE+0x{x:X} runtime=0x{ZIMAGE_BASE+x:08X}")

        audio_init_positions = []
        pat2 = struct.pack("<I", AUDIO_INIT_PTR)
        pos = 0
        while True:
            k = zimage.find(pat2, pos)
            if k < 0:
                break
            audio_init_positions.append(k)
            pos = k + 1

        print(f"Audio init pointer 0x{AUDIO_INIT_PTR:08X} native ZIMAGE occurrence(s): {len(audio_init_positions)}")

        print()
        print("Interpretation guardrails:")
        print("- Strategy A bypasses the native Audio registration stub and feeds Audio init to Image registrars.")
        print("- Strategies B/C keep the native Audio callback 1033D841 intact.")
        print("- 1033D841 is already a legal cross-image callback in this exact resolver table.")
        print("- None of these structural facts proves which Image ID is the user-visible activation trigger.")

        banner("F. BUILD THREE LOGICAL-ONLY CANDIDATES")

        cand_a = make_candidate(
            zimage,
            "candidate_A_image_stub_literal_to_audio_init",
            IMAGE_LITERAL,
            IMAGE_ORIGINAL_PTR,
            AUDIO_INIT_PTR,
        )

        cand_b = make_candidate(
            zimage,
            "candidate_B_imageA_8313_resolver_callback_to_audio",
            ia["runtime"] + 4,
            IMAGE_CALLBACK,
            AUDIO_CALLBACK,
        )

        cand_c = make_candidate(
            zimage,
            "candidate_C_imageB_8321_resolver_callback_to_audio",
            ib["runtime"] + 4,
            IMAGE_CALLBACK,
            AUDIO_CALLBACK,
        )

        for c in (cand_a, cand_b, cand_c):
            print()
            print(c["name"])
            print(f"  runtime = {c['runtime_addr']}")
            print(f"  offset  = {c['zimage_offset']}")
            print(f"  old     = {c['old_value']} ({c['old_bytes']})")
            print(f"  new     = {c['new_value']} ({c['new_bytes']})")
            print(f"  diff    = {c['changed_bytes']} bytes")
            print(f"  sha256  = {c['sha256']}")
            print(f"  path    = {c['path']}")

        manifest = {
            "stage": "S13.4F",
            "status": "OFFLINE_LOGICAL_CANDIDATES_ONLY_NOT_FLASHABLE",
            "canonical": {
                "alice_sha256": sha256(alice),
                "zimage_sha256": sha256(zimage),
            },
            "resolver_rows": {
                "image_a": ia,
                "image_b": ib,
                "audio": au,
            },
            "native_registration": {
                "image_stub": f"0x{IMAGE_STUB:08X}",
                "image_literal": f"0x{IMAGE_LITERAL:08X}",
                "image_init_pointer": f"0x{IMAGE_ORIGINAL_PTR:08X}",
                "image_registrars": [
                    f"0x{IMAGE_REG_A:08X}",
                    f"0x{IMAGE_REG_B:08X}",
                ],
                "audio_stub": f"0x{AUDIO_STUB:08X}",
                "audio_callback": f"0x{AUDIO_CALLBACK:08X}",
                "audio_init_pointer": f"0x{AUDIO_INIT_PTR:08X}",
                "audio_registrars": [
                    f"0x{AUDIO_REG_A:08X}",
                    f"0x{AUDIO_REG_B:08X}",
                    f"0x{AUDIO_REG_C:08X}",
                ],
            },
            "logical_candidates": [cand_a, cand_b, cand_c],
            "limitations": [
                "No runtime trigger identity established for 0x8313 versus 0x8321.",
                "No candidate selected for flashing.",
                "No ZIMAGE LZMA recompression performed.",
                "No VIVA repack performed.",
                "No physical flash-sector mapping performed.",
                "No handset I/O.",
            ],
        }

        manifest_path = OUTDIR / "manifest.json"
        manifest_path.write_text(
            json.dumps(manifest, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )

        banner("S13.4F DECISION GATE")
        print("FACT 1: 0x8313 and 0x8321 both resolve natively to F02F3F85.")
        print("FACT 2: 0x8928 resolves natively to the complete Audio callback 1033D841.")
        print("FACT 3: Strategy A crosses Image registrar APIs with an Audio init pointer.")
        print("FACT 4: Strategies B/C preserve the complete native Audio registration callback.")
        print("FACT 5: 1033D841 is already referenced cross-image by the same ZIMAGE resolver table.")
        print()
        print("DO NOT SELECT B OR C UNTIL THE USER-VISIBLE IMAGE TRIGGER ID IS ESTABLISHED.")
        print("DO NOT RECOMPRESS / REPACK / FLASH FROM S13.4F.")
        print()
        print("PHONE ACCESSED       : NO")
        print("FLASH MODIFIED       : NO")
        print("LZMA RECOMPRESS      : NO")
        print("VIVA REPACK          : NO")
        print("PHYSICAL CANDIDATE   : NO")
        print("HARDWARE WRITE AUTHORIZED: NO")
        print()
        print(f"MANIFEST = {manifest_path}")
        print(f"REPORT   = {REPORT}")

    finally:
        sys.stdout = real
        log.close()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
