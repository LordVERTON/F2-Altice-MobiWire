#!/usr/bin/env python3
"""S13.5A.85: bounded switch/computed-branch audit for ZIMAGE F02AE130.

Strictly OFFLINE. Reads existing pinned ALICE and ZIMAGE only. Does not
interact with USB/COM/phone, write binaries, patch, erase, flash, or repack.

Distinguishes raw Thumb pattern matches from CFG-reachable executable code.
No menu OK/Select or Audio 0x8928 assertion is made from opcode proximity.
"""
from __future__ import annotations

import argparse
import hashlib
from pathlib import Path

from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_LITTLE_ENDIAN
from capstone.arm import ARM_OP_MEM, ARM_OP_IMM, ARM_OP_REG, ARM_REG_PC

ABASE = 0x1024EC00
ASIZE = 0x157BB4
ASHA = "7246242b67afae0d13104452bc3257827cb778119b54e7a26fb7fb55993697ea"
ZBASE = 0xF023CA50
ZSIZE = 0x185E98
ZSHA = "85fba8c8ae8161e4c1f8ced7983ec30d48c54ab10e51c69fcdfb900aca220954"
SLOT = 0xF004C5E8
CALL = 0xF02AE130
CALLEE = 0xF02F2C10
JOIN = 0xF02AE1FE
SCHEMA = (
    (0xF02AE116, 0xF02AE118, 0xF02F260C),
    (0xF02AE11E, 0xF02AE120, 0xF02FC0A0),
    (0xF02AE126, 0xF02AE128, 0xF02FBF7C),
    (0xF02AE12E, 0xF02AE130, 0xF02F2C10),
)
CASE_HEADS = {x for start, bl, _ in SCHEMA for x in (start, bl)}
LOW = 0xF02ADCA0
HIGH = 0xF02AE0A0  # stop BEFORE the known case code at A0
MAX_TABLE_ENTRIES = 96


def abort(message: str) -> None:
    raise SystemExit("ABORT: " + message)


def pinned(path: Path, name: str, size: int, sha: str) -> bytes:
    if not path.is_file():
        abort(f"{name} missing: {path}")
    data = path.read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    passed = len(data) == size and digest == sha
    print(f"{name}: path={path} size=0x{len(data):X} sha256={digest} GUARD={'PASS' if passed else 'FAIL'}")
    if not passed:
        abort(f"{name} canonical size/SHA mismatch")
    return data


def at(data: bytes, addr: int, length: int) -> bytes | None:
    off = addr - ZBASE
    if length < 0 or off < 0 or off + length > len(data):
        return None
    return data[off:off + length]


def instruction(md: Cs, data: bytes, address: int):
    raw = at(data, address, 4)
    if raw is None:
        return None
    decoded = list(md.disasm(raw, address, count=1))
    return decoded[0] if decoded and decoded[0].address == address else None


def mnem(i) -> str:
    return i.mnemonic.lower().split(".")[0]


def imm_target(i) -> int | None:
    for op in i.operands:
        if op.type == ARM_OP_IMM:
            return op.imm & 0xFFFFFFFE & 0xFFFFFFFF
    return None


def print_ins(i) -> str:
    return f"0x{i.address:08X} {i.mnemonic:<9} {i.op_str:<31} bytes={i.bytes.hex(' ')}"


def require(md, data, addr, mnemonic, raw, target=None):
    i = instruction(md, data, addr)
    if i is None or mnem(i) != mnemonic or i.bytes != bytes.fromhex(raw):
        abort(f"exact known-site mismatch at 0x{addr:08X} ({mnemonic} / {raw})")
    if target is not None and imm_target(i) != target:
        abort(f"exact branch mismatch at 0x{addr:08X}: found {imm_target(i)!r}; expected 0x{target:08X}")
    print("  PASS " + print_ins(i))
    return i


def verify(md, data):
    print("\n[A] PINNED A83/A84 ANCHORS (NO NEW SEMANTIC ASSUMPTIONS)")
    for head, bl, callee in SCHEMA:
        require(md, data, head, "add", "13 a8")
        i = instruction(md, data, bl)
        if i is None or mnem(i) != "bl" or imm_target(i) != callee:
            abort(f"known case BL mismatch at 0x{bl:08X}")
        print("  PASS " + print_ins(i))
        b = instruction(md, data, bl + 4)
        if b is None or mnem(b) != "b" or imm_target(b) != JOIN:
            abort(f"known case join mismatch at 0x{bl + 4:08X}")
    require(md, data, CALL, "bl", "44 f0 6e fd", CALLEE)
    require(md, data, 0xF02F2C7C, "ldr", "06 48")
    cell = at(data, 0xF02F2C98, 4)
    if cell is None or int.from_bytes(cell, "little") != SLOT:
        abort("known slot literal mismatch")
    require(md, data, 0xF02F2C7E, "ldr", "00 68")
    require(md, data, 0xF02F2C80, "blx", "80 47")
    print("KNOWN_LINKS_PASS=YES; no run-time call inference")


def nearby(md, data, center, radius=0x18):
    lo = max(LOW, center - radius) & ~1
    hi = min(HIGH, center + 0x10) & ~1
    if hi <= lo:
        return
    blob = at(data, lo, hi - lo)
    if blob is None:
        return
    print(f"    RAW_LOCAL_DISASM=[0x{lo:08X},0x{hi:08X}) ; NOT CFG")
    for i in md.disasm(blob, lo):
        if len(str(i.op_str)) > 100:
            continue
        print("      " + print_ins(i))


def tbl_candidate(i, data):
    # TBB/TBH can derive jump destinations ONLY when the base is PC;
    # no guessing about general register bases or dynamic index values.
    memops = [op for op in i.operands if op.type == ARM_OP_MEM]
    if len(memops) != 1 or memops[0].mem.base != ARM_REG_PC:
        return {"status": "BASE_NOT_PC_OR_UNKNOWN", "matches": [], "samples": []}
    size = 1 if mnem(i) == "tbb" else 2
    table_start = i.address + 4
    hits = []
    samples = []
    for n in range(MAX_TABLE_ENTRIES):
        loc = table_start + size * n
        raw = at(data, loc, size)
        if raw is None or loc >= HIGH:
            break
        val = int.from_bytes(raw, "little")
        dest = (i.address + 4 + val * 2) & 0xFFFFFFFF
        if n < 10:
            samples.append((n, loc, val, dest))
        if dest in CASE_HEADS or dest in {JOIN, 0xF02AE0A0}:
            hits.append((n, loc, val, dest))
    return {"status": "PC_TABLE_RAW_HYPOTHESIS_NOT_RUNTIME", "matches": hits, "samples": samples}


def scan_dispatch(md, data):
    print("\n[B] NEW BOUNDED COMPUTED-BRANCH TEST — NOT A PROLOGUE RESCAN")
    print(f"THUMB_16BIT_ALIGNED_SCAN=[0x{LOW:08X},0x{HIGH:08X})")
    print("Syntactic candidates can occur in literal pools. A match is NOT a reachable dispatcher.")
    tab = []
    dyn = []
    direct = []
    for addr in range(LOW, HIGH, 2):
        i = instruction(md, data, addr)
        if i is None:
            continue
        mn = mnem(i)
        if mn in ("tbb", "tbh"):
            tab.append(i)
        elif (mn in ("bx", "blx", "mov", "add", "ldr")
              and (i.op_str.lower().startswith("pc,") or
                   (mn in ("bx", "blx") and len(i.operands) > 0
                    and i.operands[0].type == ARM_OP_REG
                    and i.op_str.lower().strip() != "lr"))):
            dyn.append(i)
        elif mn == "b" or mn.startswith("b") or mn in ("cbz", "cbnz"):
            t = imm_target(i)
            if t in CASE_HEADS:
                direct.append(i)
    print(f"RAW_TBB_TBH_CANDIDATES={len(tab)} RAW_COMPUTED_PC_OR_BX_CANDIDATES={len(dyn)}")
    print(f"RAW_DIRECT_BRANCH_INTO_FOUR_KNOWN_CASES={len(direct)}")
    strong = 0
    for i in tab[:18]:
        print("  TABLE_PATTERN " + print_ins(i))
        hypothesis = tbl_candidate(i, data)
        print(f"    {hypothesis['status']} matches={len(hypothesis['matches'])}")
        for row in hypothesis["matches"][:16]:
            n, addr, val, dst = row
            print(f"    CASE_POSSIBILITY idx={n:02d} cell=0x{addr:08X} raw=0x{val:X} -> 0x{dst:08X}")
        for row in hypothesis["samples"][:6]:
            n, addr, val, dst = row
            print(f"    sample idx={n:02d} cell=0x{addr:08X} raw=0x{val:X} -> 0x{dst:08X}")
        if hypothesis["matches"]:
            strong += 1
        nearby(md, data, i.address)
    for i in dyn[:22]:
        print("  DYNAMIC_BRANCH_PATTERN " + print_ins(i))
    for i in direct[:22]:
        print("  DIRECT_BRANCH_PATTERN " + print_ins(i))
    print(f"TBB_TBH_PC_MATCHES_TO_CASES={strong}")
    if len(tab) > 18 or len(dyn) > 22 or len(direct) > 22:
        print("CANDIDATE_PRINT_CAP_REACHED=YES; raw counts remain above")
    if not strong and not direct:
        print("BOUNDED_SELECTOR_MATCH_NOT_FOUND=YES — do not re-run adjacent prologue scans")
    else:
        print("BOUNDED_POTENTIAL_PREDECESSORS_FOUND=YES — still require executable-path and index-source proof")


def inspect_data_boundary(data):
    print("\n[C] PRE-CASE REGION TYPE WARNING — DATA vs EXECUTABLE CODE")
    for start in range(0xF02AE070, 0xF02AE0A0, 0x10):
        b = at(data, start, 0x10)
        if b is None:
            abort("boundary hex outside source image")
        print(f"  0x{start:08X}: {b.hex(' ')}")
    print("A84 decoded BKPT at F02AE09E from a raw linear sweep; this may be data.")
    print("Do not infer TBB/TBH, jump-table, or menu-event semantics without upstream proof.")


def main():
    pa = argparse.ArgumentParser(description=__doc__)
    pa.add_argument("--alice", type=Path, default=Path("research/f2/work/extracted/altice_alice/alice-py.bin"))
    pa.add_argument("--zimage", type=Path, default=Path("research/f2/work/extracted/altice_platform/zimage.bin"))
    args = pa.parse_args()
    print("S13.5A.85 — COMPUTED THUMB BRANCH / POSSIBLE TABLE LEADING TO F02AE130")
    print("STRICTLY OFFLINE; READ ONLY; no USB/COM/phone/flash/erase/write/patch/repack")
    pinned(args.alice, "ALICE", ASIZE, ASHA)
    data = pinned(args.zimage, "ZIMAGE", ZSIZE, ZSHA)
    md = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_LITTLE_ENDIAN)
    md.detail = True
    verify(md, data)
    scan_dispatch(md, data)
    inspect_data_boundary(data)
    print("\n[D] NEXT DECISION GATE")
    print("A85_OFFLINE_AUDIT_COMPLETED=YES")
    print("CONTEXT_SLOT_EXECUTION_CODE_PROVEN=YES")
    print("DISPATCH_TRIGGER_CONFIRMED=NO")
    print("MENU_OK_AUDIO_8928_PROVEN=NO")
    print("If no validated computed-branch predecessor emerges, CLOSE this UI callback detour for now.")
    print("PHONE_ACCESSED=NO FIRMWARE_MODIFIED=NO WRITE_AUTHORIZED=NO")


if __name__ == "__main__":
    main()
