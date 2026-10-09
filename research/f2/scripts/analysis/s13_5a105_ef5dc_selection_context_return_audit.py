#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""S13.5A.105 — exact selection-context helper 0x102EF5DC.

STRICTLY OFFLINE: read-only canonical ALICE + ZIMAGE, and one new TXT report.
No USB/COM, phone access, firmware patch/repack/flash, network or Notepad.

Narrow new question after A.104: THREE executable-looking ALICE wrappers each
call 0x102EF5DC immediately before BL 0x102ED240. What code and return-path
value does 0x102EF5DC expose to the latter through r0?

This script reconstructs only a bounded *local* Thumb CFG for 0x102EF5DC,
validates the six exact known BL encodings, records literal reads, register
writes involving r0, outgoing calls, conditional paths and return sites.
It does NOT infer interprocedural return values, callback activation, or
selected leaf IDs. Branches outside the bounded range are explicitly reported.
"""
from __future__ import annotations

import argparse
import hashlib
import struct
from collections import deque
from pathlib import Path

ALICE_BASE = 0x1024EC00
ALICE_SIZE = 0x157BB4
ALICE_SHA = "7246242b67afae0d13104452bc3257827cb778119b54e7a26fb7fb55993697ea"
ZIMAGE_SIZE = 0x185E98
ZIMAGE_SHA = "85fba8c8ae8161e4c1f8ced7983ec30d48c54ab10e51c69fcdfb900aca220954"
ENTRY = 0x102EF5DC
OWNER = 0x102ED240
# All bytes are from A.104's user-verified report. No derived offsets guessed.
CALL_CHAINS = (
    (0x1039CCC0, "52f78cfc", 0x1039CCC4, "50f7bcfa"),
    (0x1039E49C, "51f79ef8", 0x1039E4A0, "4ef7cefe"),
    (0x103A232C, "4df756f9", 0x103A2330, "4af786ff"),
)
OTHER_ANCHORS = {
    0x102ED240: "10b5",   # A.90/A.104 owner entry
    0x10342E2A: "0248",   # A.104: r0 = 0x6316, not selected child id
    0x10345332: "0248",   # A.104: r0 = 0x6314
}
CONDITIONAL = {
    "beq", "bne", "bgt", "bge", "blt", "ble", "bhi", "bhs", "blo", "bls",
    "bmi", "bpl", "bvs", "bvc", "cbz", "cbnz",
}


def abort(reason: str) -> None:
    raise SystemExit("ABORT: " + reason)


def wide_branch(site: int, data: bytes):
    """Decode Thumb-2 BL or unconditional B.W, including signed PC-relative."""
    if len(data) != 4:
        return None
    h1, h2 = struct.unpack("<HH", data)
    if h1 & 0xF800 != 0xF000:
        return None
    tag = h2 & 0xD000
    if tag == 0xD000:
        kind = "BL"
    elif tag == 0x9000:
        kind = "B.W"
    else:
        return None
    s, j1, j2 = (h1 >> 10) & 1, (h2 >> 13) & 1, (h2 >> 11) & 1
    i1, i2 = 1 ^ (j1 ^ s), 1 ^ (j2 ^ s)
    disp = ((s << 24) | (i1 << 23) | (i2 << 22)
            | ((h1 & 0x3FF) << 12) | ((h2 & 0x7FF) << 1))
    if disp & (1 << 24):
        disp -= 1 << 25
    return kind, (site + 4 + disp) & 0xFFFFFFFF


def self_test() -> None:
    for pre, pre_raw, site, site_raw in CALL_CHAINS:
        assert site == pre + 4
        assert wide_branch(pre, bytes.fromhex(pre_raw)) == ("BL", ENTRY), hex(pre)
        assert wide_branch(site, bytes.fromhex(site_raw)) == ("BL", OWNER), hex(site)
    assert wide_branch(0x102ED000, bytes.fromhex("10b510bd")) is None
    assert wide_branch(0x102ED000, bytes.fromhex("00f002b8")) == ("B.W", 0x102ED008)
    assert (0xF02D4F60 & 0xFFFFFFFF) == 0xF02D4F60
    print("A105_SELF_TEST=PASS THREE_EXACT_A104_BL_PAIRS=6 PLUS_NEGATIVE_WIDE")


def load_canonical(path: Path, label: str, size: int, expected: str):
    if not path.is_file():
        abort(f"{label} missing: {path}")
    blob = path.read_bytes()
    actual = hashlib.sha256(blob).hexdigest()
    if len(blob) != size or actual != expected:
        abort(f"{label} guard FAIL size=0x{len(blob):X} SHA256={actual}")
    return blob


def at(alice: bytes, addr: int, n: int):
    offset = addr - ALICE_BASE
    if offset < 0 or offset + n > len(alice):
        return None
    return alice[offset:offset+n]


def verify_anchor(alice: bytes) -> None:
    for pre, pre_raw, site, site_raw in CALL_CHAINS:
        for pc, raw in ((pre, pre_raw), (site, site_raw)):
            if at(alice, pc, 4) != bytes.fromhex(raw):
                abort(f"exact A104 call bytes mismatch at 0x{pc:08X}")
        if wide_branch(pre, at(alice, pre, 4)) != ("BL", ENTRY):
            abort(f"A104 pre-call target mismatch 0x{pre:08X}")
        if wide_branch(site, at(alice, site, 4)) != ("BL", OWNER):
            abort(f"A104 owner target mismatch 0x{site:08X}")
    for pc, hx in OTHER_ANCHORS.items():
        if at(alice, pc, len(bytes.fromhex(hx))) != bytes.fromhex(hx):
            abort(f"known A104 anchor mismatch at 0x{pc:08X}")


def get_instruction(md, alice: bytes, addr: int):
    raw = at(alice, addr, 4)
    if raw is None:
        return None
    ins = next(md.disasm(raw, addr, count=1), None)
    return ins if ins and ins.address == addr else None


def mn(ins) -> str:
    return ins.mnemonic.lower().split(".")[0]


def direct_target(ins):
    from capstone.arm import ARM_OP_IMM
    for op in reversed(ins.operands):
        if op.type == ARM_OP_IMM:
            return (int(op.imm) & 0xFFFFFFFF) & ~1
    return None


def literal(ins, alice: bytes):
    from capstone.arm import ARM_OP_MEM, ARM_REG_PC
    if mn(ins) != "ldr" or len(ins.operands) < 2:
        return None
    op = ins.operands[1]
    if op.type != ARM_OP_MEM or op.mem.base != ARM_REG_PC or op.mem.index:
        return None
    cell = ((((ins.address + 4) & ~3) + int(op.mem.disp)) & 0xFFFFFFFF)
    raw = at(alice, cell, 4)
    return (cell, struct.unpack("<I", raw)[0]) if raw else None


def fmt(ins, alice):
    lit = literal(ins, alice)
    suffix = f" ; LITERAL[0x{lit[0]:08X}]=0x{lit[1]:08X}" if lit else ""
    return f"0x{ins.address:08X} {ins.bytes.hex():<10} {ins.mnemonic:<9} {ins.op_str}{suffix}"


def is_return(ins):
    n = mn(ins)
    operands = ins.op_str.lower().replace(" ", "")
    return ((n == "pop" and "pc" in operands)
            or (n == "bx" and operands == "lr")
            or (n == "mov" and operands in ("pc,lr", "pc,r14"))
            or (n in ("ldm", "ldmia") and "pc" in operands))


def local_cfg(md, alice, span: int, max_insns: int):
    # Each decoded instruction is in the same bounded target function vicinity.
    limit = ENTRY + span
    todo = deque([ENTRY])
    visited, calls, branches, returns, notes = {}, [], [], [], []
    while todo and len(visited) < max_insns:
        pc = todo.popleft()
        if pc in visited:
            continue
        if not ENTRY <= pc < limit:
            notes.append(f"OUT_OF_WINDOW target=0x{pc:08X}")
            continue
        ins = get_instruction(md, alice, pc)
        if not ins or pc + ins.size > limit:
            notes.append(f"DECODE_OR_BOUND_ISSUE pc=0x{pc:08X}")
            continue
        visited[pc] = ins
        name, next_pc = mn(ins), pc + ins.size
        if name in ("bl", "blx"):
            from capstone.arm import ARM_OP_IMM
            target = direct_target(ins) if any(o.type == ARM_OP_IMM for o in ins.operands) else None
            calls.append((pc, target, name))
            if target is None:
                notes.append(f"INDIRECT_CALL site=0x{pc:08X}")
            todo.append(next_pc)  # BL returns assumed, explicitly qualified.
        elif is_return(ins):
            returns.append(pc)
        elif name in CONDITIONAL or name == "b":
            t = direct_target(ins)
            if t is not None:
                branches.append((pc, t, name))
                todo.append(t)
            else:
                notes.append(f"INDIRECT_BRANCH site=0x{pc:08X}")
            if name != "b":
                todo.append(next_pc)
        elif name in ("bx", "tbb", "tbh") or (name == "ldr" and ins.op_str.lower().startswith("pc,")):
            notes.append(f"INDIRECT_TERMINAL site=0x{pc:08X} {ins.op_str}")
        else:
            if name == "it" or name.startswith("it") and len(name) <= 5:
                notes.append(f"IT_PREDICATION site=0x{pc:08X} (CFG does not predicate individual instructions)")
            todo.append(next_pc)
    if todo:
        notes.append(f"MAX_INSNS_REACHED cap={max_insns}")
    return visited, calls, branches, returns, notes


def return_r0_hints(visited, returns, alice):
    result = []
    for ret in returns:
        result.append(f"  RETURN=0x{ret:08X}")
        result.append("    PRECEDING_BY_PC (not predecessor path; only a code neighborhood):")
        for pc in sorted(p for p in visited if ret - 0x28 <= p < ret):
            ins = visited[pc]
            name, ops = mn(ins), ins.op_str.lower().replace(" ", "")
            if (ops.startswith("r0,") or name in ("bl", "blx") or name in CONDITIONAL or name == "b"
                    or name == "pop" or "[r0" in ops):
                result.append("      " + fmt(ins, alice))
        result.append("    R0_PROVENANCE=LOCAL_HINT_ONLY; inspect predecessor paths and callee effects")
    return result


def build_report(alice: bytes, zimage: bytes, span: int, cap: int) -> str:
    verify_anchor(alice)
    try:
        from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_LITTLE_ENDIAN
    except ImportError as exc:
        abort("Capstone missing in analysis Python environment: " + str(exc))
    md = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_LITTLE_ENDIAN)
    md.detail = True
    visited, calls, branches, returns, notes = local_cfg(md, alice, span, cap)
    if ENTRY not in visited:
        abort("cannot decode 0x102EF5DC")
    lines = [
        "S13.5A.105 — 102EF5DC RETURN/CONTEXT PROVENANCE TO 102ED240 (OFFLINE)",
        "STRICTLY_OFFLINE=YES INPUT_IMAGES_READ_ONLY=YES NO_USB_COM_PHONE_PATCH_FLASH_REPACK=YES",
        f"ALICE_GUARD=PASS SHA256={ALICE_SHA}",
        f"ZIMAGE_GUARD=PASS SHA256={ZIMAGE_SHA}",
        "A104_SIX_EXACT_BL_ANCHORS=PASS; THREE_CALL_PAIRS=PASS",
        f"ENTRY=0x{ENTRY:08X} FILE_OFFSET=0x{ENTRY - ALICE_BASE:X} WINDOW=[0x{ENTRY:08X},0x{ENTRY+span:08X})",
        f"REACHABLE={len(visited)} CALLS={len(calls)} BRANCHES={len(branches)} RETURNS={len(returns)} NOTES={len(notes)}",
        "LIMIT: local Thumb CFG, BL/BLX return assumed, IT and indirect context not followed.",
        "LIMIT: this does NOT prove selected child ID, user OK, application launch or event-callback binding.",
        "",
        "=== A104 PREVIOUSLY PROVEN IMMEDIATE CALL CHAINS (NOT RESCANNED) ===",
    ]
    for pre, pre_raw, site, site_raw in CALL_CHAINS:
        a = get_instruction(md, alice, pre)
        b = get_instruction(md, alice, site)
        if not a or not b or mn(a) != "bl" or mn(b) != "bl":
            abort(f"Capstone BL decode disagrees with verified source at 0x{pre:08X}")
        if direct_target(a) != ENTRY or direct_target(b) != OWNER:
            abort(f"Capstone BL destination differs from A104 at 0x{pre:08X}")
        lines.append(f"0x{pre:08X} BL 0x{ENTRY:08X} ; then 0x{site:08X} BL 0x{OWNER:08X}")
    lines.append("\n=== LOCAL THUMB CFG OF 0x102EF5DC ===")
    for pc in sorted(visited):
        lines.append(fmt(visited[pc], alice))
    lines.append("\n=== DIRECT / INDIRECT CALLS (NOT FOLLOWED) ===")
    for pc, target, kind in calls:
        lines.append(f"0x{pc:08X} {kind} -> " + (f"0x{target:08X}" if target is not None else "INDIRECT"))
    lines.append("\n=== LOCAL BRANCH EDGES ===")
    for pc, target, kind in branches:
        lines.append(f"0x{pc:08X} {kind} -> 0x{target:08X}")
    lines.append("\n=== RETURN POINTS AND R0 NEARBY HINTS ===")
    lines.extend(return_r0_hints(visited, returns, alice))
    lines.append("\n=== BOUNDS / UNRESOLVED ===")
    lines.extend(notes or ["none within local bounded traversal"])
    lines.append("\n=== DECISION GATE ===")
    lines.append("If r0 is returned from a known getter, identify that object before classifying event/selection.")
    lines.append("If it is only an event-context pointer, CLOSE this helper and pivot to selected-leaf handler.")
    lines.append("NONE_OF_0x6314_0x6316_OR_AUDIO_0x8928_IS_PROVEN_TO_BE_SELECTED_CHILD_ID")
    lines.append("FM_NUMERIC_ID=UNKNOWN DESCRIPTOR_0C_SET_TO_1=UNPROVEN")
    lines.append("REPORT_ONLY=YES NO_NOTEPAD=YES NO_NETWORK=YES")
    return "\n".join(lines) + "\n"


def root_guess() -> Path:
    for parent in Path(__file__).resolve().parents:
        if (parent / "research" / "f2").is_dir():
            return parent
    return Path.cwd()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=root_guess())
    parser.add_argument("--alice", type=Path)
    parser.add_argument("--zimage", type=Path)
    parser.add_argument("--out", type=Path)
    parser.add_argument("--span", type=lambda value: int(value, 0), default=0x400)
    parser.add_argument("--max-insns", type=int, default=500)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    self_test()
    if args.self_test:
        return 0
    if not 0x100 <= args.span <= 0x800 or not 32 <= args.max_insns <= 1600:
        abort("span must be 0x100..0x800 and max-insns must be 32..1600")
    root = args.root.resolve()
    alice_file = args.alice or (root / "research/f2/work/extracted/altice_alice/alice-py.bin")
    zimage_file = args.zimage or (root / "research/f2/work/extracted/altice_platform/zimage.bin")
    report_file = args.out or (root / "research/f2/work/reports/s13_5a105_ef5dc_selection_context_return_audit.txt")
    alice = load_canonical(alice_file, "ALICE", ALICE_SIZE, ALICE_SHA)
    zimage = load_canonical(zimage_file, "ZIMAGE", ZIMAGE_SIZE, ZIMAGE_SHA)
    report = build_report(alice, zimage, args.span, args.max_insns)
    report_file.parent.mkdir(parents=True, exist_ok=True)
    try:
        with report_file.open("x", encoding="utf-8", newline="\n") as handle:
            handle.write(report)
    except FileExistsError:
        print(f"A105_REPORT_ALREADY_EXISTS_UNCHANGED={report_file}")
        return 0
    print(f"A105_REPORT_CREATED={report_file} BYTES={report_file.stat().st_size}")
    print("A105_PROOF_STATUS=REPORT_AVAILABLE_REVIEW_REQUIRED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
