#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""S13.5A.101: bounded owner provenance of A100's three non-stack STRB candidates.

STRICTLY OFFLINE: read only two SHA-pinned images; write only a new .txt report.
This is a static, heuristic Thumb CFG and DOES NOT establish runtime aliasing,
actual execution after UI selection, or an Audio app launch.
"""
from __future__ import annotations

import argparse
import hashlib
import io
from collections import deque
from pathlib import Path

ALICE_BASE = 0x1024EC00
ALICE_SIZE = 0x157BB4
ALICE_SHA = "7246242b67afae0d13104452bc3257827cb778119b54e7a26fb7fb55993697ea"
ZIMAGE_BASE = 0xF023CA50
ZIMAGE_SIZE = 0x185E98
ZIMAGE_SHA = "85fba8c8ae8161e4c1f8ced7983ec30d48c54ab10e51c69fcdfb900aca220954"

# Address: exact instruction bytes from A100, base register, source register
SITES = {
    0x102EC0A4: (bytes.fromhex("2073"), "r4", "r0"),
    0x102EC9D4: (bytes.fromhex("3973"), "r7", "r1"),
    0x10346D42: (bytes.fromhex("2573"), "r4", "r5"),
}
# Original A90/A100 facts verified again, without scanning the binary globally.
ANCHORS = {
    0x102ED25C: bytes.fromhex("2073"),
    0x10345296: bytes.fromhex("aaf7d9f8"),
    0x1034529A: bytes.fromhex("207b"),
    0x1034529C: bytes.fromhex("0128"),
    0x1034529E: bytes.fromhex("07d0"),
}
CONDS = {"beq", "bne", "bhs", "blo", "bhi", "bls", "bge", "blt", "bgt", "ble", "bmi", "bpl", "bvs", "bvc", "cbz", "cbnz"}


def u32(value: int) -> int:
    return value & 0xFFFFFFFF


def normalize_thumb_target(value: int) -> int:
    return u32(value) & ~1


def self_test() -> str:
    assert normalize_thumb_target(-0xFD2B0A0) == 0xF02D4F60
    assert normalize_thumb_target(-0xFD2B0A4) == 0xF02D4F5C
    assert normalize_thumb_target(0x10345297) == 0x10345296
    assert len(SITES) == 3 and len(ANCHORS) == 5
    assert sum(len(v[0]) for v in SITES.values()) == 6
    return "A101_SELF_TEST=PASS signed-target normalization and exact-anchor metadata"


def read_guarded(path: Path, label: str, size: int, sha: str) -> bytes:
    if not path.is_file():
        raise RuntimeError(f"ABORT: {label} missing at {path}")
    data = path.read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    if len(data) != size or digest != sha:
        raise RuntimeError(f"ABORT: {label} GUARD FAIL size=0x{len(data):X} sha256={digest}")
    return data


def at(image: bytes, address: int, n: int = 4) -> bytes:
    off = address - ALICE_BASE
    if off < 0 or off+n > len(image):
        raise ValueError(f"ALICE address out of bounds: 0x{address:08X}+0x{n:X}")
    return image[off:off+n]


def make_decoder(image: bytes):
    try:
        from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_LITTLE_ENDIAN
    except ImportError as ex:
        raise RuntimeError(f"ABORT: Capstone required in project venv: {ex}") from ex
    md = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_LITTLE_ENDIAN)
    md.detail = True
    def dec(pc: int):
        if pc & 1 or pc < ALICE_BASE or pc+4 > ALICE_BASE+len(image):
            return None
        ds = tuple(md.disasm(at(image, pc, 4), pc, count=1))
        return ds[0] if ds and ds[0].address == pc else None
    return dec


def opcode(ins) -> str:
    return ins.mnemonic.lower().split(".")[0]


def call_target(ins):
    from capstone.arm import ARM_OP_IMM
    for op in reversed(ins.operands):
        if op.type == ARM_OP_IMM:
            return normalize_thumb_target(int(op.imm))
    return None


def is_return(ins) -> bool:
    m = opcode(ins)
    op = ins.op_str.lower().replace(" ", "")
    return (m == "pop" and "pc" in op) or (m == "bx" and op == "lr") or m in {"tbb", "tbh", "udf"}


def is_push_lr(ins) -> bool:
    return opcode(ins) == "push" and "lr" in ins.op_str.lower()


def fmt(ins) -> str:
    return f"0x{ins.address:08X} {ins.bytes.hex():<10} {ins.mnemonic:<9} {ins.op_str}"


def cfg(dec, start: int, site: int, upper: int, maximum: int = 370):
    # Local CFG, limited to start..upper, direct calls assumed to return.
    todo = deque([start]); insns = {}; branches=[]; calls=[]; limits=[]
    while todo and len(insns) < maximum:
        pc = todo.popleft()
        if pc in insns:
            continue
        if pc < start or pc >= upper:
            limits.append(pc)
            continue
        inst=dec(pc)
        if not inst:
            limits.append(pc)
            continue
        insns[pc] = inst
        m=opcode(inst)
        nxt=pc+inst.size
        if is_return(inst):
            continue
        if m in ("bl", "blx"):
            calls.append((pc, call_target(inst),m))
            todo.append(nxt)
            continue
        if m == "bx":
            limits.append(pc)
            continue
        if m=="b" or m in CONDS:
            target=call_target(inst)
            branches.append((pc,m,target))
            if target is None:
                limits.append(pc)
            else:
                todo.append(target)
            if m!="b":
                todo.append(nxt)
            continue
        if m.startswith("it"):
            # linear traversal is not an execution proof under IT predication
            limits.append(pc)
        todo.append(nxt)
    return dict(insns=insns, branches=branches, calls=calls, limits=limits,
                cap_hit=bool(todo), reached=site in insns)


def audit_site(w: io.StringIO, dec, addr: int, breg: str, sreg: str):
    ins = dec(addr)
    w.write(f"\n=== A100_SITE 0x{addr:08X} ===\n")
    w.write(f"RAW_INSTRUCTION={fmt(ins)}\n")
    w.write(f"BASE={breg} SOURCE={sreg}; DESCRIPTOR_ALIAS=UNPROVEN\n")
    # Enumerate nearby plausible entry points; this is heuristic, NOT exhaustive.
    lower=max(ALICE_BASE, addr-0x380)
    starts=[]
    for pc in range(lower & ~1, addr, 2):
        op=dec(pc)
        if op and is_push_lr(op):
            starts.append(pc)
    w.write(f"PROLOGUES_WITHIN_0x380={len(starts)}\n")
    owners=[]
    for start in starts:
        outcome=cfg(dec,start,addr,addr+0xA0)
        if outcome["reached"]:
            owners.append((start,outcome))
    owners.sort(key=lambda item: item[0], reverse=True)
    w.write("LOCAL_OWNERS_REACHING_SITE="+str(len(owners))+"\n")
    for start,info in owners[:12]:
        w.write(f"  OWNER 0x{start:08X} steps={len(info['insns'])} calls={len(info['calls'])} branches={len(info['branches'])} limits={len(info['limits'])} capped={info['cap_hit']}\n")
    if not owners:
        w.write("OWNER=UNRESOLVED; raw sequential disassembly shown below is NOT CFG\n")
        # Disassemble short sequential context starting from an even boundary;
        # 32-bit Thumb alignment can still be wrong.
        lo=addr-0x50;pc=lo & ~1
        while pc<addr+0x32:
            ci=dec(pc)
            if ci is None: break
            w.write((" >> " if pc==addr else "    ")+fmt(ci)+"\n")
            pc+=ci.size
        return
    # Nearest compatible prologue only, clearly labeled heuristic.
    start,info=owners[0]
    w.write(f"NEAREST_PLAUSIBLE_OWNER=0x{start:08X} (NOT UNIQUE OR VERIFIED)\n")
    entries=info["insns"]
    w.write("=== NEAR_STORE_REACHABLE_INSTRUCTIONS ===\n")
    for pc in sorted(entries):
        if addr-0x74 <= pc <= addr+0x30:
            w.write((" >> " if pc==addr else "    ")+fmt(entries[pc])+"\n")
    w.write("=== BASE_REGISTER_WRITE_CANDIDATES_IN_OWNER (ORDERED BY PC, NOT PATH) ===\n")
    out=[]
    for pc in sorted(entries):
        if pc >= addr:
            continue
        ci=entries[pc]; op=ci.op_str.lower().replace(" ","")
        m=opcode(ci)
        # Most Thumb ALU/load instructions list destination first. BL/BLX writes r0,
        # but does not itself define persistent r4/r7 unless a copy is seen.
        if op.startswith(breg+",") and m not in {"cmp","tst","str","strb","strh","stm","stmia"}:
            out.append(ci)
        if m in ("pop","ldm","ldmia") and breg in op:
            out.append(ci)
    for ci in out[-22:]:
        w.write("    "+fmt(ci)+"\n")
    w.write("=== ALL_DIRECT_CALLS_IN_OWNER_LOCAL_CFG ===\n")
    for pc,t,m in info["calls"]:
        w.write(f"    0x{pc:08X} {m} -> "+(f"0x{t:08X}" if t is not None else "INDIRECT")+"\n")
    w.write("=== LOCAL_CF_BRANCHES ===\n")
    for pc,m,t in info["branches"]:
        if addr-0x100<=pc<=addr+0x40:
            w.write(f"    0x{pc:08X} {m} -> "+(f"0x{t:08X}" if t is not None else "INDIRECT")+"\n")
    w.write(f"OWNER_BOUNDS_NOTE=local_cfg_limits:{len(info['limits'])}; no interprocedural dataflow; no runtime alias proof\n")


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--alice',type=Path)
    parser.add_argument('--zimage',type=Path)
    parser.add_argument('--out',type=Path)
    parser.add_argument('--self-test',action='store_true')
    args=parser.parse_args()
    if args.self_test:
        print(self_test());return
    if not (args.alice and args.zimage and args.out):
        parser.error('--alice, --zimage and --out are mandatory for the audit')
    try:
        destination=args.out.resolve()
        if destination in {args.alice.resolve(),args.zimage.resolve()}:
            raise RuntimeError("ABORT: report path equals input firmware path")
        if destination.exists():
            print(f"REPORT_ALREADY_EXISTS_UNCHANGED={destination}");return
        a=read_guarded(args.alice,'ALICE',ALICE_SIZE,ALICE_SHA)
        z=read_guarded(args.zimage,'ZIMAGE',ZIMAGE_SIZE,ZIMAGE_SHA)
        for ad,(raw,_,_) in SITES.items():
            if at(a,ad,len(raw))!=raw:
                raise RuntimeError(f"ABORT: A100 STRB anchor mismatch at 0x{ad:08X}")
        for ad,raw in ANCHORS.items():
            if at(a,ad,len(raw))!=raw:
                raise RuntimeError(f"ABORT: A90/A100 anchor mismatch at 0x{ad:08X}")
        dec=make_decoder(a)
        for ad,(raw,reg,src) in SITES.items():
            ins=dec(ad)
            expect=f"{src}, [{reg}, #0xc]".replace(" ","")
            if not ins or opcode(ins)!="strb" or ins.op_str.lower().replace(" ","")!=expect:
                raise RuntimeError(f"ABORT: Thumb STRB decode mismatch at 0x{ad:08X}: {ins}")
        w=io.StringIO()
        w.write("S13.5A.101 — THREE A100 UNKNOWN BYTE WRITERS: BOUNDED THUMB OWNER/BASE PROVENANCE\n")
        w.write("STRICTLY_OFFLINE=YES / BINARIES_READ_ONLY / REPORT_ONLY / NO_NOTEPAD\n")
        w.write(f"ALICE_GUARD=PASS SHA256={ALICE_SHA}\n")
        w.write(f"ZIMAGE_GUARD=PASS SHA256={ZIMAGE_SHA}\n")
        w.write(f"A100_THREE_EXACT_STRB_ANCHORS=PASS A90_OTHER_ANCHORS=PASS count={len(ANCHORS)}\n")
        w.write("A100_TEN_TOTAL_STORES=HISTORICAL_REPORT; six look stack-relative, one proven known clear, three unclassified\n")
        w.write("METHOD=bounded heuristic per-candidate CFG; prologues within 0x380; NO automatic alias or reachability promotion\n")
        w.write("WARNING=multiple owners may reach a site; signed Thumb targets normalized; IT/call/indirect semantics limited\n")
        for ad,(_,reg,src) in SITES.items():
            audit_site(w,dec,ad,reg,src)
        w.write("\n=== EVIDENCE_BOUNDARY ===\n")
        w.write("To classify a descriptor+0x0C setter, first prove exact descriptor pointer on the store's base, value==1, and a concrete selected-leaf dispatch path.\n")
        w.write("Do not assume neighbor offsets imply same descriptor. A90 post-dispatch LDRB/CMP remains a gate, not a writer proof.\n")
        w.write("AUDIO_0x8928_MENU_BINDING=UNPROVEN FM_NUMERIC_ROM_ID=UNKNOWN\n")
        w.write("NO_PHONE_USB_COM_FLASH_PATCH_REPACK=YES\n")
        destination.parent.mkdir(parents=True,exist_ok=True)
        # Exclusive create, never overwrite existing report.
        with destination.open('x',encoding='utf-8') as output:
            output.write(w.getvalue())
        print(f"A101_REPORT_CREATED={destination}")
        print(f"A101_REPORT_BYTES={destination.stat().st_size}")
        print("A101_GUARDS=PASS")
    except (RuntimeError, ValueError, OSError) as exc:
        raise SystemExit(str(exc))

if __name__=='__main__':
    main()
