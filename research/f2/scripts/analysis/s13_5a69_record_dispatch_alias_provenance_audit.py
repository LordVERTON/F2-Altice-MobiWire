#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""S13.5A.69 — 0x20-byte record / indirect-dispatch alias provenance audit.

STRICTLY OFFLINE: read only the canonical, byte-guarded ALICE and ZIMAGE.
No USB/COM/BROM/DA, phone access, firmware write/erase, patch or repack.

QUESTION: Do ZIMAGE +0x1C -> BLX callbacks (F030C118, F0312FD2)
actually consume the same dynamic 0x20-byte records written by ALICE
10316834 through [F004C5AC+8]?

This is a bounded discriminating audit of known functions. It does NOT perform
an image-wide cross-reference search, and it does NOT infer RAM alias merely
from equal strides or nearby literals. All linear symbolic slices are marked
as path-UNVERIFIED when control flow is not fully proven.
"""
from __future__ import annotations

import argparse
import hashlib
import re
import struct
from dataclasses import dataclass
from pathlib import Path

try:
    from capstone import Cs, CS_ARCH_ARM, CS_MODE_LITTLE_ENDIAN, CS_MODE_THUMB
    from capstone.arm import ARM_OP_IMM, ARM_OP_MEM, ARM_OP_REG, ARM_REG_PC
except ImportError as exc:
    raise SystemExit(f"ABORT: capstone missing in canonical venv: {exc}")

ALICE_BASE = 0x1024EC00
ALICE_SIZE = 0x157BB4
ALICE_SHA = "7246242b67afae0d13104452bc3257827cb778119b54e7a26fb7fb55993697ea"
ZIMAGE_BASE = 0xF023CA50
ZIMAGE_SIZE = 0x185E98
ZIMAGE_SHA = "85fba8c8ae8161e4c1f8ced7983ec30d48c54ab10e51c69fcdfb900aca220954"
WRITER_GLOBAL = 0xF004C5AC
RECORD_PTR_SLOT = WRITER_GLOBAL + 8
COUNT_HANDLE = 0xF00B8094

# Start/end are taken from A.68 actual decoded function neighborhoods.
# They are NOT a claim that the region begins or ends at a function boundary.
RANGES = (
    ("ALICE writer (source of truth)", 0x10316834, 0x10316878),
    ("ALICE record buffer initialize/pointer map", 0x103139D6, 0x10313A18),
    ("ALICE alternate writer to same buffer", 0x1034E3D6, 0x1034E40C),
    ("ALICE indexed secondary state", 0x1034A7C8, 0x1034A7F2),
    ("ZIMAGE candidate A: selected record dispatch preparation", 0xF030C052, 0xF030C0A8),
    ("ZIMAGE candidate A: +0x1C -> BLX r7", 0xF030C0D6, 0xF030C124),
    ("ZIMAGE candidate B: +0x1C -> BLX r5", 0xF0312F96, 0xF0312FDA),
    ("ZIMAGE nearby item selection context", 0xF031910E, 0xF031915A),
)
CALLS = {0xF030C118: "ZIMAGE_A_BLX_R7", 0xF0312FD2: "ZIMAGE_B_BLX_R5"}
FOCUS = {
    WRITER_GLOBAL: "WRITER_GLOBAL",
    RECORD_PTR_SLOT: "RECORD_PTR_SLOT_ADDRESS",
    COUNT_HANDLE: "COUNT_HANDLE",
    0x1033E815: "AUDIO_INIT",
    0x1033F83C: "AUDIO_PLAYER",
}


def banner(title: str) -> None:
    print("\n" + "=" * 108)
    print(title)
    print("=" * 108)


@dataclass(frozen=True)
class Image:
    name: str
    base: int
    data: bytes

    def contains(self, addr: int, size: int = 1) -> bool:
        return self.base <= addr and addr + size <= self.base + len(self.data)

    def u32(self, addr: int) -> int:
        if not self.contains(addr, 4):
            raise RuntimeError(f"{self.name}: out-of-range U32 {addr:#x}")
        return struct.unpack_from("<I", self.data, addr - self.base)[0]

    def slice(self, addr: int, size: int) -> bytes:
        if not self.contains(addr, size):
            raise RuntimeError(f"{self.name}: out-of-range code {addr:#x}+{size:#x}")
        return self.data[addr-self.base:addr-self.base+size]


def guarded(path: Path, name: str, base: int, expected_size: int, expected_sha: str) -> Image:
    if not path.is_file():
        raise SystemExit(f"ABORT: {name} missing: {path}")
    b = path.read_bytes()
    digest = hashlib.sha256(b).hexdigest()
    ok = len(b) == expected_size and digest == expected_sha
    print(f"{name}: size=0x{len(b):X}; sha256={digest}; GUARD={'PASS' if ok else 'FAIL'}; path={path}")
    if not ok:
        raise SystemExit("ABORT: wrong/noncanonical image; analysis not started")
    return Image(name, base, b)


class Auditor:
    def __init__(self, images):
        self.images = images
        self.decoder = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_LITTLE_ENDIAN)
        self.decoder.detail = True

    def image_for(self, addr: int) -> Image:
        for im in self.images:
            if im.contains(addr, 2):
                return im
        raise RuntimeError(f"no canonical image for {addr:#x}")

    def one(self, addr: int):
        im = self.image_for(addr)
        data = im.slice(addr, min(4, im.base+len(im.data)-addr))
        return next(iter(self.decoder.disasm(data, addr, count=1)), None)

    def linear(self, start: int, stop: int):
        if not (start < stop and start % 2 == 0 and stop % 2 == 0 and stop-start <= 0x200):
            raise RuntimeError("ABORT: nonsensical/nonbounded disassembly window")
        pos = start
        out = []
        while pos < stop:
            ins = self.one(pos)
            if ins is None or ins.size not in (2, 4):
                raise RuntimeError(f"decode failure at 0x{pos:08X}")
            if pos+ins.size > stop:
                break  # explicit bounded window, no attempt to decode a partial last instruction
            out.append(ins)
            pos += ins.size
        return out

    def literal(self, ins):
        if not ins.mnemonic.lower().startswith("ldr") or len(ins.operands) < 2:
            return None
        op = ins.operands[1]
        if op.type != ARM_OP_MEM or op.mem.base != ARM_REG_PC:
            return None
        cell = (((ins.address+4) & ~3) + op.mem.disp) & 0xFFFFFFFF
        im = self.image_for(ins.address)
        if not im.contains(cell, 4):
            return (cell, None)
        return cell, im.u32(cell)


def expr_for_mem(base: str, disp: int, idx: str = "") -> str:
    sign = f"+0x{disp:X}" if disp >= 0 else f"-0x{-disp:X}"
    return f"MEM[{base}{sign}{('+'+idx) if idx else ''}]"


def short(expr: str, limit: int = 124):
    return expr if len(expr) <= limit else expr[:limit-3]+"..."


def mem_expr(ins, op, state):
    b = ins.reg_name(op.mem.base) if op.mem.base else "0"
    base = state.get(b, f"UNKNOWN({b})")
    index_reg = ins.reg_name(op.mem.index) if op.mem.index else ""
    idx = state.get(index_reg, f"UNKNOWN({index_reg})") if index_reg else ""
    return expr_for_mem(base, int(op.mem.disp), idx)


def audit_slice(aud: Auditor, name: str, start: int, stop: int):
    insns = aud.linear(start,stop)
    print(f"\n[{name}] 0x{start:08X}..0x{stop:08X} ({len(insns)} decoded instructions)")
    print("  NOTE: linear disassembly for literal/provenance recovery only. Branches do NOT certify reachability.")
    state = {f"r{i}":f"UNKNOWN(entry_r{i})" for i in range(13)}
    state.update({"sp":"UNKNOWN(stack)","lr":"UNKNOWN(link)"})
    have_alias = False
    calls = []
    for ins in insns:
        m = ins.mnemonic.lower().split(".")[0]
        ops = list(ins.operands)
        lit = aud.literal(ins)
        info = ""
        regs = [ins.reg_name(o.reg) if o.type == ARM_OP_REG else None for o in ops]
        dst = regs[0] if regs else None
        # A *single* linear approximation. Conditional branches/IT, unknown
        # instruction side effects and calls can invalidate its state.
        if lit is not None and dst:
            cell, value = lit
            state[dst] = f"0x{value:08X}" if value is not None else "UNKNOWN(literal_outside)"
            info = f"LITERAL cell=0x{cell:08X} value={state[dst]}"
            if value in FOCUS:
                info += f" <{FOCUS[value]}>"
        elif m in ("mov", "movs") and dst and len(ops) >= 2:
            if ops[1].type == ARM_OP_REG:
                state[dst] = state.get(regs[1],"UNKNOWN")
            elif ops[1].type == ARM_OP_IMM:
                state[dst] = f"0x{int(ops[1].imm)&0xFFFFFFFF:08X}"
        elif m in ("ldr", "ldrh", "ldrb", "ldrsh", "ldrsb") and dst and len(ops)>=2 and ops[1].type==ARM_OP_MEM:
            state[dst] = mem_expr(ins,ops[1],state)
            if "0xF004C5AC+0x8" in state[dst] or "0xF004C5AC+0x08" in state[dst]:
                have_alias=True
                info = "DIRECT_WRITER_RECORD_BASE_LOAD (F004C5AC+8)"
            elif "0xF004C5AC+0x0" in state[dst]:
                info = "GLOBAL_FIELD0_LOAD (not record-array pointer)"
            else:
                info = "LOAD="+short(state[dst])
        elif m in ("add","adds","sub","subs") and dst and len(ops)>=2:
            sign = "+" if m in ("add","adds") else "-"
            if len(ops)>=3:
                l = state.get(regs[1],"UNKNOWN") if ops[1].type==ARM_OP_REG else (hex(ops[1].imm) if ops[1].type==ARM_OP_IMM else "UNKNOWN")
                r = state.get(regs[2],"UNKNOWN") if ops[2].type==ARM_OP_REG else (hex(ops[2].imm) if ops[2].type==ARM_OP_IMM else "UNKNOWN")
            else:
                l = state.get(dst,"UNKNOWN")
                r = state.get(regs[1],"UNKNOWN") if ops[1].type==ARM_OP_REG else (hex(ops[1].imm) if ops[1].type==ARM_OP_IMM else "UNKNOWN")
            state[dst] = short(f"({l}{sign}{r})")
        elif m in ("lsl", "lsls") and dst and len(ops)>=2:
            if len(ops)>=3:
                src = state.get(regs[1],"UNKNOWN")
                sh = ops[2].imm if ops[2].type==ARM_OP_IMM else "?"
            else:
                src=state.get(dst,"UNKNOWN")
                sh=ops[1].imm if ops[1].type==ARM_OP_IMM else "?"
            state[dst]=short(f"({src}<<{sh})")
        elif m in ("bl", "blx"):
            if m=="blx" and len(ops)>0 and ops[0].type==ARM_OP_REG:
                source=state.get(regs[0],"UNKNOWN")
                calls.append((ins.address,regs[0],source))
                info=f"INDIRECT_EXECUTE origin={short(source,190)}"
            else:
                info="DIRECT_CALL (r0-r3 clobbered)"
            for reg in ("r0","r1","r2","r3"):
                state[reg]=f"UNKNOWN(call_clobber_at_0x{ins.address:08X})"
        elif m.startswith("str") and len(ops)>1 and ops[1].type==ARM_OP_MEM:
            base=mem_expr(ins,ops[1],state)
            info=f"STORE target={short(base)} value={short(state.get(regs[0], 'UNKNOWN'))}"
        elif m in ("push","pop","ldm","stm","stmia"):
            info="stack/multi-reg: symbolic state may be incomplete"
        elif m in ("cmp", "b", "beq", "bne", "bgt", "blt", "bge", "ble", "bpl", "bmi", "cbz", "cbnz", "it", "tst"):
            if m.startswith("b") or m.startswith("cb") or m=="it":
                info="CONTROL_FLOW: LINEAR SYMBOLIC STATE IS NOT PATH-PROVEN"
        elif dst and m not in ("str","strb","strh","orrs","bics"):
            # Refuse to preserve stale destinations across unimplemented ops.
            if ops[0].type==ARM_OP_REG:
                state[dst]=f"UNKNOWN(unmodeled_{m}_at_{ins.address:08X})"
        focus = ins.address in CALLS
        include = lit is not None or info or focus or (m in ("ldr","ldrh") and "#0x1c" in ins.op_str.lower())
        if include:
            print(f"  0x{ins.address:08X}: {ins.mnemonic:<8} {ins.op_str:<28} {info}")
        if focus:
            print(f"  >>> SINK {CALLS[ins.address]}: {info}")
    if not calls:
        print("  DIRECT/INDIRECT CALLS: no register-indirect BLX in this window")
    else:
        for at,reg,source in calls:
            print(f"  BLX reg @0x{at:08X}: {reg} <- {short(source,190)} (LINEAR/NOT PATH-PROVEN)")
    print(f"  Evidence of literal-base [F004C5AC+8] load in this window = {have_alias}")
    return {"name":name,"have_alias":have_alias,"calls":calls}


def main() -> int:
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--alice",type=Path,default=Path(r".\research\f2\work\extracted\altice_alice\alice-py.bin"))
    ap.add_argument("--zimage",type=Path,default=Path(r".\research\f2\work\extracted\altice_platform\zimage.bin"))
    args=ap.parse_args()
    print("S13.5A.69 — RECORD/DISPATCH ALIAS PROVENANCE AUDIT")
    print("STRICTLY OFFLINE: USB=NO COM=NO PHONE=NO BROM=NO DA=NO WRITE=NO ERASE=NO REPACK=NO")
    print("No binary modifications, no output files; stdout only.")
    banner("A. CANONICAL GUARDS (FAIL CLOSED)")
    alice=guarded(args.alice,"ALICE",ALICE_BASE,ALICE_SIZE,ALICE_SHA)
    zimage=guarded(args.zimage,"ZIMAGE",ZIMAGE_BASE,ZIMAGE_SIZE,ZIMAGE_SHA)
    a=Auditor([alice,zimage])
    banner("B. KNOWN WRITER STORAGE AND SELECTED CANDIDATE SLICES — EXACT LITERAL VALUES")
    results=[]
    for name,start,stop in RANGES:
        results.append(audit_slice(a,name,start,stop))
    banner("C. DISCRIMINATING DECISION")
    print("Writer canonical pointer expression: MEM[0xF004C5AC+0x8] + (index << 5).")
    print("Writer stores: +0x8 <- original r2, +0x10 <- original r1; no action semantics inferred.")
    for key in CALLS:
        hit=[(row['name'],reg,src) for row in results for at,reg,src in row['calls'] if at==key]
        if len(hit)!=1:
            print(f"SINK 0x{key:08X}: INCOMPLETE ({len(hit)} provenance rows); do not promote")
            continue
        name,reg,source=hit[0]
        matches="0xF004C5AC+0x8" in source or "0xF004C5AC+0x08" in source
        print(f"SINK 0x{key:08X}: callback={reg}, linear-origin={source}")
        print(f"  WRITER_BUFFER_ALIAS_IN_LINEAR_SLICE = {'CANDIDATE_ONLY' if matches else 'NOT_DEMONSTRATED'}")
        print("  Neither positive nor negative proves runtime alias: registers may arrive from callers, RAM or branch-dependent paths.")
    print("NEXT DECISION: if a sink loads an independently addressed record buffer, reject it unless exact alias is established via an initializer/pointer map; otherwise pursue actual writer-buffer field-read consumers.")
    print("A.69 is evidence collection, NOT a patch authorization.")
    print("PHONE ACCESSED=NO; FLASH MODIFIED=NO; REPACK=NO; PATCH GENERATED=NO; HARDWARE WRITE AUTHORIZED=NO")
    return 0


if __name__=='__main__':
    raise SystemExit(main())
