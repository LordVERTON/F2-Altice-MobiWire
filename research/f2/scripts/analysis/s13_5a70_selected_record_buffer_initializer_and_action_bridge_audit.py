#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""S13.5A.70 — selected-record / buffer initializer / callback-base audit.

STRICTLY OFFLINE, read only canonical SHA-guarded ALICE and ZIMAGE.
QUESTION A: Is [0xF004C5B4], the actual 0x20-byte item-writer buffer,
            initialized to the ZIMAGE callback record table 0xF00B9A30?
QUESTION B: Which selected-item value is written into the real buffer +0x10
            by ZIMAGE F0319150, and which bounded consumers read this field?

Focused search ONLY for four already-proven exact global address constants.
Never treat a shared stride or co-occurring literal as pointer alias proof.
No telephone access, USB/COM, BROM/DA, writes, patching, repacking or erase.
"""
from __future__ import annotations

import argparse
import hashlib
import struct
from dataclasses import dataclass
from pathlib import Path
from collections import defaultdict

try:
    from capstone import Cs, CS_ARCH_ARM, CS_MODE_LITTLE_ENDIAN, CS_MODE_THUMB
    from capstone.arm import ARM_OP_MEM, ARM_OP_REG, ARM_REG_PC
except ImportError as exc:
    raise SystemExit(f"ABORT: capstone not installed in canonical venv: {exc}")

ALICE_BASE = 0x1024EC00
ALICE_SIZE = 0x157BB4
ALICE_SHA = "7246242b67afae0d13104452bc3257827cb778119b54e7a26fb7fb55993697ea"
ZIMAGE_BASE = 0xF023CA50
ZIMAGE_SIZE = 0x185E98
ZIMAGE_SHA = "85fba8c8ae8161e4c1f8ced7983ec30d48c54ab10e51c69fcdfb900aca220954"
WRITER_GLOBAL = 0xF004C5AC
WRITER_PTR_SLOT = WRITER_GLOBAL + 8  # [F004C5B4]
DISPATCH_TABLE = 0xF00B9A30
SELECTION_GLOBAL = 0xF004C5CC

# Every target has prior direct evidence, no broad ID/callback scan.
ANCHORS = (
    (WRITER_GLOBAL, "writer-struct base: ptr in +8; funcs in +0,+4"),
    (WRITER_PTR_SLOT, "literal direct address of writer record pointer slot"),
    (DISPATCH_TABLE, "ZIMAGE separate/static 0x20-stride BLX callback table"),
    (SELECTION_GLOBAL, "ZIMAGE selection context: +0x18 index"),
)

# No guesswork about whether these are function boundaries; bounded exact addresses.
WINDOWS = (
    ("ALICE pointer-map construction", 0x103139EA, 0x10313A18),
    ("ALICE original record writer", 0x10316834, 0x10316878),
    ("ALICE alternate writer", 0x1034E3D6, 0x1034E40C),
    ("ZIMAGE selected record +0x10 update", 0xF031910E, 0xF031915A),
    ("ZIMAGE static callback A", 0xF030C052, 0xF030C0A6),
    ("ZIMAGE static callback B", 0xF0312F96, 0xF0312FD8),
)


def banner(s: str) -> None:
    print("\n" + "=" * 104 + "\n" + s + "\n" + "=" * 104)


@dataclass(frozen=True)
class Image:
    name: str
    base: int
    data: bytes

    def contains(self, address: int, size: int = 1) -> bool:
        return self.base <= address and address + size <= self.base + len(self.data)

    def u32(self, address: int) -> int:
        if not self.contains(address, 4):
            raise ValueError(f"{self.name}: invalid U32 0x{address:08X}")
        return struct.unpack_from("<I", self.data, address-self.base)[0]

    def slice(self, address: int, size: int) -> bytes:
        if not self.contains(address,size):
            raise ValueError(f"{self.name}: invalid code 0x{address:08X}+0x{size:X}")
        off = address-self.base
        return self.data[off:off+size]


def guarded(path: Path, name: str, base: int, size: int, sha: str) -> Image:
    if not path.is_file():
        raise SystemExit(f"ABORT: missing canonical {name}: {path}")
    b = path.read_bytes()
    actual = hashlib.sha256(b).hexdigest()
    good = len(b) == size and actual == sha
    print(f"{name}: size=0x{len(b):X} sha256={actual} GUARD={'PASS' if good else 'FAIL'} path={path}")
    if not good:
        raise SystemExit("ABORT: wrong/noncanonical input; no audit started")
    return Image(name,base,b)


class Audit:
    def __init__(self, images: list[Image]):
        self.images = images
        self.md = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_LITTLE_ENDIAN)
        self.md.detail = True

    def image(self, addr: int) -> Image:
        for im in self.images:
            if im.contains(addr,2):
                return im
        raise ValueError(f"invalid code addr 0x{addr:08X}")

    def one(self, addr: int):
        im = self.image(addr)
        block = im.slice(addr,min(4,im.base+len(im.data)-addr))
        return next(iter(self.md.disasm(block,addr,count=1)),None)

    def literal(self, ins):
        if not ins.mnemonic.lower().startswith("ldr") or len(ins.operands) < 2:
            return None
        op = ins.operands[1]
        if op.type != ARM_OP_MEM or op.mem.base != ARM_REG_PC:
            return None
        cell = (((ins.address+4) & ~3) + op.mem.disp) & 0xFFFFFFFF
        im = self.image(ins.address)
        return (cell,im.u32(cell) if im.contains(cell,4) else None)

    def exact_literal_sites(self, im: Image, cell: int) -> list[int]:
        """Decode only LDR-literal encodings; no blind decode of arbitrary data."""
        first = max(im.base,cell-4096-4)
        last = min(im.base+len(im.data)-2, cell+4096+4)  # Thumb-2 negative PC-relative offsets too
        sites=[]
        for address in range((first+1)&~1, last+1, 2):
            if not im.contains(address,2):
                continue
            h = struct.unpack_from("<H",im.data,address-im.base)[0]
            # Thumb-1 LDR Rt,[PC,#imm] or Thumb-2 LDR.W Rt,[PC,+/-imm].
            if (h & 0xF800) != 0x4800 and h not in (0xF8DF,0xF85F):
                continue
            ins=self.one(address)
            if ins is None or not im.contains(address,ins.size):
                continue
            lit=self.literal(ins)
            if lit and lit[0]==cell:
                sites.append(address)
        return sorted(set(sites))

    def exact_refs(self, constant: int, max_cells: int = 80) -> tuple[int,list[tuple[str,int,int]],bool]:
        pattern=struct.pack("<I",constant)
        raw=[]
        for im in self.images:
            start=0
            while True:
                index=im.data.find(pattern,start)
                if index<0:
                    break
                raw.append((im, im.base+index))
                start=index+1
        refs=[]
        for im,cell in raw[:max_cells]:
            for site in self.exact_literal_sites(im,cell):
                refs.append((im.name,site,cell))
        return len(raw),sorted(set(refs),key=lambda x:(x[0],x[1])),len(raw)>max_cells

    def linear(self,start:int,stop:int):
        if stop-start > 0x180 or start>=stop or start%2 or stop%2:
            raise ValueError("ABORT: improper bounded window")
        p=start
        while p<stop:
            ins=self.one(p)
            if ins is None or ins.size not in (2,4):
                print(f"  DECODE_STOP at 0x{p:08X}")
                break
            if p+ins.size>stop:
                break
            yield ins
            p+=ins.size


def compact_instr(ins, aud:Audit):
    lit=aud.literal(ins)
    suffix=""
    if lit:
        cell,value=lit
        suffix=f" ; PC-cell=0x{cell:08X} U32={f'0x{value:08X}' if value is not None else 'outside'}"
    return f"0x{ins.address:08X}: {ins.mnemonic:<8} {ins.op_str:<33}{suffix}"


def show_known(aud: Audit):
    banner("B. ACTUAL KNOWN SOURCE AND SELECTED-INDEX SLICES (LITERAL-ANNOTATED)")
    for label,start,stop in WINDOWS:
        print(f"\n[{label}] 0x{start:08X}..0x{stop:08X}")
        for ins in aud.linear(start,stop):
            print("  "+compact_instr(ins,aud))
    banner("C. PRECISE, PRIOR-GROUNDED BUFFER AND DISPATCH EXPRESSIONS")
    print("ALICE writer storage: PTR=MEM[0xF004C5B4] (source in 10316834; NOT the value 0xF004C5B4 itself)")
    print("ALICE record address: PTR + (writer_index << 5); ALICE writer stores r2 at +0x08 and r1 at +0x10")
    print("ZIMAGE F0319150: MEM[PTR + (MEM[0xF004C5CC+0x18]<<5) + 0x10] = value from selected-index dword lookup")
    print("  lookup source: a structure rooted at MEM[0xF00B97F8+0x5C]; its +0xC table is indexed using +0x8 index handle")
    print("  SOURCE ID/PURPOSE NOT KNOWN; this is a concrete selected-index connection to the writer's buffer.")
    print("ZIMAGE F030C0A0 / F0312FD2: BLX MEM[0xF00B9A30 + (MEM[0xF004C5CC+0x18]<<5) + 0x1C]")
    print("  A.69 proves static callback-table addressing, NOT equal pointer value to MEM[0xF004C5B4].")
    print("ALICE 103139F4..10313A14: 64-pointer map at (F00B81A0 - 0x100)=F00B80A0")
    print("  map[i]=MEM[0xF004C5B4]+(i<<5) for i=0..0x3F; separate pointer map, not evidence of callback alias.")


def classify_site(aud:Audit,site:int,anchor:int,max_bytes:int=0x64) -> tuple[int,int,list[str]]:
    """Print only dataflow-relevant uses after exact PC LDR, not generic xrefs.

    Heuristic evidence and NOT a proof that a store is reachable or an alias.
    The anchor-bearing register is killed if overwritten; calls kill r0..r3.
    """
    im=aud.image(site)
    instruction=aud.one(site)
    if instruction is None or not instruction.operands or instruction.operands[0].type!=ARM_OP_REG:
        return 0,0,[]
    tracked = {instruction.reg_name(instruction.operands[0].reg)}
    uses=[]
    ptr_reads=0
    ptr_stores=0
    cursor=site+instruction.size
    end=min(site+max_bytes,im.base+len(im.data))
    while cursor+2<=end:
        ins=aud.one(cursor)
        if ins is None:
            break
        opcode=ins.mnemonic.lower().split(".")[0]
        ops=ins.operands
        if opcode in ("ldr","str","ldrb","strb","ldrh","strh") and len(ops)>1 and ops[1].type==ARM_OP_MEM:
            mem=ops[1].mem
            base=ins.reg_name(mem.base)
            idx=ins.reg_name(mem.index) if mem.index else ""
            if base in tracked:
                label="PTR_SLOT +8" if anchor==WRITER_GLOBAL and mem.disp==8 else ""
                if anchor==WRITER_PTR_SLOT and mem.disp==0:
                    label="PTR_SLOT direct"
                if anchor==DISPATCH_TABLE:
                    label="DISPATCH_TABLE read/write"
                kind="STORE" if opcode.startswith("str") else "LOAD"
                uses.append(f"0x{cursor:08X} {ins.mnemonic:<6} {ins.op_str:<25} {kind} from constant 0x{anchor:08X}{' '+label if label else ''}")
                if label.startswith("PTR_SLOT"):
                    if kind=="STORE": ptr_stores+=1
                    else: ptr_reads+=1
            elif idx in tracked:
                uses.append(f"0x{cursor:08X} {ins.mnemonic} {ins.op_str} INDEXED by 0x{anchor:08X} register (candidate only)")
        # Stop before a branch to another basic block; falls-through after BL is still relevant.
        if opcode in ("b","bx","pop","cbz","cbnz") or (opcode.startswith("b") and opcode not in ("bl","blx","bic","bics")):
            break
        if opcode in ("bl","blx"):
            tracked.difference_update(("r0","r1","r2","r3"))
        # Simple register copy propagation, before invalidating its destination.
        dst = ins.reg_name(ops[0].reg) if ops and ops[0].type==ARM_OP_REG else None
        if opcode in ("mov","movs") and dst and len(ops)>1 and ops[1].type==ARM_OP_REG:
            src=ins.reg_name(ops[1].reg)
            copy=src in tracked
            tracked.discard(dst)
            if copy:
                tracked.add(dst)
        elif dst and opcode in ("ldr","ldrb","ldrh","movw","movt","add","adds","sub","subs","lsl","lsls","lsr","lsrs","orr","orrs","and","ands","eor","eors","mul","muls"):
            tracked.discard(dst)
        if not tracked:
            break
        cursor+=ins.size
    return ptr_reads,ptr_stores,uses


def main() -> int:
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--alice",type=Path,default=Path(r".\research\f2\work\extracted\altice_alice\alice-py.bin"))
    parser.add_argument("--zimage",type=Path,default=Path(r".\research\f2\work\extracted\altice_platform\zimage.bin"))
    args=parser.parse_args()
    print("S13.5A.70 — SELECTED RECORD BUFFER INITIALIZER AND ACTION BRIDGE AUDIT")
    print("STRICTLY OFFLINE: USB=NO COM=NO PHONE=NO BROM=NO DA=NO WRITE=NO ERASE=NO REPACK=NO")
    print("No code/binary modification; stdout only.")
    banner("A. CANONICAL BYTE GUARDS — FAIL CLOSED")
    alice=guarded(args.alice,"ALICE",ALICE_BASE,ALICE_SIZE,ALICE_SHA)
    zimage=guarded(args.zimage,"ZIMAGE",ZIMAGE_BASE,ZIMAGE_SIZE,ZIMAGE_SHA)
    aud=Audit([alice,zimage])
    show_known(aud)
    banner("D. FOUR EXACT-ADDRESS ANCHOR XREFS — BOUNDED, NO GENERAL CENSUS")
    candidates=[]
    for addr,label in ANCHORS:
        n,refs,truncated=aud.exact_refs(addr,max_cells=80)
        print(f"\nANCHOR 0x{addr:08X} — {label}")
        print(f"  raw U32 cells={n}; validated Thumb PC-relative LDR sites={len(refs)}; cells_truncated={truncated}")
        for name,site,cell in refs[:60]:
            nr,nw,usage=classify_site(aud,site,addr,max_bytes=0x64)
            if nw or nr:
                candidates.append((addr,name,site,nr,nw))
            print(f"  {name} LOAD 0x{site:08X} <- U32-cell 0x{cell:08X}; PTR_SLOT_READ={nr} PTR_SLOT_WRITE={nw}")
            for line in usage[:15]:
                print("      "+line)
            if len(usage)>15:
                print(f"      ... {len(usage)-15} more focused uses omitted")
        if len(refs)>60:
            print(f"  BOUNDED: {len(refs)-60} exact reader sites not displayed")
    banner("E. DISCRIMINATING EVIDENCE / NEXT GATE")
    print("Pointer slot address = 0xF004C5B4; its runtime CONTENT is the writer record base.")
    print("Known separate immediate callback table base = 0xF00B9A30; no equality can be inferred from this fact alone.")
    print("A validated ALIAS needs exact dataflow proving MEM[0xF004C5B4] == 0xF00B9A30 (or an established runtime equivalent).")
    print("Relevant pointer-slot readers/writers suggested by bounded PC-literal scan:")
    for anchor,name,site,nr,nw in candidates:
        print(f"  const=0x{anchor:08X} {name} site=0x{site:08X} candidate_ptrslot_reads={nr} writes={nw}")
    if not candidates:
        print("  None in the bounded literal-load windows. Alias remains UNKNOWN, not disproven.")
    print("F0319150 selected index -> canonical buffer +0x10 is directly observed by instruction provenance;")
    print("the source's application-ID/callback meaning and any 0x8928 exposure remain unproven.")
    print("No patch authorization from A.70 by itself. Next step must address one proved missing dataflow link.")
    print("PHONE ACCESSED=NO; FLASH MODIFIED=NO; REPACK=NO; PATCH GENERATED=NO; HARDWARE WRITE AUTHORIZED=NO")
    return 0


if __name__=="__main__":
    raise SystemExit(main())
