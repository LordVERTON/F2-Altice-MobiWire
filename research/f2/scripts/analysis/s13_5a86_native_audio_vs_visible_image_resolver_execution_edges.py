#!/usr/bin/env python3
"""S13.5A.86: image-vs-audio resolver function-pointer use, STRICTLY OFFLINE.

Focus: do any ALICE/ZIMAGE *code* PC-relative loads own the exact callback
pointers for visible Image child 0x87ED and internal Audio app 0x8928?
A registry/data pointer occurrence is NOT an invocation. This analysis does
NOT imply OK/Select, menu exposure, or any phone/firmware mutation.
"""
from __future__ import annotations

import argparse
import hashlib
import struct
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

try:
    from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_LITTLE_ENDIAN, CS_OP_MEM, CS_OP_REG
    from capstone.arm import ARM_REG_PC
except ImportError as e:
    raise SystemExit("Capstone is required in the user's offline Python venv: " + str(e))

IMAGES = {
    "ALICE": (0x1024EC00, 0x157BB4, "7246242b67afae0d13104452bc3257827cb778119b54e7a26fb7fb55993697ea",
              "research/f2/work/extracted/altice_alice/alice-py.bin"),
    "ZIMAGE": (0xF023CA50, 0x185E98, "85fba8c8ae8161e4c1f8ced7983ec30d48c54ab10e51c69fcdfb900aca220954",
               "research/f2/work/extracted/altice_platform/zimage.bin"),
}
TARGETS = {
    "IMAGE_VISIBLE_87ED_REG": 0xF02F3F9D,  # code at F02F3F9C
    "AUDIO_NATIVE_8928_REG": 0x1033D841,  # code at 1033D840
}

@dataclass
class Img:
    name: str
    base: int
    b: bytes

    def own(self, addr: int, n: int = 1) -> bool:
        return self.base <= addr and addr + n <= self.base + len(self.b)

    def section(self, addr: int, n: int) -> bytes:
        if not self.own(addr, n):
            raise ValueError(f"OOB {self.name}: 0x{addr:08X}, length=0x{n:X}")
        st = addr - self.base
        return self.b[st:st+n]


def load(name: str, path: Path) -> Img:
    base, size, sha, _ = IMAGES[name]
    data = path.read_bytes()
    h = hashlib.sha256(data).hexdigest()
    status = "PASS" if len(data) == size and h == sha else "FAIL"
    print(f"{name}: file={path} size=0x{len(data):X} sha256={h} GUARD={status}")
    if status != "PASS":
        raise SystemExit("ABORT — canonical image guard failure. No results promoted.")
    return Img(name, base, data)


def decoded(md: Cs, img: Img, addr: int, n: int = 8):
    if not img.own(addr, 2):
        return []
    maxn = min(n, img.base+len(img.b)-addr)
    if maxn < 2:
        return []
    return list(md.disasm(img.section(addr, maxn), addr, count=1))


def pc_literal_cell(ins) -> Optional[int]:
    if not ins.mnemonic.startswith("ldr") or len(ins.operands) < 2:
        return None
    m = ins.operands[1]
    if m.type != CS_OP_MEM or m.mem.base != ARM_REG_PC:
        return None
    return (((ins.address + 4) & ~3) + m.mem.disp) & 0xFFFFFFFF


def reg_str(ins, idx: int = 0) -> str:
    return ins.reg_name(ins.operands[idx].reg) if len(ins.operands) > idx and ins.operands[idx].type == CS_OP_REG else "?"


def owners(md: Cs, img: Img, cell: int, bound: int = 0x1200):
    start = max(img.base, (cell - bound) & ~1)
    out = []
    for a in range(start, cell, 2):
        di = decoded(md, img, a, 4)
        if di and pc_literal_cell(di[0]) == cell:
            out.append(di[0])
    return out


def preview(md: Cs, img: Img, addr: int, cap: int = 16):
    if not img.own(addr, 2):
        return
    a = addr
    for _ in range(cap):
        li = decoded(md, img, a, 4)
        if not li:
            break
        ins = li[0]
        more = ""
        pc_cell = pc_literal_cell(ins)
        if pc_cell is not None and img.own(pc_cell, 4):
            val = struct.unpack("<I", img.section(pc_cell, 4))[0]
            more = f" ; PC_CELL=0x{pc_cell:08X} VALUE=0x{val:08X}"
        print(f"    0x{ins.address:08X} {ins.mnemonic:<8} {ins.op_str:<34} bytes={ins.bytes.hex(' ')}{more}")
        a += ins.size
        if ins.mnemonic in {"bx", "pop", "b"} and (ins.mnemonic != "pop" or "pc" in ins.op_str):
            break


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--alice", type=Path, default=Path(IMAGES["ALICE"][3]))
    parser.add_argument("--zimage", type=Path, default=Path(IMAGES["ZIMAGE"][3]))
    a = parser.parse_args()
    print("S13.5A.86 - RESOLVER POINTER EXECUTION-EDGE DIFFERENTIAL")
    print("STRICTLY OFFLINE READ ONLY. NO USB/COM/PHONE/FLASH/ERASE/WRITE/PATCH/REPACK.")
    imgs = [load("ALICE", a.alice), load("ZIMAGE", a.zimage)]
    md = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_LITTLE_ENDIAN)
    md.detail = True

    print("\n[A] STATIC PTR OCCURRENCES VS VERIFIED PC-RELATIVE CODE OWNERS")
    for label, ptr in TARGETS.items():
        print(f"\n{label}: u32 pointer=0x{ptr:08X} entry=0x{ptr & ~1:08X}")
        needle = struct.pack('<I', ptr)
        for img in imgs:
            cells, start = [], 0
            while True:
                idx = img.b.find(needle, start)
                if idx < 0:
                    break
                # byte-aligned results retained, PC-LDR only meaningful for u32-aligned pool cell
                cells.append(img.base+idx)
                start = idx+1
            cells = sorted(cells)
            print(f"  {img.name}: RAW_U32_OCCURRENCES={len(cells)}"
                  f" ALIGNED={sum(x % 4 == 0 for x in cells)}")
            if len(cells) > 120:
                print("  FAIL-CLOSED: >120 occurrences; first 120 only, incomplete coverage.")
            for cell in cells[:120]:
                if cell & 3:
                    print(f"    CELL=0x{cell:08X} unaligned; DATA/embedded candidate, not PC-LDR owner")
                    continue
                hit = owners(md, img, cell)
                print(f"    CELL=0x{cell:08X} verified_PC_LDR_OWNERS={len(hit)}")
                for ins in hit[:6]:
                    print(f"      OWNER 0x{ins.address:08X} {ins.mnemonic} {ins.op_str} -> 0x{cell:08X}")
                    preview(md, img, ins.address, cap=8)
                if len(hit) > 6:
                    print(f"      OWNER_CAPPED={len(hit)-6} (no runtime/activation claim)")

    print("\n[B] KNOWN REGISTRATION STUB BODY PREVIEW — CONTROL DIFFERENTIAL ONLY")
    for label, ptr in TARGETS.items():
        entry = ptr & ~1
        for img in imgs:
            if img.own(entry, 2):
                print(f"  {label} entry=0x{entry:08X} in {img.name}")
                preview(md, img, entry, cap=18)

    print("\n[C] RESULT GATE")
    print("STATIC_SCAN_COMPLETE_ONLY_WHERE_NOT_CAPPED=YES")
    print("LITERAL_OWNER_NOT_EQUAL_RUNTIME_INVOKER=YES")
    print("NO_MENU_OK_OR_AUDIO_LAUNCH_PROOF=YES")
    print("NEXT: use any proven loading/dispatch pattern to identify generic selected-menu->app-resolver activation, not app registration again.")
    print("NO_PHONE_ACCESS=YES NO_FIRMWARE_MODIFIED=YES NO_WRITE_AUTHORIZED=YES")


if __name__ == "__main__":
    main()
