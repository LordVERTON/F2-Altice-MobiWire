#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""S13.5A.68 — visible item record / selected item consumer audit.

Read-only canonical ALICE and ZIMAGE static analysis. No imports from mtkclient,
no USB/COM/BROM/DA, no phone access, no patch, no firmware output.

This is a *discovery* gate. Literal xrefs and nearby BLX are reported as candidates,
never promoted to an actual menu/action relation without a real dataflow trace.
"""
from __future__ import annotations

import argparse
import hashlib
import struct
from collections import defaultdict, deque
from dataclasses import dataclass
from pathlib import Path

try:
    from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_LITTLE_ENDIAN
    from capstone.arm import ARM_OP_IMM, ARM_OP_MEM, ARM_OP_REG, ARM_REG_PC
except ImportError as exc:
    raise SystemExit("ABORT: capstone is required in the canonical project venv: " + str(exc))

TITLE = "S13.5A.68 — VISIBLE ITEM RECORD SELECTION CONSUMER AUDIT"
ALICE_BASE, ALICE_SIZE = 0x1024EC00, 0x157BB4
ALICE_SHA = "7246242b67afae0d13104452bc3257827cb778119b54e7a26fb7fb55993697ea"
ZIMAGE_BASE, ZIMAGE_SIZE = 0xF023CA50, 0x185E98
ZIMAGE_SHA = "85fba8c8ae8161e4c1f8ced7983ec30d48c54ab10e51c69fcdfb900aca220954"
ITEM_WRITER = 0x10316834
OWNER_FAMILIES = (0x10306034, 0x103647C4, 0x10392D6C)
KNOWN_AUDIO = (0x1033D840, 0x1033E815, 0x1033F83C, 0x10336788)
RECORD_STRIDE = 0x20
MAX_ANCHORS = 10
MAX_XREFS_PER_ANCHOR = 24


def banner(t):
    print("\n" + "=" * 98)
    print(t)
    print("=" * 98)


@dataclass(frozen=True)
class Image:
    name: str
    base: int
    raw: bytes

    @property
    def end(self):
        return self.base + len(self.raw)

    def contains(self, addr, size=1):
        return self.base <= addr and addr + size <= self.end

    def data_at(self, addr, size):
        if not self.contains(addr, size):
            raise ValueError(f"Out-of-bounds {self.name}: {addr:#x}+{size:#x}")
        return self.raw[addr-self.base:addr-self.base+size]

    def u32(self, addr):
        return struct.unpack("<I", self.data_at(addr, 4))[0]


class Audit:
    def __init__(self, images):
        self.images = images
        self.cs = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_LITTLE_ENDIAN)
        self.cs.detail = True
        self.decode_cache = {}
        self.cfg_cache = {}

    def img(self, addr):
        return next((im for im in self.images if im.contains(addr, 2)), None)

    def decode(self, addr):
        addr &= ~1
        if addr in self.decode_cache:
            return self.decode_cache[addr]
        im = self.img(addr)
        if not im:
            self.decode_cache[addr] = None
            return None
        bs = im.data_at(addr, min(4, im.end-addr))
        ins = next(iter(self.cs.disasm(bs, addr, count=1)), None)
        self.decode_cache[addr] = ins
        return ins

    @staticmethod
    def call_target(ins):
        if ins.mnemonic.lower().split('.')[0] not in {"bl", "blx"}:
            return None
        if not ins.operands or ins.operands[0].type != ARM_OP_IMM:
            return None
        return int(ins.operands[0].imm) & 0xFFFFFFFE

    @staticmethod
    def is_indirect_call(ins):
        return ins.mnemonic.lower().startswith("blx") and bool(ins.operands) and ins.operands[0].type == ARM_OP_REG

    @staticmethod
    def pc_literal(ins):
        m = ins.mnemonic.lower()
        if not m.startswith("ldr") or len(ins.operands) < 2:
            return None
        op = ins.operands[1]
        if op.type != ARM_OP_MEM or op.mem.base != ARM_REG_PC:
            return None
        pc = (ins.address + 4) & ~3
        return (pc + int(op.mem.disp)) & 0xFFFFFFFF

    @staticmethod
    def is_return(ins):
        s = ins.mnemonic.lower()
        op = ins.op_str.lower()
        return (s == "bx" and op == "lr") or (s.startswith("pop") and "pc" in op) or (s == "mov" and op.startswith("pc, lr"))

    def flow_successors(self, ins):
        m = ins.mnemonic.lower().split('.')[0]
        fallthrough = ins.address + ins.size
        if self.is_return(ins):
            return []
        if m in {"bl", "blx"}:
            return [fallthrough]
        if m == "bx" or m in {"tbb", "tbh", "udf", "bkpt"}:
            return []
        if m.startswith("b") and m not in {"bic", "bfi", "bfc"}:
            imm = [o.imm & 0xFFFFFFFE for o in ins.operands if o.type == ARM_OP_IMM]
            if m == "b":
                return imm[-1:]  # unconditional
            if m in {"cbz", "cbnz"}:
                return [fallthrough] + imm[-1:]
            return [fallthrough] + imm[-1:]
        if m in {"cbz", "cbnz"}:
            imm = [o.imm & 0xFFFFFFFE for o in ins.operands if o.type == ARM_OP_IMM]
            return [fallthrough] + imm[-1:]
        # ldr pc, [...] / mov pc, [...] are transfers, not linear flow
        if (m.startswith("ldr") or m.startswith("mov")) and ins.op_str.lower().startswith("pc,"):
            return []
        return [fallthrough]

    def cfg(self, entry, span=0x900, max_ins=1900):
        entry &= ~1
        key = (entry, span, max_ins)
        if key in self.cfg_cache:
            return self.cfg_cache[key]
        im = self.img(entry)
        if not im:
            return {}, True
        queue = deque([entry]); visited = {}; truncated = False
        lo = max(im.base, entry-0x20); hi = min(im.end, entry+span)
        while queue and len(visited) < max_ins:
            addr = queue.popleft()
            if addr in visited:
                continue
            if not lo <= addr < hi:
                truncated = True
                continue
            ins = self.decode(addr)
            if ins is None:
                truncated = True
                continue
            visited[addr] = ins
            for target in self.flow_successors(ins):
                if target not in visited:
                    queue.append(target)
        if queue:
            truncated = True
        self.cfg_cache[key] = (visited, truncated)
        return visited, truncated

    def literals(self, cfg):
        rows = []
        for addr, ins in sorted(cfg.items()):
            cell = self.pc_literal(ins)
            if cell is None:
                continue
            im = self.img(cell)
            if im and im.contains(cell, 4):
                rows.append((addr, cell, im.u32(cell)))
        return rows

    def print_cfg(self, entry, span, max_lines=220):
        cfg, trunc = self.cfg(entry, span=span)
        print(f"\nFUNCTION 0x{entry:08X} | reachable={len(cfg)} | truncated={trunc} | span=0x{span:X}")
        lit = {at: (cell, value) for at, cell, value in self.literals(cfg)}
        print(f"  PC-relative literals: {len(lit)}")
        for n, (addr, ins) in enumerate(sorted(cfg.items())):
            if n >= max_lines:
                print(f"  ... PRINT CAP {max_lines} reached; report is not complete CFG text")
                break
            extra = ""
            if addr in lit:
                cell, value = lit[addr]
                extra = f" ; literal@0x{cell:08X}=0x{value:08X}"
            target = self.call_target(ins)
            if target is not None:
                extra += f" ; direct-call=0x{target:08X}"
            if self.is_indirect_call(ins):
                extra += " ; INDIRECT CALL: register provenance REQUIRED"
            if ins.mnemonic.lower().startswith(("str", "stm", "stmia")):
                extra += " ; STORE (check index/record-base provenance)"
            if "#0x20" in ins.op_str.lower() or "#5" in ins.op_str.lower() and ins.mnemonic.lower().startswith("lsl"):
                extra += " ; POSSIBLE 0x20-byte stride fingerprint (not proof)"
            print(f"  0x{addr:08X}: {ins.mnemonic:<9} {ins.op_str}{extra}")
        return cfg, trunc

    def raw_u32_occurrences(self, value):
        needle = struct.pack("<I", value)
        for im in self.images:
            pos = 0
            while True:
                off = im.raw.find(needle, pos)
                if off == -1:
                    break
                yield im, im.base + off
                pos = off+1

    def confirm_literal_load_sites(self, im, cell, max_sites=12):
        """Find exact PC-relative LDRs reaching THIS cell; no claim of CFG reachability."""
        hits = []
        # For Thumb-1 and Thumb-2 LDR literal max positive range 4KB.
        # Bounded to same image; bounded number of candidates per exact cell.
        start = max(im.base, cell-0x1004)
        for at in range((start+1)&~1, cell, 2):
            ins = self.decode(at)
            if ins is not None and self.pc_literal(ins) == cell:
                hits.append(at)
                if len(hits) >= max_sites:
                    break
        return hits

    def show_window(self, at, n_before=12, n_after=26):
        """Heuristic linear decode context, NOT an independently verified function boundary."""
        im = self.img(at)
        if not im:
            return
        lo = max(im.base, at-n_before*2)
        hi = min(im.end, at+n_after*4)
        # Scan possible Thumb aligned entry positions near the xref; choose a path
        # that decodes across the anchor. False-positive contexts are possible.
        options = []
        for candidate in range(lo, min(at+1,lo+10),2):
            decoded = list(self.cs.disasm(im.data_at(candidate, hi-candidate),candidate))
            if any(ins.address == at for ins in decoded):
                options.append(decoded)
        ds = min(options,key=len) if options else [self.decode(at)]
        ds = [i for i in ds if i is not None and at-0x30 <= i.address <= at+0x70]
        for ins in ds[:38]:
            flag = " <== LITERAL LOAD" if ins.address == at else ""
            if self.is_indirect_call(ins):
                flag += " [INDIRECT BLX CANDIDATE]"
            t = self.call_target(ins)
            if t in KNOWN_AUDIO:
                flag += " [AUDIO KNOWN TARGET]"
            if ins.mnemonic.lower().startswith("str"):
                flag += " [STORE]"
            if ins.mnemonic.lower().startswith("ldr") and self.pc_literal(ins) is None:
                flag += " [DEREF]"
            print(f"      0x{ins.address:08X}: {ins.mnemonic:<9} {ins.op_str}{flag}")


def load_checked(path, name, base, expected_size, expected_sha):
    if not path.is_file():
        raise SystemExit(f"ABORT: missing {name}: {path}")
    raw = path.read_bytes()
    checksum = hashlib.sha256(raw).hexdigest()
    correct = len(raw) == expected_size and checksum.lower() == expected_sha.lower()
    print(f"{name}: {path}\n  size=0x{len(raw):X} expected=0x{expected_size:X}"
          f"\n  sha256={checksum}\n  canonical-guard={'PASS' if correct else 'FAIL'}")
    if not correct:
        raise SystemExit("ABORT: NON-CANONICAL INPUT; no analysis carried out")
    return Image(name, base, raw)


def main():
    parser = argparse.ArgumentParser(description=TITLE)
    parser.add_argument("--alice", type=Path,
        default=Path(r".\research\f2\work\extracted\altice_alice\alice-py.bin"))
    parser.add_argument("--zimage", type=Path,
        default=Path(r".\research\f2\work\extracted\altice_platform\zimage.bin"))
    args = parser.parse_args()
    print(TITLE)
    print("STRICTLY OFFLINE: USB=NO COM=NO PHONE=NO BROM=NO DA=NO FLASH_WRITE=NO ERASE=NO REPACK=NO")
    print("No code or binary modification. Script writes NOTHING: stdout is the report.")
    banner("A. CANONICAL BYTE-GUARDED INPUTS")
    alice = load_checked(args.alice, "ALICE", ALICE_BASE, ALICE_SIZE, ALICE_SHA)
    zimage = load_checked(args.zimage, "ZIMAGE", ZIMAGE_BASE, ZIMAGE_SIZE, ZIMAGE_SHA)
    auditor = Audit([alice,zimage])

    banner("B. LOW-LEVEL VISIBLE-ITEM RECORD WRITER — EXACT REACHABLE INSTRUCTIONS")
    writer_cfg, writer_trunc = auditor.print_cfg(ITEM_WRITER, span=0x500, max_lines=180)
    print("EXPECTED STRUCTURAL RECORD STRIDE: 0x20 (established before A.68)")
    print("The actual record-base/address and individual +offset field semantics are NOT pre-assumed.")
    if len(writer_cfg) < 3:
        raise SystemExit("ABORT: unexpected empty/wrong writer decode")

    banner("C. THREE ESTABLISHED DIRECT OWNER FAMILIES — WRITER CALLSITE AND ARGUMENT CONTEXT")
    all_cfg = {}
    all_cfg[ITEM_WRITER] = writer_cfg
    for owner in OWNER_FAMILIES:
        maxspan = 0xA00 if owner != 0x103647C4 else 0x1200
        cfg, trunc = auditor.print_cfg(owner, span=maxspan, max_lines=220)
        all_cfg[owner] = cfg
        sites = [x for x,ins in sorted(cfg.items()) if auditor.call_target(ins) == ITEM_WRITER]
        print(f"  ACTUAL DIRECT CALLS TO ITEM_WRITER FROM 0x{owner:08X}: {[hex(x) for x in sites]}")
        if not sites:
            print("  WARNING: no call proven in bounded CFG; adjust function boundary only after review")
        else:
            for site in sites[:4]:
                nearby = [(a,i) for a,i in sorted(cfg.items()) if site-0x32 <= a <= site+0x16]
                print(f"  --- caller argument-producing neighborhood around 0x{site:08X} ---")
                for a,i in nearby:
                    print(f"    0x{a:08X}: {i.mnemonic:<9} {i.op_str}")

    banner("D. DERIVE *CANDIDATE* GLOBAL BASES FROM THE WRITER, THEN ITS EXACT CALLER FAMILIES")
    # Avoid arbitrary F00960A0/F009607C layout state. Only anchors actually
    # read as literal pointers inside the audited record-writer path.
    anchors = defaultdict(list)
    for owner, cfg in all_cfg.items():
        for site, cell, value in auditor.literals(cfg):
            if 0xF0000000 <= value < 0xF0200000:
                anchors[value].append((owner,site,cell))
    print("All read-as-literal RAM/global pointer candidates (not proven record bases):")
    for val, origins in sorted(anchors.items()):
        print(f"  0x{val:08X} <- " + ", ".join(f"0x{f:08X}:0x{site:08X}" for f,site,_ in origins[:7]))
    print("Anchors starting in F00960xx (A.64–A.67 layout path) are excluded from this action hunt.")
    # Strong ordering: writer-owned first; then each number of callsites.
    candidates = [v for v in anchors if not 0xF0096000 <= v <= 0xF00960FF]
    candidates.sort(key=lambda v: (not any(f==ITEM_WRITER for f,_,_ in anchors[v]),-len(anchors[v]),v))
    selected = candidates[:MAX_ANCHORS]
    if len(candidates) > MAX_ANCHORS:
        print(f"NOTE: bounded to {MAX_ANCHORS} derived global anchors of {len(candidates)}; other candidates listed above.")
    if not selected:
        print("No independent RAM-base literal in the bounded writer CFG. This is a meaningful negative result.")
        print("Do NOT infer that the old layout table is the action table. Use the callsite argument provenance in C.")

    banner("E. EXACT-LITERAL LOAD READERS — RESTRICTED TO WRITER-DERIVED BASES")
    print("Entries below are static xref candidates. Instruction decode != executable reachability.")
    print("A consumer needs a witnessed selected index + record stride + field load + activation hand-off.")
    confirmed_sites = []
    builder_reachable = set().union(*(set(cfg.keys()) for cfg in all_cfg.values()))
    for val in selected:
        print(f"\nANCHOR GLOBAL 0x{val:08X} FROM " + ",".join(f"0x{f:08X}" for f,_,_ in anchors[val]))
        places = list(auditor.raw_u32_occurrences(val))
        print(f"  raw U32 literal-cell candidates = {len(places)}")
        if len(places) > MAX_XREFS_PER_ANCHOR:
            print(f"  BOUNDED: showing at most {MAX_XREFS_PER_ANCHOR} raw cells; this anchor may be ambiguous")
        for im, cell in places[:MAX_XREFS_PER_ANCHOR]:
            sites = auditor.confirm_literal_load_sites(im,cell,max_sites=8)
            print(f"  {im.name} literal-cell 0x{cell:08X}: exact PC-LDR sites={len(sites)}"
                  + (" (cap 8)" if len(sites)==8 else ""))
            for site in sites[:5]:
                print(f"    candidate exact LDR at 0x{site:08X}")
                if site not in builder_reachable:
                    confirmed_sites.append((val,im,site))
                else:
                    print("      owner/writer-local site: excluded from NEW reader shortlist")
    banner("F. NEW NON-WRITER READER CANDIDATES — FIELD/INDEX/ACTIVATION WINDOW")
    print("These windows are for discriminating dataflow manually; not proof of an action callback.")
    seen = set()
    for val, im, site in confirmed_sites:
        if (im.name,site) in seen:
            continue
        seen.add((im.name,site))
        if len(seen)>26:
            print("Reader window report cap reached (26); bounded audit ends")
            break
        print(f"\nANCHOR=0x{val:08X} | {im.name} candidate reader at 0x{site:08X}")
        auditor.show_window(site)

    banner("G. ACTION TRACE DECISION (EVIDENCE RULE)")
    print(f"VIS_WRITER_ENTRY = 0x{ITEM_WRITER:08X}; EXPECTED_RECORD_STRIDE = 0x{RECORD_STRIDE:X}")
    print(f"WRITER_CFG_REACHED = {len(writer_cfg)}; TRUNCATED = {writer_trunc}")
    print(f"NON-LAYOUT_ANCHORS_DERIVED = {len(candidates)}")
    print(f"ANCHORS_READER_SCREENED = {len(selected)}")
    print(f"NON-WRITER_LITERAL_SITE_CANDIDATES = {len(seen)}")
    print("NO AUTOMATIC PATCH PROMOTION: no selected-index/record-field/dispatcher chain is claimed here.")
    print("Assess candidate evidence in order: writer store target -> record base -> selected-index")
    print("-> +0xNN field load -> event/OK/Select callsite -> dispatcher -> 0x8928 route.")
    print("If none is proven, next gate must be one narrowly named missing link, not another global census.")
    print("PHONE ACCESSED = NO; FLASH MODIFIED = NO; PATCH GENERATED = NO; HARDWARE WRITE AUTHORIZED = NO")


if __name__ == "__main__":
    main()
