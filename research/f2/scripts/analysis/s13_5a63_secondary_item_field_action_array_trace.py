#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
S13.5A.63 - 0x10306034 secondary item-field writer / action-array provenance

STRICTLY OFFLINE.
No USB/COM/BROM/DA/device access. No flash write/erase/repack/patch.

A.62 established three direct owners of ITEM_WRITER 0x10316834:
  - 0x103647C4: already-known B709 root UI builder.
  - 0x10306034: tiny wrapper that calls ITEM_WRITER, then 0x102FFEC8
                with (item_index, original_r3).
  - 0x10392D6C: resource/layout-oriented list builder.

This gate investigates the new patch-relevant unknown exposed by A.62:
what does 0x102FFEC8 write, and what is the provenance of the r3 value
fed into 0x10306034 by its parents (especially 0x10349F4C)?

Goals:
1. Resolve and dump 0x102FFEC8 (including import veneer normalization).
2. Compare its storage/global pattern with ITEM_WRITER 0x10316834.
3. Census all callers of 0x102FFEC8 / normalized target.
4. Reverse-call 0x10349F4C and 0x1032AFA0 and recover call-argument
   provenance, focusing on r3 / per-item auxiliary arrays.
5. Dump static arrays reached through literal pointers when possible and
   classify entries as code pointers, firmware pointers, IDs, or raw data.
6. Search candidate arrays/functions for 8569/87ED/86C0/8928 and known
   Audio init/callback/player pointers.
7. Do not revisit B709 topology, ROOT_MAPPER, or the S13.2A redirect.

Output:
research/f2/work/reports/s13_5a63_secondary_item_field_action_array_trace.txt
"""

from __future__ import annotations

import re
import sys
import traceback
from collections import defaultdict
from contextlib import redirect_stdout
from pathlib import Path

TITLE = "S13.5A.63 - SECONDARY ITEM FIELD / ACTION ARRAY TRACE"

ITEM_WRITER = 0x10316834
SECONDARY_CALL = 0x102FFEC8
WRAPPER = 0x10306034
PARENT_A = 0x1032AFA0
PARENT_B = 0x10349F4C

FOCUS = {
    0xB709: "B709",
    0xB702: "B702",
    0x8569: "8569",
    0x87ED: "87ED",
    0x86C0: "86C0",
    0x8928: "8928",
    0x8321: "8321",
    0x8313: "8313",
    0x1033D840: "CB_8928",
    0x1033D841: "CB_8928_THUMB",
    0x1033E814: "INIT_8928",
    0x1033E815: "INIT_8928_THUMB",
    0x1033F83C: "AUDIO_PLAYER",
    0x1033F83D: "AUDIO_PLAYER_THUMB",
    0x1033EF28: "INIT_86C0",
    0x1033EF29: "INIT_86C0_THUMB",
    0x10348D04: "INIT_8569",
    0x10348D05: "INIT_8569_THUMB",
}

KNOWN_HELPERS = {
    ITEM_WRITER: "ITEM_WRITER",
    WRAPPER: "ITEM_WRITER_PLUS_SECONDARY",
    PARENT_A: "PARENT_A",
    PARENT_B: "PARENT_B",
    0x1031DA2C: "RESOURCE_CONVERT_A",
    0x10321B40: "RESOURCE_CONVERT_B",
    0x10317F44: "ITEM_AUX_CONVERT",
    0x10316540: "LIST_UI_INIT",
}

PUSH_RE = re.compile(r"^push", re.I)
LDR_PC_RE = re.compile(r"^ldr\s+(r(?:1[0-2]|[0-9])),\s*\[pc", re.I)
MOV_REG_RE = re.compile(r"^(?:movs?|mov)\s+(r(?:1[0-2]|[0-9])),\s*(r(?:1[0-2]|[0-9]))$", re.I)
MOV_IMM_RE = re.compile(r"^(?:movs?|mov)\s+(r(?:1[0-2]|[0-9])),\s*#(0x[0-9a-f]+|\d+)$", re.I)


class Tee:
    def __init__(self, *streams):
        self.streams = streams

    def write(self, data):
        for s in self.streams:
            s.write(data)
            s.flush()
        return len(data)

    def flush(self):
        for s in self.streams:
            s.flush()


def hline(label):
    print()
    print("=" * 120)
    print(label)
    print("=" * 120)


def audit_func(aud, addr):
    try:
        return aud.audit_func(addr & ~1, max_span=0x3000, max_insns=5000)
    except TypeError:
        return aud.audit_func(addr & ~1)


def reverse_calls(aud, targets):
    targets = {x & ~1 for x in targets}
    out = {x: [] for x in targets}
    for img in aud.images:
        pc = img.base & ~1
        while pc < img.end - 2:
            x = aud.decode_one(pc)
            if x is not None and x.is_call and x.target is not None:
                norm, via = aud.normalized_target(x.target)
                raw_norm = x.target & ~1
                if norm in targets:
                    out[norm].append((img.name, pc, x.target, via))
                if raw_norm in targets and raw_norm != norm:
                    out[raw_norm].append((img.name, pc, x.target, via))
            pc += 2
    return out


def candidate_entries(aud, site, back=0x900):
    img = aud.image_for(site)
    if img is None:
        return []
    start = max(img.base, site - back) & ~1
    rows = []
    seen = set()
    pc = start
    while pc <= site:
        x = aud.decode_one(pc)
        if x is not None and PUSH_RE.match(x.text.strip()) and "lr" in x.text.lower():
            try:
                fa = audit_func(aud, pc)
            except Exception:
                fa = None
            if fa is not None and site in fa.insns and pc not in seen:
                seen.add(pc)
                rows.append((pc, fa))
        pc += 2
    rows.sort(key=lambda r: (site - r[0], r[0]))
    return rows


def best_owner(aud, site):
    rows = candidate_entries(aud, site)
    return rows[0] if rows else (None, None)


def normalize_text(s):
    return re.sub(r"\s+", " ", s.lower().replace("\t", " ")).strip()


def dump_function(aud, fa, marks=None):
    marks = marks or {}
    for addr in sorted(fa.insns):
        x = fa.insns[addr]
        extra = []
        if x.target is not None:
            norm, via = aud.normalized_target(x.target)
            label = KNOWN_HELPERS.get(norm) or FOCUS.get(norm) or FOCUS.get(norm | 1)
            extra.append(
                f"target=0x{norm:08X}"
                + (f"<{label}>" if label else "")
                + (f"[{via}]" if via else "")
            )
        if x.literal_value is not None:
            v = x.literal_value
            label = FOCUS.get(v)
            extra.append(f"literal=0x{v:08X}" + (f"<{label}>" if label else ""))
            s = aud.string_at(v)
            if s:
                extra.append(f'STR="{s}"')
        suffix = (" ; " + " ".join(extra)) if extra else ""
        mark = f" <{marks[addr]}>" if addr in marks else ""
        print(f"0x{addr:08X}: {x.text}{suffix}{mark}")


def context(aud, center, before=0x60, after=0x70, mark="SITE"):
    img = aud.image_for(center)
    if img is None:
        return
    pc = max(img.base, center - before) & ~1
    end = min(img.end, center + after)
    while pc < end:
        x = aud.decode_one(pc)
        if x is None:
            pc += 2
            continue
        extra = []
        if x.target is not None:
            norm, via = aud.normalized_target(x.target)
            lab = KNOWN_HELPERS.get(norm) or FOCUS.get(norm) or FOCUS.get(norm | 1)
            extra.append(
                f"target=0x{norm:08X}"
                + (f"<{lab}>" if lab else "")
                + (f"[{via}]" if via else "")
            )
        if x.literal_value is not None:
            v = x.literal_value
            lab = FOCUS.get(v)
            extra.append(f"literal=0x{v:08X}" + (f"<{lab}>" if lab else ""))
            s = aud.string_at(v)
            if s:
                extra.append(f'STR="{s}"')
        suffix = (" ; " + " ".join(extra)) if extra else ""
        flag = f" <{mark}>" if pc == center else ""
        print(f"0x{pc:08X}: {x.text}{suffix}{flag}")
        pc += max(2, x.size)


def literal_values(fa):
    vals = []
    for row in fa.literals:
        if row and isinstance(row[-1], int):
            vals.append((row[0], row[-1]))
    return vals


def storage_signature(aud, fa):
    """
    Mechanical summary only: literal globals plus STR/STRH/STRB texts.
    Useful to compare whether the two writers touch the same state family.
    """
    print("  literal globals/pointers:")
    for site, v in literal_values(fa):
        img = aud.image_for(v)
        tag = img.name if img is not None else ""
        lab = FOCUS.get(v, "")
        print(
            f"    0x{site:08X} -> 0x{v:08X}"
            + (f" [{tag}]" if tag else "")
            + (f" <{lab}>" if lab else "")
        )
    print("  stores:")
    for addr in sorted(fa.insns):
        t = normalize_text(fa.insns[addr].text)
        if t.startswith(("str ", "strh ", "strb ")):
            print(f"    0x{addr:08X}: {fa.insns[addr].text}")


def classify_word(aud, v):
    if v in FOCUS:
        return FOCUS[v]
    if (v & ~1) in FOCUS:
        return FOCUS[v & ~1]
    img = aud.image_for(v & ~1)
    if img is not None:
        x = aud.decode_one(v & ~1)
        if x is not None:
            low = x.text.lower()
            if low.startswith(("push", "b ", "b.w", "mov", "ldr", "sub sp")):
                return f"{img.name}_CODE?"
        return f"{img.name}_PTR"
    if 0 <= v <= 0xFFFF:
        return "U16/ID?"
    return "RAW"


def read_u32(aud, addr):
    img = aud.image_for(addr)
    if img is None or addr + 4 > img.end:
        return None
    off = addr - img.base
    return int.from_bytes(img.data[off:off+4], "little")


def dump_pointer_array(aud, ptr, words=16):
    img = aud.image_for(ptr)
    if img is None:
        print(f"    pointer 0x{ptr:08X}: outside canonical images")
        return
    print(f"    array@0x{ptr:08X} image={img.name}")
    for i in range(words):
        a = ptr + 4*i
        v = read_u32(aud, a)
        if v is None:
            break
        print(f"      +0x{4*i:02X} 0x{v:08X} {classify_word(aud, v)}")


def simple_reg_provenance(aud, fa, callsite, reg, max_back=40):
    """
    Conservative backward explanation of one argument register.
    Returns a textual provenance and an optional literal value.
    """
    addrs = [a for a in sorted(fa.insns) if a < callsite][-max_back:]
    want = reg
    visited = set()

    for addr in reversed(addrs):
        x = fa.insns[addr]
        t = normalize_text(x.text)

        # A call clobbers r0-r3 if we still trace one of them.
        if x.is_call and want in {"r0","r1","r2","r3"}:
            return (f"{want} clobbered by call @0x{addr:08X}", None)

        m = LDR_PC_RE.match(t)
        if m and m.group(1) == want and x.literal_value is not None:
            return (f"{want} <- literal @0x{addr:08X}", x.literal_value)

        m = MOV_IMM_RE.match(t)
        if m and m.group(1) == want:
            return (f"{want} <- immediate @0x{addr:08X}", int(m.group(2),0))

        m = MOV_REG_RE.match(t)
        if m and m.group(1) == want:
            src = m.group(2)
            if src in visited:
                return (f"register cycle while tracing {reg}", None)
            visited.add(src)
            want = src
            continue

        # Stack/memory source: report exact instruction and stop.
        if re.match(rf"^ldr(?:b|h)?\s+{re.escape(want)},", t):
            return (f"{want} <- memory via 0x{addr:08X}: {x.text}", x.literal_value)

        # Generic write to wanted register => unknown arithmetic/dataflow.
        first = t.split(" ", 1)
        if len(first) == 2:
            dst = first[1].split(",", 1)[0].strip()
            if dst == want and not t.startswith(("cmp ", "tst ", "str", "push", "stm")):
                return (f"{want} overwritten @0x{addr:08X}: {x.text}", x.literal_value)

    return (f"no bounded definition found for {reg}", None)


def callsites_to(aud, target):
    rev = reverse_calls(aud, {target & ~1})
    return rev.get(target & ~1, [])


def focus_hits_in_function(fa):
    hits = []
    for site, v in literal_values(fa):
        if v in FOCUS or (v & ~1) in FOCUS:
            hits.append((site, v, FOCUS.get(v) or FOCUS.get(v & ~1)))
    return hits


def main_body():
    repo = Path.cwd().resolve()
    helper = repo / "research/f2/automation/jobs/s13_5a51_launcher_dispatch_init_trace.py"
    if not helper.is_file():
        raise SystemExit(
            "Run from C:\\Users\\verto\\F2-Altice-MobiWire; canonical A.51 helper not found."
        )

    sys.path.insert(0, str(helper.parent))
    import s13_5a51_launcher_dispatch_init_trace as m

    alice, zimage = m.load_images()
    aud = m.StaticAudit(alice, zimage)

    print("=" * 120)
    print(TITLE)
    print("=" * 120)
    print("STRICTLY OFFLINE: canonical firmware reads only.")
    print("Scope: secondary per-item field/action semantics exposed by A.62.")

    hline("A. CANONICAL IMAGE GUARDS")
    print(f"ALICE size=0x{len(alice.data):X} sha256={m.sha256(alice.data)}")
    print(f"ZIMAGE size=0x{len(zimage.data):X} sha256={m.sha256(zimage.data)}")
    print("Canonical loader = PASS")

    hline("B. RESOLVE 0x102FFEC8")
    secondary_norm, secondary_via = aud.normalized_target(SECONDARY_CALL)
    print(f"raw target      = 0x{SECONDARY_CALL:08X}")
    print(f"normalized      = 0x{secondary_norm:08X}")
    print(f"via             = {secondary_via or 'DIRECT/NO_VENEER'}")
    sec_fa = audit_func(aud, secondary_norm)
    print(f"image           = {sec_fa.image}")
    print(f"insns           = {len(sec_fa.insns)}")
    print(f"calls           = {len(sec_fa.calls)}")
    print(f"literals        = {len(sec_fa.literals)}")
    dump_function(aud, sec_fa)

    hline("C. ITEM_WRITER VS SECONDARY WRITER STORAGE SIGNATURE")
    item_fa = audit_func(aud, ITEM_WRITER)
    print("\nITEM_WRITER 0x10316834")
    storage_signature(aud, item_fa)
    print("\nSECONDARY target")
    storage_signature(aud, sec_fa)

    hline("D. ALL CALLERS OF RAW/NORMALIZED SECONDARY HELPER")
    targets = {SECONDARY_CALL & ~1, secondary_norm & ~1}
    rev = reverse_calls(aud, targets)
    seen_sites = set()
    for target in sorted(targets):
        rows = rev.get(target, [])
        print(f"\nTARGET 0x{target:08X} callers={len(rows)}")
        for image_name, site, raw, via in rows:
            key = (image_name, site)
            if key in seen_sites:
                continue
            seen_sites.add(key)
            owner, fa = best_owner(aud, site)
            print(
                f"  {image_name} callsite=0x{site:08X} raw=0x{raw:08X} "
                f"via={via or 'DIRECT'} owner="
                + (f"0x{owner:08X}" if owner is not None else "UNKNOWN")
            )
            context(aud, site, before=0x48, after=0x50, mark="SECONDARY_CALL")

    hline("E. WRAPPER 0x10306034 EXACT CONTRACT")
    wrapper_fa = audit_func(aud, WRAPPER)
    dump_function(
        aud,
        wrapper_fa,
        marks={
            0x1030603A: "ITEM_WRITER",
            0x10306042: "SECONDARY_HELPER",
        },
    )
    print(
        "\nA.62 observed contract: incoming r0=item_index; original r3 is saved in r5; "
        "after ITEM_WRITER the wrapper calls 0x102FFEC8 with r0=item_index, r1=original_r3."
    )

    hline("F. DIRECT CALLERS OF WRAPPER 0x10306034")
    wrapper_calls = callsites_to(aud, WRAPPER)
    print(f"direct callers={len(wrapper_calls)}")
    for image_name, site, raw, via in wrapper_calls:
        owner, fa = best_owner(aud, site)
        print(
            f"\n{image_name} callsite=0x{site:08X} owner="
            + (f"0x{owner:08X}" if owner is not None else "UNKNOWN")
        )
        if fa is not None:
            for reg in ("r0","r1","r2","r3"):
                prov, val = simple_reg_provenance(aud, fa, site, reg)
                lab = ""
                if val is not None:
                    lab = f" value=0x{val:08X} {classify_word(aud, val)}"
                print(f"  {reg}: {prov}{lab}")
                if reg == "r3" and val is not None and aud.image_for(val) is not None:
                    dump_pointer_array(aud, val, words=16)
        context(aud, site, before=0x78, after=0x58, mark="WRAPPER_CALL")

    hline("G. REVERSE CALLERS OF 0x10349F4C (R3 ARRAY PROVIDER CANDIDATE)")
    parent_b_calls = callsites_to(aud, PARENT_B)
    print(f"direct callers={len(parent_b_calls)}")
    parent_b_literal_arrays = []
    for image_name, site, raw, via in parent_b_calls:
        owner, fa = best_owner(aud, site)
        print(
            f"\n{image_name} callsite=0x{site:08X} owner="
            + (f"0x{owner:08X}" if owner is not None else "UNKNOWN")
        )
        if fa is not None:
            for reg in ("r0","r1","r2","r3"):
                prov, val = simple_reg_provenance(aud, fa, site, reg, max_back=60)
                print(
                    f"  {reg}: {prov}"
                    + (f" value=0x{val:08X} {classify_word(aud, val)}" if val is not None else "")
                )
                if reg == "r3" and val is not None and aud.image_for(val) is not None:
                    parent_b_literal_arrays.append(val)
                    dump_pointer_array(aud, val, words=24)
            hits = focus_hits_in_function(fa)
            for hs, hv, hn in hits:
                print(f"  FOCUS literal 0x{hv:08X}<{hn}> at 0x{hs:08X}")
        context(aud, site, before=0x90, after=0x70, mark="PARENT_B_CALL")

    hline("H. REVERSE CALLERS OF 0x1032AFA0")
    parent_a_calls = callsites_to(aud, PARENT_A)
    print(f"direct callers={len(parent_a_calls)}")
    for image_name, site, raw, via in parent_a_calls:
        owner, fa = best_owner(aud, site)
        print(
            f"\n{image_name} callsite=0x{site:08X} owner="
            + (f"0x{owner:08X}" if owner is not None else "UNKNOWN")
        )
        if fa is not None:
            for reg in ("r0","r1","r2","r3"):
                prov, val = simple_reg_provenance(aud, fa, site, reg, max_back=60)
                print(
                    f"  {reg}: {prov}"
                    + (f" value=0x{val:08X} {classify_word(aud, val)}" if val is not None else "")
                )
            for hs, hv, hn in focus_hits_in_function(fa):
                print(f"  FOCUS literal 0x{hv:08X}<{hn}> at 0x{hs:08X}")
        context(aud, site, before=0x90, after=0x70, mark="PARENT_A_CALL")

    hline("I. STATIC ARRAY FOCUS SEARCH")
    arrays = sorted(set(parent_b_literal_arrays))
    if not arrays:
        print("No literal r3 array pointer recovered at direct 0x10349F4C callsites.")
    for ptr in arrays:
        print(f"\nARRAY 0x{ptr:08X}")
        for i in range(32):
            v = read_u32(aud, ptr + 4*i)
            if v is None:
                break
            label = FOCUS.get(v) or FOCUS.get(v & ~1)
            if label:
                print(f"  +0x{4*i:02X} 0x{v:08X} <{label}>")

    hline("J. 0x10392D6C DEPRIORITIZATION CHECK")
    other = audit_func(aud, 0x10392D6C)
    print(
        "This owner is retained only as a control. A.62 showed it iterates a dword array, "
        "writes ITEM_WRITER with r2=0, then measures each entry via F02E19FC and computes "
        "aggregate geometry. Dumping focus literals only:"
    )
    hits = focus_hits_in_function(other)
    if not hits:
        print("  focus literals: NONE")
    else:
        for hs, hv, hn in hits:
            print(f"  0x{hs:08X}: 0x{hv:08X} <{hn}>")

    hline("K. DECISION GATE")
    sec_literals = {v for _, v in literal_values(sec_fa)}
    item_literals = {v for _, v in literal_values(item_fa)}
    shared_globals = sorted(v for v in (sec_literals & item_literals) if v >= 0xF0000000)
    print(f"secondary normalized target = 0x{secondary_norm:08X}")
    print(f"secondary direct/normalized caller sites = {len(seen_sites)}")
    print(f"shared high globals with ITEM_WRITER = {len(shared_globals)}")
    for v in shared_globals:
        print(f"  0x{v:08X}")

    if shared_globals:
        print(
            "RESULT: secondary helper shares item-state globals with ITEM_WRITER; "
            "treat 0x10306034 as a two-stage per-item record writer until disproven."
        )
    else:
        print(
            "RESULT: no literal-global overlap was mechanically proven. Use the exact "
            "secondary disassembly and callsites above to classify its storage target."
        )

    print(
        "NEXT IF R3 RESOLVES TO STATIC CODE-POINTER ARRAY: identify the action invoked for "
        "a selected item and compare it with Audio callback/init. "
        "NEXT IF R3 IS DATA/ID ARRAY: recover the downstream consumer before selecting a patch."
    )

    print()
    print("PHONE ACCESSED       : NO")
    print("FLASH MODIFIED       : NO")
    print("PATCH GENERATED      : NO")
    print("PHYSICAL CANDIDATE   : NO")
    print("HARDWARE WRITE AUTHORIZED: NO")


def main():
    repo = Path.cwd().resolve()
    report = repo / "research/f2/work/reports/s13_5a63_secondary_item_field_action_array_trace.txt"
    report.parent.mkdir(parents=True, exist_ok=True)

    with report.open("w", encoding="utf-8", newline="\n") as fp:
        tee = Tee(sys.stdout, fp)
        with redirect_stdout(tee):
            try:
                main_body()
                print()
                print("=" * 120)
                print("EXIT CODE = 0")
                print("=" * 120)
                return 0
            except Exception:
                print()
                print("=" * 120)
                print("EXCEPTION")
                print("=" * 120)
                traceback.print_exc(file=tee)
                print()
                print("EXIT CODE = 1")
                return 1


if __name__ == "__main__":
    raise SystemExit(main())
