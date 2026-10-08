#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
S13.5A.60 - synthesized B702 owner / builder trace

STRICTLY OFFLINE.
Reads only canonical extracted firmware files from the local repository.
No phone/USB/COM/BROM/DA access. No write/erase/repack/patch.

Why this gate:
A.58/A.59 found no literal load of 0xB702, while nearby B70x IDs are often
constructed arithmetically (for example: MOVS #0xB7 ; LSLS #8 ; ADDS #n).
A.60 therefore searches code for synthesized B702, then classifies the
surrounding call pipeline and compares it with synthesized B700..B70F peers.

Output:
research/f2/work/reports/s13_5a60_b702_synthesized_owner_builder_trace.txt
"""

from __future__ import annotations

import re
import sys
import traceback
from collections import Counter, defaultdict
from contextlib import redirect_stdout
from pathlib import Path

TITLE = "S13.5A.60 - SYNTHESIZED B702 OWNER / BUILDER TRACE"

B702 = 0xB702
B709 = 0xB709
B7_LO = 0xB700
B7_HI = 0xB70F

ROOT_MAPPER = 0x10319094

# Generic registry/menu-looking helpers already seen around B70x construction.
FOCUS_CALLS = {
    0xF02D53DC: "F02D53DC",
    0xF02AE4E4: "F02AE4E4",
    0xF03002A0: "F03002A0",
    0x10318848: "10318848",
    ROOT_MAPPER: "ROOT_MAPPER",
    0xF02AE864: "F02AE864",
    0xF02E5C9C: "F02E5C9C",
}

REG_RE = r"r(?:1[0-2]|[0-9])"
MOV_IMM_RE = re.compile(rf"^\s*movs?\s+({REG_RE})\s*,\s*#(0x[0-9a-f]+|\d+)\s*$", re.I)
MOV_REG_RE = re.compile(rf"^\s*movs?\s+({REG_RE})\s*,\s*({REG_RE})\s*$", re.I)
LSL_RE = re.compile(
    rf"^\s*lsls?\s+({REG_RE})\s*,\s*(?:({REG_RE})\s*,\s*)?#(0x[0-9a-f]+|\d+)\s*$",
    re.I,
)
ADD_IMM_2_RE = re.compile(
    rf"^\s*adds?\s+({REG_RE})\s*,\s*(?:({REG_RE})\s*,\s*)?#(0x[0-9a-f]+|\d+)\s*$",
    re.I,
)
SUB_IMM_2_RE = re.compile(
    rf"^\s*subs?\s+({REG_RE})\s*,\s*(?:({REG_RE})\s*,\s*)?#(0x[0-9a-f]+|\d+)\s*$",
    re.I,
)


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


def hline(s):
    print()
    print("=" * 120)
    print(s)
    print("=" * 120)


def parse_imm(s):
    return int(s, 0)


def writes_reg(text, reg):
    low = text.lower().strip()
    # Conservative set: any common data-processing/load mnemonic whose first
    # operand is reg is considered a clobber.
    return bool(
        re.match(
            rf"^(?:movs?|ldr(?:b|h|sh|sb)?|adds?|subs?|lsls?|lsrs?|asrs?|"
            rf"orrs?|ands?|eors?|muls?|adcs?|sbcs?|rsbs?|uxth|uxtb|sxth|sxtb)"
            rf"\s+{re.escape(reg)}\b",
            low,
        )
    )


def step_const(text, consts):
    """
    Tiny straight-line constant propagator for the common Thumb idioms used
    to synthesize 16-bit IDs. It is intentionally conservative.
    """
    low = text.lower().strip()

    m = MOV_IMM_RE.match(low)
    if m:
        consts[m.group(1)] = parse_imm(m.group(2)) & 0xFFFFFFFF
        return

    m = MOV_REG_RE.match(low)
    if m:
        dst, src = m.group(1), m.group(2)
        if src in consts:
            consts[dst] = consts[src]
        else:
            consts.pop(dst, None)
        return

    m = LSL_RE.match(low)
    if m:
        dst = m.group(1)
        src = m.group(2) or dst
        sh = parse_imm(m.group(3))
        if src in consts:
            consts[dst] = (consts[src] << sh) & 0xFFFFFFFF
        else:
            consts.pop(dst, None)
        return

    m = ADD_IMM_2_RE.match(low)
    if m:
        dst = m.group(1)
        src = m.group(2) or dst
        imm = parse_imm(m.group(3))
        if src in consts:
            consts[dst] = (consts[src] + imm) & 0xFFFFFFFF
        else:
            consts.pop(dst, None)
        return

    m = SUB_IMM_2_RE.match(low)
    if m:
        dst = m.group(1)
        src = m.group(2) or dst
        imm = parse_imm(m.group(3))
        if src in consts:
            consts[dst] = (consts[src] - imm) & 0xFFFFFFFF
        else:
            consts.pop(dst, None)
        return

    # Unknown obvious write => drop any value we were tracking.
    for reg in list(consts):
        if writes_reg(low, reg):
            consts.pop(reg, None)


def decode_linear(aud, start, max_insns=32):
    out = []
    pc = start & ~1
    for _ in range(max_insns):
        x = aud.decode_one(pc)
        if x is None:
            break
        out.append(x)
        pc += max(2, x.size)
    return out


def find_b7_syntheses(aud):
    """
    Seed only on MOV[S] reg,#0xB7 and propagate a short straight-line window.
    Record each first transition of a register into B700..B70F.
    """
    hits = []
    seen = set()

    for img in aud.images:
        pc = img.base & ~1
        end = img.end - 2
        while pc < end:
            x = aud.decode_one(pc)
            if x is None:
                pc += 2
                continue

            m = MOV_IMM_RE.match(x.text.lower().strip())
            if not m or parse_imm(m.group(2)) != 0xB7:
                pc += 2
                continue

            seed_reg = m.group(1)
            consts = {}
            prev = {}
            seq = decode_linear(aud, pc, max_insns=18)

            for y in seq:
                prev = dict(consts)
                step_const(y.text, consts)

                for reg, value in list(consts.items()):
                    if B7_LO <= value <= B7_HI and prev.get(reg) != value:
                        key = (img.name, pc, y.addr, reg, value)
                        if key not in seen:
                            seen.add(key)
                            hits.append(
                                {
                                    "image": img.name,
                                    "seed": pc,
                                    "site": y.addr,
                                    "reg": reg,
                                    "value": value,
                                    "seed_reg": seed_reg,
                                }
                            )

                # Do not chase through unconditional control transfers.
                low = y.text.lower().strip()
                if (
                    (y.is_jump and not low.startswith(("beq", "bne", "bhi", "bls", "bcc", "bcs", "blo", "bhs", "bgt", "blt", "bge", "ble")))
                    or y.is_call
                ):
                    # The value synthesis itself is still valid before the call,
                    # but continuing propagation across the call is unsafe.
                    break

            pc += 2

    hits.sort(key=lambda h: (h["image"], h["site"], h["value"]))
    return hits


def candidate_entries(aud, site, back=0x300):
    img = aud.image_for(site)
    if img is None:
        return []
    start = max(img.base, site - back) & ~1
    rows = []
    seen = set()
    pc = start

    while pc <= site:
        x = aud.decode_one(pc)
        if x is not None:
            low = x.text.lower()
            if low.startswith("push") and "lr" in low:
                fa = aud.audit_func(pc, max_span=0x1800, max_insns=2000)
                if site in fa.insns and pc not in seen:
                    seen.add(pc)
                    rows.append((pc, fa))
        pc += 2

    rows.sort(key=lambda row: (site - row[0], row[0]))
    return rows


def normalized_calls(aud, fa):
    out = []
    for site, raw in fa.calls:
        norm, via = aud.normalized_target(raw)
        out.append((site, norm, raw, via))
    return out


def dump_context(aud, center, before=0x40, after=0x80, mark="FOCUS"):
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
            label = FOCUS_CALLS.get(norm)
            extra.append(
                f"target=0x{norm:08X}"
                + (f"<{label}>" if label else "")
                + (f"[{via}]" if via else "")
            )
        if x.literal_value is not None:
            extra.append(f"literal=0x{x.literal_value:08X}")
            s = aud.string_at(x.literal_value)
            if s:
                extra.append(f'STR="{s}"')

        suffix = (" ; " + " ".join(extra)) if extra else ""
        flag = f" <{mark}>" if pc == center else ""
        print(f"0x{pc:08X}: {x.text}{suffix}{flag}")
        pc += max(2, x.size)


def calls_after_site(aud, fa, site, span=0x100):
    out = []
    for callsite, raw in fa.calls:
        if site <= callsite <= site + span:
            norm, via = aud.normalized_target(raw)
            out.append((callsite, norm, raw, via))
    return sorted(out)


def reverse_direct_calls(aud, targets):
    targets = {t & ~1 for t in targets}
    out = {t: [] for t in targets}

    for img in aud.images:
        pc = img.base & ~1
        end = img.end - 2
        while pc < end:
            x = aud.decode_one(pc)
            if x is not None and x.is_call and x.target is not None:
                norm, via = aud.normalized_target(x.target)
                if norm in targets:
                    out[norm].append((img.name, pc, x.target, via))
            pc += 2
    return out


def function_strings(aud, fa):
    seen = set()
    out = []
    for _, _, value in fa.literals:
        s = aud.string_at(value)
        if s and s not in seen:
            seen.add(s)
            out.append(s)
    return out


def main_body():
    repo = Path.cwd().resolve()
    helper = repo / "research/f2/automation/jobs/s13_5a51_launcher_dispatch_init_trace.py"
    if not helper.is_file():
        raise SystemExit(
            "Run from C:\\Users\\verto\\F2-Altice-MobiWire so the canonical "
            "A.51 helper is available."
        )

    sys.path.insert(0, str(helper.parent))
    import s13_5a51_launcher_dispatch_init_trace as m

    alice, zimage = m.load_images()
    aud = m.StaticAudit(alice, zimage)

    print("=" * 120)
    print(TITLE)
    print("=" * 120)
    print("STRICTLY OFFLINE: local firmware reads only.")

    hline("A. CANONICAL IMAGE GUARDS")
    print(f"ALICE size=0x{len(alice.data):X} sha256={m.sha256(alice.data)}")
    print(f"ZIMAGE size=0x{len(zimage.data):X} sha256={m.sha256(zimage.data)}")
    print("Canonical A.51 loader = PASS")

    hline("B. SYNTHESIZED B700..B70F IDS")
    hits = find_b7_syntheses(aud)
    print(f"synthesized_B70x_hits={len(hits)}")

    by_value = defaultdict(list)
    for h in hits:
        by_value[h["value"]].append(h)

    for value in range(B7_LO, B7_HI + 1):
        rows = by_value.get(value, [])
        print(f"0x{value:04X}: syntheses={len(rows)}")
        for h in rows[:30]:
            print(
                f"  {h['image']} seed=0x{h['seed']:08X} "
                f"site=0x{h['site']:08X} reg={h['reg']}"
            )
        if len(rows) > 30:
            print("  ... truncated")

    hline("C. B702 SYNTHESIS CONTEXTS")
    b702_hits = by_value.get(B702, [])
    print(f"B702_syntheses={len(b702_hits)}")

    b702_funcs = {}
    provenance = defaultdict(list)

    for h in b702_hits:
        print(
            f"\n{h['image']} seed=0x{h['seed']:08X} "
            f"B702_at=0x{h['site']:08X} reg={h['reg']}"
        )
        dump_context(aud, h["seed"], before=0x20, after=0xC0, mark="B7_SEED")

        entries = candidate_entries(aud, h["site"])
        print(f"  enclosing_candidates={len(entries)}")
        for entry, fa in entries[:3]:
            b702_funcs.setdefault(entry, fa)
            provenance[entry].append(h)
            calls = calls_after_site(aud, fa, h["site"], span=0x140)
            print(
                f"    entry=0x{entry:08X} insns={len(fa.insns)} "
                f"calls_after={len(calls)}"
            )
            for callsite, norm, raw, via in calls[:30]:
                label = FOCUS_CALLS.get(norm, "")
                print(
                    f"      0x{callsite:08X} -> 0x{norm:08X}"
                    + (f" <{label}>" if label else "")
                    + (f" [{via}]" if via else "")
                )

    hline("D. B702 OWNER FUNCTIONS")
    owners = []
    for entry, fa in b702_funcs.items():
        calls = normalized_calls(aud, fa)
        call_targets = {norm for _, norm, _, _ in calls}
        strings = function_strings(aud, fa)

        score = 0
        for target in FOCUS_CALLS:
            if target in call_targets:
                score += 5
        if ROOT_MAPPER in call_targets:
            score += 5
        if any(x in call_targets for x in (0xF02AE4E4, 0xF03002A0, 0xF02D53DC)):
            score += 7

        owners.append((score, entry, fa, call_targets, strings))

    owners.sort(key=lambda row: (-row[0], row[1]))

    for score, entry, fa, targets, strings in owners:
        print(
            f"entry=0x{entry:08X} image={fa.image} score={score} "
            f"insns={len(fa.insns)} calls={len(fa.calls)}"
        )
        if targets:
            print(
                "  CALL_TARGETS:",
                ", ".join(
                    f"0x{x:08X}" + (f"<{FOCUS_CALLS[x]}>" if x in FOCUS_CALLS else "")
                    for x in sorted(targets)
                )
            )
        for s in strings[:20]:
            print(f'  STR "{s}"')
        print(
            "  SYNTH_SITES:",
            ", ".join(
                f"0x{x['site']:08X}" for x in provenance[entry]
            )
        )

    hline("E. PEER B70x PIPELINE COMPARISON")
    # For each synthesized B70x value, collect enclosing owner + normalized
    # call targets. Shared targets reveal the common builder/registry pipeline.
    peer_rows = []
    target_freq = Counter()

    for value, rows in sorted(by_value.items()):
        local_funcs = {}
        for h in rows:
            for entry, fa in candidate_entries(aud, h["site"])[:1]:
                local_funcs.setdefault(entry, fa)

        for entry, fa in local_funcs.items():
            targets = {norm for _, norm, _, _ in normalized_calls(aud, fa)}
            peer_rows.append((value, entry, fa, targets))
            for t in targets:
                target_freq[t] += 1

    print("Most common call targets across synthesized B70x owners:")
    for target, count in target_freq.most_common(40):
        label = FOCUS_CALLS.get(target, "")
        print(
            f"  0x{target:08X} owners={count}"
            + (f" <{label}>" if label else "")
        )

    print("\nPer-ID owner summary:")
    for value, entry, fa, targets in peer_rows:
        focus = [t for t in targets if t in FOCUS_CALLS]
        print(
            f"0x{value:04X} owner=0x{entry:08X} image={fa.image} "
            f"focus_calls="
            + (
                ",".join(
                    f"0x{x:08X}<{FOCUS_CALLS[x]}>" for x in sorted(focus)
                )
                if focus
                else "NONE"
            )
        )

    hline("F. REVERSE CALLERS OF B702 OWNER FUNCTIONS")
    owner_targets = [entry for _, entry, _, _, _ in owners[:12]]
    reverse = reverse_direct_calls(aud, owner_targets) if owner_targets else {}

    for target in owner_targets:
        rows = reverse.get(target & ~1, [])
        print(f"\nTARGET 0x{target:08X}: direct_callers={len(rows)}")
        for image_name, site, raw, via in rows[:40]:
            print(
                f"  {image_name} callsite=0x{site:08X} "
                f"via={via or 'DIRECT'}"
            )
            dump_context(aud, site, before=0x30, after=0x24, mark="OWNER_CALL")
        if len(rows) > 40:
            print("  ... truncated")

    hline("G. B702 SYNTHESIS -> FOCUS CALL DATAFLOW WINDOWS")
    # Straight-line local windows: after each exact B702 synthesis, show all
    # calls until the first return/unconditional branch or 0x100 bytes.
    for h in b702_hits:
        print(
            f"\nB702 synth site=0x{h['site']:08X} reg={h['reg']} "
            f"image={h['image']}"
        )
        img = aud.image_for(h["site"])
        pc = h["site"] & ~1
        end = min(img.end, h["site"] + 0x100)
        while pc < end:
            x = aud.decode_one(pc)
            if x is None:
                pc += 2
                continue

            if x.is_call and x.target is not None:
                norm, via = aud.normalized_target(x.target)
                label = FOCUS_CALLS.get(norm)
                print(
                    f"  CALL 0x{pc:08X} -> 0x{norm:08X}"
                    + (f" <{label}>" if label else "")
                    + (f" [{via}]" if via else "")
                )

            low = x.text.lower().strip()
            if m.StaticAudit.is_return(x.text):
                break
            if x.is_jump and low.startswith(("b ", "b.w ")):
                break

            pc += max(2, x.size)

    hline("H. DECISION GATE")
    print(f"B702_syntheses={len(b702_hits)}")
    print(f"B702_owner_functions={len(owners)}")

    strong = []
    for score, entry, fa, targets, strings in owners:
        focus = targets & set(FOCUS_CALLS)
        if score >= 7 or focus:
            strong.append((score, entry, focus))

    print(f"strong_B702_owner_candidates={len(strong)}")
    for score, entry, focus in strong:
        print(
            f"  0x{entry:08X} score={score} focus="
            + (
                ",".join(
                    f"0x{x:08X}<{FOCUS_CALLS[x]}>" for x in sorted(focus)
                )
                if focus
                else "NONE"
            )
        )

    if strong:
        best = strong[0]
        print(
            f"RESULT: synthesized B702 is owned by executable code; "
            f"leading owner = 0x{best[1]:08X}."
        )
        print(
            "NEXT: trace the exact B702 owner output and compare the visible "
            "node/action construction for its children 8569 and 87ED."
        )
    elif b702_hits:
        print(
            "RESULT: synthesized B702 code exists, but no already-known focus "
            "helper is called in the same owner function."
        )
        print(
            "NEXT: follow the reverse caller of the nearest B702 owner and "
            "track the synthesized ID through one function boundary."
        )
    else:
        print(
            "RESULT: no MOVS #0xB7 / shift / add synthesis of B702 was found."
        )
        print(
            "NEXT: scan alternative constant-building forms (MOVW, table "
            "halfwords, arithmetic from neighboring B70x IDs)."
        )

    print()
    print("PHONE ACCESSED       : NO")
    print("FLASH MODIFIED       : NO")
    print("PATCH GENERATED      : NO")
    print("PHYSICAL CANDIDATE   : NO")
    print("HARDWARE WRITE AUTHORIZED: NO")


def main():
    repo = Path.cwd().resolve()
    report = repo / "research/f2/work/reports/s13_5a60_b702_synthesized_owner_builder_trace.txt"
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
