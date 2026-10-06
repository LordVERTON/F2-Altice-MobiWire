#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from __future__ import annotations

import os
from collections import defaultdict
import s13_5a51_launcher_dispatch_init_trace as m

TITLE = "S13.5A.52 - 8569 INIT SEMANTIC FAMILY CLASSIFICATION"


def hline(s):
    print()
    print("=" * 120)
    print(s)
    print("=" * 120)


def profile(aud, root, depth=5):
    funcs, edges, focus, strings = m.callgraph(aud, root, depth=depth, max_funcs=240)
    calls = set()
    for fa in funcs.values():
        for _, raw in fa.calls:
            calls.add(aud.normalized_target(raw)[0])
    return funcs, edges, focus, strings, calls


def unique_strings(rows):
    seen = set()
    out = []
    for entry, site, ptr, s in rows:
        key = (ptr, s)
        if key not in seen:
            seen.add(key)
            out.append((entry, site, ptr, s))
    return out


def token_rows(rows):
    toks = ("audio", "audios", "music", "mp3", "sound", "image", "photo", "camera", "video", "radio", "fm")
    out = []
    for entry, site, ptr, s in rows:
        low = s.lower()
        hit = next((t for t in toks if t in low), None)
        if hit:
            out.append((hit, entry, site, ptr, s))
    return out


def show_profile(aud, name, root):
    funcs, edges, focus, strings, calls = profile(aud, root)
    print(f"{name}: root=0x{root:08X} funcs={len(funcs)} calls={len(calls)} strings={len(strings)} focus={len(focus)}")
    for label, target in (("86C0", m.INIT_86C0), ("8928", m.INIT_8928), ("PLAYER", m.AUDIO_PLAYER)):
        p = m.shortest_path(edges, root, target)
        print(f"  path->{label}: " + (" -> ".join(f"0x{x:08X}" for x in p) if p else "NONE"))
    for entry, site, ptr, s in unique_strings(strings)[:100]:
        print(f'  STR func=0x{entry:08X} site=0x{site:08X} ptr=0x{ptr:08X} "{s}"')
    return funcs, edges, focus, strings, calls


def scan_calls(aud, targets):
    hits = defaultdict(list)
    for img in aud.images:
        addr = img.base & ~1
        end = img.end - 2
        while addr < end:
            x = aud.decode_one(addr)
            if x is not None and x.is_call and x.target is not None:
                norm, _ = aud.normalized_target(x.target)
                if norm in targets:
                    hits[norm].append((img.name, addr))
            addr += 2
    return hits


def context_literals(aud, center, radius=0x40):
    out = []
    addr = (center - radius) & ~1
    end = center + radius
    while addr < end:
        x = aud.decode_one(addr)
        if x is not None and x.literal_value is not None:
            out.append((addr, x.text, x.literal_value, aud.string_at(x.literal_value)))
        addr += 2
    return out


def ptr_context(aud, ptr, name):
    hits = aud.pointer_occurrences(ptr)
    print(f"{name} pointer 0x{ptr:08X}: occurrences={len(hits)}")
    for image_name, addr, value in hits[:20]:
        print(f"  {image_name} 0x{addr:08X}=0x{value:08X}")
        img = next(x for x in aud.images if x.name == image_name)
        a = max(img.base, (addr - 0x18) & ~3)
        end = min(img.end, addr + 0x1C)
        while a + 4 <= end:
            v = img.read_u32(a)
            tags = []
            s = aud.string_at(v)
            if s:
                tags.append(f'STR="{s}"')
            if aud.image_for(v & ~1) is not None and aud.decode_one(v & ~1) is not None:
                tags.append("CODE")
            mark = " HIT" if a == (addr & ~3) else ""
            extra = (" " + " ".join(tags)) if tags else ""
            print(f"    0x{a:08X}: 0x{v:08X}{mark}{extra}")
            a += 4


def main():
    print("=" * 120)
    print(TITLE)
    print("=" * 120)
    if os.environ.get("F2_AUTOMATION_OFFLINE") != "1":
        raise SystemExit("offline automation marker missing")

    hline("A. CANONICAL IMAGE GUARDS")
    alice, zimage = m.load_images()
    aud = m.StaticAudit(alice, zimage)

    hline("B. DEPTH-5 ROOT PROFILES")
    profiles = {}
    for name, root in (("8569", m.INIT_8569), ("86C0", m.INIT_86C0), ("8928", m.INIT_8928)):
        profiles[name] = show_profile(aud, name, root)

    hline("C. 8569 DIRECT CALLEES AND DEPTH-3 SEMANTICS")
    fa = aud.audit_func(m.INIT_8569)
    targets = set()
    for site, raw in fa.calls:
        norm, via = aud.normalized_target(raw)
        follow = aud.can_follow_thumb(raw)
        targets.add(norm)
        print(f"root_site=0x{site:08X} raw=0x{raw:08X} norm=0x{norm:08X} via={via or 'DIRECT'} follow={f'0x{follow:08X}' if follow is not None else 'NONE'}")
        if follow is None:
            continue
        sub = profile(aud, follow, depth=3)
        print(f"  subtree funcs={len(sub[0])} calls={len(sub[4])} strings={len(sub[3])}")
        for entry, ssite, ptr, s in unique_strings(sub[3])[:60]:
            print(f'  STR func=0x{entry:08X} site=0x{ssite:08X} ptr=0x{ptr:08X} "{s}"')

    hline("D. REVERSE CALLS TO THE FOUR 8569 TARGETS")
    rev = scan_calls(aud, targets)
    bucket = defaultdict(lambda: defaultdict(list))
    for target in sorted(targets):
        rows = rev.get(target, [])
        print(f"target=0x{target:08X} callsites={len(rows)}")
        for image_name, site in rows[:80]:
            print(f"  {image_name} 0x{site:08X}")
            for a, text, lit, s in context_literals(aud, site)[:10]:
                if s:
                    print(f'    LIT 0x{a:08X}: {text} -> 0x{lit:08X} "{s}"')
            bucket[(image_name, site & ~0xFF)][target].append(site)

    hline("E. CO-CALL WINDOWS")
    ranked = []
    for key, d in bucket.items():
        ranked.append((len(d), sum(len(v) for v in d.values()), key, d))
    ranked.sort(reverse=True)
    shown = 0
    for unique, count, (image_name, base), d in ranked:
        if unique < 2:
            continue
        shown += 1
        print(f"{image_name} 0x{base:08X}..0x{base+0xFF:08X}: unique_targets={unique} calls={count}")
        for target, sites in sorted(d.items()):
            print(f"  0x{target:08X}: " + ", ".join(f"0x{x:08X}" for x in sites))
        if shown >= 40:
            break
    if shown == 0:
        print("none")

    hline("F. INIT POINTER CONTEXT")
    ptr_context(aud, m.INITPTR_8569, "8569")
    ptr_context(aud, m.INITPTR_86C0, "86C0")
    ptr_context(aud, m.INITPTR_8928, "8928")

    hline("G. CLOSURE SIGNATURE COMPARISON")
    for a, b in (("8569", "86C0"), ("8569", "8928"), ("86C0", "8928")):
        sa = profiles[a][4]
        sb = profiles[b][4]
        inter = sa & sb
        union = sa | sb
        print(f"{a} vs {b}: shared={len(inter)} union={len(union)} jaccard={(len(inter)/len(union) if union else 1.0):.4f}")
        if inter:
            print("  shared:", ", ".join(f"0x{x:08X}" for x in sorted(inter)[:80]))

    hline("H. DECISION GATE")
    p8569 = profiles["8569"]
    p86 = m.shortest_path(p8569[1], m.INIT_8569, m.INIT_86C0)
    p89 = m.shortest_path(p8569[1], m.INIT_8569, m.INIT_8928)
    pap = m.shortest_path(p8569[1], m.INIT_8569, m.AUDIO_PLAYER)
    tokens = token_rows(p8569[3])
    audio_hits = [x for x in tokens if x[0] in {"audio", "audios", "music", "mp3", "sound", "radio", "fm"}]
    visual_hits = [x for x in tokens if x[0] in {"image", "photo", "camera", "video"}]
    print(f"8569 path->86C0={bool(p86)} path->8928={bool(p89)} path->PLAYER={bool(pap)}")
    print(f"8569 audio/music tokens={len(audio_hits)} visual tokens={len(visual_hits)}")
    print(f"8569 overlap with 86C0={len(p8569[4] & profiles['86C0'][4])}")
    print(f"8569 overlap with 8928={len(p8569[4] & profiles['8928'][4])}")
    if p89 or pap:
        print("RESULT: deeper static convergence to the confirmed Audio chain exists.")
        print("NEXT: isolate the first converging edge and its UI/resource owner.")
    elif audio_hits:
        print("RESULT: semantic Audio/Music evidence exists without callgraph convergence.")
        print("NEXT: trace the exact resource/event carrying that relation.")
    elif visual_hits:
        print("RESULT: visual-media semantic evidence exists; 8569-as-Audio is further weakened.")
        print("NEXT: pivot to the 86C0/8928 owner/resource consumers.")
    else:
        print("RESULT: no direct semantic or callgraph proof identifies 8569 as Audio.")
        print("NEXT: use reverse-call, co-call and pointer contexts to select one owner/resource trace.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
