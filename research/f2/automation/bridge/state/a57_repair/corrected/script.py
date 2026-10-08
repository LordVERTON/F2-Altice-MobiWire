#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from __future__ import annotations

import os
from collections import defaultdict
import s13_5a51_launcher_dispatch_init_trace as m

TITLE = "S13.5A.57 - 86C0 / 8928 ROOT-MAPPER OWNER DIFFERENTIAL"
TARGET_LABELS = ("86C0_A", "86C0_B", "86C0_C", "8928")
CONTROL_LABEL = "8569"
SEMANTIC_TOKENS = (
    "audio", "audios", "music", "mp3", "sound", "player", "play",
    "file", "folder", "image", "photo", "camera", "video", "radio", "fm",
)


def hline(s):
    print()
    print("=" * 120)
    print(s)
    print("=" * 120)


def context(aud, start, end, marks=None):
    marks = marks or {}
    pc = start & ~1
    while pc < end:
        x = aud.decode_one(pc)
        if x is None:
            pc += 2
            continue
        extra = []
        if x.target is not None:
            norm, via = aud.normalized_target(x.target)
            extra.append(f"target=0x{norm:08X}" + (f"[{via}]" if via else ""))
        if x.literal_value is not None:
            extra.append(f"literal@0x{x.literal_addr:08X}=0x{x.literal_value:08X}")
            s = aud.string_at(x.literal_value)
            if s:
                extra.append(f'STR="{s}"')
        mark = marks.get(pc, "")
        suffix = (" ; " + " ".join(extra)) if extra else ""
        print(f"0x{pc:08X}: {x.text}{suffix}{mark}")
        pc += max(2, x.size)


def reverse_direct_calls(aud, targets):
    targets = {x & ~1 for x in targets}
    out = defaultdict(list)
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


def closure_profile(aud, root, depth=3, max_funcs=180):
    funcs, edges, focus, strings = m.callgraph(aud, root & ~1, depth=depth, max_funcs=max_funcs)
    calls = set()
    globals_ = set()
    string_rows = []
    for fa in funcs.values():
        for _, raw in fa.calls:
            calls.add(aud.normalized_target(raw)[0])
        for _, _, value in fa.literals:
            if 0xF0000000 <= value < 0xF0200000:
                globals_.add(value)
    seen = set()
    for entry, site, ptr, s in strings:
        key = (ptr, s)
        if key not in seen:
            seen.add(key)
            string_rows.append((entry, site, ptr, s))
    return {"funcs": funcs, "edges": edges, "focus": focus, "strings": string_rows, "calls": calls, "globals": globals_}


def semantic_strings(rows):
    out = []
    for entry, site, ptr, s in rows:
        low = s.lower()
        hits = [t for t in SEMANTIC_TOKENS if t in low]
        if hits:
            out.append((hits, entry, site, ptr, s))
    return out


def print_profile(label, root, p):
    print(f"{label}: root=0x{root:08X} funcs={len(p['funcs'])} calls={len(p['calls'])} globals={len(p['globals'])} strings={len(p['strings'])}")
    sem = semantic_strings(p["strings"])
    print(f"  semantic_strings={len(sem)}")
    semkeys = {(row[3], row[4]) for row in sem}
    for hits, entry, site, ptr, s in sem[:60]:
        print(f'  TOK={",".join(hits)} func=0x{entry:08X} site=0x{site:08X} ptr=0x{ptr:08X} "{s}"')
    for entry, site, ptr, s in p["strings"][:40]:
        if (ptr, s) in semkeys:
            continue
        print(f'  STR func=0x{entry:08X} site=0x{site:08X} ptr=0x{ptr:08X} "{s}"')


def forward_use(aud, callsite, span=0x28):
    pc = callsite + 4
    end = callsite + span
    while pc < end:
        x = aud.decode_one(pc)
        if x is None:
            pc += 2
            continue
        extra = []
        if x.target is not None:
            norm, via = aud.normalized_target(x.target)
            extra.append(f"target=0x{norm:08X}" + (f"[{via}]" if via else ""))
        if x.literal_value is not None:
            extra.append(f"literal=0x{x.literal_value:08X}")
        suffix = (" ; " + " ".join(extra)) if extra else ""
        print(f"  0x{pc:08X}: {x.text}{suffix}")
        if m.StaticAudit.is_return(x.text):
            break
        pc += max(2, x.size)


def main():
    print("=" * 120)
    print(TITLE)
    print("=" * 120)
    if os.environ.get("F2_AUTOMATION_OFFLINE") != "1":
        raise SystemExit("offline automation marker missing")

    hline("A. CANONICAL IMAGE GUARDS")
    alice, zimage = m.load_images()
    aud = m.StaticAudit(alice, zimage)
    contexts = {label: (owner, load, call) for label, owner, load, call in m.MAPPER_CONTEXTS}

    hline("B. PROVEN ROOT_MAPPER CALL CONTEXTS")
    profiles = {}
    owner_targets = set()
    for label in (CONTROL_LABEL,) + TARGET_LABELS:
        owner, load, call = contexts[label]
        owner_targets.add(owner)
        print(f"\n{label}: owner=0x{owner:08X} load=0x{load:08X} root_mapper_call=0x{call:08X}")
        context(aud, max(owner, call - 0x50), call + 0x30, {load: " <ID_LOAD>", call: " <ROOT_MAPPER_CALL>"})
        print("  POST-CALL USE:")
        forward_use(aud, call)
        p = closure_profile(aud, owner, depth=3)
        profiles[label] = p
        print_profile(label, owner, p)

    hline("C. REVERSE DIRECT CALLERS OF OWNER FUNCTIONS")
    reverse = reverse_direct_calls(aud, owner_targets)
    for label in (CONTROL_LABEL,) + TARGET_LABELS:
        owner = contexts[label][0]
        rows = reverse.get(owner & ~1, [])
        print(f"{label} owner=0x{owner:08X}: direct_callers={len(rows)}")
        for image_name, site, raw, via in rows[:80]:
            print(f"  {image_name} 0x{site:08X} raw=0x{raw:08X} via={via or 'DIRECT'}")
            context(aud, site - 0x18, site + 0x10, {site: " <OWNER_CALL>"})
        if len(rows) > 80:
            print("  ... truncated")

    hline("D. 86C0 OWNER-FAMILY UNION VS 8928 OWNER")
    union_86_calls = set()
    union_86_globals = set()
    union_86_strings = []
    seen_strings = set()
    for label in ("86C0_A", "86C0_B", "86C0_C"):
        p = profiles[label]
        union_86_calls |= p["calls"]
        union_86_globals |= p["globals"]
        for row in p["strings"]:
            key = (row[2], row[3])
            if key not in seen_strings:
                seen_strings.add(key)
                union_86_strings.append(row)
    p8928 = profiles["8928"]
    shared_calls = union_86_calls & p8928["calls"]
    shared_globals = union_86_globals & p8928["globals"]
    print(f"86C0 owner union calls={len(union_86_calls)} globals={len(union_86_globals)} strings={len(union_86_strings)}")
    print(f"8928 owner calls={len(p8928['calls'])} globals={len(p8928['globals'])} strings={len(p8928['strings'])}")
    print(f"shared_calls={len(shared_calls)} shared_globals={len(shared_globals)}")
    if shared_calls:
        print("shared call targets:", ", ".join(f"0x{x:08X}" for x in sorted(shared_calls)[:120]))
    if shared_globals:
        print("shared globals:", ", ".join(f"0x{x:08X}" for x in sorted(shared_globals)[:120]))
    print("\n86C0 union semantic strings:")
    for hits, entry, site, ptr, s in semantic_strings(union_86_strings):
        print(f'  TOK={",".join(hits)} func=0x{entry:08X} site=0x{site:08X} ptr=0x{ptr:08X} "{s}"')
    print("\n8928 semantic strings:")
    for hits, entry, site, ptr, s in semantic_strings(p8928["strings"]):
        print(f'  TOK={",".join(hits)} func=0x{entry:08X} site=0x{site:08X} ptr=0x{ptr:08X} "{s}"')

    hline("E. REGISTRATION CALLBACK / INIT DIFFERENTIAL")
    focus_roots = {
        "CB_86C0": m.CB_86C0,
        "CB_8928": m.CB_8928,
        "INIT_86C0": m.INIT_86C0,
        "INIT_8928": m.INIT_8928,
        "AUDIO_PLAYER": m.AUDIO_PLAYER,
    }
    root_profiles = {}
    for label, root in focus_roots.items():
        p = closure_profile(aud, root, depth=4)
        root_profiles[label] = p
        print_profile(label, root, p)
        for target_label, target in (("INIT_8928", m.INIT_8928), ("AUDIO_PLAYER", m.AUDIO_PLAYER)):
            path = m.shortest_path(p["edges"], root & ~1, target & ~1)
            print(f"  path->{target_label}: " + (" -> ".join(f"0x{x:08X}" for x in path) if path else "NONE"))

    hline("F. GLOBAL-LITERAL FINGERPRINTS")
    for a, b in (("CB_86C0", "CB_8928"), ("INIT_86C0", "INIT_8928"), ("INIT_86C0", "AUDIO_PLAYER"), ("INIT_8928", "AUDIO_PLAYER")):
        ga = root_profiles[a]["globals"]
        gb = root_profiles[b]["globals"]
        inter = ga & gb
        print(f"{a} vs {b}: shared_globals={len(inter)} union={len(ga|gb)}")
        if inter:
            print("  shared:", ", ".join(f"0x{x:08X}" for x in sorted(inter)[:120]))

    hline("G. REVERSE DIRECT CALLERS OF AUDIO ROOTS")
    rev_audio = reverse_direct_calls(aud, (m.CB_86C0, m.CB_8928, m.INIT_86C0, m.INIT_8928, m.AUDIO_PLAYER))
    for label, root in focus_roots.items():
        rows = rev_audio.get(root & ~1, [])
        print(f"{label} 0x{root:08X}: direct_callers={len(rows)}")
        for image_name, site, raw, via in rows[:80]:
            print(f"  {image_name} 0x{site:08X} raw=0x{raw:08X} via={via or 'DIRECT'}")
            context(aud, site - 0x18, site + 0x10, {site: " <CALL>"})
        if len(rows) > 80:
            print("  ... truncated")

    hline("H. DECISION GATE")
    sem86 = semantic_strings(union_86_strings)
    sem89 = semantic_strings(p8928["strings"])
    audios86 = [x for x in sem86 if any(t in x[0] for t in ("audios", "audio", "music"))]
    player89 = [x for x in sem89 if any(t in x[0] for t in ("player", "audio", "music"))]
    p86_to_89 = m.shortest_path(root_profiles["INIT_86C0"]["edges"], m.INIT_86C0, m.INIT_8928)
    p86_to_player = m.shortest_path(root_profiles["INIT_86C0"]["edges"], m.INIT_86C0, m.AUDIO_PLAYER)
    p89_to_player = m.shortest_path(root_profiles["INIT_8928"]["edges"], m.INIT_8928, m.AUDIO_PLAYER)
    print(f"86C0 owner audio/music semantic strings={len(audios86)}")
    print(f"8928 owner audio/music/player semantic strings={len(player89)}")
    print(f"INIT_86C0 -> INIT_8928 path={bool(p86_to_89)}")
    print(f"INIT_86C0 -> AUDIO_PLAYER path={bool(p86_to_player)}")
    print(f"INIT_8928 -> AUDIO_PLAYER path={bool(p89_to_player)}")
    print(f"86C0/8928 owner shared_calls={len(shared_calls)} shared_globals={len(shared_globals)}")
    if p89_to_player and not p86_to_player:
        print("FACT: the confirmed 8928 init reaches the native Audio Player while 86C0 init does not in the same bounded model.")
    if audios86:
        print("SUPPORTED: 86C0 owner/init side carries Audio-folder/domain semantics distinct from direct player launch.")
    if p89_to_player and audios86 and not p86_to_player:
        print("STRONGLY SUPPORTED: 86C0 is an Audio-domain owner/browser/helper role, while 8928 is the native player application role.")
        print("NEXT: trace the B702-visible/menu builder consumer that chooses between enumerated children and logical-parent 86C0/8928, rather than patching either init path.")
    else:
        print("Role split remains incomplete.")
        print("NEXT: use the owner contexts, reverse callers, and global fingerprints above to select the smallest discriminating relation between 86C0 and 8928.")
    print()
    print("PHONE ACCESSED       : NO")
    print("FLASH MODIFIED       : NO")
    print("PATCH GENERATED      : NO")
    print("PHYSICAL CANDIDATE   : NO")
    print("HARDWARE WRITE AUTHORIZED: NO")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
