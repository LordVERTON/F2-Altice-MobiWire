#!/usr/bin/env python3
"""
S13.5A.18 - MULTIMEDIA VISIBLE-LABEL / RESOLVER-ANCHOR AUDIT

STRICTLY OFFLINE / READ-ONLY.

S13.5A.17 closed the generic menu framework:

    UI zero-based index
      -> SELECT_CB(index)
      -> descriptor.children[index]
      -> descriptor+0x18 selected child
      -> enter submenu: +0x18 -> +0x14
      -> provider-backed rebuild

The active task is now concrete:
  identify the numeric menu ID corresponding to the visible "Multimedia"
  node, identify its real children, and determine whether Audio 0x8928 is
  absent or merely filtered.

This pass deliberately uses visible/resource anchors first, then resolver IDs.

Evidence lanes:
  A. canonical ALICE/ZIMAGE verification;
  B. exact visible-label search in ASCII / UTF-16LE:
       Multimedia, Image Viewer, FM Radio, Audio Player
     plus a few capitalization/French variants;
  C. real PC-literal / ADR xrefs to those strings;
  D. resolver-table correlation:
       ID -> callback, callback/enclosing function -> label xref;
  E. exact ID constants 0x8313 / 0x8321 / 0x8928:
       literal loads + MOVW occurrences;
  F. structurally referenced u16-array candidates around Image IDs;
  G. rank candidates that also contain discovered FM IDs or Audio 0x8928;
  H. strict decision gate.

Raw co-location alone is NEVER promoted as menu membership.
No patch is generated.

NO USB/COM.
NO PHONE ACCESS.
NO FLASH WRITE.
NO PATCH.
NO REPACK.
"""

from __future__ import annotations

import argparse
import hashlib
import io
import struct
import sys
import unicodedata
from dataclasses import dataclass
from pathlib import Path

from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_THUMB, CS_MODE_LITTLE_ENDIAN
from capstone.arm import ARM_OP_IMM, ARM_OP_MEM, ARM_OP_REG, ARM_REG_PC

ALICE_BASE = 0x1024EC00
ALICE_SIZE = 0x157BB4
ALICE_SHA256 = "7246242b67afae0d13104452bc3257827cb778119b54e7a26fb7fb55993697ea"

ZIMAGE_BASE = 0xF023CA50
ZIMAGE_SIZE = 0x185E98
ZIMAGE_SHA256 = "85fba8c8ae8161e4c1f8ced7983ec30d48c54ab10e51c69fcdfb900aca220954"

RESOLVER_BASE = 0xF0345E68
RESOLVER_COUNT = 58
RESOLVER_STRIDE = 8

KNOWN_IDS = {
    0x8313: "IMAGE_A",
    0x8321: "IMAGE_B",
    0x8928: "AUDIO",
}

KNOWN_CALLBACKS = {
    0x8313: 0xF02F3F84,
    0x8321: 0xF02F3F84,
    0x8928: 0x1033D840,
}

LABEL_GROUPS = {
    "MULTIMEDIA": [
        "Multimedia",
        "MULTIMEDIA",
        "multimedia",
        "Multimédia",
        "MULTIMÉDIA",
    ],
    "IMAGE_VIEWER": [
        "Image Viewer",
        "IMAGE VIEWER",
        "Image viewer",
        "Visionneuse d'images",
        "Visionneuse",
    ],
    "FM_RADIO": [
        "FM Radio",
        "FM RADIO",
        "Radio FM",
        "RADIO FM",
    ],
    "AUDIO_PLAYER": [
        "Audio Player",
        "AUDIO PLAYER",
        "Audio player",
        "Lecteur audio",
        "LECTEUR AUDIO",
    ],
}

md_t = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_LITTLE_ENDIAN)
md_t.detail = True
md_a = Cs(CS_ARCH_ARM, CS_MODE_ARM | CS_MODE_LITTLE_ENDIAN)
md_a.detail = True


class Tee:
    def __init__(self, *streams):
        self.streams = streams

    def write(self, s):
        for st in self.streams:
            st.write(s)
        return len(s)

    def flush(self):
        for st in self.streams:
            st.flush()


@dataclass
class Image:
    name: str
    data: bytes
    base: int

    @property
    def end(self):
        return self.base + len(self.data)

    def contains(self, addr: int):
        return self.base <= addr < self.end

    def off(self, addr: int):
        return addr - self.base


@dataclass
class StringHit:
    image: str
    group: str
    variant: str
    encoding: str
    addr: int
    size: int


@dataclass
class ResolverRow:
    index: int
    addr: int
    menu_id: int
    field2: int
    callback_ptr: int

    @property
    def callback(self):
        return self.callback_ptr & ~1


def banner(s: str):
    print()
    print("=" * 136)
    print(s)
    print("=" * 136)


def sha256(data: bytes):
    return hashlib.sha256(data).hexdigest()


def u16(data: bytes, off: int):
    if off < 0 or off + 2 > len(data):
        return None
    return struct.unpack_from("<H", data, off)[0]


def u32(data: bytes, off: int):
    if off < 0 or off + 4 > len(data):
        return None
    return struct.unpack_from("<I", data, off)[0]


def verify(path: Path, name: str, base: int, size: int, expected_sha: str):
    if not path.is_file():
        raise SystemExit(f"ABORT: missing canonical {name}: {path}")

    data = path.read_bytes()
    got = sha256(data)

    print(f"{name} = {path}")
    print(f"  runtime base = 0x{base:08X}")
    print(f"  size         = 0x{len(data):X}")
    print(f"  sha256       = {got}")

    if len(data) != size:
        raise SystemExit(f"ABORT: {name} size mismatch")

    if got.lower() != expected_sha.lower():
        raise SystemExit(f"ABORT: {name} SHA256 mismatch")

    print(f"[PASS] canonical {name}")
    return Image(name, data, base)


def image_for(images, addr: int):
    a = addr & ~1
    for img in images:
        if img.contains(a):
            return img
    return None


def decode1(img: Image, addr: int, mode="THUMB"):
    if not img.contains(addr):
        return None

    md = md_t if mode == "THUMB" else md_a
    xs = list(md.disasm(img.data[img.off(addr):img.off(addr)+4], addr, count=1))
    return xs[0] if xs else None


def dis(img: Image, start: int, end: int, mode="THUMB"):
    if not img.contains(start):
        return []

    md = md_t if mode == "THUMB" else md_a
    end = min(end, img.end)

    return [
        x for x in md.disasm(img.data[img.off(start):img.off(end)], start)
        if x.address < end
    ]


def fmt(x):
    return f"0x{x.address:08X}: {x.bytes.hex(' '):<14} {x.mnemonic:<9} {x.op_str}"


def direct_target(x):
    if x is None or x.mnemonic not in {"b", "bl", "blx"} or not x.operands:
        return None

    op = x.operands[0]
    if op.type == ARM_OP_IMM:
        return op.imm & 0xFFFFFFFF

    return None


def literal_load(img: Image, x, mode="THUMB"):
    if x is None or not x.mnemonic.startswith("ldr") or len(x.operands) < 2:
        return None

    d, s = x.operands[0], x.operands[1]

    if d.type != ARM_OP_REG or s.type != ARM_OP_MEM or s.mem.base != ARM_REG_PC:
        return None

    pc = ((x.address + 4) & ~3) if mode == "THUMB" else (x.address + 8)
    la = (pc + s.mem.disp) & 0xFFFFFFFF

    if not img.contains(la):
        return None

    return x.reg_name(d.reg), d.reg, la, u32(img.data, img.off(la))


def print_region(img: Image, start: int, end: int, mode="THUMB", marks=None):
    marks = marks or set()

    for x in dis(img, start, end, mode):
        notes = []

        t = direct_target(x)
        if t is not None:
            notes.append(f"target=0x{t:08X}")

        li = literal_load(img, x, mode)
        if li:
            rn, _, la, val = li
            notes.append(f"literal@0x{la:08X}=0x{val:08X}->{rn}")

        mark = ">>>" if x.address in marks else "   "
        print(mark, fmt(x) + ((" ; " + ", ".join(notes)) if notes else ""))


def all_hits(data: bytes, needle: bytes):
    out = []
    pos = 0

    while True:
        pos = data.find(needle, pos)
        if pos < 0:
            return out
        out.append(pos)
        pos += 1


def is_prologue(x):
    return bool(x and x.mnemonic == "push" and "lr" in x.op_str)


def candidate_prologues(img: Image, target: int, back=0x500, forward=0x900):
    lo = max(img.base, target-back) & ~1
    out = []

    for a in range(lo, target+1, 2):
        x = decode1(img, a, "THUMB")
        if not is_prologue(x):
            continue

        xs = dis(img, a, min(img.end, a+forward), "THUMB")
        if any(z.address == target for z in xs):
            out.append(a)

    return out


def enclosing_start(img: Image, target: int):
    cands = candidate_prologues(img, target)
    return cands[-1] if cands else None


def find_string_hits(img: Image):
    hits = []
    seen = set()

    for group, variants in LABEL_GROUPS.items():
        for variant in variants:
            encodings = [
                ("ASCII", variant.encode("utf-8")),
                ("UTF16LE", variant.encode("utf-16le")),
            ]

            for enc_name, pat in encodings:
                for off in all_hits(img.data, pat):
                    key = (group, enc_name, off)
                    if key in seen:
                        continue
                    seen.add(key)
                    hits.append(
                        StringHit(
                            image=img.name,
                            group=group,
                            variant=variant,
                            encoding=enc_name,
                            addr=img.base+off,
                            size=len(pat),
                        )
                    )

    return sorted(hits, key=lambda h: (h.group,h.addr,h.encoding,h.variant))


def pointer_words_to_value(img: Image, value: int):
    out = []

    for off in all_hits(img.data, struct.pack("<I", value & 0xFFFFFFFF)):
        out.append(img.base+off)

    return out


def real_literal_xrefs_to_word(img: Image, word_addr: int):
    out = []

    # Thumb literal users.
    for a in range(max(img.base,word_addr-0x500)&~1, word_addr+1, 2):
        x = decode1(img,a,"THUMB")
        li = literal_load(img,x,"THUMB") if x else None
        if li and li[2] == word_addr:
            out.append(("THUMB",x,li[3]))

    # ARM literal users.
    for a in range(max(img.base,word_addr-0x1000)&~3, word_addr+1, 4):
        x = decode1(img,a,"ARM")
        li = literal_load(img,x,"ARM") if x else None
        if li and li[2] == word_addr:
            out.append(("ARM",x,li[3]))

    uniq = {(m,x.address):(m,x,v) for m,x,v in out}
    return [uniq[k] for k in sorted(uniq)]


def adr_target(x):
    if x is None or x.mnemonic != "adr" or len(x.operands)<2:
        return None

    if x.operands[1].type == ARM_OP_IMM:
        return x.operands[1].imm & 0xFFFFFFFF

    return None


def adr_xrefs(img: Image, target: int):
    out = []

    # ADR is mainly useful in Thumb here.
    for off in range(0,len(img.data)-4,2):
        x = decode1(img,img.base+off,"THUMB")
        if x is None or x.mnemonic != "adr":
            continue

        t = adr_target(x)
        if t == target:
            out.append(x)

    return out


def string_xrefs(img: Image, hit: StringHit):
    out = []

    for word_addr in pointer_words_to_value(img,hit.addr):
        for mode,x,val in real_literal_xrefs_to_word(img,word_addr):
            out.append(
                {
                    "kind":"LITERAL_PTR",
                    "mode":mode,
                    "x":x,
                    "word_addr":word_addr,
                    "loaded":val,
                }
            )

    for x in adr_xrefs(img,hit.addr):
        out.append(
            {
                "kind":"ADR",
                "mode":"THUMB",
                "x":x,
                "word_addr":None,
                "loaded":hit.addr,
            }
        )

    uniq={}
    for r in out:
        uniq[(r["kind"],r["mode"],r["x"].address,r["word_addr"])] = r
    return [uniq[k] for k in sorted(uniq,key=lambda q:(q[2],q[0]))]


def parse_resolver(zimage: Image):
    rows = []

    if not zimage.contains(RESOLVER_BASE):
        raise SystemExit("ABORT: resolver base outside canonical ZIMAGE")

    off = zimage.off(RESOLVER_BASE)

    for i in range(RESOLVER_COUNT):
        roff = off + i*RESOLVER_STRIDE

        menu_id = u16(zimage.data,roff)
        field2 = u16(zimage.data,roff+2)
        cb = u32(zimage.data,roff+4)

        rows.append(
            ResolverRow(
                index=i,
                addr=RESOLVER_BASE+i*RESOLVER_STRIDE,
                menu_id=menu_id,
                field2=field2,
                callback_ptr=cb,
            )
        )

    return rows


def correlate_xref_with_resolver(images, rows, xref_img: Image, x):
    """
    Return exact/enclosing/proximity resolver matches.

    Exact callback function start is strongest.
    Proximity is SUPPORTING ONLY.
    """
    fs = enclosing_start(xref_img,x.address)

    exact=[]
    enclosing=[]
    near=[]

    for row in rows:
        cb=row.callback
        if cb == x.address:
            exact.append(row)

        if fs is not None and cb == fs:
            enclosing.append(row)

        if abs(cb - x.address) <= 0x200:
            near.append(row)

    return fs,exact,enclosing,near


def real_literal_xrefs_for_value(img: Image,value: int):
    out=[]

    for word_addr in pointer_words_to_value(img,value):
        for mode,x,val in real_literal_xrefs_to_word(img,word_addr):
            if val == value:
                out.append((mode,x,word_addr))

    uniq={(m,x.address,w):(m,x,w) for m,x,w in out}
    return [uniq[k] for k in sorted(uniq)]


def scan_movw_ids(img: Image):
    hits=[]

    for off in range(0,len(img.data)-4,2):
        a=img.base+off
        xs=list(md_t.disasm(img.data[off:off+4],a,count=1))
        if not xs:
            continue

        x=xs[0]
        if x.mnemonic != "movw" or len(x.operands)<2:
            continue

        if x.operands[1].type != ARM_OP_IMM:
            continue

        imm=x.operands[1].imm & 0xFFFF
        if imm in KNOWN_IDS:
            hits.append((x,imm))

    return hits


def classify_id_constant_context(img: Image, x, menu_id: int):
    fs=enclosing_start(img,x.address)
    lo=max(img.base,x.address-0x20)
    hi=min(img.end,x.address+0x30)

    return fs,lo,hi


def plausible_menu_id(v: int):
    if v in {0,0xFFFF}:
        return False

    # Deliberately broad. This is only ranking/support.
    return 0x1000 <= v <= 0xBFFF


def pointer_refs_to_region(images, addr: int):
    """
    Find exact pointer words equal to addr across canonical images,
    then count real literal users of those pointer words.
    """
    refs=[]

    for img in images:
        for waddr in pointer_words_to_value(img,addr):
            lx=real_literal_xrefs_to_word(img,waddr)
            refs.append((img,waddr,lx))

    return refs


def child_array_candidates(images, img: Image, anchor_id: int, other_ids: set[int]):
    """
    Around each raw u16 anchor, try possible starts up to 8 u16 before it.
    Keep only candidate starts with a concrete pointer/reference signal.

    This does NOT prove registry membership.
    """
    pat=struct.pack("<H",anchor_id)
    candidates=[]

    for off in all_hits(img.data,pat):
        anchor_addr=img.base+off

        for back_words in range(0,9):
            start_off=off-back_words*2
            if start_off < 0:
                continue

            vals=[]
            for i in range(16):
                v=u16(img.data,start_off+i*2)
                if v is None:
                    break
                vals.append(v)

            if not vals or anchor_id not in vals:
                continue

            # Require at least two broadly menu-like 16-bit values.
            menu_like=[v for v in vals if plausible_menu_id(v)]
            if len(menu_like)<2:
                continue

            start_addr=img.base+start_off
            refs=pointer_refs_to_region(images,start_addr)

            # Exact pointer reference is required to call it STRUCTURALLY REFERENCED.
            if not refs:
                continue

            contains_other=sorted(set(vals) & other_ids)
            candidates.append(
                {
                    "img":img,
                    "start":start_addr,
                    "anchor":anchor_addr,
                    "vals":vals,
                    "refs":refs,
                    "contains_other":contains_other,
                }
            )

    # dedup by image/start
    uniq={}
    for c in candidates:
        key=(c["img"].name,c["start"])
        old=uniq.get(key)
        if old is None or len(c["contains_other"]) > len(old["contains_other"]):
            uniq[key]=c

    return [uniq[k] for k in sorted(uniq,key=lambda q:(q[0],q[1]))]


def local_u16_window(img: Image, addr: int, before=8, after=12):
    off=img.off(addr)
    lo=max(0,off-before*2)
    vals=[]

    for i in range(before+after+1):
        o=lo+i*2
        if o+2>len(img.data):
            break
        vals.append((img.base+o,u16(img.data,o)))

    return vals


def search_optional_dump(path: Path):
    if not path or not path.is_file():
        return []

    data=path.read_bytes()
    out=[]

    for group,variants in LABEL_GROUPS.items():
        for variant in variants:
            for enc_name,pat in (
                ("ASCII",variant.encode("utf-8")),
                ("UTF16LE",variant.encode("utf-16le")),
            ):
                for off in all_hits(data,pat):
                    out.append((group,variant,enc_name,off))

    return out


def parse_args():
    p=argparse.ArgumentParser()

    p.add_argument(
        "--alice",
        default="research/f2/work/extracted/altice_alice/alice-py.bin",
    )

    p.add_argument(
        "--zimage",
        default="research/f2/work/extracted/altice_platform/zimage.bin",
    )

    p.add_argument(
        "--dump",
        default="research/f2/data/dumps/mobiwire_dump_2.bin",
        help="Optional raw dump used only for string-presence support.",
    )

    p.add_argument(
        "--report",
        default="research/f2/work/reports/s13_5a18_multimedia_visible_label_resolver_anchor.txt",
    )

    return p.parse_args()


def resolve(root: Path,s: str):
    p=Path(s)
    return p if p.is_absolute() else root/p


def main():
    args=parse_args()
    root=Path.cwd()

    report_path=resolve(root,args.report)
    report_path.parent.mkdir(parents=True,exist_ok=True)

    cap=io.StringIO()
    old=sys.stdout
    sys.stdout=Tee(old,cap)

    try:
        banner("S13.5A.18 - MULTIMEDIA VISIBLE-LABEL / RESOLVER-ANCHOR AUDIT")
        print("STRICTLY OFFLINE")
        print("PHONE ACCESSED       : NO")
        print("FLASH MODIFIED       : NO")
        print("PATCH GENERATED      : NO")
        print("REPACK               : NO")

        banner("A. CANONICAL INPUTS")
        alice=verify(
            resolve(root,args.alice),
            "ALICE",
            ALICE_BASE,
            ALICE_SIZE,
            ALICE_SHA256,
        )
        zimage=verify(
            resolve(root,args.zimage),
            "ZIMAGE",
            ZIMAGE_BASE,
            ZIMAGE_SIZE,
            ZIMAGE_SHA256,
        )
        images=[alice,zimage]

        rows=parse_resolver(zimage)

        print()
        print(f"resolver rows = {len(rows)}")

        for mid,name in KNOWN_IDS.items():
            rr=[r for r in rows if r.menu_id==mid]
            print(f"{name} 0x{mid:04X}: resolver rows={len(rr)}")
            for r in rr:
                print(
                    f"  row@0x{r.addr:08X} field2=0x{r.field2:04X} "
                    f"callback=0x{r.callback_ptr:08X}"
                )

        banner("B. VISIBLE LABEL SEARCH")
        all_string_hits=[]

        for img in images:
            hits=find_string_hits(img)
            all_string_hits.extend(hits)

            print()
            print(f"{img.name}: label hits = {len(hits)}")

            for h in hits:
                print(
                    f"  {h.group:<14} {h.encoding:<7} "
                    f"0x{h.addr:08X} {h.variant!r}"
                )

        banner("C. STRING XREFS / RESOLVER CORRELATION")
        discovered_label_ids={k:set() for k in LABEL_GROUPS}

        for h in all_string_hits:
            img=next(i for i in images if i.name==h.image)
            refs=string_xrefs(img,h)

            print()
            print(
                f"{h.image} {h.group} {h.encoding} "
                f"string@0x{h.addr:08X} {h.variant!r}"
            )
            print(f"  code xrefs = {len(refs)}")

            for ref in refs:
                x=ref["x"]
                print(
                    f"  {ref['kind']} {ref['mode']} {fmt(x)}"
                    + (
                        f" ; pointer-word@0x{ref['word_addr']:08X}"
                        if ref["word_addr"] is not None else ""
                    )
                )

                if ref["mode"]!="THUMB":
                    continue

                fs,exact,enclosing,near=correlate_xref_with_resolver(
                    images,rows,img,x
                )

                print(
                    f"    enclosing Thumb function = "
                    f"{('0x%08X'%fs) if fs is not None else 'UNKNOWN'}"
                )

                if exact:
                    for r in exact:
                        discovered_label_ids[h.group].add(r.menu_id)
                        print(
                            f"    [EXACT RESOLVER CALLBACK] "
                            f"id=0x{r.menu_id:04X} callback=0x{r.callback:08X}"
                        )

                if enclosing:
                    for r in enclosing:
                        discovered_label_ids[h.group].add(r.menu_id)
                        print(
                            f"    [ENCLOSING FUNCTION == RESOLVER CALLBACK] "
                            f"id=0x{r.menu_id:04X} callback=0x{r.callback:08X}"
                        )

                # Near matches are supporting only.
                if near and not exact and not enclosing:
                    shown=near[:12]
                    print("    nearby resolver callbacks (SUPPORT ONLY):")
                    for r in shown:
                        print(
                            f"      id=0x{r.menu_id:04X} "
                            f"cb=0x{r.callback:08X} "
                            f"delta={r.callback-x.address:+#x}"
                        )

                print("    local context:")
                print_region(
                    img,
                    max(img.base,x.address-0x20),
                    min(img.end,x.address+0x30),
                    ref["mode"],
                    {x.address},
                )

        banner("D. DISCOVERED LABEL -> RESOLVER ID SETS")
        for group in LABEL_GROUPS:
            ids=sorted(discovered_label_ids[group])
            print(
                f"{group:<14}: "
                + (
                    ", ".join(f"0x{x:04X}" for x in ids)
                    if ids else "NONE"
                )
            )

        banner("E. KNOWN ID CONSTANT XREFS")
        for img in images:
            print()
            print(f"### {img.name}")

            for mid,name in KNOWN_IDS.items():
                refs=real_literal_xrefs_for_value(img,mid)
                print(f"{name} 0x{mid:04X}: real literal const xrefs={len(refs)}")

                for mode,x,waddr in refs[:80]:
                    fs=enclosing_start(img,x.address) if mode=="THUMB" else None
                    print(
                        f"  {mode} {fmt(x)} literal-word@0x{waddr:08X} "
                        f"enclosing={('0x%08X'%fs) if fs else 'UNKNOWN'}"
                    )

            movw=scan_movw_ids(img)
            print(f"MOVW known-ID occurrences = {len(movw)}")

            for x,mid in movw[:100]:
                fs=enclosing_start(img,x.address)
                print(
                    f"  {KNOWN_IDS[mid]} 0x{mid:04X}: {fmt(x)} "
                    f"enclosing={('0x%08X'%fs) if fs else 'UNKNOWN'}"
                )

        banner("F. STRUCTURALLY REFERENCED CHILD-ARRAY CANDIDATES")
        discovered_fm_ids=set(discovered_label_ids["FM_RADIO"])
        other_ids=set(KNOWN_IDS) | discovered_fm_ids

        all_candidates=[]

        for img in images:
            for anchor in (0x8313,0x8321):
                cs=child_array_candidates(images,img,anchor,other_ids)
                all_candidates.extend(cs)

        # Dedup.
        uniq={}
        for c in all_candidates:
            key=(c["img"].name,c["start"])
            old=uniq.get(key)
            if old is None or len(c["contains_other"])>len(old["contains_other"]):
                uniq[key]=c
        all_candidates=[uniq[k] for k in sorted(uniq)]

        print(f"structurally referenced candidates = {len(all_candidates)}")

        ranked=[]

        for c in all_candidates:
            vals=c["vals"]
            known=set(vals)&set(KNOWN_IDS)
            fms=set(vals)&discovered_fm_ids

            score=0
            score += 5 if (0x8313 in vals or 0x8321 in vals) else 0
            score += 5*len(fms)
            score += 4 if 0x8928 in vals else 0
            score += min(4,len(c["refs"]))

            ranked.append((score,c,known,fms))

        ranked.sort(key=lambda t:(-t[0],t[1]["img"].name,t[1]["start"]))

        for score,c,known,fms in ranked[:120]:
            print()
            print(
                f"SCORE={score} {c['img'].name} "
                f"candidate@0x{c['start']:08X} "
                f"anchor@0x{c['anchor']:08X}"
            )

            print(
                "  vals = "
                + " ".join(
                    f"{v:04X}"
                    + (
                        f"<{KNOWN_IDS[v]}>"
                        if v in KNOWN_IDS
                        else (
                            "<FM_CANDIDATE>"
                            if v in discovered_fm_ids else ""
                        )
                    )
                    for v in c["vals"]
                )
            )

            print(
                "  known co-members = "
                + (
                    ", ".join(f"0x{x:04X}" for x in sorted(known|fms))
                    if (known or fms) else "NONE"
                )
            )

            print(f"  exact pointer-reference groups = {len(c['refs'])}")

            for ref_img,waddr,lx in c["refs"]:
                print(
                    f"    {ref_img.name}: pointer word@0x{waddr:08X} "
                    f"real code xrefs={len(lx)}"
                )

                for mode,x,val in lx[:12]:
                    print(f"      {mode} {fmt(x)}")

        banner("G. OPTIONAL RAW-DUMP LABEL SUPPORT")
        dump_path=resolve(root,args.dump)

        if dump_path.is_file():
            dh=search_optional_dump(dump_path)
            print(f"dump = {dump_path}")
            print(f"label hits = {len(dh)}")

            for group,variant,enc,off in dh[:200]:
                print(
                    f"  {group:<14} {enc:<7} dump+0x{off:08X} {variant!r}"
                )

            print(
                "NOTE: dump offsets are SUPPORTING ONLY here; no runtime mapping "
                "is inferred by this script."
            )
        else:
            print(f"optional dump not found: {dump_path}")

        banner("H. DECISION GATE")
        multimedia_ids=sorted(discovered_label_ids["MULTIMEDIA"])
        image_label_ids=sorted(discovered_label_ids["IMAGE_VIEWER"])
        fm_ids=sorted(discovered_label_ids["FM_RADIO"])
        audio_label_ids=sorted(discovered_label_ids["AUDIO_PLAYER"])

        strong_arrays=[
            (score,c,known,fms)
            for score,c,known,fms in ranked
            if fms and (0x8313 in c["vals"] or 0x8321 in c["vals"])
        ]

        audio_arrays=[
            (score,c,known,fms)
            for score,c,known,fms in ranked
            if 0x8928 in c["vals"]
            and (0x8313 in c["vals"] or 0x8321 in c["vals"])
        ]

        print(
            "visible Multimedia resolver-ID matches = "
            + (", ".join(f"0x{x:04X}" for x in multimedia_ids) if multimedia_ids else "NONE")
        )
        print(
            "Image Viewer resolver-ID matches        = "
            + (", ".join(f"0x{x:04X}" for x in image_label_ids) if image_label_ids else "NONE")
        )
        print(
            "FM Radio resolver-ID matches            = "
            + (", ".join(f"0x{x:04X}" for x in fm_ids) if fm_ids else "NONE")
        )
        print(
            "Audio Player resolver-ID matches        = "
            + (", ".join(f"0x{x:04X}" for x in audio_label_ids) if audio_label_ids else "NONE")
        )
        print(f"Image+FM referenced array candidates       = {len(strong_arrays)}")
        print(f"Image+Audio referenced array candidates    = {len(audio_arrays)}")
        print()

        if multimedia_ids:
            print("[PASS] A visible-label path directly correlates Multimedia with resolver ID(s).")
            print("[NEXT] Use only those ID(s) as parent candidates and resolve their provider-backed child list.")
        elif strong_arrays:
            print("[PASS] Referenced array candidate(s) contain both a known Image ID and a label-derived FM ID.")
            print("[NEXT] Prove which parent owns the strongest array; do not infer parent from raw proximity.")
        elif fm_ids:
            print("[PASS] FM Radio resolver candidate(s) recovered from visible-label correlation.")
            print("[NEXT] Search provider-backed parent/children ownership for Image + FM siblings.")
        else:
            print("[OPEN] No direct visible-label resolver binding yet.")
            print("[NEXT] Use the string xrefs / ID constant functions printed above to recover resource IDs")
            print("       and callback ownership. Do not return to broad raw-ID co-location.")

        if audio_arrays:
            print()
            print("[IMPORTANT SUPPORT] At least one structurally referenced candidate contains Image + Audio 0x8928.")
            print("This is NOT yet proof that Audio belongs to visible Multimedia; parent ownership is still required.")

        print()
        print("FACTS ENTERING A.18:")
        print("  UI selected index is zero-based")
        print("  SELECT_CB(index) resolves descriptor.children[index]")
        print("  selected child becomes descriptor+0x14 on submenu entry")
        print()
        print("STILL UNKNOWN UNTIL THIS GATE PROVES IT:")
        print("  numeric visible Multimedia ID")
        print("  FM Radio child ID")
        print("  exact Multimedia children[]")
        print("  0x8928 absent vs present-but-filtered")
        print()
        print("PHONE ACCESSED       : NO")
        print("FLASH MODIFIED       : NO")
        print("PATCH GENERATED      : NO")
        print("PHYSICAL CANDIDATE   : NO")
        print("HARDWARE WRITE AUTHORIZED: NO")
        print()
        print(f"REPORT = {report_path}")

        return 0

    finally:
        sys.stdout=old
        report_path.write_text(cap.getvalue(),encoding="utf-8")


if __name__=="__main__":
    raise SystemExit(main())
