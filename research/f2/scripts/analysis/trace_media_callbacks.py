#!/usr/bin/env python3
"""Reproduce the targeted callback-pointer, xref, and MMI-wrapper inventory."""
import json
import re
import struct
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from _paths import ALTICE_ALICE, ALTICE_PACKAGE, DUMP_MAIN, GHIDRA_REPORTS, REPO_ROOT

ROOT=REPO_ROOT
BASE=0x101812C4
SLOTS=[
 {"slot":0,"offset":0x00,"cell":0x10236314,"raw":0x1028D231,"target":0x1028D230},
 {"slot":1,"offset":0x04,"cell":0x10236318,"raw":0x1029D3BD,"target":0x1029D3BC},
 {"slot":2,"offset":0x08,"cell":0x1023631C,"raw":0x1028D395,"target":0x1028D394},
 {"slot":3,"offset":0x0C,"cell":0x10236320,"raw":0x1028D4C1,"target":0x1028D4C0},
 {"slot":4,"offset":0x10,"cell":0x10236324,"raw":0x1028D379,"target":0x1028D378},
 {"slot":5,"offset":0x14,"cell":0x10236328,"raw":0x1028D41D,"target":0x1028D41C},
 {"slot":6,"offset":0x18,"cell":0x1023632C,"raw":0x1028D43B,"target":0x1028D43A},
 {"slot":7,"offset":0x1C,"cell":0x10236330,"raw":0x1028D115,"target":0x1028D114},
 {"slot":8,"offset":0x20,"cell":0x10236334,"raw":0x1028D0D5,"target":0x1028D0D4},
 {"slot":9,"offset":0x24,"cell":None,"raw":None,"target":None,"source":"return value from thunk 0x1022FA68"},
]
FILES={
 "dump":DUMP_MAIN,
 "ROM":ALTICE_PACKAGE/"DL188_GX1882_NIKITI_PCB01_gsm_MT6261_S00"/"ROM",
 "VIVA":ALTICE_ALICE/"altice_VIVA.bin",
 "ALICE_compressed":ALTICE_ALICE/"altice_ALICE_2.bin",
 "ALICE_decompressed":ALTICE_ALICE/"alice-py.bin",
 "service_image":ALTICE_PACKAGE/"DL188_GX1882_NIKITI_PCB01_gsm_MT6261_S00.ALTICE_F2_DS_V02_1_181023_MP.bin",
}
DETAILS=GHIDRA_REPORTS/"altice_details.jsonl"

def load_funcs():
    return {f["entry"].lower():f for f in (json.loads(x) for x in DETAILS.open(encoding="utf-8") if x.strip())}

def calls(f):
    return [i for i in f.get("instructions",[]) if i.get("call")]

def fmt_context(data,off,radius=0x40):
    lo=max(0,off-radius); hi=min(len(data),off+4+radius)
    return {"start":lo,"end":hi,"hex":data[lo:hi].hex(" ")}

def main():
    funcs=load_funcs(); data_by_file={}; raw_hits=[]
    for label,path in FILES.items():
        if not path.exists(): continue
        data=path.read_bytes(); data_by_file[label]=data
        for slot in SLOTS:
            raw=slot.get("raw")
            if raw is None: continue
            for value in sorted({raw,raw&~1}):
                needle=struct.pack("<I",value); pos=0
                while True:
                    off=data.find(needle,pos)
                    if off<0: break
                    hit={"file":label,"path":str(path),"slot":slot["slot"],"offset":off,
                         "value":value,"address":hex(BASE+off) if label=="ALICE_decompressed" else None,
                         "context":fmt_context(data,off)}
                    raw_hits.append(hit); pos=off+1
    # Explicit context: compressed ALICE_2 occupies a well-defined slice of VIVA.
    viva=data_by_file.get("VIVA",b""); comp=data_by_file.get("ALICE_compressed",b"")
    viva_alice_rel=0x0018129C-0x0004C20C
    outside_hits=[]
    if viva and comp and viva[viva_alice_rel:viva_alice_rel+len(comp)]==comp:
        outside=viva[:viva_alice_rel]+viva[viva_alice_rel+len(comp):]
        for s in SLOTS:
            if s.get("raw") is None: continue
            for value in {s["raw"],s["raw"]&~1}:
                p=0; n=struct.pack("<I",value)
                while (p:=outside.find(n,p))>=0:
                    outside_hits.append({"slot":s["slot"],"value":hex(value),"outside_viva_offset":hex(p)})
                    p+=1
    constructor=funcs.get("102362a4",{})
    callers=funcs.get("101b31fc",{})
    owner=funcs.get("10214940",{})
    callback=funcs.get("1028d114",{})
    # Simple load-field then BLX scan. These are structural candidates only;
    # matching an offset alone cannot prove that the loaded object is this vtable.
    indirect=[]
    loadpat=re.compile(r"ldr\s+(r\d+),\s*\[(r\d+)(?:,#0x([0-9a-f]+))?\]",re.I)
    blxpat=re.compile(r"blx\s+(r\d+)\b",re.I)
    for f in funcs.values():
        ins=f.get("instructions",[])
        for idx,i in enumerate(ins):
            m=loadpat.search(i.get("text",""))
            if not m: continue
            off=int(m.group(3) or "0",16); reg=m.group(1)
            for j in range(idx+1,min(len(ins),idx+8)):
                cm=blxpat.search(ins[j].get("text",""))
                if cm and cm.group(1).lower()==reg.lower():
                    indirect.append({"function":f["entry"],"load":i["address"],"load_text":i["text"],
                                     "call":ins[j]["address"],"call_text":ins[j]["text"],"field_offset":off})
                    break
    # Source-file references are reliable module breadcrumbs, not semantic labels.
    source_refs=[]
    for f in funcs.values():
        for i in f.get("instructions",[]):
            for r in i.get("refs",[]):
                s=r.get("string")
                if s and re.search(r"\.c[\"']?$",s,re.I):
                    source_refs.append({"function":f["entry"],"instruction":i["address"],"source":s})
    # UI/resource fingerprint: direct-call count across behaviorally characterized wrappers.
    ui_targets={"resource_short_string":0x10254204,"resource_text":0x102500F0,
                "message_wrapper":0x1023A6E0,"message_to_display":0x102340F0,
                "display_builder":0x102429A8}
    ranking=[]
    for f in funcs.values():
        direct={k:sum(1 for i in calls(f) if any(int(t,16)==v for t in i.get("targets",[]) if re.fullmatch(r"[0-9a-fA-F]+",t))) for k,v in ui_targets.items()}
        if sum(direct.values()):
            ranking.append({"function":f["entry"],"bytes":f.get("bytes"),"instructions":len(f.get("instructions",[])),
                            "direct_primitive_counts":direct,"primitive_total":sum(direct.values())})
    ranking.sort(key=lambda x:(x["primitive_total"],x["instructions"]),reverse=True)
    # Similar function-pointer initializer heuristic: literal load of code pointer followed by store.
    constructors=[]
    for f in funcs.values():
        ins=f.get("instructions",[]); pairs=[]
        for i,x in enumerate(ins[:-1]):
            if not re.search(r"ldr\s+r0,\s*\[0x[0-9a-f]+\]",x.get("text",""),re.I): continue
            m=re.search(r"str\s+r0,\s*\[r\d+,#0x([0-9a-f]+)\]",ins[i+1].get("text",""),re.I)
            if not m: continue
            refs=x.get("refs",[])
            raw=next((int(r["u32"],16) for r in refs if r.get("u32") and re.fullmatch(r"[0-9a-fA-F]{8}",r["u32"])),None)
            if raw is not None and raw&1 and BASE<= (raw&~1)<0x10300000:
                pairs.append({"offset":int(m.group(1),16),"value":hex(raw),"load":x["address"],"store":ins[i+1]["address"]})
        if len(pairs)>=3: constructors.append({"function":f["entry"],"bytes":f.get("bytes"),"slots":pairs})
    # Exact slot-7 code facts from dedicated Ghidra-forced Thumb export.
    forced=(GHIDRA_REPORTS/"media_api_targets.txt").read_text(encoding="utf-8")
    m=re.search(r"===== pointer_cell=10236330.*?\n(.*?)(?=\n===== pointer_cell=|\Z)",forced,re.S)
    slot7_excerpt=m.group(1) if m else ""
    # All function/primitive references in target callbacks for graph artifact.
    report={"firmware":"ALTICE_F2_DS_V02.1_181023_MP","base":hex(BASE),"constructor":{
        "entry":"0x102362a4","size":constructor.get("bytes"),"instructions":len(constructor.get("instructions",[])),
        "incoming":constructor.get("incoming",[]),"calls":[{"address":i["address"],"text":i["text"],"targets":i.get("targets",[])} for i in calls(constructor)],
        "string_refs":[r for i in constructor.get("instructions",[]) for r in i.get("refs",[]) if r.get("string")],
        "stores":slot7_excerpt},"slots":SLOTS,"raw_pointer_hits":raw_hits,"non_alice_viva_hits":outside_hits,
        "indirect_field_call_candidates":indirect,"source_refs":source_refs,"ui_targets":ui_targets,
        "ui_candidate_ranking":ranking[:150],"similar_pointer_constructors":constructors,
        "important_functions":{a:{"name":funcs.get(a,{}).get("name"),"bytes":funcs.get(a,{}).get("bytes"),
          "incoming":funcs.get(a,{}).get("incoming",[]),"calls":[{"address":i["address"],"text":i["text"],"targets":i.get("targets",[])} for i in calls(funcs.get(a,{}))]}
          for a in ("101b31fc","10214940","102272ec","102362a4")}}
    outdir=GHIDRA_REPORTS; outdir.mkdir(parents=True,exist_ok=True)
    (outdir/"media_callback_analysis.json").write_text(json.dumps(report,ensure_ascii=False,indent=2),encoding="utf-8")
    xlines=["RAW CALLBACK POINTER SCAN — addresses little-endian, even and Thumb-odd forms",
            "The firmware image is read-only. Runtime address is supplied only for decompressed ALICE."]
    for h in raw_hits:
        xlines.append(f"slot{h['slot']} value={h['value']:#010x} file={h['file']} offset=0x{h['offset']:X} runtime={h['address'] or 'unknown'}")
        xlines.append("  context="+h["context"]["hex"])
    xlines.append("\nVIVA excluding embedded ALICE_2 slice: "+json.dumps(outside_hits))
    (outdir/"media_callback_xrefs.txt").write_text("\n".join(xlines)+"\n",encoding="utf-8")
    ilines=["INDIRECT CALL INVENTORY", "Confirmed object consumers:",
            "101B31FC: ldr r2,[r4,#0] at 101B3266; blx r2 at 101B326A (slot 0).",
            "101B31FC: ldr r1,[r4,#0x20] at 101B3270; blx r1 at 101B3274 (slot 8).",
            "The constructed object is returned through param9 and caller 10214940 supplies its output field at runtime.",
            "Offset-only candidates below are ambiguous: they can be unrelated object layouts."]
    for off in (0,4,8,12,16,20,24,28,32,36):
        rows=[x for x in indirect if x["field_offset"]==off]
        ilines.append(f"\nfield +0x{off:02X}: {len(rows)} simple LDR→BLX patterns")
        for x in rows[:40]: ilines.append(f"  {x['function']} {x['load']} {x['load_text']} -> {x['call']} {x['call_text']}")
    ilines.append("\nNo offset-only match is asserted to consume the aud_player_media object without dataflow proof.")
    (outdir/"media_indirect_calls.txt").write_text("\n".join(ilines)+"\n",encoding="utf-8")
    mmi=["MMI / RESOURCE CANDIDATES — heuristic fingerprint, not menu identification",
         "R1 0x10254204: returns a non-empty short-string pointer via external thunk; generic resource lookup candidate.",
         "R2 0x102500F0: resolves a nonzero ID/value through external thunk to a char pointer; generic text lookup candidate.",
         "R3 0x1023A6E0: wrapper converts four IDs/values with R1/R2 then calls 0x102340F0.",
         "R4 0x102340F0 forwards to 0x102429A8; that routine updates global UI state and calls display/GUI helpers. Generic dialog/display builder candidate.",
         "Direct 0x1023A6E0 callers: 0x1028D114 and 0x10296E54. Shared use is consistent with a reusable popup/message UI, not a unique AudioPlayer screen.",
         "Ranked direct callers of the characterized wrappers:"]
    for row in ranking[:100]: mmi.append(f"  {row['function']} bytes={row['bytes']} ins={row['instructions']} score={row['primitive_total']} {row['direct_primitive_counts']}")
    (outdir/"altice_mmi_candidate_functions.txt").write_text("\n".join(mmi)+"\n",encoding="utf-8")
    vlines=["VIDEO BACKEND / FRONTEND CANDIDATES (targeted pass)",
            "No analogous video source-file path (.c) occurs in the existing ALICE Ghidra string xrefs.",
            "No `.mp4`, `.3gp`, `.avi`, `video_player.c`, `vdoply`, or `video\\` literal was found in ALICE-decompressed, VIVA, ROM or dump scans in this pass.",
            "The pointer-constructor heuristic found these functions with >=3 adjacent literal-function-pointer stores:"]
    for f in constructors: vlines.append(f"  {f['function']} bytes={f['bytes']} slots={len(f['slots'])}")
    vlines.append("Only 0x102362A4 matched in the existing function export. This is not proof that video code is absent; compressed/stripped resources or APIs without readable names remain possible.")
    (outdir/"video_backend_candidates.txt").write_text("\n".join(vlines)+"\n",encoding="utf-8")
    print("Wrote media callback reports to",outdir)
    print("raw pointer hits:",len(raw_hits),"indirect field patterns:",len(indirect),"pointer constructors:",len(constructors))

if __name__=="__main__": main()
