#!/usr/bin/env python3
"""Read-only inventory of Altice F2 menu/resource markers and Ghidra xrefs.

This deliberately reports string hits as leads only. It does not infer menu
membership from a label, nor classify the factory-test FMradio entry as UI FM.
"""
import argparse
import json
import re
import struct
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from _paths import ALTICE_ALICE, ALTICE_PACKAGE, DUMP_MAIN, GHIDRA_REPORTS

TERMS = [
    "Multimedia", "Multimédia", "Extras", "Extra", "Image viewer",
    "Image Viewer", "ImageViewer", "imgview", "FM radio", "FM Radio",
    "FMradio", "fmrdo", "Audio", "Audio player", "Audio Player",
    "AudioPlayer", "AUDPLY", "Music", "Playlist", "Video", "Video player",
    "Video Player", "vdoply", "Sound recorder", "Recorder", "sndrec",
    "Camera", "File manager", "ZIMAGE_ER", "BOOT_ZIMAGE", "DCMCMP",
]
SOURCES = {
    "dump": DUMP_MAIN,
    "rom": ALTICE_PACKAGE / "DL188_GX1882_NIKITI_PCB01_gsm_MT6261_S00" / "ROM",
    "viva": ALTICE_ALICE / "altice_VIVA.bin",
    "alice_compressed": ALTICE_ALICE / "altice_ALICE_2.bin",
    "alice_decompressed": ALTICE_ALICE / "alice-py.bin",
    "service_image": ALTICE_PACKAGE / "DL188_GX1882_NIKITI_PCB01_gsm_MT6261_S00.ALTICE_F2_DS_V02_1_181023_MP.bin",
}

def scan(data):
    hits=[]
    for term in TERMS:
        for enc,label in (("ascii","ASCII"),("utf-16le","UTF16LE"),("utf-16be","UTF16BE")):
            needle=term.encode(enc,errors="ignore")
            pos=0
            while True:
                at=data.find(needle,pos)
                if at<0: break
                hits.append({"term":term,"encoding":label,"offset":at})
                pos=at+1
    return sorted(hits,key=lambda h:(h["offset"],h["term"],h["encoding"]))

def gfh(data):
    out=[]; pos=0
    while True:
        at=data.find(b"MMM\x01",pos)
        if at<0: break
        pos=at+1
        if at+0x38>len(data) or data[at+8:at+17]!=b"FILE_INFO": continue
        typ=struct.unpack_from("<H",data,at+0x18)[0]
        size=struct.unpack_from("<I",data,at+0x20)[0]
        name=data[at+0x40:at+0xC0].split(b"\0",1)[0].decode("latin1","replace")
        out.append({"offset":at,"type":typ,"size":size,"end":at+size,"name":name})
    return out

def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--out",default=str(GHIDRA_REPORTS / "altice_menu_inventory.json"))
    args=ap.parse_args()
    results={"firmware":"ALTICE_F2_DS_V02.1_181023_MP","read_only":True,"components":{},"gfh_dump":[],"ghidra_text_xrefs":[]}
    for label,path in SOURCES.items():
        if path.exists():
            data=path.read_bytes()
            results["components"][label]={"path":str(path),"size":len(data),"hits":scan(data)}
    dump=SOURCES["dump"]
    if dump.exists(): results["gfh_dump"]=gfh(dump.read_bytes())
    details=GHIDRA_REPORTS / "altice_details.jsonl"
    if details.exists():
        rx=re.compile(r"audio|mp3|audply|video|vdoply|multimedia|extras?|image|imgview|fmr|radio|recorder|camera|playlist",re.I)
        for line in details.open(encoding="utf-8"):
            row=json.loads(line)
            for ins in row.get("instructions",[]):
                for ref in ins.get("refs",[]):
                    value=ref.get("string")
                    if value and rx.search(value):
                        results["ghidra_text_xrefs"].append({"function":row.get("entry"),"instruction":ins.get("address"),"target":ref.get("to"),"string":value})
    out=Path(args.out); out.parent.mkdir(parents=True,exist_ok=True)
    out.write_text(json.dumps(results,ensure_ascii=False,indent=2),encoding="utf-8")
    print(out)
    print("components scanned:",len(results["components"]),"Ghidra matching string xrefs:",len(results["ghidra_text_xrefs"]))

if __name__=="__main__": main()
