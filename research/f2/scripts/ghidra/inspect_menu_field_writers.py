import json
from pathlib import Path

path = Path(__file__).resolve().parents[4] / "research" / "f2" / "work" / "ghidra" / "alice_reports" / "altice_details.jsonl"
targets = {"102b7f00", "1023c6e4", "101f6474", "10281d68", "102757d0", "102ba458"}
for line in open(path, encoding="utf-8"):
    d = json.loads(line)
    if d.get("entry") not in targets:
        continue
    print("===", d.get("entry"), d.get("name"), d.get("bytes"))
    print("IN", d.get("incoming"))
    for ins in d.get("instructions", []):
        if ins.get("mnemonic") == "strh" and "#0x18]" in ins.get("text", ""):
            print(ins.get("address"), ins.get("text"), ins.get("refs"))

print("=== ALL +0x18 HALFWORD WRITERS WITH RELATED DESCRIPTOR FIELDS ===")
for line in open(path, encoding="utf-8"):
    d = json.loads(line)
    ins = d.get("instructions", [])
    stores = [i for i in ins if i.get("mnemonic") == "strh" and "#0x18]" in i.get("text", "")]
    text = " ".join(i.get("text", "") for i in ins)
    if stores and any(x in text for x in ("#0x14]", "#0x40]", "#0x48]")):
        print(d.get("entry"), d.get("bytes"), "fields", [x for x in ("#0x14]", "#0x40]", "#0x48]") if x in text], "callers", [x.get("caller") for x in d.get("incoming", []) if "CALL" in x.get("type", "")])
        for i in stores:
            print(" ", i.get("address"), i.get("text"))
