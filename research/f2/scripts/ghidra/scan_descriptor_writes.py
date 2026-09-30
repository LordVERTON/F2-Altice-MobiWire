import json
import re
from pathlib import Path

root = Path(__file__).resolve().parents[4] / "research" / "f2"
details = root / "work" / "ghidra" / "alice_reports" / "altice_details.jsonl"
rows = [json.loads(line) for line in details.open(encoding="utf-8")]
out = []
for fn in rows:
    ins = fn.get("instructions", [])
    text = " ".join(i.get("text", "") for i in ins)
    writes = [i for i in ins if i.get("mnemonic") == "strh" and
              ("#0x14]" in i.get("text", "") or "#0x18]" in i.get("text", ""))]
    descriptor_shape = any(token in text for token in ("#0x40]", "#0x44]", "#0x48]"))
    if writes and descriptor_shape:
        out.append({"function": fn["entry"], "name": fn.get("name"),
                    "candidate_shape": True,
                    "writes": [{"address": i["address"], "text": i["text"]} for i in writes],
                    "field_refs": sorted(set(re.findall(r"#0x(?:40|44|48)", text)))})

(root / "work" / "ghidra" / "alice_reports" / "menu_descriptor_writes_scan.json").write_text(
    json.dumps(out, indent=2), encoding="utf-8")
for r in out:
    print(r["function"], r["name"], r["writes"], r["field_refs"])
