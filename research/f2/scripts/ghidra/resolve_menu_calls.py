from pathlib import Path
import json
import struct

ROOT = Path(__file__).resolve().parents[4]
F2 = ROOT / "research" / "f2"
BASE = 0x101812C4
BIN = F2 / "work" / "extracted" / "altice_alice" / "alice-py.bin"
TRANS = F2 / "work" / "extracted" / "altice_alice" / "alice-translated-py.bin"
DETAILS = F2 / "work" / "ghidra" / "alice_reports" / "altice_details.jsonl"
CALLS = [0x1027572C, 0x10275732, 0x10275798]
REPORT = F2 / "work" / "ghidra" / "alice_reports"


def thumb_branch(data, addr):
    off = addr - BASE
    h1, h2 = struct.unpack_from("<HH", data, off)
    s = (h1 >> 10) & 1
    j1, j2 = (h2 >> 13) & 1, (h2 >> 11) & 1
    i1, i2 = 1 ^ (j1 ^ s), 1 ^ (j2 ^ s)
    raw = (s << 24) | (i1 << 23) | (i2 << 22) | ((h1 & 0x3FF) << 12) | ((h2 & 0x7FF) << 1)
    delta = raw - (1 << 25) if raw & (1 << 24) else raw
    is_blx = (h2 & 0x1000) == 0
    pc = ((addr + 4) & ~3) if is_blx else addr + 4
    return off, h1, h2, pc, delta, (pc + delta) & 0xFFFFFFFF, is_blx


files = {"alice-py": BIN.read_bytes(), "alice-translated-py": TRANS.read_bytes()}
rows = []
for addr in CALLS:
    row = {"callsite": f"0x{addr:08X}", "offset": f"0x{addr-BASE:X}", "files": {}}
    for name, data in files.items():
        off, h1, h2, pc, delta, target, is_blx = thumb_branch(data, addr)
        row["files"][name] = {
            "bytes": data[off:off+4].hex(" "), "halfwords": [f"0x{h1:04X}", f"0x{h2:04X}"],
            "instruction": "BLX" if is_blx else "BL", "pc": f"0x{pc:08X}",
            "delta": f"{delta:+#x}", "target": f"0x{target:08X}",
        }
    rows.append(row)

details = [json.loads(line) for line in DETAILS.open(encoding="utf-8")]
func = next(d for d in details if d.get("entry", "").lower() == "10275714")
ins = {i["address"].lower(): i for i in func["instructions"]}
for row in rows:
    addr = row["callsite"][2:].lower()
    row["ghidra_instruction"] = ins[addr]["text"]
    row["ghidra_bytes"] = ins[addr]["hex"]

rom_path = F2 / "data" / "firmware-packages" / "altice-service" / "altice_service_package" / "DL188_GX1882_NIKITI_PCB01_gsm_MT6261_S00" / "ROM"
viva_path = F2 / "work" / "extracted" / "altice_alice" / "altice_VIVA.bin"
def gfh(path):
    data = path.read_bytes()
    return {"file": str(path.relative_to(ROOT)), "size": len(data), "type": struct.unpack_from("<H", data, 0x18)[0],
            "load_addr": struct.unpack_from("<I", data, 0x1C)[0], "file_len": struct.unpack_from("<I", data, 0x20)[0]}

rom, viva = gfh(rom_path), gfh(viva_path)
memory = {
    "ROM_package": {**rom, "start": rom["load_addr"], "end_exclusive": rom["load_addr"] + rom["file_len"]},
    "VIVA_package": {**viva, "start": viva["load_addr"], "end_exclusive": viva["load_addr"] + viva["file_len"]},
    "ALICE_decompressed": {"base": BASE, "size": len(files["alice-py"]), "end_exclusive": BASE + len(files["alice-py"])}
}
for row in rows:
    for target in [0xF02D8870, 0xF032ACDC]:
        memory_key = f"target_{target:08X}"
        memory[memory_key] = {"inside_ROM_package": memory["ROM_package"]["start"] <= target < memory["ROM_package"]["end_exclusive"],
                              "inside_VIVA_package": memory["VIVA_package"]["start"] <= target < memory["VIVA_package"]["end_exclusive"],
                              "inside_decompressed_ALICE": BASE <= target < BASE + len(files["alice-py"])}

for row in rows:
    print(json.dumps(row, indent=2))

print("THUNKS")
for addr in [0x1022EA20, 0x1022EAB0]:
    off = addr - BASE
    raw = files["alice-py"][off:off+8]
    print(f"0x{addr:08X} offset=0x{off:X} bytes={raw.hex(' ')} target_literal=0x{struct.unpack_from('<I', raw, 4)[0]:08X}")

json_data = {"call_sites": rows, "memory_map": memory,
             "interpretation": "Calls in corrected alice-py reach local ARM-state veneers; each veneer is LDR pc,[literal] and loads the odd Thumb entry point in the F0 platform API region. Those F0 addresses are outside the package ROM/VIVA file-backed ranges. The pre-untranslation alice-translated-py branch targets differ and do not identify the APIs."}
(REPORT / "menu_external_api_resolution.json").write_text(json.dumps(json_data, indent=2), encoding="utf-8")

txt = ["Menu API target resolution — static/offline", "", "Call-site decoding (ALICE base 0x101812C4):"]
for row in rows:
    txt += [f"\n{row['callsite']}  {row['ghidra_instruction']} ({row['ghidra_bytes']})",
            f"  offset: {row['offset']}"]
    for name, val in row["files"].items():
        txt.append(f"  {name}: bytes={val['bytes']}; halfwords={val['halfwords'][0]} {val['halfwords'][1]}; {val['instruction']}; PC={val['pc']}; delta={val['delta']}; decoded target={val['target']}")
txt += ["", "Second hop through the corrected ALICE veneer:",
        "0x1022EA20: 04 F0 1F E5 = ARM LDR pc,[pc,#-4]; literal at +4 = 0xF032ACDD (Thumb entry 0xF032ACDC).",
        "0x1022EAB0: 04 F0 1F E5 = ARM LDR pc,[pc,#-4]; literal at +4 = 0xF02D8871 (Thumb entry 0xF02D8870).",
        "The two BLX call sites therefore reach local veneers; the external API target comes from the literal load, not the BLX displacement.",
        "", "GFH package ranges (load_addr at GFH +0x1C; file_len at +0x20):"]
for name in ("ROM_package", "VIVA_package"):
    m = memory[name]
    txt.append(f"{name}: 0x{m['start']:08X} .. 0x{m['end_exclusive']:08X} (exclusive), size 0x{m['file_len']:X}")
m = memory["ALICE_decompressed"]
txt.append(f"ALICE decompressed: 0x{m['base']:08X} .. 0x{m['end_exclusive']:08X} (exclusive), size 0x{m['size']:X}")
txt += ["", "Neither F0 target is inside the extracted ROM or VIVA package ranges, nor in the decompressed ALICE range.",
        "The package headers do not map the SoC's internal/system ROM at F0xxxxxx. Thus the addresses are strongly evidenced as intended external platform-ROM APIs by named one-instruction veneers and odd Thumb literals, but physical mapping cannot be proven from these firmware package files alone. They are not ordinary functions in the supplied ROM image and not BL translation artifacts.",
        "", "Menu dataflow:",
        "0x102731A0 loads a 16-bit ID with LDRH r0,[r4,#0x14] at 0x102731F2, then BL 0x10275714 at 0x102731F4.",
        "0x102731A0 receives the descriptor in r1 (saved as r4). Its only direct caller is 0x10279AF6; that caller obtains the descriptor from the generic menu framework and passes it in r1.",
        "0x10275714 saves input r0 as r4. At 0x10275730 it moves r4 to r0, then calls the child-count API veneer at 0x1022EAB0 at 0x10275732; returned count is stored at descriptor+0x48 (0x1027573A).",
        "At 0x10275726 it passes parent ID in r0 and an output array in r1 to 0x1022EA20 (child-ID enumeration). It later calls child-count again with each child ID in r0 at 0x10275796-0x10275798 to mark whether that child itself has children.",
        "The parent ID is therefore a runtime 16-bit descriptor field at descriptor+0x14. Static ALICE has no fixed value at the generic call site; the concrete Multimedia ID is not established by this pass.",
        "", "A combined Ghidra project Altice_F2_ROM_ALICE_combined was created. It imports ALICE at 0x101812C4 and adds the service ROM memory block at its GFH load address 0x1000A000. Ghidra confirms both F0 targets are UNMAPPED in this combined image; the three menu call sites remain calls to local ALICE veneers. The ROM file does not contain the internal/system ROM implementation.",
        "Combined project is under research/f2/work/ghidra/alice_projects_combined/Altice_F2_ROM_ALICE_combined. Ghidra map check: 0xF02D8870 and 0xF032ACDC are UNMAPPED; service ROM is 0x1000A000..0x1004BE0B; ALICE block is 0x101812C4..0x102D8E77."]
(REPORT / "menu_external_api_resolution.txt").write_text("\n".join(txt) + "\n", encoding="utf-8")

(REPORT / "menu_parent_id_dataflow.txt").write_text("""0x10275714 parent-ID dataflow

1. 0x10279AF6 is the only direct caller of 0x102731A0.
2. 0x102731A0 receives the menu descriptor in R1 and moves it to R4 (0x102731A4).
3. LDRH R0,[R4,#0x14] at 0x102731F2 reads the current parent/menu ID as a 16-bit value.
4. BL 0x10275714 at 0x102731F4 passes that ID in R0.
5. 0x10275714 saves it in R4. It passes R4 to child enumeration at 0x10275726/0x1027572C, and to child count at 0x10275730/0x10275732. The returned count is stored in descriptor+0x48.
6. The same child-count veneer is called for each child ID in the loop to determine whether that child has descendants.

The ID is dynamic, read from the menu descriptor. The static caller does not hard-code a Multimedia ID. The only direct caller of the generic preparation function is 0x102731A0; recovering the concrete ID requires resolving the runtime descriptor population/parent selection path.
""", encoding="utf-8")

(REPORT / "menu_parent_children.txt").write_text("""Child enumeration API resolution

Child-count API:
  ALICE veneer: 0x1022EAB0 (one ARM instruction: LDR pc,[0x1022EAB4])
  external Thumb entry literal: 0xF02D8871 -> code address 0xF02D8870
  signature at call site: R0 = 16-bit menu/child ID; return R0 used as child count.

Child-ID enumeration API:
  ALICE veneer: 0x1022EA20 (one ARM instruction: LDR pc,[0x1022EA24])
  external Thumb entry literal: 0xF032ACDD -> code address 0xF032ACDC
  signature at call site: R0 = parent ID; R1 = output child-ID array. The function fills the array; caller iterates IDs as 16-bit values.

The exact implementation and internal filtering rules are not in the supplied ROM/VIVA files, so flags/hidden-child semantics cannot be inferred from these two veneers. The concrete Multimedia parent and its child IDs remain unresolved; this generic path has a runtime parent ID, not a static constant.
""", encoding="utf-8")
