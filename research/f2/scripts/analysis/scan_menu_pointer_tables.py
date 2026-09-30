#!/usr/bin/env python3
"""Find plausible static Thumb callback tables in firmware components (read-only)."""
import json
import struct
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from _paths import ALTICE_ALICE, DUMP_MAIN, GHIDRA_REPORTS, REPO_ROOT

ROOT = REPO_ROOT
OUT = GHIDRA_REPORTS
BASE = 0x101812C4
ALICE = ALTICE_ALICE / "alice-py.bin"
TSV = OUT / "altice_functions.tsv"
TARGETS = {
    "ALICE_decompressed": ALICE,
    "VIVA": ALTICE_ALICE / "altice_VIVA.bin",
    "ROM": ALTICE_ALICE.parents[2] / "data" / "firmware-packages" / "altice-service" / "altice_service_package" / "DL188_GX1882_NIKITI_PCB01_gsm_MT6261_S00" / "ROM",
    "dump": DUMP_MAIN,
}
MMI_CALLS = {0x1023A6E0, 0x102340F0, 0x102429A8, 0x10254204, 0x102500F0,
             0x10275880, 0x10275714}


def main():
    funcs = {}
    spans = []
    for line in TSV.read_text(encoding="utf-8").splitlines()[1:]:
        cols = line.split("\t")
        if len(cols) < 5:
            continue
        try:
            entry, size, nins = int(cols[0], 16), int(cols[2]), int(cols[3])
        except ValueError:
            continue
        funcs[entry] = {"size": size, "instructions": nins, "name": cols[1]}
        spans.append((entry - BASE, entry - BASE + size))
    blob = ALICE.read_bytes()
    valid = {entry | 1 for entry, meta in funcs.items() if meta["instructions"] >= 4 and meta["size"] >= 8}
    mask = bytearray(len(blob))
    for lo, hi in spans:
        for x in range(max(0, lo), min(len(blob), hi)):
            mask[x] = 1

    # Repeated function-pointer fields: records can have 4..32-byte stride.
    found = []
    for stride in range(4, 33, 4):
        for field in range(0, stride, 4):
            off = field
            while off + stride * 2 <= len(blob):
                if mask[off] or off + stride >= len(blob) or mask[off + stride]:
                    off += 4
                    continue
                v0 = struct.unpack_from("<I", blob, off)[0]
                v1 = struct.unpack_from("<I", blob, off + stride)[0]
                if v0 not in valid or v1 not in valid:
                    off += 4
                    continue
                run = [v0, v1]
                cursor = off + 2 * stride
                while cursor + 4 <= len(blob) and not mask[cursor]:
                    val = struct.unpack_from("<I", blob, cursor)[0]
                    if val not in valid:
                        break
                    run.append(val)
                    cursor += stride
                if len(run) >= 2:
                    aligned_targets = []
                    for p in run:
                        e = p & ~1
                        aligned_targets.append({"pointer": hex(p), "entry": hex(e), **funcs[e]})
                    found.append({"file_offset": off, "runtime": hex(BASE + off), "stride": stride,
                                  "field_offset": field, "run_length": len(run), "targets": aligned_targets,
                                  "span_bytes": (len(run) - 1) * stride + 4,
                                  "data_region_only": True})
                    off += len(run) * stride
                else:
                    off += 4
    # Deduplicate exact same runs found under different stride/field interpretations.
    unique = {}
    for row in found:
        key = (row["file_offset"], tuple(x["pointer"] for x in row["targets"]))
        if key not in unique or row["stride"] < unique[key]["stride"]:
            unique[key] = row
    found = sorted(unique.values(), key=lambda x: (x["run_length"], -x["stride"]), reverse=True)

    # Raw pointer hits in non-ALICE components; runtime pointers may be absent when compressed.
    external_hits = []
    for label, path in TARGETS.items():
        if label == "ALICE_decompressed" or not path.exists():
            continue
        b = path.read_bytes()
        for p in sorted(valid):
            needle = struct.pack("<I", p)
            pos = 0
            while (pos := b.find(needle, pos)) >= 0:
                external_hits.append({"component": label, "file_offset": hex(pos), "pointer": hex(p)})
                pos += 1

    report = {"firmware": "ALTICE_F2_DS_V02.1_181023_MP", "runtime_base": hex(BASE),
              "method": "Aligned Thumb pointers to known Ghidra functions, scanning non-code portions of decompressed ALICE; fixed record strides 4..32 bytes.",
              "candidate_runs": found, "raw_external_component_hits": external_hits,
              "caveat": "A pointer run is only a structural lead. It does not prove a menu table or identify Image Viewer/FM Radio."}
    (OUT / "multimedia_pointer_table_scan.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    lines = ["ALICE STATIC THUMB POINTER TABLE SCAN", f"Known function targets: {len(valid)}",
             f"Candidate repeated runs after deduplication: {len(found)}", ""]
    for row in found[:200]:
        targets = ", ".join(f"{x['pointer']} ({x['entry']}, {x['instructions']} ins)" for x in row["targets"])
        lines.append(f"runtime={row['runtime']} fileoff=0x{row['file_offset']:X} stride={row['stride']} field=+{row['field_offset']} n={row['run_length']} targets={targets}")
    lines += ["", f"Raw callback pointers in ROM/VIVA/dump: {len(external_hits)}.",
              "No candidate is promoted to Multimedia without a shared parent and semantic validation of both children."]
    (OUT / "multimedia_pointer_table_scan.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("candidate runs:", len(found), "external raw function-pointer hits:", len(external_hits))
    for row in found[:12]:
        print(row["runtime"], "stride", row["stride"], "n", row["run_length"], [x["entry"] for x in row["targets"]])


if __name__ == "__main__":
    main()
