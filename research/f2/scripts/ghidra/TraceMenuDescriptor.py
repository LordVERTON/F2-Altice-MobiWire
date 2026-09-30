"""Export the confirmed dynamic menu-descriptor path from the existing Ghidra detail export."""
import json
from pathlib import Path

root = Path(__file__).resolve().parents[4] / "research" / "f2"
reports = root / "work" / "ghidra" / "alice_reports"
details = [json.loads(x) for x in (reports / "altice_details.jsonl").open(encoding="utf-8")]
by_addr = {x.get("entry", "").lower(): x for x in details}

def fn(addr):
    d = by_addr[addr.lower()]
    return {"entry": "0x" + d["entry"], "name": d["name"], "size_bytes": d["bytes"],
            "range_end_exclusive": "0x%08X" % (int(d["min"], 16) + d["bytes"]),
            "incoming": d.get("incoming", []),
            "instructions": [{"address": "0x" + i["address"], "bytes": i["hex"], "text": i["text"]}
                             for i in d.get("instructions", [])]}

functions = {a: fn(a) for a in ("10279af6", "102731a0", "10275714", "10275880", "1021f904", "102ba458", "102757d0", "1024c4bc")}
evidence = {
    "descriptor_source": "0x10279AF6 obtains active context through external veneer 0x1022F7C8, passes that context to external veneer 0x1022F7B8, and passes the returned descriptor as R1 to 0x102731A0.",
    "parent_field": {"offset": "+0x14", "width": 2, "read_at": "0x102731F2", "read_instruction": "ldrh r0,[r4,#0x14]"},
    "minimum_observed_size": "0x4E bytes (through first U16 history slot at +0x4C); actual allocation/array extent not found",
    "confirmed_internal_parent_writer": {"function": "0x102BA458", "instruction": "0x102BA47E", "text": "strh r1,[r0,#0x14]", "value_source": "ldrh r1,[r0,#0x18] at 0x102BA47C", "condition": "item index is within supported range and state byte at +0x180 for that child has bit 0 set", "interpretation": "navigation into selected child/submenu; not a constructor"},
    "selected_item_lookup": {"function": "0x1021F904", "instruction": "0x1021F922", "text": "ldrh r0,[r4,#0x18]", "use": "passes selected child ID to 0x1024C4BC, which searches the child-ID array at descriptor+0x40 up to count at +0x48"},
    "render_refresh": {"function": "0x10279AF6", "caller": "0x102BA458", "descriptor_accessor": "external target 0xF02DFBB4 via veneer 0x1022F7B8"},
    "reset": {"function": "0x102757D0", "instruction": "0x1027584E", "text": "strh r5,[r4,#0x18]", "value": 0, "note": "clears selected child during menu-state reset"},
    "menu_id_value": None,
    "menu_child_ids": None,
    "conclusion": "Descriptor ownership/allocation and its initial parent value are behind external framework APIs. The internal transition copies selected child ID +0x18 into current parent ID +0x14. No concrete Multimedia ID is encoded at the confirmed generic call site."
}

fields = [
    {"offset": "+0x04", "access": "R/W", "role": "navigation/history depth; incremented when entering child; indexes history at +0x4C"},
    {"offset": "+0x0A", "access": "W", "role": "render/update state; set during prepare and cleared after render"},
    {"offset": "+0x0C", "access": "R/W", "role": "pending activation/selection flag; 0x1021F904 tests and clears it"},
    {"offset": "+0x0D", "access": "R", "role": "render mode/state"},
    {"offset": "+0x0E", "access": "R/W", "role": "render state; set during prepare, cleared by reset/render"},
    {"offset": "+0x0F", "access": "R/W", "role": "submode used by renderer"},
    {"offset": "+0x10", "access": "R/W", "role": "submenu/navigation flag; set on transition"},
    {"offset": "+0x14", "width": 2, "access": "R/W", "role": "current parent/menu ID; read by 0x102731A0 and set from +0x18 by 0x102BA458"},
    {"offset": "+0x16", "width": 2, "access": "R/W", "role": "previous parent ID; copied from +0x14 before transition"},
    {"offset": "+0x18", "width": 2, "access": "R/W", "role": "currently selected child ID; read by selection handler and reset to zero"},
    {"offset": "+0x1A", "width": 2, "access": "R/W", "role": "navigation counter/history state; incremented on transition"},
    {"offset": "+0x1C..+0x3C", "access": "R/W", "role": "renderer resource/layout pointers and parameters; roles not individually proven"},
    {"offset": "+0x40", "width": 4, "access": "R/W", "role": "pointer to U16 child-ID array"},
    {"offset": "+0x44", "width": 4, "access": "R/W", "role": "renderer/category/type flags"},
    {"offset": "+0x48", "width": 4, "access": "R/W", "role": "child count from external API"},
    {"offset": "+0x4C+", "width": "2 bytes each", "access": "R/W", "role": "parent/navigation history IDs; extent depends on history depth"}
]

data = {"functions": functions, "descriptor_fields": fields, "evidence": evidence,
        "writer_scan": json.loads((reports / "menu_descriptor_writes_scan.json").read_text(encoding="utf-8")),
        "limits": ["No concrete numeric parent ID is recovered.", "External accessor/child APIs are not implemented in extracted ALICE/ROM package.", "Other same-offset STRH operations were excluded when their base is a stack/temp or unrelated object; see writer scan."]}

(reports / "menu_descriptor_analysis.json").write_text(json.dumps(data, indent=2), encoding="utf-8")
(reports / "menu_descriptor_writes.json").write_text(json.dumps({
    "confirmed_menu_descriptor_writer": evidence["confirmed_internal_parent_writer"],
    "other_same_offset_candidates_excluded": [
        {"address": "0x101F6700", "function": "0x101F6474", "reason": "writes nested structure at argument+0x74; unrelated field layout"},
        {"address": "0x1023C7FE", "function": "0x1023C6E4", "reason": "writes service/heap record, not the menu context"},
        {"address": "0x10281D96", "function": "0x10281D68", "reason": "destination is a stack-built temporary structure"}
    ],
    "selected_child_reset": {"function": "0x102757D0", "address": "0x1027584E", "instruction": "strh r5,[r4,#0x18]", "value": 0}
}, indent=2), encoding="utf-8")
(reports / "menu_parent_ids.json").write_text(json.dumps({"dynamic_parent_id": evidence["menu_id_value"], "parent_source": "descriptor+0x18 selected child copied to +0x14", "known_static_callers": [{"caller": "0x10279AF6", "parent_id": "runtime descriptor+0x14"}, {"caller": "0x1021F904", "action": "reads selected child ID +0x18; transitions via 0x102BA458"}], "multimedia_id": None}, indent=2), encoding="utf-8")
(reports / "menu_child_launch_map.json").write_text(json.dumps({"parent_id": None, "child_ids": None, "launch_handlers": None, "status": "not recoverable in this pass; enumeration and descriptor accessors target external framework APIs"}, indent=2), encoding="utf-8")

analysis = ["Menu descriptor trace — Altice F2", "", "Confirmed path:",
            "0x102CF370 -> 0x1021F904 -> 0x102BA458 -> 0x10279AF6 -> 0x102731A0 -> 0x10275714",
            "0x10279AF6 calls 0x1022F7C8 (external 0xF02E2CC4) to obtain the active context; it then calls 0x1022F7B8 (external 0xF02DFBB4) with that context and passes the returned descriptor in R1 to 0x102731A0.",
            "0x102731A0 reads the U16 menu ID from descriptor+0x14 at 0x102731F2 and passes it to child enumeration/count preparation.",
            "The descriptor is not allocated or initialized by 0x10279AF6; it is fetched from the framework through an external accessor.", "",
            "Concrete internal writer found:",
            "0x102BA458 is a menu-navigation transition, not a constructor. At 0x102BA47C it loads U16 descriptor+0x18, then at 0x102BA47E stores that selected child ID into U16 descriptor+0x14. It saves the old +0x14 at +0x16, increments navigation state, records the parent in the history area beginning +0x4C, sets +0x10, and calls refresh at 0x10279AF6.",
            "0x1021F904 obtains the descriptor for the active context, tests/clears byte +0x0C, reads selected child ID +0x18, and searches the child ID array via 0x1024C4BC. That lookup reads pointer +0x40 and count +0x48.",
            "0x102757D0 resets selected ID +0x18 to zero and clears menu state; it is not the source of the actual menu ID.", "",
            "Descriptor fields observed:"]
analysis.extend(f"{f['offset']}: {f['role']} (access {f['access']})" for f in fields)
analysis += ["", "Parent ID value:",
             "The confirmed +0x14 writer takes its value from the currently selected child ID at +0x18. This explains how selecting Multimedia from the main list becomes the submenu parent ID, but the numeric ID is supplied by runtime menu state/child enumeration and is not a literal in these functions.",
             "The direct caller chain does not contain a static constructor or numeric ID. The external framework accessor and child enumeration implementation are not present in the extracted package. The physical observation of two Multimedia entries remains external evidence, not a statically recovered child count.", "",
             "Minimum observed descriptor extent is 0x4E bytes: the U32 count at +0x48 ends at +0x4C and a U16 history value is written beginning at +0x4C. History may extend further; allocation size was not recovered.", "",
             "Writer scan and false-positive filtering:",
             "The ALICE instruction scan found many same-offset stores. The structurally confirmed menu-descriptor write is 0x102BA47E because the same base register also accesses +0x18, +0x40, +0x44, +0x48 and feeds the menu refresh path. 0x10281D68 writes into a stack-built temporary descriptor; 0x101F6474 and 0x1023C6E4 operate on unrelated nested/display or service structures. These are not evidence of the menu parent field.", "",
             "No child IDs or launch handlers are assigned in this pass. The child list is produced through the external 0xF032ACDC API."]
(reports / "menu_descriptor_analysis.txt").write_text("\n".join(analysis) + "\n", encoding="utf-8")

(reports / "menu_descriptor_writes.txt").write_text("""Menu descriptor field write analysis

Confirmed write to the menu descriptor's +0x14 parent field:
  function 0x102BA458, range 0x102BA458-0x102BA49E, 70 bytes
  0x102BA47C: LDRH R1,[R0,#0x18]       ; selected child/menu ID
  0x102BA47E: STRH R1,[R0,#0x14]       ; current parent/menu ID = selected child
  Same object: +0x16 previous parent, +0x1A navigation counter, +0x40 child array, +0x44 renderer mode, +0x4C history; then refresh via 0x10279AF6.
  Caller: 0x1021F904; it verifies the selected ID at +0x18 exists in the child array (+0x40, bounded by +0x48) before invoking the transition.

This is a navigation-state update, not the descriptor constructor or the initial root-menu setup.

Other same-offset stores found by scan:
  0x101F6700, 0x1023C7FE, 0x10281D96: same numerical offset but different nested/stack/service objects; not the menu descriptor.
  0x1027584E stores zero to descriptor+0x18 during menu-state reset.
  0x102B7F2A stores zero into a stack local at SP+0x18; unrelated.

No internal ALICE constructor that initializes descriptor+0x14 to a fixed menu constant was identified. The active descriptor comes from external context/descriptor APIs.
""", encoding="utf-8")

(reports / "menu_parent_ids.txt").write_text("""Menu parent ID provenance

The ID read at 0x102731F2 is a U16 at descriptor+0x14. It is runtime state, not a constant at the generic renderer call site.

Known transitions/callers:
  0x10279AF6 -> 0x102731A0: obtains the active menu context (external 0xF02E2CC4), obtains its descriptor (external 0xF02DFBB4), and passes that descriptor as R1. Parent ID is whatever U16 is currently at descriptor+0x14.
  0x1021F904 -> 0x102BA458: reads selected child U16 at descriptor+0x18, finds its index in the child array at +0x40 (count +0x48), then enters it.
  0x102BA458: writes selected child ID (+0x18) to current parent ID (+0x14), preserving prior +0x14 at +0x16, then refreshes.

Therefore when Multimedia is selected from the Main Menu, its ID becomes the current parent ID through this transition. The numeric value cannot be recovered statically from the internal call chain: the selected child list comes from external framework API 0xF032ACDC and active descriptor accessor 0xF02DFBB4. No static parent ID table/value was demonstrated.

Multimedia parent ID: UNKNOWN (dynamic value).
Child count: physical observation says two; static external API result unavailable.
Child IDs and launch callbacks: not recovered.
""", encoding="utf-8")

(reports / "menu_child_launch_map.txt").write_text("""Child ID to launch map

No concrete parent/child IDs or launch handlers were recovered in this pass.

Known path:
  descriptor+0x14 (current parent U16)
    -> external child enumeration 0xF032ACDC via 0x1022EA20
    -> child U16 array at descriptor+0x40
    -> child count at descriptor+0x48 from external 0xF02D8870 via 0x1022EAB0
    -> renderer 0x10275880

Selected item state:
  descriptor+0x18 holds selected child ID; 0x1021F904 looks it up in the array using 0x1024C4BC. On submenu entry, 0x102BA458 copies it into +0x14.

Image Viewer / FM Radio assignments remain unproven from static IDs. Resolving them requires the child list/API backing data or runtime descriptor values. No AudioPlayer or other application analysis was performed.
""", encoding="utf-8")

print("Wrote menu descriptor analysis reports to", reports)
