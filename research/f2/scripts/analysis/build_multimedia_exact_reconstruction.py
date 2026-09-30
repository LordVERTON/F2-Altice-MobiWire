#!/usr/bin/env python3
"""Write an evidence-bounded reconstruction of the Altice menu rendering path."""
import json
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from _paths import GHIDRA_REPORTS

OUT = GHIDRA_REPORTS

FUNCTIONS = [
    {"address": "0x10275714", "name": "MMI_GetChildrenAndResources_candidate", "size": 168, "instructions": 75,
     "evidence": ["calls external 0xF02D8870 with parent ID; result becomes descriptor child count at +0x48",
                  "calls external 0xF032ACDC to populate an output buffer beginning at external state +0x100",
                  "iterates child IDs, sets the selected resource ID, obtains text via 0x10254204",
                  "calls external 0xF02F9CCC per child and stores a 16-bit result in the child array",
                  "sets bit 0 in per-child flags at external state +0x180 when 0xF02D8870(childID) is nonzero"]},
    {"address": "0x102731A0", "name": "MMI_ListRefresh_candidate", "size": 546, "instructions": 242,
     "evidence": ["reads selected/parent ID at descriptor +0x14", "calls 0x10275714 to obtain child metadata",
                  "uses child count at descriptor +0x48", "calls 0x10275880 with the descriptor to render the list"]},
    {"address": "0x10275880", "name": "MMI_ShowCategory_candidate", "size": 856, "instructions": 403,
     "evidence": ["iterates descriptor child count at +0x48", "dispatches by category/type at +0x44",
                  "for category value 8 calls 0x102429A8 with count and string/image metadata arrays",
                  "supports many category modes; therefore generic framework, not Multimedia-specific"]},
    {"address": "0x102429A8", "name": "MMI_DisplayBuilder_candidate", "size": 178, "instructions": 77,
     "evidence": ["called by wrapper 0x102340F0 and other generic UI paths", "resolves text values via 0x102500F0",
                  "sets UI/category state including constant 0x43", "calls display/list helpers 0x1028046C, 0x10284EBC, 0x10247FA0 and others"]},
    {"address": "0x1024C4BC", "name": "MMI_FindChildIndex_candidate", "size": 42, "instructions": 19,
     "evidence": ["reads child count at descriptor +0x48", "searches 16-bit IDs in array at descriptor +0x40", "returns matching child index or -1"]},
    {"address": "0x102BA458", "name": "MMI_SelectionChange_candidate", "size": 70, "instructions": 34,
     "evidence": ["checks per-item bit in state array at external +0x180", "updates selected ID/index fields in descriptor", "redraws through 0x10279AF6"]},
    {"address": "0x10279AF6", "name": "MMI_RedrawCurrentList_candidate", "size": 22, "instructions": 8,
     "evidence": ["gets current UI descriptor and selected object via external APIs", "calls 0x102731A0"]},
]

report = """ALTICE F2 - MULTIMEDIA EXACT RECONSTRUCTION (evidence-bounded)

FIRMWARE / OBSERVATION
Firmware: ALTICE_F2_DS_V02.1_181023_MP, MT6261, ALICE base 0x101812C4.
Observation supplied for the physical phone: Multimedia displays exactly two visible rows, Image Viewer and FM Radio.

RESULT
The exact Multimedia parent ID, child IDs, resource IDs, callbacks, and source table were NOT identified in the static artifacts available in this pass. The physical observation establishes the rendered result, not the binary addresses or IDs.

GENERIC LIST/MENU FRAMEWORK CANDIDATE (high confidence as generic framework; not attributed to Multimedia)
1) 0x10275714 (168 bytes / 75 instructions) is the strongest child-list preparation candidate. It receives a parent ID, asks external API 0xF02D8870 for a count, has external API 0xF032ACDC populate child IDs in an external buffer, resolves text resources, calls 0xF02F9CCC per child, and records whether each child ID itself has children.
2) 0x102731A0 (546 bytes / 242 instructions) refreshes a list descriptor. It calls 0x10275714, consumes the child count at descriptor +0x48, and passes the descriptor to 0x10275880.
3) 0x10275880 (856 bytes / 403 instructions) is a generic category/list renderer. It iterates the count at +0x48 and branches on a display mode at +0x44. One branch calls 0x102429A8 with the count and string/image arrays. It supports numerous category modes, so it is not identified as the Multimedia renderer specifically.
4) 0x102429A8 is a generic display builder reached through 0x102340F0. It resolves text and configures common UI/display helpers; no Multimedia, Image Viewer, or FM-specific behavior was established.
5) 0x1024C4BC searches a 16-bit child-ID array at descriptor +0x40, bounded by child count +0x48, and returns an index or -1.
6) 0x102BA458 updates selected-item state and calls 0x10279AF6 to redraw. 0x10279AF6 fetches the current descriptor and calls 0x102731A0.

DATA MODEL PROVEN FOR THIS GENERIC PATH
The current parent/menu ID is supplied at runtime. The framework obtains the child count and child IDs through external APIs/state, then resolves resources and renders. The working list descriptor uses +0x40 for a 16-bit ID sequence and +0x48 for count. The renderer also reads mode/flags at +0x44. This is not evidence that these offsets encode the specific Multimedia table.

IMPORTANT FLAG DISTINCTION
In 0x10275714, per-child bit 0 at external state +0x180 is set when the external child-count query 0xF02D8870(childID) returns nonzero. Structurally this indicates that a child has children / may open a submenu. It is NOT demonstrated to mean HIDDEN. No addressable Multimedia child[2] record was found in these exports, so a separate ID/callback/HIDDEN observation cannot yet be mapped to this generic flag.

An earlier user-provided clue says "child[2] -> valid ID -> valid callback -> flag HIDDEN". No table address, parent ID, or byte offset accompanied that clue. It is retained as a lead, not independently confirmed or attached to the framework flag above.

TABLE SEARCH
The ALICE scan checked aligned Thumb pointers to known Ghidra function starts in non-code regions, including regular record strides 4..32 bytes. It found no repeated static pointer run suitable for a Multimedia child table. Scans of ROM/VIVA/dump contain isolated pointer-looking matches, but no validated two-entry table linked to the current menu. The resource/menu APIs used above are external to the ALICE code image and populate runtime/external state, which explains why this pass does not yield a static table with the two child names.

APPLICATION VALIDATION
Image Viewer: no launch/highlight/init handler was connected to this list path with binary proof. The prior inventory found generic GDI/image helpers but no application cluster anchored to the visible menu row.
FM Radio: no user-menu handler was connected to this list path. The previously found FMradio factory-test table remains excluded.
Therefore child 0 and child 1 IDs/resources/callbacks remain unknown; no valid launch pointer is attributed to either row.

HIDDEN/SUPPLEMENTAL SLOTS
Physical count is two visible entries. Whether the external child-count API returns exactly two, returns more and filters hidden entries, or uses conditional per-item state is unknown. No slots 2+ can be declared present or absent. In particular, the generic +0x180 bit described above is not a hidden flag.

CONCLUSION
The best-supported answer is: the firmware has a generic MMI list pipeline (parent ID -> external child-count/ID/resource enumeration -> descriptor -> category renderer -> selection/redraw), but this pass did not identify the concrete parent or runtime data that makes the Multimedia screen contain Image Viewer and FM Radio. Exact child IDs, strings/images, highlight and launch handlers remain unlocated. No Audio Player insertion point can be named from this evidence.

NEXT STATIC TARGET
Resolve the external child/resource provider used by 0x10275714, especially 0xF02D8870 and 0xF032ACDC, and find the runtime/external menu records or table that feeds the descriptor. Only then can the Multimedia parent ID and its two visible children be attributed.

No firmware was modified; no flash image was produced.
"""

data = {
    "firmware": "ALTICE_F2_DS_V02.1_181023_MP",
    "cpu": "MT6261",
    "alice_base": "0x101812C4",
    "physical_observation": {"parent_label": "Multimedia", "visible_count": 2,
                              "visible_children": ["Image Viewer", "FM Radio"]},
    "identified_multimedia_parent": None,
    "child_rows": [
        {"index": 0, "application": "Image Viewer", "id": None, "string_id": None,
         "image_id": None, "highlight": None, "launch": None,
         "status": "visible on device; not mapped to binary entry"},
        {"index": 1, "application": "FM Radio", "id": None, "string_id": None,
         "image_id": None, "highlight": None, "launch": None,
         "status": "visible on device; not mapped to binary entry"}
    ],
    "generic_framework_candidates": FUNCTIONS,
    "generic_descriptor": {"child_ids_offset": "+0x40 (16-bit IDs)", "mode_flags_offset": "+0x44",
                           "child_count_offset": "+0x48", "evidence": "0x1024C4BC, 0x102731A0, 0x10275880"},
    "external_child_provider": {"get_child_count_candidate": "0xF02D8870",
                                "populate_child_ids_candidate": "0xF032ACDC",
                                "get_child_resource_candidate": "0xF02F9CCC",
                                "external_buffer_relative_offset": "+0x100",
                                "per_child_flags_relative_offset": "+0x180"},
    "flag_interpretation": {"bit": 0, "observed_condition": "GetChildCount(childID) != 0",
                             "likely": "child has children/submenu", "hidden_semantics_proven": False},
    "unmapped_user_reported_clue": {"description": "child[2] has valid ID and callback with HIDDEN flag",
                                    "table_address": None, "parent_id": None,
                                    "independently_confirmed": False,
                                    "reason": "no address/offset supplied; cannot match it to the generic +0x180 bit"},
    "physical_slots": {"visible_count": 2, "physical_count": None,
                       "slots_beyond_two": "uncertain; external count/filtering not mapped"},
    "pointer_table_scan": {"candidate_static_runs": 0,
                           "method": "known Thumb function pointers in non-code ALICE regions, strides 4..32",
                           "interpretation": "no validated Multimedia table found; does not exclude external/runtime tables"},
    "conclusion": "generic menu/list pipeline found; concrete Multimedia parent and its two child records not yet identified",
    "next_target": "external child/resource providers 0xF02D8870 / 0xF032ACDC and their backing runtime data"
}

OUT.mkdir(parents=True, exist_ok=True)
(OUT / "multimedia_exact_reconstruction.txt").write_text(report, encoding="ascii")
(OUT / "multimedia_exact_reconstruction.json").write_text(json.dumps(data, indent=2), encoding="utf-8")
print("Wrote multimedia exact reconstruction report and JSON to", OUT)
