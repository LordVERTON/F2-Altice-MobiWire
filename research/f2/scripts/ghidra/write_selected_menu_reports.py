import json
from pathlib import Path

out = Path(__file__).resolve().parents[4] / "research" / "f2" / "work" / "ghidra" / "alice_reports"

selected = {
    "scope": "Static analysis of extracted Altice ALICE only; external framework APIs are represented by ROM/import thunks.",
    "descriptor_fields": {"+0x14": "current parent/menu ID (U16)", "+0x18": "selected child ID (U16)", "+0x40": "pointer to child ID array", "+0x48": "child count"},
    "confirmed_writers": [
        {"function": "0x102757D0", "instruction": "0x1027584E: STRH R5,[R4,#0x18]", "value": "R5 was initialized to zero in this reset routine", "interpretation": "initialization/reset, not the highlight-change writer"},
        {"function": "0x102B7F00", "instruction": "0x102B7F2A: STRH R0,[R3,#0x18]", "base": "R3=SP; writes a stack-local record", "interpretation": "unrelated object"}
    ],
    "readers": [
        {"function": "0x1021F904", "instruction": "0x1021F924: passes *(U16 *)(descriptor+0x18) to 0x1024C4BC", "role": "uses selected ID to find its index in child list"},
        {"function": "0x10275880", "instruction": "0x10275924: reads U16 descriptor+0x18; then calls 0x1024C4BC", "role": "renderer resolves selected ID to highlight index"},
        {"function": "0x102BA458", "instruction": "0x102BA47C-0x102BA47E: copies selected ID +0x18 to parent ID +0x14", "role": "enter selected child/submenu"}
    ],
    "selected_index": {"persistent_field": "not found", "mapping": "0x1024C4BC performs selected ID -> index by linear scan; no reverse index -> ID writer identified", "confidence": "high for reverse mapping; unknown where live selection updates +0x18"},
    "main_menu": {"identified": False, "parent_id": None, "child_count": None, "child_ids": None, "reason": "child list is obtained at runtime through external APIs; no root descriptor instance or runtime values are available in the static ALICE export"},
    "multimedia": {"identified": False, "parent_id": None, "child_ids": None, "physical_child_count_observation": 2, "reason": "the observed UI count alone does not identify numeric parent or child IDs"}
}

buffer = {
    "allocator_site": "0x102731A0",
    "allocation_api_thunk": "0x1022ECF0 (external target/import mapping; allocator role inferred from call arguments and returned pointer)",
    "requested_size": "0x1C0 bytes",
    "global_heap_base_cell": "0xF00B1C38",
    "descriptor_children_pointer": "heap_base + 0x100 stored to descriptor+0x40",
    "fill_call": {"site": "0x1027572C", "thunk": "0x1022EA20", "external_target_thumb": "0xF032ACDC", "args": "R0=parent ID; R1=heap_base+0x100 output buffer", "conclusion": "external child-enumeration API fills this buffer"},
    "count_call": {"site": "0x10275732", "thunk": "0x1022EAB0", "external_target_thumb": "0xF02D8870", "args": "R0=parent ID", "return": "stored into descriptor+0x48"},
    "layout": [
        {"range": "+0x000..+0x0FF", "access": "U16 indexed values are written per child at +2*i by 0x10275714 using return from thunk 0x1022C788", "meaning": "not established; likely per-item metadata/resource value, do not label as string ID without further proof"},
        {"range": "+0x100..+0x17F", "access": "U16 child IDs; descriptor+0x40 points to +0x100; indexed by 2*i", "meaning": "confirmed child-ID array"},
        {"range": "+0x180..+0x1BF", "access": "U8 per-child flags; bit0 set when child-count API says that child has children", "meaning": "has-children marker, not hidden flag"}
    ],
    "index_id_mapping": {"function": "0x1024C4BC", "algorithm": "for i in [0,count): if *(U16 *)(descriptor+0x40+2*i)==selected_id return i; else return -1", "direction": "ID -> index only"},
    "selection_update": "No nonzero write of this descriptor's +0x18 identified in ALICE. The only descriptor-compatible write found is reset-to-zero at 0x1027584E. Live selection update may occur in external UI/framework code or through an indirect/shared-state path; this remains unproven."
}

main = {
    "identified": False,
    "root_parent_id": None,
    "root_child_count": None,
    "root_child_ids": [],
    "multimedia_parent_id": None,
    "evidence": ["0x102BA458 promotes selected ID (+0x18) into current parent (+0x14).", "0x102731A0 rebuilds child data dynamically for the current parent through external calls.", "No runtime snapshot of the descriptor or external API implementation/data table is present in the analyzed artifacts."],
    "physical_observation": "The handset displays Multimedia with exactly Image Viewer and FM Radio; this establishes the visible count, not the numeric IDs."
}

candidates = {
    "multimedia_numeric_id_found": False,
    "candidates": [],
    "why_none": "Static code establishes the navigation mechanism but parent and children are supplied dynamically by external menu APIs. No numeric ID can be attributed to Multimedia from the current ALICE-only static data without guessing.",
    "next_step": "Capture the live menu descriptor or obtain/decode the implementation and backing tables for external targets F032ACDC and F02D8870; inspect descriptor+0x14/+0x18/+0x40/+0x48 while opening the root and Multimedia."
}

def emit(stem, data, text):
    (out / f"{stem}.json").write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    (out / f"{stem}.txt").write_text(text.strip() + "\n", encoding="utf-8")

emit("menu_selected_id_trace", selected, """
SELECTED CHILD ID — STATIC TRACE

Descriptor field +0x18 is read as a U16 selected child ID by 0x1021F904 and 0x10275880. It is copied to +0x14 by 0x102BA458 when entering the selected item.

Writers found:
- 0x102757D0 / 0x1027584E: STRH R5,[R4,#0x18], where R5 is initialized to zero in the reset routine. This is a reset, not a live highlight update.
- 0x102B7F00 / 0x102B7F2A: STRH R0,[R3,#0x18], but R3=SP; this is a stack-local structure and unrelated.

No nonzero write to the live menu descriptor's +0x18 was identified in the available ALICE instructions. This does not prove the field is never updated: the writer may be in external framework code or reached through an indirect path absent from this ALICE image.

There is no confirmed persistent selected-index field. 0x1024C4BC takes a selected ID and linearly searches the U16 child IDs at descriptor+0x40, bounded by count at +0x48, returning the matching index or -1. The found operation is ID -> index; the requested reverse operation index -> selected ID remains unlocated.

0x1021F904 only consumes the current +0x18 value after a pending flag at +0x0C is set; it resolves the selected ID to an index, then calls 0x102BA458. 0x10275880 similarly resolves the selected ID for rendering/highlight. Thus the observed code handles a selection already stored elsewhere; it does not show who updates it.
""")

emit("menu_child_buffer_analysis", buffer, """
CHILD BUFFER ANALYSIS

0x102731A0 allocates 0x1C0 bytes through thunk 0x1022ECF0 and stores the returned heap base through the global pointer cell at 0xF00B1C38. It writes heap_base+0x100 to descriptor+0x40.

0x10275714 passes the current parent ID in R0 and heap_base+0x100 in R1 to thunk 0x1022EA20 (external Thumb target 0xF032ACDC) at 0x1027572C. The following count call at 0x10275732 uses thunk 0x1022EAB0 (external target 0xF02D8870); its result is stored at descriptor+0x48.

Confirmed layout/use:
- heap_base+0x100: U16 child-ID array; descriptor+0x40 points here; readers use 2-byte stride.
- heap_base+0x180: byte flags indexed by child index; bit0 is set when that child has children. This is not evidence of a hidden flag.
- heap_base+0x000: 0x10275714 writes a U16 value per child at 2*i using the result of thunk 0x1022C788. Its semantic type is not proven.

0x1024C4BC implements a linear scan of descriptor+0x40: child_ids[i] == selected_id -> return i. No code found here maps selected index back to an ID and writes +0x18.
""")

emit("main_menu_child_ids", main, """
MAIN MENU CHILD IDS

Root descriptor and numeric Main Menu parent ID: NOT IDENTIFIED.
Child count and IDs: NOT RECOVERED.

The available static ALICE code rebuilds children dynamically via external menu APIs. The external child-enumeration target 0xF032ACDC and child-count target 0xF02D8870 are represented by thunks, and the current artifacts contain no runtime descriptor snapshot or decoded backing table. Therefore numeric child IDs cannot be extracted from the present static evidence.

Known navigation mechanism: on entry, 0x102BA458 copies selected child ID at descriptor+0x18 into current parent ID at +0x14, then 0x10279AF6 refreshes the menu. 0x102731A0 subsequently allocates/repopulates the child buffer for that parent.

Handset observation: the root contains a Multimedia item, whose opened menu displays exactly Image Viewer and FM Radio. This observation does not provide their numeric IDs.
""")

emit("multimedia_id_candidates", candidates, """
MULTIMEDIA NUMERIC ID CANDIDATES

No numeric Multimedia parent ID or child IDs are identified from the current static ALICE artifacts. No candidate is promoted based only on having two children.

The verified mechanism is dynamic: parent ID +0x14 is passed to external enumeration/count APIs; their result populates a heap child-ID array referenced by +0x40 and count +0x48. Opening the selected item promotes +0x18 to +0x14.

The physical handset confirms the visible Multimedia list has two entries (Image Viewer, FM Radio). This is a validation target for a future runtime capture, not a numeric-ID proof.

Next single step: inspect the live descriptor (or decode the external menu API/backing data) at root and after opening Multimedia, recording +0x14, +0x18, +0x40 contents and +0x48.
""")
