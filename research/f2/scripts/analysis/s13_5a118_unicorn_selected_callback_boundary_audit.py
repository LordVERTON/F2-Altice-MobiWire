#!/usr/bin/env python3
"""S13.5A.118 — real ALICE selected-item callback, synthetic B702 RAM.

Uses Unicorn to execute ALICE 0x10342FC4 through its real nested call
0x10315514 and the exact store to descriptor+0x18. Stops on the next
instruction, BEFORE following UI functionality or any app launch.

Explicit host shims: platform 0x102FD104 -> 0 and 0x102FD0F4 -> synthetic
menu descriptor. No button press is emulated. This is NOT an MP3 launch test.
No phone, USB, COM, flash, firmware patch, repack, emulator configuration edit,
or Notepad. Only an exclusive-create text report is written.
"""
from __future__ import annotations

import argparse
import hashlib
from pathlib import Path
import struct
import sys

ALICE_BASE = 0x1024EC00
ALICE_SIZE = 0x157BB4
ALICE_SHA = "7246242b67afae0d13104452bc3257827cb778119b54e7a26fb7fb55993697ea"
ZIMAGE_BASE = 0xF023CA50
ZIMAGE_SIZE = 0x185E98
ZIMAGE_SHA = "85fba8c8ae8161e4c1f8ced7983ec30d48c54ab10e51c69fcdfb900aca220954"
SELECT_CB = 0x10342FC4
SELECT_GET_DESCRIPTOR_CALL = 0x10342FD0
SELECT_CHILD_LOOKUP_CALL = 0x10342FD8
SELECT_STORE = 0x10342FDC
STOP_AFTER_STORE = SELECT_STORE + 2
INDEX_TO_ID = 0x10315514
GET_STATE = 0x102FD104
GET_DESCRIPTOR = 0x102FD0F4
RAM_BASE = 0x20000000
RAM_SIZE = 0x10000
DESC = RAM_BASE + 0x1000
CHILDREN = RAM_BASE + 0x2000
STACK = RAM_BASE + 0xC000
SENTINEL = RAM_BASE + 0xF000
PAGE = 0x1000
MAX_STEPS = 350
REPORT = "s13_5a118_unicorn_selected_callback_boundary_audit.txt"
CURRENT = (0x8569, 0x87ED)
VIRTUAL = (0x8569, 0x87ED, 0x8928)
EXPECTED_SHIM_SEQUENCE = ((GET_STATE, 0), (GET_DESCRIPTOR, DESC),
                          (GET_STATE, 0), (GET_DESCRIPTOR, DESC))


def fail(msg: str) -> None:
    raise RuntimeError("A118_ABORT: " + msg)


def align_down(n: int) -> int:
    return n & ~(PAGE - 1)


def align_up(n: int) -> int:
    return (n + PAGE - 1) & ~(PAGE - 1)


def guarded(path: Path, tag: str, expected_size: int, expected_sha: str) -> bytes:
    if not path.is_file():
        fail(f"missing {tag} canonical input: {path}")
    b = path.read_bytes()
    digest = hashlib.sha256(b).hexdigest()
    if len(b) != expected_size or digest != expected_sha:
        fail(f"{tag} size/SHA mismatch size=0x{len(b):X} sha256={digest}")
    return b


def deps():
    try:
        from unicorn import (Uc, UcError, UC_ARCH_ARM, UC_MODE_THUMB,
                             UC_MODE_LITTLE_ENDIAN, UC_PROT_ALL, UC_PROT_READ,
                             UC_PROT_EXEC, UC_HOOK_CODE, UC_HOOK_MEM_INVALID,
                             UC_HOOK_MEM_WRITE)
        from unicorn.arm_const import (UC_ARM_REG_R0, UC_ARM_REG_R1,
                                       UC_ARM_REG_R4, UC_ARM_REG_SP,
                                       UC_ARM_REG_LR, UC_ARM_REG_CPSR)
        from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_LITTLE_ENDIAN
    except ImportError as e:
        fail(f"Unicorn and Capstone required in user Python: {e}")
    return locals()


def thumb_bl(src: int, dest: int) -> bytes:
    """Encode a synthetic test-only Thumb BL, never a firmware patch."""
    disp = dest - (src + 4)
    if disp & 1 or not (-(1 << 24) <= disp < (1 << 24)):
        fail("synthetic Thumb BL out of range")
    v = disp & ((1 << 25) - 1)
    s, i1, i2 = (v >> 24) & 1, (v >> 23) & 1, (v >> 22) & 1
    j1, j2 = 1 ^ (i1 ^ s), 1 ^ (i2 ^ s)
    return struct.pack("<HH", 0xF000 | (s << 10) | ((v >> 12) & 0x3FF),
                       0xD000 | (j1 << 13) | (j2 << 11) | ((v >> 1) & 0x7FF))


def shim_trace_matches(shims: list[tuple[int, int, int]]) -> bool:
    """Require two ordered pairs of guest context shims, including return values.

    In the true guest path, SELECT_CB calls GET_STATE+GET_DESCRIPTOR,
    then its nested INDEX_TO_ID does so again. Three shim calls are NOT valid.
    """
    return (tuple((pc, rv) for pc, rv, _lr in shims) == EXPECTED_SHIM_SEQUENCE
            and all((lr & 1) for _pc, _rv, lr in shims))


def static_self_test() -> None:
    assert (STOP_AFTER_STORE, SELECT_CHILD_LOOKUP_CALL, SELECT_GET_DESCRIPTOR_CALL) == (
        0x10342FDE, 0x10342FD8, 0x10342FD0)
    assert INDEX_TO_ID == 0x10315514
    assert list(VIRTUAL)[:2] == list(CURRENT) and VIRTUAL[2] == 0x8928
    assert struct.pack("<HHH", *VIRTUAL) == bytes.fromhex("6985ed872889")
    assert thumb_bl(0x30000102, 0x30000200).hex() == "00f07df8"
    example = [(pc, rv, 0x1001) for pc, rv in EXPECTED_SHIM_SEQUENCE]
    assert shim_trace_matches(example)
    assert not shim_trace_matches(example[:3])  # Original false negative.
    assert not shim_trace_matches(example[::-1])
    assert not shim_trace_matches(example[:-1] + [(GET_DESCRIPTOR, 0, 0x1001)])
    assert not shim_trace_matches(example[:-1] + [(GET_DESCRIPTOR, DESC, 0x1000)])
    print("A118_STATIC_SELF_TEST=PASS_MENU_BOUNDS_AND_SYNTHETIC_BL")


def unicorn_self_test(d: dict) -> str:
    """Actually exercise synthetic Thumb guest BL into shim with Unicorn."""
    u = d["Uc"](d["UC_ARCH_ARM"], d["UC_MODE_THUMB"] | d["UC_MODE_LITTLE_ENDIAN"])
    base = 0x30000000
    u.mem_map(base, PAGE, d["UC_PROT_ALL"])
    fun, shim, done = base + 0x100, base + 0x200, base + 0x300
    u.mem_write(fun, b"\x00\xb5" + thumb_bl(fun + 2, shim) + b"\x00\xbd")
    u.mem_write(done, b"\x00\xbf")
    u.mem_protect(base, PAGE, d["UC_PROT_READ"] | d["UC_PROT_EXEC"])
    u.mem_map(0x30010000, PAGE, d["UC_PROT_ALL"])
    u.reg_write(d["UC_ARM_REG_SP"], 0x30010800)
    u.reg_write(d["UC_ARM_REG_LR"], done | 1)
    state = {"event": None}

    def code(mu, pc, size, _):
        if pc in (shim, done):
            state["event"] = pc
            mu.emu_stop()

    u.hook_add(d["UC_HOOK_CODE"], code)
    u.emu_start(fun | 1, 0, count=30)
    if state["event"] != shim:
        fail("synthetic test shim not reached")
    lr = u.reg_read(d["UC_ARM_REG_LR"])
    u.reg_write(d["UC_ARM_REG_R0"], 0x8928)
    u.reg_write(d["UC_ARM_REG_CPSR"], u.reg_read(d["UC_ARM_REG_CPSR"]) | 0x20)
    state["event"] = None
    u.emu_start(lr | 1, 0, count=30)
    if state["event"] != done or u.reg_read(d["UC_ARM_REG_R0"]) != 0x8928:
        fail("synthetic host shim or register return failed")
    return "A118_UNICORN_SELF_TEST=PASS_SYNTHETIC_GUEST_CALL_HOST_SHIM_RETURN"


def capstone_guards(alice: bytes, d: dict) -> list[str]:
    cs = d["Cs"](d["CS_ARCH_ARM"], d["CS_MODE_THUMB"] | d["CS_MODE_LITTLE_ENDIAN"])
    out = []
    for address, name, dest in (
        (SELECT_GET_DESCRIPTOR_CALL, "SELECT_GET_DESCRIPTOR", GET_DESCRIPTOR),
        (SELECT_CHILD_LOOKUP_CALL, "SELECT_LOOKUP_CHILD", INDEX_TO_ID),
    ):
        offset = address - ALICE_BASE
        ins = list(cs.disasm(alice[offset:offset + 4], address, count=1))
        if not ins or ins[0].address != address or ins[0].mnemonic not in ("bl", "blx"):
            fail(f"anchor not direct Thumb BL/BLX {name} 0x{address:08X}")
        try:
            target = int(ins[0].op_str.lstrip("#"), 0) & ~1
        except ValueError:
            fail(f"anchor without immediate branch operand: {name}")
        if target != dest:
            fail(f"anchor {name} target=0x{target:08X} expected=0x{dest:08X}")
        out.append(f"{name}=PASS 0x{address:08X} {ins[0].mnemonic} {ins[0].op_str}")
    offset = SELECT_STORE - ALICE_BASE
    store = list(cs.disasm(alice[offset:offset + 2], SELECT_STORE, count=1))
    if not store or store[0].size != 2 or store[0].mnemonic != "strh":
        fail("descriptor selected-child store anchor not a 16-bit STRH")
    operand = store[0].op_str.lower().replace(" ", "")
    if operand not in ("r0,[r4,#0x18]", "r0,[r4,#24]"):
        fail(f"selected-child STRH operand changed: {store[0].op_str}")
    out.append(f"SELECTED_CHILD_STORE=PASS 0x{SELECT_STORE:08X} {store[0].mnemonic} {store[0].op_str}")
    for address, name in ((SELECT_CB, "SELECT_CALLBACK"), (INDEX_TO_ID, "NATIVE_INDEX_LOOKUP")):
        off = address - ALICE_BASE
        first = list(cs.disasm(alice[off:off + 4], address, count=1))
        if not first or first[0].address != address or first[0].mnemonic != "push":
            fail(f"function entry altered: {name} 0x{address:08X}")
        out.append(f"{name}=PASS ENTRY=0x{address:08X} {first[0].mnemonic} {first[0].op_str}")
    return out


def run_guest(d: dict, alice: bytes, zimage: bytes,
              children: tuple[int, ...], index: int) -> dict:
    u = d["Uc"](d["UC_ARCH_ARM"], d["UC_MODE_THUMB"] | d["UC_MODE_LITTLE_ENDIAN"])
    for base, blob in ((ALICE_BASE, alice), (ZIMAGE_BASE, zimage)):
        lo, length = align_down(base), align_up(base + len(blob)) - align_down(base)
        u.mem_map(lo, length, d["UC_PROT_ALL"])
        u.mem_write(base, blob)
        u.mem_protect(lo, length, d["UC_PROT_READ"] | d["UC_PROT_EXEC"])
    u.mem_map(RAM_BASE, RAM_SIZE, d["UC_PROT_ALL"])
    descriptor = bytearray(0x100)
    struct.pack_into("<H", descriptor, 0x14, 0xB702)
    struct.pack_into("<H", descriptor, 0x18, 0xEEEE)
    struct.pack_into("<I", descriptor, 0x40, CHILDREN)
    struct.pack_into("<I", descriptor, 0x48, len(children))
    u.mem_write(DESC, bytes(descriptor))
    u.mem_write(CHILDREN, struct.pack("<" + "H" * len(children), *children))
    u.mem_write(SENTINEL, b"\x00\xbf")
    u.reg_write(d["UC_ARM_REG_SP"], STACK)
    u.reg_write(d["UC_ARM_REG_LR"], SENTINEL | 1)
    u.reg_write(d["UC_ARM_REG_R0"], index)
    u.reg_write(d["UC_ARM_REG_R1"], 0)

    state: dict = {"stop": None, "steps": 0, "shims": [], "lookup_entries": 0,
                   "guest_stores": [], "fault": None, "outside_ram_writes": []}

    def code(mu, pc, _size, _user):
        state["steps"] += 1
        if pc == INDEX_TO_ID:
            state["lookup_entries"] += 1
        if pc in (GET_STATE, GET_DESCRIPTOR, SENTINEL):
            state["stop"] = ("shim" if pc != SENTINEL else "sentinel", pc)
            mu.emu_stop()
        elif pc == STOP_AFTER_STORE:
            state["stop"] = ("after_selected_store", pc)
            mu.emu_stop()
        elif not ((SELECT_CB <= pc < STOP_AFTER_STORE)
                  or (INDEX_TO_ID <= pc < INDEX_TO_ID + 0x60)):
            state["stop"] = ("unexpected_code", pc)
            mu.emu_stop()
        elif state["steps"] > MAX_STEPS:
            state["stop"] = ("step_limit", pc)
            mu.emu_stop()

    def store(mu, _access, address, size, value, _user):
        if address == DESC + 0x18 and size == 2:
            state["guest_stores"].append((address, value & 0xFFFF))
        elif DESC <= address < DESC + 0x100 or CHILDREN <= address < CHILDREN + 0x100:
            state["outside_ram_writes"].append((address, size, value))

    def invalid(_mu, access, address, size, value, _user):
        state["fault"] = (access, address, size, value)
        return False

    u.hook_add(d["UC_HOOK_CODE"], code)
    u.hook_add(d["UC_HOOK_MEM_WRITE"], store)
    u.hook_add(d["UC_HOOK_MEM_INVALID"], invalid)

    resume = SELECT_CB | 1
    status = "INCONCLUSIVE"
    for _ in range(12):
        state["stop"] = None
        try:
            u.emu_start(resume, 0, count=MAX_STEPS + 5)
        except d["UcError"] as e:
            status = f"GUEST_FAULT:{type(e).__name__}:{e}"
            break
        stop = state["stop"]
        if stop is None:
            status = "NO_BOUNDARY_STOP"
            break
        kind, pc = stop
        if kind == "after_selected_store":
            status = "STOP_AFTER_SELECTED_STORE"
            break
        if kind != "shim":
            status = f"{kind.upper()}_0x{pc:08X}"
            break
        lr = u.reg_read(d["UC_ARM_REG_LR"])
        if not lr & 1:
            status = f"UNEXPECTED_HELPER_LR_MODE_0x{lr:08X}"
            break
        return_value = 0 if pc == GET_STATE else DESC
        state["shims"].append((pc, return_value, lr))
        u.reg_write(d["UC_ARM_REG_R0"], return_value)
        u.reg_write(d["UC_ARM_REG_CPSR"], u.reg_read(d["UC_ARM_REG_CPSR"]) | 0x20)
        resume = lr | 1
    else:
        status = "TOO_MANY_SHIMS"

    selected = struct.unpack("<H", u.mem_read(DESC + 0x18, 2))[0]
    parent = struct.unpack("<H", u.mem_read(DESC + 0x14, 2))[0]
    count = struct.unpack("<I", u.mem_read(DESC + 0x48, 4))[0]
    ptr = struct.unpack("<I", u.mem_read(DESC + 0x40, 4))[0]
    array = struct.unpack("<" + "H" * len(children), u.mem_read(CHILDREN, len(children) * 2))
    return {
        "status": status, "selected": selected, "parent": parent, "count": count,
        "ptr": ptr, "children": array, "steps": state["steps"],
        "shims": state["shims"], "lookup_entries": state["lookup_entries"],
        "guest_stores": state["guest_stores"],
        "unexpected_descriptor_writes": state["outside_ram_writes"],
        "fault": state["fault"], "r4": u.reg_read(d["UC_ARM_REG_R4"]),
        "r0": u.reg_read(d["UC_ARM_REG_R0"]),
    }


def exercise(d: dict, alice: bytes, zimage: bytes) -> str:
    lines = [
        "S13.5A.118 — REAL ALICE SELECTED-CALLBACK CPU EDGE / SYNTHETIC B702 RAM",
        "STRICTLY_OFFLINE=YES ROM_READ_ONLY_AND_GUEST_RX=YES RAM_SYNTHETIC=YES NO_PHONE_USB_COM=YES",
        "NO_FLASH_PATCH_REPACK_NOTEPAD_EMULATOR_MANIFEST_EDIT=YES",
        "NOT_A_REAL_OK_EVENT_OR_AUDIO_LAUNCH=YES",
        f"ALICE_GUARD=PASS SIZE=0x{len(alice):X} SHA256={ALICE_SHA}",
        f"ZIMAGE_GUARD=PASS SIZE=0x{len(zimage):X} SHA256={ZIMAGE_SHA}",
        unicorn_self_test(d),
        *capstone_guards(alice, d),
        "GUEST_PATH=10342FC4(selected_index)->10315514(index_to_id)->STRH(descriptor+0x18)",
        "STOP=0x10342FDE_AFTER_STORE_BEFORE_ANY_FOLLOWUP_UI_ACTION",
        "CONTEXT_SHIMS=102FD104_RETURN_0,102FD0F4_RETURN_SYNTHETIC_DESC",
        "EXPECTED_CONTEXT_SHIM_SEQUENCE=GET_STATE,GET_DESCRIPTOR,GET_STATE,GET_DESCRIPTOR",
        "SHIM_SIDE_EFFECTS_ARE_UNPROVEN_IN_REAL_RUNTIME=YES",
        "B702_CURRENT=8569,87ED B702_VIRTUAL=8569,87ED,8928",
        "",
    ]
    failures = []
    for name, children in (("CURRENT", CURRENT), ("VIRTUAL", VIRTUAL)):
        lines.append(f"=== {name}: COUNT={len(children)} ===")
        for index in (0, 1, 2, 3):
            expected = children[index] if index < len(children) else 0xFFFF
            result = run_guest(d, alice, zimage, children, index)
            core = (
                result["status"] == "STOP_AFTER_SELECTED_STORE"
                and result["selected"] == expected
                and result["r4"] == DESC
                and result["lookup_entries"] == 1
                and shim_trace_matches(result["shims"])
                and result["parent"] == 0xB702
                and result["ptr"] == CHILDREN
                and result["count"] == len(children)
                and tuple(result["children"]) == children
                and result["guest_stores"] == [(DESC + 0x18, expected)]
                and not result["unexpected_descriptor_writes"]
                and result["fault"] is None
            )
            required = (index in (0, 1)) or (name == "VIRTUAL" and index == 2)
            # Invalid indexes are informational until callback invalid-index semantics
            # have been established by actual traces (never overclaim this path).
            label = "PASS" if core else "INCONCLUSIVE"
            if required and not core:
                failures.append((name, index, result["status"]))
            lines.append(
                f"SELECT_CALLBACK list={name} index={index} EXPECT_SELECTED=0x{expected:04X} "
                f"DESC_PLUS18=0x{result['selected']:04X} GUEST_R0=0x{result['r0']:08X} "
                f"STATUS={result['status']} STEPS={result['steps']} "
                f"ASSERT={label} GATE={'REQUIRED' if required else 'INFORMATIONAL'}"
            )
            lines.append(
                f"  R4=0x{result['r4']:08X} LOOKUP_ENTRIES={result['lookup_entries']} "
                f"SHIMS={result['shims']} GUEST_STORES={result['guest_stores']} "
                f"UNEXPECTED_DESC_WRITES={result['unexpected_descriptor_writes']} FAULT={result['fault']}"
            )
        lines.append("")
    lines += [
        "=== DECISION ===",
        "CONTROLLED_SELECTED_CALLBACK_CPU=PASS_REQUIRED_CASES" if not failures else "CONTROLLED_SELECTED_CALLBACK_CPU=INCONCLUSIVE",
        f"REQUIRED_CASE_FAILURES={failures}",
        "NATIVE_SELECTED_INDEX_WRITES_DESC_PLUS18=CONDITIONAL_GUEST_ONLY" if not failures else "NATIVE_SELECTED_INDEX_WRITES_DESC_PLUS18=NOT_FULLY_VALIDATED",
        "REAL_UI_OK_SELECT_DISPATCH=NOT_EMULATED_OR_PROVEN",
        "REAL_B702_RUNTIME_PROVIDER_AND_RELOCATION=NOT_PROVEN",
        "NATIVE_AUDIO_8928_PLAYBACK=NOT_PROVEN",
        "NEXT=IF_PASS_CHOOSE_ONE_TRUSTED_EXECUTION_EDGE_AFTER_SELECTION_BEFORE_LEAF_ACTION",
        "PHYSICAL_PATCH_AUTHORIZED=NO",
    ]
    return "\n".join(lines) + "\n"


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(r"C:\Users\verto\F2-Altice-MobiWire"))
    parser.add_argument("--out", type=Path)
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--self-test-static", action="store_true")
    args = parser.parse_args()
    static_self_test()
    if args.self_test_static:
        return
    d = deps()
    print(unicorn_self_test(d))
    if args.self_test:
        return
    root: Path = args.root
    alice = guarded(root / "research/f2/work/extracted/altice_alice/alice-py.bin", "ALICE", ALICE_SIZE, ALICE_SHA)
    zimage = guarded(root / "research/f2/work/extracted/altice_platform/zimage.bin", "ZIMAGE", ZIMAGE_SIZE, ZIMAGE_SHA)
    report = exercise(d, alice, zimage)
    out = args.out or root / "research/f2/work/reports" / REPORT
    if not out.parent.is_dir():
        fail("reports directory missing: " + str(out.parent))
    with out.open("x", encoding="utf-8", newline="\n") as f:
        f.write(report)
    print(f"A118_REPORT_CREATED={out} BYTES={out.stat().st_size}")
    print("A118_CPU_RESULT=" + ("PASS_REQUIRED_CASES" if "CONTROLLED_SELECTED_CALLBACK_CPU=PASS_REQUIRED_CASES" in report else "INCONCLUSIVE"))


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(f"A118_FAILED={type(exc).__name__}: {exc}", file=sys.stderr)
        sys.exit(2)
