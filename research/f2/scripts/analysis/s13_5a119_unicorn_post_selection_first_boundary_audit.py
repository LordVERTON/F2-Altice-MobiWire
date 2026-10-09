#!/usr/bin/env python3
"""S13.5A.119 — bounded real-ALICE CPU continuation immediately AFTER selected-ID store.

Run confirmed A118 selection guest under the same explicit synthetic B702
runtime assumptions, but let the real callback execute past descriptor+0x18
until the FIRST external CALL / return boundary. Stop BEFORE that call; do not
simulate any real OK event, UI dispatcher, app/audio callback or phone boot.

Dependencies: corrected committed A118 module in the same analysis folder,
Unicorn and Capstone in the user's Python environment. NO firmware modifications,
no phone/USB/COM, no flash/repack, no emulator manifest, no Notepad.
Only an exclusive-create TXT report under work/reports is produced.
"""
from __future__ import annotations

import argparse
import hashlib
from pathlib import Path
import struct
import sys

import s13_5a118_unicorn_selected_callback_boundary_audit as a118

EXPECTED_A118_SHA256 = "5d2b80f5054bcad8162e8327d922236fdded34f563fa2cbf404be0771af04993"
REPORT = "s13_5a119_unicorn_post_selection_first_boundary_audit.txt"
MAX_TOTAL_STEPS = 180
CALL_MNEMONICS = frozenset({"bl", "blx", "svc", "swi"})
# This window bounds only the ALICE selection callback. It does NOT establish
# a true complete function boundary for reverse engineering.
LOCAL_START, LOCAL_END = a118.SELECT_CB, 0x10343038


def fail(msg: str) -> None:
    raise RuntimeError("A119_ABORT: " + msg)


def check_dependency() -> str:
    path = Path(a118.__file__).resolve()
    digest = hashlib.sha256(path.read_bytes().replace(b"\r\n", b"\n")).hexdigest()
    if digest != EXPECTED_A118_SHA256:
        fail(f"A118 dependency source changed: {path} sha256={digest}; expected fixed v2")
    return f"A118_DEPENDENCY_SOURCE_SHA256=PASS {digest}"


def static_self_test() -> None:
    a118.static_self_test()
    assert LOCAL_START == 0x10342FC4 and LOCAL_END == 0x10343038
    assert a118.STOP_AFTER_STORE == 0x10342FDE
    assert a118.DESC + 0x18 == 0x20001018
    assert a118.VIRTUAL[2] == 0x8928
    assert {"bl", "blx"} <= CALL_MNEMONICS
    assert expected_boundary("CALL", "bl", True)
    assert expected_boundary("RETURN", "pop", True)
    assert not expected_boundary("UNEXPECTED_CODE", "bl", True)
    assert not expected_boundary("CALL", "bl", False)
    print("A119_STATIC_SELF_TEST=PASS_DEPENDENCY_AND_BOUNDARY_GATES")


def expected_boundary(kind: str, mnemonic: str, selected_store_seen: bool) -> bool:
    return selected_store_seen and ((kind == "CALL" and mnemonic in CALL_MNEMONICS) or kind == "RETURN")


def run_one(d: dict, alice: bytes, zimage: bytes,
            ids: tuple[int, ...], index: int) -> dict:
    u = d["Uc"](d["UC_ARCH_ARM"], d["UC_MODE_THUMB"] | d["UC_MODE_LITTLE_ENDIAN"])
    for base, blob in ((a118.ALICE_BASE, alice), (a118.ZIMAGE_BASE, zimage)):
        low = a118.align_down(base)
        mapped_size = a118.align_up(base + len(blob)) - low
        u.mem_map(low, mapped_size, d["UC_PROT_ALL"])
        u.mem_write(base, blob)
        u.mem_protect(low, mapped_size, d["UC_PROT_READ"] | d["UC_PROT_EXEC"])

    u.mem_map(a118.RAM_BASE, a118.RAM_SIZE, d["UC_PROT_ALL"])
    descriptor = bytearray(0x100)
    struct.pack_into("<H", descriptor, 0x14, 0xB702)
    struct.pack_into("<H", descriptor, 0x18, 0xEEEE)
    struct.pack_into("<I", descriptor, 0x40, a118.CHILDREN)
    struct.pack_into("<I", descriptor, 0x48, len(ids))
    u.mem_write(a118.DESC, bytes(descriptor))
    u.mem_write(a118.CHILDREN, struct.pack("<" + "H" * len(ids), *ids))
    u.mem_write(a118.SENTINEL, b"\x00\xbf")
    u.reg_write(d["UC_ARM_REG_SP"], a118.STACK)
    u.reg_write(d["UC_ARM_REG_LR"], a118.SENTINEL | 1)
    u.reg_write(d["UC_ARM_REG_R0"], index)
    u.reg_write(d["UC_ARM_REG_R1"], 0)

    # A118.deps() exports only the ARM registers needed by A118 itself.
    # Import A119's additional register constants here, without editing A118.
    from unicorn.arm_const import UC_ARM_REG_R2, UC_ARM_REG_R3
    cs = d["Cs"](d["CS_ARCH_ARM"], d["CS_MODE_THUMB"] | d["CS_MODE_LITTLE_ENDIAN"])
    state: dict = {"steps": 0, "event": None, "shims": [], "selected_stores": [],
                   "unexpected_writes": [], "lookup_count": 0, "fault": None,
                   "post_store_instructions": [], "boundary": None,
                   "post_store_started": False}

    def code(mu, pc, _size, _):
        state["steps"] += 1
        if state["steps"] > MAX_TOTAL_STEPS:
            state["event"] = ("STEP_CAP", pc)
            mu.emu_stop()
            return
        if pc == a118.INDEX_TO_ID:
            state["lookup_count"] += 1
        if pc in (a118.GET_STATE, a118.GET_DESCRIPTOR):
            state["event"] = ("SHIM", pc)
            mu.emu_stop()
            return
        if pc == a118.SENTINEL:
            state["event"] = ("SENTINEL", pc)
            mu.emu_stop()
            return
        if pc == a118.STOP_AFTER_STORE:
            state["post_store_started"] = True
        if not (LOCAL_START <= pc < LOCAL_END or
                a118.INDEX_TO_ID <= pc < a118.INDEX_TO_ID + 0x60):
            state["event"] = ("ESCAPE", pc)
            mu.emu_stop()
            return
        if not state["post_store_started"]:
            return
        # Never invoke a new call or indirect branch: capture register state
        # at the exact instruction boundary, before its execution.
        insns = list(cs.disasm(bytes(mu.mem_read(pc, 4)), pc, count=1))
        if not insns or insns[0].address != pc:
            state["event"] = ("BAD_DECODE", pc)
            mu.emu_stop()
            return
        ins = insns[0]
        if len(state["post_store_instructions"]) < 16:
            state["post_store_instructions"].append(f"0x{pc:08X}:{ins.mnemonic} {ins.op_str}")
        is_return = (ins.mnemonic == "pop" and "pc" in ins.op_str.lower()) or (
            ins.mnemonic == "bx" and ins.op_str.strip().lower() == "lr")
        if ins.mnemonic in CALL_MNEMONICS or ins.mnemonic in {"bx", "blx"} or is_return:
            kind = "RETURN" if is_return else "CALL" if ins.mnemonic in CALL_MNEMONICS else "INDIRECT_JUMP"
            state["event"] = ("BOUNDARY", pc)
            state["boundary"] = {
                "kind": kind, "pc": pc, "mnemonic": ins.mnemonic,
                "op": ins.op_str, "r0": mu.reg_read(d["UC_ARM_REG_R0"]),
                "r1": mu.reg_read(d["UC_ARM_REG_R1"]),
                "r2": mu.reg_read(UC_ARM_REG_R2),
                "r3": mu.reg_read(UC_ARM_REG_R3),
                "r4": mu.reg_read(d["UC_ARM_REG_R4"]),
                "selected": struct.unpack("<H", mu.mem_read(a118.DESC + 0x18, 2))[0],
            }
            mu.emu_stop()

    def mem_write(_mu, _access, address, size, value, _):
        if address == a118.DESC + 0x18 and size == 2:
            state["selected_stores"].append((address, value & 0xFFFF))
        elif a118.DESC <= address < a118.DESC + 0x100 or a118.CHILDREN <= address < a118.CHILDREN + 0x100:
            state["unexpected_writes"].append((address, size, value))

    def mem_invalid(_mu, access, address, size, value, _):
        state["fault"] = (access, address, size, value)
        return False

    u.hook_add(d["UC_HOOK_CODE"], code)
    u.hook_add(d["UC_HOOK_MEM_WRITE"], mem_write)
    u.hook_add(d["UC_HOOK_MEM_INVALID"], mem_invalid)
    resume = LOCAL_START | 1
    status = "INCONCLUSIVE"
    for _ in range(12):
        state["event"] = None
        try:
            u.emu_start(resume, 0, count=MAX_TOTAL_STEPS + 10)
        except d["UcError"] as e:
            status = f"GUEST_FAULT_{type(e).__name__}: {e}"
            break
        event = state["event"]
        if event is None:
            status = "MISSING_EVENT"
            break
        kind, pc = event
        if kind == "BOUNDARY":
            status = "NEXT_BOUNDARY_CAPTURED"
            break
        if kind != "SHIM":
            status = f"{kind}_0x{pc:08X}"
            break
        lr = u.reg_read(d["UC_ARM_REG_LR"])
        if lr & 1 == 0:
            status = f"UNEXPECTED_SHIM_LR_0x{lr:08X}"
            break
        ret = 0 if pc == a118.GET_STATE else a118.DESC
        state["shims"].append((pc, ret, lr))
        u.reg_write(d["UC_ARM_REG_R0"], ret)
        u.reg_write(d["UC_ARM_REG_CPSR"], u.reg_read(d["UC_ARM_REG_CPSR"]) | 0x20)
        resume = lr | 1
    else:
        status = "TOO_MANY_SHIMS"

    selected = struct.unpack("<H", u.mem_read(a118.DESC + 0x18, 2))[0]
    return {
        "status": status, "selected": selected, "steps": state["steps"],
        "lookup_count": state["lookup_count"],
        "shims": state["shims"], "stores": state["selected_stores"],
        "unexpected_writes": state["unexpected_writes"], "fault": state["fault"],
        "post_store_started": state["post_store_started"],
        "post_store_instructions": state["post_store_instructions"],
        "boundary": state["boundary"],
        "parent": struct.unpack("<H", u.mem_read(a118.DESC + 0x14, 2))[0],
        "count": struct.unpack("<I", u.mem_read(a118.DESC + 0x48, 4))[0],
    }


def analyze(d: dict, alice: bytes, zimage: bytes) -> str:
    control = ("CURRENT_87ED", a118.CURRENT, 1)
    virtual = ("VIRTUAL_8928", a118.VIRTUAL, 2)
    lines = [
        "S13.5A.119 — UNICORN ALICE REAL SELECTION: FIRST POST-STORE CONTROL TRANSFER",
        "NO_PHONE_USB_COM_FLASH_REPACK_FIRMWARE_PATCH_EMULATOR_MANIFEST_EDIT=YES",
        "ALICE_ZIMAGE_GUEST_ROM_RX=YES GUEST_DESCRIPTOR_RAM_SYNTHETIC=YES",
        "NOT_FULL_PHONE_BOOT_NOT_REAL_OK_EVENT_NOT_LEAF_LAUNCH=YES",
        f"ALICE_GUARD=PASS SIZE=0x{len(alice):X} SHA256={a118.ALICE_SHA}",
        f"ZIMAGE_GUARD=PASS SIZE=0x{len(zimage):X} SHA256={a118.ZIMAGE_SHA}",
        check_dependency(),
        "A118_COMMITTED_SHIM_ASSUMPTIONS=GET_STATE_RET0_AND_GET_DESCRIPTOR_RET_SYNTHETIC",
        "A118_REQUIRED_RESULT=PASSES_BOTH_INDEX_AND_WRITE_BEFORE_CONTINUATION",
        "POST_SELECTED_STORE_INSTRUCTION=0x10342FDE; STOP_BEFORE_FIRST_SUBSEQUENT_CALL_OR_RETURN",
        "FIRST_POST_STORE_CALL_IS_NOT_ASSUMED_MENU_OK_OR_AUDIO_LAUNCH=YES",
        "",
    ]
    overall = True
    for name, ids, idx in (control, virtual):
        baseline = a118.run_guest(d, alice, zimage, ids, idx)
        expected = ids[idx]
        baseline_ok = (
            baseline["status"] == "STOP_AFTER_SELECTED_STORE" and
            baseline["selected"] == expected and
            baseline["guest_stores"] == [(a118.DESC + 0x18, expected)] and
            a118.shim_trace_matches(baseline["shims"]) and
            baseline["fault"] is None
        )
        if not baseline_ok:
            fail(f"A118 positive baseline failed: {name}: {baseline}")
        result = run_one(d, alice, zimage, ids, idx)
        boundary = result["boundary"]
        ok = (
            result["status"] == "NEXT_BOUNDARY_CAPTURED" and
            result["post_store_started"] and
            result["selected"] == expected and
            result["stores"] == [(a118.DESC + 0x18, expected)] and
            not result["unexpected_writes"] and
            result["parent"] == 0xB702 and result["count"] == len(ids) and
            result["lookup_count"] == 1 and
            a118.shim_trace_matches(result["shims"]) and
            result["fault"] is None and boundary is not None and
            expected_boundary(boundary["kind"], boundary["mnemonic"], result["post_store_started"])
        )
        overall &= bool(ok)
        lines.append(f"=== {name} INDEX={idx} ===")
        lines.append(f"A118_BASELINE=PASS ID=0x{expected:04X}")
        lines.append(f"CPU_STATUS={result['status']} ASSERT={'PASS' if ok else 'INCONCLUSIVE'} STEPS={result['steps']}")
        lines.append(f"STORES={result['stores']} SELECTED=0x{result['selected']:04X} SHIMS={result['shims']}")
        lines.append(f"FAULT={result['fault']} UNEXPECTED_DESC_WRITES={result['unexpected_writes']}")
        lines.append(f"POST_STORE_INSTRUCTIONS={result['post_store_instructions']}")
        if boundary:
            lines.append(f"FIRST_POST_STORE_BOUNDARY=0x{boundary['pc']:08X} KIND={boundary['kind']} INSN={boundary['mnemonic']} {boundary['op']}")
            lines.append("BOUNDARY_REGISTERS=" + ",".join(f"{reg}=0x{boundary[reg]:08X}" for reg in ("r0", "r1", "r2", "r3", "r4")))
            lines.append(f"BOUNDARY_DESCRIPTOR_SELECTED=0x{boundary['selected']:04X}")
        else:
            lines.append("FIRST_POST_STORE_BOUNDARY=UNRESOLVED")
        lines.append("")
    lines += [
        "=== DECISION ===",
        "POST_SELECTION_FIRST_REAL_CPU_EDGE=PASS_CONTROL_AND_VIRTUAL" if overall else "POST_SELECTION_FIRST_REAL_CPU_EDGE=INCONCLUSIVE",
        "CONTROL_87ED_PROVES_REAL_OK_BUTTON_TRACE=NO",
        "VIRTUAL_8928_PROVES_NATIVE_AUDIO_LAUNCH=NO",
        "REAL_B702_DYNAMIC_PROVIDER_AND_SAFE_RELOCATION=NOT_PROVEN",
        "FOLLOWUP=CLASSIFY_CAPTURED_EDGE_AND_DECIDE_IF_POST_STORE_PATH_ONLY_HIGHLIGHT_OR_ACTION",
        "NO_PATCH_NO_PHONE_NO_AUDIO_CALLBACK_EXECUTION=YES",
    ]
    return "\n".join(lines) + "\n"


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--root", type=Path, default=Path(r"C:\Users\verto\F2-Altice-MobiWire"))
    ap.add_argument("--out", type=Path)
    ap.add_argument("--self-test", action="store_true")
    ap.add_argument("--self-test-static", action="store_true")
    args = ap.parse_args()
    static_self_test()
    check_dependency()
    if args.self_test_static:
        return
    d = a118.deps()
    print(a118.unicorn_self_test(d))
    if args.self_test:
        return
    root = args.root
    alice = a118.guarded(root / "research/f2/work/extracted/altice_alice/alice-py.bin", "ALICE", a118.ALICE_SIZE, a118.ALICE_SHA)
    zimage = a118.guarded(root / "research/f2/work/extracted/altice_platform/zimage.bin", "ZIMAGE", a118.ZIMAGE_SIZE, a118.ZIMAGE_SHA)
    a118.capstone_guards(alice, d)
    report = analyze(d, alice, zimage)
    out = args.out or root / "research/f2/work/reports" / REPORT
    if not out.parent.is_dir():
        fail("report folder missing: " + str(out.parent))
    with out.open("x", encoding="utf-8", newline="\n") as fp:
        fp.write(report)
    print(f"A119_REPORT_CREATED={out} BYTES={out.stat().st_size}")
    print("A119_RESULT=" + ("PASS_CONTROL_AND_VIRTUAL" if "POST_SELECTION_FIRST_REAL_CPU_EDGE=PASS_CONTROL_AND_VIRTUAL" in report else "INCONCLUSIVE"))


if __name__ == "__main__":
    try:
        main()
    except Exception as ex:
        print(f"A119_FAILED={type(ex).__name__}: {ex}", file=sys.stderr)
        sys.exit(2)
