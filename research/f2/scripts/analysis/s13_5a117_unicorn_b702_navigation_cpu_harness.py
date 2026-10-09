#!/usr/bin/env python3
"""S13.5A.117: bounded RAM-only Unicorn CPU smoke test for real ALICE navigation.

No physical device, USB/COM, flash, patch, repack, ROM output or emulator
configuration edits. Runs ONLY two SHA-pinned ALICE leaf functions with a
SYNTHETIC active menu descriptor and explicitly MOCKED external context APIs.

This is NOT a firmware boot or an OK/Select event trace. Successful return of
0x8928 does not establish a working Audio Player or a real displayed menu item.
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
FUNC_INDEX_TO_ID = 0x10315514
FUNC_ID_TO_INDEX = 0x10319DF8
GET_STATE = 0x102FD104
GET_DESCRIPTOR = 0x102FD0F4
RAM_BASE = 0x20000000
RAM_SIZE = 0x10000
DESC = RAM_BASE + 0x1000
CHILDREN = RAM_BASE + 0x2000
STACK = RAM_BASE + 0xC000
SENTINEL = RAM_BASE + 0xF000
PAGE = 0x1000
MAX_STEPS = 500
RESULT_NAME = "s13_5a117_unicorn_b702_navigation_cpu_harness.txt"


def fail(msg: str) -> None:
    raise RuntimeError("A117_ABORT: " + msg)


def aligned_down(x: int) -> int:
    return x & ~(PAGE - 1)


def aligned_up(x: int) -> int:
    return (x + PAGE - 1) & ~(PAGE - 1)


def guard(path: Path, label: str, size: int, digest: str) -> bytes:
    if not path.is_file():
        fail(f"missing {label}: {path}")
    b = path.read_bytes()
    got = hashlib.sha256(b).hexdigest()
    if len(b) != size or got != digest:
        fail(f"{label} canonical guard failed len={len(b):X} sha={got}")
    return b


def dependencies():
    try:
        from unicorn import Uc, UcError, UC_ARCH_ARM, UC_MODE_THUMB, UC_MODE_LITTLE_ENDIAN
        from unicorn import UC_PROT_ALL, UC_PROT_READ, UC_PROT_EXEC, UC_HOOK_CODE, UC_HOOK_MEM_INVALID
        from unicorn.arm_const import (UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_SP,
                                       UC_ARM_REG_LR, UC_ARM_REG_PC, UC_ARM_REG_CPSR)
        from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_LITTLE_ENDIAN
    except ImportError as e:
        fail(f"missing Unicorn or Capstone in selected Python environment: {e}")
    return locals()


def encode_bl(src: int, dst: int) -> bytes:
    """Thumb-2 BL immediate for the small synthetic self-test ONLY."""
    displacement = dst - (src + 4)
    if displacement & 1 or not (-(1 << 24) <= displacement < (1 << 24)):
        fail("synthetic BL displacement invalid")
    n = displacement & ((1 << 25) - 1)
    s, i1, i2 = (n >> 24) & 1, (n >> 23) & 1, (n >> 22) & 1
    j1, j2 = 1 ^ (i1 ^ s), 1 ^ (i2 ^ s)
    h1 = 0xF000 | (s << 10) | ((n >> 12) & 0x3FF)
    h2 = 0xD000 | (j1 << 13) | (j2 << 11) | ((n >> 1) & 0x7FF)
    return struct.pack("<HH", h1, h2)


def synthetic_engine_self_test(dep: dict) -> str:
    """Actually test guest Thumb BL -> host shim -> guest return with Unicorn."""
    uc = dep["Uc"](dep["UC_ARCH_ARM"], dep["UC_MODE_THUMB"] | dep["UC_MODE_LITTLE_ENDIAN"])
    base = 0x30000000
    uc.mem_map(base, PAGE, dep["UC_PROT_ALL"])
    func, stub, stop = base + 0x100, base + 0x200, base + 0x300
    # PUSH {LR}; BL stub; POP {PC}; external stop point.
    uc.mem_write(func, b"\x00\xb5" + encode_bl(func + 2, stub) + b"\x00\xbd")
    uc.mem_write(stop, b"\x00\xbf")
    uc.mem_protect(base, PAGE, dep["UC_PROT_READ"] | dep["UC_PROT_EXEC"])
    uc.mem_map(0x30010000, PAGE, dep["UC_PROT_ALL"])
    uc.reg_write(dep["UC_ARM_REG_SP"], 0x30010800)
    uc.reg_write(dep["UC_ARM_REG_LR"], stop | 1)
    state = {"hit": None, "step": 0}

    def code(h, addr, size, _):
        state["step"] += 1
        if addr in (stub, stop):
            state["hit"] = addr
            h.emu_stop()
        elif state["step"] > 30:
            state["hit"] = -1
            h.emu_stop()

    uc.hook_add(dep["UC_HOOK_CODE"], code)
    uc.emu_start(func | 1, 0, count=30)
    if state["hit"] != stub:
        fail("self-test did not reach external Thumb BL stub")
    lr = uc.reg_read(dep["UC_ARM_REG_LR"])
    uc.reg_write(dep["UC_ARM_REG_R0"], 0x42)
    uc.reg_write(dep["UC_ARM_REG_CPSR"], uc.reg_read(dep["UC_ARM_REG_CPSR"]) | 0x20)
    state["hit"] = None
    uc.emu_start(lr | 1, 0, count=30)
    if state["hit"] != stop or uc.reg_read(dep["UC_ARM_REG_R0"]) != 0x42:
        fail("self-test shim return or final return value mismatch")
    return "A117_UNICORN_SELF_TEST=PASS_SYNTHETIC_THUMB_BL_HOST_SHIM_AND_RETURN"


def prefix_anchors(alice: bytes, dep: dict) -> list[str]:
    cs = dep["Cs"](dep["CS_ARCH_ARM"], dep["CS_MODE_THUMB"] | dep["CS_MODE_LITTLE_ENDIAN"])
    result = []
    for name, addr in (("INDEX_TO_ID", FUNC_INDEX_TO_ID), ("ID_TO_INDEX", FUNC_ID_TO_INDEX)):
        off = addr - ALICE_BASE
        if not (0 <= off < len(alice) - 12):
            fail(f"entry outside ALICE {name}")
        block = list(cs.disasm(alice[off:off + 12], addr, count=4))
        if len(block) < 2 or block[0].address != addr:
            fail(f"entry {name} does not decode at the pinned Thumb address; stop")
        result.append(f"{name}_ENTRY=0x{addr:08X} FIRST=" +
                      "; ".join(f"0x{x.address:08X}:{x.mnemonic} {x.op_str}" for x in block))
    return result


def run_guest(dep: dict, alice: bytes, zimage: bytes, func: int, incoming: int,
              children: tuple[int, ...]) -> dict:
    # Image map starts on page boundaries; load pristine bytes then mark RX.
    uc = dep["Uc"](dep["UC_ARCH_ARM"], dep["UC_MODE_THUMB"] | dep["UC_MODE_LITTLE_ENDIAN"])
    for base, blob in ((ALICE_BASE, alice), (ZIMAGE_BASE, zimage)):
        page = aligned_down(base)
        length = aligned_up(base + len(blob)) - page
        uc.mem_map(page, length, dep["UC_PROT_ALL"])
        uc.mem_write(base, blob)
        uc.mem_protect(page, length, dep["UC_PROT_READ"] | dep["UC_PROT_EXEC"])
    uc.mem_map(RAM_BASE, RAM_SIZE, dep["UC_PROT_ALL"])
    descriptor = bytearray(0x100)
    struct.pack_into("<H", descriptor, 0x14, 0xB702)
    struct.pack_into("<I", descriptor, 0x40, CHILDREN)
    struct.pack_into("<I", descriptor, 0x48, len(children))
    uc.mem_write(DESC, bytes(descriptor))
    uc.mem_write(CHILDREN, struct.pack("<" + "H" * len(children), *children))
    uc.mem_write(SENTINEL, b"\x00\xbf")
    uc.reg_write(dep["UC_ARM_REG_SP"], STACK)
    uc.reg_write(dep["UC_ARM_REG_LR"], SENTINEL | 1)
    uc.reg_write(dep["UC_ARM_REG_R0"], incoming)
    uc.reg_write(dep["UC_ARM_REG_R1"], 0)
    state = {"stop": None, "steps": 0, "calls": [], "fault": None}
    admissible_start, admissible_end = func, func + (0x100 if func == FUNC_ID_TO_INDEX else 0x180)

    def code(h, addr, size, unused):
        state["steps"] += 1
        if addr in (GET_STATE, GET_DESCRIPTOR, SENTINEL):
            state["stop"] = ("return" if addr == SENTINEL else "shim", addr)
            h.emu_stop()
        elif not (admissible_start <= addr < admissible_end):
            state["stop"] = ("unexpected-execution", addr)
            h.emu_stop()
        elif state["steps"] > MAX_STEPS:
            state["stop"] = ("limit", addr)
            h.emu_stop()

    def invalid(h, access, addr, size, value, _):
        state["fault"] = f"guest unmapped/protected access={access} addr=0x{addr:08X} size={size}"
        return False

    uc.hook_add(dep["UC_HOOK_CODE"], code)
    uc.hook_add(dep["UC_HOOK_MEM_INVALID"], invalid)
    resume = func | 1
    status = "INCONCLUSIVE"
    for _ in range(12):
        state["stop"] = None
        try:
            uc.emu_start(resume, 0, count=MAX_STEPS + 5)
        except dep["UcError"] as e:
            status = f"GUEST_FAULT:{type(e).__name__}:{e}"
            break
        event = state["stop"]
        if event is None:
            status = "NO_STOP_WITHIN_LIMIT"
            break
        kind, addr = event
        if kind == "return":
            status = "RETURNED"
            break
        if kind != "shim":
            status = f"{kind.upper()}_AT_0x{addr:08X}"
            break
        lr = uc.reg_read(dep["UC_ARM_REG_LR"])
        if not (lr & 1):
            status = f"UNEXPECTED_HELPER_LR_MODE_0x{lr:08X}"
            break
        val = (0 if addr == GET_STATE else DESC)
        state["calls"].append((addr, val, lr))
        uc.reg_write(dep["UC_ARM_REG_R0"], val)
        uc.reg_write(dep["UC_ARM_REG_CPSR"], uc.reg_read(dep["UC_ARM_REG_CPSR"]) | 0x20)
        resume = lr | 1
    else:
        status = "TOO_MANY_SHIM_INTERRUPTS"
    actual = uc.reg_read(dep["UC_ARM_REG_R0"]) & 0xFFFFFFFF
    return {"status": status, "actual": actual, "steps": state["steps"], "calls": state["calls"],
            "fault": state["fault"]}


def exercise(dep: dict, alice: bytes, zimage: bytes) -> str:
    lines = [
        "S13.5A.117 — B702 NAVIGATION CPU HARNESS: REAL ALICE INSTRUCTIONS / SYNTHETIC MENU RAM",
        "NO_PHONE_USB_COM_FLASH_ERASE_PATCH_REPACK_NOTEPAD=YES",
        "INPUT_IMAGES_READ_ONLY=YES GUEST_ROM_PROTECTED_RX=YES GUEST_DATA_IN_ISOLATED_RAM=YES",
        "NO_BOOT_NO_OK_EVENT_NO_APP_LAUNCH_NO_AUDIO_CALLBACK_EXECUTION=YES",
        f"ALICE_GUARD=PASS SIZE=0x{len(alice):X} SHA256={ALICE_SHA}",
        f"ZIMAGE_GUARD=PASS SIZE=0x{len(zimage):X} SHA256={ZIMAGE_SHA}",
        synthetic_engine_self_test(dep),
        *prefix_anchors(alice, dep),
        "CONTEXT_SHIMS=102FD104_GET_STATE_RET0,102FD0F4_GET_DESCRIPTOR_RET_SYNTHETIC_DESC",
        "IMPORTANT=SHIMS_NOT_PROVEN_TRUE_REAL_RUNTIME_SIDE_EFFECTS",
        "B702_CURRENT=0x8569,0x87ED; VIRTUAL=0x8569,0x87ED,0x8928",
        "RELOCATION_NOT_PERFORMED=YES AUDIO_CALLBACK_NEVER_ENTERED=YES",
        "",
    ]
    any_failed = False
    for label, children in (("CURRENT", (0x8569, 0x87ED)),
                            ("VIRTUAL", (0x8569, 0x87ED, 0x8928))):
        lines.append(f"=== {label}: COUNT={len(children)} ===")
        for index in (0, 1, 2, 3):
            expected = children[index] if index < len(children) else 0xFFFF
            result = run_guest(dep, alice, zimage, FUNC_INDEX_TO_ID, index, children)
            passed = result["status"] == "RETURNED" and (result["actual"] & 0xFFFF) == expected
            any_failed |= not passed
            lines.append(f"INDEX_TO_ID index={index} EXPECT_U16=0x{expected:04X} GUEST_R0=0x{result['actual']:08X} STATUS={result['status']} STEPS={result['steps']} ASSERT={'PASS' if passed else 'INCONCLUSIVE'}")
            lines.append("  MOCKED_CALLS=" + repr(result["calls"]) + " FAULT=" + repr(result["fault"]))
        for ident in (0x8569, 0x87ED, 0x8928, 0xFFFF):
            expected = children.index(ident) if ident in children else 0xFFFFFFFF
            result = run_guest(dep, alice, zimage, FUNC_ID_TO_INDEX, ident, children)
            passed = result["status"] == "RETURNED" and result["actual"] == expected
            any_failed |= not passed
            lines.append(f"ID_TO_INDEX id=0x{ident:04X} EXPECT_R0=0x{expected:08X} GUEST_R0=0x{result['actual']:08X} STATUS={result['status']} STEPS={result['steps']} ASSERT={'PASS' if passed else 'INCONCLUSIVE'}")
            lines.append("  MOCKED_CALLS=" + repr(result["calls"]) + " FAULT=" + repr(result["fault"]))
        lines.append("")
    lines += [
        "=== DECISION ===",
        "CONDITIONAL_GUEST_NAVIGATION_CPU=PASS_ALL_CASES" if not any_failed else "CONDITIONAL_GUEST_NAVIGATION_CPU=INCONCLUSIVE_SOME_CASES",
        "DOES_NOT_PROVE_REAL_B702_RUNTIME_STORAGE_OR_RELOCATION=YES",
        "DOES_NOT_PROVE_REAL_SELECTED_OK_TO_LEAF_DISPATCH=YES",
        "DOES_NOT_PROVE_8928_AUDIO_ACTIVATION=YES",
        "NEXT=ONLY_IF_CPU_SMOKE_PASSES_CONSIDER_TRUSTED_UI_SELECTION_POSITIVE_CONTROL_WITH_EXPLICIT_CONTEXT_SHIMS",
        "NO_HARDWARE_PATCH_AUTHORIZED=YES",
    ]
    return "\n".join(lines) + "\n"


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--root", type=Path, default=Path(r"C:\Users\verto\F2-Altice-MobiWire"))
    p.add_argument("--out", type=Path)
    p.add_argument("--self-test", action="store_true")
    args = p.parse_args()
    dep = dependencies()
    print(synthetic_engine_self_test(dep))
    if args.self_test:
        return
    root = args.root
    alice = guard(root / "research/f2/work/extracted/altice_alice/alice-py.bin", "ALICE", ALICE_SIZE, ALICE_SHA)
    zimage = guard(root / "research/f2/work/extracted/altice_platform/zimage.bin", "ZIMAGE", ZIMAGE_SIZE, ZIMAGE_SHA)
    report = exercise(dep, alice, zimage)
    out = args.out or root / "research/f2/work/reports" / RESULT_NAME
    if not out.parent.is_dir():
        fail(f"reports directory absent: {out.parent}")
    with out.open("x", encoding="utf-8", newline="\n") as f:
        f.write(report)
    print(f"A117_REPORT_CREATED={out} BYTES={out.stat().st_size}")
    print("A117_CPU_RESULT=" + ("INCONCLUSIVE" if "CPU=INCONCLUSIVE" in report else "PASS_CONDITIONAL_GUEST_ONLY"))


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(f"A117_FAILED={type(e).__name__}: {e}", file=sys.stderr)
        sys.exit(2)
