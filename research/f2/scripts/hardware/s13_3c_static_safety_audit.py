#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
S13.3C - static/local safety audit of the S13.3B one-sector firmware harness.

This auditor NEVER imports mtk_iot_api, NEVER opens a USB device and NEVER
executes a device-access phase.
"""

from __future__ import annotations

import ast
import hashlib
import subprocess
import sys
from pathlib import Path


ROOT = Path.cwd()

HARNESS = (
    ROOT
    / "research/f2/scripts/hardware"
    / "s13_3b_one_sector_firmware_harness.py"
)

EXPECTED_REFERENCE_SHA = (
    "255a00f49b99c72871cd3a9ca9e66f4d"
    "5284590d9844ff58c3c7c5796e9616eb"
)

REFERENCE = (
    ROOT
    / "research/f2/scripts/hardware/reference"
    / "s12_10b7_sacrificial_gate_v4_reference.py"
)

EXPECTED = {
    "TARGET_ADDR": 0x00249000,
    "TARGET_LEN": 0x00001000,
    "TARGET_END": 0x00249FFF,
    "GFH_VIVA": 0x00000108,
    "LIVE_BOUNDARY": 0x002C0000,
    "GUARD_BASE": 0x00240000,
    "GUARD_LEN": 0x00040000,
    "GUARD_END": 0x0027FFFF,
    "CMD_MEM": 0xD3,
    "CMD_WRITE": 0xD5,
    "CMD_READ": 0xD6,
}

EXPECTED_BEFORE = (
    "dc8cc6b5be54d1554d71d60539f10a80"
    "77a375a3d7ddf92efe6149610ecffb1b"
)

EXPECTED_AFTER = (
    "29a21401b84442554dc051edd16ec561b"
    "bd842e01e048344e30ca547f78bb7f9"
)

EXPECTED_WRITE_TOKEN = (
    "WRITE_FIRMWARE_ONLY_0x249000_4K_AUDIO_POC"
)

EXPECTED_RESTORE_TOKEN = (
    "RESTORE_FIRMWARE_ONLY_0x249000_4K_AUDIO_POC"
)


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def fail(message: str):
    raise RuntimeError(message)


def function_node(tree, name: str):
    for node in tree.body:
        if isinstance(node, ast.FunctionDef) and node.name == name:
            return node

    fail(f"missing function: {name}")


def source_segment(text: str, node) -> str:
    segment = ast.get_source_segment(text, node)

    if segment is None:
        fail(f"unable to recover source for {getattr(node, 'name', '?')}")

    return segment


def eval_static(node, env):
    """
    Evaluate only the tiny safe constant-expression subset used by the
    harness constants. This intentionally does not execute arbitrary code.
    """
    if isinstance(node, ast.Constant):
        return node.value

    if isinstance(node, ast.Name):
        if node.id not in env:
            raise ValueError(node.id)
        return env[node.id]

    if isinstance(node, ast.UnaryOp):
        value = eval_static(node.operand, env)

        if isinstance(node.op, ast.UAdd):
            return +value

        if isinstance(node.op, ast.USub):
            return -value

        raise ValueError(type(node.op).__name__)

    if isinstance(node, ast.BinOp):
        left = eval_static(node.left, env)
        right = eval_static(node.right, env)

        if isinstance(node.op, ast.Add):
            return left + right

        if isinstance(node.op, ast.Sub):
            return left - right

        if isinstance(node.op, ast.Mult):
            return left * right

        raise ValueError(type(node.op).__name__)

    return ast.literal_eval(node)


def literal_assignments(tree):
    values = {}

    for node in tree.body:
        if not isinstance(node, ast.Assign):
            continue

        if len(node.targets) != 1:
            continue

        target = node.targets[0]

        if not isinstance(target, ast.Name):
            continue

        try:
            values[target.id] = eval_static(node.value, values)
        except Exception:
            pass

    return values


def main():
    print("=" * 112)
    print("S13.3C - STATIC SAFETY AUDIT")
    print("=" * 112)

    if not HARNESS.is_file():
        fail(f"missing harness: {HARNESS}")

    if not REFERENCE.is_file():
        fail(f"missing reference: {REFERENCE}")

    reference_sha = sha256(
        REFERENCE.read_bytes()
    )

    print(f"REFERENCE SHA = {reference_sha}")

    if reference_sha != EXPECTED_REFERENCE_SHA:
        fail("proven reference SHA mismatch")

    print("[PASS] proven S12.10B7 reference SHA")

    text = HARNESS.read_text(
        encoding="utf-8-sig"
    )

    tree = ast.parse(
        text
    )

    values = literal_assignments(
        tree
    )

    for name, expected in EXPECTED.items():
        got = values.get(name)

        if got != expected:
            fail(
                f"{name} mismatch: expected={expected!r} got={got!r}"
            )

        print(
            f"[PASS] {name} = 0x{got:X}"
        )

    if values.get("BEFORE_SHA256") != EXPECTED_BEFORE:
        fail("BEFORE_SHA256 mismatch")

    if values.get("AFTER_SHA256") != EXPECTED_AFTER:
        fail("AFTER_SHA256 mismatch")

    if values.get("CONFIRM_WRITE") != EXPECTED_WRITE_TOKEN:
        fail("write confirmation token mismatch")

    if values.get("CONFIRM_RESTORE") != EXPECTED_RESTORE_TOKEN:
        fail("restore confirmation token mismatch")

    print("[PASS] exact BEFORE SHA hardcoded")
    print("[PASS] exact AFTER SHA hardcoded")
    print("[PASS] firmware-specific write token")
    print("[PASS] firmware-specific restore token")

    if values["TARGET_ADDR"] + values["TARGET_LEN"] > values["LIVE_BOUNDARY"]:
        fail("target reaches live boundary")

    if values["GUARD_BASE"] + values["GUARD_LEN"] > values["LIVE_BOUNDARY"]:
        fail("guard reaches live boundary")

    print("[PASS] target/guard strictly below 0x2C0000")

    forbidden_text = [
        "CMD_WRITE = 0x62",
        "0x002A0000",
        "WRITE_ONLY_0x2A0000_4K",
        "PATTERN_A",
        "PATTERN_B",
        "PATTERN_FF",
    ]

    for item in forbidden_text:
        if item in text:
            fail(f"forbidden sacrificial/generic token present: {item}")

    # Check actual calls instead of documentation text.
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue

        func = node.func

        if isinstance(func, ast.Name) and func.id == "writeflash":
            fail("generic writeflash() call present")

        if isinstance(func, ast.Attribute) and func.attr == "writeflash":
            fail("generic writeflash() method call present")

    print("[PASS] sacrificial AA/55/FF logic removed")
    print("[PASS] generic writeflash()/0x62 call absent")

    main_fn = function_node(
        tree,
        "main",
    )

    main_src = source_segment(
        text,
        main_fn,
    )

    for forbidden_arg in (
        "--address",
        "--addr",
        "--target",
        "--length",
        "--payload",
        "--data",
        "--input",
        "--file",
    ):
        if forbidden_arg in main_src:
            fail(
                f"arbitrary mutation CLI parameter present: {forbidden_arg}"
            )

    print("[PASS] no arbitrary address/length/payload CLI")

    local_fn = function_node(
        tree,
        "local_audit",
    )

    local_src = source_segment(
        text,
        local_fn,
    )

    for forbidden in (
        "connect_da(",
        "d6_read_4k_native(",
        "d6_read_sector_range(",
        "d3_set_memblock(",
        "d5_write_until_processinfo(",
    ):
        if forbidden in local_src:
            fail(
                f"local_audit can touch device path: {forbidden}"
            )

    print("[PASS] local-audit has no device/protocol call")

    d3_fn = function_node(
        tree,
        "d3_set_memblock",
    )

    d3_src = source_segment(
        text,
        d3_fn,
    )

    for token in (
        "TARGET_ADDR",
        "TARGET_END",
        "GFH_VIVA",
        "CMD_MEM",
    ):
        if token not in d3_src:
            fail(
                f"D3 does not use hardcoded {token}"
            )

    print("[PASS] D3 uses only hardcoded target/end/GFH")

    d5_fn = function_node(
        tree,
        "d5_write_until_processinfo",
    )

    d5_src = source_segment(
        text,
        d5_fn,
    )

    required_d5 = (
        "len(data) != TARGET_LEN",
        "CMD_WRITE",
        "send_u8(port, 0x01)",
        "TARGET_LEN",
        "sum(data) & 0xFFFF",
        "D5 unchanged-data recovery",
        "D5 ProcessInfo",
        "NOT entering final checksum verifier",
    )

    for token in required_d5:
        if token not in d5_src:
            fail(
                f"proven D5 invariant missing: {token}"
            )

    print("[PASS] D5 one-frame Sequential Erase invariants")

    write_fn = function_node(
        tree,
        "write_candidate",
    )

    write_src = source_segment(
        text,
        write_fn,
    )

    sequence = (
        "fresh_guard_and_target(",
        "if target != before:",
        "rollback_file.write_bytes(",
        "d3_set_memblock(",
        "d5_write_until_processinfo(",
    )

    positions = []

    for token in sequence:
        pos = write_src.find(token)

        if pos < 0:
            fail(
                f"write sequence token missing: {token}"
            )

        positions.append(
            pos
        )

    if positions != sorted(positions):
        fail(
            "write safety sequence is out of order"
        )

    print(
        "[PASS] fresh D6 -> exact BEFORE -> rollback -> D3 -> D5 ordering"
    )

    verify_fn = function_node(
        tree,
        "verify_after",
    )

    verify_src = source_segment(
        text,
        verify_fn,
    )

    for token in (
        "if target != after:",
        "compare_guard_outside_target(",
        "boot_authorized",
    ):
        if token not in verify_src:
            fail(
                f"verify-after invariant missing: {token}"
            )

    print("[PASS] AFTER verify + outside-target guard check")

    # Execute ONLY the local-audit phase.
    result = subprocess.run(
        [
            sys.executable,
            str(HARNESS),
            "--phase",
            "local-audit",
        ],
        cwd=ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        timeout=30,
    )

    print()
    print("--- local-audit subprocess ---")
    print(result.stdout.rstrip())

    if result.returncode != 0:
        fail(
            f"local-audit subprocess failed: {result.returncode}"
        )

    if "S13.3B LOCAL AUDIT: PASS" not in result.stdout:
        fail(
            "local-audit PASS marker missing"
        )

    if "PHONE ACCESSED : NO" not in result.stdout:
        fail(
            "local-audit phone-access marker missing"
        )

    print("[PASS] local-audit subprocess")

    # Exercise mutation locks WITHOUT loader and WITHOUT device connection.
    for phase, marker in (
        ("write", "MUTATION LOCKED."),
        ("restore", "RESTORE LOCKED."),
    ):
        locked = subprocess.run(
            [
                sys.executable,
                str(HARNESS),
                "--phase",
                phase,
            ],
            cwd=ROOT,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=30,
        )

        if locked.returncode != 0:
            fail(
                f"{phase} lock returned {locked.returncode}"
            )

        if marker not in locked.stdout:
            fail(
                f"{phase} lock marker missing"
            )

        if "No device connection has been attempted." not in locked.stdout:
            fail(
                f"{phase} does not prove pre-connect lock"
            )

        print(
            f"[PASS] {phase} locked before device connection"
        )

    print()
    print("=" * 112)
    print("S13.3C RESULT")
    print("=" * 112)
    print("REFERENCE SHA                    : PASS")
    print("HARDCODED TARGET                 : PASS")
    print("HARDCODED BEFORE/AFTER           : PASS")
    print("NO ARBITRARY TARGET/PAYLOAD CLI  : PASS")
    print("LOCAL AUDIT DEVICE-FREE          : PASS")
    print("WRITE LOCK PRE-CONNECTION        : PASS")
    print("RESTORE LOCK PRE-CONNECTION      : PASS")
    print("D3 HARD TARGET/GFH               : PASS")
    print("D5 PROVEN SEQUENTIAL ERASE FLOW  : PASS")
    print("FRESH D6 BEFORE D3               : PASS")
    print("ROLLBACK BEFORE D3               : PASS")
    print("SEPARATE AFTER VERIFY            : PASS")
    print("OUTSIDE-TARGET GUARD VERIFY      : PASS")
    print("PHONE ACCESSED                   : NO")
    print("FLASH MODIFIED                   : NO")
    print()
    print("S13.3B/C LOCAL SAFETY GATE: PASS")
    print("HARDWARE WRITE AUTHORIZED: NO")


if __name__ == "__main__":
    try:
        main()
    except BaseException as exc:
        print(
            f"\n[ABORT] {type(exc).__name__}: {exc}",
            file=sys.stderr,
        )
        raise
