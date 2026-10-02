#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
S13.3B - Altice F2 one-sector native Audio Player POC writer.

IMPORTANT
---------
The script is generated during S13.3B, but S13.3B itself runs only
--phase local-audit. No device connection is made during that phase.

The future mutating phases are intentionally specialized:
- one exact target: 0x00249000..0x00249FFF
- one exact AFTER sector
- one exact BEFORE/rollback sector
- GFH fixed to VIVA 0x00000108
- no arbitrary address parameter
- no arbitrary payload parameter
- no generic mtkclient writeflash()/0x62
- fresh D6 guard + exact target precondition in the SAME DA session
- fresh rollback saved before D3
- native D3 + D5 Sequential Erase
- stop after recovery + ProcessInfo ACK
- verify in a separate fresh DA session before boot

This file does NOT authorize execution of a mutating phase.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import struct
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[4]

LOADER_SHA256 = (
    "b14620c0131a269279e89830f661e39d"
    "c4f5a773d700ce56561c6f9e8e84dc8a"
)

REFERENCE_SHA256 = (
    "255a00f49b99c72871cd3a9ca9e66f4d"
    "5284590d9844ff58c3c7c5796e9616eb"
)

HWCODE = 0x6261
FLASH_SIZE = 0x00400000

TARGET_ADDR = 0x00249000
TARGET_LEN = 0x00001000
TARGET_END = TARGET_ADDR + TARGET_LEN - 1

GFH_VIVA = 0x00000108
LIVE_BOUNDARY = 0x002C0000

# 256 KiB guard containing the target, entirely below the live boundary.
GUARD_BASE = 0x00240000
GUARD_LEN = 0x00040000
GUARD_END = GUARD_BASE + GUARD_LEN - 1

BEFORE_SHA256 = (
    "dc8cc6b5be54d1554d71d60539f10a80"
    "77a375a3d7ddf92efe6149610ecffb1b"
)

AFTER_SHA256 = (
    "29a21401b84442554dc051edd16ec561b"
    "bd842e01e048344e30ca547f78bb7f9"
)

BEFORE_FILE = (
    REPO_ROOT
    / "research/f2/work/candidates/s13_2b"
    / "sector_bundle_NOT_FOR_WRITE_YET"
    / "sector_249000_before.bin"
)

AFTER_FILE = (
    REPO_ROOT
    / "research/f2/work/candidates/s13_2b"
    / "sector_bundle_NOT_FOR_WRITE_YET"
    / "sector_249000_after.bin"
)

S13_2C_ROLLBACK_FILE = (
    REPO_ROOT
    / "research/f2/work/repro/s13_2c_target_sector_d6_gate"
    / "rollback_sector_249000_fresh.bin"
)

REFERENCE_FILE = (
    REPO_ROOT
    / "research/f2/scripts/hardware/reference"
    / "s12_10b7_sacrificial_gate_v4_reference.py"
)

DEFAULT_WORKDIR = (
    REPO_ROOT
    / "research/f2/work/repro/s13_3_one_sector_firmware"
)

ACK = 0x5A
NACK = 0xA5
CONT = 0x69

CMD_MEM = 0xD3
CMD_WRITE = 0xD5
CMD_READ = 0xD6

CONFIRM_WRITE = "WRITE_FIRMWARE_ONLY_0x249000_4K_AUDIO_POC"
CONFIRM_RESTORE = "RESTORE_FIRMWARE_ONLY_0x249000_4K_AUDIO_POC"


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def read_exact_file(path: Path, size: int, digest: str, label: str) -> bytes:
    if not path.is_file():
        raise RuntimeError(f"missing {label}: {path}")

    data = path.read_bytes()

    if len(data) != size:
        raise RuntimeError(
            f"{label} size mismatch: 0x{len(data):X} != 0x{size:X}"
        )

    got = sha256(data)

    if got != digest:
        raise RuntimeError(
            f"{label} SHA mismatch: expected={digest} got={got}"
        )

    return data


def local_artifacts() -> tuple[bytes, bytes]:
    before = read_exact_file(
        BEFORE_FILE,
        TARGET_LEN,
        BEFORE_SHA256,
        "S13.2B BEFORE sector",
    )

    after = read_exact_file(
        AFTER_FILE,
        TARGET_LEN,
        AFTER_SHA256,
        "S13.2B AFTER sector",
    )

    rollback = read_exact_file(
        S13_2C_ROLLBACK_FILE,
        TARGET_LEN,
        BEFORE_SHA256,
        "S13.2C fresh rollback",
    )

    reference = read_exact_file(
        REFERENCE_FILE,
        REFERENCE_FILE.stat().st_size if REFERENCE_FILE.is_file() else 0,
        REFERENCE_SHA256,
        "S12.10B7 v4 reference",
    )

    if rollback != before:
        raise RuntimeError("S13.2C rollback != S13.2B BEFORE byte-for-byte")

    if before == after:
        raise RuntimeError("BEFORE and AFTER unexpectedly identical")

    if not (
        0 <= TARGET_ADDR
        and TARGET_ADDR + TARGET_LEN <= LIVE_BOUNDARY
        and GUARD_BASE <= TARGET_ADDR
        and TARGET_ADDR + TARGET_LEN <= GUARD_BASE + GUARD_LEN
        and GUARD_BASE + GUARD_LEN <= LIVE_BOUNDARY
    ):
        raise RuntimeError("hardcoded target/guard geometry is unsafe")

    changed = [
        i for i, (a, b) in enumerate(zip(before, after))
        if a != b
    ]

    if len(changed) != 37:
        raise RuntimeError(
            f"physical changed-byte count mismatch: {len(changed)} != 37"
        )

    first = TARGET_ADDR + changed[0]
    last = TARGET_ADDR + changed[-1]

    if first != 0x00249AEF or last != 0x00249B13:
        raise RuntimeError(
            f"unexpected physical diff range: 0x{first:08X}..0x{last:08X}"
        )

    return before, after


def local_audit(workdir: Path):
    before, after = local_artifacts()

    workdir.mkdir(parents=True, exist_ok=True)

    state = {
        "stage": "S13.3B",
        "mode": "local-audit",
        "phone_accessed": False,
        "d6_used": False,
        "d3_used": False,
        "d5_used": False,
        "erase_used": False,
        "flash_write": False,
        "target_addr": TARGET_ADDR,
        "target_len": TARGET_LEN,
        "target_end": TARGET_END,
        "gfh": GFH_VIVA,
        "guard_base": GUARD_BASE,
        "guard_len": GUARD_LEN,
        "guard_end": GUARD_END,
        "before_sha256": sha256(before),
        "after_sha256": sha256(after),
        "reference_sha256": REFERENCE_SHA256,
        "write_authorized": False,
    }

    (workdir / "s13_3b_local_audit.json").write_text(
        json.dumps(state, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    print("=" * 112)
    print("S13.3B - LOCAL ARTIFACT / GEOMETRY AUDIT")
    print("=" * 112)
    print(f"TARGET        = 0x{TARGET_ADDR:08X}..0x{TARGET_END:08X}")
    print(f"LENGTH        = 0x{TARGET_LEN:X}")
    print(f"GFH           = 0x{GFH_VIVA:08X}")
    print(f"GUARD         = 0x{GUARD_BASE:08X}..0x{GUARD_END:08X}")
    print(f"BEFORE SHA    = {sha256(before)}")
    print(f"AFTER SHA     = {sha256(after)}")
    print(f"REFERENCE SHA = {REFERENCE_SHA256}")
    print()
    print("[PASS] exact BEFORE sector")
    print("[PASS] exact AFTER sector")
    print("[PASS] exact S13.2C rollback")
    print("[PASS] exact proven S12.10B7 reference")
    print("[PASS] 37-byte physical diff / expected range")
    print("[PASS] target and guard strictly below 0x2C0000")
    print()
    print("PHONE ACCESSED : NO")
    print("D6 USED        : NO")
    print("D3 USED        : NO")
    print("D5 USED        : NO")
    print("FLASH WRITE    : NO")
    print("WRITE AUTHORIZED: NO")
    print()
    print("S13.3B LOCAL AUDIT: PASS")


# ---------------------------------------------------------------------
# Proven native DA protocol primitives.
# These mirror the committed S12.10B7 v4 reference.
# ---------------------------------------------------------------------

def read_exact(port, n: int) -> bytes:
    data = bytearray()

    while len(data) < n:
        want = n - len(data)

        try:
            chunk = port.usbread(
                want,
                maxtimeout=200,
                w_max_packet_size=want,
            )
        except SystemExit as exc:
            raise RuntimeError(
                "USB backend reported device disconnect "
                f"while reading {want} bytes "
                f"({len(data)}/{n} already received)"
            ) from exc

        if not chunk:
            raise RuntimeError(
                f"short/empty USB read: wanted {n}, got {len(data)}"
            )

        data.extend(chunk)

    return bytes(data)


def recv_u8(port) -> int:
    return read_exact(port, 1)[0]


def recv_u32be(port) -> int:
    return struct.unpack(">I", read_exact(port, 4))[0]


def send_u8(port, value: int):
    if not port.usbwrite(bytes([value & 0xFF])):
        raise RuntimeError(f"USB write failed: u8 0x{value:02X}")


def send_u16be(port, value: int):
    if not port.usbwrite(struct.pack(">H", value & 0xFFFF)):
        raise RuntimeError(f"USB write failed: u16 0x{value:04X}")


def send_u32be(port, value: int):
    if not port.usbwrite(struct.pack(">I", value & 0xFFFFFFFF)):
        raise RuntimeError(f"USB write failed: u32 0x{value:08X}")


def send_bytes(port, data: bytes):
    if not port.usbwrite(data):
        raise RuntimeError(f"USB write failed: {len(data)} bytes")


def expect_ack_or_error(port, label: str):
    response = recv_u8(port)

    if response == ACK:
        return

    if response == NACK:
        code = recv_u32be(port)
        raise RuntimeError(
            f"{label}: NACK 0xA5, error=0x{code:08X}"
        )

    raise RuntimeError(
        f"{label}: unexpected response 0x{response:02X}"
    )


def connect_da(loader: Path, serialport: str | None):
    # Delayed import: local-audit cannot initialize or enumerate a device.
    from mtk_iot_api import init as mtk_init, connect as mtk_connect

    mtk = mtk_init(
        preloader=None,
        loader=str(loader),
        serialport=serialport if serialport else None,
    )

    mtk.config.iot = True

    mtk, handler = mtk_connect(
        mtk,
        directory=".",
    )

    if mtk is None:
        raise RuntimeError("Unable to connect/configure MT6261 DA")

    if int(mtk.config.hwcode) != HWCODE:
        raise RuntimeError(
            f"wrong hwcode: 0x{int(mtk.config.hwcode):04X}"
        )

    legacy = mtk.daloader.da
    dc = legacy.daconfig

    if dc.storage.flashtype != "nor":
        raise RuntimeError(
            f"wrong flash type: {dc.storage.flashtype!r}"
        )

    if int(dc.storage.flashsize) != FLASH_SIZE:
        raise RuntimeError(
            f"wrong NOR size: 0x{int(dc.storage.flashsize):X}"
        )

    nor = dc.legacy_storage.nor
    dev = tuple(int(x) for x in nor.m_nor_flash_dev_code)

    if dev[:3] != (0x00EF, 0x0070, 0x0016):
        raise RuntimeError(
            "wrong NOR device code: "
            + "/".join(f"{x:04X}" for x in dev)
        )

    print(f"[DA] hwcode      = 0x{int(mtk.config.hwcode):04X}")
    print(f"[DA] flash type  = {dc.storage.flashtype}")
    print(f"[DA] flash size  = 0x{int(dc.storage.flashsize):08X}")
    print(
        "[DA] device code = "
        + "/".join(f"{x:04X}" for x in dev)
    )

    return mtk, legacy


def close_session(mtk):
    try:
        mtk.port.close(reset=True)
    except Exception:
        try:
            mtk.port.close()
        except Exception:
            pass


def validate_loader(loader: Path):
    if loader is None or not loader.is_file():
        raise RuntimeError("exact audited loader path is required")

    got = sha256(loader.read_bytes())

    if got != LOADER_SHA256:
        raise RuntimeError(
            f"loader SHA mismatch: expected={LOADER_SHA256} got={got}"
        )


def d6_read_4k_native(legacy, addr: int) -> bytes:
    if (
        addr < 0
        or addr + 0x1000 > FLASH_SIZE
        or (addr & 0xFFF)
    ):
        raise ValueError(
            f"invalid 4 KiB D6 address: 0x{addr:08X}"
        )

    try:
        data = legacy.readflash(
            addr=addr,
            length=0x1000,
            filename="",
            parttype=None,
            display=False,
        )
    except SystemExit as exc:
        raise RuntimeError(
            "mtkclient USB backend disconnected during "
            f"native D6 @0x{addr:08X}"
        ) from exc

    if (
        not isinstance(data, (bytes, bytearray))
        or len(data) != 0x1000
    ):
        got = (
            len(data)
            if isinstance(data, (bytes, bytearray))
            else type(data).__name__
        )
        raise RuntimeError(
            f"native D6 @0x{addr:08X} returned {got}, "
            "expected 4096 bytes"
        )

    return bytes(data)


def d6_read_sector_range(legacy, addr: int, length: int) -> bytes:
    if (
        (addr & 0xFFF)
        or (length & 0xFFF)
        or length <= 0
    ):
        raise ValueError(
            "D6 sector range must be 4 KiB aligned"
        )

    if addr < 0 or addr + length > FLASH_SIZE:
        raise ValueError("D6 sector range outside NOR")

    out = bytearray()

    for index, pos in enumerate(
        range(addr, addr + length, 0x1000),
        1,
    ):
        print(
            f"[D6] sector {index:03d}/"
            f"{length // 0x1000:03d} @0x{pos:08X}"
        )
        out.extend(
            d6_read_4k_native(
                legacy,
                pos,
            )
        )

    return bytes(out)


def extract_target(guard: bytes) -> bytes:
    if len(guard) != GUARD_LEN:
        raise RuntimeError("guard length mismatch")

    offset = TARGET_ADDR - GUARD_BASE

    return guard[
        offset:
        offset + TARGET_LEN
    ]


def compare_guard_outside_target(
    current: bytes,
    baseline: bytes,
):
    if (
        len(current) != GUARD_LEN
        or len(baseline) != GUARD_LEN
    ):
        raise RuntimeError("guard length mismatch")

    lo = TARGET_ADDR - GUARD_BASE
    hi = lo + TARGET_LEN

    for i, (now, old) in enumerate(
        zip(current, baseline)
    ):
        if lo <= i < hi:
            continue

        if now != old:
            raise RuntimeError(
                "GUARD CHANGED outside target at "
                f"0x{GUARD_BASE+i:08X}: "
                f"before={old:02X} now={now:02X}"
            )


def d3_set_memblock(legacy):
    port = legacy.mtk.port

    send_u8(port, CMD_MEM)
    send_u8(port, NACK)
    send_u8(port, 1)

    send_u32be(port, TARGET_ADDR)
    send_u32be(port, TARGET_END)
    send_u32be(port, GFH_VIVA)

    expect_ack_or_error(port, "D3 region")

    unchanged = recv_u8(port)
    format_flag = recv_u8(port)

    format_times = 0
    format_status = []

    if format_flag == ACK:
        format_times = recv_u32be(port)

        if format_times > 0x100:
            raise RuntimeError(
                f"D3 unreasonable format_times={format_times}"
            )

        for _ in range(format_times):
            format_status.append(
                recv_u8(port)
            )

    pre_erase = recv_u8(port)

    print(
        f"[D3] unchanged blocks = {unchanged}"
    )
    print(
        f"[D3] format flag      = 0x{format_flag:02X}"
    )

    if format_times:
        print(
            f"[D3] format times     = {format_times}"
        )
        print(
            "[D3] format status    = "
            + " ".join(
                f"{x:02X}"
                for x in format_status
            )
        )

    print(
        f"[D3] pre-erase byte   = 0x{pre_erase:02X}"
    )

    return unchanged


def d5_write_until_processinfo(
    legacy,
    data: bytes,
):
    if len(data) != TARGET_LEN:
        raise ValueError(
            "internal safety: D5 data must be exactly 0x1000"
        )

    port = legacy.mtk.port

    send_u8(port, CMD_WRITE)
    expect_ack_or_error(
        port,
        "D5 initial",
    )

    # Sequential Erase.
    send_u8(port, 0x01)
    send_u32be(
        port,
        TARGET_LEN,
    )

    expect_ack_or_error(
        port,
        "D5 unchanged-data save",
    )
    expect_ack_or_error(
        port,
        "D5 first-sector erase",
    )

    # Exactly one 4 KiB frame.
    send_u8(port, ACK)
    send_bytes(port, data)
    send_u16be(
        port,
        sum(data) & 0xFFFF,
    )

    response = recv_u8(port)

    if response != CONT:
        code = recv_u32be(port)
        raise RuntimeError(
            "D5 frame response "
            f"0x{response:02X}, "
            f"error/status=0x{code:08X}"
        )

    write_done = recv_u8(port)

    if write_done != ACK:
        raise RuntimeError(
            "D5 write-complete byte = "
            f"0x{write_done:02X}"
        )

    expect_ack_or_error(
        port,
        "D5 unchanged-data recovery",
    )
    expect_ack_or_error(
        port,
        "D5 ProcessInfo",
    )

    print(
        "[D5] data write/recovery/ProcessInfo complete"
    )
    print(
        "[D5] deliberately NOT entering final checksum verifier"
    )


def save_json(path: Path, data: dict):
    path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    path.write_text(
        json.dumps(
            data,
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )


def fresh_guard_and_target(
    legacy,
) -> tuple[bytes, bytes]:
    guard = d6_read_sector_range(
        legacy,
        GUARD_BASE,
        GUARD_LEN,
    )

    target = extract_target(
        guard
    )

    return guard, target


def precheck_device(
    loader: Path,
    serialport: str | None,
    workdir: Path,
):
    before, after = local_artifacts()
    validate_loader(loader)

    mtk = None

    try:
        mtk, legacy = connect_da(
            loader,
            serialport,
        )

        guard, target = fresh_guard_and_target(
            legacy
        )

        if target != before:
            raise RuntimeError(
                "device precheck target mismatch: "
                f"expected={BEFORE_SHA256} "
                f"actual={sha256(target)}"
            )

        workdir.mkdir(
            parents=True,
            exist_ok=True,
        )

        (workdir / "precheck_guard_240000_27ffff.bin").write_bytes(
            guard
        )
        (workdir / "precheck_target_249000.bin").write_bytes(
            target
        )

        save_json(
            workdir / "precheck_state.json",
            {
                "stage": "S13.3",
                "phase": "precheck-device",
                "target_sha256": sha256(target),
                "guard_sha256": sha256(guard),
                "flash_write": False,
            },
        )

        print("[PASS] device target == exact BEFORE")
        print("[PASS] fresh 256 KiB guard saved")
        print("FLASH WRITE: NO")

    finally:
        if mtk is not None:
            close_session(mtk)


def write_candidate(
    loader: Path,
    serialport: str | None,
    workdir: Path,
):
    before, after = local_artifacts()
    validate_loader(loader)

    mtk = None

    try:
        mtk, legacy = connect_da(
            loader,
            serialport,
        )

        print("[WRITE] fresh D6 guard before mutation")

        guard, target = fresh_guard_and_target(
            legacy
        )

        if target != before:
            raise RuntimeError(
                "REFUSING before D3: target does not match "
                f"exact BEFORE; actual={sha256(target)}"
            )

        workdir.mkdir(
            parents=True,
            exist_ok=True,
        )

        guard_file = (
            workdir
            / "write_guard_before_240000_27ffff.bin"
        )

        rollback_file = (
            workdir
            / "rollback_fresh_before_write_249000.bin"
        )

        guard_file.write_bytes(
            guard
        )

        rollback_file.write_bytes(
            target
        )

        if sha256(
            rollback_file.read_bytes()
        ) != BEFORE_SHA256:
            raise RuntimeError(
                "fresh rollback write/read verification failed"
            )

        save_json(
            workdir / "mutation_intent.json",
            {
                "target_addr": TARGET_ADDR,
                "target_len": TARGET_LEN,
                "gfh": GFH_VIVA,
                "before_sha256": BEFORE_SHA256,
                "after_sha256": AFTER_SHA256,
                "guard_sha256": sha256(guard),
                "fresh_rollback_sha256": sha256(target),
                "d3_started": False,
                "d5_started": False,
            },
        )

        print("[PASS] exact BEFORE in same DA session")
        print("[PASS] fresh rollback persisted before D3")
        print("[MUTATION] entering proven D3 + D5 path")

        d3_set_memblock(
            legacy
        )

        d5_write_until_processinfo(
            legacy,
            after,
        )

        # Persist this before attempting to tear down the native USB stack.
        save_json(
            workdir / "write_protocol_complete.json",
            {
                "target_addr": TARGET_ADDR,
                "target_len": TARGET_LEN,
                "candidate_sha256": AFTER_SHA256,
                "protocol_point": "after-ProcessInfo",
                "verify_after_required": True,
                "boot_authorized": False,
            },
        )

        print("[PASS] D3+D5 reached ProcessInfo")
        print("[REQUIRED] power-cycle/reconnect then run verify-after")
        print("[REQUIRED] DO NOT BOOT before exact AFTER D6")

    finally:
        if mtk is not None:
            close_session(mtk)


def verify_after(
    loader: Path,
    serialport: str | None,
    workdir: Path,
):
    before, after = local_artifacts()
    validate_loader(loader)

    baseline_guard_file = (
        workdir
        / "write_guard_before_240000_27ffff.bin"
    )

    if not baseline_guard_file.is_file():
        raise RuntimeError(
            "missing fresh pre-write guard baseline"
        )

    baseline_guard = baseline_guard_file.read_bytes()

    if len(baseline_guard) != GUARD_LEN:
        raise RuntimeError(
            "pre-write guard baseline length mismatch"
        )

    mtk = None

    try:
        mtk, legacy = connect_da(
            loader,
            serialport,
        )

        guard, target = fresh_guard_and_target(
            legacy
        )

        if target != after:
            raise RuntimeError(
                "AFTER VERIFY FAILED: "
                f"expected={AFTER_SHA256} "
                f"actual={sha256(target)}. "
                "DO NOT BOOT."
            )

        compare_guard_outside_target(
            guard,
            baseline_guard,
        )

        workdir.mkdir(
            parents=True,
            exist_ok=True,
        )

        (
            workdir
            / "verified_after_target_249000.bin"
        ).write_bytes(
            target
        )

        (
            workdir
            / "verified_after_guard_240000_27ffff.bin"
        ).write_bytes(
            guard
        )

        save_json(
            workdir / "verify_after_state.json",
            {
                "target_sha256": sha256(target),
                "guard_outside_target_unchanged": True,
                "boot_authorized": True,
            },
        )

        print("[PASS] exact AFTER sector")
        print("[PASS] guard outside target byte-identical")
        print("BOOT AUTHORIZED BY FLASH VERIFY: YES")

    finally:
        if mtk is not None:
            close_session(mtk)


def restore_before(
    loader: Path,
    serialport: str | None,
    workdir: Path,
):
    before, after = local_artifacts()
    validate_loader(loader)

    mtk = None

    try:
        mtk, legacy = connect_da(
            loader,
            serialport,
        )

        guard, target = fresh_guard_and_target(
            legacy
        )

        if target != after:
            raise RuntimeError(
                "REFUSING restore: current target is not exact AFTER; "
                f"actual={sha256(target)}"
            )

        workdir.mkdir(
            parents=True,
            exist_ok=True,
        )

        (
            workdir
            / "restore_guard_before_240000_27ffff.bin"
        ).write_bytes(
            guard
        )

        d3_set_memblock(
            legacy
        )

        d5_write_until_processinfo(
            legacy,
            before,
        )

        save_json(
            workdir / "restore_protocol_complete.json",
            {
                "protocol_point": "after-ProcessInfo",
                "expected_restored_sha256": BEFORE_SHA256,
                "verify_restored_required": True,
            },
        )

        print("[PASS] restore D3+D5 reached ProcessInfo")
        print("[REQUIRED] separate verify-restored D6 session")

    finally:
        if mtk is not None:
            close_session(mtk)


def verify_restored(
    loader: Path,
    serialport: str | None,
    workdir: Path,
):
    before, after = local_artifacts()
    validate_loader(loader)

    baseline_guard_file = (
        workdir
        / "restore_guard_before_240000_27ffff.bin"
    )

    if not baseline_guard_file.is_file():
        raise RuntimeError(
            "missing restore pre-write guard"
        )

    baseline_guard = baseline_guard_file.read_bytes()

    mtk = None

    try:
        mtk, legacy = connect_da(
            loader,
            serialport,
        )

        guard, target = fresh_guard_and_target(
            legacy
        )

        if target != before:
            raise RuntimeError(
                "RESTORE VERIFY FAILED: "
                f"expected={BEFORE_SHA256} "
                f"actual={sha256(target)}"
            )

        compare_guard_outside_target(
            guard,
            baseline_guard,
        )

        print("[PASS] exact BEFORE restored")
        print("[PASS] guard outside target byte-identical")

    finally:
        if mtk is not None:
            close_session(mtk)


def main():
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--phase",
        required=True,
        choices=[
            "local-audit",
            "precheck-device",
            "write",
            "verify-after",
            "restore",
            "verify-restored",
        ],
    )

    parser.add_argument(
        "--loader",
        type=Path,
        default=None,
    )

    parser.add_argument(
        "--serialport",
        default=None,
    )

    parser.add_argument(
        "--workdir",
        type=Path,
        default=DEFAULT_WORKDIR,
    )

    parser.add_argument(
        "--execute",
        action="store_true",
    )

    parser.add_argument(
        "--confirm",
        default="",
    )

    args = parser.parse_args()

    # Mutation lock is evaluated before loader validation or device connection.
    if args.phase == "write":
        if (
            not args.execute
            or args.confirm != CONFIRM_WRITE
        ):
            print("MUTATION LOCKED.")
            print("Required:")
            print("  --execute")
            print(f"  --confirm {CONFIRM_WRITE}")
            print("No device connection has been attempted.")
            return

    if args.phase == "restore":
        if (
            not args.execute
            or args.confirm != CONFIRM_RESTORE
        ):
            print("RESTORE LOCKED.")
            print("Required:")
            print("  --execute")
            print(f"  --confirm {CONFIRM_RESTORE}")
            print("No device connection has been attempted.")
            return

    if args.phase == "local-audit":
        local_audit(
            args.workdir
        )
        return

    if args.loader is None:
        raise SystemExit(
            "device phase requires --loader"
        )

    if args.phase == "precheck-device":
        precheck_device(
            args.loader,
            args.serialport,
            args.workdir,
        )
        return

    if args.phase == "write":
        write_candidate(
            args.loader,
            args.serialport,
            args.workdir,
        )
        return

    if args.phase == "verify-after":
        verify_after(
            args.loader,
            args.serialport,
            args.workdir,
        )
        return

    if args.phase == "restore":
        restore_before(
            args.loader,
            args.serialport,
            args.workdir,
        )
        return

    if args.phase == "verify-restored":
        verify_restored(
            args.loader,
            args.serialport,
            args.workdir,
        )
        return

    raise SystemExit(
        f"unsupported phase: {args.phase}"
    )


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(
            "\n[ABORT] interrupted",
            file=sys.stderr,
        )
        raise
    except BaseException as exc:
        print(
            f"\n[ABORT] {type(exc).__name__}: {exc}",
            file=sys.stderr,
        )
        raise
