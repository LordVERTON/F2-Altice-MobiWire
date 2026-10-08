#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
S12.10B7 v2 - MT6261 sacrificial NOR gate @ 0x002A0000

Purpose
-------
Qualify the exact native D3+D5 NOR path on the owned Altice F2 before any
firmware-sector mutation.

HARD SAFETY LOCKS
-----------------
- exact loader SHA256 required
- hwcode must be 0x6261
- NOR size must be exactly 0x00400000
- NOR device code must begin EF/70/16
- only address 0x002A0000
- only length  0x00001000
- GFH_FILE_TYPE fixed to 0x00000108 (VIVA)
- no generic mtkclient writeflash()/0x62
- default is read-only; mutation requires BOTH --execute and the exact
  confirmation token
- staged workflow; power-cycle the phone between mutating phases

Important protocol choice:
The mutating phases intentionally STOP after the ProcessInfo ACK. At that
point the DA has completed data write + unchanged-data recovery. The final
image-checksum verifier is not entered, so the runtime PATH_A/PATH_B selector
is irrelevant for this sacrificial gate. The session is then closed and the
result is verified in a fresh D6 session.

Phases
------
precheck
write-a
verify-a
write-b
verify-b
restore
verify-restore

Patterns:
A = 0xAA * 0x1000
B = 0x55 * 0x1000
AA -> 55 necessarily requires 0->1 transitions, so write-b proves that the
erase path is actually exercised.

This tool is intentionally specialized and refuses arbitrary address/length.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import os
import struct
import sys
import time
from pathlib import Path

# Make the repository root importable even when this script is launched from
# research/f2/scripts/hardware.
REPO_ROOT = Path(__file__).resolve().parents[4]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

# The repository already ships this helper.
from mtk_iot_api import init as mtk_init, connect as mtk_connect

LOADER_SHA256 = "b14620c0131a269279e89830f661e39dc4f5a773d700ce56561c6f9e8e84dc8a"

HWCODE = 0x6261
FLASH_SIZE = 0x00400000
TARGET_ADDR = 0x002A0000
TARGET_LEN = 0x00001000
GFH_VIVA = 0x00000108

GUARD_BASE = 0x00280000
GUARD_LEN = 0x00040000  # 256 KiB: catches the explicitly unsafe align-down envelope.

ACK = 0x5A
NACK = 0xA5
CONT = 0x69

CMD_MEM = 0xD3
CMD_WRITE = 0xD5
CMD_READ = 0xD6

CONFIRM_TOKEN = "WRITE_ONLY_0x2A0000_4K"

PATTERN_A = bytes([0xAA]) * TARGET_LEN
PATTERN_B = bytes([0x55]) * TARGET_LEN
PATTERN_FF = bytes([0xFF]) * TARGET_LEN


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def read_exact(port, n: int) -> bytes:
    """
    Match mtkclient's own legacy read path: request the whole DA packet from
    the USB backend instead of letting it fall back to EP_IN.wMaxPacketSize
    (typically 64 bytes). The old behavior could turn each 4 KiB DA packet
    into ~64 USB reads and make long dumps unstable on Windows.
    """
    data = bytearray()
    while len(data) < n:
        want = n - len(data)
        try:
            chunk = port.usbread(
                want,
                maxtimeout=200,
                w_max_packet_size=want,
            )
        except SystemExit as e:
            raise RuntimeError(
                f"USB backend reported device disconnect while reading "
                f"{want} bytes ({len(data)}/{n} already received)"
            ) from e
        if not chunk:
            raise RuntimeError(
                f"short/empty USB read: wanted {n}, got {len(data)}"
            )
        data.extend(chunk)
    return bytes(data)


def recv_u8(port) -> int:
    return read_exact(port, 1)[0]


def recv_u16be(port) -> int:
    return struct.unpack(">H", read_exact(port, 2))[0]


def recv_u32be(port) -> int:
    return struct.unpack(">I", read_exact(port, 4))[0]


def send_u8(port, v: int):
    if not port.usbwrite(bytes([v & 0xFF])):
        raise RuntimeError(f"USB write failed: u8 0x{v:02X}")


def send_u16be(port, v: int):
    if not port.usbwrite(struct.pack(">H", v & 0xFFFF)):
        raise RuntimeError(f"USB write failed: u16 0x{v:04X}")


def send_u32be(port, v: int):
    if not port.usbwrite(struct.pack(">I", v & 0xFFFFFFFF)):
        raise RuntimeError(f"USB write failed: u32 0x{v:08X}")


def send_bytes(port, data: bytes):
    if not port.usbwrite(data):
        raise RuntimeError(f"USB write failed: {len(data)} bytes")


def expect_ack_or_error(port, label: str):
    r = recv_u8(port)
    if r == ACK:
        return
    if r == NACK:
        code = recv_u32be(port)
        raise RuntimeError(f"{label}: NACK 0xA5, error=0x{code:08X}")
    raise RuntimeError(f"{label}: unexpected response 0x{r:02X}")


def connect_da(loader: Path, serialport: str | None):
    mtk = mtk_init(preloader=None, loader=str(loader),
                   serialport=serialport if serialport else None)
    mtk.config.iot = True
    mtk, handler = mtk_connect(mtk, directory=".")
    if mtk is None:
        raise RuntimeError("Unable to connect/configure MT6261 DA")

    if int(mtk.config.hwcode) != HWCODE:
        raise RuntimeError(f"wrong hwcode: 0x{int(mtk.config.hwcode):04X}")

    legacy = mtk.daloader.da
    dc = legacy.daconfig

    if dc.storage.flashtype != "nor":
        raise RuntimeError(f"wrong flash type: {dc.storage.flashtype!r}")
    if int(dc.storage.flashsize) != FLASH_SIZE:
        raise RuntimeError(f"wrong NOR size: 0x{int(dc.storage.flashsize):X}")

    nor = dc.legacy_storage.nor
    dev = tuple(int(x) for x in nor.m_nor_flash_dev_code)
    if dev[:3] != (0x00EF, 0x0070, 0x0016):
        raise RuntimeError(
            "wrong NOR device code: " +
            "/".join(f"{x:04X}" for x in dev)
        )

    print(f"[DA] hwcode      = 0x{int(mtk.config.hwcode):04X}")
    print(f"[DA] flash type  = {dc.storage.flashtype}")
    print(f"[DA] flash size  = 0x{int(dc.storage.flashsize):08X}")
    print("[DA] device code = " + "/".join(f"{x:04X}" for x in dev))
    return mtk, legacy


def close_session(mtk):
    try:
        mtk.port.close(reset=True)
    except Exception:
        try:
            mtk.port.close()
        except Exception:
            pass


def d6_read(legacy, addr: int, length: int) -> bytes:
    """
    Exact MT6261 IoT NOR D6 framing:
      D6, addr BE32, length BE32, packet_size BE32
    Then data packets, checksum16 BE, host ACK.
    """
    if addr < 0 or length <= 0 or addr + length > FLASH_SIZE:
        raise ValueError("D6 range outside NOR")

    port = legacy.mtk.port
    send_u8(port, CMD_READ)
    send_u32be(port, addr)
    send_u32be(port, length)
    send_u32be(port, 0x1000)

    expect_ack_or_error(port, "D6 header")

    out = bytearray()
    remaining = length
    while remaining:
        count = min(0x1000, remaining)
        block = read_exact(port, count)
        remote_sum = recv_u16be(port)
        local_sum = sum(block) & 0xFFFF
        if remote_sum != local_sum:
            send_u8(port, NACK)
            raise RuntimeError(
                f"D6 checksum mismatch @0x{addr+len(out):08X}: "
                f"DA=0x{remote_sum:04X} host=0x{local_sum:04X}"
            )
        out.extend(block)
        send_u8(port, ACK)
        remaining -= count
    return bytes(out)


def d6_read_chunked(legacy, addr: int, length: int, command_chunk: int = 0x40000) -> bytes:
    """
    Read large spans as multiple independent D6 commands. 0x40000 keeps each
    DA transaction short while preserving exact byte-for-byte coverage.
    """
    if command_chunk <= 0 or command_chunk % 0x1000:
        raise ValueError("command_chunk must be a positive 4 KiB multiple")

    out = bytearray()
    pos = 0
    while pos < length:
        count = min(command_chunk, length - pos)
        print(
            f"[D6] 0x{addr+pos:08X} +0x{count:X} "
            f"({pos+count:#x}/{length:#x})"
        )
        out.extend(d6_read(legacy, addr + pos, count))
        pos += count
    return bytes(out)


def d3_set_memblock(legacy):
    """
    Exact public SV5 host ordering for one image:
      D3
      image_attrs=NACK (FOTA disabled)
      count=1
      begin/end/GFH as BE32
      per-region ACK
      unchanged-block-count byte
      format-first flag byte
      optional format count/statuses
      pre-erase byte
    """
    port = legacy.mtk.port

    send_u8(port, CMD_MEM)
    send_u8(port, NACK)
    send_u8(port, 1)

    send_u32be(port, TARGET_ADDR)
    send_u32be(port, TARGET_ADDR + TARGET_LEN - 1)
    send_u32be(port, GFH_VIVA)

    expect_ack_or_error(port, "D3 region")

    unchanged = recv_u8(port)
    format_flag = recv_u8(port)

    format_times = 0
    format_status = []
    if format_flag == ACK:
        format_times = recv_u32be(port)
        if format_times > 0x100:
            raise RuntimeError(f"D3 unreasonable format_times={format_times}")
        for _ in range(format_times):
            format_status.append(recv_u8(port))

    pre_erase = recv_u8(port)

    print(f"[D3] unchanged blocks = {unchanged}")
    print(f"[D3] format flag      = 0x{format_flag:02X}")
    if format_times:
        print(f"[D3] format times     = {format_times}")
        print("[D3] format status    = " +
              " ".join(f"{x:02X}" for x in format_status))
    print(f"[D3] pre-erase byte   = 0x{pre_erase:02X}")
    return unchanged


def d5_write_until_processinfo(legacy, data: bytes):
    """
    Native legacy D5 sequence, intentionally ending immediately after the
    ProcessInfo-done ACK. No final image checksum bytes are sent.
    """
    if len(data) != TARGET_LEN:
        raise ValueError("internal safety: D5 data must be exactly 0x1000")

    port = legacy.mtk.port

    send_u8(port, CMD_WRITE)
    expect_ack_or_error(port, "D5 initial")

    # Sequential Erase
    send_u8(port, 0x01)
    send_u32be(port, TARGET_LEN)

    expect_ack_or_error(port, "D5 unchanged-data save")
    expect_ack_or_error(port, "D5 first-sector erase")

    # Exactly one 4 KiB frame
    send_u8(port, ACK)
    send_bytes(port, data)
    send_u16be(port, sum(data) & 0xFFFF)

    r = recv_u8(port)
    if r != CONT:
        # Exact DA sends an error/status dword after non-CONT frame response.
        code = recv_u32be(port)
        raise RuntimeError(
            f"D5 frame response 0x{r:02X}, error/status=0x{code:08X}"
        )

    # Exact B6.7 tail:
    # 1) write-all-data completion response
    # 2) unchanged-data recovery ACK
    # 3) ProcessInfo ACK
    write_done = recv_u8(port)
    if write_done != ACK:
        raise RuntimeError(f"D5 write-complete byte = 0x{write_done:02X}")

    expect_ack_or_error(port, "D5 unchanged-data recovery")
    expect_ack_or_error(port, "D5 ProcessInfo")

    print("[D5] data write/recovery/ProcessInfo complete")
    print("[D5] deliberately NOT entering final checksum verifier")


def load_manifest(workdir: Path) -> dict:
    p = workdir / "state.json"
    if not p.exists():
        raise RuntimeError(f"missing state manifest: {p}")
    return json.loads(p.read_text(encoding="utf-8"))


def save_manifest(workdir: Path, state: dict):
    workdir.mkdir(parents=True, exist_ok=True)
    (workdir / "state.json").write_text(
        json.dumps(state, indent=2, sort_keys=True) + "\n",
        encoding="utf-8"
    )


def compare_guard(current: bytes, baseline: bytes, allowed_addr=None):
    if len(current) != GUARD_LEN or len(baseline) != GUARD_LEN:
        raise RuntimeError("guard length mismatch")

    lo = TARGET_ADDR - GUARD_BASE
    hi = lo + TARGET_LEN

    for i, (a, b) in enumerate(zip(current, baseline)):
        if lo <= i < hi:
            continue
        if a != b:
            raise RuntimeError(
                f"GUARD CHANGED outside sacrificial sector at "
                f"0x{GUARD_BASE+i:08X}: baseline={b:02X} now={a:02X}"
            )


def required_pattern_for_phase(phase: str):
    return {
        "write-a": PATTERN_FF,
        "verify-a": PATTERN_A,
        "write-b": PATTERN_A,
        "verify-b": PATTERN_B,
        "restore": PATTERN_B,
        "verify-restore": PATTERN_FF,
    }.get(phase)


def mutation_pattern(phase: str):
    return {
        "write-a": PATTERN_A,
        "write-b": PATTERN_B,
        "restore": PATTERN_FF,
    }.get(phase)


def precheck(loader, serialport, workdir):
    print("[PRECHECK] connecting read-only")
    mtk, legacy = connect_da(loader, serialport)
    try:
        print("[PRECHECK] reading full 4 MiB baseline")
        full = d6_read_chunked(legacy, 0, FLASH_SIZE)
        target = full[TARGET_ADDR:TARGET_ADDR + TARGET_LEN]
        if target != PATTERN_FF:
            raise RuntimeError(
                f"sacrificial sector is not all-FF; sha256={sha256(target)}"
            )

        guard = full[GUARD_BASE:GUARD_BASE + GUARD_LEN]

        workdir.mkdir(parents=True, exist_ok=True)
        (workdir / "baseline_4m.bin").write_bytes(full)
        (workdir / "baseline_guard_280000_2bffff.bin").write_bytes(guard)
        (workdir / "baseline_target_2a0000.bin").write_bytes(target)

        state = {
            "loader_sha256": LOADER_SHA256,
            "hwcode": HWCODE,
            "flash_size": FLASH_SIZE,
            "target_addr": TARGET_ADDR,
            "target_len": TARGET_LEN,
            "gfh": GFH_VIVA,
            "baseline_4m_sha256": sha256(full),
            "baseline_guard_sha256": sha256(guard),
            "baseline_target_sha256": sha256(target),
            "phase_complete": "precheck",
        }
        save_manifest(workdir, state)

        print(f"[PASS] full baseline SHA256  : {sha256(full)}")
        print(f"[PASS] guard baseline SHA256 : {sha256(guard)}")
        print("[PASS] target 0x2A0000/0x1000 is 100% FF")
    finally:
        close_session(mtk)


def read_and_validate(loader, serialport, workdir, expected: bytes, full_final=False):
    state = load_manifest(workdir)
    baseline_guard = (workdir / "baseline_guard_280000_2bffff.bin").read_bytes()

    mtk, legacy = connect_da(loader, serialport)
    try:
        guard = d6_read_chunked(legacy, GUARD_BASE, GUARD_LEN)
        target_off = TARGET_ADDR - GUARD_BASE
        target = guard[target_off:target_off + TARGET_LEN]

        if target != expected:
            raise RuntimeError(
                f"target mismatch: expected_sha={sha256(expected)} "
                f"read_sha={sha256(target)}"
            )

        compare_guard(guard, baseline_guard)
        print(f"[PASS] target SHA256 = {sha256(target)}")
        print("[PASS] all bytes in 0x280000..0x2BFFFF outside target unchanged")

        if full_final:
            full = d6_read_chunked(legacy, 0, FLASH_SIZE)
            base = (workdir / "baseline_4m.bin").read_bytes()
            if full != base:
                for i, (a, b) in enumerate(zip(full, base)):
                    if a != b:
                        raise RuntimeError(
                            f"final full-flash mismatch at 0x{i:08X}: "
                            f"baseline={b:02X} now={a:02X}"
                        )
                raise RuntimeError("final full-flash mismatch")
            print(f"[PASS] final 4 MiB exact SHA256 = {sha256(full)}")

        return sha256(target)
    finally:
        close_session(mtk)


def mutate(loader, serialport, workdir, expected_before: bytes, new_data: bytes, phase: str):
    baseline_guard = (workdir / "baseline_guard_280000_2bffff.bin").read_bytes()

    print(f"[{phase.upper()}] fresh pre-read before mutation")
    mtk, legacy = connect_da(loader, serialport)
    try:
        guard = d6_read_chunked(legacy, GUARD_BASE, GUARD_LEN)
        target_off = TARGET_ADDR - GUARD_BASE
        target = guard[target_off:target_off + TARGET_LEN]

        if target != expected_before:
            raise RuntimeError(
                f"precondition failed: target SHA={sha256(target)}, "
                f"expected={sha256(expected_before)}"
            )
        compare_guard(guard, baseline_guard)
        print("[PASS] preconditions and guard verified")

        d3_set_memblock(legacy)
        d5_write_until_processinfo(legacy, new_data)
        print("[WRITE PHASE COMPLETE]")
        print("POWER-CYCLE THE PHONE/BATTERY before running the next verify phase.")
    finally:
        # DA is deliberately waiting for final checksum input here.
        close_session(mtk)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--loader", type=Path, required=True)
    ap.add_argument(
        "--phase",
        choices=["precheck", "write-a", "verify-a",
                 "write-b", "verify-b", "restore", "verify-restore"],
        required=True
    )
    ap.add_argument("--serialport", default=None,
                    help="Optional explicit serial port; omit for normal USB discovery")
    ap.add_argument(
        "--workdir",
        type=Path,
        default=Path("research/f2/work/repro/s12_10b7_sacrificial_gate")
    )
    ap.add_argument("--execute", action="store_true")
    ap.add_argument("--confirm", default="")
    args = ap.parse_args()

    if not args.loader.exists():
        raise SystemExit(f"loader not found: {args.loader}")
    lsha = sha256(args.loader.read_bytes())
    if lsha != LOADER_SHA256:
        raise SystemExit(
            f"REFUSING: loader SHA mismatch\nexpected={LOADER_SHA256}\nactual  ={lsha}"
        )

    print("=" * 110)
    print("S12.10B7 v2 - MT6261 SACRIFICIAL NOR GATE")
    print("=" * 110)
    print(f"phase        : {args.phase}")
    print(f"loader sha   : {lsha} PASS")
    print(f"target       : 0x{TARGET_ADDR:08X}..0x{TARGET_ADDR+TARGET_LEN-1:08X}")
    print(f"length       : 0x{TARGET_LEN:X}")
    print(f"GFH          : 0x{GFH_VIVA:08X} / VIVA")
    print(f"guard        : 0x{GUARD_BASE:08X}..0x{GUARD_BASE+GUARD_LEN-1:08X}")
    print("generic 0x62 : NEVER USED")
    print()

    mutating = args.phase in ("write-a", "write-b", "restore")
    if mutating:
        if not args.execute or args.confirm != CONFIRM_TOKEN:
            print("MUTATION LOCKED.")
            print("This phase requires BOTH:")
            print("  --execute")
            print(f"  --confirm {CONFIRM_TOKEN}")
            print()
            print("No device connection has been attempted.")
            return

    if args.phase == "precheck":
        precheck(args.loader, args.serialport, args.workdir)
        return

    state = load_manifest(args.workdir)
    if state.get("target_addr") != TARGET_ADDR or state.get("target_len") != TARGET_LEN:
        raise SystemExit("REFUSING: state manifest target mismatch")
    if state.get("baseline_target_sha256") != sha256(PATTERN_FF):
        raise SystemExit("REFUSING: baseline target was not all-FF")

    expected = required_pattern_for_phase(args.phase)

    if args.phase == "verify-a":
        h = read_and_validate(args.loader, args.serialport, args.workdir, PATTERN_A)
        state["verify_a_sha256"] = h
        state["phase_complete"] = "verify-a"
        save_manifest(args.workdir, state)
        return

    if args.phase == "verify-b":
        h = read_and_validate(args.loader, args.serialport, args.workdir, PATTERN_B)
        state["verify_b_sha256"] = h
        state["phase_complete"] = "verify-b"
        save_manifest(args.workdir, state)
        return

    if args.phase == "verify-restore":
        h = read_and_validate(
            args.loader, args.serialport, args.workdir, PATTERN_FF, full_final=True
        )
        state["verify_restore_sha256"] = h
        state["phase_complete"] = "verify-restore"
        state["gate_result"] = "PASS"
        save_manifest(args.workdir, state)
        print()
        print("S12.10B7 SACRIFICIAL GATE: PASS")
        print("D5 WRITE + ERASE + RECOVERY verified on owned F2.")
        print("This does NOT by itself authorize a firmware-sector write.")
        return

    new_data = mutation_pattern(args.phase)
    mutate(args.loader, args.serialport, args.workdir, expected, new_data, args.phase)
    state["phase_complete"] = args.phase
    state[f"{args.phase}_target_sha256"] = sha256(new_data)
    save_manifest(args.workdir, state)


if __name__ == "__main__":
    main()
