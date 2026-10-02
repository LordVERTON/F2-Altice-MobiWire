#!/usr/bin/env python3

import hashlib
import struct
import sys
import time
from pathlib import Path

import serial
import serial.tools.list_ports


VID = 0x0E8D
PID = 0x0003

WAIT_SECONDS = 90

CMD_LEGACY_READ = 0xA2
CMD_READ32 = 0xD1
CMD_WRITE16 = 0xD2
CMD_WRITE32 = 0xD4

CPU_ID_ADDR = 0x80000008
EXPECTED_CPU_ID = 0x6261

WDT_ADDR = 0xA0030000
WDT_DISABLE = 0x2200

FLASH_MAP_REG = 0xA0510000

DUMP_START = 0x00000000
DUMP_SIZE = 0x00400000

READ_STEP = 1024

EXPECTED_SHA = (
    "2fc100e5704cf3d6fae0817a22ce2223"
    "97702ffd7351a83763ae1bafd4416922"
)


def u16be(b):
    return struct.unpack(">H", b)[0]


def u32be(b):
    return struct.unpack(">I", b)[0]


def matching_ports():
    out = []

    for p in serial.tools.list_ports.comports():
        hwid = (p.hwid or "").upper()

        if (
            (p.vid == VID and p.pid == PID)
            or "VID_0E8D&PID_0003" in hwid
        ):
            out.append(p)

    return out


def read_exact(ser, n, timeout=1.0):
    deadline = time.monotonic() + timeout
    out = bytearray()

    while len(out) < n:

        if time.monotonic() >= deadline:
            raise TimeoutError(
                f"RX timeout {len(out)}/{n}"
            )

        chunk = ser.read(
            n - len(out)
        )

        if chunk:
            out.extend(chunk)

    return bytes(out)


def tx(ser, data):

    if isinstance(data, int):
        data = bytes([data])

    n = ser.write(data)
    ser.flush()

    if n != len(data):
        raise RuntimeError(
            f"TX incomplet {n}/{len(data)}"
        )


def echo(ser, data, timeout=1.0):

    if isinstance(data, int):
        data = bytes([data])

    tx(
        ser,
        data,
    )

    ans = read_exact(
        ser,
        len(data),
        timeout,
    )

    if ans != data:
        raise RuntimeError(
            f"echo incorrect "
            f"TX={data.hex()} "
            f"RX={ans.hex()}"
        )


def status(ser):
    value = u16be(
        read_exact(
            ser,
            2,
            1.0,
        )
    )

    if value >= 0x00FF:
        raise RuntimeError(
            f"status BROM 0x{value:04X}"
        )

    return value


def handshake(ser, log):

    log("Handshake BROM...")

    sync = (
        (0xA0, 0x5F),
        (0x0A, 0xF5),
        (0x50, 0xAF),
        (0x05, 0xFA),
    )

    for sent, expected in sync:

        tx(
            ser,
            sent,
        )

        ans = read_exact(
            ser,
            1,
            0.5,
        )[0]

        log(
            f"  {sent:02X} -> {ans:02X}"
        )

        if ans != expected:
            raise RuntimeError(
                f"handshake: attendu "
                f"{expected:02X}"
            )


def read16_legacy(ser, addr):

    echo(
        ser,
        CMD_LEGACY_READ,
    )

    echo(
        ser,
        struct.pack(
            ">I",
            addr,
        ),
    )

    echo(
        ser,
        struct.pack(
            ">I",
            1,
        ),
    )

    return u16be(
        read_exact(
            ser,
            2,
            1.0,
        )
    )


def read32_word(ser, addr):

    echo(
        ser,
        CMD_READ32,
    )

    echo(
        ser,
        struct.pack(
            ">I",
            addr,
        ),
    )

    echo(
        ser,
        struct.pack(
            ">I",
            1,
        ),
    )

    status(ser)

    value = u32be(
        read_exact(
            ser,
            4,
            1.0,
        )
    )

    status(ser)

    return value


def write16_reg(ser, addr, value):

    echo(
        ser,
        CMD_WRITE16,
    )

    echo(
        ser,
        struct.pack(
            ">I",
            addr,
        ),
    )

    echo(
        ser,
        struct.pack(
            ">I",
            1,
        ),
    )

    status(ser)

    echo(
        ser,
        struct.pack(
            ">H",
            value,
        ),
    )

    status(ser)


def write32_reg(ser, addr, value):

    echo(
        ser,
        CMD_WRITE32,
    )

    echo(
        ser,
        struct.pack(
            ">I",
            addr,
        ),
    )

    echo(
        ser,
        struct.pack(
            ">I",
            1,
        ),
    )

    status(ser)

    echo(
        ser,
        struct.pack(
            ">I",
            value,
        ),
    )

    status(ser)


def read_flash(ser, log):

    out = bytearray()

    pos = 0

    while pos < DUMP_SIZE:

        n = min(
            READ_STEP,
            DUMP_SIZE - pos,
        )

        echo(
            ser,
            CMD_READ32,
        )

        echo(
            ser,
            struct.pack(
                ">I",
                DUMP_START + pos,
            ),
        )

        echo(
            ser,
            struct.pack(
                ">I",
                n // 4,
            ),
        )

        status(ser)

        raw = read_exact(
            ser,
            n,
            5.0,
        )

        status(ser)

        # Le BROM envoie chaque U32 en ordre
        # big-endian. Le dump physique attendu
        # est little-endian.
        for i in range(
            0,
            len(raw),
            4,
        ):
            out.extend(
                raw[i:i+4][::-1]
            )

        pos += n

        if (
            pos % 0x40000 == 0
            or pos == DUMP_SIZE
        ):
            log(
                f"Lecture : "
                f"{pos:08X}/{DUMP_SIZE:08X} "
                f"{pos * 100.0 / DUMP_SIZE:6.2f}%"
            )

    return bytes(out)


def open_brom(log):

    deadline = (
        time.monotonic()
        + WAIT_SECONDS
    )

    attempt = 0

    while time.monotonic() < deadline:

        for p in matching_ports():

            attempt += 1

            log(
                f"Detection #{attempt}: "
                f"{p.device} | "
                f"{p.description}"
            )

            ser = None

            try:
                ser = serial.Serial(
                    port=p.device,
                    baudrate=115200,
                    bytesize=8,
                    parity=serial.PARITY_NONE,
                    stopbits=1,
                    timeout=0.02,
                    write_timeout=0.5,
                    rtscts=False,
                    dsrdtr=False,
                    xonxoff=False,
                )

                try:
                    ser.dtr = False
                except Exception:
                    pass

                try:
                    ser.rts = False
                except Exception:
                    pass

                time.sleep(0.02)

                try:
                    ser.reset_input_buffer()
                except Exception:
                    pass

                handshake(
                    ser,
                    log,
                )

                log("Handshake OK.")

                cpu = read16_legacy(
                    ser,
                    CPU_ID_ADDR,
                )

                log(
                    f"BB_CPU_ID = "
                    f"0x{cpu:04X}"
                )

                if cpu != EXPECTED_CPU_ID:
                    raise RuntimeError(
                        f"CPU inattendu "
                        f"0x{cpu:04X}"
                    )

                return (
                    ser,
                    p.device,
                )

            except Exception as e:

                log(
                    f"Probe echoue : "
                    f"{type(e).__name__}: "
                    f"{e}"
                )

                if ser is not None:
                    try:
                        ser.close()
                    except Exception:
                        pass

        time.sleep(0.02)

    raise RuntimeError(
        "aucune session BROM valide"
    )


def main():

    if len(sys.argv) != 2:
        print(
            "Usage: "
            "dump_mobiwire_4mb_serial.py "
            "<output.bin>"
        )
        raise SystemExit(1)

    out_path = Path(
        sys.argv[1]
    ).resolve()

    out_path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    log_path = Path(
        str(out_path) + ".log"
    )

    with log_path.open(
        "w",
        encoding="utf-8",
        buffering=1,
    ) as lf:

        def log(s=""):
            print(
                s,
                flush=True,
            )

            print(
                s,
                file=lf,
                flush=True,
            )

        log()
        log("=" * 72)
        log("S12.8 - SERIAL BROM FULL 4 MiB READBACK")
        log("=" * 72)

        log()
        log("FLASH WRITE / ERASE : NONE")
        log()
        log(
            "Deux ecritures VOLATILES de registres "
            "seront utilisees:"
        )
        log(
            "  - watchdog MT6261"
        )
        log(
            "  - FLASH_MAP_REG"
        )
        log()
        log(
            "Elles ne modifient pas le contenu NOR."
        )

        log()
        log("Preparation:")
        log("  1. cable USB debranche")
        log("  2. batterie retiree 10 secondes")
        log("  3. batterie remise")
        log("  4. telephone ETEINT")
        log("  5. aucun bouton")

        input(
            "\nAppuie ENTREE, puis branche "
            "immediatement le cable USB..."
        )

        log()
        log(
            "Recherche MediaTek "
            "0E8D:0003..."
        )

        ser = None

        try:

            ser, port = open_brom(
                log
            )

            log()
            log(
                f"Transport BROM : {port}"
            )

            log()
            log(
                "Desactivation temporaire "
                "du watchdog..."
            )

            write16_reg(
                ser,
                WDT_ADDR,
                WDT_DISABLE,
            )

            log(
                "Watchdog : PASS"
            )

            log()
            log(
                "Activation temporaire "
                "du mapping NOR..."
            )

            old_map = read32_word(
                ser,
                FLASH_MAP_REG,
            )

            new_map = (
                old_map
                | 0x2
            )

            if new_map != old_map:

                write32_reg(
                    ser,
                    FLASH_MAP_REG,
                    new_map,
                )

            verify_map = read32_word(
                ser,
                FLASH_MAP_REG,
            )

            if (
                verify_map & 0x2
            ) == 0:
                raise RuntimeError(
                    "FLASH_MAP_REG non active"
                )

            log(
                f"FLASH_MAP_REG : "
                f"0x{old_map:08X}"
                f" -> "
                f"0x{verify_map:08X}"
            )

            log()
            log(
                "Lecture NOR complete..."
            )

            data = read_flash(
                ser,
                log,
            )

            if len(data) != DUMP_SIZE:
                raise RuntimeError(
                    f"taille incorrecte "
                    f"0x{len(data):X}"
                )

            digest = hashlib.sha256(
                data
            ).hexdigest()

            out_path.write_bytes(
                data
            )

            log()
            log("=" * 72)
            log("READBACK RESULT")
            log("=" * 72)

            log(
                f"Fichier : {out_path}"
            )

            log(
                f"Taille  : "
                f"0x{len(data):X}"
            )

            log(
                f"SHA256  : {digest}"
            )

            if digest == EXPECTED_SHA:
                log(
                    "CANONICAL SHA256 : PASS"
                )
            else:
                log(
                    "CANONICAL SHA256 : FAIL"
                )

                raise RuntimeError(
                    "readback different "
                    "from canonical dump"
                )

            log()
            log(
                "FLASH WRITE / ERASE : NONE"
            )

            log(
                "VOLATILE REGISTER WRITES ONLY"
            )

            log()
            log(
                "READBACK : PASS"
            )

        finally:

            if ser is not None:
                try:
                    ser.close()
                except Exception:
                    pass


if __name__ == "__main__":
    main()
