#!/usr/bin/env python3

import struct
import time

try:
    import serial
    import serial.tools.list_ports
except ImportError:
    print("ERROR: module pyserial absent.")
    print(r"Execute: C:\Users\verto\mtkclient\.venv\Scripts\python.exe -m pip install pyserial")
    raise SystemExit(1)

VID = 0x0E8D
PID = 0x0003
WAIT_SECONDS = 90

EXPECTED_CPU = 0x6261
CPU_ADDR = 0x80000008
CMD_LEGACY_READ = 0xA2


def read_exact(ser, size, timeout=0.5):
    end = time.monotonic() + timeout
    out = bytearray()

    while len(out) < size:
        if time.monotonic() >= end:
            raise TimeoutError(
                f"timeout RX {len(out)}/{size}"
            )

        chunk = ser.read(size - len(out))

        if chunk:
            out.extend(chunk)

    return bytes(out)


def tx(ser, data):
    n = ser.write(data)
    ser.flush()

    if n != len(data):
        raise RuntimeError(
            f"TX incomplet {n}/{len(data)}"
        )


def echo(ser, data):
    tx(ser, data)

    ans = read_exact(
        ser,
        len(data),
    )

    if ans != data:
        raise RuntimeError(
            f"echo incorrect TX={data.hex()} RX={ans.hex()}"
        )


def handshake(ser):
    seq = (
        (0xA0, 0x5F),
        (0x0A, 0xF5),
        (0x50, 0xAF),
        (0x05, 0xFA),
    )

    print()
    print("Handshake BROM...")

    for sent, expected in seq:
        tx(
            ser,
            bytes([sent]),
        )

        ans = read_exact(
            ser,
            1,
        )[0]

        print(
            f"  {sent:02X} -> {ans:02X}"
        )

        if ans != expected:
            raise RuntimeError(
                f"attendu {expected:02X}"
            )


def read16_legacy(ser, addr):
    echo(
        ser,
        bytes([CMD_LEGACY_READ]),
    )

    echo(
        ser,
        struct.pack(">I", addr),
    )

    echo(
        ser,
        struct.pack(">I", 1),
    )

    return struct.unpack(
        ">H",
        read_exact(ser, 2),
    )[0]


def candidate_ports():
    found = []

    for p in serial.tools.list_ports.comports():
        hwid = (p.hwid or "").upper()
        desc = (p.description or "").upper()

        vidpid = (
            p.vid == VID
            and p.pid == PID
        )

        hwid_match = (
            "VID_0E8D&PID_0003"
            in hwid
        )

        mediatek_match = (
            "MEDIATEK USB PORT"
            in desc
        )

        if (
            vidpid
            or hwid_match
            or mediatek_match
        ):
            found.append(p)

    return found


print()
print("=" * 72)
print("S12.8 - BROM SERIAL PROBE")
print("=" * 72)
print()
print("NON DESTRUCTIF:")
print("  flash write    : NONE")
print("  flash erase    : NONE")
print("  register write : NONE")
print("  flash read     : NONE")
print()
print("Le test fait seulement:")
print("  1. handshake BROM")
print("  2. lecture BB_CPU_ID")
print()
print("Preparation:")
print("  - cable USB debranche")
print("  - batterie retiree 10 secondes")
print("  - batterie remise")
print("  - telephone laisse ETEINT")
print("  - aucun bouton a presser")
print()

input(
    "Appuie ENTREE, puis branche immediatement le cable USB..."
)

print()
print("Recherche du port MediaTek 0E8D:0003...")

deadline = time.monotonic() + WAIT_SECONDS
attempt = 0

while time.monotonic() < deadline:

    ports = candidate_ports()

    for p in ports:
        attempt += 1

        print()
        print(
            f"[{attempt}] detecte: "
            f"{p.device} | "
            f"{p.description} | "
            f"{p.hwid}"
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
                write_timeout=0.25,
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

            handshake(ser)

            print()
            print("Handshake OK.")

            cpu = read16_legacy(
                ser,
                CPU_ADDR,
            )

            print(
                f"BB_CPU_ID = 0x{cpu:04X}"
            )

            if cpu != EXPECTED_CPU:
                raise RuntimeError(
                    f"CPU inattendu 0x{cpu:04X}"
                )

            print()
            print("=" * 72)
            print("S12.8 SERIAL RESULT")
            print("=" * 72)
            print(f"PORT           : {p.device}")
            print("BROM HANDSHAKE : PASS")
            print("BB_CPU_ID      : 0x6261 PASS")
            print("FLASH WRITE    : NONE")
            print("REGISTER WRITE : NONE")
            print("FLASH READ     : NONE")
            print()
            print("VERDICT: SERIAL BROM ACCESS CONFIRMED")

            raise SystemExit(0)

        except SystemExit:
            raise

        except Exception as e:
            print(
                f"probe echoue: {type(e).__name__}: {e}"
            )

        finally:
            if ser is not None:
                try:
                    ser.close()
                except Exception:
                    pass

    time.sleep(0.02)

print()
print("=" * 72)
print("S12.8 SERIAL RESULT")
print("=" * 72)
print("FAIL: aucun handshake BROM valide.")
print("AUCUNE ECRITURE N'A ETE EFFECTUEE.")

raise SystemExit(2)
