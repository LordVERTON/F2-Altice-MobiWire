#!/usr/bin/env python3
# -*- coding: utf-8 -*-

r"""
MobiWire NIKITI / Altice F2 — MT6261 full 4 MiB NOR dump via WinUSB.

Base : probe WinUSB/BROM déjà validé sur cet appareil.

But :
- capturer le téléphone en BROM USB 0E8D:0003 ;
- confirmer le CPU MT6261 ;
- désactiver temporairement le watchdog ;
- mapper temporairement la NOR/SPI flash à l'adresse mémoire 0 ;
- lire exactement 4 MiB (0x00000000 -> 0x003FFFFF) ;
- écrire le dump sur disque ;
- calculer SHA-256 du fichier.

IMPORTANT :
- aucune commande d'effacement de flash ;
- aucune commande d'écriture de flash ;
- seules deux écritures VOLATILES de registres matériels sont utilisées :
  * watchdog MT6261 ;
  * bit de mapping de la flash.
- elles disparaissent au redémarrage et ne modifient pas le contenu de la NOR.

Pilote attendu pour USB\VID_0E8D&PID_0003 : WinUSB.

Dépendances :
    pip install pyusb libusb-package

Utilisation :
    python -u .\dump_mobiwire_4mb.py .\mobiwire_dump_1.bin

Puis refaire un cycle batterie / reconnexion et lancer :
    python -u .\dump_mobiwire_4mb.py .\mobiwire_dump_2.bin
"""

import sys
import time
import struct
import hashlib
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from _paths import DATA_ROOT

import usb.core
import usb.util
import libusb_package


VID = 0x0E8D
PID = 0x0003
WAIT_SECONDS = 90

CMD_LEGACY_READ = 0xA2
CMD_READ32 = 0xD1
CMD_WRITE16 = 0xD2
CMD_WRITE32 = 0xD4

WDT_ADDR = 0xA0030000
WDT_DISABLE = 0x2200
FLASH_MAP_REG = 0xA0510000

DUMP_START = 0x00000000
DUMP_SIZE = 0x00400000  # 4 MiB exacts
READ_STEP = 1024         # même granularité que le probe validé

backend = libusb_package.get_libusb1_backend()
if backend is None:
    print("ERREUR : backend libusb-package indisponible.", flush=True)
    raise SystemExit(1)


def u16be(b):
    return struct.unpack(">H", b)[0]


def u32be(b):
    return struct.unpack(">I", b)[0]


def human_mib(n):
    return n / (1024 * 1024)


def main():
    if len(sys.argv) >= 2:
        out_path = Path(sys.argv[1]).expanduser().resolve()
    else:
        out_path = (DATA_ROOT / "dumps" / "mobiwire_dump.bin").resolve()
    out_path.parent.mkdir(parents=True, exist_ok=True)

    log_path = out_path.with_suffix(out_path.suffix + ".log")

    with log_path.open("w", encoding="utf-8", buffering=1) as logf:

        def log(s=""):
            print(s, flush=True)
            print(s, file=logf, flush=True)

        def stop(msg, code=1):
            log("")
            log("ECHEC : " + msg)
            log(f"Journal : {log_path}")
            raise SystemExit(code)

        log("")
        log("============================================================")
        log(" MOBIWIRE / ALTICE F2 - DUMP NOR 4 MiB MT6261 (READ ONLY)")
        log("============================================================")
        log("")
        log(f"Fichier de sortie : {out_path}")
        log("")
        log("NE BRANCHEZ PAS encore le telephone.")
        log("")
        log("Preparation :")
        log("  1. Debranchez le cable USB.")
        log("  2. Retirez la batterie pendant 10 secondes.")
        log("  3. Remettez la batterie.")
        log("  4. Laissez le telephone ETEINT.")
        log("")
        input("Quand ces 4 etapes sont faites, appuyez sur ENTREE ici... ")

        log("")
        log(">>> BRANCHEZ LE CABLE USB MAINTENANT <<<")
        log(f"Attente de {VID:04X}:{PID:04X} pendant {WAIT_SECONDS} secondes...")
        log("")

        deadline = time.monotonic() + WAIT_SECONDS
        dev = None

        while time.monotonic() < deadline:
            try:
                dev = usb.core.find(
                    idVendor=VID,
                    idProduct=PID,
                    backend=backend
                )
                if dev is not None:
                    break
            except Exception:
                pass
            time.sleep(0.003)

        if dev is None:
            stop("0E8D:0003 non capture.")

        log(f">>> BROM CAPTURE : {VID:04X}:{PID:04X} <<<")
        log(f"Classe USB : 0x{dev.bDeviceClass:02X}")

        try:
            cfg = dev[0]
        except Exception as e:
            stop(f"impossible de lire la configuration USB #0 : {e!r}")

        bulk_if = ep_in = ep_out = None

        for intf in cfg:
            i_in = i_out = None

            for ep in intf:
                if usb.util.endpoint_type(ep.bmAttributes) != usb.util.ENDPOINT_TYPE_BULK:
                    continue

                if usb.util.endpoint_direction(ep.bEndpointAddress) == usb.util.ENDPOINT_IN:
                    i_in = ep
                else:
                    i_out = ep

            if i_in is not None and i_out is not None:
                bulk_if, ep_in, ep_out = intf, i_in, i_out
                break

        if bulk_if is None:
            stop("interface BULK IN/OUT introuvable.")

        ifnum = bulk_if.bInterfaceNumber
        log(
            f"Interface {ifnum} | "
            f"OUT=0x{ep_out.bEndpointAddress:02X} | "
            f"IN=0x{ep_in.bEndpointAddress:02X}"
        )

        claimed = False

        try:
            usb.util.claim_interface(dev, ifnum)
            claimed = True
            log("Interface WinUSB reclamee.")

            def tx(data, timeout=1000):
                if isinstance(data, int):
                    data = bytes([data])
                n = ep_out.write(data, timeout=timeout)
                if n != len(data):
                    raise RuntimeError(
                        f"USB write incomplet {n}/{len(data)}"
                    )

            def rx(n, timeout=1000):
                data = bytes(ep_in.read(n, timeout=timeout))
                if len(data) != n:
                    raise RuntimeError(
                        f"USB read incomplet {len(data)}/{n}"
                    )
                return data

            def echo(data, timeout=1000):
                if isinstance(data, int):
                    data = bytes([data])
                tx(data, timeout)
                ans = rx(len(data), timeout)
                if ans != data:
                    raise RuntimeError(
                        f"echo incorrect TX={data.hex()} RX={ans.hex()}"
                    )

            def status():
                s = u16be(rx(2, 1000))
                if s >= 0x00FF:
                    raise RuntimeError(
                        f"status BROM inattendu 0x{s:04X}"
                    )
                return s

            def read16_legacy(addr):
                echo(CMD_LEGACY_READ)
                echo(struct.pack(">I", addr))
                echo(struct.pack(">I", 1))
                return u16be(rx(2, 1000))

            def read32_word(addr):
                echo(CMD_READ32)
                echo(struct.pack(">I", addr))
                echo(struct.pack(">I", 1))
                status()
                v = u32be(rx(4, 1000))
                status()
                return v

            def write16_reg(addr, value):
                echo(CMD_WRITE16)
                echo(struct.pack(">I", addr))
                echo(struct.pack(">I", 1))
                status()
                echo(struct.pack(">H", value))
                status()

            def write32_reg(addr, value):
                echo(CMD_WRITE32)
                echo(struct.pack(">I", addr))
                echo(struct.pack(">I", 1))
                status()
                echo(struct.pack(">I", value))
                status()

            def read32_bytes(addr, size):
                if addr & 3 or size & 3:
                    raise ValueError(
                        "read32 exige adresse/taille multiples de 4"
                    )

                out = bytearray()
                pos = 0

                while pos < size:
                    n = min(READ_STEP, size - pos)

                    echo(CMD_READ32)
                    echo(struct.pack(">I", addr + pos))
                    echo(struct.pack(">I", n // 4))
                    status()

                    raw = rx(n, 3000)
                    status()

                    # Même conversion que le probe déjà validé :
                    # le BROM renvoie chaque mot 32-bit en big-endian.
                    for i in range(0, len(raw), 4):
                        out.extend(raw[i:i+4][::-1])

                    pos += n

                    # Progression toutes les 256 KiB et à la fin
                    if (pos % 0x40000) == 0 or pos == size:
                        pct = pos * 100.0 / size
                        log(
                            f"Lecture : {pos:08X}/{size:08X} "
                            f"({human_mib(pos):.2f}/{human_mib(size):.2f} MiB) "
                            f"{pct:6.2f}%"
                        )

                return bytes(out)

            # Handshake
            log("")
            log("Handshake BROM...")
            sync = (
                (0xA0, 0x5F),
                (0x0A, 0xF5),
                (0x50, 0xAF),
                (0x05, 0xFA),
            )

            for sent, expected in sync:
                tx(sent, 300)
                ans = rx(1, 300)
                log(f"  {sent:02X} -> {ans[0]:02X}")

                if ans != bytes([expected]):
                    stop(
                        f"handshake incorrect, attendu {expected:02X}"
                    )

            log("Handshake OK.")

            # Confirmer CPU
            cpu_id = read16_legacy(0x80000008)
            log(f"BB_CPU_ID = 0x{cpu_id:04X}")

            if cpu_id != 0x6261:
                stop("CPU différent de MT6261 : arrêt de sécurité.")

            # Désactiver WDT (registre volatil uniquement)
            log("")
            log("Desactivation temporaire du watchdog MT6261...")
            write16_reg(WDT_ADDR, WDT_DISABLE)
            log("Watchdog desactive pour cette session.")

            # Mapper flash à l'adresse 0
            log("Activation temporaire du mapping lecture de la flash...")
            old_map = read32_word(FLASH_MAP_REG)
            new_map = old_map | 0x2

            if new_map != old_map:
                write32_reg(FLASH_MAP_REG, new_map)

            log(
                f"FLASH_MAP_REG : "
                f"0x{old_map:08X} -> 0x{new_map:08X}"
            )

            log("")
            log(
                f"Lecture complete de {DUMP_SIZE} octets "
                f"({human_mib(DUMP_SIZE):.2f} MiB)..."
            )
            log(
                f"Plage : 0x{DUMP_START:08X} -> "
                f"0x{DUMP_START + DUMP_SIZE - 1:08X}"
            )
            log("")

            data = read32_bytes(DUMP_START, DUMP_SIZE)

            if len(data) != DUMP_SIZE:
                stop(
                    f"taille lue incorrecte : {len(data)} "
                    f"au lieu de {DUMP_SIZE}"
                )

            log("")
            log("Ecriture du fichier sur disque...")

            with out_path.open("wb") as f:
                f.write(data)
                f.flush()

            actual_size = out_path.stat().st_size

            if actual_size != DUMP_SIZE:
                stop(
                    f"taille fichier incorrecte : {actual_size} "
                    f"au lieu de {DUMP_SIZE}"
                )

            digest = hashlib.sha256(data).hexdigest()
            ff = data.count(0xFF) / len(data) * 100.0
            zz = data.count(0x00) / len(data) * 100.0

            log("")
            log("================ RESULTAT ================")
            log(f"Fichier : {out_path}")
            log(f"Taille  : {actual_size} octets")
            log(f"SHA256  : {digest}")
            log(f"FF      : {ff:.2f}%")
            log(f"00      : {zz:.2f}%")
            log("")
            log("AUCUNE ECRITURE/ERASE de flash n'a ete effectuee.")
            log(
                "Seuls des registres volatils MT6261 ont ete "
                "modifies pour maintenir la session et mapper la NOR."
            )
            log(f"Journal : {log_path}")

        except Exception as e:
            log("")
            log(f"ERREUR : {e!r}")
            raise

        finally:
            try:
                if claimed:
                    usb.util.release_interface(dev, ifnum)
            except Exception:
                pass

            try:
                usb.util.dispose_resources(dev)
            except Exception:
                pass


if __name__ == "__main__":
    main()
