#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
probe_mobiwire_flash_size_v2.py

Probe READ-ONLY (flash) pour MobiWire NIKITI / Altice F2 - MT6261.
Compare des fenêtres de flash mappée aux offsets :
0, 1, 2, 3, 4 et 8 MiB.

IMPORTANT :
- aucune commande d'effacement de flash
- aucune commande d'écriture de flash
- seules écritures effectuées : registres volatils MT6261
  * watchdog : 0xA0030000 <- 0x2200
  * mapping NOR : bit 1 de 0xA0510000

Dépendance :
    pip install pyusb

Le téléphone doit être éteint et apparaître en BROM USB 0E8D:0003.
"""

import sys
import time
import hashlib
import struct

import usb.core
import usb.util

VID = 0x0E8D
PID = 0x0003

EP_OUT = 0x01
EP_IN  = 0x81
INTERFACE = 0

USB_TIMEOUT_MS = 2000
WAIT_SECONDS = 120

# Commandes BROM MediaTek (mediatek_flash / mtk_cmd.h)
CMD_LEGACY_READ = 0xA2
CMD_READ16      = 0xD0
CMD_READ32      = 0xD1
CMD_WRITE16     = 0xD2
CMD_WRITE32     = 0xD4
CMD_GET_VERSION = 0xFF
CMD_GET_BL_VER  = 0xFE

# Registres MT6260/MT6261 utilisés par mediatek_flash
WDT_REG         = 0xA0030000
FLASH_MAP_REG   = 0xA0510000

# On lit 64 KiB à chaque position : assez grand pour éviter
# de conclure à partir de quelques octets seulement.
SAMPLE_SIZE = 64 * 1024

PROBE_OFFSETS = [
    0x00000000,  # 0 MiB
    0x00100000,  # 1 MiB
    0x00200000,  # 2 MiB
    0x00300000,  # 3 MiB
    0x00400000,  # 4 MiB
    0x00800000,  # 8 MiB
]


def hx(data):
    return bytes(data).hex()


class BROM:
    def __init__(self, dev):
        self.dev = dev

    def write(self, data):
        data = bytes(data)
        n = self.dev.write(EP_OUT, data, timeout=USB_TIMEOUT_MS)
        if n != len(data):
            raise RuntimeError(f"USB write incomplet: {n}/{len(data)}")

    def read_exact(self, n):
        out = bytearray()
        while len(out) < n:
            chunk = self.dev.read(
                EP_IN,
                min(1024, n - len(out)),
                timeout=USB_TIMEOUT_MS
            )
            out.extend(bytes(chunk))
        return bytes(out)

    def echo8(self, value):
        b = bytes([value & 0xFF])
        self.write(b)
        r = self.read_exact(1)
        if r != b:
            raise RuntimeError(
                f"Echo8 incorrect: envoyé {b.hex()} reçu {r.hex()}"
            )

    def echo16(self, value):
        b = struct.pack(">H", value & 0xFFFF)
        self.write(b)
        r = self.read_exact(2)
        if r != b:
            raise RuntimeError(
                f"Echo16 incorrect: envoyé {b.hex()} reçu {r.hex()}"
            )

    def echo32(self, value):
        b = struct.pack(">I", value & 0xFFFFFFFF)
        self.write(b)
        r = self.read_exact(4)
        if r != b:
            raise RuntimeError(
                f"Echo32 incorrect: envoyé {b.hex()} reçu {r.hex()}"
            )

    def status(self):
        r = self.read_exact(2)
        s = struct.unpack(">H", r)[0]
        if s >= 0x00FF:
            raise RuntimeError(f"Status BROM inattendu: 0x{s:04X}")
        return s

    def handshake(self):
        seq = [0xA0, 0x0A, 0x50, 0x05]
        expected = [0x5F, 0xF5, 0xAF, 0xFA]

        print("[*] Handshake BROM...")
        for tx, exp in zip(seq, expected):
            self.write(bytes([tx]))
            rx = self.read_exact(1)[0]
            print(f"    {tx:02X} -> {rx:02X}")
            if rx != exp:
                raise RuntimeError(
                    f"Handshake invalide: {tx:02X} -> {rx:02X}, attendu {exp:02X}"
                )

    def get_version_byte(self, cmd):
        # Contrairement aux commandes echo*, GET_VERSION / GET_BL_VER
        # répondent directement par un octet.
        self.write(bytes([cmd]))
        return self.read_exact(1)[0]

    def legacy_read16(self, addr):
        self.echo8(CMD_LEGACY_READ)
        self.echo32(addr)
        self.echo32(1)
        return struct.unpack(">H", self.read_exact(2))[0]

    def read32_word(self, addr):
        self.echo8(CMD_READ32)
        self.echo32(addr)
        self.echo32(1)
        self.status()
        v = struct.unpack(">I", self.read_exact(4))[0]
        self.status()
        return v

    def write16_reg(self, addr, value):
        self.echo8(CMD_WRITE16)
        self.echo32(addr)
        self.echo32(1)
        self.status()
        self.echo16(value)
        self.status()

    def write32_reg(self, addr, value):
        self.echo8(CMD_WRITE32)
        self.echo32(addr)
        self.echo32(1)
        self.status()
        self.echo32(value)
        self.status()

    def read_mem32(self, addr, size):
        if (addr & 3) or (size & 3):
            raise ValueError("read_mem32 exige adresse et taille alignées sur 4")

        result = bytearray()
        off = 0

        while off < size:
            n = min(1024, size - off)

            self.echo8(CMD_READ32)
            self.echo32(addr + off)
            self.echo32(n // 4)
            self.status()

            raw = self.read_exact(n)
            self.status()

            # mtk_dump.c convertit chaque mot reçu en BE vers octets LE
            for i in range(0, n, 4):
                word = struct.unpack(">I", raw[i:i+4])[0]
                result.extend(struct.pack("<I", word))

            off += n

        return bytes(result)


def wait_for_device():
    print()
    print("============================================================")
    print(" MobiWire NIKITI / Altice F2 - MT6261 flash-size probe v2")
    print(" LECTURE FLASH UNIQUEMENT - aucune écriture/effacement flash")
    print("============================================================")
    print()
    print("Batterie retirée ~10 s, remise, téléphone ÉTEINT.")
    print()
    print(">>> BRANCHEZ LE CABLE USB MAINTENANT <<<")
    print()

    deadline = time.time() + WAIT_SECONDS
    while time.time() < deadline:
        dev = usb.core.find(idVendor=VID, idProduct=PID)
        if dev is not None:
            return dev
        time.sleep(0.20)

    raise RuntimeError(
        f"Périphérique {VID:04X}:{PID:04X} non détecté dans les {WAIT_SECONDS}s"
    )


def prepare_usb(dev):
    try:
        dev.set_configuration()
    except usb.core.USBError:
        # Sous Windows/WinUSB la configuration peut déjà être active.
        pass

    try:
        if dev.is_kernel_driver_active(INTERFACE):
            dev.detach_kernel_driver(INTERFACE)
    except (NotImplementedError, usb.core.USBError):
        pass

    try:
        usb.util.claim_interface(dev, INTERFACE)
    except usb.core.USBError:
        # Selon backend/WinUSB, claim explicite peut être inutile.
        pass


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def mib(addr):
    return addr // (1024 * 1024)


def main():
    dev = None

    try:
        dev = wait_for_device()
        print(f"[+] USB trouvé : {VID:04X}:{PID:04X}")

        prepare_usb(dev)
        brom = BROM(dev)

        brom.handshake()

        try:
            brom_ver = brom.get_version_byte(CMD_GET_VERSION)
            print(f"[+] BROM version byte : 0x{brom_ver:02X}")
        except Exception as e:
            print(f"[!] Lecture version BROM ignorée : {e}")

        # Même méthode d'identification que mediatek_flash :
        # 0x80000000 + i*4, lecture legacy 16 bits.
        info = []
        for i in range(4):
            info.append(brom.legacy_read16(0x80000000 + i * 4))

        # Dans mediatek_flash :
        # HW = info[2]:info[3], SW = info[0]:info[1]
        print(
            f"[+] HW = {info[2]:04X}:{info[3]:04X}, "
            f"SW = {info[0]:04X}:{info[1]:04X}"
        )

        chip = info[2]
        if chip not in (0x6260, 0x6261):
            raise RuntimeError(
                f"Chip inattendu 0x{chip:04X}; arrêt par sécurité."
            )

        print(f"[+] Chip reconnu : MT{chip:04X}")

        # Désactivation VOLATILE du watchdog.
        print("[*] Désactivation volatile du watchdog...")
        brom.write16_reg(WDT_REG, 0x2200)

        # Mapping VOLATILE de la NOR à l'adresse mémoire 0.
        old_map = brom.read32_word(FLASH_MAP_REG)
        new_map = old_map | 0x00000002
        print(
            f"[*] FLASH_MAP_REG : 0x{old_map:08X} -> 0x{new_map:08X}"
        )
        if new_map != old_map:
            brom.write32_reg(FLASH_MAP_REG, new_map)

        print()
        print(
            f"[*] Lecture de {SAMPLE_SIZE // 1024} KiB à "
            "0, 1, 2, 3, 4 et 8 MiB..."
        )

        samples = {}

        for addr in PROBE_OFFSETS:
            label = f"{mib(addr)}MiB"
            print(f"    - {label:>4} @ 0x{addr:08X} ... ", end="", flush=True)
            data = brom.read_mem32(addr, SAMPLE_SIZE)
            digest = sha256(data)
            samples[addr] = data

            filename = f"probe_{label}.bin"
            with open(filename, "wb") as f:
                f.write(data)

            print(f"SHA256 {digest}")

        print()
        print("================ COMPARAISONS ================")

        base = samples[0]
        equal_to_zero = {}

        for addr in PROBE_OFFSETS[1:]:
            same = (samples[addr] == base)
            equal_to_zero[addr] = same
            print(
                f"0 MiB {'==' if same else '!='} {mib(addr)} MiB"
                f"    ({'IDENTIQUE' if same else 'DIFFÉRENT'})"
            )

        print()
        print("================ INTERPRÉTATION ===============")

        # On cherche le plus petit offset testé identique à 0.
        # Cela donne une période observée, pas une preuve absolue de capacité.
        period = None
        for addr in PROBE_OFFSETS[1:]:
            if equal_to_zero.get(addr):
                period = addr
                break

        if period == 0x00100000:
            print("[?] Période observée : 1 MiB.")
            print("    Taille flash probablement <= 1 MiB, à confirmer.")
        elif period == 0x00200000:
            print("[?] Période observée : 2 MiB.")
            print("    Taille flash probablement 2 MiB, à confirmer.")
        elif period == 0x00300000:
            print("[?] Répétition observée à 3 MiB.")
            print("    Cas inhabituel : ne pas conclure automatiquement.")
        elif period == 0x00400000:
            print("[+] Période observée : 4 MiB.")
            print("    Taille flash probablement 4 MiB.")
        elif period == 0x00800000:
            print("[+] Pas de répétition à 1/2/3/4 MiB,")
            print("    mais répétition à 8 MiB.")
            print("    Taille flash probablement 8 MiB.")
        else:
            print("[?] Aucune répétition détectée jusqu'à 8 MiB.")
            print("    Flash potentiellement > 8 MiB ou mapping non trivial.")

        print()
        print("NOTE : ce probe établit une PÉRIODE DE MAPPING observée.")
        print("Pour confirmer la capacité physique, un JEDEC ID/SFDP est préférable.")
        print("Aucune zone de flash n'a été écrite ou effacée.")

    except KeyboardInterrupt:
        print("\n[!] Interrompu par l'utilisateur.")
        return 130

    except Exception as e:
        print(f"\n[ERREUR] {e}")
        return 1

    finally:
        if dev is not None:
            try:
                usb.util.release_interface(dev, INTERFACE)
            except Exception:
                pass
            try:
                usb.util.dispose_resources(dev)
            except Exception:
                pass

    return 0


if __name__ == "__main__":
    sys.exit(main())
