#!/usr/bin/env python3
# -*- coding: utf-8 -*-

r"""
MobiWire NIKITI / Altice F2 — MT6261 flash probe via WinUSB.

But:
- confirmer le CPU MT6261 ;
- désactiver temporairement le watchdog (registre volatil) ;
- mapper la NOR/SPI flash en lecture via le contrôleur SFI ;
- lire de petits échantillons à 0, 4 MiB et 8 MiB ;
- comparer leurs SHA-256 afin d'estimer la taille de flash.

IMPORTANT:
- aucune commande d'effacement de flash ;
- aucune commande d'écriture de flash ;
- deux écritures VOLATILES de registres matériels sont utilisées :
  * watchdog MT6261 ;
  * bit de mapping de la flash.
Elles disparaissent au redémarrage et ne modifient pas le contenu de la NOR.

Pilote attendu pour USB\VID_0E8D&PID_0003 : WinUSB.
"""

import time
import struct
import hashlib
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from _paths import REPORTS_ROOT

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

SAMPLE_SIZE = 0x10000  # 64 KiB
OFFSETS = [0x00000000, 0x00400000, 0x00800000]

backend = libusb_package.get_libusb1_backend()
if backend is None:
    print("ERREUR : backend libusb-package indisponible.", flush=True)
    raise SystemExit(1)

log_path = REPORTS_ROOT / "acquisition" / "mobiwire_flash_probe.txt"
log_path.parent.mkdir(parents=True, exist_ok=True)
logf = log_path.open("w", encoding="utf-8", buffering=1)

def log(s=""):
    print(s, flush=True)
    print(s, file=logf, flush=True)

def stop(msg, code=1):
    log("")
    log("ECHEC : " + msg)
    log(f"Journal : {log_path}")
    raise SystemExit(code)

def u16be(b):
    return struct.unpack(">H", b)[0]

def u32be(b):
    return struct.unpack(">I", b)[0]

log("")
log("============================================================")
log(" MOBIWIRE / ALTICE F2 - PROBE FLASH MT6261 (READ ONLY FLASH)")
log("============================================================")
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
        dev = usb.core.find(idVendor=VID, idProduct=PID, backend=backend)
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
log(f"Interface {ifnum} | OUT=0x{ep_out.bEndpointAddress:02X} | IN=0x{ep_in.bEndpointAddress:02X}")

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
            raise RuntimeError(f"USB write incomplet {n}/{len(data)}")

    def rx(n, timeout=1000):
        data = bytes(ep_in.read(n, timeout=timeout))
        if len(data) != n:
            raise RuntimeError(f"USB read incomplet {len(data)}/{n}")
        return data

    def echo(data, timeout=1000):
        if isinstance(data, int):
            data = bytes([data])
        tx(data, timeout)
        ans = rx(len(data), timeout)
        if ans != data:
            raise RuntimeError(f"echo incorrect TX={data.hex()} RX={ans.hex()}")

    def status():
        s = u16be(rx(2, 1000))
        if s >= 0x00FF:
            raise RuntimeError(f"status BROM inattendu 0x{s:04X}")
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
            raise ValueError("read32 exige adresse/taille multiples de 4")
        out = bytearray()
        step = 1024
        pos = 0
        while pos < size:
            n = min(step, size - pos)
            echo(CMD_READ32)
            echo(struct.pack(">I", addr + pos))
            echo(struct.pack(">I", n // 4))
            status()
            raw = rx(n, 3000)
            status()

            # Le BROM renvoie chaque mot 32-bit en big-endian.
            # Reconstituer l'ordre d'octets du contenu mémoire.
            for i in range(0, len(raw), 4):
                out.extend(raw[i:i+4][::-1])

            pos += n
        return bytes(out)

    # Handshake
    log("")
    log("Handshake BROM...")
    sync = ((0xA0, 0x5F), (0x0A, 0xF5), (0x50, 0xAF), (0x05, 0xFA))
    for sent, expected in sync:
        tx(sent, 300)
        ans = rx(1, 300)
        log(f"  {sent:02X} -> {ans[0]:02X}")
        if ans != bytes([expected]):
            stop(f"handshake incorrect, attendu {expected:02X}")

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
    log(f"FLASH_MAP_REG : 0x{old_map:08X} -> 0x{new_map:08X}")

    log("")
    log(f"Lecture de {SAMPLE_SIZE//1024} KiB a trois offsets...")

    samples = {}
    for off in OFFSETS:
        data = read32_bytes(off, SAMPLE_SIZE)
        sha = hashlib.sha256(data).hexdigest()
        ff = data.count(0xFF) / len(data) * 100.0
        zz = data.count(0x00) / len(data) * 100.0
        samples[off] = (sha, ff, zz)
        log(f"0x{off:08X}: SHA256={sha}")
        log(f"             FF={ff:.2f}%  00={zz:.2f}%")

    log("")
    h0 = samples[0x00000000][0]
    h4 = samples[0x00400000][0]
    h8 = samples[0x00800000][0]

    if h0 == h4:
        log("INDICE FORT : 0 MiB et 4 MiB sont identiques -> flash probablement 4 MiB avec mirroring.")
    elif h0 == h8:
        log("INDICE FORT : 0 MiB et 8 MiB sont identiques -> flash probablement 8 MiB avec mirroring.")
    else:
        log("Les trois echantillons sont differents : la flash peut etre > 8 MiB, ou l'espace hors flash ne mirror pas.")
        log("Ne pas conclure sur la taille sans probe supplementaire/JEDEC.")

    log("")
    log("AUCUNE ECRITURE/ERASE de flash n'a ete effectuee.")
    log("Seuls des registres volatils MT6261 ont ete modifies pour maintenir la session et mapper la NOR.")
    log(f"Journal : {log_path}")

except Exception as e:
    log("")
    log(f"ERREUR : {e!r}")
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
    try:
        logf.close()
    except Exception:
        pass
