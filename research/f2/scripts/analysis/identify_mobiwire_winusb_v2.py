#!/usr/bin/env python3
# -*- coding: utf-8 -*-

r"""
MobiWire NIKITI / Altice F2 — identification MediaTek via WinUSB v2.

Cette version:
- utilise libusb-package (libusb récent) au lieu de la DLL de mtkclient ;
- n'appelle PAS get_active_configuration() ;
- lit directement le descripteur de configuration #0 avec dev[0] ;
- réclame ensuite l'interface WinUSB ;
- effectue uniquement handshake + lectures d'identification.

Aucune écriture/effacement de flash.
"""

import time
import struct
from pathlib import Path

import usb.core
import usb.util

try:
    import libusb_package
except ImportError:
    print("ERREUR: libusb-package n'est pas installe.", flush=True)
    print("Installez-le avec:", flush=True)
    print("  python -m pip install --upgrade libusb-package pyusb", flush=True)
    raise SystemExit(1)

VID = 0x0E8D
PID = 0x0003
WAIT_SECONDS = 90

backend = libusb_package.get_libusb1_backend()
if backend is None:
    print("ERREUR: backend libusb-package indisponible.", flush=True)
    raise SystemExit(1)

log_path = Path.cwd() / "mobiwire_identification_winusb_v2.txt"
logf = log_path.open("w", encoding="utf-8", buffering=1)

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
log(" MOBIWIRE / ALTICE F2 - WINUSB V2 (READ ONLY)")
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
        d = usb.core.find(idVendor=VID, idProduct=PID, backend=backend)
        if d is not None:
            dev = d
            break
    except Exception:
        pass
    time.sleep(0.003)

if dev is None:
    stop("0E8D:0003 non capture.")

log(f">>> BROM CAPTURE : {VID:04X}:{PID:04X} <<<")
log(f"Classe USB du device : 0x{dev.bDeviceClass:02X}")

# IMPORTANT:
# Ne pas utiliser get_active_configuration() sous Windows ici.
# On lit directement le descripteur de la première configuration.
try:
    cfg = dev[0]
except Exception as e:
    stop(f"impossible de lire le descripteur de configuration #0 : {e!r}")

log(
    f"Configuration #0 lue : valeur={cfg.bConfigurationValue}, "
    f"interfaces={cfg.bNumInterfaces}"
)

bulk_if = None
ep_in = None
ep_out = None

try:
    for intf in cfg:
        this_in = None
        this_out = None

        for ep in intf:
            if usb.util.endpoint_type(ep.bmAttributes) != usb.util.ENDPOINT_TYPE_BULK:
                continue

            direction = usb.util.endpoint_direction(ep.bEndpointAddress)
            if direction == usb.util.ENDPOINT_IN:
                this_in = ep
            elif direction == usb.util.ENDPOINT_OUT:
                this_out = ep

        if this_in is not None and this_out is not None:
            bulk_if = intf
            ep_in = this_in
            ep_out = this_out
            break
except Exception as e:
    stop(f"erreur pendant l'analyse des interfaces : {e!r}")

if bulk_if is None:
    stop("interface BULK IN/OUT introuvable.")

ifnum = bulk_if.bInterfaceNumber

log(
    f"Interface USB : {ifnum} | "
    f"OUT=0x{ep_out.bEndpointAddress:02X} | "
    f"IN=0x{ep_in.bEndpointAddress:02X}"
)

claimed = False

try:
    log("Tentative de claim_interface WinUSB...")
    usb.util.claim_interface(dev, ifnum)
    claimed = True
    log("Interface WinUSB reclamee avec succes.")

    def tx(data, timeout=200):
        if isinstance(data, int):
            data = bytes([data])
        n = ep_out.write(data, timeout=timeout)
        if n != len(data):
            raise RuntimeError(f"ecriture incomplete {n}/{len(data)}")

    def rx(n, timeout=200):
        data = bytes(ep_in.read(n, timeout=timeout))
        if len(data) != n:
            raise RuntimeError(f"lecture incomplete {len(data)}/{n}")
        return data

    log("")
    log("Handshake BROM...")

    got = False
    for attempt in range(1, 301):
        try:
            tx(0xA0, 80)
            ans = rx(1, 80)
            if ans == b"\x5F":
                log(f"  A0 -> 5F (tentative {attempt})")
                got = True
                break
        except usb.core.USBError:
            pass
        time.sleep(0.003)

    if not got:
        stop("BROM capture mais aucune reponse 0x5F.")

    for sent, expected in ((0x0A, 0xF5), (0x50, 0xAF), (0x05, 0xFA)):
        tx(sent, 250)
        ans = rx(1, 250)
        log(f"  {sent:02X} -> {ans[0]:02X}")
        if ans != bytes([expected]):
            stop(
                f"handshake incorrect : attendu 0x{expected:02X}, "
                f"recu 0x{ans[0]:02X}"
            )

    log("")
    log("******** HANDSHAKE MTK REUSSI ********")

    def echo(data):
        if isinstance(data, int):
            data = bytes([data])
        tx(data, 500)
        ans = rx(len(data), 500)
        if ans != data:
            raise RuntimeError(
                f"echo incorrect TX={data.hex()} RX={ans.hex()}"
            )

    def read16(addr):
        # CMD_LEGACY_READ = 0xA2
        echo(0xA2)
        echo(struct.pack(">I", addr))
        echo(struct.pack(">I", 1))
        return struct.unpack(">H", rx(2, 700))[0]

    log("")
    log("Lecture des identifiants (lecture seule)...")

    cpu_id = read16(0x80000008)
    log(f"BB_CPU_ID = 0x{cpu_id:04X}")

    hw = read16(0x80000000)
    sw = read16(0x80000004)
    sub = read16(0x8000000C)

    log(f"BB_CPU_HW = 0x{hw:04X}")
    log(f"BB_CPU_SW = 0x{sw:04X}")
    log(f"BB_CPU_SB = 0x{sub:04X}")

    log("")
    if cpu_id == 0x6260:
        log("CPU IDENTIFIE : MediaTek MT6260")
    elif cpu_id == 0x6261:
        log("CPU IDENTIFIE : MediaTek MT6261")
    else:
        log(f"CPU ID obtenu : 0x{cpu_id:04X}")

    log("")
    log("Aucune zone de flash n'a ete ecrite ou effacee.")
    log(f"Journal : {log_path}")

except NotImplementedError as e:
    log("")
    log(f"ERREUR DRIVER/LIBUSB : {e!r}")
    log(
        "Le peripherique est visible mais ne peut pas etre ouvert/reclame. "
        "Verifier que le service actif de 0E8D:0003 est WinUSB."
    )
except usb.core.USBError as e:
    log("")
    log(f"ERREUR USB : {e!r}")
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
