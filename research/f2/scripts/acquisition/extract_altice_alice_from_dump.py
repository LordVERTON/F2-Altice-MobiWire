#!/usr/bin/env python3
import argparse
import hashlib
import struct
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from _paths import ALTICE_ALICE

GFH_MAGIC = b"MMM\x01"
FILE_INFO = b"FILE_INFO"
VIVA_FILE_TYPE = 0x0108

def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def u16(data, off):
    return struct.unpack_from("<H", data, off)[0]

def u32(data, off):
    return struct.unpack_from("<I", data, off)[0]

def find_alice(data: bytes):
    hits = []
    for sig in (b"ALICE_1", b"ALICE_2"):
        pos = 0
        while True:
            i = data.find(sig, pos)
            if i < 0:
                break
            hits.append((i, sig))
            pos = i + 1
    return sorted(hits)

def find_viva_container(data: bytes, alice_off: int):
    candidates = []
    pos = 0
    while True:
        i = data.find(GFH_MAGIC, pos)
        if i < 0:
            break
        pos = i + 1
        if i + 0x38 > len(data):
            continue
        if data[i+8:i+17] != FILE_INFO:
            continue

        file_type = u16(data, i + 0x18)
        file_len = u32(data, i + 0x20)

        if file_type != VIVA_FILE_TYPE:
            continue
        if file_len == 0 or i + file_len > len(data):
            continue
        if i <= alice_off < i + file_len:
            candidates.append((i, file_len))

    if not candidates:
        return None
    # The nearest enclosing VIVA is normally the right one.
    return max(candidates, key=lambda x: x[0])

def main():
    ap = argparse.ArgumentParser(
        description="Extrait automatiquement VIVA et ALICE_1/ALICE_2 depuis un dump flash MediaTek."
    )
    ap.add_argument("--dump", required=True, help="Dump flash complet, ex. mobiwire_dump_2.bin")
    ap.add_argument("--out", default=str(ALTICE_ALICE), help="Dossier de sortie")
    args = ap.parse_args()

    src = Path(args.dump)
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)

    data = src.read_bytes()
    print("=== Dump ===")
    print("Fichier :", src)
    print("Taille  :", len(data), f"(0x{len(data):X})")
    print("SHA256  :", sha256(data))

    alice_hits = find_alice(data)
    if not alice_hits:
        raise SystemExit("Erreur: aucune signature ALICE_1 / ALICE_2 trouvée.")

    print("\n=== Signatures ALICE trouvées ===")
    for off, sig in alice_hits:
        print(f"{sig.decode()} @ flash 0x{off:08X}")

    # Use the first valid ALICE that can be linked to a VIVA GFH container.
    chosen = None
    for alice_off, sig in alice_hits:
        viva = find_viva_container(data, alice_off)
        if viva:
            chosen = (alice_off, sig, viva[0], viva[1])
            break

    if chosen is None:
        raise SystemExit("Erreur: ALICE trouvée, mais aucun conteneur VIVA GFH cohérent autour.")

    alice_off, sig, viva_off, viva_len = chosen
    viva_end = viva_off + viva_len
    viva = data[viva_off:viva_end]
    alice = data[alice_off:viva_end]

    viva_path = out / "altice_VIVA.bin"
    alice_path = out / f"altice_{sig.decode()}.bin"
    viva_path.write_bytes(viva)
    alice_path.write_bytes(alice)

    print("\n=== VIVA ===")
    print(f"Début flash : 0x{viva_off:08X}")
    print(f"Taille      : {viva_len} (0x{viva_len:X})")
    print(f"Fin flash   : 0x{viva_end:08X}")
    print("SHA256      :", sha256(viva))

    print("\n=== ALICE ===")
    print("Type        :", sig.decode())
    print(f"Début flash : 0x{alice_off:08X}")
    print(f"Offset VIVA : 0x{alice_off-viva_off:08X}")
    print(f"Taille      : {len(alice)} (0x{len(alice):X})")

    if len(alice) >= 20:
        base = u32(alice, 8)
        mapping = u32(alice, 12)
        dictionary = u32(alice, 16)
        print(f"Base        : 0x{base:08X}")
        print(f"Map table   : 0x{mapping:08X}")
        print(f"Dictionary  : 0x{dictionary:08X}")

    print("SHA256      :", sha256(alice))
    print("\nFichiers créés :")
    print(" ", viva_path)
    print(" ", alice_path)
    print("\nÉtape suivante :")
    print(f"  python {Path(__file__).resolve().parents[2] / 'tools' / 'unalice' / 'unalice.py'} .\\{alice_path.name}")

if __name__ == "__main__":
    main()
