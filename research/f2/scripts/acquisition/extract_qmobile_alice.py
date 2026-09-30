#!/usr/bin/env python3
import argparse
import hashlib
import struct
import zipfile
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from _paths import QMOBILE_ALICE

def sha256(b):
    return hashlib.sha256(b).hexdigest()

def main():
    ap = argparse.ArgumentParser(description="Extrait VIVA puis ALICE_1/ALICE_2 d'un firmware QMobile ZIP.")
    ap.add_argument("--zip", required=True, help="Archive QMobile ZIP")
    ap.add_argument("--out", default=str(QMOBILE_ALICE), help="Dossier de sortie")
    args = ap.parse_args()

    zpath = Path(args.zip)
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)

    with zipfile.ZipFile(zpath, "r") as z:
        viva_names = [n for n in z.namelist() if n.replace("\\", "/").endswith("/Firmware/VIVA")]
        if not viva_names:
            raise SystemExit("Erreur: fichier Firmware/VIVA introuvable dans le ZIP.")
        viva_name = viva_names[0]
        viva = z.read(viva_name)

    viva_path = out / "qmobile_VIVA.bin"
    viva_path.write_bytes(viva)

    print("=== VIVA ===")
    print("Archive :", zpath)
    print("Entrée  :", viva_name)
    print("Taille  :", len(viva), f"(0x{len(viva):X})")
    print("SHA256  :", sha256(viva))

    if len(viva) >= 0x38 and viva[:4] == b"MMM\x01" and viva[8:17] == b"FILE_INFO":
        file_ver = struct.unpack_from("<I", viva, 0x14)[0]
        file_type = struct.unpack_from("<H", viva, 0x18)[0]
        flash_dev = viva[0x1A]
        sig_type = viva[0x1B]
        load_addr = struct.unpack_from("<I", viva, 0x1C)[0]
        file_len = struct.unpack_from("<I", viva, 0x20)[0]
        max_size = struct.unpack_from("<I", viva, 0x24)[0]
        content_offset = struct.unpack_from("<I", viva, 0x28)[0]
        sig_len = struct.unpack_from("<I", viva, 0x2C)[0]
        jump_offset = struct.unpack_from("<I", viva, 0x30)[0]
        attr = struct.unpack_from("<I", viva, 0x34)[0]

        print("\n=== En-tête MediaTek GFH ===")
        print(f"file_ver       : 0x{file_ver:08X}")
        print(f"file_type      : 0x{file_type:04X} (0x0108 = VIVA attendu)")
        print(f"flash_dev      : 0x{flash_dev:02X}")
        print(f"sig_type       : 0x{sig_type:02X}")
        print(f"load_addr      : 0x{load_addr:08X}")
        print(f"file_len       : 0x{file_len:08X}")
        print(f"max_size       : 0x{max_size:08X}")
        print(f"content_offset : 0x{content_offset:08X}")
        print(f"sig_len        : 0x{sig_len:08X}")
        print(f"jump_offset    : 0x{jump_offset:08X}")
        print(f"attr           : 0x{attr:08X}")

    hits = []
    for sig in (b"ALICE_1", b"ALICE_2"):
        start = 0
        while True:
            i = viva.find(sig, start)
            if i < 0:
                break
            hits.append((i, sig.decode()))
            start = i + 1

    if not hits:
        raise SystemExit("\nErreur: aucune signature ALICE_1/ALICE_2 trouvée.")

    hits.sort()
    print("\n=== Signatures ALICE ===")
    for off, sig in hits:
        print(f"{sig} @ offset 0x{off:08X} ({off})")

    # Pour le QMobile fourni, une seule ALICE_2 est attendue.
    alice_off, alice_type = hits[0]
    alice = viva[alice_off:]
    alice_path = out / f"qmobile_{alice_type}.bin"
    alice_path.write_bytes(alice)

    print("\n=== Extraction ===")
    print("VIVA  :", viva_path)
    print("ALICE :", alice_path)
    print(f"Offset ALICE : 0x{alice_off:08X}")
    print(f"Taille ALICE : {len(alice)} (0x{len(alice):X})")
    print("SHA256 ALICE :", sha256(alice))
    print("\nÉtape suivante : lancer unalice.py sur le fichier ALICE extrait.")

if __name__ == "__main__":
    main()
