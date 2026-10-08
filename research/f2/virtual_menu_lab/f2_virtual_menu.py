#!/usr/bin/env python3
"""F2 Virtual Menu Lab. Firmware read-only, no flashing."""

import argparse
import hashlib
import json
import struct
from pathlib import Path

BASE = 0xF023CA50
EXPECTED_SIZE = 0x185E98
EXPECTED_SHA256 = (
    "85fba8c8ae8161e4c1f8ced7983ec30d48c54ab"
    "10e51c69fcdfb900aca220954"
)

RECORD_B702 = 0xF037BEA0
CHILDREN_B702 = 0xF0378720

EXPECTED_CHILDREN = (0x8569, 0x87ED)
AUDIO_ID = 0x8928

FIRMWARE = (
    Path(__file__).resolve().parents[1]
    / "work/extracted/altice_platform/zimage.bin"
)


def load_registry(path=FIRMWARE):
    """Read and validate the exact known B702 record."""
    data = Path(path).read_bytes()

    if len(data) != EXPECTED_SIZE:
        raise ValueError("ABORT: unexpected ZIMAGE size")

    digest = hashlib.sha256(data).hexdigest()
    if digest != EXPECTED_SHA256:
        raise ValueError("ABORT: ZIMAGE SHA256 mismatch")

    def read(addr, fmt):
        size = struct.calcsize(fmt)
        offset = addr - BASE
        if offset < 0 or offset + size > len(data):
            raise ValueError("ABORT: address out of range")
        return struct.unpack_from(fmt, data, offset)[0]

    parent = read(RECORD_B702, "<H")
    count = read(RECORD_B702 + 2, "<H")
    pointer = read(RECORD_B702 + 12, "<I")

    if (parent, count, pointer) != (
        0xB709, 2, CHILDREN_B702
    ):
        raise ValueError("ABORT: B702 record mismatch")

    children = tuple(
        read(pointer + i * 2, "<H")
        for i in range(count)
    )

    if children != EXPECTED_CHILDREN:
        raise ValueError("ABORT: B702 children mismatch")

    if read(pointer + count * 2, "<H") != 0xA07B:
        raise ValueError("ABORT: packed boundary mismatch")

    return {
        "sha256": digest,
        "record": f"0x{RECORD_B702:08X}",
        "parent": f"0x{parent:04X}",
        "child_count": count,
        "child_pointer": f"0x{pointer:08X}",
        "children": list(children),
        "boundary_preserved": True,
    }


def build_model(registry, inject_audio=False):
    children = list(registry["children"])

    if inject_audio:
        children.append(AUDIO_ID)

    return {
        "mode": "virtual_audio_candidate" if inject_audio else "original",
        "children": children,
        "display_labels": [
            {
                0x8569: "8569 - entree existante",
                0x87ED: "87ED - Image Viewer",
                0x8928: "8928 - Audio Player (virtuel)",
            }.get(item, f"{item:04X} - inconnu")
            for item in children
        ],
        "firmware_modified": False,
        "native_execution_proven": False,
        "visibility_proven": False,
    }


def launch_gui(registry):
    import tkinter as tk

    root = tk.Tk()
    root.title("F2 Virtual Menu Lab")
    root.geometry("420x650")
    root.resizable(False, False)

    mode = tk.BooleanVar(value=False)
    selected = [0]

    outer = tk.Frame(root, bg="#252525")
    outer.pack(fill="both", expand=True, padx=18, pady=18)

    tk.Label(
        outer, text="F2 VIRTUAL MENU LAB",
        bg="#252525", fg="white",
        font=("Segoe UI", 15, "bold")
    ).pack(pady=(10, 15))

    shell = tk.Frame(outer, bg="#111111", padx=19, pady=22)
    shell.pack(fill="x", padx=20)

    screen = tk.Frame(shell, bg="#18354e", height=260)
    screen.pack(fill="x")
    screen.pack_propagate(False)

    title = tk.Label(
        screen, text="Multimedia - B702",
        bg="#18354e", fg="white",
        font=("Segoe UI", 13, "bold")
    )
    title.pack(pady=14)

    menu_frame = tk.Frame(screen, bg="#18354e")
    menu_frame.pack(fill="both", expand=True, padx=10)

    status = tk.Label(
        outer, text="Mode original : donnees du registre",
        bg="#252525", fg="#dddddd",
        font=("Segoe UI", 10),
        wraplength=330, justify="center"
    )
    status.pack(pady=15)

    def current_model():
        return build_model(registry, mode.get())

    def draw():
        for widget in menu_frame.winfo_children():
            widget.destroy()

        model = current_model()
        labels = model["display_labels"]
        selected[0] %= len(labels)

        for index, label in enumerate(labels):
            active = index == selected[0]
            tk.Label(
                menu_frame,
                text=("> " if active else "  ") + label,
                anchor="w",
                bg="#3474a4" if active else "#18354e",
                fg="white",
                font=("Consolas", 10),
                padx=4, pady=9
            ).pack(fill="x")

        status.config(
            text=(
                "Simulation virtuelle - aucun lancement reel"
                if mode.get()
                else "Registre original B702 - aucune execution"
            )
        )

    def move(delta):
        selected[0] += delta
        draw()

    def activate():
        item = current_model()["children"][selected[0]]
        status.config(
            text=(
                f"Selection de 0x{item:04X}. "
                "Action non executee : liaison menu -> application "
                "non encore validee."
            )
        )

    def change_mode():
        selected[0] = 0
        draw()

    tk.Checkbutton(
        outer,
        text="Simuler ajout Audio Player 0x8928",
        variable=mode,
        command=change_mode,
        bg="#252525", fg="white",
        selectcolor="#303030",
        activebackground="#252525",
        activeforeground="white"
    ).pack(pady=10)

    controls = tk.Frame(outer, bg="#252525")
    controls.pack(pady=8)

    tk.Button(
        controls, text="HAUT",
        width=10, command=lambda: move(-1)
    ).grid(row=0, column=1, padx=5, pady=3)

    tk.Button(
        controls, text="GAUCHE",
        width=10, command=change_mode
    ).grid(row=1, column=0, padx=5, pady=3)

    tk.Button(
        controls, text="OK",
        width=10, command=activate
    ).grid(row=1, column=1, padx=5, pady=3)

    tk.Button(
        controls, text="BAS",
        width=10, command=lambda: move(1)
    ).grid(row=2, column=1, padx=5, pady=3)

    root.bind("<Up>", lambda event: move(-1))
    root.bind("<Down>", lambda event: move(1))
    root.bind("<Return>", lambda event: activate())
    root.bind("<Escape>", lambda event: root.destroy())

    tk.Label(
        outer,
        text=(
            "Interface indicative. Libelles, graphismes "
            "et regles de filtrage non emules."
        ),
        bg="#252525", fg="#aaaaaa",
        wraplength=335, justify="center"
    ).pack(pady=10)

    draw()
    root.mainloop()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--json", action="store_true",
        help="Print original and virtual models as JSON"
    )
    parser.add_argument(
        "--firmware", type=Path, default=FIRMWARE
    )
    args = parser.parse_args()

    registry = load_registry(args.firmware)

    if args.json:
        print(json.dumps({
            "registry": registry,
            "original": build_model(registry),
            "virtual": build_model(registry, True),
        }, indent=2))
    else:
        launch_gui(registry)


if __name__ == "__main__":
    main()
