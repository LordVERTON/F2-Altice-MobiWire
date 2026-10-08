# F2 Virtual Menu Lab — V4 (photo-backed UI)

**Purpose**: document and simulate phone navigation grounded in photos IMG_0833, IMG_0834, IMG_0836–IMG_0843, while retaining the V2 registry inspector and previous V3 source in Git history. No photos are bundled: private images and surrounding environment are not automatically published to GitHub.

Observed screens:
- Home: 3x3 blue icon grid; Photo selection titles `Phonebook`, `Camera`; bottom `OK` / `Back`. Other icon labels/actions and the position of Multimedia on grid are indicative only.
- `Multimedia`: `1 Image viewer`, `2 FM radio` (IMG_0836, IMG_0840).
- `Image viewer`: `No files`, `Options` / `Back` (IMG_0837).
- Image Options: `1 Storage` (IMG_0838).
- File manager: `Phone`, `Memory card` (IMG_0839).
- FM without earphones: `Please plug in earphone` (IMG_0841).
- FM with earphones: 87.5–108 MHz, 98.7 MHz on photographed phone, transport icons (IMG_0842).
- FM Options: `Channel list`, `Manual input`, `Auto search` (IMG_0843).

ROM-backed:
- The unchanged V2 Registry reads *canonical ZIMAGE only*, checks SHA256 and enforces B702 `[0x8569, 0x87ED]`, B709 and packed-record boundary. The photo `FM radio` item is **not** assigned an unproven ROM ID.
- Audio player 0x8928 is a virtual third Multimedia row **only when explicitly selected**. No native callbacks run.

This is **not** CPU/peripheral emulation. No receiver, image decoding, SIM, file storage, phone connection, patch generation, flash writes, or external network access.

Run from Windows PowerShell in `C:\Users\verto\F2-Altice-MobiWire-Emulator` after install:

```powershell
$PY = 'C:\Users\verto\mtkclient\.venv\Scripts\python.exe'
$ROM = 'C:\Users\verto\F2-Altice-MobiWire\research\f2\work\extracted\altice_platform\zimage.bin'
& $PY -B .\research\f2\virtual_menu_lab\f2_phone_ui_v4.py --firmware $ROM
```

Keyboard: arrow keys navigate, Enter OK, Escape Back, F1 left softkey, 1/2/3 direct selection. On FM screen, left/right shifts a **simulated** frequency when mock earphones are enabled. Explorer V2 remains available by button.

The source images were photographed in perspective and do not supply an original pixel dump or font asset. Colors, dimensions and icon shapes are approximate reconstructions, not pixel-perfect reproductions.
