# F2 Altice / MobiWire MT6261 Research

Reverse-engineering research project for the Altice / MobiWire F2 feature phone.

Main objectives:

- understand the MediaTek MT6261 firmware layout;
- document VIVA / ALICE_2;
- reproduce ALICE decompression and repacking offline;
- investigate the existing MP3/audio backend;
- implement a minimal audio-player proof of concept;
- eventually expose the missing audio player through the phone UI.

## Important

Firmware dumps, commercial firmware packages, device-specific flash images,
NVRAM, IMEI/calibration data and other proprietary binary artifacts are not
included in this repository.

The repository contains research notes, scripts, source tools and reproducible
analysis results only.

## Current milestone

Active implementation branch:

`s12-alice-extension`

Current state:

- byte-perfect ALICE_2 repacking is proven;
- controlled `+0x1000` ALICE extension round-trips exactly;
- ZIMAGE/BOOT_ZIMAGE LZMA preset behavior is characterized;
- the original LZMA preset window must remain unchanged;
- the runtime/VIVA patch-role matrix is validated;
- S12.6 is building and auditing the first offline candidate.

Current documentation:

- `research/f2/REPRISE.md`
- `research/f2/docs/reverse-engineering/s12-alice-extension-lzma-offline-2026-10-01.md`
- `research/f2/work/repro/S12_2_codex_repo_audit.md`

No handset flashing is approved yet.

