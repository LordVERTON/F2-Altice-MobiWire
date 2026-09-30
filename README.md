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

See:

`research/f2/work/repro/S12_2_codex_repo_audit.md`

The current ALICE work has demonstrated an offline byte-perfect
ALICE_2 reconstruction using the existing codebook.
