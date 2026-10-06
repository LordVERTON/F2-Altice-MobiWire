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

Current state (5 October 2026):

- S13.4H builds the dual Image-ID logical candidate D (eight bytes);
- S13.4I passes 1,728 native-instruction emulation cases for registration-state idempotence;
- S13.4J reproduces canonical ZIMAGE compression byte-for-byte and exactly decodes D;
- the physical candidate changes 384,255 bytes across 96 sectors, so the historical one-sector writer does not apply;
- next: S13.4K offline assessment of a smaller physical patch via the ALICE resolver;
- current handset state and functional Audio Player activation remain unverified.

Current documentation:

- `research/f2/REPRISE.md`
- `research/f2/docs/reverse-engineering/s13-4h-j-dual-row-registration-repack-2026-10-05.md`
- `research/f2/docs/roadmap.md`

No handset flashing is authorized for candidate D. Generated images and sector
comparisons use a canonical baseline, not verified current handset bytes.
