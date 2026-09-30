# MobiWire NIKITI / Altice F2 — reverse engineering

Notes and reproducible analysis for the MT6261 Altice F2 firmware. The upstream MTKClient code remains at the repository root; this subproject contains F2-specific scripts, documentation, and local research data.

## Current findings

- Device: MobiWire NIKITI / Altice F2; MT6261 confirmed from BROM; board family `SAGETEL61M_11C_HW`.
- Installed build: `ALTICE_F2_DS_V02.1_181023_MP`.
- The handset's Multimedia list contains Image Viewer and FM Radio.
- Static ALICE analysis found the menu framework's descriptor and dynamic child-buffer path, but not the numeric Multimedia parent/child IDs.
- Audio backend infrastructure is present; a complete Audio Player MMI application or menu entry is not proven.
- On 2026-09-28, the charging-only observation showed `0E8D:0003` with WinUSB, then `0E8D:0002` with USBSTOR. With **COM port** selected while the main firmware/menu was running, `0003` was later rebound to the signed MediaTek serial driver and exposed as COM3. The passive listener received 0 bytes in 225.223 s; an active safe AT subset responded (`AT` → `OK`, `AT+GMR`/`AT+CGMR` identify the Altice build), while `AT+CLAC` returned `ERROR`. No RAM/debug read primitive has been identified. See the runtime reports under `../../f2_runtime/reports/`.

## MP3 fast path

The immediate objective is to play a file from SD with the shortest viable route. The authoritative [MP3 roadmap](ROADMAP_MP3.md), [current status](STATUS.md), and [evidence register](EVIDENCE.md) prioritize proving the decoder, then resolving `.mp3` file association and AudioPlayer frontend before returning to menu registration. The COM test subsequently identified an AT-compatible command subset but no RAM/debug read primitive; details are in `../../f2_runtime/reports/fast_runtime_protocol_test.txt`.

See the [project status](STATUS.md), the [MP3 roadmap](ROADMAP_MP3.md), the [broader Audio/Video roadmap](docs/roadmap.md), [hardware and USB evidence](docs/hardware-usb.md), and the [reverse-engineering notes](docs/reverse-engineering/).

## Layout

- `docs/`: current documentation, evidence notes, and screenshots.
- `scripts/acquisition/`: read-oriented device identification, dump, and extraction utilities.
- `scripts/analysis/`: static analysis and report generation.
- `scripts/ghidra/`: headless Ghidra scripts and helpers.
- `runtime/`: compatibility launchers and preserved historical traces; current tools/output are in repository-root `f2_runtime/`.
- `tools/unalice/`: vendored ALICE unpacker and its license.
- `data/`: local firmware packages, dumps, and references; excluded from Git.
- `work/`: extracted firmware, Ghidra projects, and raw reports; excluded from Git.

## Start the transient USB watcher

From the repository root, run this before connecting the powered-off phone:

```powershell
./f2_runtime_test.ps1 -Mode watch -PollMs 20 -DurationSec 180
```

The watcher sends no device data and records new events under repository-root `f2_runtime/`. Use `-Menu` for the optional numbered menu. Use `-Mode passive` for a separate trial opening newly enumerated MediaTek serial ports without transmitting. AT probes require an AT-compatible prior report, exact VID/PID and matching PnP interface evidence. See the [current procedure](../../f2_runtime/README.md).

## Local prerequisites and input files

The analysis scripts expect local firmware files under `research/f2/data/` and generated files under `research/f2/work/`. They are intentionally absent from a public GitHub checkout. See [local setup](docs/local-setup.md).

## Publication boundary

This folder is prepared for a public source-and-notes release, but local dumps, service firmware, archives, extracted ALICE binaries, Ghidra databases, and runtime captures are ignored. Do not add copyrighted firmware or device-specific dumps to a public commit. The root project remains governed by its upstream MTKClient license; vendored tools retain their own notices.
