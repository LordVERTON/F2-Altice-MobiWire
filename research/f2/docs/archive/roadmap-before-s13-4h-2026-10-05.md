# Feuille de route

Le point de reprise unique est [REPRISE.md](../REPRISE.md).

## Acquis

- [x] dumps physiques 4 MiB et baselines live A/B
- [x] extraction / repack ALICE byte-perfect
- [x] backend MP3 / DAF / aud_player_media
- [x] frontend Audio Player natif
- [x] registration `0x8928 -> 0x1033D841`
- [x] Image Viewer comme contrÃ´le positif
- [x] resolver / dispatcher fermÃ©
- [x] S12.10B7 D6 / D5 / erase / recovery / restore hardware PASS
- [x] S13.1 launcher / dispatcher analysis closed
- [x] S13.2A hook `10355888: F0301C8D -> 1033E815`
- [x] S13.2B repack exact
- [x] S13.2B physical diff = 37 bytes / 1 sector
- [x] S13.2C fresh D6 target BEFORE
- [x] S13.2C fresh rollback sector saved
- [x] S13.2C.1 artifact validation
- [x] S13.3A proven S12.10B7 v4 harness imported/audited

## Candidat courant

```text
logical hook
0x10355888
F0301C8D -> 1033E815

physical target
0x249000..0x249FFF

actual changed range
0x249AEF..0x249B13

changed bytes
37
```

Hashes :

```text
BEFORE dc8cc6b5be54d1554d71d60539f10a8077a375a3d7ddf92efe6149610ecffb1b
AFTER  29a21401b84442554dc051edd16ec561bbd842e01e048344e30ca547f78bb7f9
```

## S13.3A â€” PASS

Proven reference :

`research/f2/scripts/hardware/reference/s12_10b7_sacrificial_gate_v4_reference.py`

SHA256 :

`255a00f49b99c72871cd3a9ca9e66f4d5284590d9844ff58c3c7c5796e9616eb`

Confirmed primitives :

- `d6_read_4k_native`
- `d3_set_memblock`
- `d5_write_until_processinfo`
- Sequential Erase
- one exact 4 KiB frame
- additive checksum16
- recovery
- ProcessInfo
- deliberate stop before final image checksum verifier

## Ã‰tape active â€” S13.3B

Construire le one-sector firmware harness.

Local/dry-run audit requirements:

- [ ] target hardcoded `0x249000`
- [ ] length hardcoded `0x1000`
- [ ] GFH hardcoded `0x0108`
- [ ] BEFORE SHA hardcoded
- [ ] AFTER SHA hardcoded
- [ ] payload AFTER must be exact 4096 bytes
- [ ] no target-address CLI option
- [ ] no arbitrary input payload path during mutation
- [ ] dedicated confirmation token for firmware target
- [ ] mutation requires both `--execute` and exact token
- [ ] fresh D6 before mutation in same session
- [ ] fresh rollback written before D3
- [ ] D3 then proven D5 flow
- [ ] stop after ProcessInfo
- [ ] separate verify-after phase / new DA session
- [ ] no generic `writeflash()/0x62`

No phone write during S13.3B.

## S13.3C â€” local safety audit

- [ ] AST/static audit of constants and call graph
- [ ] prove no code path can write another address
- [ ] prove precondition failure occurs before D3
- [ ] prove payload hash mismatch occurs before device connection
- [ ] prove mutation lock prevents device connection
- [ ] verify source hash of inherited reference

## S13.3 hardware execution

Only after S13.3B/C PASS:

```text
fresh D6 BEFORE in same DA session
 -> save fresh rollback
 -> D3 target 0x249000..0x249FFF / GFH 0x0108
 -> D5 Sequential Erase/write/recovery/ProcessInfo
 -> close
 -> new DA session
 -> D6 exact AFTER
```

No boot unless AFTER is exact.

## Functional POC

After exact AFTER:

- [ ] boot
- [ ] activate former Image Viewer path
- [ ] observe native Audio Player init
- [ ] test MP3 selection/playback
- [ ] Play / Pause / Resume / Stop

## Permanent rules

- never generic `writeflash()/0x62`
- never whole 4 MiB flash
- never SAV full write
- never write `>=0x2C0000`
- for this POC, only sector `0x249000`
- keep rollback until full validation