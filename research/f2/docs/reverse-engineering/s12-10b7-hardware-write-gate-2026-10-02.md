# S12.10B7 — MT6261 hardware write / erase / recovery gate

Date: 2026-10-02

Firmware:
`ALTICE_F2_DS_V02.1_181023_MP`

Platform:
`MT6261`

NOR:
4 MiB serial NOR, device code `00EF/0070/0016`.

Status:

`S12.10B7 SACRIFICIAL GATE: PASS`

## 1. Existing physical baselines

The project already has multiple independent physical dumps from the owned
phone.

Canonical historical dumps:

- `research/f2/data/dumps/mobiwire_dump_2.bin`
- `research/f2/data/dumps/mobiwire_dump_3.bin`
- size: `0x400000`
- dump2 == dump3 byte-for-byte
- SHA256:
  `2fc100e5704cf3d6fae0817a22ce222397702ffd7351a83763ae1bafd4416922`

Later live readbacks:

- two complete 4 MiB live readbacks A/B
- independent battery cycles
- byte-identical
- SHA256:
  `c571f3852f4a70d1845cc79abaa95007f8826ec858a1db1ad501c4a2a7b35ce6`

A new complete 4 MiB dump is therefore NOT a prerequisite for starting S13.

A new full dump remains optional as an additional snapshot of the current live
tail, but it is not required for patch construction.

## 2. Live-preserving candidate already established

S12.8E built a candidate that preserves the live tail.

Candidate SHA256:

`47b41c572d7d9f09ac5b9562dff5977e9ea99a16b9f8e126247992b493144fd4`

Properties already audited:

- modifications remain below `0x2C0000`
- zero candidate changes from `0x2C0000` upward
- live tail is preserved
- changed region set is derived from the physical firmware image
- ALICE/VIVA reconstruction checks pass

This remains an important architectural rule for all S13 candidates.

## 3. Sacrificial target

Physical mutation testing was deliberately restricted to:

`0x002A0000..0x002A0FFF`

Length:

`0x1000`

This sector lies in the known all-FF physical gap before `0x2C0000`.

Stable comparison guard:

`0x00280000..0x002BFFFF`

No data at or above `0x2C0000` participates in the stable equality gate.

Initial all-FF target SHA256:

`f47a8ec3e9aff2318d896942282ad4fe37d6391c82914f54a5da8a37de1300c6`

Stable 256 KiB guard SHA256:

`caac124c9e376fdf13f854555937eff52ae28f4872f71d3216c6b773693de3e4`

## 4. Hardware path used

Generic modern mtkclient `writeflash()` / command `0x62` was never used.

The tested legacy MT6261 path is:

D3 / SetMemBlock
→ D5 / WRITE with Sequential Erase
→ recovery
→ ProcessInfo
→ terminate session before final image checksum selector
→ power-cycle
→ D6 readback

GFH / IMAGE_TYPE used for the sacrificial block:

`0x0108 / VIVA`

Observed D3 state during successful mutations:

- unchanged blocks: `0`
- format flag: `0x5A`
- pre-erase byte: `0x5A`

D5 completed:

- data write
- recovery
- ProcessInfo

The final checksum verifier was deliberately not entered. Verification was
performed independently after a power-cycle using D6.

## 5. WRITE-A hardware result

Initial state:

`FF × 0x1000`

Written pattern:

`AA × 0x1000`

D6 readback SHA256:

`c622005493c4cb75f3e08eda4cc0bfe172e2c5eeca661ec4908c5490fc3d6994`

Result:

- target exact: PASS
- stable guard outside target unchanged: PASS

Conclusion:

`D5 WRITE: HARDWARE PASS`

## 6. WRITE-B / erase-path hardware result

Previous state:

`AA × 0x1000`

New pattern:

`55 × 0x1000`

D6 readback SHA256:

`0561079e4fe3390bc1d8bb706edb7d80243eeca7ddf876cefbaa8c1684db80c3`

Changing AA to 55 requires 0→1 transitions, so a NOR erase step must occur
before programming.

Result:

- target exact: PASS
- stable guard outside target unchanged: PASS

Conclusion:

`SEQUENTIAL ERASE PATH: HARDWARE PASS`

Important qualification:

The AA→55 experiment proves the hardware erase+program path. It does not, by
itself, distinguish the physical erase envelope from every larger possible
erase size because the neighboring sacrificial area is already FF.

The 4 KiB erase-unit conclusion remains strongly supported independently by the
Altice service-package descriptors:

- NOR size: `0x00400000`
- geometry field: `0x00001000`
- exact EF7016 records and geometry descriptors co-reside in the service files

Therefore 4 KiB remains the promoted planning unit for controlled sector writes.

## 7. Restore result

Restore target:

`FF × 0x1000`

There was one USB disconnect during the pre-read of an initial restore attempt.
The failure occurred before the guard check completed and therefore before D3
or D5 mutation.

The restore was retried after a full power-cycle.

Successful restore:

- pre-read complete
- guard verified
- D3 accepted
- D5 data/recovery/ProcessInfo complete

Final D6 readback:

`f47a8ec3e9aff2318d896942282ad4fe37d6391c82914f54a5da8a37de1300c6`

Stable guard:

byte-for-byte unchanged.

Final result:

`S12.10B7 SACRIFICIAL GATE: PASS`

## 8. Current hardware status

D6 READ:
`HARDWARE PASS`

D5 WRITE:
`HARDWARE PASS`

Sequential erase path:
`HARDWARE PASS`

Recovery:
`HARDWARE PASS`

Restore:
`HARDWARE PASS`

Sacrificial gate:
`PASS`

Generic 0x62:
`PROHIBITED / NEVER USED`

Whole-image flash:
`PROHIBITED`

Writes at or above 0x2C0000:
`PROHIBITED`

## 9. Audio Player status already established before S13

S13 must NOT reopen the question of whether an Audio Player frontend exists.

The native frontend / bootstrap / session / playlist / registration chain is
already established.

Audio Player registration:

`0x8928 → 0x1033D841`

Application chain:

`0x1033D840`
→ `0x1033E815`
→ `0x1033F83C`

Native playlist:

`@Playlists\audio_play_list.sal`

The File Manager / Audios path and bridge toward `aud_player_media` are also
already established.

Image Viewer provides the visible positive control in the same registration
system:

`0x8313 → F02F3F85`

`0x8321 → F02F3F85`

The remaining problem is therefore exposure / launcher activation of the
already-compiled Audio Player, not frontend reconstruction from scratch.

## 10. S13 strategy

Primary strategy:

reuse the native Audio Player already compiled in the firmware.

Target:

`0x8928 → 0x1033D841`

Goal:

find the smallest reproducible modification that exposes or launches the native
Audio Player.

A custom frontend remains fallback-only if the native application proves
unusable on hardware.

## 11. Firmware-write policy for S13

Before any S13 firmware mutation:

1. build the candidate reproducibly
2. diff it against the selected physical baseline
3. compute the exact changed 4 KiB sectors
4. reject any target sector whose address is `>= 0x2C0000`
5. immediately before mutation, D6-read every target sector from the phone
6. require exact equality with the expected original sector
7. save those freshly read original 4 KiB sectors as the rollback bundle
8. write only the required target sectors through the tested D3+D5 path
9. power-cycle
10. D6-read back every written sector and require exact equality with the candidate
11. retain the rollback bundle until boot and Audio Player testing are complete

A new full 4 MiB readback is optional, not a blocker.

The mandatory fresh read before firmware mutation is sector-specific.
