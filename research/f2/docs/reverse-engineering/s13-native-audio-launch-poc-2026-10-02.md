# S13 â€” native Audio Player launch POC â€” 2026-10-02

## Current status

- S13.1: CLOSED
- S13.2A: PASS
- S13.2B: PASS
- S13.2C: PASS
- S13.2C.1: PASS
- S13.3A: PASS
- real firmware-sector write: NOT YET PERFORMED

## Native Audio chain

```text
0x8928
 -> F0316D74/F0316D75
 -> 0x1033D841
 -> 0x1033D840 registration stub
 -> 0x1033E815 Thumb Audio init entry
 -> 0x1033F83C Audio Player init
```

## Logical POC hook

```text
runtime literal 0x10355888
U offset        0x106C88
old             F0301C8D
new             1033E815
```

Canonical ALICE U SHA256:

`7246242b67afae0d13104452bc3257827cb778119b54e7a26fb7fb55993697ea`

Patched U SHA256:

`b12f67211e1a55263af6a75e65b7caa471c15df381ae39757f179dda7a84332d`

## Physical repack

Patched compressed ALICE:

- size `0x113E2C`
- SHA256 `9ed53778084cb1dd05609d47688e6c965f8c0f0874f6d02ac2cc64b2062f35eb`

4 MiB candidate SHA256:

`9099c7bbbbd88c1dcc718fdb12de83af9852eb8f7d8f3f9aa3daba1420c28216`

Physical footprint:

```text
sector          0x249000..0x249FFF
changed range   0x249AEF..0x249B13
changed bytes   37
```

Sector hashes:

```text
BEFORE dc8cc6b5be54d1554d71d60539f10a8077a375a3d7ddf92efe6149610ecffb1b
AFTER  29a21401b84442554dc051edd16ec561bbd842e01e048344e30ca547f78bb7f9
```

NOR transitions:

- 0->1: 68
- 1->0: 66
- erase required

## S13.2C hardware D6 gate

Two fresh D6 reads matched BEFORE exactly.

Fresh rollback was saved and revalidated locally.

No D3, D5, erase, or write occurred.

The later Windows `0xC0000005` exit is classified as a native USB teardown
anomaly after successful PASS/artifact creation.

## S13.3A proven writer reference

Reference:

`research/f2/scripts/hardware/reference/s12_10b7_sacrificial_gate_v4_reference.py`

SHA256:

`255a00f49b99c72871cd3a9ca9e66f4d5284590d9844ff58c3c7c5796e9616eb`

Commit:

`5c7f83bbf01fa425a1a768dd5c49dbdc14577414`

Confirmed implementation:

- native D6 one-sector read
- D3 begin/end/GFH `0x0108`
- D5 Sequential Erase
- one exact 4 KiB frame
- additive checksum16
- unchanged-data recovery
- ProcessInfo
- deliberate exit before final checksum verifier
- explicit execute + confirmation lock
- no generic `writeflash()/0x62`

S13.3A did not access the phone and did not execute the harness.

## Next checkpoint â€” S13.3B

Build a dedicated firmware harness derived from the reference.

It must hardcode:

```text
target    0x249000..0x249FFF
BEFORE    dc8cc6b5be54d1554d71d60539f10a8077a375a3d7ddf92efe6149610ecffb1b
AFTER     29a21401b84442554dc051edd16ec561bbd842e01e048344e30ca547f78bb7f9
GFH       0x00000108
length    0x1000
```

Safety design:

1. validate payload locally before any device connection
2. no target-address CLI parameter
3. no arbitrary mutation payload parameter
4. mutation locked behind a new firmware-specific token
5. fresh D6 exact-BEFORE in same DA session
6. save fresh rollback before D3
7. D3 + proven D5 path only
8. close after ProcessInfo
9. verify AFTER using a separate DA session
10. never boot on verify mismatch

No firmware write should occur during S13.3B local construction/audit.

## Permanent rules

- never generic mtkclient `writeflash()/0x62`
- never whole 4 MiB / SAV flash
- never write `>=0x2C0000`
- this POC may target only `0x249000`
- preserve rollback until full functional validation