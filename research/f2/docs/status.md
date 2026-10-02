# Ã‰tat courant

Le point de reprise unique est [REPRISE.md](../REPRISE.md).

## Checkpoint actuel â€” 2026-10-02

### Hardware write path

S12.10B7 est terminÃ© sur le tÃ©lÃ©phone rÃ©el :

- D6 READ : HARDWARE PASS
- D5 WRITE : HARDWARE PASS
- Sequential Erase : HARDWARE PASS
- recovery / ProcessInfo : HARDWARE PASS
- AA -> 55 : HARDWARE PASS
- restore -> FF : HARDWARE PASS
- garde hors cible : byte-identical

Le generic mtkclient `writeflash()/0x62` reste interdit.

### S13.1 â€” launcher / dispatcher : CLOSED

ChaÃ®ne retenue :

```text
0x8928
 -> F0316D74/F0316D75
 -> 0x1033D841
 -> 0x1033D840 registration
 -> 0x1033E815 Audio init entry
 -> 0x1033F83C Audio Player init
```

Le cluster `10366100/22/36` est une logique de mapping/configuration d'IDs,
pas un launcher.

### S13.2A â€” hook offline : PASS

```text
runtime 0x10355888
U+0x106C88
F0301C8D -> 1033E815
```

Candidat U SHA256 :

`b12f67211e1a55263af6a75e65b7caa471c15df381ae39757f179dda7a84332d`

### S13.2B â€” repack physique : PASS

- ALICE patchÃ©e SHA256:
  `9ed53778084cb1dd05609d47688e6c965f8c0f0874f6d02ac2cc64b2062f35eb`
- candidat 4 MiB SHA256:
  `9099c7bbbbd88c1dcc718fdb12de83af9852eb8f7d8f3f9aa3daba1420c28216`
- 37 octets physiques modifiÃ©s
- plage unique `0x249AEF..0x249B13`
- secteur unique `0x249000..0x249FFF`
- aucun changement `>= 0x2C0000`

Secteur :

```text
BEFORE dc8cc6b5be54d1554d71d60539f10a8077a375a3d7ddf92efe6149610ecffb1b
AFTER  29a21401b84442554dc051edd16ec561bbd842e01e048344e30ca547f78bb7f9
```

### S13.2C / C.1 â€” hardware D6 pre-write gate : PASS

Deux D6 frais de `0x249000/0x1000` donnent exactement le BEFORE attendu.
Rollback frais sauvegardÃ© et revalidÃ©.

Aucun D3, D5, erase ou firmware write.

Le `0xC0000005` est classÃ© comme anomalie de teardown USB post-PASS aprÃ¨s
validation locale des artefacts.

### S13.3A â€” proven writer reference : PASS

RÃ©fÃ©rence commitÃ©e :

`research/f2/scripts/hardware/reference/s12_10b7_sacrificial_gate_v4_reference.py`

SHA256 :

`255a00f49b99c72871cd3a9ca9e66f4d5284590d9844ff58c3c7c5796e9616eb`

Commit :

`5c7f83bbf01fa425a1a768dd5c49dbdc14577414`

Audit local :

- D6 native 4 KiB : confirmÃ©
- D3 begin/end/GFH `0x0108` : confirmÃ©
- D5 Sequential Erase : confirmÃ©
- frame D5 4 KiB + checksum16 : confirmÃ©
- recovery + ProcessInfo : confirmÃ©
- stop avant final checksum verifier : confirmÃ©
- harness exÃ©cutÃ© pendant S13.3A : non
- tÃ©lÃ©phone accÃ©dÃ© : non
- flash modifiÃ©e : non

## Ã‰tape active

**S13.3B** : construire et auditer localement un harness firmware strictement
limitÃ© au secteur `0x249000`.

Pas de write firmware tant que S13.3B n'a pas PASS.

DÃ©tail :
[S13 native Audio Player launch POC](reverse-engineering/s13-native-audio-launch-poc-2026-10-02.md).