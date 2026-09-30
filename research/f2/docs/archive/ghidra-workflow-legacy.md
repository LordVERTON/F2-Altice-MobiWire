# Préparation Ghidra — F2

Lecture seule. Aucun fichier n'est destiné à être flashé.

## Sources
- Altice dump: .\mobiwire_dump_2.bin
- QMobile ROM interne: Qmobile_F2_MT6261_V07_10042017_MIRA/Firmware/ROM

## Recommandation Ghidra
1. Créer un projet non partagé.
2. Importer d'abord `qmobile_audio_superregion_0x000C0000_0x000E534C.bin`.
3. Format: Raw Binary.
4. Architecture à essayer: ARM little-endian, 32-bit. Sur MT6261, beaucoup de code applicatif est ARM/Thumb; laisser Ghidra analyser puis vérifier les désassemblages plausibles.
5. Base address de cette super-région: `0x000C0000` si l'on veut conserver les offsets relatifs au fichier ROM QMobile.
6. Chercher les chaînes `audio/mp3`, `FMradio`, `AT+EMAUDIO`, puis afficher leurs XREFs.
7. Importer les fenêtres Altice séparément pour comparaison; ne pas supposer que les mêmes adresses ont les mêmes fonctions.

## Point clé
Les chaînes MIME autour de 0x000D5Axx prouvent surtout la gestion de types de fichiers. Les XREFs vers ces chaînes permettront de distinguer la table MIME de l'application AudioPlayer elle-même.
