#!/usr/bin/env python3
"""Offline, read-only follow-up for the Altice aud_player_media callback graph."""
import json
import struct
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from _paths import ALTICE_ALICE, ALTICE_PACKAGE, DUMP_MAIN, GHIDRA_REPORTS, REPO_ROOT

ROOT = REPO_ROOT
OUT = GHIDRA_REPORTS
DETAILS = OUT / "altice_details.jsonl"
BASE = 0x101812C4
RAW_FILES = {
    "dump": DUMP_MAIN,
    "ROM": ALTICE_PACKAGE / "DL188_GX1882_NIKITI_PCB01_gsm_MT6261_S00" / "ROM",
    "VIVA": ALTICE_ALICE / "altice_VIVA.bin",
    "ALICE_compressed": ALTICE_ALICE / "altice_ALICE_2.bin",
    "ALICE_decompressed": ALTICE_ALICE / "alice-py.bin",
    "service_image": ALTICE_PACKAGE / "DL188_GX1882_NIKITI_PCB01_gsm_MT6261_S00.ALTICE_F2_DS_V02_1_181023_MP.bin",
}
SLOTS = [
    (0x00, 0x1028D230, "init/validation; semantics unresolved"),
    (0x04, 0x1029D3BC, "data copy/finalization"),
    (0x08, 0x1028D394, "object/resource operation; uncertain"),
    (0x0C, 0x1028D4C0, "branch on 16-bit state to 0x10290E28/0x10290EF8"),
    (0x10, 0x1028D378, "consumer not confirmed"),
    (0x14, 0x1028D41C, "shared tail reaches 0x10290F7C; invocation of this slot unconfirmed"),
    (0x18, 0x1028D43A, "event/state update via 0x10290F7C"),
    (0x1C, 0x1028D114, "localized list/UI callback"),
    (0x20, 0x1028D0D4, "cleanup"),
]
MMI = {0x10254204: "short string/resource getter", 0x102500F0: "text/resource resolver",
       0x1023A6E0: "message/resource wrapper", 0x102340F0: "display wrapper",
       0x102429A8: "GUI/display state builder"}
MEDIA = {0x102362A4, 0x10214940, 0x10235B28, 0x102528AC, 0x102529E6,
         0x1028D114, 0x1028D230, 0x1028D378, 0x1028D394, 0x1028D41C,
         0x1028D43A, 0x1028D4C0, 0x1028D0D4, 0x1029D3BC, 0x10290F7C}


def load_functions():
    return {int(f["entry"], 16): f for f in
            (json.loads(line) for line in DETAILS.open(encoding="utf-8") if line.strip())}


def call_targets(f):
    for ins in f.get("instructions", []):
        if ins.get("call"):
            for target in ins.get("targets", []):
                try:
                    yield int(target, 16), ins["address"], ins["text"]
                except (ValueError, TypeError):
                    pass


def direct_callers(funcs):
    callers = {}
    for entry, f in funcs.items():
        for target, site, text in call_targets(f):
            callers.setdefault(target, []).append((entry, site, text))
    return callers


def raw_scan():
    hits = []
    for label, path in RAW_FILES.items():
        if not path.exists():
            continue
        data = path.read_bytes()
        for value in (0x10290F7C, 0x10290F7D):
            needle = struct.pack("<I", value)
            pos = 0
            while (pos := data.find(needle, pos)) >= 0:
                lo, hi = max(0, pos - 0x100), min(len(data), pos + 0x104)
                hits.append({"file": label, "path": str(path), "offset": pos,
                             "runtime": hex(BASE + pos) if label == "ALICE_decompressed" else None,
                             "value": hex(value), "context": data[lo:hi].hex(" ")})
                pos += 1
    return hits


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    funcs = load_functions()
    callers = direct_callers(funcs)
    raw_hits = raw_scan()
    # Callback targets were explicitly created/disassembled by InspectMediaApiTargets.java;
    # the first bulk export predates those forced function definitions.
    known_direct_callers_90f7c = [
        {"caller": "0x1028D43A", "site": "0x1028D43C", "instruction": "bl 0x10290F7C",
         "status": "confirmed BL; shared tail also reachable from callback entry 0x1028D41C (slot +0x14); slot +0x18 target enters at 0x1028D43A"},
    ]
    # Direct primitive intersection is deliberately strict; indirect vtable calls are documented separately.
    ranked = []
    for entry, f in funcs.items():
        targets = {t for t, _, _ in call_targets(f)}
        media_hits = sorted(targets & MEDIA)
        mmi_hits = sorted(targets & set(MMI))
        if media_hits or mmi_hits:
            ranked.append({"entry": hex(entry), "bytes": f.get("bytes"),
                           "direct_media_targets": [hex(x) for x in media_hits],
                           "direct_mmi_targets": {hex(x): MMI[x] for x in mmi_hits},
                           "joint_score": len(media_hits) + 2 * len(mmi_hits)})
    ranked.sort(key=lambda x: (x["joint_score"], len(x["direct_media_targets"]), int(x["entry"], 16)), reverse=True)

    slot_lines = [f"+0x{off:02X} -> 0x{target:08X}: {role}" for off, target, role in SLOTS]
    (OUT / "media_parent_callbacks.txt").write_text(
        "ALTICE F2  CALLBACK PARENT / ENREGISTREMENT\n\n"
        "0x10290F7C : Thumb, 58 octets / 23 instructions; prologue/epilogue coherents dans l'export Ghidra.\n"
        "BL direct : 0x1028D43A a 0x1028D43C. Cette queue de code est egalement atteignable depuis l'entree callback 0x1028D41C (slot +0x14); l'appel de +0x14 par cette instance reste non demontre. Le slot +0x18 entre directement a 0x1028D43A et est invoque par 0x10235B28.\n"
        "Conclusion importante : 0x10290F7C est un helper appele par les callbacks; il n'enregistre pas lui-meme l'interface.\n\n"
        "Pseudo-code resume : creer/obtenir un objet via 0x10293940; si non nul, ecrire un champ 16 bits via 0x10293994, resoudre un caractere via 0x1024B758, ecrire deux autres champs via 0x102939AC et 0x102939A0, finaliser via 0x10293968; renvoyer le pointeur d'objet. Pas de callback transmis ni de pointeur de fonction stocke dans cette fonction. Les callees immediats de 0x10290F7C sont 0x10293940, 0x10293994, 0x1024B758, 0x102939AC, 0x102939A0 et 0x10293968.\n"
        "Enregistrement statique des callbacks : constructeur 0x102362A4 ecrit les cibles dans l'objet heap renvoye; caller 0x101B31FC conserve le pointeur dans le champ fourni par 0x10214940, a (*DAT_10214AA0)+0x14. Le dispatcher 0x10235B28 recoit ensuite ce pointeur.\n\n"
        "Scan little-endian de 0x10290F7C / 0x10290F7D :\n" +
        ("\n".join(f"{h['file']} +{h['offset']:#x} runtime={h['runtime']} value={h['value']} context={h['context']}" for h in raw_hits)
         if raw_hits else "Aucune occurrence brute dans le dump, ROM, VIVA, ALICE compressee/decompressee ou image de service scannes. Les appels BL sont relatifs et ne sont pas des pointeurs absolus.") +
        "\n\nCall path confirme : 0x10214940 -> 0x101B31FC -> 0x102362A4; puis instance -> 0x10235B28 -> callbacks indirects. Le caller externe le plus haut de 0x10214940 n'est pas etabli par les xrefs statiques.\n\nSlots :\n" + "\n".join(slot_lines) + "\n",
        encoding="utf-8")

    (OUT / "media_event_enum.txt").write_text(
        "EVENEMENTS OBSERVES  SIGNIFICATION NON ATTRIBUEE\n\n"
        "Dans 0x10235B28, appels via slot +0x18 (cible 0x1028D43A) transmettent les valeurs 0, 5, 6, 2, 2 et 3 selon les branches/flags de la structure evenement param_2. La constante 0x800 est assignee a une variable locale dans une branche speciale; son passage a un callee n'est pas demontre et elle n'est pas classee ici comme evenement.\n"
        "Dans 0x102528AC, le slot +0x1C (0x1028D114) est appele avec IDs 5 puis 6 et une globale de donnees.\n\n"
        "| valeur | cible appelee | condition connue | sens |\n|---:|---|---|---|\n"
        "| 0 | slot +0x18 -> 0x1028D43A -> 0x10290F7C | branche conditionnelle de 0x10235B28 | inconnu |\n"
        "| 2 | slot +0x18 | indicateur param_2 bit0 et champ param_2[1] non nul, ou branche alternative | inconnu |\n"
        "| 3 | slot +0x18 | indicateur param_2 bit2 et champ param_2[2] non nul | inconnu |\n"
        "| 5 | slot +0x18; aussi slot +0x1C dans le chemin succes | flags/chemin successif | inconnu |\n"
        "| 6 | slot +0x18; aussi slot +0x1C dans le chemin succes | flags/chemin successif | inconnu |\n\n"
        "Les valeurs 5/6 ne constituent pas encore un enum semantique : les arguments de deux slots distincts ont des roles distincts. Aucun nom playback-complete/error/open-complete n'est attribue sans preuve.\n",
        encoding="utf-8")

    (OUT / "media_context_0x84.txt").write_text(
        "OBJET ALLOUE PAR 0x102362A4\n\nAllocation heap : 0x84 octets. Les premiers 0x28 octets contiennent 9 pointeurs Thumb statiques plus un retour dynamique a +0x24. Le constructeur initialise le bloc puis renseigne ces callbacks. Les champs +0x28..+0x83 n'ont pas ete semantiquement reconstruits; l'initialisation a zero est probable mais l'externe 0x0FF4B02C n'est pas nomme avec certitude.\n\n"
        "| offset | contenu/usage observe |\n|---:|---|\n" +
        "\n".join(f"| +0x{off:02X} | 0x{target:08X}; {role} |" for off, target, role in SLOTS) +
        "\n| +0x24 | resultat dynamique du thunk 0x1022FA68 |\n| +0x28..+0x83 | inconnus; aucun champ playlist/filename/volume/duree n'est demontre |\n\n"
        "Le pointeur d'interface est conserve dans l'objet/contexte pointe par DAT_10214AA0 a +0x14. Ne pas confondre la taille 0x84 de l'interface allouee avec une preuve que ses champs sont une structure complete d'application player.\n",
        encoding="utf-8")

    joint = [x for x in ranked if x["direct_media_targets"] and len(x["direct_mmi_targets"]) >= 2]
    bridge_lines = ["MMI / MEDIA BRIDGE CANDIDATES  scan direct des appels de l'export Ghidra",
                    "Primitives MMI confirmees comme wrappers generiques : " + ", ".join(f"0x{k:08X} ({v})" for k, v in MMI.items()),
                    "Media path functions/callbacks : " + ", ".join(f"0x{x:08X}" for x in sorted(MEDIA)),
                    "Le score ci-dessous compte les cibles directes; les appels BLX de vtable sont suivis separement par dataflow.", ""]
    bridge_lines.append(f"Fonctions reunissant directement >=1 cible media ET >=2 primitives MMI : {len(joint)}")
    for item in joint[:100]:
        bridge_lines.append(f"{item['entry']} bytes={item['bytes']} joint={item['joint_score']} media={item['direct_media_targets']} mmi={item['direct_mmi_targets']}")
    bridge_lines += ["", "Le pont confirme est indirect : les callbacks stockes dans l'interface atteignent 0x1028D114, qui appelle 0x1023A6E0; la fonction wrapper appelle ensuite les primitives MMI. Les appels BLX de vtable echappent au simple scanner direct et sont couverts par les chemins de donnees documentes. Aucun candidat L4 avec file browser + key handler + media control n'est demontre."]
    (OUT / "mmi_media_bridge_candidates.txt").write_text("\n".join(bridge_lines) + "\n", encoding="utf-8")

    (OUT / "fm_positive_control.txt").write_text(
        "FM RADIO  CONTROLE POSITIF NON RESOLU\n\n"
        "Le telephone affiche FM Radio, mais l'analyse binaire existante n'a identifie ni init, ni launch, ni handler de touches, ni table d'inscription utilisateur. La table factory/hardware FMradio exclue precedemment ne constitue pas l'application MMI. Aucun cluster attribue n'est donc fourni ici; cela empeche encore une comparaison structurelle Audio/FM fiable.\n",
        encoding="utf-8")
    (OUT / "imageviewer_positive_control.txt").write_text(
        "IMAGE VIEWER  CONTROLE POSITIF NON RESOLU\n\n"
        "Image Viewer est visible sur le telephone, mais son init, launch, handler de navigation et table menu n'ont pas d'adresse binaire demontree dans les rapports existants. Les helpers GDI generiques ne suffisent pas a attribuer une application. Aucun cluster positif n'est donc revendique.\n",
        encoding="utf-8")
    (OUT / "multimedia_parent_candidates.txt").write_text(
        "PARENTS MULTIMEDIA / EXTRAS  ETAT DES CANDIDATS\n\n"
        "Aucune table/structure parent commune a Image Viewer et FM Radio n'a ete demontree. Le rapport anterieur `altice_menu_reconstruction.txt` indique explicitement que leurs handlers et IDs ne sont pas identifies. Il n'existe donc pas encore de voisinage de table permettant de tester Audio/Video/Recorder. Le candidat audio 0x10214940 est un contexte audio/Bluetooth et n'est pas un parent de menu confirme.\n",
        encoding="utf-8")

    result = {"firmware": "ALTICE_F2_DS_V02.1_181023_MP", "target": "0x10290F7C",
              "raw_pointer_hits": raw_hits,
              "direct_callers": known_direct_callers_90f7c,
              "callback_slots": [{"offset": hex(off), "target": hex(t), "role": role} for off, t, role in SLOTS],
              "event_values_observed": [0, 2, 3, 5, 6],
              "mmi_primitives": {hex(k): v for k, v in MMI.items()},
              "ranked_direct_call_candidates": ranked[:100],
              "conclusion": {"utility_0x10290f7c_is_registration_api": False,
                             "slot_plus_18_wrapper_invokes_it": True,
                             "audio_mmi_frontend": "not demonstrated",
                             "menu_registration": "not demonstrated",
                             "fm_and_image_positive_controls": "handlers remain unidentified"}}
    (OUT / "media_parent_analysis.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
    print("Reports written:", OUT)
    print("0x10290F7C BL site: 0x1028D43C; shared callback tail entered via 0x1028D41C and slot +0x18")
    print("Raw pointer hits:", len(raw_hits), "ranked functions:", len(ranked))


if __name__ == "__main__":
    main()
