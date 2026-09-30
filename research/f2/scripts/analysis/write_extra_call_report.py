"""Build the final evidence report from the exported static analyses."""
from pathlib import Path
import hashlib
import difflib
import json
import struct
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from inspect_alice_details import ROOT,load
from analyze_alice_extra_calls import PAIRS,compare,calls,target,norm,summary
from match_alice_callees import fingerprint,Matcher
from _paths import QMOBILE_ALICE, ALTICE_ALICE

NOTES={
'103fe66a': '''VERDICT: faux appel supplémentaire, confiance élevée.
L'entrée correcte est 103fe67c (PUSH). Les 18 octets 103fe66a..103fe67b sont
la fin d'un pool de constantes de 103fe598, chargé par des LDR PC-relatifs.
103fe66a tombe même au milieu du mot f00f7280 à 103fe668.
Le faux BLX à 103fe66e chevauche deux constantes (f00f7284 et f011e0b4).
1080d7d8 n'est donc PAS une cible de fonction démontrée; taille/appels/XREFs
de cette prétendue cible: sans objet. Les 8 pseudo-instructions sont listées
ci-dessous pour expliquer exactement l'ancien écart 368-360 et 22-21.
Après correction: 360 instructions, 738 octets, 21 appels de chaque côté.
Toutes les instructions s'alignent avec les mêmes opérandes après relocation;
les destinations internes des branches sont vérifiées séparément.
Le corps contient des tables de callbacks, des structures, des états et une
boucle d'attente. Ce n'est pas une suite simple d'initialisations multimédia.
Il pourrait appartenir à un service multimédia bas niveau; aucune identification
AudioPlayer, Image Viewer, Camera, Video Player ou FM Radio n'est démontrée.
AudioPlayer plausible COMME APPEL RETIRÉ: NON. Aucun appel retiré ici.''',
'10415c14': '''VERDICT: insertion réelle d'un bloc de compteur, confiance élevée.
Appel: 10415cdc; encodage ALICE source 0a f2 19 fc; après normalisation
{NORMALIZED_EXTRA_HEX}; cible du BL: 10394dcc, et non 10620512 (ancien mauvais décodage).
Six instructions supplémentaires, 14 octets:
  10415cd2 LDRH r0,[r4,#0x2e]
  10415cd4 LSL r0,r0,#0x18
  10415cd6 BMI 10415ce0
  10415cd8 LDRH r0,[r4,#0xa]
  10415cda MOV r1,#0
  10415cdc BL 10394dcc
Le BL est exécuté seulement si le bit 7 du champ halfword [r4+0x2e] vaut 0,
dans la branche où [r4+0xd]==0 et [r5+4]!=0. Il reçoit un identifiant et 0.
La cible 10394dcc fait 26 octets (11 instructions, 2 appels), sans pool inclus.
  10394dd2 -> 10300eb4: lire une valeur 16 bits dans une table indexée.
  ADD #1, puis LSL/LSR #16: incrément modulo 65536.
  10394de0 -> 1032668c: écrire la valeur et notifier.
Deux références entrantes connues:
  10415cdc depuis 10415c14, catégorie 0;
  102c4d4c depuis 102c4d2c, catégorie 1, sous condition param_1==1.
Descente sur trois niveaux (racine, enfants, petits-enfants) ci-dessous:
  10300eb4 (18 octets / 8 instructions / 1 appel) -> 1032a9c4.
  1032a9c4 (30 / 15 / 0) transforme les identifiants 0x101,0x102,0x104,0x108
  en indices 0,1,2,3; aucune initialisation d'application.
  1032668c (88 / 37 / 7) met à jour [f01c679c+4*indice+2*catégorie],
  prépare une écriture de 2 octets et une notification de code 0x250b.
  1031ea94 choisit un identifiant dans une table; 10329cc0 est un adaptateur;
  1032af68 construit/transmet une notification. Les deux appels 0ffd4164
  et 0ffd40b0 sont hors image: leur rôle allocation/libération est une
  hypothèse tirée de l'usage des pointeurs, pas une identification symbolique.
Le compteur évoque des statistiques par contexte/SIM avec deux catégories;
une attribution SMS envoyé/reçu serait plausible mais reste NON PROUVÉE.
Aucun homologue Altice convaincant trouvé pour le compteur (meilleur score
de présélection 0.564), ni son getter/setter; cela ne prouve pas leur absence
du firmware complet. Deux helpers génériques ont de bons homologues Altice.
Contexte lexical des appels: 103aa774 <-> 102cac54 (suppression dans une file),
puis EXTRA, puis 103cabf4 <-> 102d29d8 (préparation de la partie suivante).
ATTENTION: l'appel précédent est dans une branche alternative; ces trois
appels ne constituent PAS une séquence exécutée systématiquement.
La fonction appelante traite un résultat et une opération segmentée; elle
ne ressemble pas à InitMultimedia. Les dix autres sites sont alignés.
Deux cibles communes sont des wrappers d'une seule instruction: leur hash
est ambigu, et ne suffit pas à établir leur identité.
AudioPlayer plausible COMME InitAudioPlayerApp: NON (confiance élevée).
Un lien indirect du compteur avec une application ne peut être exclu sans symboles.''',
'104323d4': '''VERDICT: faux appel supplémentaire par conflit de modes, confiance élevée.
L'ancien corps mélangeait une fonction ARM et des morceaux Thumb situés avant
l'entrée (10431ba4, 10431c2e, 10432080...). L'instruction ARM à 10432574
était décodée en deux demi-instructions Thumb, entraînant une fausse branche
vers ces morceaux. Le BL 10431c2e -> 105d37f4 n'appartient pas au corps ARM.
Le projet corrigé retrouve 106 instructions ARM / 424 octets / 1 appel,
exactement comme Altice. Le vrai appel 10432564 -> 10432660 correspond à
102d8460 -> 102d855c; les deux cibles ont 13 instructions, 0 appel et les
mêmes opérandes après relocation. Les branches des deux corps correspondent.
Multiplications, interpolation, saturation à +/-32768, échantillons 16 bits,
chemins mono/stéréo: routine de génération/mixage audio probable, commune
aux deux firmwares. Cela ne démontre ni un lecteur MP3 ni son initialisation.
AudioPlayer plausible COMME APPEL RETIRÉ: NON. Le code audio est commun ici.''',
'102f13b6': '''VERDICT: mauvais appariement de fonctions / fragment, confiance élevée.
Les 5 BL QMobile appellent tous 1032b6d4 avec r0=5,6,7,8,9 et r1=1.
Les 4 BL Altice alternent 10252000 et 1025429a avec r0=0 et r1=0x16/0x17.
Les cibles et les paramètres invalident l'hypothèse de quatre homologues
encadrant un EXTRA. Aucun appel supplémentaire unique ne peut être désigné.
1032b6d4 est un wrapper de 14 octets / 6 instructions / 1 appel vers 103213b0;
son homologue candidat 10251b30 a les mêmes opérandes normalisés et mnémoniques.
L'entrée QMobile commence sans prologue et prolonge une série d'appels depuis
102f133c: frontière du rapport d'origine non fiable (préservée comme seed
dans le projet de diagnostic pour permettre la comparaison).
AudioPlayer plausible COMME preuve de suppression: NON.''',
'10314ca8': '''VERDICT: fausse entrée QMobile, confiance élevée.
L'ancien BLX #0x690 est une demi-instruction artificielle, sans cible résolue.
L'entrée reconnue après normalisation est 10314cac: table de décisions
effectuant des CMP, branches, MOV de petites constantes et BX LR, sans appel.
Le couple initial 1 appel contre 0 n'établit aucune suppression de fonction.
Pas de taille ni de graphe à attribuer à une prétendue cible 0x690.
AudioPlayer plausible COMME appel retiré: NON.''',
'103512f0': '''VERDICT: différence réelle de placement UI, attribution précise incertaine.
Le vrai bloc ajouté commence à 103513ac: BLX 102e0238, CMP r0,#0, BEQ,
puis calculs locaux de coordonnées dans une branche. Il contient 11
instructions supplémentaires; les différences BL/BLX à 10351320 et
103513d6 sont des substitutions à des sites communs, pas deux autres ajouts.
102e0238 est un veneer ARM de 4 octets: LDR pc,[102e023c]. Le mot chargé est
f0342f91, soit une destination Thumb f0342f90. Cette destination finale n'est
pas mappée dans ALICE: taille, appels et récursion au-delà du veneer inconnus.
La cible a de nombreux appels entrants (liste exhaustive dans le fichier arbre).
Le retour sélectionne local_18+1 ou local_1c-1 avant l'appel de dessin/placement
1031f290 <-> 1024a240. Cela ressemble à un test d'orientation de l'interface
(p.ex. RTL), sans preuve permettant d'attribuer un nom exact.
Les wrappers LDR pc ont un hash identique très fréquent: ce n'est pas une preuve
d'homologie de leurs destinations externes. Arbre arrêté aux régions non mappées.
AudioPlayer plausible COMME initialisation: NON; rôle exact du prédicat: INCERTAIN.''',
'10408eda': '''VERDICT: mauvais appariement, confiance élevée.
Les deux premiers appels QMobile ciblent 103250e4 (35 instructions / 7 appels),
alors que les deux cibles Altice n'ont que 5 instructions / 0 appel chacune.
Les scores de séquences sont quasi nuls et les arguments diffèrent.
Le meilleur homologue de 103250e4 est 1024cb88, avec identité normalisée.
Le BL 10408ef4 -> 102bc944 est le site lexical non aligné, mais le nommer
EXTRA serait injustifié faute d'homologie de l'appelant. Sa cible fait
122 octets / 50 instructions / 11 appels; graphe et références exportés.
L'entrée QMobile sans prologue et le POP asymétrique signalent aussi un fragment.
AudioPlayer plausible COMME preuve de suppression: NON.'''
}

def blocks(f):
    ins=f['instructions']; addrs={i['address'] for i in ins}
    leaders={f['entry']}
    for pos,i in enumerate(ins):
        if i['jump']:
            leaders.update(t for t in i['targets'] if t in addrs)
        if (i['jump'] or i['terminal']) and pos+1<len(ins): leaders.add(ins[pos+1]['address'])
        if pos and int(ins[pos-1]['address'],16)+ins[pos-1]['length']!=int(i['address'],16): leaders.add(i['address'])
    result=[]; current=[]
    for i in ins:
        if i['address'] in leaders and current: result.append(current); current=[]
        current.append(i)
    if current: result.append(current)
    return result

def main():
    sys.stdout.reconfigure(encoding='utf-8')
    q0,q,a=load('qmobile'),load('qmobile_normalized'),load('altice')
    matches=json.loads((ROOT/'callee_matches.json').read_text())
    indexed={m['altice']:m for m in matches}
    matcher=Matcher(q,a)
    lines=[]
    def p(s=''): lines.append(str(s))
    p('ANALYSE STATIQUE DES APPELS SUPPLEMENTAIRES — MT6261 / MAUI')
    p('Sources locales seulement; aucun accès au téléphone, aucune image de flash créée.')
    p('CONCLUSION: premier et troisième candidats faux positifs; deuxième = compteur, pas InitAudioPlayerApp.')
    p('Les sept couples du rapport initial avec dCalls=+1 ont été examinés dans leur ordre de priorité.')
    p('Les autres couples des 498 correspondances ne sont pas tous présents dans le rapport limité à 150 lignes.')
    p('Cette analyse ne prouve pas à elle seule que le lecteur MP3 a été retiré du firmware Altice.')
    p('\nPROVENANCE / CORRECTION NECESSAIRE')
    for folder in [QMOBILE_ALICE, ALTICE_ALICE]:
        for name in ['alice-py.bin','alice-translated-py.bin']:
            path=folder/name; b=path.read_bytes()
            p(f'{folder}/{name}: {len(b)} octets; SHA256 {hashlib.sha256(b).hexdigest()}')
    p('Les deux fichiers QMobile sont identiques: conversion BL/BLX non appliquée, contrairement à Altice.')
    p('AnalyzeAliceNormalized.java reproduit untranslate_bl_blx() du unalice.py local dans un projet Ghidra distinct.')
    p('Aucune réécriture des binaires sources. Le projet normalisé est un artefact d’analyse, pas un firmware flashable.')
    p('Les adresses restent celles du modèle Ghidra demandé; le placement physique/runtime complet n’est pas validé.')
    p('La correction des cibles est corroborée par les corps homologues et l’identité des opérandes, pas seulement par leur présence dans la plage.')
    p('QMobile: 10291 fonctions dans l’export normalisé; cette population diffère des 9141 anciennes empreintes.')
    p('L’export ancien détaillé compte 9471 entrées (dont corps sans instructions), après le post-traitement Ghidra.')
    p('Les anciennes statistiques globales et empreintes ne doivent donc pas servir de preuve de suppression.')
    p('\nMETHODE ET LIMITES')
    p('Alignement monotone des instructions: mnémonique + registres + petits immédiats + déplacements mémoire.')
    p('Les adresses absolues de 7-8 chiffres hexadécimaux sont abstraites; les cibles BL/BLX sont comparées séparément.')
    p('Les branches internes sont comparées via la correspondance instruction-à-instruction des destinations.')
    p('Pour un remplacement de même longueur, une instruction de même mnémonique garde sa position homologue; ses opérandes différents restent affichés.')
    p('Score de présélection des cibles = 0.50*similarité opérandes + 0.35*similarité mnémoniques + 0.15*Jaccard 4-grammes.')
    p('Présélection des 40 meilleurs candidats par 4-grammes et ratio de taille 0.55..1.8; pas preuve d’absence si aucun match.')
    p('Les appels sortants des cibles communes sont comparés sur un niveau additionnel dans callee_matches.json.')
    p('Les hashes portent uniquement sur les mnémoniques. Petits wrappers et veneers: collisions structurelles fréquentes.')
    p('Listes triées par ADRESSE, non par chronologie d’exécution. Les branches/retours/boucles sont conservés.')
    p('Les BLX via registre restent indéterminés sans les tables runtime: sites homologues != cibles prouvées homologues.')
    p('Une cible hors mémoire n’est pas assimilée à une fonction absente du firmware complet.')
    p('Aucun symbole AudioPlayer, Camera, Image Viewer, Video Player ou FM Radio n’a été attribué sans preuve.')

    for n,(old,ae) in enumerate(PAIRS,1):
        qe={'103fe66a':'103fe67c','10314ca8':'10314cac'}.get(old,old)
        f,g=q[qe],a[ae]; original=q0[old]
        p('\n'+'='*100); p(f'CANDIDAT {n}: QMobile {old} <-> Altice {ae}')
        p('Rapport initial: '+summary(original)+' <-> '+summary(g))
        p('Analyse normalisée: '+summary(f)+' <-> '+summary(g))
        extra_ins=next(i for i in q['10415c14']['instructions'] if i['address']=='10415cdc')
        p(NOTES[old].replace('{NORMALIZED_EXTRA_HEX}',bytes.fromhex(extra_ins['hex']).hex(' ')))
        if n==1:
            p('\nPseudo-instructions QMobile seules dans le rapport initial (DONNEES, PAS CODE):')
            for i in original['instructions']:
                if int(i['address'],16)<int(qe,16): p(i['address']+' '+i['hex']+' '+i['text'])
            raw=(QMOBILE_ALICE/'alice-py.bin').read_bytes()
            p('Mots de données et leurs références depuis la fonction précédente:')
            for addr in range(0x103fe664,0x103fe67c,4):
                p(f'{addr:08x}: {struct.unpack_from("<I",raw,addr-0x1018a598)[0]:08x}')
            for i in q['103fe598']['instructions']:
                for r in i['refs']:
                    if r['to'] in [f'{addr:08x}' for addr in range(0x103fe664,0x103fe67c,4)]: p(i['address']+' '+i['text'])
        p('\nAPPELS QMOBILE (ordre des adresses):')
        for k,i in enumerate(calls(f),1): p(f'Q{k:02}: {i["address"]} {i["text"]} => {target(i)}')
        p('APPELS ALTICE (ordre des adresses):')
        for k,i in enumerate(calls(g),1): p(f'A{k:02}: {i["address"]} {i["text"]} => {target(i)}')
        p('\nCORRESPONDANCE DES SITES ET PREUVES SUR LES CIBLES:')
        m=indexed.get(ae,{})
        for cp in m.get('call_pairs',[]):
            s=cp['evidence']; qt,at=cp['qtarget'],cp['atarget']
            p(f'{cp["qsite"]} -> {qt}  <->  {cp["asite"]} -> {at}')
            if s:
                p(f'  Instructions {s["q_ins"]}/{s["a_ins"]}; appels {s["q_calls"]}/{s["a_calls"]}; '
                  f'MN={s["mnemonic"]:.3f}, OP={s["operands"]:.3f}, score={s["score"]:.3f}; hash identique={s["hash_equal"]}')
                p(f'  Hash Q {s["q_hash"]}; hash A {s["a_hash"]}')
                if min(s['q_ins'],s['a_ins'])<=2: p('  CONFIANCE FAIBLE SUR LA CIBLE: wrapper trop court et ambigu; suivre le saut terminal.')
                if s['score']<.7: p('  HOMOLOGIE NON RETENUE: similarité trop faible; alignement lexical seulement.')
            else: p('  Cible non résolue ou hors image; correspondance de site fondée seulement sur le contexte.')
            if cp['alternatives']: p('  Meilleurs candidats globaux: '+', '.join(f'{r["altice"]} score={r["score"]:.3f}' for r in cp['alternatives']))
            for child in cp.get('call_structure',[]):
                cs=child['evidence']
                p(f'    Structure enfant: {child["qtarget"]} <-> {child["atarget"]}; '
                  +(f'MN={cs["mnemonic"]:.3f}, OP={cs["operands"]:.3f}, appels={cs["q_calls"]}/{cs["a_calls"]}' if cs else 'non résolu/non aligné'))
        if old=='103512f0':
            p('Deux substitutions supplémentaires de sites communs (BL versus BLX):')
            p('  Q10351320 -> 0ffe848e <-> A1027a1e0 -> 1022f6b0; cibles finales non vérifiées.')
            p('  Q103513d6 -> 0ffd2c90 <-> A1027a27e -> 1022f910; cibles finales non vérifiées.')
            p('Les 11 sites communs encadrent un seul ajout: Q103513ac -> 102e0238.')
        p('\nBLOCS ET BRANCHES:')
        rows=compare(f,g); amap={x['address']:y['address'] for t,x,y in rows if t=='='}
        sm=difflib.SequenceMatcher(None,list(map(norm,f['instructions'])),list(map(norm,g['instructions'])),autojunk=False)
        for tag,i,j,k,l in sm.get_opcodes():
            if tag=='replace' and j-i==l-k:
                for x,y in zip(f['instructions'][i:j],g['instructions'][k:l]):
                    if x['mnemonic']==y['mnemonic'] or (x['call'] and y['call']):
                        amap[x['address']]=y['address']
        for tag,x,y in rows:
            if x and x['jump'] and y and y['jump']:
                mapped=[amap.get(t) for t in x['targets']]
                status='OUI' if mapped==y['targets'] and mapped else 'NON ETABLIE (destination modifiée ou non alignée)'
                p(f'{x["address"]} {x["text"]} <-> {y["address"]} {y["text"]}; '
                  f'destination homologue={status}; condition={x["mnemonic"]==y["mnemonic"]}')
        for label,fn in [('Q',f),('A',g)]:
            p(label+' blocs de base (les appels ne découpent pas un bloc):')
            for block in blocks(fn):
                last=block[-1]
                p(f'  {block[0]["address"]}..{last["address"]} ({len(block)} instructions); '
                  f'fin={last["text"]}; saut={last["targets"] if last["jump"] else []}; suite={last.get("fallthrough")}')
        p('\nALIGNEMENT INTEGRAL DES INSTRUCTIONS:')
        p('= même instruction normalisée; - présente dans le segment Q non aligné; + segment A non aligné.')
        p('Un remplacement produit - puis +; cela ne signifie pas que toutes ces lignes sont des ajouts/suppressions sémantiques.')
        for tag,x,y in rows:
            p(f'{tag} {x["address"]+" "+x["text"] if x else "":50s} | {y["address"]+" "+y["text"] if y else ""}')
        p('\nREFERENCES ENTRANTES DES CANDIDATS:')
        for label,fn in [('Q',f),('A',g)]: p(label+' '+json.dumps(fn['incoming'],ensure_ascii=False))

    p('\n'+'='*100+'\nCIBLE SUPPLEMENTAIRE REELLE: 10394dcc — PREUVES SUR TROIS NIVEAUX')
    trees=(ROOT/'qmobile_extra_trees.txt').read_text(encoding='utf-8')
    firsttree=trees.split('=== depth=0 address=102c4d2c ===')[0]
    p(firsttree)
    p('INSTRUCTIONS COMPLETES DES TROIS FONCTIONS PRINCIPALES DU COMPTEUR:')
    for e in ['10394dcc','10300eb4','1032668c']:
        fn=q[e]; p(summary(fn))
        for i in fn['instructions']: p(i['address']+' '+i['text']+' '+json.dumps(i['refs'],ensure_ascii=False))
    p('\nRECHERCHE D’HOMOLOGUES POUR LE COMPTEUR ET SES HELPERS:')
    p((ROOT/'extra_target_matches.json').read_text())
    p('\nAUTRE CIBLE REELLE: 102e0238')
    fn=q['102e0238']; p(summary(fn)); p('Destination terminale: '+str(fn.get('thunk')))
    for i in fn['instructions']: p(i['address']+' '+i['text']+' '+json.dumps(i['refs']))
    p('Références entrantes: '+json.dumps(fn['incoming']))
    p('Récursion arrêtée à f0342f90: code absent des blocs ALICE importés. Pas de taille inventée.')
    p('\nARTEFACTS REPRODUCTIBLES')
    p('run_extra_call_analysis.ps1: export Ghidra en lecture seule, normalisation dans projet distinct, analyses Python.')
    p('qmobile_details.jsonl, altice_details.jsonl: état initial, instructions et références.')
    p('qmobile_normalized_details.jsonl: état corrigé avec instructions et références.')
    p('callee_matches.json: fingerprints, alternatives et structure des appels enfants.')
    p('candidate_*_instructions.txt: alignements anciens; normalized_*_instructions.txt: alignements corrigés.')
    p('qmobile_extra_trees.txt: toutes les décompilations ciblées, appels sortants et références entrantes.')
    p('Les décompilations peuvent mal inférer les prototypes; les conclusions de compteur sont vérifiées dans les instructions.')
    p('\nPROCHAINE ADRESSE A ANALYSER: 10275ee8 (appelant de 102c4d2c), pour attribuer le compteur;')
    p('pour rechercher AudioPlayer, recalculer d’abord les candidats à partir du projet QMobile normalisé.')
    p('Aucune conclusion de retrait du lecteur audio ne découle de ces sept candidats.')
    validation=ROOT/'extra_call_validation.json'
    if validation.exists():
        p('\nVERIFICATIONS INDEPENDANTES (verify_extra_call_evidence.py)')
        p(validation.read_text(encoding='utf-8'))
    (ROOT/'extra_call_analysis.txt').write_text('\n'.join(lines)+'\n',encoding='utf-8')
    terminal='''Candidat principal : deuxième candidat, seul ajout interne confirmé parmi les trois prioritaires
QMobile : 0x10415C14
Altice : 0x102C6F8C

Appel supplémentaire QMobile :
adresse appel : 0x10415CDC
cible : 0x10394DCC
taille cible : 26 octets / 11 instructions
nombre d'appels cible : 2

Contexte des appels avant/après :
103AA774 <-> 102CAC54 (branche alternative), EXTRA,
103CABF4 <-> 102D29D8 (partie suivante, conditionnelle).

Interprétation : incrément d'un compteur 16 bits puis mise à jour/notification.
Premier et troisième candidats : faux positifs (21/21 puis 1/1 appels).

AudioPlayer plausible : NON
Raison : compteur, sans structure d'initialisation d'applications multimédia.
Le retrait d'AudioPlayer reste non démontré.

Prochaine adresse à analyser : 0x10275EE8 (pour attribuer le compteur).
'''
    (ROOT/'extra_call_summary.txt').write_text(terminal,encoding='utf-8')
    print(terminal)
    print('Rapport :',ROOT/'extra_call_analysis.txt')

if __name__=='__main__': main()
