# F2 Virtual Menu Lab - chantier distinct

Branche : feature/f2-virtual-menu-lab

## Phase 1 - Prototype
- [x] Lecteur du registre B702 avec hash canonique
- [x] Mode original et mode Audio virtuel
- [x] Interface Windows de navigation
- [x] Tests automatiques hors ligne

## Phase 2 - Simulation des menus
- [ ] Lire les autres enregistrements depuis le registre reel
- [ ] Decoder les relations de menu B709 et B702
- [ ] Integrer les regles de filtrage prouvees
- [ ] Integrer les metadata et ressources d'affichage prouvees

## Phase 3 - Verification de la modification
- [ ] Identifier une zone de relogement demonstrablement sure
- [ ] Etablir toutes les references et consommateurs concernes
- [ ] Produire un diff sur copie de travail uniquement
- [ ] Verifier le repack, les hashes et le retour arriere

## Limites actuelles
Une entree simulee n'est pas une preuve d'execution
ou de visibilite sur le vrai telephone.

La modification du child_count seule est interdite :
le tableau B703 suit immediatement B702.

Ne pas refaire les analyses de registre S13.5A.39-49,
les recherches de callback Audio S11/S13.1d,
ni les pistes UI deja fermees.
