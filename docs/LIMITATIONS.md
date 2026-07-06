# LIMITATIONS — CANARIS

Document d'honnêteté : les limites connues, assumées et non résolues. En
entretien, c'est un argument de crédibilité, pas une faiblesse cachée.

> **Ce qui n'a PAS été exécuté dans l'environnement de dev** (et pourquoi), en une
> phrase chacun :
> - **Blocage LSM `-EPERM`** : jamais enforced ici (WSL2 n'a pas `bpf` dans la
>   liste LSM active) — seulement compilé + verifier. → `vm/validate_enforce.sh`.
> - **Kill réel du responder** : jamais validé en intégration ici (décalage de
>   PID-namespace du conteneur) — prouvé par test unitaire C same-namespace.
>   → `vm/validate_kill.sh` sur VM native.
> - **Driver Windows (~1000 lignes)** : **écrit, revu statiquement, jamais compilé
>   ni chargé** (pas de WDK) — build/chargement = `vm/build_windows.ps1` +
>   `vm/validate_windows.md` ; points d'attention dans `windows/REVIEW_NOTES.md`.
> - **Faux positifs** : 0 sur workloads **synthétiques** seulement ici — mesure
>   réelle = `vm/fp_workload.sh`.

---

## 0. Préservation : baseline périodique, PAS un snapshot réactif (décision T1)

**Historique de la décision.** La première version prenait le snapshot **à la
détection** — donc sur des fichiers **déjà chiffrés** : préservation inutile contre
un chiffreur rapide (mesuré : 200 fichiers en 37 ms, 30 en 7 ms). Correction : la
source de récupération est désormais un **baseline PÉRIODIQUE pris AVANT l'attaque**
(défaut 15 min, rotation 8), qui **copie** les fichiers (jamais un lien dur vers la
source vivante, sinon une réécriture en place corromprait la sauvegarde) et
**exclut** tout fichier déjà chiffré. Le snapshot pris à la détection est conservé
mais **relabellé `post-incident` (forensique)**, pas une source de restauration.
**Limite** : le baseline est **local** (même machine) et périodique → une fenêtre
de perte = les fichiers créés/modifiés depuis le dernier baseline. Une vraie
stratégie 3-2-1 (copie hors-ligne/distante) reste hors périmètre (§8).

## 1. Déploiement Windows sans signature WHQL (limitation MAJEURE, assumée)

En production Windows moderne (Secure Boot + HVCI), un minifilter **non signé
WHQL ne peut pas se charger**. La certification WHQL (EV code signing + tests
Microsoft) coûte plusieurs k€ et 3–6 mois — **hors cadre d'un projet étudiant**.

* **Conséquence** : le composant Windows est démontrable **en VM (Test Signing +
  HVCI désactivé)** mais non déployable en l'état sur un poste corporate.
* **Non résolu** — assumé explicitement.
* **Repli documenté** : **Controlled Folder Access** (API Defender) + **ETW**
  (télémétrie userspace). Moins robuste (pas de blocage kernel custom), mais
  déployable sans signature. Non implémenté ici (documenté comme voie de repli).

## 2. Blocage Linux dépendant de LSM BPF au boot

Le blocage synchrone `-EPERM` exige que le LSM `bpf` soit actif
(`lsm=…,bpf` dans la cmdline kernel, `/sys/kernel/security/lsm`). Sinon, le loader
**détecte** l'absence et bascule en **mode dégradé** (observation + kill), qui est
une **mitigation** et non un blocage : un chiffreur rapide peut altérer quelques
fichiers avant le kill (mais le snapshot en préserve une copie).

## 3. Course du chiffrement rapide (race condition)

La réponse userspace (kill) n'est pas instantanée. Un ransomware très rapide peut
chiffrer N fichiers avant d'être tué. Mitigations : (a) blocage **synchrone**
LSM/minifilter dès le 1er accès **canary** — ne dépend pas de l'userspace ;
(b) **snapshot avant kill**. Mesuré : cf. `docs/VALIDATION.md` (Phase 4).

## 4. Whitelist par EXÉCUTABLE (inode) — pas par nom (durci T2)

L'exemption est décidée par l'**identité de l'exécutable** : (device, inode) du
binaire côté Linux (`task->mm->exe_file`), chemin d'image complet normalisé côté
Windows. Le `comm`/`argv[0]` (falsifiable via `prctl`) n'accorde **aucun**
privilège, et un process non whitelisté garde **toujours le seuil par défaut**
(un ransomware renommé `rsync` n'hérite ni de l'exemption ni d'un quota élevé —
prouvé par les tests anti-spoof, `docs/VALIDATION.md`).

**Limite résiduelle** : un attaquant qui parvient à **remplacer** le binaire
whitelisté lui-même (même inode) hériterait de l'exemption. Le durcissement ultime
serait une vérification **Authenticode / hash signé** du binaire à chaque décision
(hors scope — coût de perf + gestion des certificats ; noté dans
`windows/REVIEW_NOTES.md`). Le calcul de l'inode d'exe à chaque événement ajoute
aussi un léger surcoût (à mesurer, cf. R8).

## 4bis. Profils STATIQUES curatés — pas une baseline apprise

Ce que le cahier appelle « seuil adaptatif par processus » est, dans
l'implémentation, un ensemble **statique curaté** : une whitelist d'exécutables de
confiance + un **seuil par défaut unique**. Ce n'est **pas** une baseline apprise
par utilisateur/processus (pas de ML). C'est un **choix d'ingénierie assumé** :
prévisible, auditable, sans dérive ni empoisonnement d'apprentissage, et sans le
risque de faux négatifs d'un modèle mal calibré. Une vraie détection adaptative
(apprentissage de baseline d'I/O par processus, percentiles glissants) est un
**travail futur** identifié, pas une fonctionnalité présente. Le terme
« adaptatif » du cahier est donc à lire comme « profils curatés par processus ».

## 5. btime non modifiable sous Linux

Le générateur de canary fixe atime/mtime partout, et le **btime (creation time)
uniquement sous Windows** (SetFileTime). Sous Linux, le btime ext4 nécessite
`debugfs -w -R 'set_inode_field … crtime …'` (root, hors ligne) — documenté dans
`HANDOFF.md`, non automatisé.

## 6. Reconstruction de chemin limitée en eBPF

Le blocage LSM identifie les cibles par **(device, inode)** et remonte au plus
16 dentries parents (borne du verifier). Une hiérarchie protégée plus profonde
que 16 niveaux ne serait pas couverte par la remontée d'ancêtres (les canaries
individuels le restent, par inode). En pratique suffisant.

## 7. Portée du VssGuard (matching par mots-clés)

VssGuard reconnaît des motifs de command-line connus (vssadmin/wmic/bcdedit/
wbadmin/powershell). Un attaquant appelant l'API VSS **directement** (COM
`IVssBackupComponents`) sans passer par ces binaires ne serait pas détecté par ce
mécanisme (il le serait par le blocage de suppression des fichiers de snapshot).

## 8. Snapshot local, pas hors-ligne

Le snapshot (`rsync --link-dest` / VSS) reste sur la **même machine**. Un
ransomware avec privilèges suffisants pourrait tenter de le supprimer — d'où
l'auto-protection du dossier de snapshots (Linux) et VssGuard (Windows). Une vraie
stratégie 3-2-1 exigerait une copie **hors-ligne / distante** (hors périmètre).

## 9. Périmètre explicitement hors-scope (cahier §2.2)

Chiffrement préventif (rejeté, §2.1), envoi de clé, macOS/Android/embarqué,
ransomware in-memory, ciblage ESXi, mouvement latéral réseau, déploiement WHQL.
