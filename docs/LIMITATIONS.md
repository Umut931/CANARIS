# LIMITATIONS — CANARIS

Document d'honnêteté : les limites connues, assumées et non résolues. En
entretien, c'est un argument de crédibilité, pas une faiblesse cachée.

---

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

## 4. Whitelist par nom de processus (`comm`) — falsifiable

La whitelist Linux compare le `comm` (15 car.), falsifiable : un binaire malveillant
nommé `rsync` serait exempté. Idem, la whitelist Windows compare un suffixe de
chemin d'exécutable (plus robuste mais contournable par copie). **Durcissement
prévu** : identifier l'exécutable par son **inode**/hash, pas son nom.

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
