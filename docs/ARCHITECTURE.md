# ARCHITECTURE — CANARIS

Anti-ransomware multi-OS à interception noyau. Trois piliers : **canary files**,
**interception noyau** (blocage réel), **réponse de préservation** (snapshot).

---

## 1. Vue d'ensemble

```
                    ┌───────────────────────────────┐
                    │   CANARY FILES (leurres)       │
                    │   réalistes, faible entropie   │  common/canary_generator.py
                    └───────────────┬───────────────┘
                                    │ accès détecté
              ┌─────────────────────┴─────────────────────┐
              │                                            │
      ┌───────▼─────────┐                         ┌────────▼─────────┐
      │     WINDOWS      │                         │      LINUX        │
      │  Minifilter Ring0│                         │  eBPF + LSM BPF   │
      │                  │                         │                   │
      │ IRP_MJ_CREATE    │                         │ kprobes openat/   │
      │ IRP_MJ_WRITE     │  observation +          │  write/unlinkat   │  (observation)
      │ IRP_MJ_SET_INFO  │  blocage synchrone      │ lsm/file_open     │
      │ STATUS_ACCESS_   │                         │ lsm/inode_unlink  │  (blocage -EPERM)
      │   DENIED         │                         │ lsm/inode_rename  │
      │ VssGuard (PsSet  │                         │ ring buffer       │
      │  CreateProcess…) │                         │                   │
      └───────┬──────────┘                         └────────┬──────────┘
              │ FltSendMessage (comm port)                  │ BPF_MAP_TYPE_RINGBUF
      ┌───────▼──────────┐                         ┌────────▼──────────┐
      │  Service (C++)    │                         │  Loader (C/libbpf) │
      │  • push config    │                         │  • push maps       │
      │  • kill process   │                         │  • détection        │  profiles.c
      │  • VSS snapshot   │                         │  • kill + rsync snap │  responder.c
      └───────────────────┘                         └────────────────────┘
                                                     ▲ moteur de référence
                                                     │ (Python) : canaris_engine.py
```

Les deux OS partagent la **même stratégie** ; seule la mécanique noyau diffère
(minifilter FltMgr côté Windows, eBPF/LSM côté Linux).

---

## 2. Pilier 1 — Canary files (`common/canary_generator.py`)

Fichiers leurres indétectables par heuristique (cahier F1) :

| Propriété | Choix | Pourquoi |
|---|---|---|
| Magic bytes | PDF `%PDF-`, docx/xlsx `PK\x03\x04` (ZIP OOXML **valide**) | passe pour un vrai document |
| Taille | log-normale [50 Ko, 5 Mo] | une taille uniforme trahirait un leurre |
| Entropie | < 6 bits/octet (texte lisible, ZIP **non compressé**) | un ransomware saute les fichiers déjà haute-entropie |
| Timestamps | atime/mtime + **btime** (Windows) dans le passé | paraît réellement utilisé |
| Nom / placement | `RIB_2023.pdf`, sous-dossiers profonds | crédible, jamais `canary.txt` |

Le générateur émet `canary_manifest.json` + `canary_files.txt` (liste consommée
par le loader Linux `--canary-list` et le service Windows).

---

## 3. Pilier 2 — Interception noyau

### 3.1 Linux (`linux/bpf/canaris.bpf.c`)

Deux niveaux (CLAUDE.md §2.2) :

* **kprobes** (`ksyscall/openat|openat2|write|unlinkat`) → **observation** pure
  (read-only), émission vers un `BPF_MAP_TYPE_RINGBUF`.
* **LSM BPF** (`lsm/file_open`, `lsm/inode_unlink`, `lsm/inode_rename`) →
  **blocage synchrone** : renvoie `-EPERM` si la cible est un canary ou sous un
  dossier protégé ET le process n'est pas whitelisté.

Identification robuste par **(device, inode)** (pas de reconstruction de chemin
coûteuse), + remontée bornée de 16 dentries parents pour la protection de
sous-arbre. Maps alimentées par l'userspace : `protected_files`, `whitelist`,
`config_map`. CO-RE (BTF) pour la portabilité entre kernels.

**Mode dégradé** : si le LSM `bpf` n'est pas actif au boot, le loader le détecte,
désactive les programmes LSM et bascule en observation + réponse par kill
(mitigation, pas blocage) — cf. §6.

### 3.2 Windows (`windows/driver/Canaris.c`)

Minifilter (altitude **328000**, plage anti-virus) avec pré-callbacks sur
`IRP_MJ_CREATE`, `IRP_MJ_WRITE`, `IRP_MJ_SET_INFORMATION` (rename/delete). Blocage
= `FLT_PREOP_COMPLETE` + `STATUS_ACCESS_DENIED`. Communication avec le service
via `FltCreateCommunicationPort` (ACL admin). Mémoire `ExAllocatePool2`.

---

## 4. Pilier 3 — Détection comportementale + réponse

### 4.1 Détection (`linux/userspace/profiles.c` ; réf. `common/canaris_engine.py`)

* **Compteur d'I/O par PID** sur fenêtre glissante (défaut 2 s).
* **Seuil ADAPTATIF par profil de processus** (`config/profiles.json` →
  `config/thresholds.conf`) — jamais un seuil global fixe (CLAUDE.md §2.3). Un
  process whitelisté à fort débit (npm, git, OneDrive, Defender) ne déclenche pas.
* **Scoping** : seuls les accès aux **zones protégées** (canaries + dossiers
  protégés) sont comptés — le bruit système (dockerd, etc.) est ignoré (évite les
  faux positifs catastrophiques).
* Signaux : accès canary (**immédiat**, hors seuil — cahier §12), taux d'I/O,
  suppression massive, read-then-write.

### 4.2 Réponse (`linux/userspace/responder.c` ; `windows/service/responder.cpp`)

1. **Préserver d'abord** : snapshot (`rsync --link-dest`, repli `cp -a` ; VSS via
   WMI côté Windows) — liens durs, quasi instantané.
2. **Puis tuer** le processus (`SIGKILL` / `TerminateProcess`).
3. **Journaliser** (horodaté) chaque détection/réponse.

La seule réponse de préservation est le **snapshot** — pas de chiffrement
préventif (CLAUDE.md §2.1).

---

## 5. Anti-suppression de sauvegardes (VssGuard)

* **Windows** (`VssGuard.c` + `vssguard_rules.h`) : `PsSetCreateProcessNotifyRoutineEx`
  reconnaît `vssadmin delete/resize shadows`, `wmic shadowcopy delete`, `bcdedit`
  (désactivation récupération), `wbadmin delete`, PowerShell `Win32_Shadowcopy`.
  → **alerte priorité maximale immédiate** (indépendante du seuil I/O, cahier
  §2.4) + blocage de la création du process (`CreationStatus = STATUS_ACCESS_DENIED`).
* **Linux** (F5.3) : le répertoire de snapshots est **auto-protégé** ; toute
  suppression y est bloquée/détectée par `lsm/inode_unlink`.

---

## 6. Flux de données & dégradation gracieuse

```
 openat/write/unlink ──kprobe──▶ ringbuf ──▶ loader ──scoping──▶ détecteur ──▶ responder
 file_open/unlink/rename ──LSM──▶ -EPERM (bloque) + event CANARY_HIT/BLOCKED ──┘
```

| Situation | Comportement |
|---|---|
| LSM BPF actif (kernel `lsm=…,bpf`) | **blocage synchrone** dès le 1er accès canary + réponse |
| LSM BPF inactif | mode **dégradé** : observation + kill (mitigation) ; documenté |
| Minifilter non chargeable (WHQL) | repli **CFA + ETW** (documenté, `docs/LIMITATIONS.md`) |

---

## 7. Implémentation de référence & tests

`common/canaris_engine.py` implémente l'algorithme de détection/réponse en Python.
Il sert de **référence** (l'algo que reproduit le C), de **harnais de test** (rejeu
de traces sans VM) et de **matcher du mode dégradé** (consomme le flux `--json` du
loader). Les tests C (`tests/ctest/`) valident le code de production réel
(`profiles.c`, `responder.c`, `vssguard_rules.h`). Voir `docs/VALIDATION.md` pour
les preuves d'exécution.
