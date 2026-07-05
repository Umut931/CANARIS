# CLAUDE.md — CANARIS

> Fichier de contexte projet pour Claude Code. Nom de code **CANARIS** (canary + référence contre-espionnage). Renommable — remplacer partout si besoin.

---

## 1. Résumé du projet

CANARIS est un logiciel anti-ransomware **multi-OS** basé sur trois piliers :

1. **Canary files réalistes** — fichiers leurres indétectables par analyse heuristique
2. **Interception noyau** — blocage réel des I/O malveillantes (Ring 0 Windows / LSM BPF Linux)
3. **Réaction automatique de préservation** — kill du processus + snapshot instantané (VSS / rsync)

**Objectif** : détecter et stopper un ransomware en cours de chiffrement, puis préserver les données via snapshot — le tout depuis le noyau, hors de portée du malware.

---

## 2. ⚠️ Décisions d'architecture NON NÉGOCIABLES

Ces choix résultent d'une analyse de failles. Ne pas les remettre en question sans raison forte.

### 2.1 — PAS de chiffrement préventif
L'idée initiale prévoyait de chiffrer préventivement les dossiers et d'envoyer la clé à une « adresse de confiance ». **Cette fonctionnalité est SUPPRIMÉE définitivement.** Raisons :
- On réimplémente exactement le mécanisme du ransomware
- La perte/compromission de clé = on devient soi-même le ransomware
- Le canal d'envoi de clé = single point of failure (MITM)
- Le snapshot suffit comme réponse de préservation

**La seule réponse de préservation autorisée est le SNAPSHOT (copy-on-write / rsync --link-dest / VSS).**

### 2.2 — Linux : LSM BPF, pas seulement kprobes
Les **kprobes sont read-only** → impossible de bloquer une syscall. Pour le blocage réel, utiliser les **LSM BPF hooks** (kernel ≥ 5.7) qui peuvent retourner `-EPERM`. Architecture Linux :
- **kprobes** → observation / télémétrie (openat, write, unlinkat)
- **LSM BPF** → décision de blocage (`lsm/file_open`, `lsm/inode_unlink`, `lsm/inode_rename`)

### 2.3 — Threshold adaptatif, jamais fixe
Un seuil global fixe (50 I/O / 2 s) génère des faux positifs catastrophiques (npm install, sync OneDrive, git clone, scan Defender). Le compteur d'I/O doit être **paramétré par profil de processus** avec baseline calibrée. Le seuil fixe n'existe que comme valeur par défaut de secours.

### 2.4 — Détection de suppression VSS = signal prioritaire
Les ransomwares suppriment les shadow copies **avant** de chiffrer (`vssadmin delete shadows`, `wmic shadowcopy delete`, `bcdedit`). Ce comportement ne déclenche pas le seuil d'I/O. Il faut une détection dédiée (process-creation callback) qui traite cette action comme **alerte maximale immédiate**, indépendamment du compteur d'I/O.

### 2.5 — Développement exclusivement en VM
Un minifilter ou un LSM BPF bugué peut **BSOD / kernel panic**. Jamais de test sur bare metal. VM dédiée avec snapshots fréquents. Test Signing Mode dans la VM Windows uniquement.

---

## 3. Architecture

```
CANARIS/
├── linux/
│   ├── bpf/
│   │   ├── canaris.bpf.c        # programmes eBPF (kprobes + LSM hooks)
│   │   └── canaris.h            # structures partagées kernel/userspace
│   ├── userspace/
│   │   ├── main.c              # loader libbpf + boucle d'événements (ring buffer)
│   │   ├── responder.c        # kill process + snapshot rsync
│   │   └── profiles.c         # threshold adaptatif par process
│   └── Makefile
├── windows/
│   ├── driver/
│   │   ├── Canaris.c          # minifilter (registration, pre/post callbacks)
│   │   ├── Canaris.h
│   │   ├── VssGuard.c         # détection suppression shadow copies
│   │   └── Canaris.inf        # installation driver
│   ├── service/
│   │   ├── service.cpp        # service userspace (communication port)
│   │   └── responder.cpp      # kill + IOCTL_CANARIS_TRIGGER_VSS
│   └── Canaris.sln
├── common/
│   └── canary_generator.py    # générateur de canary files réalistes (cross-OS)
├── tests/
│   ├── ransim/               # scénarios de test (RanSim / simulateur maison)
│   └── falsepositive/        # workloads légitimes (npm, git, rsync)
├── docs/
│   ├── ARCHITECTURE.md
│   ├── THREAT_MODEL.md
│   └── LIMITATIONS.md
├── CLAUDE.md
└── README.md
```

---

## 4. Toolchain & commandes

### Linux (composant prioritaire — développer en premier)
```bash
# Dépendances (Ubuntu 22.04+, kernel ≥ 5.15)
sudo apt install clang llvm libbpf-dev linux-tools-$(uname -r) bpftool

# Vérifier le support BTF (obligatoire pour CO-RE)
ls /sys/kernel/btf/vmlinux

# Générer le skeleton depuis le .bpf.c
clang -O2 -g -target bpf -c linux/bpf/canaris.bpf.c -o canaris.bpf.o
bpftool gen skeleton canaris.bpf.o > linux/userspace/canaris.skel.h

# Build userspace
make -C linux

# Charger (nécessite root ou CAP_BPF + CAP_SYS_ADMIN)
sudo ./linux/canaris

# Debug : voir les logs des programmes eBPF
sudo cat /sys/kernel/debug/tracing/trace_pipe

# Vérifier qu'un programme passe le verifier
sudo bpftool prog load canaris.bpf.o /sys/fs/bpf/canaris
```

### Windows (VM avec Test Signing)
```powershell
# Activer Test Signing dans la VM (jamais en prod)
bcdedit /set testsigning on   # puis reboot

# Build : Visual Studio + WDK (Windows Driver Kit) installés
msbuild windows\Canaris.sln /p:Configuration=Debug /p:Platform=x64

# Installer le minifilter
sc create Canaris type= filesys binPath= "C:\path\Canaris.sys"
fltmc load Canaris

# Vérifier le chargement
fltmc filters              # doit lister Canaris avec son altitude

# Décharger
fltmc unload Canaris
```

---

## 5. Conventions techniques

### eBPF
- **CO-RE obligatoire** (Compile Once Run Everywhere) via BTF — pas de dépendance aux headers du kernel cible
- Communication kernel→userspace : `BPF_MAP_TYPE_RINGBUF` (pas de perf buffer legacy)
- Compteurs d'I/O par PID : `BPF_MAP_TYPE_HASH` clé = PID, valeur = struct { count, window_start }
- Tout programme doit passer le **BPF verifier** — pas de boucle non bornée, pas de déréférencement non vérifié
- Les LSM hooks retournent `0` (autoriser) ou `-EPERM` (bloquer)

### Minifilter Windows
- **Altitude : 320000–329999** (plage FSFilter Anti-Virus) — à réserver, éviter les collisions avec Defender
- Callbacks : `IRP_MJ_CREATE`, `IRP_MJ_WRITE`, `IRP_MJ_SET_INFORMATION` (rename/delete)
- Blocage : `FLT_PREOP_COMPLETE` + `STATUS_ACCESS_DENIED` dans le pré-callback
- Communication : `FltCreateCommunicationPort` (kernel ↔ service userspace)
- Détection suppression VSS : `PsSetCreateProcessNotifyRoutineEx` surveillant `vssadmin.exe` / `wmic.exe` / `bcdedit.exe` avec arguments suspects
- **Pool memory** : toujours `ExAllocatePool2` (pas `ExAllocatePoolWithTag`, déprécié), libérer systématiquement
- Tester chaque callback avec Driver Verifier activé

### Canary files (générateur Python)
- Contenu crédible par extension : faux `.docx`/`.xlsx`/`.pdf` avec structure de fichier valide (magic bytes corrects)
- Tailles : distribution **log-normale** entre 50 Ko et 5 Mo (pas uniforme → paraît naturel)
- Timestamps : modifier `atime`, `mtime` **ET** `btime` (birth time) de façon cohérente
  - Linux : `os.utime` + `debugfs -w -R 'set_inode_field ... crtime'` pour btime
  - Windows : `SetFileTime` sur les trois timestamps
- **Éviter la haute entropie** : le contenu ne doit PAS ressembler à du chiffré (un ransomware saute les fichiers déjà haute-entropie). Contenu = texte/données structurées lisibles
- Placement : `Documents`, `Desktop`, `Downloads` + ≥ 2 niveaux de sous-dossiers

---

## 6. Contraintes de l'environnement (à connaître avant de coder)

| Contrainte | Impact | Conséquence pour le dev |
|---|---|---|
| **DSE** (Driver Signature Enforcement) | Windows 10 1607+ refuse les drivers non signés | Test Signing en VM ; WHQL requis pour la prod (hors scope étudiant) |
| **HVCI** | Bloque les drivers non-WHQL même DSE off | Désactiver HVCI dans la VM de test |
| **Secure Boot** | Bloque Test Signing | Désactivé dans la VM uniquement |
| **BPF verifier** | Rejette tout programme non prouvé sûr | Écrire des programmes simples, bornés, vérifiables |
| **kernel ≥ 5.7** | Requis pour LSM BPF | Cibler Ubuntu 22.04 (5.15) minimum |
| **BTF** (`/sys/kernel/btf/vmlinux`) | Requis pour CO-RE | Vérifier sa présence au démarrage |

---

## 7. Ordre de développement imposé

1. **Linux d'abord** (plus rapide, pas de contrainte de signature) : kprobe openat → log
2. LSM BPF hook `lsm/file_open` → blocage `-EPERM` sur canary
3. Générateur de canary files
4. Compteur d'I/O + threshold adaptatif + ring buffer
5. Responder Linux (kill + rsync snapshot)
6. **Windows ensuite** (VM Test Signing) : minifilter minimal → callbacks
7. VssGuard (détection suppression shadow copies)
8. Intégration, tests faux positifs, documentation

**Ne jamais commencer par Windows.** Le minifilter est la partie la plus risquée (BSOD) et la moins portable.

---

## 8. Règles de sécurité dev (STRICTES)

- ❌ Jamais de test kernel sur une machine physique de travail
- ❌ Jamais commiter de vrai malware dans le repo (utiliser RanSim ou un simulateur maison qui touche uniquement des fichiers de test)
- ❌ Jamais de RCON/secrets/mot de passe en clair dans le code ou la config
- ✅ VM dédiée avec snapshot pris avant chaque chargement de driver
- ✅ Driver Verifier activé pendant tout le dev Windows
- ✅ `bpftool prog load` pour valider un programme eBPF avant de le lancer réellement

---

## 9. Ce qui est HORS SCOPE (ne pas implémenter)

- Chiffrement préventif (supprimé — voir §2.1)
- Envoi de clé à une adresse de confiance (supprimé)
- macOS, systèmes embarqués
- Ransomwares in-memory / sans accès filesystem
- Ransomwares ciblant les hyperviseurs (ESXi)
- Déploiement production Windows signé WHQL (documenter la limitation, ne pas la résoudre)

---

## 10. Glossaire rapide

- **Minifilter** : driver de filtrage filesystem Windows, s'insère dans la pile I/O manager (Ring 0)
- **Altitude** : position d'un minifilter dans la pile de filtrage (unique, attribuée par plage)
- **eBPF** : machine virtuelle du kernel Linux exécutant du bytecode vérifié en toute sécurité
- **kprobe** : point d'observation sur une fonction kernel (read-only)
- **LSM BPF** : hooks Linux Security Module attachables en eBPF, capables de bloquer (return < 0)
- **CO-RE** : Compile Once Run Everywhere — portabilité eBPF via BTF
- **VSS** : Volume Shadow Copy Service (mécanisme de snapshot Windows)
- **CFA** : Controlled Folder Access (protection dossiers native de Defender — solution de repli)
- **DSE / HVCI** : mécanismes d'intégrité de code Windows bloquant les drivers non signés
