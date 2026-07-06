# CANARIS

**Logiciel anti-ransomware multi-OS à interception noyau.**

> 🚧 **Statut : en construction.** Composant Linux (eBPF + LSM BPF) prioritaire, composant Windows (minifilter) en second. Voir le [cahier des charges](CAHIER_DES_CHARGES.md) et le [contexte projet](CLAUDE.md).

CANARIS détecte et stoppe un ransomware **en cours de chiffrement**, puis préserve les données via snapshot — le tout depuis le noyau, hors de portée du malware. Aucune signature : la détection est **comportementale**.

---

## Les trois piliers

| Pilier | Rôle | Linux | Windows |
|---|---|---|---|
| **1. Canary files** | Leurres réalistes, faible entropie, indétectables par heuristique | `common/canary_generator.py` | idem (cross-OS) |
| **2. Interception noyau** | Blocage réel des I/O malveillantes (Ring 0) | eBPF kprobes (observation) + **LSM BPF** (blocage `-EPERM`) | Minifilter (`STATUS_ACCESS_DENIED`) |
| **3. Réaction de préservation** | Kill du processus + snapshot instantané | `rsync --link-dest` | VSS via IOCTL |

> ⚠️ **Pas de chiffrement préventif.** Décision d'architecture non négociable (voir [CLAUDE.md §2.1](CLAUDE.md)). La seule réponse de préservation est le **snapshot**.

---

## Architecture

```
CANARY FILES (leurres) ──accès détecté──┐
                                        │
        ┌───────────────┐        ┌──────┴────────┐
        │   WINDOWS      │        │    LINUX       │
        │  Minifilter    │        │ eBPF + LSM BPF │
        │  (Ring 0)      │        │  (kernel)      │
        │  STATUS_ACCESS_│        │  return -EPERM │
        │  DENIED        │        │  ring buffer   │
        │  VssGuard      │        │                │
        └──────┬─────────┘        └──────┬─────────┘
     comm port │                         │ ring buffer
        ┌───────▼────────┐        ┌───────▼────────┐
        │ Service         │       │ Userspace       │
        │ kill + VSS snap │       │ kill + rsync    │
        └─────────────────┘       └─────────────────┘
```

Détail dans [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

---

## Démarrage rapide (Linux — composant prioritaire)

```bash
# Dépendances (Ubuntu 22.04+, kernel >= 5.15 avec BTF + LSM BPF)
sudo apt install clang llvm libbpf-dev linux-tools-$(uname -r) bpftool make

# Build (génère le skeleton + compile le loader)
make -C linux

# Charger (root ou CAP_BPF + CAP_SYS_ADMIN)
sudo ./linux/canaris --protect ~/Documents --config config/profiles.json

# Générer des canary files réalistes
python3 common/canary_generator.py --target-dir ~/Documents --count 20
```

Instructions de test complètes (VM Linux root, VM Windows WDK) : [HANDOFF.md](HANDOFF.md).

---

## État de la recette (cahier des charges §10)

| # | Test | Statut |
|---|---|---|
| R1 | Blocage `-EPERM` sur accès canary (Linux) | ✅ verifier LSM OK (Docker/WSL2) · 🖥️ enforcement HANDOFF (VM `lsm=…,bpf`) |
| R2 | Simulateur ransomware → kill + snapshot < 500 ms | ✅ détection+snapshot E2E réel + kill/latence unit C (47 ms) · 🖥️ E2E VM native |
| R3 | Chargement minifilter (VM Win) | 🖥️ HANDOFF (VM WDK) |
| R4 | RanSim en VM Windows | 🖥️ HANDOFF |
| R5 | Suppression VSS → alerte prioritaire | ✅ matching testé (C + Python) · 🖥️ driver HANDOFF (VM) |
| R6 | npm install → zéro faux positif | ✅ testé (simulé) |
| R7 | OneDrive + git clone → zéro faux positif | ✅ testé (simulé) |
| R8 | Benchmark latence I/O < 5 % | 🖥️ HANDOFF (VM, `demo/benchmark_io.sh`) |

Légende : ✅ testé automatiquement · 🖥️ à valider en VM (voir [HANDOFF.md](HANDOFF.md)).
Preuves d'exécution détaillées : [docs/VALIDATION.md](docs/VALIDATION.md).

---

## Limitation majeure assumée

En production Windows moderne (Secure Boot + HVCI), un minifilter non signé **WHQL** ne peut pas se charger. CANARIS Windows est démontrable **en VM (Test Signing)** mais non déployable en l'état. Cette limitation est **documentée et non résolue** (le coût WHQL dépasse le cadre d'un projet étudiant). Repli documenté : Controlled Folder Access + ETW. Détails : [docs/LIMITATIONS.md](docs/LIMITATIONS.md).

---

## Sécurité du développement

- ❌ Jamais de test kernel sur machine physique de travail — **VM dédiée uniquement**, snapshot avant chaque chargement de driver.
- ❌ Jamais de vrai malware dans le repo — le simulateur ne touche que `tests/sandbox/`.
- ✅ `bpftool prog load` (BPF verifier) et Driver Verifier obligatoires avant tout chargement réel.

---

## Licence & auteur

Umut Celikler — Bachelor Cybersécurité & Ethical Hacking, EFREI Paris. Projet de portfolio technique à visée démonstrative.
