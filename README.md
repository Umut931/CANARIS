# CANARIS

**Logiciel anti-ransomware multi-OS à interception noyau.**

> 🚧 **Statut : en construction.** Composant Linux (eBPF + LSM BPF) prioritaire, composant Windows (minifilter) en second. Voir le [cahier des charges](CAHIER_DES_CHARGES.md) et le [contexte projet](CLAUDE.md).

CANARIS détecte et stoppe un ransomware **en cours de chiffrement**, puis préserve les données via un **baseline propre pris avant l'attaque** — le tout depuis le noyau, hors de portée du malware. Aucune signature : la détection est **comportementale**.

---

## Matrice PROUVÉ ICI ✅ / À VALIDER EN VM 🖥️ (recette §10)

> Honnêteté avant tout : **aucun mécanisme marqué 🖥️ n'est présenté comme validé.**
> Les deux piliers de la thèse sécurité — **blocage LSM `-EPERM`** et **kill réel** —
> n'ont pas pu être exécutés dans l'env de dev (Docker/WSL2 sans `bpf` LSM actif ni
> init-namespace) ; des harnais turnkey les prouvent en VM (`vm/`).

| # | Exigence | Prouvé ICI (comment) | À valider en VM (script) |
|---|---|---|---|
| R1 | Blocage `-EPERM` sur canary (Linux) | Verifier LSM OK sur les 3 hooks (Docker/WSL2) ; logique prouvée | 🖥️ `vm/validate_enforce.sh` (kernel `lsm=…,bpf`) |
| R2 | Détection→kill→snapshot | Détection scopée + **baseline avant attaque** E2E réel ; kill+latence unit C (47 ms) ; baseline préserve l'original malgré chiffreur 7 ms | 🖥️ `vm/validate_kill.sh` (VM native) |
| R3 | Chargement minifilter | Revue statique (`windows/REVIEW_NOTES.md`) — **jamais compilé** | 🖥️ `vm/build_windows.ps1` + `vm/validate_windows.md` |
| R4 | RanSim en VM Windows | — | 🖥️ `vm/validate_windows.md` §5 |
| R5 | Suppression VSS → alerte | Matching command-lines testé (C + Python) | 🖥️ `vm/validate_windows.md` §6 |
| R6 | npm install → 0 faux positif | 0 FP sur workloads **synthétiques** (56 tests) | 🖥️ `vm/fp_workload.sh` (npm **réel**) |
| R7 | git/rsync/sync → 0 faux positif | 0 FP synthétiques | 🖥️ `vm/fp_workload.sh` (git/rsync **réels**) |
| R8 | Surcoût latence I/O < 5 % | — | 🖥️ `demo/benchmark_io.sh` (Lin) / `vm/validate_windows.md` §7 (Win) |

Preuves d'exécution détaillées : [docs/VALIDATION.md](docs/VALIDATION.md). Limites
assumées : [docs/LIMITATIONS.md](docs/LIMITATIONS.md).

---

## Les trois piliers

| Pilier | Rôle | Linux | Windows |
|---|---|---|---|
| **1. Canary files** | Leurres réalistes, faible entropie, indétectables par heuristique | `common/canary_generator.py` | idem (cross-OS) |
| **2. Interception noyau** | Blocage réel des I/O malveillantes (Ring 0) | eBPF kprobes (observation) + **LSM BPF** (blocage `-EPERM`) | Minifilter (`STATUS_ACCESS_DENIED`) |
| **3. Réaction de préservation** | Kill du processus + snapshot instantané | `rsync --link-dest` | VSS via IOCTL |

> ⚠️ **Pas de chiffrement préventif.

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
