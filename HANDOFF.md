# HANDOFF — Tests nécessitant un environnement privilégié

Ce fichier liste **tout ce qui ne peut pas être exécuté dans l'environnement de développement** (Windows/git-bash sans kernel Linux ni WDK/Test Signing) et doit être validé par l'utilisateur dans ses VM.

L'environnement de build utilisé pour ce projet est **Windows 11 + git-bash (MSYS2)** avec Python 3.14 et git. Il **ne dispose pas** de : clang/LLVM ciblant BPF, libbpf, bpftool, kernel Linux avec BTF, ni WDK/Visual Studio pour le driver Windows. Tout ce qui suit y est donc marqué `[HANDOFF]`.

Convention :
- **`[HANDOFF-LINUX-ROOT]`** — nécessite une VM Linux (kernel ≥ 5.7, BTF, LSM BPF activé, root)
- **`[HANDOFF-WIN-WDK]`** — nécessite une VM Windows avec WDK + Test Signing + HVCI désactivé

> **Déjà validé pendant le dev** (via Docker `--privileged` sur le kernel WSL2 6.18,
> voir `docs/VALIDATION.md`) : compilation CO-RE, **BPF verifier** (kprobes + 3 LSM),
> observation live des syscalls, détection scopée + snapshot end-to-end, tests C
> (`profiles.c`/`responder.c`/`vssguard_rules.h`) et 47 tests Python. Restent ci-dessous
> ce qui exige le kernel cible bootté `lsm=…,bpf` (enforcement) ou une VM Windows WDK.
>
> Démo/bench prêts : `demo/run_demo.sh` (détection→snapshot pour la vidéo),
> `demo/benchmark_io.sh` (surcoût I/O R8).

---

## Prérequis VM Linux (root)

```bash
# Ubuntu 22.04+ recommandé (kernel 5.15+)
sudo apt update
sudo apt install -y clang llvm libbpf-dev linux-tools-common \
    linux-tools-$(uname -r) bpftool make gcc pkg-config libelf-dev rsync

# 1. Vérifier le support BTF (obligatoire pour CO-RE)
ls -l /sys/kernel/btf/vmlinux      # doit exister

# 2. Vérifier que LSM BPF est activé dans le kernel
cat /sys/kernel/security/lsm       # doit contenir "bpf"
# Sinon : ajouter "lsm=...,bpf" à GRUB_CMDLINE_LINUX, update-grub, reboot
#   GRUB_CMDLINE_LINUX="lsm=lockdown,capability,yama,apparmor,bpf"

# 3. Vérifier le kernel
uname -r                           # >= 5.7 pour LSM BPF, >= 5.15 conseillé
```

---

## Tests VM Linux (root)

### [HANDOFF-LINUX-ROOT] T-L1 — Build complet (compile + skeleton)

> Checkpoint Phase 1 : `clang -O2 -g -target bpf` compile sans erreur, skeleton généré.

```bash
cd CANARIS
# Générer vmlinux.h (CO-RE) si absent :
bpftool btf dump file /sys/kernel/btf/vmlinux format c > linux/bpf/vmlinux.h

make -C linux                      # doit produire linux/canaris sans erreur
```
**Attendu** : `linux/canaris` créé, aucune erreur de compilation, `canaris.skel.h` généré.

### [HANDOFF-LINUX-ROOT] T-L2 — BPF verifier (chargement à sec)

> Checkpoint Phases 1 & 2 : le programme passe le verifier.

```bash
sudo bpftool prog load linux/bpf/canaris.bpf.o /sys/fs/bpf/canaris_test
# Si succès : aucun message d'erreur, /sys/fs/bpf/canaris_test créé
sudo rm /sys/fs/bpf/canaris_test
```
**Attendu** : chargement accepté (verifier OK). En cas d'échec, le verifier imprime le log d'instructions fautif.

### [HANDOFF-LINUX-ROOT] T-L3 — Observation kprobe (Phase 1, exigence F2.4)

```bash
sudo ./linux/canaris --protect /tmp/canaris_demo &
sleep 1
mkdir -p /tmp/canaris_demo && echo test > /tmp/canaris_demo/file.txt
cat /tmp/canaris_demo/file.txt
# Observer la sortie : événements openat/write/unlinkat affichés
sudo cat /sys/kernel/debug/tracing/trace_pipe   # logs bruts des progs eBPF
```
**Attendu** : chaque accès fichier produit un événement dans la boucle ring buffer.

### [HANDOFF-LINUX-ROOT] T-L4 — Blocage LSM BPF sur canary (Phase 2, exigence F2.5, recette R1)

```bash
# 1. Générer un canary et le déclarer protégé
python3 common/canary_generator.py --target-dir /tmp/canaris_demo --count 1 --extensions txt
sudo ./linux/canaris --protect /tmp/canaris_demo --config config/profiles.json &

# 2. Processus NON whitelisté tente de lire/écrire le canary
cat /tmp/canaris_demo/RIB_2023.pdf        # attendu : "Permission denied" (-EPERM)

# 3. Processus whitelisté (ex: rsync ajouté à la whitelist) : autorisé
```
**Attendu (R1)** : accès depuis process non whitelisté → `Permission denied` + log ; process whitelisté → autorisé.

### [HANDOFF-LINUX-ROOT] T-L5 — Simulateur ransomware → kill + snapshot (Phase 4, recette R2)

```bash
sudo ./linux/canaris --protect tests/sandbox --config config/profiles.json &
python3 tests/ransim/simulate.py --target tests/sandbox --files 200 --window 2
```
**Attendu (R2)** : détection < 500 ms, process simulateur tué, snapshot rsync créé dans `snapshots/<timestamp>/`. Mesurer le délai imprimé par le responder.

### [HANDOFF-LINUX-ROOT] T-L6 — Fallback si LSM BPF indisponible

Si `cat /sys/kernel/security/lsm` ne contient pas `bpf` et qu'on ne peut pas modifier GRUB :
```bash
# Le loader détecte l'absence de LSM BPF et bascule en mode kretprobe + signal.
sudo ./linux/canaris --protect tests/sandbox --force-fallback
```
**Attendu** : observation + kill sur détection (blocage best-effort, documenté comme dégradé).

---

## Prérequis VM Windows (WDK + Test Signing)

⚠️ **Prendre un snapshot VM AVANT tout chargement de driver.** Un minifilter bugué peut BSOD.

```powershell
# 1. Activer Test Signing (jamais en prod)
bcdedit /set testsigning on
# 2. Désactiver HVCI (bloque les drivers non-WHQL même Test Signing on)
#    Sécurité Windows > Sécurité des appareils > Isolation du noyau > Intégrité mémoire = OFF
# 3. (VM) Désactiver Secure Boot dans les paramètres du firmware VM
# 4. Reboot
# 5. Activer Driver Verifier sur le driver pendant tout le dev
verifier /standard /driver Canaris.sys
```

---

## Tests VM Windows (WDK + Test Signing)

### [HANDOFF-WIN-WDK] T-W1 — Build du driver + service

```powershell
# WDK + Visual Studio 2022 installés
msbuild windows\Canaris.sln /p:Configuration=Debug /p:Platform=x64
```
**Attendu** : `Canaris.sys`, `Canaris.inf`, `CanarisSvc.exe` produits sans erreur.

### [HANDOFF-WIN-WDK] T-W2 — Chargement minifilter (recette R3)

```powershell
sc create Canaris type= filesys binPath= "C:\path\Canaris.sys"
fltmc load Canaris
fltmc filters            # doit lister "Canaris" avec son altitude (320000-329999)
```
**Attendu (R3)** : Canaris listé, aucun BSOD.

### [HANDOFF-WIN-WDK] T-W2.5 — Configuration + démarrage du service

Le service pousse la config au driver et traite les alertes (kill + VSS).
Placer les fichiers de config dans `C:\ProgramData\Canaris\` :

```powershell
mkdir C:\ProgramData\Canaris -Force
# dossiers protégés (un chemin DOS par ligne)
"C:\CanarisDemo" | Out-File -Encoding ascii C:\ProgramData\Canaris\protected_dirs.txt
# canaries : réutiliser la liste produite par le générateur
copy C:\CanarisDemo\canary_files.txt C:\ProgramData\Canaris\canary_files.txt
# whitelist : noms/chemins d'exécutables de confiance (un par ligne)
"OneDrive.exe`nMsMpEng.exe`nCode.exe" | Out-File -Encoding ascii C:\ProgramData\Canaris\whitelist.txt

# lancer le service en mode console (test)
.\x64\Debug\CanarisSvc.exe --console
# (production : sc create CanarisSvc binPath= "...CanarisSvc.exe" start= auto ; sc start CanarisSvc)
```
**Attendu** : « Configuration poussee au minifilter. » dans le log
`C:\ProgramData\Canaris\canaris_events.log`.

### [HANDOFF-WIN-WDK] T-W3 — Blocage canary (exigence F2.2)

```powershell
# Générer un canary, le déclarer protégé (voir T-W2.5), tenter d'y écrire
python common\canary_generator.py --target-dir C:\CanarisDemo --count 1
notepad C:\CanarisDemo\RIB_2023.pdf   # tentative d'écriture → STATUS_ACCESS_DENIED
```
**Attendu** : accès refusé (`STATUS_ACCESS_DENIED`), notification au service
→ log `ALERTE CANARY/BLOCKED pid=… cible=…`, puis kill + snapshot VSS.

### [HANDOFF-WIN-WDK] T-W4 — RanSim (KnowBe4) (recette R4)

```powershell
# Installer RanSim dans la VM, lancer les scénarios
# Attendu : détection comportementale + kill + déclenchement VSS
```
**Attendu (R4)** : détection + réponse déclenchée.

### [HANDOFF-WIN-WDK] T-W5 — VssGuard : suppression VSS (recette R5)

```powershell
vssadmin delete shadows /all         # dans la VM
# ou : wmic shadowcopy delete
```
**Attendu (R5)** : alerte **priorité maximale immédiate** déclenchée (indépendante du seuil I/O), avant tout chiffrement. Optionnellement, l'exécution est bloquée.

### [HANDOFF-WIN-WDK] T-W6 — Benchmark latence I/O (recette R8, NF1)

```powershell
# Mesurer le débit I/O avec et sans le minifilter chargé (ex: diskspd)
diskspd -c1G -d30 -w50 C:\bench\testfile.dat   # filtre déchargé
fltmc load Canaris
diskspd -c1G -d30 -w50 C:\bench\testfile.dat   # filtre chargé
```
**Attendu (R8/NF1)** : surcoût < 5 %.

---

## Récapitulatif des tests exécutables automatiquement (hors HANDOFF)

Ces tests **sont** lancés dans l'environnement de dev (Python) — voir `tests/` :
- ✅ Entropie des canary files < 6 bits/octet
- ✅ Distribution des tailles ∈ [50 Ko, 5 Mo]
- ✅ Magic bytes corrects par extension
- ✅ mtime modifié dans le passé
- ✅ Logique de détection (compteur I/O, profils curatés par processus) sur traces simulées
- ✅ Parsing des command-lines VssGuard (vssadmin/wmic/bcdedit)
- ✅ Faux positifs = 0 sur workloads simulés (npm install, git clone, OneDrive)
