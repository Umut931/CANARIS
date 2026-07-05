# Environnement de build utilisé

Détection réalisée au démarrage du projet (Phase 0). Enregistrée pour transparence.

| Élément | Valeur détectée | Impact |
|---|---|---|
| OS de dev | Windows 11 Pro (build 26200) + git-bash MSYS2 | Pas de kernel Linux → eBPF non chargeable ici |
| Python | 3.14.5 (`python`) | ✅ générateur + tests exécutables |
| git | 2.54.0.windows.1 | ✅ versioning |
| clang / LLVM (BPF) | absent | ⚠️ compile eBPF → `[HANDOFF-LINUX-ROOT]` (T-L1) |
| libbpf / bpftool | absent | ⚠️ skeleton + verifier → `[HANDOFF-LINUX-ROOT]` (T-L2) |
| BTF (`/sys/kernel/btf/vmlinux`) | absent (Windows) | ⚠️ CO-RE → VM |
| WDK / MSVC | non requis ici | ⚠️ build driver → `[HANDOFF-WIN-WDK]` (T-W1) |
| WSL | 1 distro (`docker-desktop`, minimale) | Non utilisable comme env de build général |
| Docker | CLI présent, daemon variable | Best-effort pour compiler l'eBPF si disponible |

**Conséquence** : tout le code est écrit intégralement ; les tests Python sont exécutés ici ;
la compilation eBPF, le BPF verifier, le chargement LSM BPF et le build/chargement du minifilter
Windows sont documentés dans [../HANDOFF.md](../HANDOFF.md) avec commandes exactes.
