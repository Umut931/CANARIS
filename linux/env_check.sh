#!/usr/bin/env bash
# CANARIS — vérification de l'environnement Linux avant build/chargement eBPF.
# Vérifie : kernel, BTF (CO-RE), LSM BPF activé, toolchain (clang/libbpf/bpftool).
# Sortie : code 0 si prêt pour build + LSM BPF, 1 si BTF/toolchain manquant,
#          2 si buildable mais LSM BPF indisponible (mode fallback nécessaire).
set -u

green() { printf '\033[32m✓\033[0m %s\n' "$1"; }
yellow(){ printf '\033[33m!\033[0m %s\n' "$1"; }
red()   { printf '\033[31m✗\033[0m %s\n' "$1"; }

rc=0

echo "=== CANARIS env_check ==="

# 1. Kernel
kver=$(uname -r)
kmaj=$(echo "$kver" | cut -d. -f1)
kmin=$(echo "$kver" | cut -d. -f2)
if [ "$kmaj" -gt 5 ] || { [ "$kmaj" -eq 5 ] && [ "$kmin" -ge 7 ]; }; then
  green "Kernel $kver (>= 5.7, LSM BPF supporté)"
else
  red "Kernel $kver < 5.7 — LSM BPF indisponible, mode fallback obligatoire"
  rc=2
fi

# 2. BTF (obligatoire pour CO-RE)
if [ -r /sys/kernel/btf/vmlinux ]; then
  green "BTF présent (/sys/kernel/btf/vmlinux) — CO-RE OK"
else
  red "BTF absent — CO-RE impossible. Recompiler le kernel avec CONFIG_DEBUG_INFO_BTF=y"
  rc=1
fi

# 3. LSM BPF activé
if [ -r /sys/kernel/security/lsm ]; then
  if grep -q bpf /sys/kernel/security/lsm; then
    green "LSM BPF activé ($(cat /sys/kernel/security/lsm))"
  else
    yellow "LSM 'bpf' absent de $(cat /sys/kernel/security/lsm)"
    yellow "  -> Ajouter 'bpf' à GRUB_CMDLINE_LINUX (lsm=...,bpf), update-grub, reboot"
    [ "$rc" -eq 0 ] && rc=2
  fi
else
  yellow "/sys/kernel/security/lsm illisible (securityfs non monté ?)"
  [ "$rc" -eq 0 ] && rc=2
fi

# 4. Toolchain
for tool in clang bpftool make; do
  if command -v "$tool" >/dev/null 2>&1; then
    green "$tool présent ($(command -v $tool))"
  else
    red "$tool absent — sudo apt install clang bpftool make llvm libbpf-dev"
    rc=1
  fi
done

# 5. libbpf (header)
if [ -f /usr/include/bpf/libbpf.h ] || ls /usr/include/*/bpf/libbpf.h >/dev/null 2>&1; then
  green "libbpf headers présents"
else
  yellow "libbpf.h introuvable — sudo apt install libbpf-dev"
fi

echo "=== résultat: rc=$rc (0=prêt, 1=build impossible, 2=fallback requis) ==="
exit $rc
