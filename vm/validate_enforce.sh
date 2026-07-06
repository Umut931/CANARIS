#!/usr/bin/env bash
# CANARIS — [HANDOFF-VM] validation TURNKEY du blocage LSM -EPERM (recette R1).
#
# Prouve que, LSM bpf actif, l'accès à un canary par un EXÉCUTABLE non whitelisté
# est REFUSÉ (-EPERM) au niveau kernel, tandis qu'un exécutable whitelisté (par
# inode) est autorisé. Verdict PASS/FAIL non ambigu + preuve horodatée.
#
#   sudo ./vm/validate_enforce.sh
#
# Ce script REFUSE de rapporter PASS si l'environnement n'est pas le bon (pas de
# LSM bpf actif) : il imprime alors la remédiation exacte (voir setup_lsm_vm.md).
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
EV="$ROOT/vm/evidence/enforce_$(date +%Y%m%d-%H%M%S).log"
mkdir -p "$ROOT/vm/evidence"

log(){ echo "$@" | tee -a "$EV"; }
fail(){ log "VERDICT: FAIL — $*"; exit 1; }

log "=== CANARIS validate_enforce $(date -Is) ==="
log "kernel: $(uname -r)"

# 0. root
[ "$(id -u)" -eq 0 ] || fail "root requis (chargement eBPF)."

# 1. LSM bpf actif — sinon remédiation exacte et FAIL (jamais de PASS ici).
LSM="$(cat /sys/kernel/security/lsm 2>/dev/null || echo '')"
log "LSM actifs: $LSM"
if ! echo "$LSM" | grep -q bpf; then
    log "ERREUR: le LSM 'bpf' n'est PAS actif — le blocage -EPERM est impossible."
    log "Remédiation : ajouter 'bpf' à GRUB_CMDLINE_LINUX (lsm=...,bpf), update-grub, reboot."
    log "Détails : vm/setup_lsm_vm.md"
    fail "environnement inadapté (LSM bpf inactif)."
fi

# 2. build
[ -x "$ROOT/linux/canaris" ] || make -C "$ROOT/linux" 2>&1 | tee -a "$EV" || fail "build échoué"

# 3. préparation : dossier protégé + canary + un lecteur whitelisté
WORK="$(mktemp -d /tmp/canaris_enforce.XXXXXX)"
CTRL="$WORK/.control"; DOCS="$WORK/docs"; mkdir -p "$DOCS" "$CTRL"
python3 "$ROOT/common/canary_generator.py" --target-dir "$DOCS" --control-dir "$CTRL" \
    --count 1 --extensions txt --seed 1 --quiet 2>&1 | tee -a "$EV"
CANARY="$(head -1 "$CTRL/canary_files.txt")"
[ -f "$CANARY" ] || fail "canary introuvable"
log "canary: $CANARY"

# lecteur whitelisté = copie de /bin/cat, dont l'inode est whitelisté
GOOD="$WORK/goodreader"; cp "$(command -v cat)" "$GOOD"
echo "$GOOD" > "$WORK/wl.txt"

# 4. charge le moteur en ENFORCE, protège le dossier + canary
"$ROOT/linux/canaris" --protect "$DOCS" --canary "$CANARY" --whitelist "$WORK/wl.txt" \
    --baseline-interval 0 --snapshot-root "$WORK/sn" --baseline-root "$WORK/bl" \
    --log "$WORK/c.log" -q >"$WORK/loader.out" 2>&1 &
LP=$!
trap 'kill -INT $LP 2>/dev/null; rm -rf "$WORK"' EXIT
sleep 3

# confirme que le loader est bien en ENFORCE (pas dégradé)
if grep -qi "DÉGRADÉ\|indisponible" "$WORK/loader.out"; then
    log "$(cat "$WORK/loader.out")"
    fail "le loader a basculé en mode dégradé (LSM inactif malgré la liste ?)."
fi

# 5. TEST 1 : lecture par un process NON whitelisté -> doit être REFUSÉE
log "--- Test 1 : cat (non whitelisté) lit le canary ---"
if OUT="$(cat "$CANARY" 2>&1)"; then
    log "RÉSULTAT: lecture AUTORISÉE (inattendu) : ${OUT:0:40}"
    T1=FAIL
else
    log "RÉSULTAT: lecture REFUSÉE -> $OUT"
    echo "$OUT" | grep -qi "denied\|non autoris\|permission" && T1=PASS || T1=FAIL
fi
log "Test 1 (blocage non whitelisté): $T1"

# 6. TEST 2 : lecture par l'exécutable whitelisté -> doit être AUTORISÉE
log "--- Test 2 : goodreader (whitelisté par inode) lit le canary ---"
if "$GOOD" "$CANARY" >/dev/null 2>&1; then
    log "RÉSULTAT: lecture AUTORISÉE"; T2=PASS
else
    log "RÉSULTAT: lecture REFUSÉE (inattendu pour un exécutable whitelisté)"; T2=FAIL
fi
log "Test 2 (exemption whitelisté): $T2"

# 7. verdict
if [ "$T1" = PASS ] && [ "$T2" = PASS ]; then
    log "VERDICT: PASS — blocage -EPERM confirmé (R1) ; whitelist par inode confirmée."
    exit 0
fi
fail "un test a échoué (T1=$T1 T2=$T2)."
