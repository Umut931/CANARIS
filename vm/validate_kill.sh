#!/usr/bin/env bash
# CANARIS — [HANDOFF-VM] validation TURNKEY du KILL réel du responder (recette R2).
#
# Sur VM NATIVE (init PID-namespace : le PID rapporté par eBPF == PID réel), lance
# un simulateur de ransomware LONG dans la sandbox et prouve que le responder tue
# le VRAI processus (kill=ok) et préserve les données via le baseline propre.
# Verdict PASS/FAIL non ambigu + preuve horodatée.
#
#   sudo ./vm/validate_kill.sh
#
# NB : ce test fonctionne même en mode dégradé (sans LSM bpf) — il valide la
# chaîne détection -> kill -> baseline, pas le blocage synchrone (voir
# validate_enforce.sh pour ça).
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
EV="$ROOT/vm/evidence/kill_$(date +%Y%m%d-%H%M%S).log"
mkdir -p "$ROOT/vm/evidence"
log(){ echo "$@" | tee -a "$EV"; }
fail(){ log "VERDICT: FAIL — $*"; exit 1; }

log "=== CANARIS validate_kill $(date -Is) ==="
[ "$(id -u)" -eq 0 ] || fail "root requis (chargement eBPF)."

# Refuse un environnement conteneurisé où le PID eBPF (init-ns) n'est pas killable.
if [ -f /run/.containerenv ] || grep -qa 'docker\|lxc\|containerd' /proc/1/cgroup 2>/dev/null; then
    log "ATTENTION: environnement conteneurisé détecté."
    log "Le kill peut échouer (décalage de PID-namespace : le PID eBPF est celui de"
    log "l'init-namespace, non killable ici). Exécuter ce test sur une VM NATIVE."
    fail "conteneur détecté — exécuter sur VM native."
fi

[ -x "$ROOT/linux/canaris" ] || make -C "$ROOT/linux" 2>&1 | tee -a "$EV" || fail "build échoué"

WORK="$(mktemp -d /tmp/canaris_kill.XXXXXX)"
DOCS="$WORK/docs"; mkdir -p "$DOCS"
for i in $(seq 1 40); do echo "donnees originales $i" > "$DOCS/doc_$i.txt"; done

# loader : baseline initial + détection + responder (mode -o : peu importe LSM ici)
"$ROOT/linux/canaris" --protect "$DOCS" --baseline-interval 3600 \
    --snapshot-root "$WORK/sn" --baseline-root "$WORK/bl" \
    --log "$WORK/c.log" -o -q >"$WORK/loader.out" 2>&1 &
LP=$!
trap 'kill -INT $LP 2>/dev/null; rm -rf "$WORK"' EXIT
sleep 3

# baseline propre pris avant l'attaque ?
BL="$(ls -d "$WORK"/bl/baseline-* 2>/dev/null | head -1)"
NB=$(find "$BL" -name 'doc_*.txt' 2>/dev/null | wc -l)
log "baseline initial: $BL ($NB fichiers propres)"
[ "$NB" -ge 40 ] || fail "baseline initial incomplet ($NB/40)."

# simulateur LONG (assez de fichiers pour rester vivant pendant la réaction)
log "--- lancement du simulateur ransomware (sandbox) ---"
python3 "$ROOT/tests/ransim/simulate.py" --target "$DOCS" --files 4000 --run >/dev/null 2>&1 &
SIM=$!
sleep 3

if kill -0 "$SIM" 2>/dev/null; then
    log "simulateur (pid $SIM) encore vivant après 3s -> a-t-il été tué par CANARIS ?"
fi
sleep 2
# le simulateur a-t-il été tué par CANARIS (kill=ok dans le log) ?
if grep -qi "kill=ok" "$WORK/c.log"; then KILL=PASS; else KILL=FAIL; fi
log "$(grep REPONSE "$WORK/c.log" | head -2)"
log "kill par CANARIS: $KILL"

# le baseline reste propre (aucun chiffré) et contient l'original
LOCKED_IN_BL=$(find "$BL" -name '*.CANARIS_LOCKED' 2>/dev/null | wc -l)
log "fichiers chiffrés dans le baseline (doit être 0): $LOCKED_IN_BL"
[ "$LOCKED_IN_BL" -eq 0 ] || fail "le baseline contient du chiffré (bug de préservation)."

kill -INT $LP 2>/dev/null; wait $LP 2>/dev/null || true

if [ "$KILL" = PASS ]; then
    log "VERDICT: PASS — kill réel confirmé (R2) + baseline propre préservé."
    exit 0
fi
fail "kill non confirmé (voir $WORK/c.log)."
