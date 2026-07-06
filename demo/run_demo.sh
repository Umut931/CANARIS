#!/usr/bin/env bash
# CANARIS — démo de bout en bout (Linux, root). Reproduit : génération de
# canaries -> chargement du moteur noyau -> simulateur ransomware (sandbox) ->
# détection -> kill + snapshot de préservation. Idéal pour la vidéo (cahier L6).
#
#   sudo ./demo/run_demo.sh
#
# Prérequis : make -C linux réussi (voir HANDOFF.md), python3, rsync.
# Pour le BLOCAGE synchrone, booter le kernel avec lsm=...,bpf (sinon mode
# dégradé : observation + kill, cf. docs/LIMITATIONS.md).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SANDBOX="$ROOT/tests/sandbox/demo"
SNAPS="$ROOT/snapshots"
LOG="$ROOT/canaris_events.log"
FILES="${1:-800}"

say() { printf '\n\033[1;36m== %s\033[0m\n' "$1"; }

[ "$(id -u)" -eq 0 ] || { echo "Ce démo nécessite root (chargement eBPF)."; exit 1; }

say "0. Build (si nécessaire)"
[ -x "$ROOT/linux/canaris" ] || make -C "$ROOT/linux"

say "1. Nettoyage + génération de canaries réalistes dans la sandbox"
CONTROL="$ROOT/tests/sandbox/.control"     # HORS de l'arbre protégé (T3)
rm -rf "$SANDBOX" "$LOG" "$CONTROL"; mkdir -p "$SANDBOX" "$CONTROL"
python3 "$ROOT/common/canary_generator.py" --target-dir "$SANDBOX" \
    --control-dir "$CONTROL" --count 15 --seed 7 --quiet
echo "Canaries générés :"; find "$SANDBOX" -type f | head -5
echo "Manifeste HORS arbre protégé : $CONTROL/canary_files.txt"

say "2. Chargement du moteur noyau CANARIS (protège la sandbox)"
"$ROOT/linux/canaris" \
    --protect "$SANDBOX" \
    --canary-list "$CONTROL/canary_files.txt" \
    --whitelist "$ROOT/config/whitelist.txt" \
    --thresholds "$ROOT/config/thresholds.conf" \
    --snapshot-root "$SNAPS" \
    --baseline-root "$ROOT/baselines" \
    --baseline-interval 30 \
    --log "$LOG" \
    --quiet &
CANARIS_PID=$!
trap 'kill -INT $CANARIS_PID 2>/dev/null || true' EXIT
sleep 2.5

say "3. Lancement du simulateur de ransomware (SANDBOX uniquement)"
echo "Le simulateur va lire/chiffrer/renommer $FILES fichiers..."
python3 "$ROOT/tests/ransim/simulate.py" --target "$SANDBOX" --files "$FILES" --run || true
sleep 2

say "4. Résultat : journal de détection/réponse"
cat "$LOG" 2>/dev/null || echo "(aucun log — LSM a peut-être tout bloqué)"

say "5. Préservation : baseline PROPRE (pris avant l'attaque)"
BL=$(ls -d "$ROOT"/baselines/baseline-* 2>/dev/null | tail -1)
if [ -n "$BL" ]; then
    echo "Dernier baseline : $BL"
    echo "  fichiers propres préservés : $(find "$BL" -type f | wc -l)"
    echo "  fichiers chiffrés dedans (doit être 0) : $(find "$BL" -name '*.CANARIS_LOCKED' | wc -l)"
    echo "  -> RESTAURATION possible depuis ce baseline (contenu original)."
fi
echo "(Le snapshot post-incident est FORENSIQUE, pas une source de restauration.)"

say "Démo terminée. (Ctrl-C déjà géré ; CANARIS s'arrête.)"
