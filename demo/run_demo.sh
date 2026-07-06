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
rm -rf "$SANDBOX" "$LOG"; mkdir -p "$SANDBOX"
python3 "$ROOT/common/canary_generator.py" --target-dir "$SANDBOX" --count 15 --seed 7 --quiet
echo "Canaries générés :"; find "$SANDBOX" -type f | head -5

say "2. Chargement du moteur noyau CANARIS (protège la sandbox)"
"$ROOT/linux/canaris" \
    --protect "$SANDBOX" \
    --canary-list "$SANDBOX/canary_files.txt" \
    --whitelist "$ROOT/config/whitelist.txt" \
    --thresholds "$ROOT/config/thresholds.conf" \
    --snapshot-root "$SNAPS" \
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

say "5. Snapshot de préservation créé"
ls -1 "$SNAPS" 2>/dev/null | tail -1 | while read -r s; do
    echo "snapshots/$s : $(find "$SNAPS/$s" -type f | wc -l) fichiers préservés"
done

say "Démo terminée. (Ctrl-C déjà géré ; CANARIS s'arrête.)"
