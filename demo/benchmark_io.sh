#!/usr/bin/env bash
# CANARIS — benchmark de la latence I/O ajoutée par l'interception (cahier NF1/R8).
# Mesure le temps de création/écriture/lecture de N fichiers hors zone protégée,
# SANS puis AVEC le moteur CANARIS chargé, et calcule le surcoût (cible < 5 %).
#
#   sudo ./demo/benchmark_io.sh
#
# [HANDOFF-LINUX-ROOT] : nécessite root (chargement eBPF). Résultat à reporter
# dans docs/VALIDATION.md.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BENCH="/tmp/canaris_bench"
PROTECTED="/tmp/canaris_protected"
N="${1:-5000}"

[ "$(id -u)" -eq 0 ] || { echo "root requis"; exit 1; }
[ -x "$ROOT/linux/canaris" ] || make -C "$ROOT/linux"

workload() {
    local dir="$1"
    rm -rf "$dir"; mkdir -p "$dir"
    local start end
    start=$(date +%s.%N)
    for i in $(seq 1 "$N"); do
        printf 'contenu de test %d\n' "$i" > "$dir/f_$i.txt"
        cat "$dir/f_$i.txt" > /dev/null
    done
    end=$(date +%s.%N)
    echo "$end - $start" | bc -l
}

echo "== Benchmark I/O CANARIS ($N fichiers) =="

echo "-- 1. Baseline (moteur NON chargé) --"
BASE=$(workload "$BENCH")
printf "baseline : %.3f s\n" "$BASE"

echo "-- 2. Avec CANARIS chargé (zone protégée séparée) --"
mkdir -p "$PROTECTED"
"$ROOT/linux/canaris" --protect "$PROTECTED" --log /tmp/canaris_bench.log \
    --snapshot-root /tmp/canaris_bench_snaps &
CPID=$!
trap 'kill -INT $CPID 2>/dev/null || true' EXIT
sleep 2.5
WITH=$(workload "$BENCH")
printf "avec CANARIS : %.3f s\n" "$WITH"

OVER=$(echo "scale=2; ($WITH - $BASE) / $BASE * 100" | bc -l)
echo "-- Surcoût : ${OVER}% (cible NF1 < 5%) --"
