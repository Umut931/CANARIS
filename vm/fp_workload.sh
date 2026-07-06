#!/usr/bin/env bash
# CANARIS — [HANDOFF-VM] mesure des FAUX POSITIFS sur de VRAIS workloads (R6/R7/NF5).
#
# Charge CANARIS sur un répertoire de travail réel, lance de VRAIS logiciels
# légitimes (npm install, git clone, rsync d'une grosse arbo) exécutés par leurs
# VRAIS binaires (whitelistés par inode), et compte les réactions de CANARIS.
# Objectif NF5 : < 1 % des sessions déclenchent une réaction (idéalement 0).
#
#   sudo ./vm/fp_workload.sh
#
# Remplace la prétention « 0 faux positif » (synthétique, prouvée en dev) par une
# mesure reproductible sur workloads réels. Certains workloads nécessitent
# INTERNET (npm/git) ; ils sont ignorés proprement si indisponibles.
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
EV="$ROOT/vm/evidence/fp_$(date +%Y%m%d-%H%M%S).log"
mkdir -p "$ROOT/vm/evidence"
log(){ echo "$@" | tee -a "$EV"; }
fail(){ log "ERREUR — $*"; exit 1; }

log "=== CANARIS fp_workload $(date -Is) ==="
[ "$(id -u)" -eq 0 ] || fail "root requis (chargement eBPF)."
[ -x "$ROOT/linux/canaris" ] || make -C "$ROOT/linux" 2>&1 | tee -a "$EV" || fail "build échoué"

WORK="$(mktemp -d /tmp/canaris_fp.XXXXXX)"
AREA="$WORK/area"; mkdir -p "$AREA"
CLOG="$WORK/c.log"

# Whitelist = VRAIS chemins des binaires légitimes (résolus en inode par le loader).
WL="$WORK/wl.txt"; : > "$WL"
for t in node npm git rsync cp bash sh tar gzip python3; do
    p="$(command -v "$t" 2>/dev/null)" && echo "$p" >> "$WL"
done
log "whitelist (binaires réels): $(wc -l < "$WL") entrées"

# Charge CANARIS en protégeant la zone de travail. Baseline désactivé (on mesure
# les faux positifs de DÉTECTION, pas la préservation).
"$ROOT/linux/canaris" --protect "$AREA" --whitelist "$WL" --baseline-interval 0 \
    --snapshot-root "$WORK/sn" --baseline-root "$WORK/bl" --log "$CLOG" -o -q \
    >"$WORK/loader.out" 2>&1 &
LP=$!
trap 'kill -INT $LP 2>/dev/null; rm -rf "$WORK"' EXIT
sleep 3

SESSIONS=0; FALSEPOS=0
before_count(){ grep -c REPONSE "$CLOG" 2>/dev/null || echo 0; }
run_session(){
    local name="$1"; shift
    SESSIONS=$((SESSIONS+1))
    local b; b=$(before_count)
    log "--- session '$name' ---"
    ( cd "$AREA" && "$@" ) >>"$EV" 2>&1
    sleep 1
    local a; a=$(before_count)
    if [ "$a" -gt "$b" ]; then
        FALSEPOS=$((FALSEPOS+1))
        log "FAUX POSITIF sur '$name' :"
        grep REPONSE "$CLOG" | tail -n $((a-b)) | tee -a "$EV"
    else
        log "OK '$name' : aucune réaction"
    fi
}

# 1) rsync d'une grosse arborescence locale (pas d'internet requis)
if command -v rsync >/dev/null; then
    run_session "rsync /usr/share -> area" rsync -a --delete /usr/share/ "$AREA/usrshare/"
else
    log "rsync indisponible — session ignorée"
fi

# 2) tar/extract massif (local)
if command -v tar >/dev/null; then
    run_session "tar czf + extract" bash -c 'tar czf a.tgz /usr/include 2>/dev/null; mkdir -p ex; tar xzf a.tgz -C ex 2>/dev/null'
fi

# 3) git clone volumineux (INTERNET requis)
if command -v git >/dev/null && curl -sI https://github.com >/dev/null 2>&1; then
    run_session "git clone linux (depth1)" git clone --depth 1 https://github.com/torvalds/linux.git kern
else
    log "git/internet indisponible — session git ignorée"
fi

# 4) npm install (INTERNET requis)
if command -v npm >/dev/null && curl -sI https://registry.npmjs.org >/dev/null 2>&1; then
    run_session "npm install express" bash -c 'mkdir -p npmp && cd npmp && npm init -y >/dev/null && npm install express >/dev/null'
else
    log "npm/internet indisponible — session npm ignorée"
fi

kill -INT $LP 2>/dev/null; wait $LP 2>/dev/null || true

RATE=0
[ "$SESSIONS" -gt 0 ] && RATE=$(awk "BEGIN{printf \"%.1f\", 100*$FALSEPOS/$SESSIONS}")
log ""
log "=== RÉSULTAT : $FALSEPOS faux positif(s) / $SESSIONS session(s) = ${RATE}% (cible NF5 < 1%) ==="
if [ "$FALSEPOS" -eq 0 ]; then
    log "VERDICT: PASS — aucun faux positif sur les workloads réels exécutés."
    exit 0
else
    log "VERDICT: à AFFINER — ajouter les binaires fautifs ci-dessus à la whitelist"
    log "(config/whitelist.txt) ou ajuster le seuil par défaut (config/profiles.json)."
    exit 1
fi
