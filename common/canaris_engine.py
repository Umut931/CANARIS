#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""CANARIS — moteur de détection comportementale + réponse (userspace).

Ce module implémente l'algorithme de détection (Phase 4) et sert à la fois :
  * de **référence** : c'est l'algorithme que le composant C (linux/userspace/
    profiles.c + responder.c) reproduit à l'identique pour la production ;
  * de **harnais de test** : les tests (tests/test_detection.py,
    tests/falsepositive/) rejouent des traces d'événements dans ce moteur pour
    prouver la détection et l'absence de faux positifs, sans VM ;
  * de **matcher userspace du mode dégradé** : si le LSM BPF ne peut pas
    bloquer (voir HANDOFF T-L6), le loader C peut émettre ses événements en
    JSON et ce moteur applique la politique (matching canary par chemin + kill),
    ce qui reste une mitigation efficace (kill dès le 1er accès canary).

Décisions clés (CLAUDE.md §2.3, cahier F3) :
  * **seuil ADAPTATIF par profil de processus** — jamais un seuil global fixe
    (celui-ci n'existe que comme secours pour les process inconnus) ;
  * un **accès canary** par un process non whitelisté déclenche la réponse
    IMMÉDIATEMENT (indépendamment de tout seuil — cahier §12, mitige la race
    condition du chiffrement rapide) ;
  * signaux corroborants : taux d'I/O, suppression massive, read-then-write.
"""
from __future__ import annotations

import json
import os
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from pathlib import Path

# ---- Constantes de flags open() (pour détecter read-then-write) -----------
O_ACCMODE = 0o3
O_RDONLY = 0o0
O_WRONLY = 0o1
O_RDWR = 0o2
O_CREAT = 0o100
O_TRUNC = 0o1000

# ---- Types d'événements (miroir de enum canaris_event_type côté eBPF) ------
EV_OPEN = "OPEN"
EV_WRITE = "WRITE"
EV_UNLINK = "UNLINK"
EV_RENAME = "RENAME"
EV_CANARY_HIT = "CANARY_HIT"


@dataclass
class Event:
    """Événement filesystem, tel qu'émis par le loader eBPF."""
    ts: float          # secondes (epoch ou monotonic cohérent)
    type: str          # EV_*
    pid: int
    comm: str          # nom court du process — AFFICHAGE seulement (falsifiable)
    path: str = ""     # chemin cible (vide pour WRITE : fd sans chemin)
    flags: int = 0     # flags open() (pour OPEN)
    exe: str = ""      # chemin de l'EXÉCUTABLE appelant — sert à la whitelist
                       # (identité par inode/chemin, pas le comm)


@dataclass
class Verdict:
    """Décision de réponse."""
    pid: int
    comm: str
    reason: str        # 'canary_access' | 'io_rate' | 'mass_delete' | 'read_then_write'
    detail: str
    score: float
    ts: float


@dataclass
class _PidState:
    comm: str = ""
    io_events: deque = field(default_factory=deque)     # (ts, type) dans la fenêtre
    unlink_paths: deque = field(default_factory=deque)  # (ts, path)
    # suivi read-then-write : path -> {'r': bool, 'w': bool}
    rw_seen: dict = field(default_factory=dict)
    responded: bool = False


class Profiles:
    """Charge et interroge les profils de seuil adaptatif (config/profiles.json)."""

    def __init__(self, config: dict, extra_whitelist=None):
        self.default = config.get("default", {"window_seconds": 2.0, "io_threshold": 60})
        self.detection = config.get("detection", {})
        # Whitelist d'EXÉCUTABLES (par chemin/identité), jamais par comm.
        self.whitelisted_exes = set()
        for entry in config.get("whitelisted_executables", []):
            path = entry["path"] if isinstance(entry, dict) else str(entry)
            self.whitelisted_exes.add(self._norm_exe(path))
        for path in (extra_whitelist or []):
            self.whitelisted_exes.add(self._norm_exe(path))

    @staticmethod
    def _norm_exe(path: str) -> str:
        """Identité d'exécutable : (device, inode) si le fichier existe (robuste
        aux liens/chemins), sinon le chemin normalisé (utile en test)."""
        path = str(path).strip()
        try:
            st = os.stat(path)
            return f"dev{st.st_dev}:ino{st.st_ino}"
        except OSError:
            return os.path.normcase(os.path.normpath(path))

    def window(self) -> float:
        return float(self.default.get("window_seconds", 2.0))

    def threshold(self) -> int:
        return int(self.default.get("io_threshold", 60))

    def is_whitelisted_exe(self, exe: str) -> bool:
        """True si l'exécutable (par identité inode/chemin) est whitelisté.
        Le comm n'entre JAMAIS en jeu (anti-spoofing, T2)."""
        if not exe:
            return False
        return self._norm_exe(exe) in self.whitelisted_exes

    @classmethod
    def load(cls, path, extra_whitelist=None):
        with open(path, encoding="utf-8") as f:
            return cls(json.load(f), extra_whitelist=extra_whitelist)


class Detector:
    """Détecteur comportemental à fenêtre glissante et seuil adaptatif.

    Alimenter avec `observe(event)`. Renvoie un `Verdict` la première fois
    qu'un processus franchit un signal de détection, sinon None.
    """

    def __init__(self, profiles: Profiles, canary_paths=None, protected_dirs=None):
        self.profiles = profiles
        self.canary_paths = {str(p) for p in (canary_paths or [])}
        self.protected_dirs = [str(p) for p in (protected_dirs or [])]
        self.state: dict[int, _PidState] = defaultdict(_PidState)
        det = profiles.detection
        self.canary_immediate = det.get("canary_hit_is_immediate", True)
        self.mass_delete_threshold = int(det.get("mass_delete_threshold", 30))
        self.rtw_weight = float(det.get("read_then_write_weight", 2.0))
        # seuil de fichiers read-then-write distincts déclenchant l'alerte
        self.rtw_threshold = int(det.get("read_then_write_threshold", 12))

    # ------------------------------------------------------------------ util
    def _is_canary(self, ev: Event) -> bool:
        if ev.type == EV_CANARY_HIT:
            return True
        return ev.path in self.canary_paths

    def _under_protected(self, path: str) -> bool:
        return any(path.startswith(d.rstrip("/") + "/") or path == d
                   for d in self.protected_dirs)

    @staticmethod
    def _is_write_open(flags: int) -> bool:
        acc = flags & O_ACCMODE
        return acc in (O_WRONLY, O_RDWR) or bool(flags & (O_CREAT | O_TRUNC))

    @staticmethod
    def _is_read_open(flags: int) -> bool:
        acc = flags & O_ACCMODE
        return acc in (O_RDONLY, O_RDWR)

    def _prune(self, st: _PidState, now: float, window: float):
        cutoff = now - window
        while st.io_events and st.io_events[0][0] < cutoff:
            st.io_events.popleft()
        while st.unlink_paths and st.unlink_paths[0][0] < cutoff:
            st.unlink_paths.popleft()

    # --------------------------------------------------------------- observe
    def observe(self, ev: Event):
        st = self.state[ev.pid]
        st.comm = ev.comm
        # Exemption par EXÉCUTABLE (identité inode/chemin), jamais par comm (T2).
        whitelisted = self.profiles.is_whitelisted_exe(ev.exe)

        # 1) Accès canary => réponse IMMÉDIATE (sauf exécutable whitelisté).
        if self._is_canary(ev) and not whitelisted:
            if not st.responded:
                st.responded = True
                return Verdict(ev.pid, ev.comm, "canary_access",
                               f"accès canary {ev.path or '(cible)'}", 1000.0, ev.ts)
            return None

        # Les exécutables de confiance ne déclenchent jamais les seuils.
        if whitelisted:
            return None

        # Seuil PAR DÉFAUT pour tout non-whitelisté (jamais élevé sur la foi du
        # comm falsifiable — un ransomware nommé « rsync » garde le seuil défaut).
        window = self.profiles.window()
        threshold = self.profiles.threshold()

        # 2) Mise à jour de la fenêtre glissante.
        if ev.type in (EV_OPEN, EV_WRITE, EV_UNLINK, EV_RENAME):
            st.io_events.append((ev.ts, ev.type))
        if ev.type == EV_UNLINK and ev.path:
            st.unlink_paths.append((ev.ts, ev.path))
        # read-then-write via flags d'open
        if ev.type == EV_OPEN and ev.path:
            rec = st.rw_seen.setdefault(ev.path, {"r": False, "w": False})
            if self._is_read_open(ev.flags):
                rec["r"] = True
            if self._is_write_open(ev.flags):
                rec["w"] = True
        self._prune(st, ev.ts, window)

        if st.responded:
            return None

        # 3) Signaux de détection.
        count = len(st.io_events)
        if count >= threshold:
            st.responded = True
            return Verdict(ev.pid, ev.comm, "io_rate",
                           f"{count} I/O en {window:.0f}s (seuil {threshold})",
                           float(count) / threshold, ev.ts)

        distinct_unlinks = len({p for _, p in st.unlink_paths})
        if distinct_unlinks >= self.mass_delete_threshold:
            st.responded = True
            return Verdict(ev.pid, ev.comm, "mass_delete",
                           f"{distinct_unlinks} suppressions distinctes",
                           float(distinct_unlinks) / self.mass_delete_threshold, ev.ts)

        rtw = sum(1 for r in st.rw_seen.values() if r["r"] and r["w"])
        if rtw >= self.rtw_threshold:
            st.responded = True
            return Verdict(ev.pid, ev.comm, "read_then_write",
                           f"{rtw} fichiers lus-puis-réécrits (chiffrement en place)",
                           float(rtw) / self.rtw_threshold, ev.ts)

        return None


# Marqueurs de fichiers déjà chiffrés : un BASELINE ne doit JAMAIS les capturer.
ENCRYPTION_MARKERS = (
    ".locked", ".canaris_locked", ".encrypted", ".enc", ".crypt", ".crypto",
    ".locky", ".cerber", ".ryuk", ".conti", ".lockbit", ".pay", ".wcry", ".wncry",
)


# ==========================================================================
# Responder : baseline périodique + snapshot réactif + kill (F4.1/F4.3/F4.6)
# ==========================================================================
class Responder:
    """Préservation en DEUX temps (leçon de la course du chiffrement rapide) :

      1. **Baseline PÉRIODIQUE** (`baseline_snapshot`) pris AVANT toute attaque,
         toutes les N minutes. C'est la source de RÉCUPÉRATION. Il **copie** les
         fichiers modifiés (jamais un lien dur vers la source vivante — sinon une
         réécriture en place corromprait la sauvegarde) et déduplique par liens
         durs contre le baseline PRÉCÉDENT (sémantique `rsync --link-dest`). Il
         **exclut** tout fichier portant un marqueur de chiffrement.

      2. **Snapshot RÉACTIF** (`incident_snapshot`) pris à la détection : capture
         l'état COURANT (potentiellement déjà chiffré). Il est étiqueté
         `post-incident-state` = FORENSIQUE, PAS une source de restauration.

    En mode ENFORCE (LSM actif) le blocage empêche le chiffrement → les fichiers
    restent propres. En mode DÉGRADÉ, le baseline périodique est la seule vraie
    garantie de préservation. Les deux se renforcent (belt & suspenders).
    """

    def __init__(self, snapshot_root, log_path=None, dry_run=False,
                 baseline_root=None, keep_baselines=8, markers=ENCRYPTION_MARKERS):
        self.snapshot_root = Path(snapshot_root)          # réactif / forensique
        self.baseline_root = (Path(baseline_root) if baseline_root
                              else self.snapshot_root.parent / "baselines")
        self.log_path = Path(log_path) if log_path else None
        self.dry_run = dry_run
        self.keep_baselines = keep_baselines
        self.markers = tuple(m.lower() for m in markers)

    # --------------------------------------------------------------- log
    def log(self, msg: str):
        line = f"{time.strftime('%Y-%m-%dT%H:%M:%S')} {msg}"
        if self.log_path:
            with open(self.log_path, "a", encoding="utf-8") as f:
                f.write(line + "\n")
        return line

    # ------------------------------------------------------------- utils
    def _is_encrypted(self, path: Path) -> bool:
        return path.name.lower().endswith(self.markers)

    @staticmethod
    def _under(path: Path, root: Path) -> bool:
        try:
            path.resolve().relative_to(root.resolve())
            return True
        except (ValueError, OSError):
            return False

    def _skip(self, src: Path) -> bool:
        """Ne jamais capturer : un fichier chiffré, ni le contenu des stores."""
        return (self._is_encrypted(src)
                or self._under(src, self.baseline_root)
                or self._under(src, self.snapshot_root))

    # -------------------------------------------------- baseline (T1)
    def latest_clean_baseline(self):
        bs = sorted(self.baseline_root.glob("baseline-*"))
        return bs[-1] if bs else None

    def _rotate_baselines(self, keep: int):
        import shutil
        bs = sorted(self.baseline_root.glob("baseline-*"))
        for old in bs[:-keep] if keep > 0 else bs:
            shutil.rmtree(old, ignore_errors=True)

    def baseline_snapshot(self, protected_dirs, keep=None) -> Path:
        """Baseline propre pris périodiquement AVANT toute attaque. Copie les
        fichiers changés, déduplique par lien dur contre le baseline précédent,
        exclut les fichiers chiffrés et les stores. Applique la rotation (K)."""
        import shutil
        keep = self.keep_baselines if keep is None else keep
        ts = time.strftime("%Y%m%d-%H%M%S") + f"-{int(time.time()*1000) % 1000:03d}"
        dest = self.baseline_root / f"baseline-{ts}"
        if self.dry_run:
            return dest
        prev = self.latest_clean_baseline()
        dest.mkdir(parents=True, exist_ok=True)

        for d in protected_dirs:
            d = Path(d)
            if not d.exists() or not d.is_dir():
                continue
            for src in d.rglob("*"):
                if src.is_dir() or self._skip(src):
                    continue
                try:
                    st = src.stat()
                except OSError:
                    continue
                rel = Path(d.name) / src.relative_to(d)
                target = dest / rel
                target.parent.mkdir(parents=True, exist_ok=True)

                # Déduplication : lien dur depuis le baseline précédent si le
                # fichier n'a pas changé (taille+mtime, comme rsync --link-dest).
                linked = False
                if prev is not None:
                    pf = prev / rel
                    if pf.exists():
                        try:
                            pst = pf.stat()
                            if pst.st_size == st.st_size and \
                               int(pst.st_mtime) == int(st.st_mtime):
                                os.link(pf, target)     # copie-de-copie : sûr
                                linked = True
                        except OSError:
                            pass
                if not linked:
                    # COPIE du contenu source (immunise contre une réécriture
                    # en place ultérieure — jamais de lien dur vers la source).
                    try:
                        shutil.copy2(src, target)
                    except OSError:
                        pass

        self._rotate_baselines(keep)
        return dest

    # ------------------------------------------------ snapshot réactif
    def incident_snapshot(self, protected_dirs) -> Path:
        """Snapshot FORENSIQUE de l'état courant à la détection (peut contenir du
        chiffré). Étiqueté post-incident-state ; N'EST PAS une source de
        restauration — celle-ci est le dernier baseline propre."""
        ts = time.strftime("%Y%m%d-%H%M%S") + f"-{int(time.time()*1000) % 1000:03d}"
        dest = self.snapshot_root / f"post-incident-{ts}"
        if self.dry_run:
            return dest
        dest.mkdir(parents=True, exist_ok=True)
        import shutil
        for d in protected_dirs:
            d = Path(d)
            if not d.exists():
                continue
            for src in d.rglob("*"):
                if src.is_dir() or self._under(src, self.snapshot_root) or \
                        self._under(src, self.baseline_root):
                    continue
                target = dest / d.name / src.relative_to(d)
                target.parent.mkdir(parents=True, exist_ok=True)
                try:
                    os.link(src, target)
                except OSError:
                    try:
                        shutil.copy2(src, target)
                    except OSError:
                        pass
        return dest

    def kill(self, pid: int) -> bool:
        """Termine le processus suspect (SIGKILL/Terminate)."""
        if self.dry_run:
            return True
        import signal
        try:
            if os.name == "nt":
                import subprocess
                subprocess.run(["taskkill", "/F", "/PID", str(pid)],
                               capture_output=True)
            else:
                os.kill(pid, signal.SIGKILL)
            return True
        except (ProcessLookupError, OSError):
            return False

    def respond(self, verdict: Verdict, protected_dirs) -> dict:
        """Réponse : snapshot forensique de l'état courant PUIS kill. La source
        de RÉCUPÉRATION recommandée est le dernier baseline propre (loggué)."""
        t0 = time.perf_counter()
        snap = self.incident_snapshot(protected_dirs)
        killed = self.kill(verdict.pid)
        elapsed_ms = (time.perf_counter() - t0) * 1000.0
        baseline = self.latest_clean_baseline()
        line = self.log(
            f"RÉPONSE pid={verdict.pid} comm={verdict.comm} raison={verdict.reason} "
            f"({verdict.detail}) forensique={snap.name} kill={'ok' if killed else 'échec'} "
            f"latence={elapsed_ms:.1f}ms")
        self.log(f"  RESTAURATION recommandée depuis le dernier baseline propre : "
                 f"{baseline if baseline else '(AUCUN baseline — activez le baseline périodique !)'}")
        return {"snapshot": snap, "killed": killed, "elapsed_ms": elapsed_ms,
                "baseline": baseline, "log": line}


def run_periodic_baseline(responder: "Responder", protected_dirs, interval_s,
                          stop_event=None, max_iterations=None):
    """Boucle de baseline périodique (à lancer dans un thread par le service).
    Prend un baseline propre toutes `interval_s` secondes jusqu'à l'arrêt."""
    import threading
    n = 0
    while True:
        responder.baseline_snapshot(protected_dirs)
        n += 1
        if max_iterations and n >= max_iterations:
            return
        if stop_event is not None:
            if isinstance(stop_event, threading.Event):
                if stop_event.wait(interval_s):
                    return
            else:
                time.sleep(interval_s)
        else:
            time.sleep(interval_s)


# ==========================================================================
# Rejoueur de trace (outil de test / mode dégradé)
# ==========================================================================
def replay(events, profiles: Profiles, canary_paths=None, protected_dirs=None,
           responder: Responder = None):
    """Rejoue une liste d'`Event` dans le détecteur. Renvoie la liste des
    verdicts. Si `responder` est fourni, déclenche la réponse (utilisé par le
    mode dégradé et certains tests d'intégration)."""
    det = Detector(profiles, canary_paths, protected_dirs)
    verdicts = []
    for ev in events:
        v = det.observe(ev)
        if v:
            verdicts.append(v)
            if responder:
                responder.respond(v, protected_dirs or [])
    return verdicts


if __name__ == "__main__":
    # Mode dégradé / analyse : lit des événements JSON-lines sur stdin
    # (émis par le loader C avec --json) et applique la politique.
    import argparse
    import sys

    import threading

    ap = argparse.ArgumentParser(description="Moteur de détection CANARIS (userspace)")
    ap.add_argument("--config", default="config/profiles.json")
    ap.add_argument("--canary-list", help="fichier de chemins canary")
    ap.add_argument("--protect", action="append", default=[], help="dossier protégé")
    ap.add_argument("--snapshot-root", default="snapshots")
    ap.add_argument("--baseline-root", default=None,
                    help="racine des baselines propres (défaut: <snapshot-root>/../baselines)")
    ap.add_argument("--baseline-interval", type=float, default=0.0,
                    help="secondes entre baselines périodiques (0 = désactivé)")
    ap.add_argument("--keep-baselines", type=int, default=8)
    ap.add_argument("--baseline-once", action="store_true",
                    help="prendre un seul baseline propre puis quitter (cron/test)")
    ap.add_argument("--log", default="canaris_events.log")
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    profs = Profiles.load(args.config)
    canaries = []
    if args.canary_list and Path(args.canary_list).exists():
        canaries = [l.strip() for l in open(args.canary_list, encoding="utf-8")
                    if l.strip()]
    det = Detector(profs, canaries, args.protect)
    resp = Responder(args.snapshot_root, args.log, dry_run=args.dry_run,
                     baseline_root=args.baseline_root,
                     keep_baselines=args.keep_baselines)

    if args.baseline_once:
        b = resp.baseline_snapshot(args.protect)
        print(f"Baseline propre créé : {b}")
        sys.exit(0)

    # Baseline périodique dans un thread (préservation AVANT attaque).
    if args.baseline_interval > 0 and args.protect:
        t = threading.Thread(target=run_periodic_baseline,
                             args=(resp, args.protect, args.baseline_interval),
                             daemon=True)
        t.start()
        print(f"Baseline périodique actif : toutes les {args.baseline_interval:.0f}s "
              f"(garde {args.keep_baselines})")

    print(f"CANARIS engine — {len(canaries)} canaries, {len(args.protect)} dossiers protégés")
    for raw in sys.stdin:
        raw = raw.strip()
        if not raw:
            continue
        try:
            d = json.loads(raw)
        except json.JSONDecodeError:
            continue
        ev = Event(ts=d.get("ts", time.time()), type=d.get("type", ""),
                   pid=int(d.get("pid", 0)), comm=d.get("comm", ""),
                   path=d.get("path", ""), flags=int(d.get("flags", 0)))
        v = det.observe(ev)
        if v:
            r = resp.respond(v, args.protect)
            print(r["log"])
