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
    comm: str          # nom court du process (<=15 car)
    path: str = ""     # chemin cible (vide pour WRITE : fd sans chemin)
    flags: int = 0     # flags open() (pour OPEN)


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

    def __init__(self, config: dict):
        self.default = config.get("default", {"window_seconds": 2.0, "io_threshold": 60})
        self.detection = config.get("detection", {})
        # index comm -> profil (via match + aliases)
        self._index = {}
        for prof in config.get("profiles", []):
            names = [prof.get("match", "")] + list(prof.get("aliases", []))
            for n in names:
                if n:
                    self._index[self._norm(n)] = prof

    @staticmethod
    def _norm(name: str) -> str:
        # comm noyau : 15 car max, sans extension .exe (Linux)
        name = name.strip()
        if name.lower().endswith(".exe"):
            name = name[:-4]
        return name[:15]

    def for_comm(self, comm: str) -> dict:
        return self._index.get(self._norm(comm))

    def window(self, comm: str) -> float:
        p = self.for_comm(comm)
        return float((p or self.default).get("window_seconds",
                     self.default.get("window_seconds", 2.0)))

    def threshold(self, comm: str) -> int:
        p = self.for_comm(comm)
        return int((p or self.default).get("io_threshold",
                   self.default.get("io_threshold", 60)))

    def is_whitelisted(self, comm: str) -> bool:
        p = self.for_comm(comm)
        return bool(p and p.get("whitelisted"))

    @classmethod
    def load(cls, path):
        with open(path, encoding="utf-8") as f:
            return cls(json.load(f))


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
        whitelisted = self.profiles.is_whitelisted(ev.comm)

        # 1) Accès canary => réponse IMMÉDIATE (sauf process whitelisté).
        if self._is_canary(ev) and not whitelisted:
            if not st.responded:
                st.responded = True
                return Verdict(ev.pid, ev.comm, "canary_access",
                               f"accès canary {ev.path or '(cible)'}", 1000.0, ev.ts)
            return None

        # Les process de confiance ne déclenchent jamais les seuils comportementaux.
        if whitelisted:
            return None

        window = self.profiles.window(ev.comm)
        threshold = self.profiles.threshold(ev.comm)

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


# ==========================================================================
# Responder : snapshot + kill (Phase 4, F4.1/F4.3/F4.6)
# ==========================================================================
class Responder:
    """Réponse de préservation : snapshot des dossiers protégés (liens durs à la
    façon `rsync --link-dest`) puis terminaison du processus, avec journalisation.

    Portable : utilise les liens durs (os.link) pour un snapshot incrémental
    quasi instantané ; repli sur copie si les liens durs échouent (systèmes de
    fichiers hétérogènes). La version C (responder.c) utilise rsync --link-dest.
    """

    def __init__(self, snapshot_root, log_path=None, dry_run=False):
        self.snapshot_root = Path(snapshot_root)
        self.log_path = Path(log_path) if log_path else None
        self.dry_run = dry_run

    def log(self, msg: str):
        line = f"{time.strftime('%Y-%m-%dT%H:%M:%S')} {msg}"
        if self.log_path:
            with open(self.log_path, "a", encoding="utf-8") as f:
                f.write(line + "\n")
        return line

    def snapshot(self, protected_dirs) -> Path:
        """Crée snapshots/<timestamp>/ avec des liens durs vers le contenu
        actuel des dossiers protégés (préservation avant chiffrement)."""
        ts = time.strftime("%Y%m%d-%H%M%S") + f"-{int(time.time()*1000) % 1000:03d}"
        dest = self.snapshot_root / ts
        if self.dry_run:
            return dest
        dest.mkdir(parents=True, exist_ok=True)
        for d in protected_dirs:
            d = Path(d)
            if not d.exists():
                continue
            base = dest / d.name
            for src in d.rglob("*"):
                if src.is_dir():
                    continue
                rel = src.relative_to(d)
                target = base / rel
                target.parent.mkdir(parents=True, exist_ok=True)
                try:
                    os_link(src, target)          # lien dur : ~instantané
                except OSError:
                    import shutil
                    shutil.copy2(src, target)      # repli copie
        return dest

    def kill(self, pid: int) -> bool:
        """Termine le processus suspect (SIGKILL/Terminate)."""
        if self.dry_run:
            return True
        import os
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
        """Réponse complète : snapshot PUIS kill, avec mesure de latence.
        Ordre : on préserve d'abord (snapshot par liens durs, quasi instantané),
        puis on tue — le snapshot capture l'état avant toute écriture ultérieure."""
        t0 = time.perf_counter()
        snap = self.snapshot(protected_dirs)
        killed = self.kill(verdict.pid)
        elapsed_ms = (time.perf_counter() - t0) * 1000.0
        line = self.log(
            f"RÉPONSE pid={verdict.pid} comm={verdict.comm} raison={verdict.reason} "
            f"({verdict.detail}) snapshot={snap.name} kill={'ok' if killed else 'échec'} "
            f"latence={elapsed_ms:.1f}ms")
        return {"snapshot": snap, "killed": killed, "elapsed_ms": elapsed_ms,
                "log": line}


def os_link(src, dst):
    """os.link avec import local (garde le module importable partout)."""
    import os
    os.link(src, dst)


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

    ap = argparse.ArgumentParser(description="Moteur de détection CANARIS (userspace)")
    ap.add_argument("--config", default="config/profiles.json")
    ap.add_argument("--canary-list", help="fichier de chemins canary")
    ap.add_argument("--protect", action="append", default=[], help="dossier protégé")
    ap.add_argument("--snapshot-root", default="snapshots")
    ap.add_argument("--log", default="canaris_events.log")
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    profs = Profiles.load(args.config)
    canaries = []
    if args.canary_list and Path(args.canary_list).exists():
        canaries = [l.strip() for l in open(args.canary_list, encoding="utf-8")
                    if l.strip()]
    det = Detector(profs, canaries, args.protect)
    resp = Responder(args.snapshot_root, args.log, dry_run=args.dry_run)
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
