#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""CANARIS — simulateur de ransomware pour tests (SANDBOX UNIQUEMENT).

⚠️ SÉCURITÉ (mission §3, CLAUDE.md §8) : ce simulateur n'est PAS un ransomware.
Il ne chiffre rien avec une vraie clé et **refuse de toucher quoi que ce soit
hors d'un répertoire sandbox** (chemin contenant « sandbox » ou passé avec
--force pour un dossier temporaire de test). Il reproduit uniquement le
*pattern d'I/O* d'un ransomware (lecture → réécriture en place → renommage
.locked, en rafale) afin de valider la détection.

Deux usages :
  * `iter_ransomware_events(...)` : produit une trace d'`Event` (pour rejouer
    dans le moteur de détection — tests sans VM/BPF) ;
  * `--run` : exécute réellement les opérations dans la sandbox (pour le test
    end-to-end avec le loader eBPF réel — Docker/VM).

    python tests/ransim/simulate.py --target tests/sandbox --files 200 --run
"""
from __future__ import annotations

import argparse
import os
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "common"))
from canaris_engine import (Event, EV_OPEN, EV_WRITE, EV_UNLINK, EV_RENAME,  # noqa: E402
                            O_RDONLY, O_WRONLY, O_TRUNC, O_CREAT)

RANSOM_EXT = ".CANARIS_LOCKED"        # extension factice ajoutée par le "chiffreur"
DEFAULT_COMM = "cryptor"              # comm d'un binaire inconnu (non whitelisté)


def _guard(target: Path, force: bool):
    """Empêche toute opération réelle hors sandbox."""
    rp = str(target.resolve()).replace("\\", "/").lower()
    if "sandbox" in rp or force:
        return
    raise SystemExit(
        f"REFUS: '{target}' n'est pas une sandbox. Utilisez tests/sandbox/ "
        f"ou --force (dossier temporaire de test uniquement).")


# --------------------------------------------------------------------------
# Génération de trace d'événements (tests sans BPF)
# --------------------------------------------------------------------------
def iter_ransomware_events(target_dir, n_files=200, comm=DEFAULT_COMM, pid=4242,
                           start_ts=0.0, files_per_sec=400.0):
    """Produit la trace d'I/O d'un ransomware chiffrant `n_files` fichiers :
    pour chaque fichier -> open(read), open(write+trunc), write, rename(.locked).
    Les événements sont rapprochés dans le temps (rafale typique)."""
    dt = 1.0 / files_per_sec
    ts = start_ts
    for i in range(n_files):
        base = f"{target_dir}/doc_{i:04d}.txt"
        yield Event(ts, EV_OPEN, pid, comm, base, O_RDONLY)                 # lit l'original
        yield Event(ts, EV_OPEN, pid, comm, base, O_WRONLY | O_TRUNC)       # rouvre en écriture
        yield Event(ts, EV_WRITE, pid, comm, "", 0)                        # écrit (chiffré)
        yield Event(ts, EV_RENAME, pid, comm, base, 0)                     # renomme .locked
        ts += dt


def iter_massdelete_events(target_dir, n_files=60, comm="wiper", pid=777,
                           start_ts=0.0):
    """Trace d'une suppression massive (ransomware supprimant les originaux)."""
    ts = start_ts
    for i in range(n_files):
        yield Event(ts, EV_UNLINK, pid, comm, f"{target_dir}/old_{i:04d}.dat", 0)
        ts += 0.002


# --------------------------------------------------------------------------
# Exécution RÉELLE dans la sandbox (test E2E avec BPF réel)
# --------------------------------------------------------------------------
def prepare_sandbox(target: Path, n_files: int, size_kb: int = 8):
    """Crée n_files fichiers « utilisateur » à chiffrer."""
    target.mkdir(parents=True, exist_ok=True)
    payload = ("données importantes de l'utilisateur — " * 32).encode()[: size_kb * 1024]
    for i in range(n_files):
        (target / f"doc_{i:04d}.txt").write_bytes(payload)


def run_real(target: Path, n_files: int, force: bool = False) -> float:
    """Exécute le pattern ransomware réel dans la sandbox. Renvoie la durée (s)."""
    _guard(target, force)
    prepare_sandbox(target, n_files)
    t0 = time.perf_counter()
    for i in range(n_files):
        p = target / f"doc_{i:04d}.txt"
        if not p.exists():
            continue
        data = p.read_bytes()                       # lecture de l'original
        # "chiffrement" factice réversible (XOR) — AUCUNE vraie crypto, sandbox
        enc = bytes(b ^ 0x5A for b in data)
        p.write_bytes(enc)                          # réécriture en place
        p.rename(p.with_suffix(p.suffix + RANSOM_EXT))  # renommage .locked
    return time.perf_counter() - t0


def main(argv=None):
    ap = argparse.ArgumentParser(description="Simulateur de ransomware (sandbox only)")
    ap.add_argument("--target", default="tests/sandbox", help="répertoire sandbox")
    ap.add_argument("--files", type=int, default=200)
    ap.add_argument("--run", action="store_true", help="exécuter réellement (sandbox)")
    ap.add_argument("--force", action="store_true",
                    help="autoriser un dossier hors 'sandbox' (temp de test only)")
    args = ap.parse_args(argv)
    target = Path(args.target)

    if args.run:
        dur = run_real(target, args.files, args.force)
        rate = args.files / dur if dur else 0
        print(f"Simulateur : {args.files} fichiers « chiffrés » en {dur*1000:.0f} ms "
              f"({rate:.0f} f/s) dans {target}")
    else:
        n = sum(1 for _ in iter_ransomware_events(str(target), args.files))
        print(f"(dry) trace de {n} événements pour {args.files} fichiers. "
              f"Utilisez --run pour exécuter réellement dans la sandbox.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
