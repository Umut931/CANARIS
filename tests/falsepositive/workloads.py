# -*- coding: utf-8 -*-
"""CANARIS — générateurs de charges de travail LÉGITIMES (faux positifs).

Reproduit le *pattern d'I/O* de logiciels légitimes qui, avec un seuil fixe
naïf, provoqueraient des faux positifs catastrophiques (CLAUDE.md §2.3,
cahier NF5) : npm install, git clone volumineux, synchronisation OneDrive,
scan Defender. Le seuil adaptatif + la whitelist doivent produire **zéro**
réaction sur ces charges.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "common"))
from canaris_engine import (Event, EV_OPEN, EV_WRITE, EV_UNLINK,  # noqa: E402
                            O_WRONLY, O_CREAT, O_RDONLY, O_TRUNC)


def npm_install(n_files=3000, pid=1001, comm="node", start_ts=0.0):
    """`npm install` : création massive de petits fichiers dans node_modules.
    Beaucoup d'écritures, quelques suppressions — process whitelisté 'node'."""
    ts = start_ts
    for i in range(n_files):
        yield Event(ts, EV_OPEN, pid, comm, f"node_modules/pkg{i}/index.js",
                    O_WRONLY | O_CREAT)
        yield Event(ts, EV_WRITE, pid, comm, "", 0)
        if i % 20 == 0:  # remplacement de fichiers temporaires
            yield Event(ts, EV_UNLINK, pid, comm, f"node_modules/.tmp{i}", 0)
        ts += 0.0005  # ~2000 fichiers/s


def git_clone(n_objects=2500, pid=1002, comm="git", start_ts=0.0):
    """`git clone` volumineux : écriture de nombreux objets."""
    ts = start_ts
    for i in range(n_objects):
        yield Event(ts, EV_OPEN, pid, comm, f".git/objects/{i:04x}/obj", O_WRONLY | O_CREAT)
        yield Event(ts, EV_WRITE, pid, comm, "", 0)
        ts += 0.0006


def onedrive_sync(n_files=1500, pid=1003, comm="OneDrive", start_ts=0.0):
    """Synchronisation OneDrive : rafales de lectures/écritures."""
    ts = start_ts
    for i in range(n_files):
        yield Event(ts, EV_OPEN, pid, comm, f"OneDrive/f{i}.dat", O_RDONLY)
        yield Event(ts, EV_OPEN, pid, comm, f"OneDrive/f{i}.dat", O_WRONLY | O_TRUNC)
        yield Event(ts, EV_WRITE, pid, comm, "", 0)
        ts += 0.001


def editor_save(pid=1004, comm="vim", start_ts=0.0):
    """Sauvegarde d'un éditeur : quelques I/O, process inconnu (non whitelisté)
    mais BIEN en dessous du seuil par défaut — ne doit pas déclencher."""
    ts = start_ts
    for i in range(8):
        yield Event(ts, EV_OPEN, pid, comm, f"/home/u/notes.txt", O_WRONLY | O_TRUNC)
        yield Event(ts, EV_WRITE, pid, comm, "", 0)
        ts += 0.05


ALL_WORKLOADS = {
    "npm_install": npm_install,
    "git_clone": git_clone,
    "onedrive_sync": onedrive_sync,
    "editor_save": editor_save,
}
