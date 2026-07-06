# -*- coding: utf-8 -*-
"""CANARIS — générateurs de charges de travail LÉGITIMES (faux positifs).

Reproduit le *pattern d'I/O* de logiciels légitimes qui, avec un seuil fixe
naïf, provoqueraient des faux positifs catastrophiques (CLAUDE.md §2.3,
cahier NF5) : npm install, git clone volumineux, synchronisation OneDrive,
scan Defender. La whitelist d'exécutables (par inode) + le seuil par défaut
doivent produire **zéro**
réaction sur ces charges.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "common"))
from canaris_engine import (Event, EV_OPEN, EV_WRITE, EV_UNLINK,  # noqa: E402
                            O_WRONLY, O_CREAT, O_RDONLY, O_TRUNC)


# Chemins d'exécutables whitelistés (cohérents avec config/whitelist.txt).
# L'exemption est par exe, jamais par comm : chaque workload légitime porte son
# `exe` réel. (Sur la machine de dev ces fichiers n'existent pas → matching par
# chemin normalisé, ce qui suffit aux tests.)
NODE = "/usr/bin/node"
GIT = "/usr/bin/git"
RSYNC = "/usr/bin/rsync"


def npm_install(n_files=3000, pid=1001, comm="node", start_ts=0.0):
    """`npm install` : création massive de petits fichiers dans node_modules.
    Exécutable whitelisté /usr/bin/node (exempté par inode/chemin, pas par comm)."""
    ts = start_ts
    for i in range(n_files):
        yield Event(ts, EV_OPEN, pid, comm, f"node_modules/pkg{i}/index.js",
                    O_WRONLY | O_CREAT, exe=NODE)
        yield Event(ts, EV_WRITE, pid, comm, "", 0, exe=NODE)
        if i % 20 == 0:  # remplacement de fichiers temporaires
            yield Event(ts, EV_UNLINK, pid, comm, f"node_modules/.tmp{i}", 0, exe=NODE)
        ts += 0.0005  # ~2000 fichiers/s


def git_clone(n_objects=2500, pid=1002, comm="git", start_ts=0.0):
    """`git clone` volumineux : écriture de nombreux objets. Exe /usr/bin/git."""
    ts = start_ts
    for i in range(n_objects):
        yield Event(ts, EV_OPEN, pid, comm, f".git/objects/{i:04x}/obj",
                    O_WRONLY | O_CREAT, exe=GIT)
        yield Event(ts, EV_WRITE, pid, comm, "", 0, exe=GIT)
        ts += 0.0006


def onedrive_sync(n_files=1500, pid=1003, comm="rsync", start_ts=0.0):
    """Synchronisation (rsync-like) : rafales de lectures/écritures. Exe whitelisté."""
    ts = start_ts
    for i in range(n_files):
        yield Event(ts, EV_OPEN, pid, comm, f"sync/f{i}.dat", O_RDONLY, exe=RSYNC)
        yield Event(ts, EV_OPEN, pid, comm, f"sync/f{i}.dat", O_WRONLY | O_TRUNC, exe=RSYNC)
        yield Event(ts, EV_WRITE, pid, comm, "", 0, exe=RSYNC)
        ts += 0.001


def editor_save(pid=1004, comm="vim", start_ts=0.0):
    """Sauvegarde d'un éditeur : exe NON whitelisté (/usr/bin/vim) mais BIEN en
    dessous du seuil par défaut → ne doit pas déclencher."""
    ts = start_ts
    for i in range(8):
        yield Event(ts, EV_OPEN, pid, comm, f"/home/u/notes.txt",
                    O_WRONLY | O_TRUNC, exe="/usr/bin/vim")
        yield Event(ts, EV_WRITE, pid, comm, "", 0, exe="/usr/bin/vim")
        ts += 0.05


ALL_WORKLOADS = {
    "npm_install": npm_install,
    "git_clone": git_clone,
    "onedrive_sync": onedrive_sync,
    "editor_save": editor_save,
}
