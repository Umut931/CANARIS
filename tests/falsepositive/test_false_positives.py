# -*- coding: utf-8 -*-
"""Tests faux positifs (Phase 4, cahier NF5, recette R6/R7).

Rejoue des charges de travail LÉGITIMES (npm install, git clone, OneDrive,
sauvegarde d'éditeur) dans le moteur de détection et exige **zéro** réaction.
C'est la preuve que le seuil adaptatif + whitelist évitent les faux positifs
catastrophiques d'un seuil global fixe.

    python -m pytest tests/falsepositive/test_false_positives.py -v
"""
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "common"))
sys.path.insert(0, str(ROOT / "tests" / "falsepositive"))

from canaris_engine import Detector, Profiles  # noqa: E402
import workloads  # noqa: E402


@pytest.fixture(scope="module")
def profiles():
    return Profiles.load(ROOT / "config" / "profiles.json")


def _replay_count_verdicts(profiles, event_iter):
    det = Detector(profiles)
    verdicts = [v for ev in event_iter if (v := det.observe(ev))]
    return verdicts


@pytest.mark.parametrize("name", list(workloads.ALL_WORKLOADS.keys()))
def test_legitimate_workload_no_false_positive(profiles, name):
    """Chaque charge légitime → 0 verdict (aucun kill/snapshot déclenché)."""
    gen = workloads.ALL_WORKLOADS[name]
    verdicts = _replay_count_verdicts(profiles, gen())
    assert verdicts == [], (
        f"FAUX POSITIF sur '{name}': {[v.reason for v in verdicts]}")


def test_combined_workloads_no_false_positive(profiles):
    """Toutes les charges légitimes entrelacées (PIDs distincts) → 0 verdict."""
    det = Detector(profiles)
    gens = [g() for g in workloads.ALL_WORKLOADS.values()]
    verdicts = []
    exhausted = False
    while not exhausted:
        exhausted = True
        for g in gens:
            ev = next(g, None)
            if ev is not None:
                exhausted = False
                v = det.observe(ev)
                if v:
                    verdicts.append(v)
    assert verdicts == [], f"faux positif combiné: {[v.reason for v in verdicts]}"


def test_false_positive_rate_is_zero(profiles):
    """Recette R6/R7 : taux de faux positifs = 0 % sur l'ensemble simulé."""
    total_processes = 0
    false_positives = 0
    for gen in workloads.ALL_WORKLOADS.values():
        total_processes += 1
        if _replay_count_verdicts(profiles, gen()):
            false_positives += 1
    rate = false_positives / total_processes
    assert rate == 0.0, f"taux de faux positifs {rate:.0%} != 0"
