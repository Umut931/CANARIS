# -*- coding: utf-8 -*-
"""Tests du BASELINE PÉRIODIQUE (T1) — la correction du snapshot réactif inutile.

Le snapshot pris à la détection capture un état déjà chiffré : inutile contre un
chiffreur rapide. La vraie préservation est un baseline propre pris AVANT
l'attaque. Ces tests prouvent que le baseline :
  * NE capture JAMAIS de fichier chiffré (marqueur d'extension) ;
  * survit à une réécriture EN PLACE de la source (c'est une COPIE, pas un lien
    dur vers la source vivante) — le bug qui rendrait la sauvegarde inutile ;
  * tourne périodiquement et applique la rotation (garde K).

    python -m pytest tests/test_baseline_snapshot.py -v
"""
import sys
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "common"))
sys.path.insert(0, str(ROOT / "tests" / "ransim"))

from canaris_engine import Responder  # noqa: E402
import simulate  # noqa: E402


def _make_clean(protected: Path, n=20):
    protected.mkdir(parents=True, exist_ok=True)
    for i in range(n):
        (protected / f"doc_{i:04d}.txt").write_text(f"contenu original important {i}\n" * 20)


def test_baseline_taken_before_attack_has_no_encrypted_files(tmp_path):
    """Baseline AVANT attaque → il contient les fichiers propres, et après que le
    simulateur a tout chiffré, le baseline ne contient AUCUN fichier chiffré."""
    protected = tmp_path / "Documents"
    _make_clean(protected, n=20)

    resp = Responder(tmp_path / "snapshots", baseline_root=tmp_path / "baselines")
    baseline = resp.baseline_snapshot([protected])

    # 1. le baseline contient les 20 fichiers propres avec leur contenu original
    saved = list(baseline.rglob("doc_*.txt"))
    assert len(saved) == 20, f"baseline incomplet: {len(saved)}"
    assert (baseline / "Documents" / "doc_0000.txt").read_text().startswith(
        "contenu original important 0")

    # 2. l'attaque chiffre tout dans la sandbox
    simulate.run_real(protected, 20, force=True)
    locked = list(protected.glob("*.CANARIS_LOCKED"))
    assert locked, "le simulateur aurait dû chiffrer"

    # 3. le baseline ne contient AUCUN fichier chiffré et garde le contenu propre
    assert not list(baseline.rglob("*.CANARIS_LOCKED")), \
        "le baseline ne doit JAMAIS capturer de fichier chiffré"
    assert not list(baseline.rglob("*.LOCKED"))
    # le contenu préservé est toujours l'original (preuve de restauration possible)
    assert (baseline / "Documents" / "doc_0000.txt").read_text().startswith(
        "contenu original important 0")


def test_baseline_survives_in_place_rewrite(tmp_path):
    """CRITIQUE : un lien dur vers la source vivante serait corrompu par une
    réécriture en place. Le baseline doit être une COPIE → contenu préservé même
    après réécriture du même inode."""
    protected = tmp_path / "data"
    protected.mkdir()
    victim = protected / "secret.txt"
    victim.write_text("DONNEES ORIGINALES")

    resp = Responder(tmp_path / "snap", baseline_root=tmp_path / "bl")
    baseline = resp.baseline_snapshot([protected])

    # réécriture EN PLACE (même inode) — simule un chiffreur in-place
    with open(victim, "r+b") as f:
        f.seek(0)
        f.write(b"XXXXXXXXXXXXXXXXX")  # écrase le contenu

    preserved = (baseline / "data" / "secret.txt").read_text()
    assert preserved == "DONNEES ORIGINALES", \
        "le baseline a été corrompu par la réécriture (lien dur vers la source ?)"


def test_baseline_excludes_already_encrypted_files(tmp_path):
    """Un fichier portant déjà un marqueur de chiffrement n'est jamais copié."""
    protected = tmp_path / "d"
    protected.mkdir()
    (protected / "clean.txt").write_text("ok")
    (protected / "victim.txt.CANARIS_LOCKED").write_text("deja chiffre")
    (protected / "other.encrypted").write_text("chiffre aussi")

    resp = Responder(tmp_path / "s", baseline_root=tmp_path / "b")
    baseline = resp.baseline_snapshot([protected])

    names = {p.name for p in baseline.rglob("*") if p.is_file()}
    assert "clean.txt" in names
    assert not any(".CANARIS_LOCKED" in n or n.endswith(".encrypted") for n in names)


def test_baseline_rotation_keeps_k(tmp_path):
    """Après K+2 baselines, il en reste exactement K (rotation)."""
    protected = tmp_path / "docs"
    _make_clean(protected, n=3)
    resp = Responder(tmp_path / "s", baseline_root=tmp_path / "bl", keep_baselines=4)

    for _ in range(6):  # K=4, on en prend 6
        resp.baseline_snapshot([protected])
        time.sleep(0.01)  # timestamps distincts (ms)

    remaining = sorted((tmp_path / "bl").glob("baseline-*"))
    assert len(remaining) == 4, f"rotation cassée: {len(remaining)} baselines restants"


def test_baseline_dedup_hardlinks_unchanged(tmp_path):
    """Déduplication : un fichier inchangé entre deux baselines partage l'inode
    (lien dur contre le baseline précédent) — coût disque marginal."""
    import os
    protected = tmp_path / "docs"
    protected.mkdir()
    f = protected / "stable.txt"
    f.write_text("inchangé")
    # fixe mtime pour que la comparaison taille+mtime détecte l'égalité
    past = time.time() - 3600
    os.utime(f, (past, past))

    resp = Responder(tmp_path / "s", baseline_root=tmp_path / "bl")
    b1 = resp.baseline_snapshot([protected])
    b2 = resp.baseline_snapshot([protected])

    i1 = (b1 / "docs" / "stable.txt").stat().st_ino
    i2 = (b2 / "docs" / "stable.txt").stat().st_ino
    assert i1 == i2, "fichier inchangé non dédupliqué (devrait partager l'inode)"


def test_periodic_baseline_runner(tmp_path):
    """Le runner périodique prend bien plusieurs baselines."""
    from canaris_engine import run_periodic_baseline
    protected = tmp_path / "docs"
    _make_clean(protected, n=2)
    resp = Responder(tmp_path / "s", baseline_root=tmp_path / "bl", keep_baselines=10)
    run_periodic_baseline(resp, [protected], interval_s=0.01, max_iterations=3)
    assert len(list((tmp_path / "bl").glob("baseline-*"))) == 3
