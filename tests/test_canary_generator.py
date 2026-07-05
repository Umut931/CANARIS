# -*- coding: utf-8 -*-
"""Tests du générateur de canary files (Phase 3, exigences F1.1–F1.4).

Ces tests sont **exécutables dans l'environnement de dev** (pas de VM requise).
Ils prouvent qu'un canary passe pour un vrai document et ne ressemble pas à du
chiffré.

    python -m pytest tests/test_canary_generator.py -v
"""
import os
import sys
import time
import zipfile
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "common"))
import canary_generator as cg  # noqa: E402


@pytest.fixture(scope="module")
def generated(tmp_path_factory):
    """Génère un lot de canaries reproductible pour toute la suite."""
    target = tmp_path_factory.mktemp("canaries")
    manifest = cg.generate(target, count=24,
                           extensions=["pdf", "docx", "xlsx", "txt"],
                           seed=1234, verbose=False)
    return target, manifest


# ---------------------------------------------------------------- entropie --
def test_entropy_below_6_bits(generated):
    """F1.3 : chaque canary a une entropie de Shannon < 6 bits/octet
    (prouve qu'il ne ressemble pas à du contenu chiffré)."""
    _, manifest = generated
    assert manifest, "aucun canary généré"
    for e in manifest:
        data = Path(e["path"]).read_bytes()
        ent = cg.shannon_entropy(data)
        assert ent < 6.0, f"{e['path']} entropie {ent:.2f} >= 6.0 (ressemble à du chiffré)"


def test_entropy_helper_bounds():
    """Sanity : l'entropie vaut 0 pour un flux constant et ~8 pour de l'aléatoire."""
    assert cg.shannon_entropy(b"\x00" * 4096) == 0.0
    assert cg.shannon_entropy(b"") == 0.0
    rnd = os.urandom(65536)
    assert cg.shannon_entropy(rnd) > 7.5  # l'aléatoire est proche de 8


# ------------------------------------------------------------------- taille --
def test_size_distribution_in_range(generated):
    """F1.2 : toutes les tailles sont dans [50 Ko, 5 Mo]."""
    _, manifest = generated
    for e in manifest:
        size = Path(e["path"]).stat().st_size
        assert cg.MIN_SIZE <= size <= cg.MAX_SIZE, \
            f"{e['path']} taille {size} hors bornes"


def test_size_distribution_is_varied(generated):
    """F1.2 : la distribution log-normale produit des tailles variées
    (pas une taille constante, qui trahirait un leurre)."""
    _, manifest = generated
    sizes = sorted(e["size"] for e in manifest)
    # au moins 8 tailles distinctes et un ratio max/min significatif
    assert len(set(sizes)) >= 8
    assert sizes[-1] / sizes[0] > 2.0


# -------------------------------------------------------------- magic bytes --
def test_magic_bytes_per_extension(generated):
    """F1.1 : magic bytes valides par extension."""
    _, manifest = generated
    for e in manifest:
        head = Path(e["path"]).read_bytes()[:8]
        magic = cg.MAGIC[e["ext"]]
        if magic is not None:
            assert head.startswith(magic), \
                f"{e['path']} magic attendu {magic!r}, obtenu {head!r}"


def test_docx_xlsx_are_valid_zip_packages(generated):
    """F1.1 : les .docx/.xlsx sont des paquets OOXML **valides** (ZIP intègre,
    [Content_Types].xml présent) — ils s'ouvriraient dans Office."""
    _, manifest = generated
    for e in manifest:
        if e["ext"] not in ("docx", "xlsx"):
            continue
        p = Path(e["path"])
        assert zipfile.is_zipfile(p)
        z = zipfile.ZipFile(p)
        assert z.testzip() is None, f"zip corrompu {p}"
        assert "[Content_Types].xml" in z.namelist()
        if e["ext"] == "docx":
            assert "word/document.xml" in z.namelist()
        else:
            assert "xl/workbook.xml" in z.namelist()


def test_pdf_structure_valid(generated):
    """F1.1 : les PDF ont l'en-tête %PDF- et se terminent par %%EOF."""
    _, manifest = generated
    for e in manifest:
        if e["ext"] != "pdf":
            continue
        data = Path(e["path"]).read_bytes()
        assert data.startswith(b"%PDF-")
        assert b"%%EOF" in data[-64:]
        assert b"xref" in data and b"trailer" in data


# -------------------------------------------------------------- timestamps --
def test_mtime_modified_in_past(generated):
    """F1.4 : le mtime est effectivement positionné dans le passé (nettement,
    > 30 jours), ce qui prouve que les timestamps ont bien été réécrits et que
    le fichier ne trahit pas une création instantanée (mtime ≈ maintenant)."""
    _, manifest = generated
    now = time.time()
    thirty_days = 30 * 86400
    for e in manifest:
        mtime = Path(e["path"]).stat().st_mtime
        assert mtime < now - thirty_days, \
            f"{e['path']} mtime trop récent ({now - mtime:.0f}s)"
        # cohérence : mtime postérieur au btime (création)
        assert mtime >= e["btime"] - 1, f"{e['path']} mtime antérieur au btime"


@pytest.mark.skipif(os.name != "nt", reason="btime réglable via API seulement sur Windows")
def test_btime_set_on_windows(generated):
    """F1.4 (Windows) : le birth time (creation time) est modifié dans le passé
    via SetFileTime. Sous Linux, btime nécessite debugfs (voir HANDOFF)."""
    _, manifest = generated
    assert all(e["btime_set"] for e in manifest), "btime non appliqué"
    now = time.time()
    for e in manifest:
        ctime = Path(e["path"]).stat().st_ctime  # creation time sur Windows
        assert ctime < now - 180 * 86400


# ---------------------------------------------------------------- nommage ----
def test_names_are_credible(generated):
    """F1.6 : noms crédibles (jamais 'canary.*'), extensions attendues,
    placement en sous-dossiers profonds (>= 2 niveaux)."""
    target, manifest = generated
    for e in manifest:
        p = Path(e["path"])
        assert "canary" not in p.name.lower()
        assert p.suffix.lstrip(".") in cg.SUPPORTED_EXTS
        rel = p.relative_to(target)
        assert len(rel.parts) >= 3, f"{rel} pas assez profond (F1.5)"


def test_manifest_and_list_written(generated, tmp_path):
    """Le manifeste JSON et la liste de chemins (pour le loader) sont produits."""
    target, manifest = generated
    man_path, list_path = cg.write_manifest(manifest, target)
    assert man_path.exists() and list_path.exists()
    lines = list_path.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == len(manifest)
    for line in lines:
        assert Path(line).exists()


def test_rejects_unsupported_extension(tmp_path):
    with pytest.raises(ValueError):
        cg.generate(tmp_path, count=1, extensions=["exe"], seed=0, verbose=False)
