# -*- coding: utf-8 -*-
"""Tests de la logique de détection comportementale + responder (Phase 4).

Exécutables sans VM/BPF : on rejoue des traces d'événements dans le moteur
(common/canaris_engine.py), qui est l'algorithme de référence reproduit par le
composant C. Couvre F3.1–F3.4, F4.1, F4.3, F4.6 et la mesure de latence (NF2).

    python -m pytest tests/test_detection.py -v
"""
import subprocess
import sys
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "common"))
sys.path.insert(0, str(ROOT / "tests" / "ransim"))

import canaris_engine as ce  # noqa: E402
from canaris_engine import Detector, Profiles, Responder, Event, EV_OPEN, O_WRONLY  # noqa: E402
import simulate  # noqa: E402


@pytest.fixture(scope="module")
def profiles():
    return Profiles.load(ROOT / "config" / "profiles.json")


# ============================ DÉTECTION (vrais positifs) ====================
def test_ransomware_simulation_triggers_detection(profiles):
    """Checkpoint Phase 4 : simulate.py (>N fichiers/2s) → détection déclenchée."""
    events = list(simulate.iter_ransomware_events("/sandbox", n_files=200))
    det = Detector(profiles)
    verdict = None
    for ev in events:
        verdict = det.observe(ev)
        if verdict:
            break
    assert verdict is not None, "le ransomware simulé n'a pas été détecté"
    assert verdict.reason in ("io_rate", "read_then_write")
    assert verdict.comm == "cryptor"


def test_detection_is_fast_within_window(profiles):
    """La détection survient TÔT (bien avant la fin de la rafale) — mitige la
    race condition du chiffrement rapide (cahier §12)."""
    events = list(simulate.iter_ransomware_events("/sandbox", n_files=500))
    det = Detector(profiles)
    fired_at = None
    for idx, ev in enumerate(events):
        if det.observe(ev):
            fired_at = idx
            break
    assert fired_at is not None
    # doit se déclencher en bien moins d'événements que la trace complète
    assert fired_at < len(events) // 3


def test_canary_access_is_immediate(profiles):
    """F3.5/§12 : un seul accès canary par un process non whitelisté déclenche
    immédiatement, sans attendre le seuil d'I/O."""
    canaries = {"/docs/RIB_2023.pdf"}
    det = Detector(profiles, canary_paths=canaries)
    v = det.observe(Event(0.0, EV_OPEN, 9, "cryptor", "/docs/RIB_2023.pdf", 0))
    assert v is not None and v.reason == "canary_access"


def test_canary_access_by_whitelisted_is_allowed(profiles):
    """Un process whitelisté (backup) accédant à un canary ne déclenche pas."""
    canaries = {"/docs/RIB_2023.pdf"}
    det = Detector(profiles, canary_paths=canaries)
    v = det.observe(Event(0.0, EV_OPEN, 9, "rsync", "/docs/RIB_2023.pdf", 0))
    assert v is None


def test_mass_delete_detection(profiles):
    """F3.4 : suppression massive de fichiers distincts → détection."""
    det = Detector(profiles)
    verdict = None
    for ev in simulate.iter_massdelete_events("/sandbox", n_files=60):
        verdict = det.observe(ev)
        if verdict:
            break
    assert verdict is not None and verdict.reason in ("mass_delete", "io_rate")


def test_read_then_write_pattern(profiles):
    """F3.3 : lecture puis réécriture des mêmes fichiers (chiffrement en place)."""
    det = Detector(profiles)
    # étale les fichiers pour rester sous le seuil d'I/O mais accumuler du R-T-W
    fired = None
    ts = 0.0
    for i in range(40):
        path = f"/data/file_{i}.doc"
        det.observe(Event(ts, EV_OPEN, 5, "unknownx", path, 0))              # read
        v = det.observe(Event(ts, EV_OPEN, 5, "unknownx", path, O_WRONLY))   # write
        if v:
            fired = v
            break
        ts += 0.3  # espace dans le temps -> le seuil d'I/O ne se déclenche pas
    assert fired is not None and fired.reason == "read_then_write"


# ============================ SEUIL ADAPTATIF ===============================
def test_adaptive_threshold_spares_whitelisted_high_io(profiles):
    """CLAUDE.md §2.3 : un process whitelisté à fort I/O (node) ne déclenche
    jamais, alors qu'un inconnu au même débit déclencherait."""
    det_wl = Detector(profiles)
    det_unknown = Detector(profiles)
    fired_wl = fired_unknown = False
    for i in range(300):
        e_wl = Event(i * 0.001, EV_OPEN, 1, "node", f"/n/f{i}", O_WRONLY)
        e_uk = Event(i * 0.001, EV_OPEN, 2, "cryptor", f"/n/f{i}", O_WRONLY)
        if det_wl.observe(e_wl):
            fired_wl = True
        if det_unknown.observe(e_uk):
            fired_unknown = True
    assert not fired_wl, "process whitelisté ne doit pas déclencher"
    assert fired_unknown, "process inconnu au même débit doit déclencher"


def test_unknown_process_below_default_threshold_is_quiet(profiles):
    """Un process inconnu sous le seuil par défaut ne déclenche pas."""
    det = Detector(profiles)
    fired = False
    for i in range(10):  # 10 I/O, seuil défaut ~60
        if det.observe(Event(i * 0.01, EV_OPEN, 3, "somebin", f"/f{i}", O_WRONLY)):
            fired = True
    assert not fired


# ============================ RESPONDER ====================================
def test_responder_snapshot_and_kill_latency(tmp_path):
    """F4.1/F4.3/NF2 : le responder crée un snapshot ET tue le bon PID, en
    < 500 ms. On lance un vrai sous-processus (dummy) puis on le tue."""
    # dossier protégé avec du contenu à préserver
    protected = tmp_path / "Documents"
    protected.mkdir()
    for i in range(30):
        (protected / f"doc{i}.txt").write_text("contenu utilisateur " * 50)

    # sous-processus « ransomware » qui tourne (à tuer)
    proc = subprocess.Popen([sys.executable, "-c",
                             "import time\nwhile True: time.sleep(0.05)"])
    try:
        resp = Responder(tmp_path / "snapshots", tmp_path / "canaris.log")
        verdict = ce.Verdict(proc.pid, "cryptor", "io_rate", "test", 9.0, time.time())
        result = resp.respond(verdict, [protected])

        # snapshot créé et non vide
        snap = result["snapshot"]
        assert snap.exists()
        files = list(snap.rglob("*.txt"))
        assert len(files) == 30, f"snapshot incomplet: {len(files)} fichiers"
        # bon PID tué
        assert result["killed"] is True
        time.sleep(0.2)
        assert proc.poll() is not None, "le processus n'a pas été tué"
        # latence sous la cible NF2
        assert result["elapsed_ms"] < 500, f"latence {result['elapsed_ms']:.0f}ms >= 500ms"
        # journalisation (F4.6)
        assert (tmp_path / "canaris.log").exists()
    finally:
        if proc.poll() is None:
            proc.kill()


def test_incident_snapshot_captures_current_state(tmp_path):
    """Le snapshot forensique (post-incident) capture l'état courant par liens
    durs quasi instantanés. NB : c'est de la forensique, pas la source de
    restauration — celle-ci est le baseline (voir test_baseline_snapshot.py)."""
    protected = tmp_path / "data"
    protected.mkdir()
    (protected / "a.txt").write_text("secret")
    (protected / "sub").mkdir()
    (protected / "sub" / "b.txt").write_text("secret2")

    resp = Responder(tmp_path / "snap")
    snap = resp.incident_snapshot([protected])
    assert "post-incident" in snap.name
    assert (snap / "data" / "a.txt").read_text() == "secret"
    assert (snap / "data" / "sub" / "b.txt").read_text() == "secret2"
