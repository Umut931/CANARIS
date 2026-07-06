# -*- coding: utf-8 -*-
"""Tests du matching VssGuard (Phase 6, cahier F5.1).

Vérifie que la logique de parsing des command-lines reconnaît les commandes de
destruction de sauvegardes (vrais positifs) sans se déclencher sur des commandes
bénignes (vrais négatifs). Exécutable sans VM.

    python -m pytest tests/test_vssguard_parsing.py -v
"""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "common"))
import vssguard_rules as vg  # noqa: E402


SUSPICIOUS = [
    ("vssadmin.exe", "vssadmin delete shadows /all /quiet", vg.VG_VSSADMIN_DELETE),
    ("C:\\Windows\\System32\\vssadmin.exe", "vssadmin  Delete  Shadows /All",
     vg.VG_VSSADMIN_DELETE),
    ("vssadmin.exe", "vssadmin resize shadowstorage /for=c: /maxsize=401MB",
     vg.VG_VSSADMIN_RESIZE),
    ("wmic.exe", "wmic shadowcopy delete", vg.VG_WMIC_SHADOW_DELETE),
    ("WMIC.EXE", "WMIC SHADOWCOPY DELETE /NOINTERACTIVE", vg.VG_WMIC_SHADOW_DELETE),
    ("bcdedit.exe", "bcdedit /set {default} recoveryenabled No", vg.VG_BCDEDIT_RECOVERY),
    ("bcdedit.exe", "bcdedit /set {default} bootstatuspolicy ignoreallfailures",
     vg.VG_BCDEDIT_RECOVERY),
    ("wbadmin.exe", "wbadmin delete catalog -quiet", vg.VG_WBADMIN_DELETE),
    ("wbadmin.exe", "wbadmin delete systemstatebackup -keepversions:0",
     vg.VG_WBADMIN_DELETE),
    ("powershell.exe",
     "powershell -c \"Get-WmiObject Win32_Shadowcopy | Remove-WmiObject\"",
     vg.VG_PS_SHADOW_DELETE),
]

BENIGN = [
    ("vssadmin.exe", "vssadmin list shadows"),
    ("vssadmin.exe", "vssadmin list shadowstorage"),
    ("notepad.exe", "notepad C:\\Users\\me\\doc.txt"),
    ("bcdedit.exe", "bcdedit /enum"),
    ("wbadmin.exe", "wbadmin get status"),
    ("powershell.exe", "powershell Get-Process"),
    ("git.exe", "git commit -m 'delete old shadows of code'"),  # 'shadow' hors contexte
    ("cmd.exe", "cmd /c echo hello"),
]


@pytest.mark.parametrize("image,cmd,expected", SUSPICIOUS)
def test_suspicious_commands_detected(image, cmd, expected):
    assert vg.classify(image, cmd) == expected
    assert vg.is_suspicious(image, cmd)


@pytest.mark.parametrize("image,cmd", BENIGN)
def test_benign_commands_not_flagged(image, cmd):
    assert vg.classify(image, cmd) == vg.VG_NONE
    assert not vg.is_suspicious(image, cmd)


def test_git_commit_mentioning_shadow_is_not_flagged():
    """Garde-fou faux positif : une commande git mentionnant 'shadow' dans un
    message ne doit pas déclencher (pas d'outil vss/wmic/bcdedit)."""
    assert not vg.is_suspicious("git.exe",
                                "git commit -m 'refactor shadow delete logic'")
