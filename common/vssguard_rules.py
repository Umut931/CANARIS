#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""CANARIS — règles VssGuard (miroir Python de windows/driver/vssguard_rules.h).

Reconnaît les commandes de destruction de sauvegardes lancées par les
ransomwares AVANT chiffrement (cahier F5.1, CLAUDE.md §2.4). Cette version
Python est la référence testée par tests/test_vssguard_parsing.py ; le driver
Windows applique la même logique en C (header portable partagé).
"""
from __future__ import annotations

VG_NONE = "none"
VG_VSSADMIN_DELETE = "vssadmin delete shadows"
VG_VSSADMIN_RESIZE = "vssadmin resize shadowstorage"
VG_WMIC_SHADOW_DELETE = "wmic shadowcopy delete"
VG_BCDEDIT_RECOVERY = "bcdedit disable recovery"
VG_WBADMIN_DELETE = "wbadmin delete backup"
VG_PS_SHADOW_DELETE = "powershell shadowcopy delete"


def _ci(hay: str, needle: str) -> bool:
    return needle.lower() in (hay or "").lower()


def _image_is(image: str, suffix: str) -> bool:
    return (image or "").lower().endswith(suffix.lower())


def classify(image: str, cmdline: str) -> str:
    """Classe une création de processus. Renvoie VG_* (VG_NONE si bénin)."""
    cmd = cmdline or ""

    if _image_is(image, "vssadmin.exe") or _ci(cmd, "vssadmin"):
        if _ci(cmd, "delete") and _ci(cmd, "shadow"):
            return VG_VSSADMIN_DELETE
        if _ci(cmd, "resize") and _ci(cmd, "shadowstorage"):
            return VG_VSSADMIN_RESIZE
    if _image_is(image, "wmic.exe") or _ci(cmd, "wmic"):
        if _ci(cmd, "shadowcopy") and _ci(cmd, "delete"):
            return VG_WMIC_SHADOW_DELETE
    if _image_is(image, "bcdedit.exe") or _ci(cmd, "bcdedit"):
        if _ci(cmd, "recoveryenabled") and _ci(cmd, "no"):
            return VG_BCDEDIT_RECOVERY
        if _ci(cmd, "bootstatuspolicy") and _ci(cmd, "ignoreallfailures"):
            return VG_BCDEDIT_RECOVERY
    if _image_is(image, "wbadmin.exe") or _ci(cmd, "wbadmin"):
        if _ci(cmd, "delete") and (_ci(cmd, "catalog") or
                                   _ci(cmd, "systemstatebackup") or _ci(cmd, "backup")):
            return VG_WBADMIN_DELETE
    if (_image_is(image, "powershell.exe") or _image_is(image, "pwsh.exe")
            or _ci(cmd, "powershell")):
        if _ci(cmd, "win32_shadowcopy") and (_ci(cmd, "delete") or _ci(cmd, "remove")):
            return VG_PS_SHADOW_DELETE
    return VG_NONE


def is_suspicious(image: str, cmdline: str) -> bool:
    return classify(image, cmdline) != VG_NONE
