#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""CANARIS — compile config/profiles.json vers les fichiers plats lus par le
loader C (évite un parseur JSON dans le userspace C).

Source de vérité = config/profiles.json (humain). Fichiers dérivés :
  * config/thresholds.conf  — seuil PAR DÉFAUT + paramètres de détection
  * config/whitelist.txt    — EXÉCUTABLES de confiance (chemins) que le loader
                              résout en (device, inode) pour la map BPF

    python common/profiles_compile.py            # régénère les deux
    python common/profiles_compile.py --check    # vérifie qu'ils sont à jour
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PROFILES_JSON = ROOT / "config" / "profiles.json"
THRESHOLDS_CONF = ROOT / "config" / "thresholds.conf"
WHITELIST_TXT = ROOT / "config" / "whitelist.txt"

# Exécutables additionnels indispensables (toolchain/repli), whitelistés par
# chemin. Ajoutés à ceux de profiles.json.
EXTRA_EXES = ["/usr/bin/make", "/usr/bin/cc", "/usr/bin/gcc", "/usr/bin/ld",
              "/bin/cp", "/usr/local/bin/canaris"]


def compile_thresholds(config: dict) -> str:
    default = config.get("default", {})
    det = config.get("detection", {})
    lines = [
        "# CANARIS thresholds.conf — DÉRIVÉ de config/profiles.json.",
        "# Ne pas éditer à la main : lancer common/profiles_compile.py.",
        "# Seuil UNIQUE par défaut (pas de seuil par comm : le comm est",
        "# falsifiable ; les apps de confiance sont whitelistées par inode).",
        "# format: default <window_s> <io_threshold>",
        "#         mass_delete <n> | read_then_write <n>",
        f"default {default.get('window_seconds', 2.0)} {default.get('io_threshold', 60)}",
        f"mass_delete {det.get('mass_delete_threshold', 30)}",
        f"read_then_write {det.get('read_then_write_threshold', 12)}",
    ]
    return "\n".join(lines) + "\n"


def compile_whitelist(config: dict) -> str:
    paths = []
    for entry in config.get("whitelisted_executables", []):
        p = entry["path"] if isinstance(entry, dict) else str(entry)
        note = entry.get("note", "") if isinstance(entry, dict) else ""
        paths.append((p, note))
    seen = {p for p, _ in paths}
    for p in EXTRA_EXES:
        if p not in seen:
            paths.append((p, "toolchain/repli"))
            seen.add(p)

    lines = [
        "# CANARIS whitelist noyau — DÉRIVÉ de config/profiles.json.",
        "# Ne pas éditer à la main : lancer common/profiles_compile.py.",
        "# EXÉCUTABLES de confiance (chemins absolus, UN par ligne, sans commentaire",
        "# en ligne). Le loader résout chaque chemin en (device, inode) : l'exemption",
        "# est par INODE, jamais par comm (falsifiable). Chemins absents = ignorés.",
    ]
    lines.extend(p for p, _ in paths)   # chemins seuls (fichier consommé en C)
    return "\n".join(lines) + "\n"


def main(argv=None):
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass
    ap = argparse.ArgumentParser(description="Compile profiles.json -> config plats")
    ap.add_argument("--check", action="store_true",
                    help="échoue si les fichiers dérivés ne sont pas à jour")
    args = ap.parse_args(argv)

    config = json.loads(PROFILES_JSON.read_text(encoding="utf-8"))
    thresholds = compile_thresholds(config)
    whitelist = compile_whitelist(config)

    if args.check:
        cur_t = THRESHOLDS_CONF.read_text(encoding="utf-8") if THRESHOLDS_CONF.exists() else ""
        cur_w = WHITELIST_TXT.read_text(encoding="utf-8") if WHITELIST_TXT.exists() else ""
        if cur_t != thresholds or cur_w != whitelist:
            print("Fichiers dérivés PAS à jour (relancer profiles_compile.py)")
            return 1
        print("Fichiers dérivés à jour.")
        return 0

    THRESHOLDS_CONF.write_text(thresholds, encoding="utf-8")
    WHITELIST_TXT.write_text(whitelist, encoding="utf-8")
    print(f"✓ écrit {THRESHOLDS_CONF}")
    print(f"✓ écrit {WHITELIST_TXT} ({len(config.get('whitelisted_executables', []))} exes + extras)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
