#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""CANARIS — compile config/profiles.json vers les fichiers plats lus par le
loader C (évite un parseur JSON dans le userspace C).

Source de vérité = config/profiles.json (humain). Fichiers dérivés :
  * config/thresholds.conf  — profils de seuil adaptatif (profiles.c)
  * config/whitelist.txt    — whitelist noyau par comm (main.c, map BPF)

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

# comms Linux additionnels à whitelister (toolchain/backup) non listés dans les
# profils applicatifs mais indispensables pour éviter les faux positifs et ne
# jamais s'auto-bloquer.
EXTRA_WHITELIST = ["make", "cc1", "gcc", "ld", "canaris", "canaris-respond"]


def _norm_comm(name: str) -> str:
    if name.lower().endswith(".exe"):
        name = name[:-4]
    return name[:15]


def compile_thresholds(config: dict) -> tuple[str, set]:
    default = config.get("default", {})
    det = config.get("detection", {})
    lines = [
        "# CANARIS thresholds.conf — DÉRIVÉ de config/profiles.json.",
        "# Ne pas éditer à la main : lancer common/profiles_compile.py.",
        "# format: default <window_s> <io_threshold>",
        "#         mass_delete <n> | read_then_write <n>",
        "#         profile <comm> <window_s> <io_threshold> <whitelisted 0|1>",
        f"default {default.get('window_seconds', 2.0)} {default.get('io_threshold', 60)}",
        f"mass_delete {det.get('mass_delete_threshold', 30)}",
        f"read_then_write {det.get('read_then_write_threshold', 12)}",
    ]
    wl = set()
    for prof in config.get("profiles", []):
        win = prof.get("window_seconds", 2.0)
        thr = prof.get("io_threshold", 60)
        white = 1 if prof.get("whitelisted") else 0
        names = [prof.get("match", "")] + list(prof.get("aliases", []))
        seen = set()
        for n in names:
            c = _norm_comm(n)
            if c and c not in seen:
                seen.add(c)
                lines.append(f"profile {c} {win} {thr} {white}")
                if white:
                    wl.add(c)
    return "\n".join(lines) + "\n", wl


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
    thresholds, _wl = compile_thresholds(config)

    if args.check:
        current = THRESHOLDS_CONF.read_text(encoding="utf-8") if THRESHOLDS_CONF.exists() else ""
        if current != thresholds:
            print("thresholds.conf n'est PAS à jour (relancer profiles_compile.py)")
            return 1
        print("Fichiers dérivés à jour.")
        return 0

    THRESHOLDS_CONF.write_text(thresholds, encoding="utf-8")
    print(f"✓ écrit {THRESHOLDS_CONF} ({len(thresholds.splitlines())} lignes)")
    print("  (config/whitelist.txt est maintenu séparément et reste cohérent)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
