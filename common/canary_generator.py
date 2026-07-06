#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""CANARIS — générateur de canary files réalistes (cross-OS).

Un canary file est un leurre : son accès par un processus non légitime signale
une activité de ransomware. Pour être indétectable par l'analyse heuristique
d'un ransomware moderne (CLAUDE.md §5, cahier F1), un canary doit :

  * porter des **magic bytes valides** pour son extension (.docx/.xlsx/.pdf/.txt)
    afin de passer pour un vrai document ;
  * avoir une **taille crédible** tirée d'une loi **log-normale** entre 50 Ko
    et 5 Mo (une taille uniforme paraîtrait artificielle) ;
  * présenter une **faible entropie** (< ~6 bits/octet) : un ransomware saute
    les fichiers déjà à haute entropie (supposés déjà chiffrés/compressés), donc
    un leurre chiffré-like serait ignoré. Le contenu est du texte lisible ;
  * avoir des **timestamps cohérents** (atime/mtime, + btime sur Windows) situés
    dans le passé, comme un document réellement utilisé ;
  * porter un **nom crédible** (RIB_2023.pdf, contrat_client.docx…) et être
    **placé en profondeur** dans Documents/Desktop/Downloads + sous-dossiers.

Le générateur produit aussi un manifeste (`canary_manifest.json`) et une liste
de chemins (`canary_files.txt`) consommée par le loader Linux
(`--canary-list`) et le service Windows.

Usage :
    python canary_generator.py --target-dir ~/Documents --count 20
    python canary_generator.py --target-dir C:\\Users\\me\\Documents \\
        --count 40 --extensions pdf,docx,txt --seed 1
"""
from __future__ import annotations

import argparse
import io
import json
import math
import os
import random
import struct
import sys
import time
import zipfile
from collections import Counter
from datetime import datetime, timedelta
from pathlib import Path

# --------------------------------------------------------------------------
# Bornes de taille (cahier F1.2)
# --------------------------------------------------------------------------
MIN_SIZE = 50 * 1024              # 50 Ko
MAX_SIZE = 5 * 1024 * 1024        # 5 Mo
SUPPORTED_EXTS = ("pdf", "docx", "xlsx", "txt")

# --------------------------------------------------------------------------
# Corpus de texte réaliste (faible entropie, français administratif crédible)
# --------------------------------------------------------------------------
_WORDS = (
    "facture client contrat montant total euros paiement échéance référence "
    "date signature société adresse numéro compte bancaire virement acompte "
    "prestation service livraison commande devis remise TVA hors taxes net à "
    "payer conditions générales vente responsabilité garantie confidentiel "
    "document interne rapport annuel exercice comptable bilan résultat charges "
    "produits trésorerie fournisseur commande bon réception quantité prix "
    "unitaire désignation article stock inventaire ressources humaines salaire "
    "bulletin paie cotisations congés effectif poste département direction "
    "projet planning livrable jalon budget prévisionnel réel écart analyse "
    "synthèse recommandation validation approbation diffusion restreinte "
    "monsieur madame veuillez agréer expression salutations distinguées objet "
    "courrier recommandé accusé réception pièce jointe cordialement"
).split()

_FIRST_NAMES = ["Jean", "Marie", "Pierre", "Sophie", "Luc", "Camille", "Nicolas",
                "Julie", "Thomas", "Emma", "Antoine", "Chloé", "Paul", "Léa"]
_LAST_NAMES = ["Martin", "Bernard", "Dubois", "Durand", "Moreau", "Laurent",
               "Simon", "Michel", "Lefebvre", "Garcia", "Roux", "Fontaine"]

# Noms de fichiers crédibles par extension (cahier F1.6)
_NAME_TEMPLATES = {
    "pdf":  ["RIB_{year}", "releve_bancaire_{month}_{year}", "facture_{num}",
             "contrat_bail_{year}", "attestation_{year}", "bulletin_paie_{month}_{year}",
             "avis_imposition_{year}", "quittance_loyer_{month}_{year}"],
    "docx": ["contrat_client_{name}", "compte_rendu_reunion_{date}", "lettre_motivation",
             "rapport_activite_{year}", "note_de_service_{num}", "cv_{name}",
             "convention_{year}", "proces_verbal_{date}"],
    "xlsx": ["budget_{year}", "suivi_tresorerie_{year}", "inventaire_{month}_{year}",
             "planning_projet_{year}", "tableau_bord_{month}", "comptes_{year}",
             "liste_clients_{year}", "frais_deplacement_{month}_{year}"],
    "txt":  ["notes_{date}", "mots_de_passe_perso", "todo_{year}", "brouillon_{num}",
             "identifiants_comptes", "memo_{month}", "coordonnees_{name}"],
}

# Sous-arborescences réalistes (>= 2 niveaux, cahier F1.5)
_SUBTREES = [
    "Documents/Factures/{year}",
    "Documents/Administratif/Impots",
    "Documents/Banque/Releves",
    "Documents/Travail/Contrats",
    "Documents/Personnel/Famille",
    "Desktop/Projets/Client_{name}",
    "Desktop/A_traiter/Urgent",
    "Downloads/Recus/{year}",
    "Downloads/Archives/{month}",
]


# ==========================================================================
# Entropie
# ==========================================================================
def shannon_entropy(data: bytes) -> float:
    """Entropie de Shannon en bits/octet (0..8). Sert de preuve que le
    contenu ne ressemble pas à du chiffré (cible < 6, cf. tests)."""
    if not data:
        return 0.0
    counts = Counter(data)
    n = len(data)
    ent = 0.0
    for c in counts.values():
        p = c / n
        ent -= p * math.log2(p)
    return ent


# ==========================================================================
# Génération de texte lisible (faible entropie)
# ==========================================================================
def _make_person(rng: random.Random) -> str:
    return f"{rng.choice(_FIRST_NAMES)} {rng.choice(_LAST_NAMES)}"


def readable_text(target_bytes: int, rng: random.Random) -> str:
    """Produit du texte français crédible d'environ `target_bytes` octets.
    L'entropie de ce texte est ~4 bits/octet (mots répétés, ponctuation)."""
    out = []
    size = 0
    # En-tête de type courrier/document
    header = (
        f"Société GÉNÉRALE DES EXEMPLES SARL\n"
        f"{rng.randint(1, 200)} rue de la République, {rng.randint(10000, 99999)} "
        f"{rng.choice(['Paris', 'Lyon', 'Lille', 'Nantes', 'Bordeaux'])}\n"
        f"Objet : {rng.choice(['Facture', 'Contrat', 'Relevé', 'Note'])} "
        f"n°{rng.randint(1000, 9999)}\n"
        f"À l'attention de {_make_person(rng)}\n\n"
    )
    out.append(header)
    size += len(header.encode("utf-8"))
    while size < target_bytes:
        # phrase de 8 à 18 mots
        nwords = rng.randint(8, 18)
        words = rng.choices(_WORDS, k=nwords)
        sentence = " ".join(words).capitalize() + rng.choice([".", ".", ".", " :", " ;"]) + " "
        if rng.random() < 0.15:
            sentence += "\n"
        if rng.random() < 0.05:
            sentence += (f"\nMontant : {rng.randint(50, 9999)},{rng.randint(0,99):02d} € "
                         f"- Réf {rng.randint(100000, 999999)}\n")
        out.append(sentence)
        size += len(sentence.encode("utf-8"))
    return "".join(out)


# ==========================================================================
# Constructeurs par format (magic bytes valides — cahier F1.1)
# ==========================================================================
def build_txt(target: int, rng: random.Random) -> bytes:
    """.txt : texte brut (pas de magic bytes ; BOM UTF-8 optionnel)."""
    txt = readable_text(target, rng)
    data = txt.encode("utf-8")
    return data[:target] if len(data) > target else data


def build_pdf(target: int, rng: random.Random) -> bytes:
    """PDF valide (magic %PDF-), un objet stream de texte lisible non compressé,
    table xref correcte. Structure conforme, faible entropie."""
    # Corps de texte (stream de contenu non compressé)
    body_text = readable_text(max(target - 2048, 1024), rng)
    # Échapper les caractères PDF spéciaux dans le flux montré
    esc = body_text.replace("\\", r"\\").replace("(", r"\(").replace(")", r"\)")
    # Un flux de contenu qui "montre" du texte + du remplissage lisible en commentaire
    stream = (
        "BT\n/F1 12 Tf\n72 720 Td\n14 TL\n"
        + "".join(f"({line[:90]}) Tj T*\n"
                 for line in esc.splitlines()[:40])
        + "ET\n"
        + "% " + esc.replace("\n", "\n% ")  # remplissage lisible commenté
    ).encode("latin-1", "replace")

    objects = []
    objects.append(b"<< /Type /Catalog /Pages 2 0 R >>")
    objects.append(b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>")
    objects.append(b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] "
                   b"/Resources << /Font << /F1 5 0 R >> >> /Contents 4 0 R >>")
    objects.append(b"<< /Length " + str(len(stream)).encode() + b" >>\nstream\n"
                   + stream + b"\nendstream")
    objects.append(b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>")

    out = io.BytesIO()
    out.write(b"%PDF-1.7\n%\xe2\xe3\xcf\xd3\n")  # header + binary comment marker
    offsets = []
    for i, obj in enumerate(objects, start=1):
        offsets.append(out.tell())
        out.write(f"{i} 0 obj\n".encode())
        out.write(obj)
        out.write(b"\nendobj\n")
    xref_pos = out.tell()
    n = len(objects) + 1
    out.write(f"xref\n0 {n}\n".encode())
    out.write(b"0000000000 65535 f \n")
    for off in offsets:
        out.write(f"{off:010d} 00000 n \n".encode())
    out.write(b"trailer\n")
    out.write(f"<< /Size {n} /Root 1 0 R >>\n".encode())
    out.write(b"startxref\n")
    out.write(f"{xref_pos}\n".encode())
    out.write(b"%%EOF\n")
    data = out.getvalue()

    # Ajuster à la taille cible : padding par commentaires lisibles avant %%EOF
    if len(data) < target:
        pad_needed = target - len(data)
        pad = ("\n% " + readable_text(pad_needed + 64, rng).replace("\n", "\n% "))
        pad_bytes = pad.encode("latin-1", "replace")[:pad_needed]
        data = data.replace(b"%%EOF\n", pad_bytes + b"\n%%EOF\n")
    return data


def _zip_stored(files: dict[str, bytes]) -> bytes:
    """Construit un ZIP **non compressé** (ZIP_STORED) : conserve la faible
    entropie du texte (la compression augmenterait l'entropie apparente).
    Base des formats OOXML (.docx/.xlsx), magic bytes PK\\x03\\x04."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_STORED) as z:
        for name, content in files.items():
            z.writestr(name, content)
    return buf.getvalue()


def build_docx(target: int, rng: random.Random) -> bytes:
    """.docx minimal mais **valide** (OOXML WordprocessingML), non compressé."""
    paras = readable_text(max(target - 4096, 1024), rng).splitlines()
    body = "".join(
        "<w:p><w:r><w:t xml:space=\"preserve\">"
        + (p.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;"))
        + "</w:t></w:r></w:p>"
        for p in paras if p.strip()
    )
    document = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
        f"<w:body>{body}<w:sectPr/></w:body></w:document>"
    )
    content_types = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
        '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
        '<Default Extension="xml" ContentType="application/xml"/>'
        '<Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>'
        '</Types>'
    )
    rels = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>'
        '</Relationships>'
    )
    return _zip_stored({
        "[Content_Types].xml": content_types.encode("utf-8"),
        "_rels/.rels": rels.encode("utf-8"),
        "word/document.xml": document.encode("utf-8"),
    })


def build_xlsx(target: int, rng: random.Random) -> bytes:
    """.xlsx minimal mais **valide** (OOXML SpreadsheetML), non compressé."""
    # Remplit une feuille de lignes lisibles (désignation ; montant)
    rows = []
    r = 1
    approx = 0
    while approx < max(target - 4096, 1024):
        label = " ".join(rng.choices(_WORDS, k=rng.randint(2, 5)))
        val = f"{rng.randint(10, 99999)}.{rng.randint(0,99):02d}"
        cell = (f'<row r="{r}"><c r="A{r}" t="inlineStr"><is><t>'
                f'{label}</t></is></c><c r="B{r}"><v>{val}</v></c></row>')
        rows.append(cell)
        approx += len(cell)
        r += 1
    sheet = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
        f"<sheetData>{''.join(rows)}</sheetData></worksheet>"
    )
    workbook = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" '
        'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">'
        '<sheets><sheet name="Feuil1" sheetId="1" r:id="rId1"/></sheets></workbook>'
    )
    wb_rels = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/>'
        '</Relationships>'
    )
    content_types = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
        '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
        '<Default Extension="xml" ContentType="application/xml"/>'
        '<Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>'
        '<Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>'
        '</Types>'
    )
    rels = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/>'
        '</Relationships>'
    )
    return _zip_stored({
        "[Content_Types].xml": content_types.encode("utf-8"),
        "_rels/.rels": rels.encode("utf-8"),
        "xl/workbook.xml": workbook.encode("utf-8"),
        "xl/_rels/workbook.xml.rels": wb_rels.encode("utf-8"),
        "xl/worksheets/sheet1.xml": sheet.encode("utf-8"),
    })


_BUILDERS = {
    "txt": build_txt,
    "pdf": build_pdf,
    "docx": build_docx,
    "xlsx": build_xlsx,
}

# Magic bytes attendus par extension (pour les tests / vérification)
MAGIC = {
    "pdf": b"%PDF-",
    "docx": b"PK\x03\x04",
    "xlsx": b"PK\x03\x04",
    "txt": None,  # pas de magic imposé
}


# ==========================================================================
# Taille : loi log-normale bornée (cahier F1.2)
# ==========================================================================
def sample_size(rng: random.Random) -> int:
    """Tire une taille en octets selon une loi log-normale, bornée
    [50 Ko, 5 Mo]. Médiane ~300 Ko, longue traîne vers 5 Mo."""
    # médiane exp(mu) = 300 Ko ; sigma module l'étalement
    mu = math.log(300 * 1024)
    sigma = 0.9
    for _ in range(64):
        val = rng.lognormvariate(mu, sigma)
        if MIN_SIZE <= val <= MAX_SIZE:
            return int(val)
    return int(min(max(val, MIN_SIZE), MAX_SIZE))


# ==========================================================================
# Timestamps cohérents (cahier F1.4)
# ==========================================================================
def _rand_past_times(rng: random.Random):
    """Renvoie (btime, mtime, atime) en epoch, cohérents et dans le passé :
    création il y a 1..3 ans, dernière modif après, dernier accès après."""
    now = time.time()
    created = now - rng.uniform(365, 3 * 365) * 86400
    modified = created + rng.uniform(0, (now - created) * 0.8)
    accessed = modified + rng.uniform(0, (now - modified) * 0.9)
    return created, modified, accessed


def _set_windows_times(path: Path, created, accessed, modified) -> bool:
    """Positionne les 3 timestamps sous Windows via SetFileTime (kernel32),
    y compris le **btime** (creation time). Renvoie True si appliqué."""
    import ctypes
    from ctypes import wintypes

    EPOCH_AS_FILETIME = 116444736000000000  # 1601->1970 en unités de 100 ns
    HUNDREDS_OF_NS = 10_000_000

    def to_ft(ts):
        v = int(ts * HUNDREDS_OF_NS) + EPOCH_AS_FILETIME
        return wintypes.FILETIME(v & 0xFFFFFFFF, (v >> 32) & 0xFFFFFFFF)

    GENERIC_WRITE = 0x40000000
    FILE_WRITE_ATTRIBUTES = 0x100
    OPEN_EXISTING = 3
    FILE_ATTRIBUTE_NORMAL = 0x80

    CreateFileW = ctypes.windll.kernel32.CreateFileW
    CreateFileW.restype = wintypes.HANDLE
    CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
                            ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD,
                            wintypes.HANDLE]
    handle = CreateFileW(str(path), FILE_WRITE_ATTRIBUTES, 0, None,
                         OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, None)
    if handle == wintypes.HANDLE(-1).value or handle is None:
        return False
    try:
        ct, at, mt = to_ft(created), to_ft(accessed), to_ft(modified)
        SetFileTime = ctypes.windll.kernel32.SetFileTime
        ok = SetFileTime(handle, ctypes.byref(ct), ctypes.byref(at),
                         ctypes.byref(mt))
        return bool(ok)
    finally:
        ctypes.windll.kernel32.CloseHandle(handle)


def apply_timestamps(path: Path, rng: random.Random) -> dict:
    """Applique atime/mtime (+ btime sur Windows). Sous Linux, btime n'est pas
    modifiable par les API standard (nécessite debugfs) : documenté, non bloquant."""
    created, modified, accessed = _rand_past_times(rng)
    info = {"btime": created, "mtime": modified, "atime": accessed,
            "btime_set": False}
    if os.name == "nt":
        info["btime_set"] = _set_windows_times(path, created, accessed, modified)
        # os.utime pour garantir atime/mtime aussi
        os.utime(path, (accessed, modified))
    else:
        os.utime(path, (accessed, modified))
        # btime : voir HANDOFF (debugfs set_inode_field crtime). Non modifiable ici.
    return info


# ==========================================================================
# Nommage & placement
# ==========================================================================
def _fmt(template: str, rng: random.Random) -> str:
    year = rng.randint(2019, 2024)
    month = rng.choice(["janvier", "fevrier", "mars", "avril", "mai", "juin",
                        "juillet", "aout", "septembre", "octobre", "novembre",
                        "decembre"])
    return template.format(
        year=year, month=month, num=rng.randint(100, 9999),
        date=f"{rng.randint(1,28):02d}-{rng.randint(1,12):02d}-{year}",
        name=rng.choice(_LAST_NAMES),
    )


def make_name(ext: str, rng: random.Random, used: set) -> str:
    for _ in range(50):
        base = _fmt(rng.choice(_NAME_TEMPLATES[ext]), rng)
        name = f"{base}.{ext}"
        if name not in used:
            used.add(name)
            return name
    used.add(f"{base}_{rng.randint(1,99999)}.{ext}")
    return f"{base}_{rng.randint(1,99999)}.{ext}"


def make_subdir(target_dir: Path, rng: random.Random) -> Path:
    tree = _fmt(rng.choice(_SUBTREES), rng)
    d = target_dir / tree
    d.mkdir(parents=True, exist_ok=True)
    return d


# ==========================================================================
# Génération principale
# ==========================================================================
def generate(target_dir: Path, count: int, extensions, seed=None,
             verbose=True) -> list[dict]:
    rng = random.Random(seed)
    exts = [e.strip().lower().lstrip(".") for e in extensions]
    for e in exts:
        if e not in SUPPORTED_EXTS:
            raise ValueError(f"extension non supportée: {e} (dispo: {SUPPORTED_EXTS})")

    target_dir = target_dir.expanduser().resolve()
    target_dir.mkdir(parents=True, exist_ok=True)
    used_names: set = set()
    manifest = []

    for i in range(count):
        ext = exts[i % len(exts)] if len(exts) > 1 else exts[0]
        ext = rng.choice(exts)
        size = sample_size(rng)
        data = _BUILDERS[ext](size, rng)
        subdir = make_subdir(target_dir, rng)
        name = make_name(ext, rng, used_names)
        path = subdir / name
        path.write_bytes(data)
        ts = apply_timestamps(path, rng)
        ent = shannon_entropy(data if len(data) <= 262144 else data[:262144])
        entry = {
            "path": str(path),
            "ext": ext,
            "size": len(data),
            "entropy_bits_per_byte": round(ent, 3),
            "btime": ts["btime"], "mtime": ts["mtime"], "atime": ts["atime"],
            "btime_set": ts["btime_set"],
        }
        manifest.append(entry)
        if verbose:
            print(f"  [{i+1:>3}/{count}] {ext:>4}  {len(data):>9,} o  "
                  f"H={ent:4.2f}  {path.relative_to(target_dir)}")
    return manifest


def default_control_dir() -> Path:
    """Répertoire de contrôle par défaut, HORS de l'arbre protégé/scanné."""
    return Path.home() / ".canaris"


def write_manifest(manifest, control_dir: Path):
    """Écrit canary_manifest.json (riche) + canary_files.txt (chemins bruts) dans
    le RÉPERTOIRE DE CONTRÔLE — JAMAIS dans l'arbre protégé (T3).

    Un manifeste laissé dans le dossier scanné serait une « carte au trésor » :
    un ransomware le lirait pour éviter tous les canaries. Le répertoire de
    contrôle est distinct (défaut ~/.canaris/), en dehors de --target-dir."""
    control_dir = Path(control_dir)
    control_dir.mkdir(parents=True, exist_ok=True)
    man_path = control_dir / "canary_manifest.json"
    list_path = control_dir / "canary_files.txt"
    with open(man_path, "w", encoding="utf-8") as f:
        json.dump({"generated_at": datetime.now().isoformat(),
                   "count": len(manifest), "canaries": manifest}, f,
                  indent=2, ensure_ascii=False)
    with open(list_path, "w", encoding="utf-8") as f:
        for e in manifest:
            f.write(e["path"] + "\n")
    try:
        os.chmod(control_dir, 0o700)  # limite l'accès au répertoire de contrôle
    except OSError:
        pass
    return man_path, list_path


def main(argv=None):
    # La console Windows par défaut (cp1252) ne peut pas encoder ✓/⚠️ : on
    # bascule stdout/stderr en UTF-8 tolérant si possible.
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass

    p = argparse.ArgumentParser(description="Générateur de canary files CANARIS")
    p.add_argument("--target-dir", required=True, help="Répertoire racine cible")
    p.add_argument("--control-dir", default=None,
                   help="Répertoire de contrôle pour le manifeste/la liste, HORS "
                        "de l'arbre protégé (défaut ~/.canaris/)")
    p.add_argument("--count", type=int, default=20, help="Nombre de canaries")
    p.add_argument("--extensions", default="pdf,docx,xlsx,txt",
                   help="Extensions séparées par des virgules")
    p.add_argument("--seed", type=int, default=None, help="Graine (reproductible)")
    p.add_argument("--quiet", action="store_true")
    args = p.parse_args(argv)

    target = Path(args.target_dir).expanduser().resolve()
    control = Path(args.control_dir).expanduser().resolve() if args.control_dir \
        else default_control_dir()
    # SÉCURITÉ T3 : le répertoire de contrôle ne doit JAMAIS être sous la cible
    # protégée (sinon le manifeste redevient une carte au trésor scannée).
    try:
        control.relative_to(target)
        print(f"ERREUR: --control-dir ({control}) est sous --target-dir ({target}). "
              f"Le manifeste serait exposé au ransomware. Choisissez un dossier séparé.")
        return 2
    except ValueError:
        pass

    exts = args.extensions.split(",")
    print(f"CANARIS — génération de {args.count} canary(s) dans {target}")
    print(f"          manifeste/liste dans le contrôle : {control}")
    manifest = generate(target, args.count, exts, seed=args.seed,
                        verbose=not args.quiet)
    man_path, list_path = write_manifest(manifest, control)
    total = sum(e["size"] for e in manifest)
    avg_ent = sum(e["entropy_bits_per_byte"] for e in manifest) / max(len(manifest), 1)
    n_high = sum(1 for e in manifest if e["entropy_bits_per_byte"] >= 6.0)
    print(f"\n✓ {len(manifest)} canaries — {total:,} octets — entropie moy. "
          f"{avg_ent:.2f} bits/o ({n_high} au-dessus de 6.0)")
    print(f"✓ Manifeste : {man_path}")
    print(f"✓ Liste (loader) : {list_path}")
    if n_high:
        print("⚠️  certains fichiers dépassent 6 bits/o — à investiguer")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
