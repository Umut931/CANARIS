# Cahier des charges — CANARIS

**Logiciel anti-ransomware multi-OS à interception noyau**

| | |
|---|---|
| **Projet** | CANARIS |
| **Type** | Logiciel de sécurité endpoint (détection & réponse anti-ransomware) |
| **Plateformes** | Windows 10/11 (x64), Linux (kernel ≥ 5.7) |
| **Auteur** | Umut Celikler — Bachelor Cybersécurité & Ethical Hacking, EFREI Paris |
| **Version doc** | 1.0 |
| **Statut** | Conception validée — Architecture complète (Option A) |

---

## 1. Présentation du projet

### 1.1 Contexte

Les antivirus classiques reposent majoritairement sur des signatures et réagissent **après** que le chiffrement a commencé. Les ransomwares modernes (LockBit 3.0, BlackCat/ALPHV, Conti) chiffrent des milliers de fichiers par minute en multithreading, suppriment les sauvegardes système en préambule, et détectent les leurres simplistes par analyse de métadonnées.

CANARIS propose une défense **proactive et bas niveau** : au lieu d'attendre une signature connue, le logiciel détecte le **comportement** du ransomware (accès à des fichiers leurres, taux d'I/O anormal, suppression de snapshots) et l'intercepte **depuis le noyau**, hors de portée du malware, puis préserve les données via snapshot instantané.

### 1.2 Objectifs

- **O1** — Détecter un ransomware en cours d'exécution en moins de 500 ms après son premier comportement suspect
- **O2** — Bloquer réellement les opérations malveillantes depuis le noyau (pas seulement les journaliser)
- **O3** — Préserver les données par snapshot automatique avant qu'elles ne soient chiffrées ou supprimées
- **O4** — Maintenir un taux de faux positifs < 1 % sur des charges de travail normales
- **O5** — Fonctionner sur Windows et Linux avec une architecture cohérente

### 1.3 Public visé

Projet de portfolio technique à visée démonstrative (VM, entretien, GitHub). **Non destiné à un déploiement production Windows signé** (contrainte WHQL documentée en §9).

---

## 2. Périmètre

### 2.1 Dans le périmètre

- Détection comportementale par canary files réalistes
- Interception filesystem noyau (blocage réel des I/O)
- Détection du taux d'I/O anormal avec seuil adaptatif par processus
- Détection de la suppression de shadow copies / sauvegardes
- Réponse automatique : terminaison du processus + snapshot
- Support Windows (minifilter) et Linux (eBPF + LSM BPF)

### 2.2 Hors périmètre

- ❌ **Chiffrement préventif des dossiers** (rejeté par analyse de risque — voir §8)
- ❌ Envoi de clé de déchiffrement à un tiers de confiance
- ❌ macOS, Android, systèmes embarqués
- ❌ Ransomwares in-memory (sans écriture disque)
- ❌ Ransomwares ciblant les hyperviseurs (ESXi/VMware)
- ❌ Défense contre le mouvement latéral réseau (SMB)
- ❌ Déploiement production Windows signé WHQL

---

## 3. Architecture générale

CANARIS repose sur **trois piliers** déclinés sur chaque OS :

```
                    ┌─────────────────────────────┐
                    │      CANARY FILES (leurres)  │
                    │  réalistes, faible entropie  │
                    └──────────────┬──────────────┘
                                   │ accès détecté
              ┌────────────────────┴────────────────────┐
              │                                          │
      ┌───────▼────────┐                        ┌────────▼───────┐
      │   WINDOWS       │                        │    LINUX        │
      │  Minifilter     │                        │  eBPF + LSM BPF │
      │  (Ring 0)       │                        │  (kernel)       │
      │                 │                        │                 │
      │ • IRP_MJ_CREATE │                        │ • kprobes       │
      │ • IRP_MJ_WRITE  │                        │   (observation) │
      │ • IRP_MJ_SET_INFO│                       │ • LSM hooks     │
      │ • STATUS_ACCESS_│                        │   (blocage      │
      │   DENIED (block)│                        │    -EPERM)      │
      │ • VssGuard      │                        │ • ring buffer   │
      └───────┬─────────┘                        └────────┬────────┘
              │ notification (comm port)                  │ ring buffer
      ┌───────▼─────────┐                        ┌────────▼────────┐
      │  Service         │                        │  Userspace      │
      │  userspace       │                        │  (libbpf)       │
      │  • kill process  │                        │  • kill process │
      │  • VSS snapshot  │                        │  • rsync snap   │
      └──────────────────┘                        └─────────────────┘
```

---

## 4. Exigences fonctionnelles

### F1 — Génération de canary files réalistes

| Réf | Exigence | Priorité |
|---|---|---|
| F1.1 | Générer des fichiers leurres avec magic bytes valides par extension (.docx, .xlsx, .pdf, .txt) | Haute |
| F1.2 | Tailles distribuées en loi log-normale entre 50 Ko et 5 Mo | Haute |
| F1.3 | Contenu à **faible entropie** (lisible, ne ressemblant pas à du chiffré) | Haute |
| F1.4 | Timestamps `atime`, `mtime`, `btime` modifiés de façon cohérente | Haute |
| F1.5 | Placement dans Documents, Desktop, Downloads + sous-dossiers profonds | Moyenne |
| F1.6 | Nommage crédible (pas de « canary.txt », mais « RIB_2023.pdf », « contrat_client.docx ») | Moyenne |

### F2 — Interception & blocage noyau

| Réf | Exigence | Priorité |
|---|---|---|
| F2.1 (Win) | Minifilter interceptant `IRP_MJ_CREATE`, `IRP_MJ_WRITE`, `IRP_MJ_SET_INFORMATION` | Haute |
| F2.2 (Win) | Blocage immédiat via `STATUS_ACCESS_DENIED` sur accès canary ou dossier protégé par processus non whitelisté | Haute |
| F2.3 (Win) | Enregistrement à une altitude dans la plage anti-malware (320000–329999) | Haute |
| F2.4 (Lin) | kprobes d'observation sur `__x64_sys_openat`, `__x64_sys_write`, `__x64_sys_unlinkat` | Haute |
| F2.5 (Lin) | LSM BPF hooks (`lsm/file_open`, `lsm/inode_unlink`, `lsm/inode_rename`) retournant `-EPERM` pour bloquer | Haute |
| F2.6 | Whitelist de processus légitimes (backup, sync, IDE) exemptés du blocage | Haute |

### F3 — Détection comportementale

| Réf | Exigence | Priorité |
|---|---|---|
| F3.1 | Compteur d'I/O par PID sur fenêtre glissante (défaut 2 s) | Haute |
| F3.2 | **Seuil adaptatif par profil de processus** (baseline calibrée, pas de seuil global fixe) | Haute |
| F3.3 | Détection du pattern read-then-write sur les mêmes fichiers | Moyenne |
| F3.4 | Détection de suppression massive de fichiers | Moyenne |
| F3.5 | Détection de la suppression de shadow copies / sauvegardes (signal prioritaire, indépendant du seuil I/O) | Haute |

### F4 — Réponse automatique

| Réf | Exigence | Priorité |
|---|---|---|
| F4.1 | Terminaison du processus suspect | Haute |
| F4.2 (Win) | Déclenchement d'un snapshot VSS via IOCTL dédié | Haute |
| F4.3 (Lin) | Snapshot via `rsync --link-dest` ou `cp -a` (copie incrémentale à liens durs) | Haute |
| F4.4 | Gel des accès aux dossiers protégés pendant la réponse | Moyenne |
| F4.5 | Notification à l'utilisateur (log + alerte visuelle) | Moyenne |
| F4.6 | Journalisation horodatée de tous les événements de détection/réponse | Haute |

### F5 — Détection anti-suppression de sauvegardes (VssGuard)

| Réf | Exigence | Priorité |
|---|---|---|
| F5.1 (Win) | Détecter l'exécution de `vssadmin delete shadows`, `wmic shadowcopy delete`, `bcdedit` avec arguments suspects via callback de création de processus (`PsSetCreateProcessNotifyRoutineEx`) | Haute |
| F5.2 (Win) | Optionnellement bloquer ces exécutions ou déclencher immédiatement la réponse maximale | Haute |
| F5.3 (Lin) | Détecter la suppression de répertoires de snapshot / d'outils de backup | Moyenne |

---

## 5. Exigences non-fonctionnelles

### 5.1 Performance

- **NF1** — Latence I/O ajoutée par l'interception < 5 % sur des accès fichiers normaux (à mesurer par benchmark)
- **NF2** — Temps de réaction détection → kill → snapshot < 500 ms
- **NF3** — Empreinte mémoire du service userspace < 100 Mo

### 5.2 Fiabilité

- **NF4** — Zéro BSOD / kernel panic pendant les tests (Driver Verifier / BPF verifier obligatoires)
- **NF5** — Faux positifs < 1 % sur 24 h de charge normale (OneDrive, npm install, git clone, scan Defender)
- **NF6** — Dégradation gracieuse : si le minifilter ne peut charger, basculer sur Controlled Folder Access + ETW (documenté)

### 5.3 Sécurité (du logiciel lui-même)

- **NF7** — Aucun secret en clair (config, code, logs)
- **NF8** — Le service userspace ne doit pas être terminable par un processus non privilégié
- **NF9** — Communication kernel ↔ userspace via canal authentifié (communication port Windows / vérification PID côté Linux)

### 5.4 Compatibilité

- **NF10** — Windows 10 1607+ et Windows 11 (x64)
- **NF11** — Linux kernel ≥ 5.7 avec BTF (`/sys/kernel/btf/vmlinux` présent) et LSM BPF activé
- **NF12** — Coexistence avec Microsoft Defender (choix d'altitude non conflictuel)

---

## 6. Contraintes techniques

| Contrainte | Description | Traitement |
|---|---|---|
| **DSE** | Driver signé requis en prod Windows | Test Signing en VM ; prod hors scope |
| **HVCI** | Bloque drivers non-WHQL | Désactivé dans la VM de test |
| **Secure Boot** | Incompatible Test Signing | Désactivé dans la VM |
| **BPF verifier** | Rejette les programmes non sûrs | Programmes bornés & simples |
| **kprobes read-only** | Ne peuvent pas bloquer | Blocage délégué aux LSM BPF hooks |
| **Coût WHQL** | EV + tests Microsoft, plusieurs k€, 3-6 mois | Non résolu — limitation assumée |

---

## 7. Livrables

| Livrable | Description |
|---|---|
| **L1** | Composant Linux : programmes eBPF (kprobes + LSM) + loader userspace libbpf |
| **L2** | Composant Windows : minifilter driver + service userspace |
| **L3** | Générateur de canary files (Python, cross-OS) |
| **L4** | Suite de tests : scénarios ransomware (RanSim/simulateur) + workloads faux positifs |
| **L5** | Documentation : `ARCHITECTURE.md`, `THREAT_MODEL.md`, `LIMITATIONS.md`, `README.md` |
| **L6** | Vidéo démo (30-60 s) : détection + snapshot en VM |
| **L7** | Dépôt GitHub public documenté |

---

## 8. Justification du rejet du chiffrement préventif

L'idée initiale prévoyait de chiffrer préventivement les dossiers importants et d'envoyer la clé à une adresse de confiance. **Cette fonctionnalité est rejetée** pour les raisons suivantes :

1. **Réimplémentation du ransomware** — chiffrer soi-même les fichiers = même mécanisme que l'attaque
2. **Perte de clé = auto-ransomware** — réseau coupé, adresse compromise ou bug ⇒ données perdues par nos soins
3. **Single point of failure** — le canal d'envoi de clé est interceptable (MITM), l'attaquant récupère la clé
4. **Latence** — chiffrement symétrique temps réel sur tous les accès protégés
5. **Aucun produit commercial ne le fait** (SentinelOne, CrowdStrike, Defender for Endpoint) — choix délibéré du marché

**Le snapshot (VSS / rsync) remplit le même objectif de préservation sans ces risques.**

---

## 9. Limitation majeure assumée : déploiement Windows

En production Windows moderne (Secure Boot + HVCI), un minifilter non signé WHQL **ne peut pas se charger**. CANARIS Windows est donc démontrable **en VM (Test Signing)** mais non déployable en l'état sur un poste corporate.

**Cette limitation est documentée et non résolue** (le coût WHQL dépasse le cadre d'un projet étudiant). Le README l'explicite honnêtement — c'est un argument de crédibilité en entretien, pas une faiblesse cachée.

Solution de repli documentée : **Controlled Folder Access** (API Defender) + **ETW** en userspace, moins robuste mais déployable sans signature.

---

## 10. Critères d'acceptation (recette)

| # | Test | Critère de réussite |
|---|---|---|
| R1 | Accès à un canary depuis un process de test (Linux) | Log + blocage `-EPERM` confirmé |
| R2 | Simulateur ransomware en VM Linux | Process tué + snapshot rsync créé en < 500 ms |
| R3 | Chargement minifilter (VM Win Test Signing) | `fltmc filters` liste Canaris, pas de BSOD |
| R4 | RanSim (KnowBe4) en VM Windows | Détection + réponse déclenchée |
| R5 | Suppression VSS simulée | Alerte prioritaire déclenchée avant tout chiffrement |
| R6 | npm install (gros projet) 24 h | Zéro faux positif |
| R7 | Sync OneDrive + git clone volumineux | Zéro faux positif |
| R8 | Benchmark latence I/O | Surcoût < 5 % |

---

## 11. Planning & jalons

| Mois | Jalon | Contenu |
|---|---|---|
| **M1** | Fondation Linux | kprobes + LSM BPF blocking + générateur de canary files |
| **M2** | Comportement + réponse Linux | Threshold adaptatif + ring buffer + responder rsync |
| **M3** | Minifilter Windows (VM) | Callbacks I/O + blocage + VssGuard + communication port |
| **M4** | Intégration & livraison | Tests faux positifs, documentation, démo, GitHub |

**Première action** : installer la toolchain eBPF (Ubuntu 22.04) et écrire un programme « hello world » loguant chaque `openat` (~50 lignes de C) pour valider l'environnement.

---

## 12. Risques & mitigations

| Risque | Prob. | Impact | Mitigation |
|---|---|---|---|
| BSOD du minifilter en dev | Élevée | Élevé | VM + snapshots, Driver Verifier |
| Seuil → faux positifs massifs | Élevée | Élevé | Seuil adaptatif + whitelist + calibration |
| Suppression VSS avant détection | Élevée | Élevé | VssGuard dédié (callback création process) |
| Race condition (chiffrement rapide) | Élevée | Moyen | Blocage dès le 1er hit canary, pas seulement au seuil |
| Conflit d'altitude avec Defender | Moyenne | Moyen | Altitude réservée dans la plage anti-malware |
| Kernel panic LSM BPF | Moyenne | Élevé | VM + validation `bpftool prog load` |
| WHQL infaisable | Certaine | Moyen | Limitation documentée + repli CFA/ETW |

### Déclencheurs de révision
- **Fin M1** : si LSM BPF ne bloque pas sur le kernel cible → repli kretprobe + signal userspace immédiat
- **Fin M2** : si faux positifs > 5 % → abandonner la fenêtre fixe pour un modèle de baseline par processus
- **Fin M3** : si minifilter instable en Test Signing → basculer partie Windows sur ETW + CFA
- **Événement** : publication d'une technique d'évasion minifilter (exploit noyau) → réévaluer Ring 0 vs approche hyperviseur

---

## 13. Glossaire

- **Canary file** — fichier leurre dont l'accès signale une activité malveillante
- **Minifilter** — driver de filtrage filesystem Windows (Ring 0)
- **Altitude** — position unique d'un minifilter dans la pile de filtrage
- **eBPF** — VM du kernel Linux exécutant du bytecode vérifié
- **kprobe** — sonde d'observation sur une fonction kernel (lecture seule)
- **LSM BPF** — hooks Linux Security Module en eBPF, capables de bloquer (retour < 0)
- **CO-RE** — Compile Once Run Everywhere (portabilité eBPF via BTF)
- **VSS** — Volume Shadow Copy Service (snapshots Windows)
- **CFA** — Controlled Folder Access (protection dossiers native Defender)
- **DSE / HVCI** — mécanismes d'intégrité de code Windows
- **WHQL** — Windows Hardware Quality Labs (certification/signature Microsoft)
- **ETW** — Event Tracing for Windows (télémétrie userspace)
