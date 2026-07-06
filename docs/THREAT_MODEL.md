# THREAT MODEL — CANARIS

Honnêteté totale : ce document distingue ce que CANARIS **couvre**, ce qu'il
**ne couvre pas**, et les hypothèses.

---

## 1. Actif à protéger

Les fichiers de données de l'utilisateur (documents, photos, sauvegardes) sur un
poste Windows 10/11 ou Linux (kernel ≥ 5.7). Objectif : empêcher leur
chiffrement/suppression massive par un ransomware, ou au moins en **préserver une
copie** avant le chiffrement.

## 2. Attaquant

Ransomware userspace « classique » (LockBit-like, BlackCat-like, Conti-like) :
processus non privilégié ou administrateur local qui parcourt le filesystem,
lit → chiffre → réécrit/renomme des milliers de fichiers, et supprime les shadow
copies en préambule. **Pas** de 0-day noyau, pas d'accès hyperviseur.

---

## 3. Ce qui est COUVERT

| Menace | Mécanisme CANARIS | OS |
|---|---|---|
| Chiffrement de fichiers utilisateur | canary files + blocage LSM/minifilter au 1er accès | Lin/Win |
| Balayage rapide d'un dossier | seuil adaptatif scopé aux zones protégées → kill + snapshot | Lin/Win |
| Renommage `.locked` / suppression de l'original | `lsm/inode_rename` + `inode_unlink` / `IRP_MJ_SET_INFORMATION` | Lin/Win |
| Suppression des shadow copies / sauvegardes | VssGuard (process-creation) → alerte max + blocage ; auto-protection snapshots | Win / Lin |
| Faux positifs (npm, git, OneDrive, Defender) | seuil **adaptatif** par profil + whitelist | Lin/Win |
| Perte de données pendant la réponse | snapshot **avant** le kill (préservation d'abord) | Lin/Win |

## 4. Ce qui N'EST PAS couvert (hors périmètre, cahier §2.2)

| Menace | Pourquoi hors périmètre |
|---|---|
| Ransomware **in-memory** / sans écriture disque | pas d'I/O filesystem à intercepter |
| Ciblage des **hyperviseurs** (ESXi) | hors plateforme |
| **0-day noyau** désactivant le driver/eBPF | l'attaquant Ring 0 est au même niveau que la défense |
| **Mouvement latéral réseau** (SMB) | pas de composant réseau |
| Chiffrement **très lent** (sous le seuil, quelques fichiers/heure) | indiscernable d'un usage légitime — mais le 1er accès **canary** reste bloquant |
| Désinstallation du service **avec privilèges admin** | NF8 limite (process non privilégié) ; un admin peut tout |
| macOS / Android / embarqué | hors plateforme |

## 5. Hypothèses de confiance

* Le noyau et la chaîne de démarrage sont sains (Secure Boot en prod ; le blocage
  LSM/minifilter suppose que l'attaquant n'est pas déjà Ring 0).
* Le service userspace tourne en privilégié et n'est pas terminable par un
  process non privilégié (NF8) ; le canal kernel↔userspace est authentifié (ACL
  du port Windows / vérification côté Linux, NF9).
* Sur Linux, le LSM `bpf` est activé au boot pour le **blocage** ; sinon mode
  dégradé (mitigation par kill).

## 6. Vecteurs résiduels connus

* **Course du chiffrement rapide** : un chiffreur qui traite N fichiers plus vite
  que la réaction userspace peut en perdre quelques-uns avant le kill. Mitigation :
  blocage **synchrone** LSM/minifilter dès le 1er hit canary (ne dépend pas de
  l'userspace) + snapshot. Cf. `docs/VALIDATION.md` (Phase 4).
* **Whitelist par nom (`comm`) falsifiable** : un ransomware se renommant `rsync`
  serait whitelisté. Mitigation prévue : whitelist par **inode d'exécutable**
  (durcissement documenté dans `LIMITATIONS.md`).
* **Canaries connus** : un attaquant ciblé pourrait apprendre l'emplacement des
  canaries. Mitigation : génération aléatoire, placement multi-niveaux, protection
  de **dossiers entiers** (pas seulement des canaries).
