# Faux positifs sur workloads RÉELS (recette R6/R7, NF5)

> **Honnêteté.** Le « 0 faux positif » prouvé en dev l'est sur des **traces
> synthétiques** (workloads simulés dans le moteur, `tests/falsepositive/`). Ce
> protocole le mesure sur de **vrais logiciels** exécutés sur une VM.

## Ce que ça mesure

Objectif **NF5** : < 1 % des sessions de travail normal déclenchent une réaction.
Idéalement **0**. La détection étant scopée aux zones protégées et exemptée par
**inode d'exécutable**, un npm/git/rsync légitime (vrai binaire whitelisté) ne
doit jamais déclencher.

## Prérequis

- VM Linux (idéalement avec LSM bpf actif pour tester le chemin complet, mais le
  script fonctionne aussi en mode dégradé — il mesure la DÉTECTION).
- Outils : `rsync`, `tar` (locaux) ; `git`, `npm` + **internet** pour les sessions
  réseau (ignorées proprement si absents).

## Lancer

```bash
sudo ./vm/fp_workload.sh
```

Le script :
1. whiteliste les **vrais chemins** de node/npm/git/rsync/cp/… (résolus en inode) ;
2. charge CANARIS sur une zone de travail dédiée ;
3. exécute chaque workload réel dans cette zone protégée ;
4. compte les réactions de CANARIS attribuables à chaque session ;
5. écrit un verdict PASS / à AFFINER + preuve dans `vm/evidence/fp_<date>.log`.

## Interpréter

- **PASS** (0 faux positif) : la whitelist par inode + le seuil par défaut tiennent
  sur charge réelle.
- **à AFFINER** : le log liste le `comm`/exécutable fautif. Deux leviers :
  - ajouter le binaire à `config/whitelist.txt` (exemption par inode) — voie
    recommandée pour un outil de confiance ;
  - ajuster le seuil par défaut dans `config/profiles.json` (puis
    `python common/profiles_compile.py`) — voie globale, à utiliser avec prudence.

## Durée / charge

Prévoir un disque suffisant : `rsync /usr/share`, `git clone --depth 1` du kernel
et `npm install express` créent des milliers de fichiers — c'est précisément le
but (charge réaliste). Sur une VM 2 vCPU / 4 Go, compter quelques minutes.

## Consigner

Copier `vm/evidence/fp_<date>.log` et reporter le taux dans la matrice de
`README.md` (colonne « À valider en VM » de R6/R7).
