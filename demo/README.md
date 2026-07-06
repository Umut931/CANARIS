# Démo CANARIS

Scripts de démonstration Linux (à exécuter en **VM root**, cf. `../HANDOFF.md`).

## `run_demo.sh` — démo complète (pour la vidéo, cahier L6)

```bash
sudo ./demo/run_demo.sh [nb_fichiers]     # défaut 800
```

Enchaîne : génération de canaries réalistes → chargement du moteur noyau
(protège la sandbox) → simulateur de ransomware (SANDBOX uniquement) →
**détection** → **kill + snapshot de préservation**. Affiche le journal et le
nombre de fichiers préservés dans le snapshot.

Pour le **blocage synchrone** (idéal en démo), booter le kernel avec
`lsm=lockdown,capability,yama,apparmor,bpf`. Sinon mode dégradé (observation +
kill) — cf. `../docs/LIMITATIONS.md`.

## `benchmark_io.sh` — surcoût I/O (cahier R8 / NF1)

```bash
sudo ./demo/benchmark_io.sh [nb_fichiers]  # défaut 5000
```

Mesure le temps d'un workload I/O hors zone protégée sans puis avec CANARIS
chargé, et calcule le surcoût (cible < 5 %).

## Conseils vidéo (30–60 s)

1. Terminal 1 : `sudo ./demo/run_demo.sh 800`.
2. Montrer les canaries générés, le chargement, puis l'alerte + le snapshot.
3. Ouvrir `snapshots/<timestamp>/` : les fichiers utilisateurs sont préservés
   **avant** le chiffrement.
4. Souligner : détection **comportementale** (pas de signature), réaction
   **noyau**, préservation par **snapshot** (jamais de chiffrement préventif).
