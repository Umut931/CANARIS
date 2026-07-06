# VM Linux avec LSM BPF actif — activation du blocage `-EPERM`

> **BLOQUANT pour la crédibilité du projet.** Le blocage synchrone LSM est la
> pièce maîtresse ; il n'a PAS pu être exécuté dans l'environnement de dev
> (Docker/WSL2 : `bpf` absent de la liste LSM active). Ce guide + `validate_enforce.sh`
> le prouvent sur un vrai kernel.

## Pourquoi

`CONFIG_BPF_LSM=y` ne suffit pas : le LSM `bpf` doit aussi être **activé au boot**
via le paramètre kernel `lsm=...,bpf`. Sinon les programmes `lsm/*` se chargent et
passent le verifier, mais **n'enforce pas** (le hook n'est pas invoqué).

## Vérifier l'état actuel

```bash
uname -r                              # kernel >= 5.7
zcat /proc/config.gz | grep BPF_LSM   # attendu : CONFIG_BPF_LSM=y
cat /sys/kernel/security/lsm          # doit CONTENIR "bpf"
```

Si `bpf` est absent de la dernière commande → suivre l'activation ci-dessous.

## Activer `bpf` LSM (Ubuntu 22.04 / 24.04, GRUB)

```bash
sudo sed -i 's/^GRUB_CMDLINE_LINUX="\(.*\)"/GRUB_CMDLINE_LINUX="\1 lsm=landlock,lockdown,yama,integrity,bpf"/' /etc/default/grub
# Vérifier la ligne (adapter selon la distro ; l'important est de TERMINER par ,bpf) :
grep GRUB_CMDLINE_LINUX /etc/default/grub
sudo update-grub
sudo reboot
```

Après reboot :

```bash
cat /sys/kernel/security/lsm   # doit maintenant contenir bpf
```

### Alternative cloud (rapide)

Une image **Ubuntu 24.04** sur la plupart des clouds permet d'ajouter `lsm=...,bpf`
via le cloud-init / GRUB comme ci-dessus. Multipass en local :

```bash
multipass launch 24.04 --name canaris --disk 10G --memory 4G
multipass shell canaris
# puis appliquer l'activation GRUB ci-dessus + reboot
```

## Prérequis de build (une fois dans la VM)

```bash
sudo apt update
sudo apt install -y clang llvm libbpf-dev linux-tools-$(uname -r) \
    bpftool make gcc pkg-config libelf-dev rsync python3
```

## Ensuite

Lancer les harnais turnkey (verdict PASS/FAIL, preuve horodatée) :

```bash
sudo ./vm/validate_enforce.sh    # prouve le blocage -EPERM (canary)
sudo ./vm/validate_kill.sh       # prouve le kill réel du responder
```

Les preuves sont écrites dans `vm/evidence/`.
