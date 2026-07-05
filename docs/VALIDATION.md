# VALIDATION — preuves d'exécution réelles

Ce fichier consigne les **résultats réels** des tests exécutés pendant le développement,
avec leurs sorties. Il distingue ce qui a été **réellement validé** de ce qui reste
`[HANDOFF]` (à rejouer dans les VM de l'utilisateur).

## Environnement de validation

Bien que la machine de dev soit Windows, l'eBPF a pu être **compilé et exécuté pour de vrai**
grâce à un conteneur Docker `--privileged` s'appuyant sur le **kernel WSL2 6.18** (qui expose
`/sys/kernel/btf/vmlinux`). Image de build : `linux/Dockerfile.build` (clang 18, bpftool 7.4,
libbpf-dev).

> ⚠️ Ceci valide le code (compile, verifier, attach, événements) mais **pas** sur le kernel
> Ubuntu cible de l'utilisateur ni avec LSM BPF activé au boot. Les tests VM de `HANDOFF.md`
> restent la validation de référence sur la plateforme cible.

---

## Phase 1 — Observation (kprobes) — ✅ VALIDÉ RÉELLEMENT

### T-L1 — Compilation CO-RE ✅

```
$ docker run --rm -v "$PWD:/work" -w /work canaris-build make -C linux
  GEN     bpf/vmlinux.h (depuis /sys/kernel/btf/vmlinux)
  CLANG   bpf/canaris.bpf.o
  SKEL    userspace/canaris.skel.h
  CC      userspace/main.o
  LINK    canaris
==> Build Linux OK : ./canaris
```
Clang 18.1.3, `-target bpf`, CO-RE via BTF. Aucune erreur ni warning.

### T-L2 — BPF verifier ✅

```
$ bpftool prog loadall linux/bpf/canaris.bpf.o /sys/fs/bpf/canaris_verify
VERIFIER: OK (all programs accepted)
65: kprobe  name canaris_openat  tag 52f9f387ecb2cbfe  gpl
    xlated 712B  jited 406B  memlock 4096B  map_ids 41,39,38
```
Tous les programmes passent le verifier **et** sont JIT-compilés.

### T-L3 — Observation live (F2.4) ✅

Loader attaché, activité fichier générée, événements remontés via ring buffer :

```
HEURE    TYPE   PID         COMM             CIBLE
20:40:43 OPEN   pid=8198    comm=sh          /tmp/canaris_probe_test.txt
20:40:43 OPEN   pid=8235    comm=cat         /tmp/canaris_probe_test.txt
20:40:43 UNLINK pid=8236    comm=rm          /tmp/canaris_probe_test.txt
----- total events captured: 337 -----
```
`echo >` (open+write), `cat` (open), `rm` (unlinkat) correctement observés.
337 événements système capturés au total sur la fenêtre → le ring buffer fonctionne.

---

<!-- Les phases suivantes ajoutent leurs preuves ici. -->
