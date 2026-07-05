# CANARIS — build du composant Linux (eBPF CO-RE + loader userspace libbpf).
#
# Cibles :
#   make            -> build complet : vmlinux.h, canaris.bpf.o, skeleton, canaris
#   make verify     -> charge le .o à sec pour passer le BPF verifier (root)
#   make clean
#
# Prérequis (VM Linux) : clang, llvm, bpftool, libbpf-dev, make, gcc.
# Voir ../HANDOFF.md [HANDOFF-LINUX-ROOT].

CLANG    ?= clang
BPFTOOL  ?= bpftool
CC       ?= cc

# Détection de l'architecture cible pour les macros CO-RE (__TARGET_ARCH_x86…).
ARCH := $(shell uname -m | sed 's/x86_64/x86/;s/aarch64/arm64/;s/ppc64le/powerpc/;s/mips.*/mips/')

BPF_SRC   := bpf/canaris.bpf.c
BPF_OBJ   := bpf/canaris.bpf.o
VMLINUX_H := bpf/vmlinux.h
SKEL_H    := userspace/canaris.skel.h

USER_SRCS := $(wildcard userspace/*.c)
USER_OBJS := $(USER_SRCS:.c=.o)
TARGET    := canaris

# Flags
BPF_CFLAGS  := -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) -Ibpf -Wall
USER_CFLAGS := -g -O2 -Wall -Iuserspace -Ibpf
USER_LDLIBS := -lbpf -lelf -lz

.PHONY: all verify clean

all: $(TARGET)

# 1. vmlinux.h généré depuis le BTF du kernel courant (CO-RE).
$(VMLINUX_H):
	@echo "  GEN     $@ (depuis /sys/kernel/btf/vmlinux)"
	@if [ ! -r /sys/kernel/btf/vmlinux ]; then \
		echo "ERREUR: /sys/kernel/btf/vmlinux absent — BTF requis pour CO-RE"; exit 1; \
	fi
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $@

# 2. Compilation du programme eBPF (Compile Once Run Everywhere).
$(BPF_OBJ): $(BPF_SRC) bpf/canaris.h $(VMLINUX_H)
	@echo "  CLANG   $@"
	$(CLANG) $(BPF_CFLAGS) -c $(BPF_SRC) -o $@
	@# strip DWARF pour alléger l'objet chargé (le BTF est conservé par -g)
	@llvm-strip -g $@ 2>/dev/null || true

# 3. Génération du skeleton C depuis l'objet BPF.
$(SKEL_H): $(BPF_OBJ)
	@echo "  SKEL    $@"
	$(BPFTOOL) gen skeleton $(BPF_OBJ) > $@

# 4. Compilation des sources userspace (dépendent du skeleton).
userspace/%.o: userspace/%.c $(SKEL_H) bpf/canaris.h
	@echo "  CC      $@"
	$(CC) $(USER_CFLAGS) -c $< -o $@

# 5. Édition de liens du binaire final.
$(TARGET): $(USER_OBJS)
	@echo "  LINK    $@"
	$(CC) $(USER_CFLAGS) $(USER_OBJS) $(USER_LDLIBS) -o $@
	@echo "==> Build Linux OK : ./$(TARGET)"

# Passage du BPF verifier sans exécuter le loader (nécessite root).
verify: $(BPF_OBJ)
	@echo "==> Chargement à sec (BPF verifier)…"
	$(BPFTOOL) prog load $(BPF_OBJ) /sys/fs/bpf/canaris_verify && \
		echo "verifier OK" && rm -f /sys/fs/bpf/canaris_verify

clean:
	rm -f $(BPF_OBJ) $(SKEL_H) $(USER_OBJS) $(TARGET) $(VMLINUX_H)
	@echo "==> clean OK"
