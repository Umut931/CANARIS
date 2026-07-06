# Tests unitaires C de la logique userspace (détection + responder), SANS eBPF.
# Compile directement profiles.c / responder.c avec les harnais de test.
#
#   make -C tests/ctest        # compile + exécute
#
CC      ?= cc
US      := ../../linux/userspace
WINDRV  := ../../windows/driver
CFLAGS  := -g -O2 -Wall -I$(US) -I$(WINDRV)

.PHONY: all run clean
all: run

test_detector: test_detector.c $(US)/profiles.c
	$(CC) $(CFLAGS) $^ -o $@

test_responder: test_responder.c $(US)/responder.c
	$(CC) $(CFLAGS) $^ -o $@

test_vssguard: test_vssguard.c $(WINDRV)/vssguard_rules.h
	$(CC) $(CFLAGS) test_vssguard.c -o $@

run: test_detector test_responder test_vssguard
	@echo "--- test_detector ---"  && ./test_detector
	@echo "--- test_responder ---" && ./test_responder
	@echo "--- test_vssguard ---"  && ./test_vssguard

clean:
	rm -f test_detector test_responder test_vssguard
