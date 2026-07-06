# Tests unitaires C de la logique userspace (détection + responder), SANS eBPF.
# Compile directement profiles.c / responder.c avec les harnais de test.
#
#   make -C tests/ctest        # compile + exécute
#
CC      ?= cc
US      := ../../linux/userspace
CFLAGS  := -g -O2 -Wall -I$(US)

.PHONY: all run clean
all: run

test_detector: test_detector.c $(US)/profiles.c
	$(CC) $(CFLAGS) $^ -o $@

test_responder: test_responder.c $(US)/responder.c
	$(CC) $(CFLAGS) $^ -o $@

run: test_detector test_responder
	@echo "--- test_detector ---"  && ./test_detector
	@echo "--- test_responder ---" && ./test_responder

clean:
	rm -f test_detector test_responder
