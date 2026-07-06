# CANARIS — Makefile racine (orchestration des sous-builds)
#
# Cibles :
#   make linux      -> build du composant Linux (eBPF + loader userspace)
#   make canary     -> aucun build (Python), lance les tests du générateur
#   make test       -> lance toute la suite de tests exécutable dans l'env courant
#   make clean      -> nettoie les artefacts Linux
#
# Le composant Windows se build en VM avec WDK :
#   msbuild windows/Canaris.sln /p:Configuration=Debug /p:Platform=x64
# (voir HANDOFF.md — non buildable ici).

PYTHON ?= python3

.PHONY: all linux windows canary test test-canary test-detection test-vssguard test-falsepositive clean help

all: linux
	@echo "==> Composant Linux buildé. Composant Windows : voir HANDOFF.md (VM WDK)."

linux:
	@echo "==> Build du composant Linux..."
	$(MAKE) -C linux

windows:
	@echo "==> Le composant Windows se build en VM Windows avec WDK :"
	@echo "    msbuild windows/Canaris.sln /p:Configuration=Debug /p:Platform=x64"
	@echo "    Voir HANDOFF.md [HANDOFF-WIN-WDK]."

# ---- Tests exécutables dans l'environnement courant (Python) ----
test: test-canary test-detection test-vssguard test-falsepositive
	@echo "==> Suite de tests terminée."

test-canary:
	@echo "==> Tests générateur de canary (entropie / taille / magic bytes / timestamps)..."
	$(PYTHON) -m pytest tests/test_canary_generator.py -v

test-detection:
	@echo "==> Tests logique de détection (profils curatés, compteur I/O)..."
	$(PYTHON) -m pytest tests/test_detection.py -v

test-vssguard:
	@echo "==> Tests parsing VssGuard (command-lines suspectes)..."
	$(PYTHON) -m pytest tests/test_vssguard_parsing.py -v

test-falsepositive:
	@echo "==> Tests faux positifs (npm/git/OneDrive simulés)..."
	$(PYTHON) -m pytest tests/falsepositive/test_false_positives.py -v

clean:
	$(MAKE) -C linux clean
	@echo "==> Nettoyage terminé."

help:
	@echo "Cibles : linux | windows | canary | test | clean"
	@echo "Tests VM (root Linux / WDK Windows) : voir HANDOFF.md"
