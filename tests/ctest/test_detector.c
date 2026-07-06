// SPDX-License-Identifier: GPL-2.0
/* Test unitaire C de la détection à seuil adaptatif (linux/userspace/profiles.c).
 * Valide l'algorithme réel (pas un miroir Python) en dehors du chemin eBPF.
 *
 * Build/run : voir tests/ctest/Makefile (compile avec profiles.c, sans libbpf).
 */
#include "profiles.h"
#include <stdio.h>
#include <string.h>

static int failures = 0;
#define CHECK(cond, msg) do { \
	if (!(cond)) { printf("  ✗ %s\n", msg); failures++; } \
	else         { printf("  ✓ %s\n", msg); } \
} while (0)

/* Config minimale en dur (indépendante du fichier). */
static void mkcfg(struct profiles_config *cfg)
{
	memset(cfg, 0, sizeof(*cfg));
	snprintf(cfg->def.comm, PROF_COMM_LEN, "%s", "default");
	cfg->def.window_s = 2.0; cfg->def.threshold = 60; cfg->def.whitelisted = 0;
	cfg->mass_delete_threshold = 30;
	cfg->read_then_write_threshold = 12;
	/* node whitelisté à seuil élevé */
	snprintf(cfg->list[0].comm, PROF_COMM_LEN, "%s", "node");
	cfg->list[0].window_s = 2.0; cfg->list[0].threshold = 4000;
	cfg->list[0].whitelisted = 1;
	cfg->n = 1;
}

int main(void)
{
	struct profiles_config cfg;
	mkcfg(&cfg);
	char detail[128];

	printf("== test_detector ==\n");

	/* arguments detector_observe : (..., is_canary, is_unlink, is_whitelisted, ...) */

	/* 1) rafale ransomware -> io_rate (exe non whitelisté) */
	{
		struct pid_state *t = pidstate_table_new();
		enum verdict_reason v = VERDICT_NONE;
		for (int i = 0; i < 200 && v == VERDICT_NONE; i++)
			v = detector_observe(&cfg, t, 42, "cryptor", i * 0.001,
					     0, 0, 0, detail, sizeof(detail));
		CHECK(v == VERDICT_IO_RATE, "rafale inconnue -> io_rate");
		pidstate_table_free(t);
	}

	/* 2) EXÉCUTABLE whitelisté (inode) au même débit -> aucune détection */
	{
		struct pid_state *t = pidstate_table_new();
		enum verdict_reason v = VERDICT_NONE;
		for (int i = 0; i < 500 && v == VERDICT_NONE; i++)
			v = detector_observe(&cfg, t, 43, "node", i * 0.001,
					     0, 0, 1 /*whitelisté*/, detail, sizeof(detail));
		CHECK(v == VERDICT_NONE, "exe whitelisté (inode) -> pas de détection");
		pidstate_table_free(t);
	}

	/* 3) accès canary -> réponse immédiate (exe non whitelisté) */
	{
		struct pid_state *t = pidstate_table_new();
		enum verdict_reason v = detector_observe(&cfg, t, 44, "cryptor",
			0.0, 1 /*canary*/, 0, 0, detail, sizeof(detail));
		CHECK(v == VERDICT_CANARY, "accès canary -> immédiat");
		pidstate_table_free(t);
	}

	/* 4) canary par EXÉCUTABLE whitelisté -> autorisé */
	{
		struct pid_state *t = pidstate_table_new();
		enum verdict_reason v = detector_observe(&cfg, t, 45, "node",
			0.0, 1 /*canary*/, 0, 1 /*whitelisté*/, detail, sizeof(detail));
		CHECK(v == VERDICT_NONE, "canary + exe whitelisté -> autorisé");
		pidstate_table_free(t);
	}

	/* 4b) ANTI-SPOOF : comm 'node' (profil whitelisté historique) MAIS exe non
	 *     whitelisté -> le canary est quand même détecté. Le comm ne protège pas. */
	{
		struct pid_state *t = pidstate_table_new();
		enum verdict_reason v = detector_observe(&cfg, t, 99, "node",
			0.0, 1 /*canary*/, 0, 0 /*exe NON whitelisté*/, detail, sizeof(detail));
		CHECK(v == VERDICT_CANARY,
		      "comm 'node' spoofé (exe non whitelisté) -> détecté (pas d'exemption par comm)");
		pidstate_table_free(t);
	}

	/* 5) suppression massive -> mass_delete (sous le seuil d'I/O) */
	{
		struct pid_state *t = pidstate_table_new();
		enum verdict_reason v = VERDICT_NONE;
		for (int i = 0; i < 35 && v == VERDICT_NONE; i++)
			v = detector_observe(&cfg, t, 46, "wiper", i * 0.001,
					     0, 1 /*unlink*/, 0, detail, sizeof(detail));
		CHECK(v == VERDICT_MASS_DELETE || v == VERDICT_IO_RATE,
		      "suppression massive détectée");
		pidstate_table_free(t);
	}

	/* 6) déclenchement unique : ne re-déclenche pas après réponse */
	{
		struct pid_state *t = pidstate_table_new();
		enum verdict_reason first = VERDICT_NONE, again = VERDICT_NONE;
		for (int i = 0; i < 200; i++) {
			enum verdict_reason v = detector_observe(&cfg, t, 47,
				"cryptor", i * 0.001, 0, 0, 0, detail, sizeof(detail));
			if (v != VERDICT_NONE) { if (!first) first = v; else again = v; }
		}
		CHECK(first == VERDICT_IO_RATE && again == VERDICT_NONE,
		      "un seul déclenchement par PID");
		pidstate_table_free(t);
	}

	printf(failures ? "\nÉCHECS: %d\n" : "\nOK (test_detector)\n", failures);
	return failures ? 1 : 0;
}
