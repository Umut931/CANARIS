// SPDX-License-Identifier: GPL-2.0
/* CANARIS — détection comportementale : profils curatés par processus (Phase 4).
 *
 * Reproduit en C l'algorithme de common/canaris_engine.py (référence testée).
 * Charge le seuil PAR DÉFAUT depuis config/thresholds.conf (dérivé de
 * profiles.json par common/profiles_compile.py), maintient un compteur d'I/O
 * par PID sur fenêtre glissante (tumbling window {count, window_start} — cf.
 * CLAUDE.md §5). L'exemption des apps de confiance se fait par la WHITELIST
 * d'exécutables (par inode), pas par un seuil élevé accordé au comm. Profils
 * STATIQUES curatés, pas une baseline apprise (docs/LIMITATIONS.md).
 */
#ifndef CANARIS_PROFILES_H
#define CANARIS_PROFILES_H

#include <stdint.h>

#define PROF_COMM_LEN     16
#define MAX_PROFILES      128
#define PIDSTATE_SLOTS    8192

struct profile {
	char   comm[PROF_COMM_LEN];
	double window_s;
	int    threshold;
	int    whitelisted;
};

struct profiles_config {
	struct profile def;              /* seuil par défaut (secours)        */
	struct profile list[MAX_PROFILES];
	int    n;
	int    mass_delete_threshold;
	int    read_then_write_threshold;
};

/* État par PID (fenêtre glissante + signaux). */
struct pid_state {
	int      used;
	uint32_t pid;
	char     comm[PROF_COMM_LEN];
	double   window_start;
	int      io_count;
	int      unlink_count;           /* approx suppression massive        */
	int      responded;
};

/* Résultat de décision. */
enum verdict_reason {
	VERDICT_NONE = 0,
	VERDICT_CANARY,
	VERDICT_IO_RATE,
	VERDICT_MASS_DELETE,
};

/* Charge thresholds.conf. Renvoie 0 si OK (sinon garde les valeurs par défaut). */
int profiles_load(struct profiles_config *cfg, const char *path);

/* Profil correspondant à un comm (ou &cfg->def si inconnu). */
const struct profile *profiles_match(const struct profiles_config *cfg,
				     const char *comm);

/* Table d'états par PID (allouée par le loader). */
struct pid_state *pidstate_table_new(void);
void pidstate_table_free(struct pid_state *table);

/* Traite un événement. `is_canary` = 1 si accès canary (LSM ou match chemin).
 * `is_unlink` = 1 pour une suppression. `is_whitelisted` = 1 si l'EXÉCUTABLE
 * appelant est whitelisté (identifié par inode, calculé côté eBPF) — c'est LUI
 * qui exempte, pas le comm (le `comm` ne sert qu'au profil de seuil + affichage).
 * Renvoie la raison de déclenchement (ou VERDICT_NONE). Remplit *detail. */
enum verdict_reason detector_observe(const struct profiles_config *cfg,
				     struct pid_state *table,
				     uint32_t pid, const char *comm,
				     double now, int is_canary, int is_unlink,
				     int is_whitelisted,
				     char *detail, int detail_len);

#endif /* CANARIS_PROFILES_H */
