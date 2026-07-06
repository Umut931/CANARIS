// SPDX-License-Identifier: GPL-2.0
/* CANARIS — détection : profils curatés par processus + seuil par défaut (Phase 4).
 * NB : profils STATIQUES curatés, pas une baseline apprise (docs/LIMITATIONS.md). */
#include "profiles.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* --------------------------------------------------------- chargement ---- */

static void set_default(struct profiles_config *cfg)
{
	memset(cfg, 0, sizeof(*cfg));
	snprintf(cfg->def.comm, PROF_COMM_LEN, "%s", "default");
	cfg->def.window_s = 2.0;
	cfg->def.threshold = 60;
	cfg->def.whitelisted = 0;
	cfg->mass_delete_threshold = 30;
	cfg->read_then_write_threshold = 12;
}

int profiles_load(struct profiles_config *cfg, const char *path)
{
	set_default(cfg);

	FILE *f = fopen(path, "r");
	if (!f) {
		fprintf(stderr, "profiles: %s introuvable, seuils par défaut\n", path);
		return -1;
	}
	char line[512];
	while (fgets(line, sizeof(line), f)) {
		char *s = line;
		while (*s == ' ' || *s == '\t') s++;
		if (*s == '#' || *s == '\n' || *s == '\0')
			continue;

		char kw[64];
		if (sscanf(s, "%63s", kw) != 1)
			continue;

		if (strcmp(kw, "default") == 0) {
			sscanf(s, "%*s %lf %d", &cfg->def.window_s, &cfg->def.threshold);
		} else if (strcmp(kw, "mass_delete") == 0) {
			sscanf(s, "%*s %d", &cfg->mass_delete_threshold);
		} else if (strcmp(kw, "read_then_write") == 0) {
			sscanf(s, "%*s %d", &cfg->read_then_write_threshold);
		} else if (strcmp(kw, "profile") == 0 && cfg->n < MAX_PROFILES) {
			struct profile *p = &cfg->list[cfg->n];
			char comm[64] = {};
			double win = 2.0; int thr = 60, white = 0;
			if (sscanf(s, "%*s %63s %lf %d %d", comm, &win, &thr, &white) >= 2) {
				snprintf(p->comm, PROF_COMM_LEN, "%s", comm);
				p->window_s = win;
				p->threshold = thr;
				p->whitelisted = white;
				cfg->n++;
			}
		}
	}
	fclose(f);
	return 0;
}

const struct profile *profiles_match(const struct profiles_config *cfg,
				     const char *comm)
{
	for (int i = 0; i < cfg->n; i++)
		if (strncmp(cfg->list[i].comm, comm, PROF_COMM_LEN - 1) == 0)
			return &cfg->list[i];
	return &cfg->def;
}

/* ------------------------------------------------------ table par PID ---- */

struct pid_state *pidstate_table_new(void)
{
	return calloc(PIDSTATE_SLOTS, sizeof(struct pid_state));
}

void pidstate_table_free(struct pid_state *table)
{
	free(table);
}

/* Sondage linéaire simple. En cas de collision de slot, on réutilise/évince. */
static struct pid_state *pidstate_get(struct pid_state *table, uint32_t pid,
				      const char *comm)
{
	uint32_t h = (pid * 2654435761u) % PIDSTATE_SLOTS;
	for (int i = 0; i < 64; i++) {
		struct pid_state *st = &table[(h + i) % PIDSTATE_SLOTS];
		if (!st->used) {
			st->used = 1;
			st->pid = pid;
			snprintf(st->comm, PROF_COMM_LEN, "%s", comm);
			st->window_start = 0;
			st->io_count = 0;
			st->unlink_count = 0;
			st->responded = 0;
			return st;
		}
		if (st->pid == pid)
			return st;
	}
	/* table saturée localement : réutilise le premier slot sondé */
	struct pid_state *st = &table[h];
	st->pid = pid;
	snprintf(st->comm, PROF_COMM_LEN, "%s", comm);
	st->window_start = 0;
	st->io_count = 0;
	st->unlink_count = 0;
	st->responded = 0;
	return st;
}

/* --------------------------------------------------------- détection ----- */

enum verdict_reason detector_observe(const struct profiles_config *cfg,
				     struct pid_state *table,
				     uint32_t pid, const char *comm,
				     double now, int is_canary, int is_unlink,
				     int is_whitelisted,
				     char *detail, int detail_len)
{
	/* 1) Accès canary => réponse immédiate (sauf exécutable whitelisté). */
	if (is_canary && !is_whitelisted) {
		struct pid_state *st = pidstate_get(table, pid, comm);
		if (st->responded)
			return VERDICT_NONE;
		st->responded = 1;
		snprintf(detail, detail_len, "acces canary");
		return VERDICT_CANARY;
	}
	if (is_whitelisted)
		return VERDICT_NONE;

	/* Seuil : un process NON whitelisté utilise toujours le seuil PAR DÉFAUT.
	 * On n'accorde JAMAIS un seuil élevé sur la foi du comm (falsifiable) — un
	 * ransomware renommé « rsync » ne doit pas hériter du quota de rsync. Les
	 * apps légitimes à fort débit doivent être whitelistées par inode (exempt). */
	const struct profile *prof = &cfg->def;

	struct pid_state *st = pidstate_get(table, pid, comm);
	if (st->responded)
		return VERDICT_NONE;

	/* 2) Fenêtre glissante (tumbling) {count, window_start}. */
	if (st->window_start == 0 || (now - st->window_start) > prof->window_s) {
		st->window_start = now;
		st->io_count = 0;
		st->unlink_count = 0;
	}
	st->io_count++;
	if (is_unlink)
		st->unlink_count++;

	/* 3) Signaux. */
	if (st->io_count >= prof->threshold) {
		st->responded = 1;
		snprintf(detail, detail_len, "%d I/O en %.0fs (seuil %d)",
			 st->io_count, prof->window_s, prof->threshold);
		return VERDICT_IO_RATE;
	}
	if (st->unlink_count >= cfg->mass_delete_threshold) {
		st->responded = 1;
		snprintf(detail, detail_len, "%d suppressions", st->unlink_count);
		return VERDICT_MASS_DELETE;
	}
	return VERDICT_NONE;
}
