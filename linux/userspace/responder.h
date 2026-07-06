// SPDX-License-Identifier: GPL-2.0
/* CANARIS — réponse automatique de préservation (Phase 4, F4.1/F4.3/F4.6).
 *
 * La SEULE réponse de préservation autorisée est le SNAPSHOT (CLAUDE.md §2.1) :
 * pas de chiffrement préventif. On préserve d'abord (rsync --link-dest, snapshot
 * incrémental à liens durs, quasi instantané), puis on tue le processus suspect.
 */
#ifndef CANARIS_RESPONDER_H
#define CANARIS_RESPONDER_H

#include <stdint.h>

struct responder {
	char snapshot_root[512];
	char log_path[512];
	char last_snapshot[640];   /* snapshot précédent (pour --link-dest)  */
	int  dry_run;
	int  have_rsync;
};

int responder_init(struct responder *r, const char *snapshot_root,
		   const char *log_path, int dry_run);

/* Crée snapshots/<timestamp>/ (liens durs vers le contenu actuel des dossiers
 * protégés). Remplit out_path. Renvoie 0 si OK. */
int responder_snapshot(struct responder *r, const char *const *dirs, int n,
		       char *out_path, int out_len);

/* Termine le processus suspect (SIGKILL). */
int responder_kill(uint32_t pid);

/* Journalisation horodatée (fichier + stdout). */
void responder_log(struct responder *r, const char *fmt, ...);

/* Réponse complète : snapshot PUIS kill, avec mesure de latence. Renvoie la
 * latence en millisecondes (ou -1 en erreur). */
double responder_respond(struct responder *r, uint32_t pid, const char *comm,
			 const char *reason, const char *detail,
			 const char *const *dirs, int n);

#endif /* CANARIS_RESPONDER_H */
