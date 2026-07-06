// SPDX-License-Identifier: GPL-2.0
/* CANARIS — réponse automatique de préservation (Phase 4, F4.1/F4.3/F4.6 ; T1).
 *
 * Préservation en DEUX temps (leçon de la course du chiffrement rapide) :
 *   1. BASELINE PÉRIODIQUE (responder_baseline) pris AVANT toute attaque, la
 *      source de RÉCUPÉRATION. rsync --link-dest contre le baseline PRÉCÉDENT
 *      (jamais de lien dur vers la source vivante) + --exclude des fichiers déjà
 *      chiffrés. Rotation (garde K).
 *   2. SNAPSHOT RÉACTIF/FORENSIQUE (responder_snapshot) pris à la détection :
 *      capture l'état courant (potentiellement chiffré). FORENSIQUE, pas une
 *      source de restauration.
 * Pas de chiffrement préventif (CLAUDE.md §2.1).
 */
#ifndef CANARIS_RESPONDER_H
#define CANARIS_RESPONDER_H

#include <stdint.h>

struct responder {
	char snapshot_root[512];   /* réactif/forensique                      */
	char baseline_root[512];   /* baselines propres (récupération)        */
	char log_path[512];
	char last_snapshot[640];
	char last_baseline[640];   /* baseline précédent (pour --link-dest)   */
	int  keep_baselines;       /* rotation : nombre de baselines gardés   */
	int  dry_run;
	int  have_rsync;
};

int responder_init(struct responder *r, const char *snapshot_root,
		   const char *baseline_root, const char *log_path,
		   int keep_baselines, int dry_run);

/* Baseline PROPRE périodique (récupération). Exclut les fichiers chiffrés,
 * déduplique par lien dur contre le baseline précédent, applique la rotation.
 * Remplit out_path. Renvoie 0 si OK. */
int responder_baseline(struct responder *r, const char *const *dirs, int n,
		       char *out_path, int out_len);

/* Snapshot FORENSIQUE de l'état courant à la détection (peut être chiffré). */
int responder_snapshot(struct responder *r, const char *const *dirs, int n,
		       char *out_path, int out_len);

/* Termine le processus suspect (SIGKILL). */
int responder_kill(uint32_t pid);

/* Journalisation horodatée (fichier + stdout). */
void responder_log(struct responder *r, const char *fmt, ...);

/* Réponse complète : snapshot forensique PUIS kill ; loggue le dernier baseline
 * propre comme source de restauration. Renvoie la latence (ms) ou -1. */
double responder_respond(struct responder *r, uint32_t pid, const char *comm,
			 const char *reason, const char *detail,
			 const char *const *dirs, int n);

#endif /* CANARIS_RESPONDER_H */
