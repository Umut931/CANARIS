// SPDX-License-Identifier: GPL-2.0
/* CANARIS — loader userspace (libbpf).
 *
 * Phase 1 : charge les programmes eBPF (kprobes), pousse la config globale,
 * puis lit le ring buffer et affiche les événements filesystem observés.
 *
 * Les phases suivantes étendent ce loader (maps canaries/whitelist, détection
 * comportementale, responder). Voir linux/userspace/{profiles,responder}.c.
 *
 * Build : voir linux/Makefile (génère canaris.skel.h via bpftool gen skeleton).
 */
#include <argp.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <bpf/libbpf.h>

#include "canaris.skel.h"
#include "../bpf/canaris.h"

static volatile sig_atomic_t exiting = 0;

static struct {
	const char *config_path;
	const char *protect_dir;
	int verbose;
	int enforce;
} env = {
	.config_path = NULL,
	.protect_dir = NULL,
	.verbose = 0,
	.enforce = 1,
};

/* ------------------------------------------------------------- argp ------ */

const char *argp_program_version = "canaris 0.1 (Phase 1 — observation)";
static const char argp_doc[] =
	"CANARIS — anti-ransomware à interception noyau (composant Linux).\n"
	"Charge les programmes eBPF et observe les accès fichiers.\n";

static const struct argp_option opts[] = {
	{ "protect", 'p', "DIR",  0, "Répertoire protégé (canaries + fichiers)" },
	{ "config",  'c', "FILE", 0, "Fichier de profils (config/profiles.json)" },
	{ "observe", 'o', NULL,   0, "Mode observation seule (LSM ne bloque pas)" },
	{ "verbose", 'v', NULL,   0, "Sortie détaillée (logs libbpf)" },
	{ 0 },
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	switch (key) {
	case 'p': env.protect_dir = arg; break;
	case 'c': env.config_path = arg; break;
	case 'o': env.enforce = 0; break;
	case 'v': env.verbose = 1; break;
	default:  return ARGP_ERR_UNKNOWN;
	}
	return 0;
}

static const struct argp argp = { opts, parse_arg, NULL, argp_doc };

/* -------------------------------------------------------- libbpf log ----- */

static int libbpf_print_fn(enum libbpf_print_level level, const char *fmt,
			   va_list args)
{
	if (level == LIBBPF_DEBUG && !env.verbose)
		return 0;
	return vfprintf(stderr, fmt, args);
}

static void sig_handler(int sig)
{
	(void)sig;
	exiting = 1;
}

/* ------------------------------------------------------ event handler ---- */

static const char *type_str(__u32 t)
{
	switch (t) {
	case EVENT_OPEN:       return "OPEN  ";
	case EVENT_WRITE:      return "WRITE ";
	case EVENT_UNLINK:     return "UNLINK";
	case EVENT_RENAME:     return "RENAME";
	case EVENT_BLOCKED:    return "BLOCK ";
	case EVENT_CANARY_HIT: return "CANARY";
	default:               return "?????";
	}
}

static int handle_event(void *ctx, void *data, size_t sz)
{
	(void)ctx;
	if (sz < sizeof(struct canaris_event))
		return 0;
	const struct canaris_event *e = data;

	char ts[32];
	time_t now = time(NULL);
	struct tm tm;
	localtime_r(&now, &tm);
	strftime(ts, sizeof(ts), "%H:%M:%S", &tm);

	if (e->event_type == EVENT_WRITE) {
		printf("%s %s pid=%-7u comm=%-16s fd=%u bytes=%llu\n",
		       ts, type_str(e->event_type), e->tgid, e->comm,
		       e->flags, (unsigned long long)e->ino);
	} else {
		printf("%s %s pid=%-7u comm=%-16s %s\n",
		       ts, type_str(e->event_type), e->tgid, e->comm,
		       e->filename);
	}
	return 0;
}

/* ---------------------------------------------------------- config -------- */

static int push_config(struct canaris_bpf *skel)
{
	struct canaris_config cfg = {
		.self_tgid = (__u32)getpid(),
		.enforce   = env.enforce ? 1 : 0,
	};
	__u32 zero = 0;
	int err = bpf_map__update_elem(skel->maps.config_map, &zero, sizeof(zero),
				       &cfg, sizeof(cfg), BPF_ANY);
	if (err)
		fprintf(stderr, "échec push config: %d\n", err);
	return err;
}

/* -------------------------------------------------------------- main ----- */

int main(int argc, char **argv)
{
	struct canaris_bpf *skel = NULL;
	struct ring_buffer *rb = NULL;
	int err;

	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;

	libbpf_set_print(libbpf_print_fn);
	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	skel = canaris_bpf__open();
	if (!skel) {
		fprintf(stderr, "échec ouverture du skeleton BPF\n");
		return 1;
	}

	err = canaris_bpf__load(skel);
	if (err) {
		fprintf(stderr, "échec chargement BPF (verifier ?): %d\n", err);
		goto cleanup;
	}

	err = push_config(skel);
	if (err)
		goto cleanup;

	err = canaris_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "échec attach des programmes: %d\n", err);
		goto cleanup;
	}

	rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);
	if (!rb) {
		fprintf(stderr, "échec création ring buffer\n");
		err = 1;
		goto cleanup;
	}

	printf("CANARIS chargé (mode=%s). Protégé=%s. Ctrl-C pour arrêter.\n",
	       env.enforce ? "enforce" : "observe",
	       env.protect_dir ? env.protect_dir : "(aucun)");
	printf("%-8s %-6s %-11s %-16s %s\n", "HEURE", "TYPE", "PID", "COMM", "CIBLE");

	while (!exiting) {
		err = ring_buffer__poll(rb, 200 /* ms */);
		if (err == -EINTR) {
			err = 0;
			break;
		}
		if (err < 0) {
			fprintf(stderr, "erreur poll ring buffer: %d\n", err);
			break;
		}
	}

	printf("\nArrêt de CANARIS.\n");

cleanup:
	ring_buffer__free(rb);
	canaris_bpf__destroy(skel);
	return err < 0 ? -err : err;
}
