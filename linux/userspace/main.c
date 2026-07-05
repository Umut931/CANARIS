// SPDX-License-Identifier: GPL-2.0
/* CANARIS — loader userspace (libbpf).
 *
 * Phase 1 : charge les kprobes, lit le ring buffer, affiche les événements.
 * Phase 2 : pousse les maps (fichiers protégés/canaries + whitelist), active
 *           les hooks LSM BPF qui bloquent réellement (-EPERM).
 *
 * Les phases suivantes ajoutent la détection comportementale + le responder
 * (linux/userspace/{profiles,responder}.c) branchés sur la boucle d'événements.
 *
 * Build : voir linux/Makefile (canaris.skel.h via bpftool gen skeleton).
 */
#include <argp.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <bpf/libbpf.h>

#include "canaris.skel.h"
#include "../bpf/canaris.h"

#define MAX_PROTECT_DIRS 64
#define MAX_CANARY_ARGS  256

static volatile sig_atomic_t exiting = 0;

static struct {
	const char *config_path;
	const char *whitelist_path;
	const char *canary_list_path;
	const char *protect_dirs[MAX_PROTECT_DIRS];
	int         n_protect;
	const char *canaries[MAX_CANARY_ARGS];
	int         n_canaries;
	int         verbose;
	int         enforce;
} env = {
	.enforce = 1,
};

/* ------------------------------------------------------------- argp ------ */

const char *argp_program_version = "canaris 0.2 (Phase 2 — LSM BPF blocking)";
static const char argp_doc[] =
	"CANARIS — anti-ransomware à interception noyau (composant Linux).\n"
	"Charge les programmes eBPF, protège les dossiers/canaries et bloque\n"
	"les accès malveillants au niveau du kernel (LSM BPF).\n";

enum { OPT_CANARY = 0x100, OPT_CANARY_LIST };

static const struct argp_option opts[] = {
	{ "protect",     'p', "DIR",  0, "Répertoire protégé (répétable)" },
	{ "config",      'c', "FILE", 0, "Profils de seuil (config/profiles.json)" },
	{ "whitelist",   'w', "FILE", 0, "Liste de process de confiance (1 comm/ligne)" },
	{ "canary",      OPT_CANARY,      "PATH", 0, "Fichier canary (répétable)" },
	{ "canary-list", OPT_CANARY_LIST, "FILE", 0, "Liste de canaries (1 chemin/ligne)" },
	{ "observe",     'o', NULL,   0, "Observation seule (LSM ne bloque pas)" },
	{ "verbose",     'v', NULL,   0, "Sortie détaillée (logs libbpf)" },
	{ 0 },
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	switch (key) {
	case 'p':
		if (env.n_protect < MAX_PROTECT_DIRS)
			env.protect_dirs[env.n_protect++] = arg;
		break;
	case 'c': env.config_path = arg; break;
	case 'w': env.whitelist_path = arg; break;
	case OPT_CANARY:
		if (env.n_canaries < MAX_CANARY_ARGS)
			env.canaries[env.n_canaries++] = arg;
		break;
	case OPT_CANARY_LIST: env.canary_list_path = arg; break;
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

static void sig_handler(int sig) { (void)sig; exiting = 1; }

/* -------------------------------------------------- LSM BPF preflight ---- */

/* Le blocage réel (retour -EPERM) nécessite que le LSM "bpf" soit actif, ce
 * qui dépend du paramètre de boot `lsm=...,bpf` (kernel >= 5.7). On lit la
 * liste des LSM actifs pour le savoir. Renvoie 1 si bpf actif, 0 sinon. */
static int lsm_bpf_available(void)
{
	FILE *f = fopen("/sys/kernel/security/lsm", "r");
	if (!f)
		return 0;
	char buf[512] = {};
	size_t n = fread(buf, 1, sizeof(buf) - 1, f);
	fclose(f);
	buf[n] = '\0';
	/* liste type "capability,landlock,yama,...,bpf" */
	return strstr(buf, "bpf") != NULL;
}

/* ------------------------------------------------------ dev encoding ----- */

/* Le kernel stocke super_block->s_dev en encodage MKDEV interne :
 *   (major << 20) | minor        (MINORBITS = 20)
 * alors que stat(2) renvoie un st_dev glibc encodé différemment. On décode
 * st_dev via major()/minor() puis on ré-encode comme le kernel, sinon la clé
 * (dev,ino) ne matcherait jamais celle lue en BPF. */
static __u32 kernel_dev(dev_t st_dev)
{
	return ((__u32)major(st_dev) << 20) | ((__u32)minor(st_dev) & ((1U << 20) - 1));
}

/* ----------------------------------------------------- map population ---- */

static int add_protected(struct canaris_bpf *skel, const char *path,
			 __u8 is_canary, __u8 is_dir)
{
	struct stat st;
	if (stat(path, &st) != 0) {
		fprintf(stderr, "  ! stat(%s) échoué: %s\n", path, strerror(errno));
		return -1;
	}
	struct file_key key = {
		.ino = (__u64)st.st_ino,
		.dev = kernel_dev(st.st_dev),
	};
	struct protect_val val = { .is_canary = is_canary, .is_dir = is_dir };
	int err = bpf_map__update_elem(skel->maps.protected_files,
				       &key, sizeof(key), &val, sizeof(val), BPF_ANY);
	if (err)
		fprintf(stderr, "  ! ajout map échoué pour %s: %d\n", path, err);
	else if (env.verbose)
		printf("  + protégé %s (dev=%u ino=%llu canary=%u dir=%u)\n",
		       path, key.dev, (unsigned long long)key.ino, is_canary, is_dir);
	return err;
}

static int add_whitelist_comm(struct canaris_bpf *skel, const char *name)
{
	char comm[TASK_COMM_LEN] = {};
	strncpy(comm, name, TASK_COMM_LEN - 1);
	__u8 one = 1;
	return bpf_map__update_elem(skel->maps.whitelist, comm, sizeof(comm),
				    &one, sizeof(one), BPF_ANY);
}

/* Lit un fichier de lignes (comm ou chemin), applique cb sur chacune. */
static int foreach_line(const char *path,
			int (*cb)(struct canaris_bpf *, const char *),
			struct canaris_bpf *skel)
{
	FILE *f = fopen(path, "r");
	if (!f) {
		fprintf(stderr, "  ! ouverture %s échouée: %s\n", path, strerror(errno));
		return -1;
	}
	char line[4096];
	int n = 0;
	while (fgets(line, sizeof(line), f)) {
		char *s = line;
		while (*s == ' ' || *s == '\t') s++;
		if (*s == '#' || *s == '\n' || *s == '\0')
			continue;
		size_t len = strlen(s);
		while (len > 0 && (s[len - 1] == '\n' || s[len - 1] == '\r' ||
				   s[len - 1] == ' '))
			s[--len] = '\0';
		if (len == 0)
			continue;
		if (cb(skel, s) == 0)
			n++;
	}
	fclose(f);
	return n;
}

static int wl_cb(struct canaris_bpf *skel, const char *name)
{
	return add_whitelist_comm(skel, name);
}
static int canary_cb(struct canaris_bpf *skel, const char *path)
{
	return add_protected(skel, path, 1 /*canary*/, 0);
}

static int setup_maps(struct canaris_bpf *skel)
{
	int have_dirs = 0, n_can = 0, n_wl = 0;

	for (int i = 0; i < env.n_protect; i++)
		if (add_protected(skel, env.protect_dirs[i], 0, 1) == 0)
			have_dirs = 1;

	for (int i = 0; i < env.n_canaries; i++)
		if (add_protected(skel, env.canaries[i], 1, 0) == 0)
			n_can++;

	if (env.canary_list_path) {
		int r = foreach_line(env.canary_list_path, canary_cb, skel);
		if (r > 0) n_can += r;
	}
	if (env.whitelist_path) {
		int r = foreach_line(env.whitelist_path, wl_cb, skel);
		if (r > 0) n_wl += r;
	}

	/* Config globale : self_tgid, enforce, have_dirs. */
	struct canaris_config cfg = {
		.self_tgid = (__u32)getpid(),
		.enforce   = env.enforce ? 1 : 0,
		.have_dirs = have_dirs ? 1 : 0,
	};
	__u32 zero = 0;
	int err = bpf_map__update_elem(skel->maps.config_map, &zero, sizeof(zero),
				       &cfg, sizeof(cfg), BPF_ANY);
	if (err) {
		fprintf(stderr, "échec push config: %d\n", err);
		return err;
	}
	printf("Config: %d dossier(s) protégé(s), %d canary(s), %d process whitelistés.\n",
	       env.n_protect, n_can, n_wl);
	return 0;
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

	char ts[16];
	time_t now = time(NULL);
	struct tm tm;
	localtime_r(&now, &tm);
	strftime(ts, sizeof(ts), "%H:%M:%S", &tm);

	if (e->event_type == EVENT_CANARY_HIT || e->event_type == EVENT_BLOCKED) {
		printf("%s \033[31m%s\033[0m pid=%-7u comm=%-16s %s%s\n",
		       ts, type_str(e->event_type), e->tgid, e->comm,
		       e->filename[0] ? e->filename : "(cible)",
		       e->ret ? "  [-EPERM]" : "  [observé]");
		fflush(stdout);
	} else if (e->event_type == EVENT_WRITE) {
		printf("%s %s pid=%-7u comm=%-16s fd=%u bytes=%llu\n",
		       ts, type_str(e->event_type), e->tgid, e->comm,
		       e->flags, (unsigned long long)e->ino);
	} else {
		printf("%s %s pid=%-7u comm=%-16s %s\n",
		       ts, type_str(e->event_type), e->tgid, e->comm, e->filename);
	}
	return 0;
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

	/* Dégradation gracieuse (cahier NF6, Phase 2 fallback) : si le LSM bpf
	 * n'est pas actif au boot, on ne peut pas bloquer via -EPERM. On
	 * désactive alors le chargement des 3 programmes LSM (évite un échec
	 * d'attach) et on bascule en mode observation ; la mitigation par kill
	 * du responder (Phase 4) prend le relais. Voir HANDOFF.md T-L6. */
	int lsm_ok = lsm_bpf_available();
	if (!lsm_ok) {
		fprintf(stderr,
			"AVERTISSEMENT: LSM 'bpf' inactif (/sys/kernel/security/lsm) —\n"
			"  blocage -EPERM indisponible. Mode DÉGRADÉ (observation +\n"
			"  kill responder). Pour activer le blocage : ajouter 'bpf' à\n"
			"  GRUB_CMDLINE_LINUX (lsm=...,bpf), reboot. Voir HANDOFF.md T-L6.\n");
		bpf_program__set_autoload(skel->progs.canaris_file_open, false);
		bpf_program__set_autoload(skel->progs.canaris_inode_unlink, false);
		bpf_program__set_autoload(skel->progs.canaris_inode_rename, false);
		env.enforce = 0;
	}

	err = canaris_bpf__load(skel);
	if (err) {
		fprintf(stderr, "échec chargement BPF (verifier ?): %d\n", err);
		goto cleanup;
	}

	err = setup_maps(skel);
	if (err)
		goto cleanup;

	err = canaris_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "échec attach: %d\n", err);
		fprintf(stderr, "  (si erreur sur lsm/*, vérifier 'bpf' dans "
				"/sys/kernel/security/lsm — voir HANDOFF.md T-L6)\n");
		goto cleanup;
	}

	rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);
	if (!rb) {
		fprintf(stderr, "échec création ring buffer\n");
		err = 1;
		goto cleanup;
	}

	printf("CANARIS chargé (mode=%s%s). Ctrl-C pour arrêter.\n",
	       env.enforce ? "ENFORCE (blocage -EPERM via LSM BPF)" : "observe",
	       (!lsm_ok) ? " — LSM bpf indisponible, blocage délégué au responder" : "");
	printf("%-8s %-6s %-11s %-16s %s\n", "HEURE", "TYPE", "PID", "COMM", "CIBLE");

	while (!exiting) {
		err = ring_buffer__poll(rb, 200 /* ms */);
		if (err == -EINTR) { err = 0; break; }
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
