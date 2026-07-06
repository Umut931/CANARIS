// SPDX-License-Identifier: GPL-2.0
/* CANARIS — implémentation du responder (Phase 4). */
#include "responder.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

/* Exécute argv[] (fork/exec/waitpid, sans shell -> pas d'injection).
 * Renvoie le code de sortie, ou -1 si échec d'exec. */
static int run_cmd(const char *const argv[])
{
	pid_t pid = fork();
	if (pid < 0)
		return -1;
	if (pid == 0) {
		/* silence stdout/stderr de l'enfant */
		int fd = open("/dev/null", 1 /*O_WRONLY*/);
		if (fd >= 0) { dup2(fd, 1); dup2(fd, 2); close(fd); }
		execvp(argv[0], (char *const *)argv);
		_exit(127);
	}
	int status = 0;
	if (waitpid(pid, &status, 0) < 0)
		return -1;
	return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}

static int command_exists(const char *name)
{
	const char *argv[] = { "sh", "-c", NULL, NULL };
	char buf[256];
	snprintf(buf, sizeof(buf), "command -v %s >/dev/null 2>&1", name);
	argv[2] = buf;
	return run_cmd(argv) == 0;
}

static double now_ms(void)
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return ts.tv_sec * 1000.0 + ts.tv_nsec / 1.0e6;
}

int responder_init(struct responder *r, const char *snapshot_root,
		   const char *baseline_root, const char *log_path,
		   int keep_baselines, int dry_run)
{
	memset(r, 0, sizeof(*r));
	snprintf(r->snapshot_root, sizeof(r->snapshot_root), "%s",
		 snapshot_root ? snapshot_root : "snapshots");
	snprintf(r->baseline_root, sizeof(r->baseline_root), "%s",
		 baseline_root ? baseline_root : "baselines");
	snprintf(r->log_path, sizeof(r->log_path), "%s",
		 log_path ? log_path : "canaris_events.log");
	r->keep_baselines = keep_baselines > 0 ? keep_baselines : 8;
	r->dry_run = dry_run;
	r->have_rsync = command_exists("rsync");
	mkdir(r->snapshot_root, 0700);
	mkdir(r->baseline_root, 0700);
	return 0;
}

void responder_log(struct responder *r, const char *fmt, ...)
{
	char msg[1024];
	va_list ap;
	va_start(ap, fmt);
	vsnprintf(msg, sizeof(msg), fmt, ap);
	va_end(ap);

	char ts[32];
	time_t now = time(NULL);
	struct tm tm;
	localtime_r(&now, &tm);
	strftime(ts, sizeof(ts), "%Y-%m-%dT%H:%M:%S", &tm);

	printf("%s %s\n", ts, msg);
	fflush(stdout);
	FILE *f = fopen(r->log_path, "a");
	if (f) {
		fprintf(f, "%s %s\n", ts, msg);
		fclose(f);
	}
}

/* Marqueurs de fichiers déjà chiffrés : un BASELINE ne doit jamais les copier. */
static const char *ENC_EXCLUDES[] = {
	"--exclude=*.LOCKED", "--exclude=*.CANARIS_LOCKED", "--exclude=*.encrypted",
	"--exclude=*.enc", "--exclude=*.crypt", "--exclude=*.crypto",
	"--exclude=*.lockbit", "--exclude=*.ryuk", "--exclude=*.conti",
};
#define N_ENC_EXCLUDES ((int)(sizeof(ENC_EXCLUDES) / sizeof(ENC_EXCLUDES[0])))

static void gen_stamp(char *ts, size_t len)
{
	struct timespec now;
	clock_gettime(CLOCK_REALTIME, &now);
	struct tm tm;
	time_t t = now.tv_sec;
	localtime_r(&t, &tm);
	char stamp[24];
	strftime(stamp, sizeof(stamp), "%Y%m%d-%H%M%S", &tm);
	snprintf(ts, len, "%s-%03d", stamp, (int)(now.tv_nsec / 1000000));
}

/* Synchronise UN dossier source vers dest/<base>/, avec --link-dest optionnel
 * (contre <linkroot>/<base>) et exclusion optionnelle des fichiers chiffrés. */
static void sync_one(struct responder *r, const char *src, const char *dest,
		     const char *linkroot, int exclude_enc)
{
	const char *base = strrchr(src, '/');
	base = base ? base + 1 : src;

	if (!r->have_rsync) {
		/* repli : cp -a (pas d'exclusion fine ; le baseline propre repose
		 * alors sur la fréquence de prise plutôt que sur l'exclusion). */
		const char *argv[] = { "cp", "-a", src, dest, NULL };
		run_cmd(argv);
		return;
	}

	char subdest[800], srcslash[600], linkdest[800] = {};
	snprintf(subdest, sizeof(subdest), "%s/%s", dest, base);
	mkdir(subdest, 0700);
	snprintf(srcslash, sizeof(srcslash), "%s/", src);

	const char *argv[8 + N_ENC_EXCLUDES];
	int a = 0;
	argv[a++] = "rsync";
	argv[a++] = "-a";
	if (linkroot && linkroot[0]) {
		snprintf(linkdest, sizeof(linkdest), "--link-dest=%s/%s", linkroot, base);
		argv[a++] = linkdest;
	}
	if (exclude_enc)
		for (int e = 0; e < N_ENC_EXCLUDES; e++)
			argv[a++] = ENC_EXCLUDES[e];
	argv[a++] = srcslash;
	argv[a++] = subdest;
	argv[a] = NULL;
	run_cmd(argv);
}

/* Rotation : ne garde que les `keep` derniers "baseline-*" (tri lexical = tri
 * temporel grâce à l'horodatage). */
static void rotate_baselines(struct responder *r)
{
	DIR *d = opendir(r->baseline_root);
	if (!d)
		return;
	enum { MAX_TRACK = 128, NAME_W = 256 };
	char names[MAX_TRACK][NAME_W];
	int count = 0;
	struct dirent *e;
	while ((e = readdir(d)) && count < MAX_TRACK) {
		if (strncmp(e->d_name, "baseline-", 9) == 0)
			snprintf(names[count++], NAME_W, "%s", e->d_name);
	}
	closedir(d);
	/* tri à bulles (petits volumes) */
	for (int i = 0; i < count; i++)
		for (int j = i + 1; j < count; j++)
			if (strcmp(names[i], names[j]) > 0) {
				char tmp[NAME_W];
				snprintf(tmp, NAME_W, "%s", names[i]);
				snprintf(names[i], NAME_W, "%s", names[j]);
				snprintf(names[j], NAME_W, "%s", tmp);
			}
	for (int i = 0; i < count - r->keep_baselines; i++) {
		char path[900];
		/* précisions bornées : cap la largeur des %s (évite le warning de
		 * troncature dû à la perte de borne de tableau au -O2). */
		snprintf(path, sizeof(path), "%.511s/%.255s", r->baseline_root, names[i]);
		const char *argv[] = { "rm", "-rf", path, NULL };
		run_cmd(argv);
	}
}

int responder_baseline(struct responder *r, const char *const *dirs, int n,
		       char *out_path, int out_len)
{
	char ts[48];
	gen_stamp(ts, sizeof(ts));
	char dest[600];
	snprintf(dest, sizeof(dest), "%s/baseline-%s", r->baseline_root, ts);
	if (out_path)
		snprintf(out_path, out_len, "%s", dest);
	if (r->dry_run)
		return 0;
	if (mkdir(dest, 0700) != 0 && errno != EEXIST)
		return -1;

	for (int i = 0; i < n; i++)
		sync_one(r, dirs[i], dest,
			 r->last_baseline[0] ? r->last_baseline : NULL,
			 1 /* exclut les fichiers chiffrés */);

	snprintf(r->last_baseline, sizeof(r->last_baseline), "%s", dest);
	rotate_baselines(r);
	return 0;
}

int responder_snapshot(struct responder *r, const char *const *dirs, int n,
		       char *out_path, int out_len)
{
	char ts[48];
	gen_stamp(ts, sizeof(ts));
	char dest[600];
	/* étiqueté post-incident : FORENSIQUE, pas une source de restauration. */
	snprintf(dest, sizeof(dest), "%s/post-incident-%s", r->snapshot_root, ts);
	snprintf(out_path, out_len, "%s", dest);
	if (r->dry_run)
		return 0;
	if (mkdir(dest, 0700) != 0 && errno != EEXIST)
		return -1;

	for (int i = 0; i < n; i++)
		sync_one(r, dirs[i], dest,
			 r->last_snapshot[0] ? r->last_snapshot : NULL,
			 0 /* forensique : on capture tout, y compris chiffré */);

	snprintf(r->last_snapshot, sizeof(r->last_snapshot), "%s", dest);
	return 0;
}

int responder_kill(uint32_t pid)
{
	if (kill((pid_t)pid, SIGKILL) == 0)
		return 0;
	return -errno;
}

double responder_respond(struct responder *r, uint32_t pid, const char *comm,
			 const char *reason, const char *detail,
			 const char *const *dirs, int n)
{
	double t0 = now_ms();
	char snap[600] = {};
	responder_snapshot(r, dirs, n, snap, sizeof(snap));
	int killed = r->dry_run ? 0 : responder_kill(pid);
	double elapsed = now_ms() - t0;

	const char *snapname = strrchr(snap, '/');
	snapname = snapname ? snapname + 1 : snap;
	char killstr[48];
	if (r->dry_run)
		snprintf(killstr, sizeof(killstr), "dry-run");
	else if (killed == 0)
		snprintf(killstr, sizeof(killstr), "ok");
	else
		snprintf(killstr, sizeof(killstr), "echec(%s)", strerror(-killed));
	responder_log(r,
		"REPONSE pid=%u comm=%s raison=%s (%s) forensique=%s kill=%s latence=%.1fms",
		pid, comm, reason, detail ? detail : "", snapname,
		killstr, elapsed);
	/* Source de RÉCUPÉRATION = dernier baseline propre (pas le forensique). */
	if (r->last_baseline[0]) {
		const char *bn = strrchr(r->last_baseline, '/');
		responder_log(r, "  RESTAURATION recommandee depuis le baseline propre : %s",
			      bn ? bn + 1 : r->last_baseline);
	} else {
		responder_log(r, "  ATTENTION : aucun baseline propre — activez le "
			      "baseline periodique (--baseline-interval)");
	}
	return elapsed;
}
