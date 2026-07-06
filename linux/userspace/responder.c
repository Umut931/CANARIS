// SPDX-License-Identifier: GPL-2.0
/* CANARIS — implémentation du responder (Phase 4). */
#include "responder.h"

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
		   const char *log_path, int dry_run)
{
	memset(r, 0, sizeof(*r));
	strncpy(r->snapshot_root, snapshot_root ? snapshot_root : "snapshots",
		sizeof(r->snapshot_root) - 1);
	strncpy(r->log_path, log_path ? log_path : "canaris_events.log",
		sizeof(r->log_path) - 1);
	r->dry_run = dry_run;
	r->have_rsync = command_exists("rsync");
	mkdir(r->snapshot_root, 0700);
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

int responder_snapshot(struct responder *r, const char *const *dirs, int n,
		       char *out_path, int out_len)
{
	char ts[48];
	struct timespec now;
	clock_gettime(CLOCK_REALTIME, &now);
	struct tm tm;
	time_t t = now.tv_sec;
	localtime_r(&t, &tm);
	char stamp[24];
	strftime(stamp, sizeof(stamp), "%Y%m%d-%H%M%S", &tm);
	int millis = (int)(now.tv_nsec / 1000000);
	snprintf(ts, sizeof(ts), "%s-%03d", stamp, millis);

	char dest[600];
	snprintf(dest, sizeof(dest), "%s/%s", r->snapshot_root, ts);
	snprintf(out_path, out_len, "%s", dest);
	if (r->dry_run)
		return 0;
	if (mkdir(dest, 0700) != 0 && errno != EEXIST)
		return -1;

	for (int i = 0; i < n; i++) {
		if (r->have_rsync) {
			/* rsync -a --link-dest=<prev> <src>/ <dest>/<name>/ */
			char linkdest[800] = {};
			const char *base = strrchr(dirs[i], '/');
			base = base ? base + 1 : dirs[i];
			char subdest[800];
			snprintf(subdest, sizeof(subdest), "%s/%s", dest, base);
			mkdir(subdest, 0700);

			char srcslash[600];
			snprintf(srcslash, sizeof(srcslash), "%s/", dirs[i]);

			const char *argv[8];
			int a = 0;
			argv[a++] = "rsync";
			argv[a++] = "-a";
			if (r->last_snapshot[0]) {
				snprintf(linkdest, sizeof(linkdest),
					 "--link-dest=%s/%s", r->last_snapshot, base);
				argv[a++] = linkdest;
			}
			argv[a++] = srcslash;
			argv[a++] = subdest;
			argv[a] = NULL;
			run_cmd(argv);
		} else {
			/* repli : cp -a <src> <dest>/ (copie récursive) */
			const char *argv[] = { "cp", "-a", dirs[i], dest, NULL };
			run_cmd(argv);
		}
	}
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
		"REPONSE pid=%u comm=%s raison=%s (%s) snapshot=%s kill=%s latence=%.1fms",
		pid, comm, reason, detail ? detail : "", snapname,
		killstr, elapsed);
	return elapsed;
}
