// SPDX-License-Identifier: GPL-2.0
/* Test unitaire C du responder (linux/userspace/responder.c) : kill réel d'un
 * processus fils + snapshot d'un répertoire. Valide le chemin de réponse hors
 * eBPF (le kill via PID fonctionne quand loader et cible partagent la même
 * PID-namespace — cas d'une VM bare-metal ; le test end-to-end en conteneur
 * souffre d'un décalage de namespace, cf. docs/VALIDATION.md).
 */
#include "responder.h"
#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

static int failures = 0;
#define CHECK(cond, msg) do { \
	if (!(cond)) { printf("  ✗ %s\n", msg); failures++; } \
	else         { printf("  ✓ %s\n", msg); } \
} while (0)

static int count_files(const char *dir)
{
	int n = 0;
	DIR *d = opendir(dir);
	if (!d) return 0;
	struct dirent *e;
	while ((e = readdir(d))) {
		if (e->d_name[0] == '.') continue;
		char path[1024];
		snprintf(path, sizeof(path), "%s/%s", dir, e->d_name);
		struct stat st;
		if (stat(path, &st) == 0) {
			if (S_ISDIR(st.st_mode)) n += count_files(path);
			else n++;
		}
	}
	closedir(d);
	return n;
}

int main(void)
{
	printf("== test_responder ==\n");
	char tmpl[] = "/tmp/canaris_ctestXXXXXX";
	char *base = mkdtemp(tmpl);
	if (!base) { perror("mkdtemp"); return 2; }

	char protected[1100], snaproot[1100], logp[1100];
	snprintf(protected, sizeof(protected), "%s/Documents", base);
	snprintf(snaproot, sizeof(snaproot), "%s/snapshots", base);
	snprintf(logp, sizeof(logp), "%s/canaris.log", base);
	mkdir(protected, 0700);
	for (int i = 0; i < 25; i++) {
		char f[1200];
		snprintf(f, sizeof(f), "%s/doc%02d.txt", protected, i);
		FILE *fp = fopen(f, "w");
		if (fp) { fprintf(fp, "contenu utilisateur important %d\n", i); fclose(fp); }
	}

	char blroot[1100];
	snprintf(blroot, sizeof(blroot), "%s/baselines", base);
	struct responder r;
	responder_init(&r, snaproot, blroot, logp, 8, 0);

	/* --- baseline propre (T1) : capture les fichiers, exclut les chiffrés --- */
	char bout[600];
	/* pose un fichier déjà chiffré : il ne doit PAS entrer dans le baseline */
	char locked[1200];
	snprintf(locked, sizeof(locked), "%s/deja.txt.CANARIS_LOCKED", protected);
	FILE *lf = fopen(locked, "w");
	if (lf) { fprintf(lf, "chiffre"); fclose(lf); }
	int brc = responder_baseline(&r, (const char *[]){ protected }, 1, bout, sizeof(bout));
	CHECK(brc == 0, "responder_baseline renvoie 0");
	int bfiles = count_files(bout);
	CHECK(bfiles == 25, "baseline contient les 25 fichiers propres (chiffré exclu)");

	/* --- snapshot forensique --- */
	char out[600];
	int rc = responder_snapshot(&r, (const char *[]){ protected }, 1, out, sizeof(out));
	CHECK(rc == 0, "responder_snapshot renvoie 0");
	int nf = count_files(out);
	CHECK(nf == 26, "snapshot forensique capture tout (25 + le chiffré)");

	/* --- kill réel d'un fils --- */
	pid_t child = fork();
	if (child == 0) {
		/* fils : boucle jusqu'à être tué */
		for (;;) pause();
		_exit(0);
	}
	usleep(100000); /* laisse le fils démarrer */
	int krc = responder_kill((uint32_t)child);
	CHECK(krc == 0, "responder_kill renvoie 0");
	int status = 0;
	pid_t w = waitpid(child, &status, 0);
	CHECK(w == child && WIFSIGNALED(status) && WTERMSIG(status) == 9,
	      "le fils a bien été tué par SIGKILL");

	/* --- réponse complète + latence --- */
	pid_t child2 = fork();
	if (child2 == 0) { for (;;) pause(); _exit(0); }
	usleep(100000);
	double ms = responder_respond(&r, (uint32_t)child2, "cryptor", "io_rate",
				      "test", (const char *[]){ protected }, 1);
	waitpid(child2, NULL, 0);
	CHECK(ms >= 0 && ms < 500.0, "réponse complète < 500 ms (NF2)");

	/* nettoyage best-effort */
	char cmd[1200];
	snprintf(cmd, sizeof(cmd), "rm -rf %s", base);
	if (system(cmd)) { /* ignore */ }

	printf(failures ? "\nÉCHECS: %d\n" : "\nOK (test_responder)\n", failures);
	return failures ? 1 : 0;
}
