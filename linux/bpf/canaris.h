/* CANARIS — structures partagées kernel (eBPF) <-> userspace (libbpf).
 *
 * Ce header est inclus par :
 *   - linux/bpf/canaris.bpf.c   (côté noyau, après vmlinux.h)
 *   - linux/userspace/main.c    (côté userspace, après <bpf/libbpf.h>)
 *
 * Il n'inclut aucun autre header : il suppose que les types __u8/__u32/__u64
 * sont déjà définis par l'includeur (vmlinux.h côté noyau, <linux/types.h>
 * côté userspace). C'est le pattern standard libbpf pour un header partagé.
 */
#ifndef CANARIS_H
#define CANARIS_H

#define TASK_COMM_LEN     16
#define MAX_FILENAME_LEN  256

/* Types d'événements émis via le ring buffer (kernel -> userspace). */
enum canaris_event_type {
	EVENT_OPEN       = 1,  /* openat observé (kprobe)                 */
	EVENT_WRITE      = 2,  /* write observé  (kprobe)                 */
	EVENT_UNLINK     = 3,  /* unlinkat observé (kprobe)               */
	EVENT_RENAME     = 4,  /* rename observé (LSM, Phase 2)           */
	EVENT_BLOCKED    = 5,  /* opération bloquée par LSM (-EPERM)      */
	EVENT_CANARY_HIT = 6,  /* accès à un canary : alerte immédiate    */
};

/* Événement remonté à l'userspace. Chaque producteur remplit ce qu'il a :
 *  - les kprobes (Phase 1) remplissent filename (chemin utilisateur) ;
 *  - les hooks LSM (Phase 2) remplissent ino/dev (identité inode robuste)
 *    + le nom de dentry en best-effort.
 */
struct canaris_event {
	__u64 timestamp_ns;              /* bpf_ktime_get_ns()               */
	__u32 pid;                       /* PID (thread)                     */
	__u32 tgid;                      /* TGID (process)                   */
	__u32 uid;                       /* UID appelant                     */
	__u32 event_type;                /* enum canaris_event_type          */
	__s32 ret;                       /* verdict LSM (0 / -EPERM)         */
	__u32 flags;                     /* open flags / fd / rename flags   */
	__u64 ino;                       /* inode cible (0 si inconnu)       */
	__u32 dev;                       /* device de l'inode                */
	__u32 _pad;
	char  comm[TASK_COMM_LEN];       /* nom du process appelant          */
	char  filename[MAX_FILENAME_LEN];/* chemin (kprobe) ou nom dentry    */
};

/* Clé du map des fichiers protégés / canaries : (device, inode).
 * L'identification par inode est robuste (insensible aux renommages de chemin
 * et à la reconstruction de chemin, coûteuse et bornée dans le verifier).
 */
struct file_key {
	__u64 ino;
	__u32 dev;
	__u32 _pad;
};

/* Valeur associée : décrit pourquoi le fichier est protégé. */
struct protect_val {
	__u8 is_canary;   /* 1 = canary (accès => alerte immédiate)          */
	__u8 is_dir;      /* 1 = répertoire protégé (match par ancêtre)      */
	__u8 _pad[6];
};

/* Config globale poussée par l'userspace (single-entry array map, clé 0). */
struct canaris_config {
	__u32 self_tgid;   /* TGID du loader lui-même : à ne jamais bloquer  */
	__u8  enforce;     /* 1 = LSM bloque (-EPERM), 0 = observe seulement  */
	__u8  _pad[3];
};

#endif /* CANARIS_H */
