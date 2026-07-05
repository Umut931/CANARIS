// SPDX-License-Identifier: GPL-2.0
/* CANARIS — programmes eBPF.
 *
 * Phase 1 (ce fichier, partie kprobes) : OBSERVATION.
 *   kprobes CO-RE sur les syscalls openat / write / unlinkat, émission des
 *   événements vers l'userspace via un BPF_MAP_TYPE_RINGBUF.
 *
 *   Les kprobes sont READ-ONLY : elles ne peuvent PAS bloquer une syscall
 *   (CLAUDE.md §2.2). Le blocage réel est délégué aux hooks LSM BPF (Phase 2,
 *   ajoutés plus bas dans ce même fichier).
 *
 * CO-RE : ce programme n'inclut PAS les headers du kernel cible. Il s'appuie
 * sur vmlinux.h (généré depuis /sys/kernel/btf/vmlinux) + les macros CO-RE,
 * ce qui le rend portable entre versions de kernel (Compile Once Run Everywhere).
 *
 * Attache via SEC("ksyscall/<nom>") : libbpf résout automatiquement la fonction
 * d'entrée spécifique à l'architecture — sur x86_64 c'est __x64_sys_openat,
 * __x64_sys_write, __x64_sys_unlinkat (cf. cahier des charges F2.4) — et gère
 * le déballage du wrapper pt_regs. C'est l'équivalent CO-RE portable d'un
 * kprobe sur __x64_sys_openat, sans coder en dur le préfixe d'architecture.
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "canaris.h"

char LICENSE[] SEC("license") = "GPL";

/* ------------------------------------------------------------------ maps -- */

/* Ring buffer kernel -> userspace (pas de perf buffer legacy, cf. §5). */
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 24); /* 16 Mo */
} rb SEC(".maps");

/* Config globale poussée par l'userspace (clé 0). Sert notamment à ignorer
 * le loader lui-même pour éviter les boucles de rétroaction. */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct canaris_config);
} config_map SEC(".maps");

/* -------------------------------------------------------------- helpers -- */

static __always_inline struct canaris_config *get_config(void)
{
	__u32 zero = 0;
	return bpf_map_lookup_elem(&config_map, &zero);
}

/* Renseigne les champs communs (pid/tgid/uid/comm/timestamp) d'un événement. */
static __always_inline void fill_common(struct canaris_event *e, __u32 type)
{
	__u64 id = bpf_get_current_pid_tgid();
	e->timestamp_ns = bpf_ktime_get_ns();
	e->pid  = (__u32)id;
	e->tgid = (__u32)(id >> 32);
	e->uid  = (__u32)bpf_get_current_uid_gid();
	e->event_type = type;
	e->ret = 0;
	e->flags = 0;
	e->ino = 0;
	e->dev = 0;
	e->_pad = 0;
	e->filename[0] = '\0';
	bpf_get_current_comm(&e->comm, sizeof(e->comm));
}

/* True si l'appelant est le loader CANARIS lui-même (à ne pas tracer). */
static __always_inline int is_self(void)
{
	struct canaris_config *cfg = get_config();
	if (!cfg)
		return 0;
	__u32 tgid = (__u32)(bpf_get_current_pid_tgid() >> 32);
	return cfg->self_tgid != 0 && tgid == cfg->self_tgid;
}

/* Émet un événement "chemin" (openat / unlinkat) dans le ring buffer. */
static __always_inline int emit_path_event(__u32 type, const char *user_path,
					   __u32 flags)
{
	struct canaris_event *e;

	if (is_self())
		return 0;

	e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e)
		return 0; /* ring buffer plein : on drop, jamais de blocage ici */

	fill_common(e, type);
	e->flags = flags;
	if (user_path)
		bpf_probe_read_user_str(&e->filename, sizeof(e->filename),
					user_path);
	bpf_ringbuf_submit(e, 0);
	return 0;
}

/* ----------------------------------------------------------- kprobes ----- */
/* NB : BPF_KSYSCALL déballe le wrapper pt_regs et fournit les vrais arguments
 * du syscall de façon portable (CO-RE). */

/* openat(int dfd, const char *filename, int flags, umode_t mode) */
SEC("ksyscall/openat")
int BPF_KSYSCALL(canaris_openat, int dfd, const char *filename, int flags)
{
	return emit_path_event(EVENT_OPEN, filename, (__u32)flags);
}

/* openat2(int dfd, const char *filename, struct open_how *, size_t)
 * Certaines libs récentes utilisent openat2 ; on le couvre aussi. */
SEC("ksyscall/openat2")
int BPF_KSYSCALL(canaris_openat2, int dfd, const char *filename)
{
	return emit_path_event(EVENT_OPEN, filename, 0);
}

/* unlinkat(int dfd, const char *pathname, int flag) */
SEC("ksyscall/unlinkat")
int BPF_KSYSCALL(canaris_unlinkat, int dfd, const char *pathname, int flag)
{
	return emit_path_event(EVENT_UNLINK, pathname, (__u32)flag);
}

/* write(unsigned int fd, const char *buf, size_t count)
 * Le syscall write ne porte pas de chemin (juste un fd) : on émet un
 * événement de télémétrie avec le fd et le nombre d'octets. L'identité du
 * fichier écrit est résolue au niveau des hooks LSM/vfs (Phase 2). */
SEC("ksyscall/write")
int BPF_KSYSCALL(canaris_write, unsigned int fd, const char *buf, size_t count)
{
	struct canaris_event *e;

	if (is_self())
		return 0;

	e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e)
		return 0;

	fill_common(e, EVENT_WRITE);
	e->flags = fd;
	e->ino = (__u64)count; /* réutilise ino pour transporter le nb d'octets */
	bpf_ringbuf_submit(e, 0);
	return 0;
}
