#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/syscall.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>

#include "syscall.h"

static const char *syscall_name(unsigned long nr)
{
	switch(nr) {
		case SYS_read: return "read";
		case SYS_write: return "write";
		case SYS_open: return "open";
		case SYS_openat: return "openat";
		case SYS_access: return "acceess";
		case SYS_close: return "close";
		case SYS_accept: return "accept";
		case SYS_pread64: return "pread64";
		case SYS_mprotect: return "mprotect";
		case SYS_brk: return "brk";
		case SYS_mmap: return "mmap";
		case SYS_munmap: return "munmap";
		case SYS_fstat: return "fstat";
		case SYS_clone: return "clone";
		case SYS_fork: return "fork";
		case SYS_vfork: return "vfork";
		case SYS_execve: return "execve";
		case SYS_exit: return "exit";
		case SYS_exit_group: return "exit_group";
		case SYS_set_tid_address: return "set_tid_address";
		case SYS_set_robust_list: return "set_robust_list";
		case SYS_arch_prctl: return "arch_prctl";
		case SYS_prlimit64: return "prlimit64";
		case SYS_rseq: return "rseq";
		default: return "unknown";
	}
}

int entering(const struct traced_task * t)
{
	return !(t->status & IN_SYSCALL);
}

int exiting(const struct traced_task * t)
{
	return (t->status & HAS_NO_RETURN) ? 1 : t->status & IN_SYSCALL;
}

void done_entering(struct traced_task * t, int * seq)
{
	t->status |= IN_SYSCALL;
	(*seq)++;
}

void done_exiting(struct traced_task * t, int * seq, long opts)
{
	t->status &= ~IN_SYSCALL;
	if (opts & VIEW_TIMELINE)
		(*seq)++;
}

#define WORD_BYTES sizeof(long)

void read_memory(struct traced_task * t, unsigned long reg_addr, size_t sz)
{
	if (t->mem_buf) {
		fprintf(stderr, "memory check point\n");
		free(t->mem_buf);
	}
	t->mem_buf = calloc(sz + 1, 1);

	for (size_t off = 0; off < sz; off += WORD_BYTES) {
		unsigned long addr = reg_addr + off;
		long ret = ptrace(PTRACE_PEEKDATA, t->tid, addr, NULL);
		size_t n = sz - off;
		if (n > WORD_BYTES) n = WORD_BYTES;
			memcpy(t->mem_buf + off, &ret, n);
	}
}

void decode_event(struct traced_task * t, int event)
{
}

int decode_syscall_enter(struct traced_task * t, long opts)
{
	struct user_regs_struct *reg = (struct user_regs_struct *)(t->user_regs);
	const char *sn;

	if (!(t->status & START_TRACE)) {
		t->last_entry_ts.tv_sec = t->entry_ts.tv_sec;
		t->last_entry_ts.tv_nsec = t->entry_ts.tv_nsec;
	} 
	clock_gettime(CLOCK_MONOTONIC, &t->entry_ts);

	ptrace(PTRACE_GETREGS, t->tid, 0, reg);
	t->nr = reg->orig_rax;
	sn = syscall_name(t->nr);
	strncpy(t->syscall_name, sn, strlen(sn) + 1);

	switch (t->nr) {
		case SYS_execve:
			read_memory(t, reg->rdi, 64);
			break;

		case SYS_write:
			read_memory(t, reg->rsi, reg->rdx);
			break;

		case SYS_openat:
			read_memory(t, reg->rsi, 32);
			break;

		case SYS_access:
			read_memory(t, reg->rdi, 32);
			break;

		case SYS_exit_group:
			t->status |= HAS_NO_RETURN;
			break;

		default:
			break;
	}
	return 0;
}

int decode_syscall_exit(struct traced_task * t, long opts)
{
	struct user_regs_struct *reg = (struct user_regs_struct *)(t->user_regs);
	unsigned long long nr;

	ptrace(PTRACE_GETREGS, t->tid, 0, reg);
	nr = reg->orig_rax;
	t->syscall_ret = (long long)reg->rax;

	if (t->nr != nr) {
		printf("check point\n");
		return -1;
	}

	if (t->status & START_TRACE)
		t->status &= ~START_TRACE;

	if (opts & VIEW_TIMELINE) {
		if (!(t->status & START_TRACE)) {
			t->last_entry_ts.tv_sec = t->entry_ts.tv_sec;
			t->last_entry_ts.tv_nsec = t->entry_ts.tv_nsec;
		}
		clock_gettime(CLOCK_MONOTONIC, &t->entry_ts);
	}
	return 0;
}

void reenter_syscall(const struct traced_task * t)
{
	ptrace(PTRACE_SYSCALL, t->pid, 0L, 0L);
}

void set_trace_options(struct traced_task * t, long opts)
{
	ptrace(PTRACE_SETOPTIONS, t->pid, 0L, opts);
}