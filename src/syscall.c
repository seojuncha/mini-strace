#include <sys/ptrace.h>
#include <sys/user.h>
#include <stdio.h>
#include <unistd.h>
#include <time.h>

#include "syscall.h"

static const char *syscall_name(unsigned long nr)
{
	switch(nr) {
		case sys_read: return "read";
		case sys_write: return "write";
		case sys_open: return "open";
		case sys_openat: return "openat";
		case sys_access: return "acceess";
		case sys_close: return "close";
		case sys_accept: return "accept";
		case sys_pread64: return "pread64";
		case sys_mprotect: return "mprotect";
		case sys_brk: return "brk";
		case sys_mmap: return "mmap";
		case sys_munmap: return "munmap";
		case sys_fstat: return "fstat";
		case sys_clone: return "clone";
		case sys_fork: return "fork";
		case sys_vfork: return "vfork";
		case sys_execve: return "execve";
		case sys_exit: return "exit";
		case sys_exit_group: return "exit_group";
		case sys_set_tid_address: return "set_tid_address";
		case sys_set_robust_list: return "set_robust_list";
		case sys_arch_prctl: return "arch_prctl";
		case sys_prlimit64: return "prlimit64";
		case sys_rseq: return "rseq";
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

void done_entering(struct traced_task * t)
{
	t->status |= IN_SYSCALL;
	t->seq++;
}

void done_exiting(struct traced_task * t, long opts)
{
	t->status &= ~IN_SYSCALL;
	if (opts & VIEW_TIMELINE)
		t->seq++;
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

	if (t->nr == sys_exit_group)
		t->status |= HAS_NO_RETURN;

	return 0;
}

int decode_syscall_exit(struct traced_task * t, long opts)
{
	struct user_regs_struct *reg = (struct user_regs_struct *)(t->user_regs);
	unsigned long long nr;

	ptrace(PTRACE_GETREGS, t->tid, 0, reg);
	nr = reg->orig_rax;
	t->syscall_ret = reg->rax;

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