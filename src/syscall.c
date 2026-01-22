#include <sys/ptrace.h>
#include <sys/user.h>
#include <stdio.h>
#include <unistd.h>
#include <time.h>

#include "syscall.h"

enum sys
{
	sys_read,
	sys_write,
	sys_open,
	sys_close,
	sys_clone = 56,
	sys_fork,
	sys_vfork,
	sys_execve,
	sys_exit,
	sys_exit_group = 231,
	sys_openat = 257
};

static const char *syscall_name(unsigned long nr) {
	switch(nr) {
		case 0: return "read";
		case 1: return "write";
		case 2: return "open";
		case 3: return "close";
		// case 4: return "stat";
		// case 5: return "fstat";
		// case 8: return "lseek";
		// case 9: return "mmap";
		// case 10: return "mprotect";
		// case 11: return "munmap";
		// case 12: return "brk";
		// case 17: return "pread64";
		// case 18: return "pwrite64";
		// case 21: return "access";
		//case 39: return "getpid";
		case 56: return "clone";
		case 57: return "fork";
		case 58: return "vfork";
		case 59: return "execve";
		case 60: return "exit";
		case 231: return "exit_group";
		case 257: return "openat";
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
	} else {
		t->status &= ~START_TRACE;
	}
	clock_gettime(CLOCK_MONOTONIC, &t->entry_ts);

	ptrace(PTRACE_GETREGS, t->tid, 0, reg);
	t->nr = reg->orig_rax;
	sn = syscall_name(t->nr);
	strncpy(t->syscall_name, sn, strlen(sn) + 1);

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