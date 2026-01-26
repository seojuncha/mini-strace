#include <sys/user.h>
#include <sys/syscall.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>

#include "def.h"

#define ERR_ITEM(error_code) { error_code, #error_code }

enum print_digit_opt
{
	digit_opt_dec,
	digit_opt_hex
};

struct error_table
{
	int code;
	char str[16];
} err_tbl[] = {
	{0, ""},   /* dummy for zero index */
	ERR_ITEM(EPERM),
	ERR_ITEM(ENOENT),
	ERR_ITEM(ESRCH),
	ERR_ITEM(EINTR),
	ERR_ITEM(EIO),
	ERR_ITEM(ENXIO),
	ERR_ITEM(E2BIG),
	ERR_ITEM(ENOEXEC),
	ERR_ITEM(EBADF),
	ERR_ITEM(ECHILD),
	ERR_ITEM(EAGAIN),
	ERR_ITEM(ENOMEM),
	ERR_ITEM(EACCES),
	ERR_ITEM(EFAULT),
	ERR_ITEM(ENOTBLK),
	ERR_ITEM(EBUSY),
	ERR_ITEM(EEXIST),
	ERR_ITEM(EXDEV),
	ERR_ITEM(ENODEV),
	ERR_ITEM(ENOTDIR),
	ERR_ITEM(EISDIR),
	ERR_ITEM(EINVAL),
	ERR_ITEM(ENFILE),
	ERR_ITEM(EMFILE),
	ERR_ITEM(ENOTTY),
	ERR_ITEM(ETXTBSY),
	ERR_ITEM(EFBIG),
	ERR_ITEM(ENOSPC),
	ERR_ITEM(ESPIPE),
	ERR_ITEM(EROFS),
	ERR_ITEM(EMLINK),
	ERR_ITEM(EPIPE),
	ERR_ITEM(EDOM),
	ERR_ITEM(ERANGE)
};

void print_pid(const struct traced_task * t)
{
	fprintf(stderr, "pid=%d tid=%d ", t->pid, t->tid);
}
 
void print_seq(const struct traced_task * t)
{
	fprintf(stderr, "[%06d] ", t->seq);
}

void print_relative_time(const struct traced_task * t)
{
	long sec, nano;
	double duration;
	
	if (t->status & START_TRACE) {
		fprintf(stderr, "+0.000ms ");
	} else {
		sec = t->entry_ts.tv_sec - t->last_entry_ts.tv_sec;
		nano = t->entry_ts.tv_nsec - t->last_entry_ts.tv_nsec;
		duration = sec * 1000 + (double)nano / 1000000.0;
		fprintf(stderr, "%+.03fms ", duration);
	}
}

void print_args_digit(int has_next, const char *n, int v, enum print_digit_opt o)
{
	if (o == digit_opt_dec)
		fprintf(stderr, "%s=%d", n, v);
	else
		fprintf(stderr, "%s=0x%x", n, v);

	if (has_next)
		fprintf(stderr, ", ");
}
 
void print_args_str(int has_next, const char *name, const char *str)
{
	size_t len = strlen(str) + 1;

	/* TODO: have to filter the option(max_length) */
	if (len > 64)
		len = 64;

	fprintf(stderr, "%s=\"", name); 
	for (int i = 0; i < len; i++) {
		if (str[i] == '\n')
			fprintf(stderr, "\\n");
		else
			fprintf(stderr, "%c", str[i]);
	}

	fprintf(stderr, "\"");
	if (has_next)
		fprintf(stderr, ", ");
}
 
void print_args_macro(int has_next, const char *name, int value)
{
	fprintf(stderr, "%s=", name);
	if (value == AT_FDCWD) {
		fprintf(stderr, "AT_FDCWD");
		goto next; 
	} 
	fprintf(stderr, "O_RDONLY");

	if (value & O_CLOEXEC)
	fprintf(stderr, "|O_CLOEXEC");
	if (value & O_APPEND)
	fprintf(stderr, "|O_APPEND");
	if (value & O_ASYNC)
	fprintf(stderr, "|O_ASYNC");

next:
	if (has_next)
		fprintf(stderr, ", ");
}

void print_syscall_args(const struct traced_task * t, long opts)
{
	struct user_regs_struct *reg = (struct user_regs_struct *)(t->user_regs);

	fprintf(stderr, " (");
	switch (t->nr) {
		case SYS_write:
			print_args_digit(1, "fd", reg->rdi, digit_opt_dec);
			print_args_str(1, "buf", t->mem_buf);
			print_args_digit(0, "count", reg->rdx, digit_opt_dec);
			break;

		case SYS_close:
			print_args_digit(0, "fd", reg->rdi, digit_opt_dec);
			break;
		
		case SYS_clone:
			print_args_digit(1, "fn", reg->rdi, digit_opt_hex);
			print_args_digit(1, "stack", reg->rsi, digit_opt_hex);
			break;
		
		case SYS_access:
			print_args_str(1, "pathname", t->mem_buf);
			print_args_digit(0, "mode", reg->rsi, digit_opt_hex);
			break;

		case SYS_openat:
			if ((int)reg->rdi == AT_FDCWD)
				print_args_macro(1, "dirfd", reg->rdi);
			else 
				print_args_digit(1, "dirfd", reg->rdi, digit_opt_dec);
			print_args_str(1, "pathname", t->mem_buf);
			print_args_macro(0, "flags", reg->rdx);
			break;
		
		case SYS_brk:
			print_args_digit(0, "addr", reg->rdi, digit_opt_hex);
			break;

		case SYS_mmap:
			print_args_digit(1, "addr", reg->rdi, digit_opt_hex);
			print_args_digit(1, "length", reg->rsi, digit_opt_dec);
			print_args_digit(1, "prot", reg->rdx, digit_opt_hex);
			print_args_digit(0, "flags", reg->r10, digit_opt_hex);
			break;
		
		case SYS_munmap:
			print_args_digit(1, "addr", reg->rdi, digit_opt_hex);
			print_args_digit(0, "length", reg->rsi, digit_opt_dec);
			break;

		case SYS_mprotect:
			print_args_digit(1, "addr", reg->rdi, digit_opt_hex);
			print_args_digit(1, "len", reg->rsi, digit_opt_dec);
			print_args_digit(0, "prot", reg->rdx, digit_opt_hex);
			break;

		case SYS_execve:
			// print_args_str(1, "pathname", t->mem_buf, strlen(t->mem_buf) + 1);
			print_args_digit(1, "argv", reg->rsi, digit_opt_hex);
			print_args_digit(0, "envp", reg->rdx, digit_opt_hex);
			break;

		case SYS_exit_group:
			print_args_digit(0, "status", reg->rdi, digit_opt_dec);
			break;

		case SYS_set_tid_address:
			print_args_digit(0, "tidptr", reg->rdi, digit_opt_hex);
			break;

		default:
			break;
	}
	fprintf(stderr, ")");
	if (opts & VIEW_TIMELINE)
		fprintf(stderr, "\n");
}

void print_ret_detail(int nr, long long ret)
{
	switch (nr) {
		case SYS_clone:
			fprintf(stderr, " %s(new thread %lld is created)%s", GREEN, ret, RESET);
			break;
		default:
			break;
	}
}

void print_syscall_ret(const struct traced_task * t, long opts)
{
	if (opts & VIEW_TIMELINE) {
		fprintf(stderr, " ret = ");
	} else {
		fprintf(stderr, " = ");
	}

	// TODO: exit_group is failed in here. because of no sigtrap event!
	if (t->status & HAS_NO_RETURN) {
		fprintf(stderr, "?");
		goto newline;
	}
	else {
		if (t->nr == SYS_mmap || t->nr == SYS_brk)
			fprintf(stderr, "0x%llx", t->syscall_ret);
		else
			fprintf(stderr, "%lld", t->syscall_ret);
	}

	if (t->syscall_ret < 0) {
		int idx = abs(t->syscall_ret);
		fprintf(stderr, "%s <=== %s (%s)%s",
			RED, err_tbl[idx].str, strerror(err_tbl[idx].code), RESET);
	}
	print_ret_detail(t->nr, t->syscall_ret);

newline:
        (opts & VIEW_TIMELINE) ? fprintf(stderr, "\n\n") : fprintf(stderr, "\n");
}

void print_syscall(const struct traced_task * t, long opts, int in_syscall)
{
	if (!in_syscall) {
		print_seq(t);
		if (opts & SHOW_RELATIVE_TIME)
			print_relative_time(t);
		if (opts & SHOW_PID)
			print_pid(t);
		if (opts & VIEW_TIMELINE)
			fprintf(stderr, "ENTER ");
		fprintf(stderr, "%s", t->syscall_name);
		print_syscall_args(t, opts);
	} else {
		if (opts & VIEW_TIMELINE) {
			print_seq(t);
			if (opts & SHOW_RELATIVE_TIME)
				print_relative_time(t);
			if (opts & SHOW_PID)
				print_pid(t);
			fprintf(stderr, "EXIT  %s", t->syscall_name);
		}
		print_syscall_ret(t, opts);
	}
}