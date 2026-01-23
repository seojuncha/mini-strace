#ifndef DEF_H_
#define DEF_H_

#include <sys/wait.h>
#include <string.h>
#include <stdint.h>
#include <time.h>

#define MAX_TASKS 5

/* traced_task options */
#define IN_SYSCALL 0x01
#define HAS_NO_RETURN 0x02
#define START_TRACE 0x10
#define TASK_ACTIVATED 0x20

/* global tracer options */
#define VIEW_TIMELINE 0x100
#define SHOW_PID 0x200
#define SHOW_RELATIVE_TIME 0x400

/* colored text */
#define RED  "\033[0;31m"
#define GREEN "\033[0;32m"
#define YELLOW "\033[0;33m"
#define RESET "\033[0m"

enum sys
{
	sys_read,
	sys_write,
	sys_open,
	sys_close,
	sys_stat,
	sys_fstat,
	sys_lstat,
	sys_poll,
	sys_lseek,
	sys_mmap,
	sys_mprotect,
	sys_munmap,
	sys_brk,
	sys_rt_sigaction,
	sys_rt_sigprocmask,
	sys_rt_sigreturn,
	sys_ioctl,
	sys_pread64,
	sys_pwrite64,
	sys_readv,
	sys_writev,
	sys_access,
	sys_pipe,
	sys_select,
	sys_sched_yield,
	sys_mremap,
	sys_msync,
	sys_mincore,
	sys_madvise,
	sys_shmget,
	sys_shmat,
	sys_shmctl,
	sys_dup,
	sys_dup2,
	sys_pause,
	sys_nanosleep,
	sys_getitimer,
	sys_alarm,
	sys_setitimer,
	sys_getpid,
	sys_sendfile,
	sys_socket,
	sys_connect,
	sys_accept,
	sys_sendto,
	sys_recvfrom,
	sys_sendmsg,
	sys_recvmsg,
	sys_shutdown,
	sys_bind,
	sys_listen,
	sys_getsockname,
	sys_getpeername,
	sys_socketpair,
	sys_setsockopt,
	sys_getsockopt,

	sys_clone = 56,
	sys_fork,
	sys_vfork,
	sys_execve,
	sys_exit,
	sys_wait4,
	sys_kill,
	sys_uname,
	sys_semget,
	sys_semop,
	sys_semctl,
	sys_shmdt,
	sys_msgget,
	sys_msgsnd,
	sys_msgrcv,
	sys_msgctl,
	sys_fcntl,
	sys_flock,
	sys_fsync,
	sys_fdatasync,
	sys_truncate,
	sys_ftruncate,
	sys_getdents,
	sys_getcwd,
	sys_chdir,
	sys_fchdir,
	sys_rename,
	sys_mkdir,
	sys_rmdir,
	sys_creat,
	sys_link,
	sys_unlink,
	sys_symlink,
	sys_readlink,
	sys_chmod,
	sys_fchmod,
	sys_chown,
	sys_fchown,
	sys_arch_prctl = 158,
	sys_set_tid_address = 218,
	sys_exit_group = 231,
	sys_openat = 257,
	sys_set_robust_list = 273,
	sys_prlimit64 = 302,
	sys_rseq = 334
};

struct traced_task
{
	int seq;
	int pid;
	int tid;
	int status;

	int nr;
	char syscall_name[16];
	unsigned long syscall_ret;

	void *user_regs;

	struct timespec last_entry_ts;
	struct timespec entry_ts;
};

struct task_block
{
	pid_t tracee_pid;
	long trace_opts;

	// in here??? 
	int opts;

	struct traced_task tt[MAX_TASKS];
};


/* new interfaces */
void add_new_task(struct task_block * tb, pid_t pid);
void remove_task(struct task_block * tb, pid_t pid);
struct traced_task *get(struct task_block * tb, pid_t pid);
int alive_tasks(const struct task_block * tb);

#endif
