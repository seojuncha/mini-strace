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

struct traced_task
{
	int seq;
	int pid;
	int tid;
	int status;

	int nr;
	char syscall_name[16];
	long long syscall_ret;

	void * user_regs;
	char * mem_buf;
	size_t mem_sz;

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
