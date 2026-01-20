#ifndef DEF_H_
#define DEF_H_

#include <sys/wait.h>
#include <string.h>
#include <stdint.h>

#define MAX_TASKS 5

#define TASK_SYSCALL_ENTER (0x0001)
#define TASK_SYSCALL_EXIT (0x0002)

struct task {
  pid_t pid;

  char exec_path[128];
  int exec_ret;

  int in_syscall;
  int alive;
  int is_leaf;   /* is not a root tracee */
};

struct traced_task {
  int seq;
  int pid;
  int tid;
  int status;

  unsigned long nr;
  char sysname[16];
  unsigned long ret;

  void *user_regs;
};

struct task_block {
  pid_t tracee_pid;
  long opts;
  struct traced_task tt[MAX_TASKS];
};

#if 0
struct task *find_task(struct task *tasks, pid_t pid);

void add_traced_task(struct task *tasks, pid_t pid, int is_leaf);
void remove_traced_task(struct task *tasks, pid_t pid);
int have_alive_tasks(const struct task *tasks);
#else

/* new interfaces */
void add_new_task(struct task_block *tb, pid_t pid);
void remove_task(struct task_block *tb, pid_t pid);
struct traced_task *get(struct task_block *tb, pid_t pid);
#endif

#endif