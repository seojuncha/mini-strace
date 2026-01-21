#ifndef DEF_H_
#define DEF_H_

#include <sys/wait.h>
#include <string.h>
#include <stdint.h>

#define MAX_TASKS 5

#define TASK_ACTIVATED 0x1000

#define TASK_SYSCALL_ENTER 0x0001
#define TASK_SYSCALL_EXIT 0x0002


struct traced_task {
  int seq;
  int pid;
  int tid;
  int status;

  unsigned long nr;
  char sysname[16];
  unsigned long sysret;

  void *user_regs;
};

struct task_block {
  pid_t tracee_pid;
  long opts;
  struct traced_task tt[MAX_TASKS];
};


/* new interfaces */
void add_new_task(struct task_block *tb, pid_t pid);
void remove_task(struct task_block *tb, pid_t pid);
struct traced_task *get(struct task_block *tb, pid_t pid);
int alive_tasks(const struct task_block *tb);

#endif
