#ifndef DEF_H_
#define DEF_H_

#include <sys/wait.h>
#include <string.h>
#include <stdint.h>

#define MAX_TASKS 5

#define TASK_IN_SYSCALL (0x0001)
#define TASK_IS_ALIVE (0x0001 << 1)

struct task {
  pid_t pid;

  char exec_path[128];
  int exec_ret;

  int in_syscall;
  int alive;
  int is_leaf;   /* is not a root tracee */
};


struct trace_opts {

};

struct traced_task {
  int pid;
  int tid;
  uint16_t status;
};

struct task_block {
  pid_t tracee_pid;
  long opts;
  struct traced_task tt[MAX_TASKS];
};

struct task *find_task(struct task *tasks, pid_t pid);

void add_traced_task(struct task *tasks, pid_t pid, int is_leaf);
void remove_traced_task(struct task *tasks, pid_t pid);
int have_alive_tasks(const struct task *tasks);

/* new interfaces */
void add_new_task(struct task_block *tb, pid_t pid);
struct traced_task *get(struct task_block *tb, pid_t pid);


#endif