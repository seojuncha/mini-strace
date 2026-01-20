#include <sys/user.h>
#include <stdio.h>
#include <stdlib.h>

#include "def.h"

#if 0
struct task *find_task(struct task *tasks, pid_t pid) {
  int i; 
  for (i = 0; i < MAX_TASKS; i++) {
    struct task *t = &tasks[i];
    if (t->pid == pid)
      return t;
  }
  return NULL;
}



void add_traced_task(struct task *tasks, pid_t pid, int is_leaf) {
  int i; 
  for (i = 0; i < MAX_TASKS; i++) {
    struct task *t = &tasks[i];
    if (t->pid == 0) {
      t->pid = pid;
      t->in_syscall = 0;
      t->alive = 1;
      t->is_leaf = is_leaf;
      break;
    }
  }
  printf("[  debug] [%d] add new traced task: %d\n", i, pid);
}



void remove_traced_task(struct task *tasks, pid_t pid) {
  int i;
  for (i = 0; i < MAX_TASKS; i++) {
    struct task *t = &tasks[i];
    if (t->pid == pid) {
      memset(t, 0, sizeof(struct task));
      break;
    }
  }
  printf("[  debug] [%d] remove traced task: %d\n", i, pid);
}

int have_alive_tasks(const struct task *tasks) {
  int count = 0;
  int i;
  for (i = 0; i < MAX_TASKS; i++) {
    count += tasks[i].alive;
  }
  return count;
}

#else

int alive_tasks(const struct task_block *tb) {
  int count = 0;
  for (int i = 0; i < MAX_TASKS; i++) {
    if (tb->tt[i].status & TASK_ACTIVATED)
      count++;
  }
  return count;
}

struct traced_task *get(struct task_block *tb, pid_t pid) {
  for (int i = 0; i < MAX_TASKS; i++) {
    struct traced_task *t = &(tb->tt[i]);
    if (t->pid == pid) {
      return t;
    }
  }
  printf("%d not found task\n", pid);
  return NULL;
}

void add_new_task(struct task_block *tb, pid_t pid) {
  for (int i = 0; i < MAX_TASKS; i++) {
    struct traced_task *t = &(tb->tt[i]);
    if (t->pid == 0) {
      t->pid = pid;
      t->tid = pid;
      t->status |= TASK_ACTIVATED | TASK_SYSCALL_ENTER;
      t->user_regs = malloc(sizeof(struct user_regs_struct));
      memset(t->user_regs, 0, sizeof(struct user_regs_struct));
      break;
    }
  }
}

void remove_task(struct task_block *tb, pid_t pid) {
  for (int i = 0; i < MAX_TASKS; i++) {
    struct traced_task *t = &(tb->tt[i]);
    if (t->pid == pid) {
      free(t->user_regs);
      memset(t, 0, sizeof(struct traced_task));
      printf("%d removed\n", pid);
      break;
    }
  }
}

#endif