#include <sys/user.h>
#include <stdio.h>
#include <stdlib.h>

#include "def.h"

int alive_tasks(const struct task_block * tb)
{
	int count = 0;

	for (int i = 0; i < MAX_TASKS; i++) {
		const struct traced_task * t = &tb->tt[i];
		if (t->tid != 0 && t->status & TASK_ACTIVATED)
			count++;
	}
	// fprintf(stderr, "task count = %d\n", count);
	return count;
}

struct traced_task *get(struct task_block * tb, pid_t tid)
{
	for (int i = 0; i < MAX_TASKS; i++) {
		struct traced_task *t = &(tb->tt[i]);
		if (t->tid == tid)
			return t;
	}
	printf("%d not found task\n", tid);
	return NULL;
}

void add_new_task(struct task_block * tb, pid_t pid, pid_t tid)
{
	for (int i = 0; i < MAX_TASKS; i++) {
		struct traced_task *t = &(tb->tt[i]);
		if (t->pid == 0) {
			t->pid = pid;
			t->tid = tid;
			t->status |= START_TRACE | TASK_ACTIVATED;
			t->user_regs = malloc(sizeof(struct user_regs_struct));
			memset(t->user_regs, 0, sizeof(struct user_regs_struct));
			// printf("%d added to %d\n", tid, pid);
			break;
		}
	}
}

void remove_task(struct task_block * tb, pid_t tid)
{
	for (int i = 0; i < MAX_TASKS; i++) {
		struct traced_task *t = &(tb->tt[i]);
		if (t->tid == tid) {
			if (t->user_regs)
				free(t->user_regs);
			if (t->mem_buf)
				free(t->mem_buf);
			memset(t, 0, sizeof(struct traced_task));
			// printf("%d removed\n", tid);
			break;
		}
	}
}