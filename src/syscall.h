#ifndef SYSCALL_H_
#define SYSCALL_H_

#include "def.h"

int entering(const struct traced_task *t);
int exiting(const struct traced_task *t);

void done_entering(struct traced_task *t);
void done_exiting(struct traced_task *t);

int decode_syscall_enter(struct traced_task *t);
int decode_syscall_exit(struct traced_task *t);

void print_syscall(const struct traced_task *t);

void reenter(const struct traced_task *t);

#endif