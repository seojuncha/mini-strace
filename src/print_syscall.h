#ifndef PRINT_SYSCALL_H_
#define PRINT_SYSCALL_H_

#include "def.h"

void print_syscall(const struct traced_task *t, int seq, long opts, int in_syscall);

#endif