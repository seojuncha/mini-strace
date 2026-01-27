#ifndef SYSCALL_H_
#define SYSCALL_H_

#include "def.h"

int entering(const struct traced_task * t);
int exiting(const struct traced_task * t);

void done_entering(struct traced_task * t, int * seq);
void done_exiting(struct traced_task * t, int * seq, long opts);

void decode_event(struct traced_task * t, int event);
int decode_syscall_enter(struct traced_task * t, long opts);
int decode_syscall_exit(struct traced_task * t, long opts);

void reenter_syscall(const struct traced_task * t);

void set_trace_options(struct traced_task * t, long opts);

#endif