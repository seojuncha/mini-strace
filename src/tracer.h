#ifndef TRACER_H_
#define TRACER_H_

#include <sys/types.h>

#include "def.h"

int tracer_loop(pid_t tracee_pid);
void read_exe_path(pid_t pid, char *buf, size_t size);

int init_tracee(struct task_block *tb, pid_t tracee_pid);
int dispatch_loop(struct task_block *tb);

#endif