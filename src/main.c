#define _POSIX_SOURCE
#include <sys/ptrace.h>
#include <sys/types.h>
#include <unistd.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>

#include "def.h"
#include "tracer.h"

int main(int argc, char *argv[]) {
  pid_t tracee_pid = fork();
 
  if (tracee_pid < 0) {
    fprintf(stderr, "Fork failed\n");
    return 1;
  } 

  /* Tracee process */
  if (tracee_pid == 0) {
    if (ptrace(PTRACE_TRACEME, 0, 0, 0)) {
      perror("ptrace error");
      return 1;
    }
 
    /* Allow the parent to observe signal-delivery-stop */
    raise(SIGSTOP);
    execve(argv[1], &argv[1], NULL);
    perror("execve");
  } else {
    struct task_block tb = {0};
    if (init_tracee(&tb, tracee_pid) != 0) {
      fprintf(stderr, "init_tracee error\n");
      return 1;
    }
    return dispatch_loop(&tb);
  } 
}
