#define _POSIX_SOURCE
#include <unistd.h>     /* fork() */
#include <sys/ptrace.h> /* ptrace() */
#include <sys/types.h>
#include <signal.h>
#include <stdio.h>
 
#include "tracer.h"
 
int main(int argc, char *argv[]) {
	pid_t pid;
  pid = fork();
  
  if (pid < 0) {
    /* Error */
    fprintf(stderr, "Fork failed\n");
    return 1;
  } else if (pid == 0) {
    /* Child process */
    if (ptrace(PTRACE_TRACEME, 0, 0, 0)) {
      perror("ptrace error");
      return 1;
    }
 
    /* Allow the parent to observe signal-delevery-stop */
    raise(SIGSTOP);
    execve(argv[1], &argv[1], NULL);
    perror("execve");
  } else {
    if (tracer_loop() < 0) {
      fprintf(stderr, "abnormal exited tracer loop\n");
      return 1;
    }
    printf("[pid:%d] Parent process\n", pid);
  }
	return 0;
}
