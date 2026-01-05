#define _POSIX_SOURCE
#include <unistd.h>     /* fork() */
#include <sys/ptrace.h> /* ptrace() */
#include <sys/types.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>

#include "tracer.h"

int main(int argc, char *argv[]) {
  char exepath[256];
  pid_t pid;
  pid = fork();

  memset(exepath, 0, sizeof(exepath));
  
  if (pid < 0) {
    /* Error */
    fprintf(stderr, "Fork failed\n");
    return 1;
  } else if (pid == 0) {
    /* Child process */
    pid_t child = getpid();
    if (ptrace(PTRACE_TRACEME, 0, 0, 0)) {
      perror("ptrace error");
      return 1;
    }

    // read_exe_path(child, exepath, sizeof(exepath));
    // printf("==== before exec[pid:%d]: %s", child, exepath);
 
    /* Allow the parent to observe signal-delivery-stop */
    raise(SIGSTOP);
    execve(argv[1], &argv[1], NULL);
    perror("execve");
  } else {
    if (tracer_loop(pid) < 0) {
      fprintf(stderr, "abnormal exited tracer loop\n");
      return 1;
    }
    printf("[info] [pid:%d] Tracer is terminated.\n", getpid());
  }
	return 0;
}
