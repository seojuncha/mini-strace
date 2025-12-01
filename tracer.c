#include <sys/wait.h>
#include <sys/ptrace.h>
#include <stdio.h>
#include <signal.h>
 
/*#define DEBUG*/
 
#if defined(DEBUG)
static void check_signal(int status) {
  if (WIFEXITED(status)) printf("1\n");
  if (WEXITSTATUS(status)) printf("2\n");
  if (WIFSIGNALED(status)) printf("3\n");
  if (WTERMSIG(status)) printf("4\n");
  if (WIFSTOPPED(status)) printf("5\n");
  if (WSTOPSIG(status)) printf("6\n");
}
#endif
 
int tracer_loop() {
  int status, sig;
  int syscall_count = 0;
  pid_t pid;
 
  do {
    pid = waitpid(0, &status, 0);
    if (pid == -1) {
      perror("waitpid error");
      return -1;
    }
 
#if defined(DEBUG)
    check_signal(status);
#endif
    if (WIFSTOPPED(status)) {
      sig = WSTOPSIG(status);
      if (sig == (SIGTRAP | 0x80)) {
        syscall_count += 1;
      } else if (sig == SIGSTOP) {
        /* signal-delevery-stop state */
        printf("sigstop\n");
        ptrace(PTRACE_SETOPTIONS, pid, 0L, PTRACE_O_TRACESYSGOOD);
      } else {
        fprintf(stderr, "unknown signal: %d\n", sig);
      }
      ptrace(PTRACE_SYSCALL, pid, 0L, 0L);
    }
  } while (!WIFEXITED(status) && !WIFSIGNALED(status));
  printf("totally: %d\n", syscall_count);
  return syscall_count;
}
