#include <sys/wait.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <stdio.h>
#include <string.h>
#include <signal.h>
 
#include "syscalls_x64.h"
 
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
  struct user_regs_struct reg;
  unsigned long long sysnum;
  const char *sysname;
  pid_t pid;
 
  memset(&reg, 0x0, sizeof(struct user_regs_struct));
 
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
        ptrace(PTRACE_GETREGS, pid, 0, &reg);
 
        sysnum = reg.orig_rax;
        sysname = x64_syscall_name(sysnum);
        if (strncmp("unknown", sysname, 7)) {
          printf("syscall[%lld] %s\n", sysnum, sysname);
          syscall_count += 1;
        }
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
