#include <sys/wait.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <stdio.h>
#include <string.h>
#include <signal.h>
 
#include "syscalls_x64.h"
 
static void read_data(pid_t pid, char *str, const struct user_regs_struct *reg) {
  int i = 0, j = 0;
  unsigned long long addr = 0;
  long peekdata = 0;
 
  for (i = 0; i < 8; i++) {
    addr = reg->rsi + (i<<3);
    peekdata = ptrace(PTRACE_PEEKDATA, pid, addr, NULL);
    for (j = 0; j < 8; j++) {
      str[j + (i<<3)] = ((peekdata >> (j * 8)) & 0xff);
    }
  }
}
 
static void print_syscall(pid_t pid, const struct user_regs_struct *reg) {
  int i = 0;
  char str[64];
  unsigned long long retval = reg->rax;
  unsigned long long sysnum = reg->orig_rax;
  const char *sysname = x64_syscall_name(sysnum);
 
  memset(&str, 0, sizeof(str));
 
  switch(sysnum) {
    case 0:
    case 1:
      read_data(pid, str, reg);
 
      printf("%s[%lld] (fd=%lld, buf=0x%llx [\"", sysname, sysnum, reg->rdi, reg->rsi);
      for (i = 0; i < 60; i++) {
        if (str[i] == '\n') {
          printf("\\n");
        } else {
          printf("%c", str[i]);
        }
      }
      printf("\"], count=%lld) -> 0x%llx\n", reg->rdx, retval);
      break;
    default:
      printf("%s[%lld] -> 0x%llx\n",sysname, sysnum, retval);
      break;
  }
}
 
static int is_not_unknown(const char *sysname) {
  return strncmp("unknown", sysname, 7);
}
 
int tracer_loop() {
  int status, sig;
  struct user_regs_struct reg;
  int in_syscall = 0;
  unsigned long long sysnum;
  const char *sysname;
  pid_t pid;
 
  memset(&reg, 0, sizeof(struct user_regs_struct));
 
  do {
    pid = waitpid(0, &status, 0);
    if (pid == -1) {
      perror("waitpid error");
      return -1;
    }
 
    if (WIFSTOPPED(status)) {
      sig = WSTOPSIG(status);
      if (sig == (SIGTRAP | 0x80)) {
        if (!in_syscall) {
          in_syscall = 1;
          /*ptrace(PTRACE_GETREGS, pid, 0, &reg);*/
        } else {
          ptrace(PTRACE_GETREGS, pid, 0, &reg);
          sysnum = reg.orig_rax;
          sysname = x64_syscall_name(sysnum);
          if (is_not_unknown(sysname)) {
            print_syscall(pid, &reg);
          }
          in_syscall = 0;
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
  return 0;
}

