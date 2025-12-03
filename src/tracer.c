#include <sys/wait.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <stdio.h>
#include <string.h>
#include <signal.h>
 
#include "syscalls_x64.h"
#include "error.h"
 
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
 
/*
Example:
 openat(AT_FDCWD, "/root/ccos_lib/glibc-hwcaps/x86-64-v3/libc.so.6", O_RDONLY|O_CLOEXEC)
static void read_openat(pid_t pid, const struct user_regs_struct *reg) {
}
*/
 
static void print_syscall(pid_t pid, const struct user_regs_struct *reg) {
  int i = 0;
  char str[128];
  unsigned long long retval = reg->rax;
  unsigned long long sysnum = reg->orig_rax;
  const char *sysname = x64_syscall_name(sysnum);
 
  memset(&str, 0, sizeof(str));
 
  switch(sysnum) {
    case 0:  /* read */
    case 1:  /* write */
      read_data(pid, str, reg);
 
      printf("%s[%lld] (fd=%lld, buf=0x%llx [\"", sysname, sysnum, reg->rdi, reg->rsi);
      for (i = 0; i < 60; i++) {
        if (str[i] == '\n') {
          printf("\\n");
        } else {
          printf("%c", str[i]);
        }
      }
      printf("\"], count=%lld) -> %lld\n", reg->rdx, retval);
      break;
    case 257: /* openat */ {
      unsigned long long dirfd = reg->rdi;
      unsigned long long pathname = reg->rsi;
      /*
      unsigned long long flags = reg->rdx;
      unsigned long long  mode = reg->r10;
      */
      read_data(pid, str, reg);
 
      /* is negative */
      if (retval >> 32) {
        printf("%s[%lld] (dirfd=0x%llx, pathname=0x%llx [\"%s\"]) -> %s(%lld) %s\n",
            sysname, sysnum,
            dirfd, pathname, str,
            err_tbl[~retval].str, (long long)retval+1, strerror(err_tbl[~retval].code));
      } else {
        printf("%s[%lld] (dirfd=0x%llx, pathname=0x%llx [\"%s\"]) -> %lld\n",
            sysname, sysnum, 
            dirfd, pathname, str,
            retval);
      }
    }
    break;
    default:
      printf("%s[%lld] -> %lld\n",sysname, sysnum, (long long)retval);
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
