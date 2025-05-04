#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <sys/ptrace.h>
#include <sys/types.h>   // pid_t
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>

struct syscall_entry {
  int num;
  const char *name;
  int argc;
};

static const struct syscall_entry syscall_table[] = {
  {0, "restart_syscall", 0},
  {1, "exit", 0},
  {2, "fork", 0},
  {3, "read", 0},
  {4, "write", 3},
  {5, "open", 0},
  {6, "close", 0},
  {8, "create", 0},
  {9, "link", 0},
  {10, "unlink", 0},
  {11, "execve", 3},
  {12, "chdir", 0},
  {14, "mknod", 0},
  {15, "chmod", 0},
  {16, "lchown", 0},
  {19, "lseek", 0},
  {20, "getpid", 0},
  {21, "mount", 0},
  {23, "setuid", 0},
  {24, "getuid", 0},
  {26, "ptrace", 0},
  {29, "pause", 0},

  {45, "brk", 1},
  {125, "mprotect", 3},
  {191, "ugetrlimit", 2},
  {248, "exit_group", 1},
  {256, "set_tid_address", 1},
  {338, "set_robust_list", 2},
  {332, "readlinkat", 4},
  {384, "getrandom", 3},
  {398, "rseq", 4},

  {983045, "set_tls", 1}   // 0x0f0000 + 5
  // and so on...
};

const struct syscall_entry *get_syscall_entry(int num) {
  unsigned int sz = sizeof(syscall_table) / sizeof(struct syscall_entry);
  for (int i = 0; i < sz; i++) {
    if (num == syscall_table[i].num) {
      return &syscall_table[i];
    }
  }
}

int main(int argc, char *argv[]) {
  int ret;
  int status;
  bool in_syscall = false;
  pid_t pid;

  if (argc < 2) {
    fprintf(stderr, "not enought arguments\n");
    exit(1);
  }

  // temp, no arguments in tracee.
  if (argv[2] == NULL) printf("its okay\n");

  pid = fork();
  if (pid < 0) {
    perror("fork error");
    exit(1);
  }

  if (pid == 0) {
    pid = getpid();
    if (ptrace(PTRACE_TRACEME, 0L, 0L, 0L) < 0) {
      perror("ptrace_trackme");
      exit(1);
    }
    /* Important:
      - While being traced, the tracee will stop each time a signal is delivered, even if the signal is being ignored */
    kill(pid, SIGSTOP);
    execv(argv[1], &argv[1]);
    // If the process reached here, there is an error.
    perror("execv");
    exit(1);
  } else {
    /* When delivering system call traps, set bit 7 in the signal number (i.e., deliver SIGTRAP|0x80).  */
    do {
      ret = waitpid(pid, &status, __WALL);
      if (ret < 0) {
        perror("waitpid");
        exit(1);
      }
      /* Syscall-enter-stop and syscall-exit-stop are observed by the
       tracer as waitpid(2) returning with WIFSTOPPED(status) true, and
       WSTOPSIG(status) giving SIGTRAP.  If the PTRACE_O_TRACESYSGOOD
       option was set by the tracer, then WSTOPSIG(status) will give the
       value (SIGTRAP | 0x80).

       Syscall-stops can be distinguished from signal-delivery-stop with 
       SIGTRAP by querying PTRACE_GETSIGINFO for the following cases: */
      if (WIFSTOPPED(status)) {
        // printf("stopped: %d\n", WSTOPSIG(status));
        switch (WSTOPSIG(status)) {
          case SIGSTOP:
            if (ptrace(PTRACE_SETOPTIONS, pid, 0L, PTRACE_O_TRACESYSGOOD) < 0) {
              perror("setoption");
              exit(1);
            }
            break;
          case SIGTRAP | 0x80:
            struct user_regs regs;
            if (ptrace(PTRACE_GETREGS, pid, 0L, &regs) < 0) {
              perror("ptrace_getregs");
              exit(1);
            }
            unsigned long sys_num = regs.uregs[7];
            const struct syscall_entry *entry = get_syscall_entry(sys_num);
            const char *sys_name = entry->name;
            if (!in_syscall) {
              if (sys_name) {
                printf("[%d] %s(", sys_num, sys_name);
                for (int i = 0; i < entry->argc; i++) {
                  printf("r%d=%ld  ",i, regs.uregs[i]);
                }

                // only for test PEEK_DATA now
                if (sys_num == 11) {
                  struct user user_data;
                  ptrace(PTRACE_PEEKDATA, pid, regs.uregs[0], 0L);
                }
                printf(")\n");
              } else {
                printf("unkonwn syscall: %ld\n", sys_num);
              }
              in_syscall = true;
            } else {
              unsigned long sys_ret = regs.uregs[0];
              // printf("  ret: %ld\n", sys_ret);
              in_syscall = false;
            }
            break;
          default:
            printf("unknown stop signal: %d\n", WSTOPSIG(status));
            break;
        }
        // Restart a stopped tracee.
        if (ptrace(PTRACE_SYSCALL, pid, 0L, 0L) < 0) {
          perror("ptrace_syscall");
          break;
        }
      }
    } while (!WIFEXITED(status) && !WIFSIGNALED(status));
  }
  return 0;
}