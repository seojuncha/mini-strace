#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <sys/ptrace.h>
#include <sys/types.h>   // pid_t
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>


int main(int argc, char *argv[]) {
  int ret;
  int status;
  bool in_syscall = false;
  pid_t pid;

  printf("start!\n");

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
    printf("tracee: %d\n", pid);
    if (ptrace(PTRACE_TRACEME, 0L, 0L, 0L) < 0) {
      perror("ptrace_trackme");
      exit(1);
    }
    /*
      Important:
      - While being traced, the tracee will stop each time a signal is delivered, even if the signal is being ignored
    */
    kill(pid, SIGSTOP);
    execv(argv[1], &argv[1]);
    exit(1);
  } else {
    /*
      When delivering system call traps, set bit 7 in the signal number (i.e., deliver SIGTRAP|0x80).
    */
    do {
      
      // if (ptrace(PTRACE_SETOPTIONS, pid, 0L, PTRACE_O_TRACESYSGOOD) < 0) {
      //   perror("error");
      //   exit(1);
      // }

      ret = waitpid(pid, &status, __WALL);
      if (ret < 0) {
        perror("waitpid");
        exit(1);
      }
      // syscall-enter-stop
      // syscall-exit-stop
      // signal-delivery-stop

      /*
       Syscall-enter-stop and syscall-exit-stop are observed by the
       tracer as waitpid(2) returning with WIFSTOPPED(status) true, and
       WSTOPSIG(status) giving SIGTRAP.  If the PTRACE_O_TRACESYSGOOD
       option was set by the tracer, then WSTOPSIG(status) will give the
       value (SIGTRAP | 0x80).

       Syscall-stops can be distinguished from signal-delivery-stop with 
       SIGTRAP by querying PTRACE_GETSIGINFO for the following cases:
       */
      if (WIFSTOPPED(status)) {
        // printf("stopped: %d\n", WSTOPSIG(status));
        switch (WSTOPSIG(status)) {
          case SIGSTOP:
            // printf("sigstop\n");
            if (ptrace(PTRACE_SETOPTIONS, pid, 0L, PTRACE_O_TRACESYSGOOD) < 0) {
              perror("setoption");
              exit(1);
            }
            break;
          case SIGTRAP | 0x80:
            struct user_regs regs;
            if (!in_syscall) {
              printf("Syscall Entry\n");
              if (ptrace(PTRACE_GETREGS, pid, 0L, &regs) != -1) {
                printf("  r0=%ld\n", regs.uregs[0]);
                printf("  r7=%ld\n", regs.uregs[7]);
                // write syscall
                if (regs.uregs[7] == 4) {
                  printf("WRITE with %ld, %ld, %ld\n", regs.uregs[0], regs.uregs[1], regs.uregs[2]);
                  printf("May be dummy?: %ld\n", regs.uregs[3]);
                }
              }
              in_syscall = true;
            } else {
              printf("Syscall Exit\n");
              if (ptrace(PTRACE_GETREGS, pid, 0L, &regs) != -1) {
                printf("  r0=%ld\n", regs.uregs[0]);
                printf("  r7=%ld\n", regs.uregs[7]);
              }
              in_syscall = false;
            }
            break;
          default:
            printf("what: %d\n", WSTOPSIG(status));
            break;
        }
        // Restart
        if (ptrace(PTRACE_SYSCALL, pid, 0L, 0L) < 0) {
          perror("ptrace_syscall");
          break;
        }
      }
    } while (!WIFEXITED(status) && !WIFSIGNALED(status));
  }
  printf("Done\n");
  return 0;
}