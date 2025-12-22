#define _GNU_SOURCE
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/types.h>
#include <stdio.h>
#include <string.h>
#include <signal.h>
 
#include "syscalls_x64.h"
#include "error.h"

#define MAX_TASKS 5

struct exec_param {
  char path[128];
  int ret;
};

struct task {
  pid_t pid;
  int in_syscall;
  int alive;
  int is_leaf;   /* is not a root tracee */
};

struct task *find_task(struct task *tasks, pid_t pid) {
  int i; 
  for (i = 0; i < MAX_TASKS; i++) {
    struct task *t = &tasks[i];
    if (t->pid == pid)
      return t;
  }
  return NULL;
}

void add_traced_task(struct task *tasks, pid_t pid, int is_leaf) {
  int i; 
  for (i = 0; i < MAX_TASKS; i++) {
    struct task *t = &tasks[i];
    if (t->pid == 0) {
      t->pid = pid;
      t->in_syscall = 0;
      t->alive = 1;
      t->is_leaf = is_leaf;
      break;
    }
  }
  fprintf(stderr, "[mini-strace] [%d] add new traced task: %d\n", i, pid);
}

int have_alive_tasks(const struct task *tasks) {
  int count = 0;
  int i;

  for (i = 0; i < MAX_TASKS; i++) {
    count += tasks[i].alive;
  }

  return count;
}

void read_exe_path(pid_t pid, char *buf, size_t size) {
  char path[64];
  ssize_t n = 0;

  sprintf(path, "/proc/%d/exe", pid);
  n = readlink(path, buf, size - 1);

  if (n >= 0) {
    buf[n] = '\n';
  } else {
    sprintf(buf,"??");
  }
}
 
static void read_data(pid_t pid, char *str, unsigned long long reg_addr) {
  int i = 0, j = 0;
  unsigned long long addr = 0;
  long peekdata = 0;
 
  for (i = 0; i < 8; i++) {
    addr = reg_addr + (i<<3);
    peekdata = ptrace(PTRACE_PEEKDATA, pid, addr, NULL);
    for (j = 0; j < 8; j++) {
      str[j + (i<<3)] = ((peekdata >> (j * 8)) & 0xff);
    }
  }
}

static void print_waitpid(pid_t pid, int status) {
  printf("[DEBUG] [%d] ", pid);
 
  if (WIFEXITED(status))
      printf("WEXITSTATUS %d\n", WEXITSTATUS(status));
  else if (WIFSIGNALED(status))
      printf("WTERMSIG %d\n", WTERMSIG(status));
  else if (WIFSTOPPED(status))
      printf("WSTOPSIG %d\n", WSTOPSIG(status));
  else if (WIFCONTINUED(status))
      printf("continued\n");
  else 
      printf("unkown status, %d\n", status);
}

static void print_syscall(const struct task *t, const struct user_regs_struct *reg) {
  int i = 0;
  char str[128];
  unsigned long long retval = reg->rax;
  unsigned long long sysnum = reg->orig_rax;
  const char *sysname = x64_syscall_name(sysnum);
 
  memset(&str, 0, sizeof(str));

  if (t->is_leaf) {
    printf("[pid %d] ", t->pid);
  }
 
  switch(sysnum) {
    case 0:  /* read */
    case 1:  /* write */
      read_data(t->pid, str, reg->rsi);
      printf("%s[%lld] (fd=%lld, buf=0x%llx [\"", sysname, sysnum, reg->rdi, reg->rsi);
      for (i = 0; i < 60; i++) {
        if (str[i] == '\n') {
          printf("\\n");
        } else {
          printf("%c", str[i]);
        }
      }
      printf("\"], count=%lld) = %lld\n", reg->rdx, retval);
      break;
    // case 9:  /* mmap */
    // case 12: /* brk */
    //   printf("%s[%lld] = 0x%llx\n",sysname, sysnum, retval);
    //   break;
    case 3:
    case 56:
    case 59:
    case 231:
      printf("%s[%lld] = %lld\n", sysname, sysnum, retval);
      break;
    case 257: /* openat */ {
      unsigned long long dirfd = reg->rdi;
      unsigned long long pathname = reg->rsi;
      /*
      unsigned long long flags = reg->rdx;
      unsigned long long  mode = reg->r10;
      */
      read_data(t->pid, str, reg->rsi);
 
      /* is negative */
      if (retval >> 32) {
        printf("%s[%lld] (dirfd=0x%llx, pathname=0x%llx [\"%s\"]) = %s(%lld) %s\n",
            sysname, sysnum,
            dirfd, pathname, str,
            err_tbl[~retval].str, (long long)retval+1, strerror(err_tbl[~retval].code));
      } else {
        printf("%s[%lld] (dirfd=0x%llx, pathname=0x%llx [\"%s\"]) = %lld\n",
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
 
int tracer_loop(pid_t tracee_pid) {
  int status;
  struct user_regs_struct reg;
  pid_t pid;
  unsigned long long sysnum;
  const char *sysname;

  long trace_opts = PTRACE_O_TRACESYSGOOD | PTRACE_O_TRACEEXEC | PTRACE_O_TRACEFORK;
  struct exec_param ep;

  struct task tasks[MAX_TASKS];
  struct task *cur_task = NULL;
  size_t task_count;
 
  memset(&reg, 0, sizeof(struct user_regs_struct));
  memset(tasks, 0, sizeof(struct task) * MAX_TASKS);

  pid = waitpid(tracee_pid, &status, 0);
  if (pid == -1) {
    perror("waitpid");
    return -1;
  }

  // print_waitpid(pid, status);

  /* add the first child of tracer, tracee */
  if (WIFSTOPPED(status) && (WSTOPSIG(status) == SIGSTOP)) {
    ptrace(PTRACE_SETOPTIONS, pid, 0L, trace_opts);
    ptrace(PTRACE_SYSCALL, pid, 0L, 0L);
    add_traced_task(tasks, pid, 0);
  }

  while (have_alive_tasks(tasks)) {
    /* wait all processes */
    pid = waitpid(-1, &status, 0);
    if (pid == -1) {
      perror("waitpid");
      return -1;
    }

    // print_waitpid(pid, status);

    cur_task = find_task(tasks, pid);
    if (!cur_task) {
      fprintf(stderr, "[mini-strace] couldn't find a task: %d\n", pid);
      continue;
    }

    /* terminated */
    if (WIFEXITED(status) || WIFSIGNALED(status)) {
      cur_task->alive = 0;
      fprintf(stderr, "[mini-strace] %d has terminated\n", cur_task->pid);
      continue;
    }

    if (WIFSTOPPED(status)) {
      if (WSTOPSIG(status) == SIGSTOP) {
        fprintf(stderr, "[mini-strace] set options\n");
        ptrace(PTRACE_SETOPTIONS, pid, 0L, trace_opts);
        ptrace(PTRACE_SYSCALL, pid, 0L, 0L);
      } else if (WSTOPSIG(status) == (SIGTRAP | 0x80)) {
        ptrace(PTRACE_GETREGS, pid, 0, &reg);
        sysnum = reg.orig_rax;
        sysname = x64_syscall_name(sysnum);

        // printf("[%lld] %s, in_syscall=%d\n",sysnum, sysname, cur_task->in_syscall);

        if (!(cur_task->in_syscall)) {
          cur_task->in_syscall = 1;
          if (sysnum == SYS_execve) {
            char str[128];
            memset(str, 0, 128);
            read_data(pid, str, reg.rdi);
            memcpy(ep.path, str, 128); 
          }
        } else {
          if (is_not_unknown(sysname)) {
            if (sysnum == SYS_execve) {
              ep.ret = reg.rax;
              if (cur_task->is_leaf) {
                printf("[pid %d] ", cur_task->pid);
              }
              printf("%s[%lld] (path=\"%s\" ) = %d\n", sysname, sysnum, ep.path, ep.ret);
            }
            print_syscall(cur_task, &reg);

            /* temp */
            if (sysnum == 56) {
              add_traced_task(tasks, reg.rax, 1);
            }
          }
          cur_task->in_syscall = 0;
        }
        ptrace(PTRACE_SYSCALL, pid, 0L, 0L);
      } else {
        fprintf(stderr, "unknown stop signal\n");
        ptrace(PTRACE_SYSCALL, pid, 0L, 0L);
      }
    } else {
      if ((status >> 8) == (SIGTRAP | (PTRACE_EVENT_EXEC << 8))) {
        char exepath[256] = {0};
        read_exe_path(pid, exepath, sizeof(exepath));
        printf("==== after EXECVE pid: %d [\"%s\"]", pid, exepath);
        // add_traced_task(tasks, pid, 0);
        ptrace(PTRACE_SYSCALL, pid, 0L, 0L);
        continue;
      } else if ((status >> 8) == (SIGTRAP | (PTRACE_EVENT_FORK << 8))) {
        printf("=== after FORK pid: %d\n", pid);
        /*
        add_traced_task(tasks, pid);
        ptrace(PTRACE_SYSCALL, pid, 0L, 0L);
        */
        continue;
      } else {
        // fprintf(stderr, "unknown ptrace_event_*\n");
      }
    }
  }

  return 0;
}
