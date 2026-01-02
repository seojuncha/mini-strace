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
  char exec_path[128];
  int exec_ret;
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

void remove_traced_task(struct task *tasks, pid_t pid) {
  int i;
  for (i = 0; i < MAX_TASKS; i++) {
    struct task *t = &tasks[i];
    if (t->pid == pid) {
      memset(t, 0, sizeof(struct task));
    }
  }
}

int have_alive_tasks(const struct task *tasks) {
  int count = 0;
  int i;
  for (i = 0; i < MAX_TASKS; i++) {
    count += tasks[i].alive;
  }
  return count;
}

static int is_not_unknown(const char *sysname) {
  return strncmp("unknown", sysname, 7);
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
      for (i = 0; i < (reg->rdx > 60 ? 60 : reg->rdx); i++) {
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

static void handle_event(struct task *tasks, pid_t pid, int ws) {
  struct task *t;
  char exepath[256] = {0};
  unsigned long new_pid = 0;

  switch (ws) {
    case (SIGTRAP | (PTRACE_EVENT_EXEC << 8)):
      t = find_task(tasks, pid);
      if (t) {
        read_exe_path(pid, t->exec_path, sizeof(t->exec_path));
        printf("==== after EXECVE pid: %d [\"%s\"]", pid, t->exec_path);
      }
      break;
    case (SIGTRAP | (PTRACE_EVENT_FORK << 8)):
    case (SIGTRAP | (PTRACE_EVENT_CLONE << 8)):
      ptrace(PTRACE_GETEVENTMSG, pid, 0L, &new_pid);
      printf("=== after FORK pid: %ld\n", new_pid);
      add_traced_task(tasks, new_pid, 1);
      break;
    default:
      fprintf(stderr, "unknown ptrace_event_*\n");
      break;
  }
}

static void handle_syscall(struct task *cur_task, pid_t pid) {
  struct user_regs_struct reg;
  unsigned long long sysnum;
  const char *sysname;

  ptrace(PTRACE_GETREGS, pid, 0, &reg);
  sysnum = reg.orig_rax;
  sysname = x64_syscall_name(sysnum);

  // printf("[%lld] %s, in_syscall=%d\n",sysnum, sysname, cur_task->in_syscall);

  if (!(cur_task->in_syscall)) {
    cur_task->in_syscall = 1;
    if (sysnum == SYS_execve) {
      read_data(pid, cur_task->exec_path, reg.rdi);
    }
  } else {
    if (is_not_unknown(sysname)) {
      if (sysnum == SYS_execve) {
        cur_task->exec_ret = reg.rax;
        if (cur_task->is_leaf) {
          printf("[pid %d] ", cur_task->pid);
        }
        printf("%s[%lld] (path=\"%s\" ) = %d\n", sysname, sysnum, cur_task->exec_path, cur_task->exec_ret);
      }
      print_syscall(cur_task, &reg);
    }
    cur_task->in_syscall = 0;
  }
}
 
int tracer_loop(pid_t tracee_pid) {
  int status;
  struct user_regs_struct reg;
  pid_t pid;

  long trace_opts = PTRACE_O_TRACESYSGOOD | PTRACE_O_TRACEEXEC | PTRACE_O_TRACEFORK | PTRACE_O_TRACECLONE;
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

    /* stopped */
    if (WIFSTOPPED(status)) {
      switch (WSTOPSIG(status)) {
        case (SIGSTOP):
          ptrace(PTRACE_SETOPTIONS, pid, 0L, trace_opts);
          break;
        case (SIGTRAP):
          handle_event(tasks, pid, (status >> 8));
          break;
        case (SIGTRAP | 0x80):
          handle_syscall(cur_task, pid);
          break;
        default:
          fprintf(stderr, "unknown stop signal: %d\n", WSTOPSIG(status));
          break;
      }
      ptrace(PTRACE_SYSCALL, pid, 0L, 0L);
    }
  }

  return 0;
}
