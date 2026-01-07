#define _GNU_SOURCE
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/types.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <signal.h>
#include <time.h>
 
#include "syscalls_x64.h"
#include "error.h"

#define MAX_TASKS 5

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
  fprintf(stderr, "[  debug] [%d] add new traced task: %d\n", i, pid);
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

static inline void now_ns(void) {
  time_t sec;
  long usec;
  struct tm local;
  struct timespec ts;

  clock_gettime(CLOCK_REALTIME, &ts);

  sec = ts.tv_sec;
  localtime_r(&sec, &local);

  usec = ts.tv_nsec / 1000;

  fprintf(stderr, "[syscall] [%02d:%02d:%02d.%06ld] ",
    local.tm_hour,
    local.tm_min,
    local.tm_sec,
    usec);
}
 
static void read_data(pid_t pid, char *str, unsigned long long reg_addr) {
  int i, j;
  unsigned long long addr;
  long peekdata;

 for (i = 0; i < 8; i++) {
    addr = reg_addr + (i<<3);
    peekdata = ptrace(PTRACE_PEEKDATA, pid, addr, NULL);
    for (j = 0; j < 8; j++) {
      str[j + (i<<3)] = ((peekdata >> (j * 8)) & 0xff);
    }
  }
}

static void print_waitpid(pid_t pid, int status) {
  printf("[  debug] [%d] ", pid);
 
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

  /* print timestamp */
  now_ns();

  /* print PID/TID */
  fprintf(stderr, "%d/%d ", t->pid, t->pid);

  fprintf(stderr, "[%3lld] ", sysnum);

  switch(sysnum) {
    case 0:  /* read */
    case 1:  /* write */
      read_data(t->pid, str, reg->rsi);
      fprintf(stderr, "%s (fd=%lld, buf=0x%llx [\"", sysname, reg->rdi, reg->rsi);
      for (i = 0; i < (reg->rdx > 60 ? 60 : reg->rdx); i++) {
        if (str[i] == '\n') {
          fprintf(stderr, "\\n");
        } else {
          fprintf(stderr, "%c", str[i]);
        }
      }
      fprintf(stderr, "\"], count=%lld) = %lld\n", reg->rdx, retval);
      break;
    // case 9:  /* mmap */
    // case 12: /* brk */
    //   printf("%s[%lld] = 0x%llx\n",sysname, sysnum, retval);
    //   break;
    case 3:
      fprintf(stderr, "%s () = %lld\n", sysname, (long long)retval);
      break;
    case 56:
      fprintf(stderr, "%s () = %lld\n", sysname, (long long)retval);
      break;
    case 59:
      fprintf(stderr, "%s (path=%s) = %d\n", sysname, t->exec_path, t->exec_ret);
      break;
    case 231:
      fprintf(stderr, "%s () = %lld\n", sysname, retval);
      break;
    case 257: /* openat */ {
      unsigned long long dirfd = reg->rdi;
      unsigned long long pathname = reg->rsi;

      read_data(t->pid, str, reg->rsi);
 
      /* is negative */
      if (retval >> 32) {
        fprintf(stderr, "%s (dirfd=0x%llx, pathname=0x%llx [\"%s\"]) = %s(%lld) %s\n",
            sysname,
            dirfd, pathname, str,
            err_tbl[~retval].str, (long long)retval+1, strerror(err_tbl[~retval].code));
      } else {
        fprintf(stderr, "%s (dirfd=0x%llx, pathname=0x%llx [\"%s\"]) = %lld\n",
            sysname,
            dirfd, pathname, str,
            retval);
      }
      break;
    }

    default:
      fprintf(stderr, "%s () = %lld\n", sysname, (long long)retval);
      break;
  }
}

static void handle_event(struct task *tasks, pid_t pid, int ws) {
  struct task *t;
  unsigned long new_pid = 0;

  switch (ws) {
    case (SIGTRAP | (PTRACE_EVENT_EXEC << 8)):
      fprintf(stderr, "[  debug] event_exec\n");
      t = find_task(tasks, pid);
      if (t) {
        read_exe_path(pid, t->exec_path, sizeof(t->exec_path));
        // printf("==== after EXECVE pid: %d [\"%s\"]", pid, t->exec_path);
      }
      break;

    case (SIGTRAP | (PTRACE_EVENT_FORK << 8)):
      fprintf(stderr, "[  debug] event_fork\n");
      ptrace(PTRACE_GETEVENTMSG, pid, 0L, &new_pid);
      add_traced_task(tasks, new_pid, 1);
      break;

    case (SIGTRAP | (PTRACE_EVENT_CLONE << 8)):
      fprintf(stderr, "[  debug] event_clone\n");
      ptrace(PTRACE_GETEVENTMSG, pid, 0L, &new_pid);
      add_traced_task(tasks, new_pid, 1);
      break;

    default:
      fprintf(stderr, "[err] unknown ptrace_event_*\n");
      break;
  }
}

static void handle_syscall(struct task *cur_task, pid_t pid) {
  struct user_regs_struct reg;
  unsigned long long nr;
  const char *sysname;

  ptrace(PTRACE_GETREGS, pid, 0, &reg);

  nr = reg.orig_rax;
  sysname = x64_syscall_name(nr);

  if (!(cur_task->in_syscall)) {
    cur_task->in_syscall = 1;
    if (nr == SYS_execve) {
      read_data(pid, cur_task->exec_path, reg.rdi);
    }
  } else {
    if (is_not_unknown(sysname)) {
      if (nr == SYS_execve) {
        cur_task->exec_ret = reg.rax;
      }
      print_syscall(cur_task, &reg);
    }
    cur_task->in_syscall = 0;
  }
}
 
int tracer_loop(pid_t tracee_pid) {
  int status;
  pid_t pid;
  long trace_opts = PTRACE_O_TRACESYSGOOD | PTRACE_O_TRACEEXEC | PTRACE_O_TRACEFORK | PTRACE_O_TRACECLONE;

  struct user_regs_struct reg;

  struct task tasks[MAX_TASKS];
  struct task *cur_task = NULL;
 
  memset(&reg, 0, sizeof(struct user_regs_struct));
  memset(tasks, 0, sizeof(struct task) * MAX_TASKS);

  pid = waitpid(tracee_pid, &status, 0);
  if (pid == -1) {
    perror("waitpid");
    return -1;
  }

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

    cur_task = find_task(tasks, pid);
    if (!cur_task) {
      fprintf(stderr, "[    err] couldn't find a task: %d\n", pid);
      continue;
    }

    /* tracee has terminated */
    if (WIFEXITED(status) || WIFSIGNALED(status)) {
      cur_task->alive = 0;
      fprintf(stderr, "[   info] %d has terminated\n", cur_task->pid);
      continue;
    }

    /* tracee has stopped */
    if (WIFSTOPPED(status)) {
      switch (WSTOPSIG(status)) {
        /* signal delivery stopped */
        case (SIGSTOP):
          ptrace(PTRACE_SETOPTIONS, pid, 0L, trace_opts);
          break;

        /* PTRACE_EVENT_* stopped */
        case (SIGTRAP):
          handle_event(tasks, pid, (status >> 8));
          break;

        /* syscall stopped */
        case (SIGTRAP | 0x80):
          handle_syscall(cur_task, pid);
          break;

        case (SIGCHLD):
          fprintf(stderr, "[   info] %d's child has exited\n", cur_task->pid);
          break;

        default:
          fprintf(stderr, "[    err] unknown stop signal: %d\n", WSTOPSIG(status));
          break;
      }
      ptrace(PTRACE_SYSCALL, pid, 0L, 0L);
    }
  }

  return 0;
}
