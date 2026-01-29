#include <sys/wait.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/types.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <signal.h>
#include <time.h>
#include <errno.h>

#include "syscall.h"
#include "print_syscall.h"

static void handle_event(struct task_block *tb, pid_t pid, int ws)
{
  struct traced_task *t = get(tb, pid);
  unsigned long ret = 0;

  switch (ws) {
    case (SIGTRAP | (PTRACE_EVENT_EXEC << 8)):
      ptrace(PTRACE_GETEVENTMSG, pid, 0L, &ret);
      printf("[  debug] %d event_exec: %lu\n", pid, ret);
      decode_event(t, PTRACE_EVENT_EXEC);
      break;

    case (SIGTRAP | (PTRACE_EVENT_FORK << 8)):
      ptrace(PTRACE_GETEVENTMSG, pid, 0L, &ret);
      printf("[  debug] %d event_fork: %lu\n", pid, ret);
      add_new_task(tb, pid, ret);
      ptrace(PTRACE_SYSCALL, ret, 0L, 0L);
      break;

    case (SIGTRAP | (PTRACE_EVENT_CLONE << 8)):
      ptrace(PTRACE_GETEVENTMSG, pid, 0L, &ret);
      printf("[  debug] %d event_clone: %lu\n", pid, ret);
      add_new_task(tb, pid, ret);
      ptrace(PTRACE_SYSCALL, ret, 0L, 0L);
      break;

    case (SIGTRAP | (PTRACE_EVENT_EXIT << 8)):
      ptrace(PTRACE_GETEVENTMSG, pid, 0L, &ret);
      printf("[  debug] event_exit: %d\n", (int)ret);
      fprintf(stderr, "---- thread %d will be exited (code=%d) ----\n", pid, (int)ret);
      break;

    default:
      printf("[err] unknown ptrace_event_*\n");
      break;
  }
}

static void handle_syscall(struct task_block *tb, pid_t pid)
{
  struct traced_task * t = get(tb, pid);

  if (entering(t)) {
    if (decode_syscall_enter(t, tb->opts) != 0)
      return;
    done_entering(t, &tb->seq);
    print_syscall(t, tb->seq, tb->opts, 0);
  } else if (exiting(t)) {
    if (decode_syscall_exit(t, tb->opts) != 0)
      return;
    done_exiting(t, &tb->seq, tb->opts);
    print_syscall(t, tb->seq, tb->opts, 1);
  } else {
    printf("unkonwn status: %d\n", t->status);
  }
}

int init_tracee(struct task_block *tb, pid_t tracee_pid)
{
  int ws = 0;
  pid_t pid = waitpid(tracee_pid, &ws, 0);

  if (pid == -1) {
    perror("waitpid 1");
    return -1;
  }
  tb->trace_opts = PTRACE_O_TRACESYSGOOD | PTRACE_O_TRACEEXEC | PTRACE_O_TRACEEXIT
                  | PTRACE_O_TRACEFORK | PTRACE_O_TRACECLONE | PTRACE_O_TRACEVFORK;
  /* add the first child of tracer, tracee */
  if (WIFSTOPPED(ws) && (WSTOPSIG(ws) == SIGSTOP)) {
    add_new_task(tb, pid, pid);
    ptrace(PTRACE_SETOPTIONS, pid, 0L, tb->trace_opts);
    ptrace(PTRACE_SYSCALL, pid, 0L, 0L);
  }
  return 0;
}

int dispatch_loop(struct task_block *tb)
{
  int ws;
  struct traced_task *t;

  while (alive_tasks(tb)) {
    pid_t pid = waitpid(-1, &ws, __WALL);

    if (pid == -1 && errno != 0) {
      perror("waidpid 2");
      return -1;
    }

    t = get(tb, pid);
    if (t == NULL) {
      printf("no traced task, terminate the dispatch loop\n");
      return -2;
    }

    /* tracee has terminated */
    if (WIFEXITED(ws) || WIFSIGNALED(ws)) {
      remove_task(tb, pid);
      continue;
    }

    if (WIFSTOPPED(ws)) {
      switch (WSTOPSIG(ws)) {
      /* signal delivery stopped */
      case (SIGSTOP):
        set_trace_options(t, tb->trace_opts);
        break;

      /* PTRACE_EVENT_* stopped */
      case (SIGTRAP):
        handle_event(tb, pid, (ws >> 8));
        break;

      /* syscall stopped */
      case (SIGTRAP | 0x80):
        handle_syscall(tb, pid);
        break;

      case (SIGCHLD):
        printf("[   info] %d's child has exited\n", t->pid);
        break;

      default:
        printf("[    err] unknown stop signal: %d\n", WSTOPSIG(ws));
        break;
      }
      ptrace(PTRACE_SYSCALL, pid, 0L, 0L);
      // reenter_syscall(tb);
    }
  }
  printf("normal terminated\n");
  return 0;
}
