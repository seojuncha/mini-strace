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
#include <errno.h>

#include "syscall.h"
#include "print_syscall.h"

/*
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

static void handle_event(struct task_block *tb, pid_t pid, int ws) {
  struct task *t;
  unsigned long ret = 0;

  switch (ws) {
    case (SIGTRAP | (PTRACE_EVENT_EXEC << 8)):
      printf("[  debug] event_exec\n");
      t = get(tb, pid);
      if (t) {
        read_exe_path(pid, t->exec_path, sizeof(t->exec_path));
        // printf("==== after EXECVE pid: %d [\"%s\"]", pid, t->exec_path);
      }
      break;

    case (SIGTRAP | (PTRACE_EVENT_FORK << 8)):
      ptrace(PTRACE_GETEVENTMSG, pid, 0L, &ret);
      printf("[  debug] event_fork: %lu\n", ret);
      add_new_task(tb, ret);
      break;

    case (SIGTRAP | (PTRACE_EVENT_CLONE << 8)):
      ptrace(PTRACE_GETEVENTMSG, pid, 0L, &ret);
      printf("[  debug] event_clone: %lu\n", ret);
      add_new_task(tb, ret);
      break;
    
    case (SIGTRAP | (PTRACE_EVENT_EXIT << 8)):
      ptrace(PTRACE_GETEVENTMSG, pid, 0L, &ret);
      printf("[  debug] event_exit: %lu\n", ret);
      fprintf(stderr, "---- child %d exited (code=%lu) ----\n", pid, ret);
      break;

    default:
      printf("[err] unknown ptrace_event_*\n");
      break;
  }
}
*/

static void handle_syscall(struct task_block * tb, pid_t pid)
{
	struct traced_task * t = get(tb, pid);

	if (entering(t)) {
		if (decode_syscall_enter(t, tb->opts) != 0)
			return;
		done_entering(t);
		print_syscall(t, tb->opts, 0);
	} else if (exiting(t)) {
		if (decode_syscall_exit(t, tb->opts) != 0)
			return;
		done_exiting(t, tb->opts);
		print_syscall(t, tb->opts, 1);
	} else {
		printf("unkonwn status: %d\n", t->status);
	}
}

int init_tracee(struct task_block * tb, pid_t tracee_pid)
{
	int ws = 0;
	pid_t pid = waitpid(tracee_pid, &ws, 0);

	if (pid == -1) {
		perror("waitpid 1");
		return -1;
	}
	tb->trace_opts = PTRACE_O_TRACESYSGOOD | PTRACE_O_TRACEEXEC | PTRACE_O_TRACEFORK | PTRACE_O_TRACECLONE | PTRACE_O_TRACEEXIT | PTRACE_O_TRACEVFORK;
	/* add the first child of tracer, tracee */
	if (WIFSTOPPED(ws) && (WSTOPSIG(ws) == SIGSTOP)) {
		add_new_task(tb, pid);
		ptrace(PTRACE_SETOPTIONS, pid, 0L, tb->trace_opts);
		ptrace(PTRACE_SYSCALL, pid, 0L, 0L);
	}
	return 0;
}

int dispatch_loop(struct task_block * tb)
{
	int ws;
	struct traced_task *t;

	while (alive_tasks(tb)) {
		int pid = waitpid(-1, &ws, __WALL);

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
				// handle_event(t, pid, (ws >> 8));
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
			reenter_syscall(t);
		}
	}
	printf("normal terminated\n");
	return 0;
}
