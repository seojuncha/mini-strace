#include <sys/types.h>

int tracer_loop(pid_t tracee_pid);
void read_exe_path(pid_t pid, char *buf, size_t size);