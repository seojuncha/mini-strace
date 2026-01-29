#ifndef SYSCALL_MAP_
#define SYSCALL_MAP_

#ifdef __cplusplus
extern "C" {
#endif

const char *syscall_name(unsigned long nr);

#ifdef __cplusplus
}
#endif

#endif