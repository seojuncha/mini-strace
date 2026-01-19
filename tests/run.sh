#!/bin/bash

echo "Compile tests..."

gcc -Wall t01_write_ok.c -o t01_write_ok
gcc -Wall t02_open_fail.c -o t02_open_fail
gcc -Wall t03_access_fail.c -o t03_access_fail
gcc -Wall t04_fork_basic.c -o t04_fork_basic
gcc -Wall t05_exec_child.c -o t05_exec_child
gcc -Wall t06_thread_clone.c -o t06_thread_clone

echo "Run strace"
test -d strace_log || mkdir strace_log

strace -o strace_log/t01.log -e trace=execve,openat,write,exit_group ./t01_write_ok 1>/dev/null
strace -o strace_log/t02.log -e trace=execve,openat,write,exit_group ./t02_open_fail 1>/dev/null
strace -o strace_log/t03.log -e trace=execve,openat,write,exit_group ./t03_access_fail 1>/dev/null
strace -f -o strace_log/t04.log -e trace=execve,openat,write,fork,clone,exit_group ./t04_fork_basic 1>/dev/null
strace -o strace_log/t05.log -e trace=execve,openat,fork,clone,write,exit_group ./t05_exec_child 1>/dev/null
strace -f -o strace_log/t06.log -e trace=execve,openat,fork,clone,clone3,write,exit_group ./t06_thread_clone 1>/dev/null

echo "Complete stracing!"