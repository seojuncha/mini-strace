#!/bin/bash

#gcc src/syscalls_x64.c src/def.c src/tracer.c src/main.c && ./a.out ./fork-exec-test.out ./fork-exec-test.out /usr/bin/echo "hello world" 1>/dev/null
# gcc src/syscalls_x64.c src/tracer.c src/main.c && ./a.out ./fork-exec-test.out /usr/bin/echo "hello world" 1>/dev/null
# gcc src/syscalls_x64.c src/tracer.c src/main.c && ./a.out clone-test.out 1>/dev/null
# gcc src/syscalls_x64.c src/tracer.c src/main.c && ./a.out pthread-test.out 1>/dev/null

cd tests
./run.sh

cd ..

gcc -Wall -std=gnu11 src/def.c src/syscall.c src/tracer.c src/main.c -o mini-strace
./mini-strace /workspace/src/linux/mini-strace/tests/t01_write_ok