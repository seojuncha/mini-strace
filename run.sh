#!/bin/bash
gcc sample/fork-test.c -o fork-test.out
gcc sample/fork-exec-test.c -o fork-exec-test.out
gcc sample/clone-test.c -o clone-test.out
gcc sample/pthread-test.c -o pthread-test.out
gcc src/syscalls_x64.c src/def.c src/tracer.c src/main.c && ./a.out ./fork-exec-test.out ./fork-exec-test.out /usr/bin/echo "hello world" 1>/dev/null
# gcc src/syscalls_x64.c src/tracer.c src/main.c && ./a.out ./fork-exec-test.out /usr/bin/echo "hello world" 1>/dev/null
# gcc src/syscalls_x64.c src/tracer.c src/main.c && ./a.out clone-test.out 1>/dev/null
# gcc src/syscalls_x64.c src/tracer.c src/main.c && ./a.out pthread-test.out 1>/dev/null
