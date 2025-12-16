#!/bin/bash
gcc sample/fork-test.c -o fork-test.out
gcc src/syscalls_x64.c src/tracer.c src/main.c && ./a.out fork-test.out
