const char *x64_syscall_name(unsigned long long nr) {
  switch(nr) {
    case 0: return "read";
    case 1: return "write";
    case 2: return "open";
    case 3: return "close";
    case 4: return "stat";
    case 5: return "fstat";
    case 8: return "lseek";
    case 9: return "mmap";
    case 10: return "mprotect";
    case 11: return "munmap";
    case 12: return "brk";
    case 17: return "pread64";
    case 18: return "pwrite64";
    case 21: return "access";
    case 59: return "execve";
    case 60: return "exit";
    case 231: return "exit_group";
    case 257: return "openat";
    case 262: return "newfstatat";
    default: return "unknown";
  }
}
