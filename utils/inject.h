long get_inject_code_addr(pid_t pid);
long get_so_addr(pid_t pid, char *so_name);
long get_libc_addr(pid_t pid);
long get_function_addr(char *so_name, char *func_name);
int inject(char *libname, pid_t pid);
