#ifndef UFTRACE_TRACEFS_H
#define UFTRACE_TRACEFS_H

#include <stdbool.h>
#include <stddef.h>
#include <unistd.h>

char *get_tracing_file(const char *name);

void put_tracing_file(char *file);

int open_tracing_file(const char *name, int flags);

ssize_t read_tracing_file(const char *name, char *buf, size_t len);

int write_tracing_file(const char *name, const char *val);

int __write_tracing_file(int fd, const char *name, const char *val, bool append,
			 bool correct_sys_prefix);

int append_tracing_file(const char *name, const char *val);

int set_tracing_pid(int pid);

int set_tracing_clock(char *clock_str);

#endif /* UFTRACE_TRACEFS_H */
