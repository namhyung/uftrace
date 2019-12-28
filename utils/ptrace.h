#include <sys/ptrace.h>
#include <wait.h>
#include <time.h>
#include "mcount-arch.h"

void ptrace_attach(pid_t target);
void ptrace_detach(pid_t target);

void ptrace_getregs(pid_t target, ARCH_REGS *regs);
void ptrace_setregs(pid_t target, ARCH_REGS *regs);
void ptrace_write(int pid, unsigned long addr, void *vptr, int len);
