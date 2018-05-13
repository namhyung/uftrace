#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <wait.h>
#include <time.h>

#define PR_FMT		"attach"
#define PR_DOMAIN	DBG_DYNAMIC
#include "utils/ptrace.h"
#include "utils/utils.h"

void ptrace_attach(pid_t target)
{
	int status;

	if (ptrace(PTRACE_ATTACH, target, NULL, NULL) == -1)
		pr_err("ptrace(PTRACE_ATTACH) failed");

	if (waitpid(target, &status, WUNTRACED) != target)
		pr_err("waitpid(%d) failed", target);
}

void ptrace_detach(pid_t target)
{
	if (ptrace(PTRACE_DETACH, target, NULL, NULL) == -1)
		pr_err("ptrace(PTRACE_DETACH) failed");
}

void ptrace_getregs(pid_t target, ARCH_REGS *regs)
{
	if (ptrace(PTRACE_GETREGS, target, NULL, regs) == -1)
		pr_err("ptrace(PTRACE_GETREGS) failed");
}

void ptrace_setregs(pid_t target, ARCH_REGS *regs)
{
	if (ptrace(PTRACE_SETREGS, target, NULL, regs) == -1)
		pr_err("ptrace(PTRACE_SETREGS) failed");
}

void ptrace_write(int pid, unsigned long addr, void *vptr, int len)
{
	int count = 0;
	long word = 0;

	while (count < len) {
		memcpy(&word, vptr + count, sizeof(word));
		word = ptrace(PTRACE_POKETEXT, pid, addr + count, word);
		if (word == -1)
			pr_err("ptrace(PTRACE_POKETEXT) failed");
		count += sizeof(word);
	}
}
