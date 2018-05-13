#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <wait.h>
#include <time.h>

#include "ptrace.h"
#include "utils.h"

/*
 * ptrace_attach()
 *
 * Use ptrace() to attach to a process. This requires calling waitpid() to
 * determine when the process is ready to be traced.
 *
 * args:
 * - int pid: pid of the process to attach to
 *
 */
void ptrace_attach(pid_t target)
{
	int waitpidstatus;

	if(ptrace(PTRACE_ATTACH, target, NULL, NULL) == -1) {
		pr_err("ptrace(PTRACE_ATTACH) failed\n");
	}

	if(waitpid(target, &waitpidstatus, WUNTRACED) != target) {
		pr_err("waitpid(%d) failed\n", target);
	}
}

/*
 * ptrace_detach()
 *
 * Detach from a process that is being ptrace()d. Unlike ptrace_cont(), this
 * completely ends our relationship with the target process.
 *
 * args:
 * - int pid: pid of the process to detach from. this process must already be
 *   ptrace()d by us in order for this to work.
 *
 */
void ptrace_detach(pid_t target)
{
	if(ptrace(PTRACE_DETACH, target, NULL, NULL) == -1) {
		pr_err("ptrace(PTRACE_DETACH) failed\n");
	}
}

/*
 * ptrace_getregs()
 *
 * Use ptrace() to get a process' current register state.  Uses REG_TYPE
 * preprocessor macro in order to allow for both ARM and x86/x86_64
 * functionality.
 *
 * args:
 * - int pid: pid of the target process
 * - struct REG_TYPE* regs: a struct (either user_regs_struct or user_regs,
 *   depending on architecture) to store the resulting register data in
 *
 */
void ptrace_getregs(pid_t target, struct REG_TYPE* regs)
{
	if(ptrace(PTRACE_GETREGS, target, NULL, regs) == -1) {
		pr_err("ptrace(PTRACE_GETREGS) failed\n");
	}
}

/*
 * ptrace_cont()
 *
 * Continue the execution of a process being traced using ptrace(). Note that
 * this is different from ptrace_detach(): we still retain control of the
 * target process after this call.
 *
 * args:
 * - int pid: pid of the target process
 *
 */
void ptrace_cont(pid_t target)
{
	struct timespec* sleeptime = malloc(sizeof(struct timespec));

	sleeptime->tv_sec = 1;
	sleeptime->tv_nsec = 0000000;

	if(ptrace(PTRACE_CONT, target, NULL, NULL) == -1) {
		pr_err("ptrace(PTRACE_CONT) failed\n");
	}

	nanosleep(sleeptime, NULL);

	// make sure the target process received SIGTRAP after stopping.
	checktargetsig(target);
}

/*
 * ptrace_setregs()
 *
 * Use ptrace() to set the target's register state.
 *
 * args:
 * - int pid: pid of the target process
 * - struct REG_TYPE* regs: a struct (either user_regs_struct or user_regs,
 *   depending on architecture) containing the register state to be set in the
 *   target process
 *
 */
void ptrace_setregs(pid_t target, struct REG_TYPE* regs)
{
	if(ptrace(PTRACE_SETREGS, target, NULL, regs) == -1) {
		pr_err("ptrace(PTRACE_SETREGS) failed\n");
	}
}

/*
 * ptrace_getsiginfo()
 *
 * Use ptrace() to determine what signal was most recently raised by the target
 * process. This is primarily used for to determine whether the target process
 * has segfaulted.
 *
 * args:
 * - int pid: pid of the target process
 *
 * returns:
 * - a siginfo_t containing information about the most recent signal raised by
 *   the target process
 *
 */
siginfo_t ptrace_getsiginfo(pid_t target)
{
	siginfo_t targetsig;
	if(ptrace(PTRACE_GETSIGINFO, target, NULL, &targetsig) == -1)
	{
		pr_err("ptrace(PTRACE_GETSIGINFO) failed\n");
	}
	return targetsig;
}

/*
 * ptrace_read()
 *
 * Use ptrace() to read the contents of a target process' address space.
 *
 * args:
 * - int pid: pid of the target process
 * - unsigned long addr: the address to start reading from
 * - void *vptr: a pointer to a buffer to read data into
 * - int len: the amount of data to read from the target
 *
 */
void ptrace_read(int pid, unsigned long addr, void *vptr, int len)
{
	int bytesRead = 0;
	int i = 0;
	long word = 0;
	long *ptr = (long *) vptr;

	while (bytesRead < len) {
		word = ptrace(PTRACE_PEEKTEXT, pid, addr + bytesRead, NULL);
		if(word == -1) {
			pr_err("ptrace(PTRACE_PEEKTEXT) failed\n");
			exit(1);
		}
		bytesRead += sizeof(word);
		ptr[i++] = word;
	}
}

/*
 * ptrace_write()
 *
 * Use ptrace() to write to the target process' address space.
 *
 * args:
 * - int pid: pid of the target process
 * - unsigned long addr: the address to start writing to
 * - void *vptr: a pointer to a buffer containing the data to be written to the
 *   target's address space
 * - int len: the amount of data to write to the target
 *
 */
void ptrace_write(int pid, unsigned long addr, void *vptr, int len)
{
	int byteCount = 0;
	long word = 0;

	while (byteCount < len) {
		memcpy(&word, vptr + byteCount, sizeof(word));
		word = ptrace(PTRACE_POKETEXT, pid, addr + byteCount, word);
		if(word == -1) {
			pr_err("ptrace(PTRACE_POKETEXT) failed\n");
		}
		byteCount += sizeof(word);
	}
}

/*
 * checktargetsig()
 *
 * Check what signal was most recently returned by the target process being
 * ptrace()d. We expect a SIGTRAP from the target process, so raise an error
 * and exit if we do not receive that signal. The most likely non-SIGTRAP
 * signal for us to receive would be SIGSEGV.
 *
 * args:
 * - int pid: pid of the target process
 *
 */
void checktargetsig(int pid)
{
	// check the signal that the child stopped with.
	siginfo_t targetsig = ptrace_getsiginfo(pid);

	// if it wasn't SIGTRAP, then something bad happened (most likely a
	// segfault).
	if(targetsig.si_signo != SIGTRAP) {
		pr_dbg("instead of expected SIGTRAP, target stopped with signal %d: %s\n", targetsig.si_signo, strsignal(targetsig.si_signo));
		pr_dbg("sending process %d a SIGSTOP signal for debugging purposes\n", pid);
		ptrace(PTRACE_CONT, pid, NULL, SIGSTOP);
		pr_err("EXIT");
	}
}

/*
 * restore_state_and_detach()
 *
 * Once we're done debugging a target process, restore the process' backed-up
 * data and register state and let it go on its merry way.
 *
 * args:
 * - pid_t target: pid of the target process
 * - unsigned long addr: address within the target's address space to write
 *   backed-up data to
 * - void* backup: a buffer pointing to the backed-up data
 * - int datasize: the amount of backed-up data to write
 * - struct REG_TYPE oldregs: backed-up register state to restore
 *
 */
void restore_state_and_detach(pid_t target, unsigned long addr, void* backup, int datasize, struct REG_TYPE oldregs)
{
	ptrace_write(target, addr, backup, datasize);
	ptrace_setregs(target, &oldregs);
	ptrace_detach(target);
}
