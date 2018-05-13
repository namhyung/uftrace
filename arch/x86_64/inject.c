/*
 * Linux module for injecting shared object to the process by using ptrace.
 *
 * copied from: https://github.com/gaffe23/linux-inject
 * Released under the GPL v2+.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/user.h>
#include <wait.h>
#include <sys/time.h>
#include "utils/inject-utils.h"
#include "utils/ptrace.h"
#include "utils/utils.h"

/*
 * inject_shared_lib()
 *
 * This is the code that will actually be injected into the target process.
 * This code is responsible for loading the shared library into the target
 * process' address space.  First, it calls malloc() to allocate a buffer to
 * hold the filename of the library to be loaded. Then, it calls
 * __libc_dlopen_mode(), libc's implementation of dlopen(), to load the desired
 * shared library. Finally, it calls free() to free the buffer containing the
 * library name. Each time it needs to give control back to the injector
 * process, it breaks back in by executing an "int $3" instruction. See the
 * comments below for more details on how this works.
 *
 */

void inject_shared_lib(long mallocaddr, long freeaddr, long dlopenaddr)
{
	// here are the assumptions I'm making about what data will be located
	// where at the time the target executes this code:
	//
	//   rdi = address of malloc() in target process
	//   rsi = address of free() in target process
	//   rdx = address of __libc_dlopen_mode() in target process
	//   rcx = size of the path to the shared library we want to load

	// save addresses of free() and __libc_dlopen_mode() on the stack for later use
	asm(
		// rsi is going to contain the address of free(). it's going to get wiped
		// out by the call to malloc(), so save it on the stack for later
		"push %rsi \n"
		// same thing for rdx, which will contain the address of _dl_open()
		"push %rdx"
	);

	// call malloc() from within the target process
	asm(
		// save previous value of r9, because we're going to use it to call malloc()
		"push %r9 \n"
		// now move the address of malloc() into r9
		"mov %rdi,%r9 \n"
		// choose the amount of memory to allocate with malloc() based on the size
		// of the path to the shared library passed via rcx
		"mov %rcx,%rdi \n"
		// now call r9; malloc()
		"callq *%r9 \n"
		// after returning from malloc(), pop the previous value of r9 off the stack
		"pop %r9 \n"
		// break in so that we can see what malloc() returned
		"int $3"
	);

	// call __libc_dlopen_mode() to load the shared library
	asm(
		// get the address of __libc_dlopen_mode() off of the stack so we can call it
		"pop %rdx \n"
		// as before, save the previous value of r9 on the stack
		"push %r9 \n"
		// copy the address of __libc_dlopen_mode() into r9
		"mov %rdx,%r9 \n"
		// 1st argument to __libc_dlopen_mode(): filename = the address of the buffer returned by malloc()
		"mov %rax,%rdi \n"
		// 2nd argument to __libc_dlopen_mode(): flag = RTLD_LAZY
		"movabs $1,%rsi \n"
		// call __libc_dlopen_mode()
		"callq *%r9 \n"
		// restore old r9 value
		"pop %r9 \n"
		// break in so that we can see what __libc_dlopen_mode() returned
		"int $3"
	);

	// call free() to free the buffer we allocated earlier.
	//
	// Note: I found that if you put a nonzero value in r9, free() seems to
	// interpret that as an address to be freed, even though it's only
	// supposed to take one argument. As a result, I had to call it using a
	// register that's not used as part of the x64 calling convention. I
	// chose rbx.
	asm(
		// at this point, rax should still contain our malloc()d buffer from earlier.
		// we're going to free it, so move rax into rdi to make it the first argument to free().
		"mov %rax,%rdi \n"
		// pop rsi so that we can get the address to free(), which we pushed onto the stack a while ago.
		"pop %rsi \n"
		// save previous rbx value
		"push %rbx \n"
		// load the address of free() into rbx
		"mov %rsi,%rbx \n"
		// zero out rsi, because free() might think that it contains something that should be freed
		"xor %rsi,%rsi \n"
		// break in so that we can check out the arguments right before making the call
		"int $3 \n"
		// call free()
		"callq *%rbx \n"
		// restore previous rbx value
		"pop %rbx"
	);

	// we already overwrote the RET instruction at the end of this function
	// with an INT 3, so at this point the injector will regain control of
	// the target's execution.
}

/*
 * inject_shared_lib_end()
 *
 * This function's only purpose is to be contiguous to inject_shared_lib(),
 * so that we can use its address to more precisely figure out how long
 * inject_shared_lib() is.
 *
 */

void inject_shared_lib_end()
{
}

int inject(char* libname, pid_t pid)
{
	char* lib_path = realpath(libname, NULL);
	pid_t target = 0;

	if(!lib_path) {
		pr_err_ns("can't find file \"%s\"\n", libname);
	}
	target = pid;

	int lib_path_length = strlen(lib_path) + 1;

	int mypid = getpid();
	long mylibcaddr = getlibcaddr(mypid);

	// find the addresses of the syscalls that we'd like to use inside the
	// target, as loaded inside THIS process (i.e. NOT the target process)
	long malloc_addr = get_function_addr("malloc");
	long free_addr = get_function_addr("free");
	long dlopen_addr = get_function_addr("__libc_dlopen_mode");

	// use the base address of libc to calculate offsets for the syscalls
	// we want to use
	long malloc_offset = malloc_addr - mylibcaddr;
	long free_offset = free_addr - mylibcaddr;
	long dlopen_offset = dlopen_addr - mylibcaddr;


	// get the target process' libc address and use it to find the
	// addresses of the syscalls we want to use inside the target process
	long target_libc_addr = getlibcaddr(target);
	long target_malloc_addr = target_libc_addr + malloc_offset;
	long target_free_addr = target_libc_addr + free_offset;
	long target_dlopen_addr = target_libc_addr + dlopen_offset;

	struct user_regs_struct oldregs, regs;
	memset(&oldregs, 0, sizeof(struct user_regs_struct));
	memset(&regs, 0, sizeof(struct user_regs_struct));

	ptrace_attach(target);

	ptrace_getregs(target, &oldregs);
	memcpy(&regs, &oldregs, sizeof(struct user_regs_struct));

	// find a good address to copy code to
	long addr = freespaceaddr(target) + sizeof(long);

	// now that we have an address to copy code to, set the target's rip to
	// it. we have to advance by 2 bytes here because rip gets incremented
	// by the size of the current instruction, and the instruction at the
	// start of the function to inject always happens to be 2 bytes long.
	regs.rip = addr + 2;

	// pass arguments to my function inject_shared_lib() by loading them
	// into the right registers. note that this will definitely only work
	// on x64, because it relies on the x64 calling convention, in which
	// arguments are passed via registers rdi, rsi, rdx, rcx, r8, and r9.
	// see comments in inject_shared_lib() for more details.
	regs.rdi = target_malloc_addr;
	regs.rsi = target_free_addr;
	regs.rdx = target_dlopen_addr;
	regs.rcx = lib_path_length;
	ptrace_setregs(target, &regs);

	// figure out the size of inject_shared_lib() so we know how big of a buffer to allocate.
	size_t inject_shared_lib_size = (intptr_t)inject_shared_lib_end - (intptr_t)inject_shared_lib;

	// also figure out where the RET instruction at the end of
	// inject_shared_lib() lies so that we can overwrite it with an INT 3
	// in order to break back into the target process. note that on x64,
	// gcc and clang both force function addresses to be word-aligned,
	// which means that functions are padded with NOPs. as a result, even
	// though we've found the length of the function, it is very likely
	// padded with NOPs, so we need to actually search to find the RET.
	intptr_t inject_shared_lib_ret = (intptr_t)find_ret(inject_shared_lib_end) - (intptr_t)inject_shared_lib;

	// back up whatever data used to be at the address we want to modify.
	char* backup = malloc(inject_shared_lib_size * sizeof(char));
	ptrace_read(target, addr, backup, inject_shared_lib_size);

	// set up a buffer to hold the code we're going to inject into the
	// target process.
	char* newcode = malloc(inject_shared_lib_size * sizeof(char));
	memset(newcode, 0, inject_shared_lib_size * sizeof(char));

	// copy the code of inject_shared_lib() to a buffer.
	memcpy(newcode, inject_shared_lib, inject_shared_lib_size - 1);
	// overwrite the RET instruction with an INT 3.
	newcode[inject_shared_lib_ret] = INTEL_INT3_INSTRUCTION;

	// copy inject_shared_lib()'s code to the target address inside the
	// target process' address space.
	ptrace_write(target, addr, newcode, inject_shared_lib_size);

	// now that the new code is in place, let the target run our injected
	// code.
	ptrace_cont(target);


	// at this point, the target should have run malloc(). check its return
	// value to see if it succeeded, and bail out cleanly if it didn't.
	struct user_regs_struct malloc_regs;
	memset(&malloc_regs, 0, sizeof(struct user_regs_struct));
	ptrace_getregs(target, &malloc_regs);
	unsigned long long target_buf = malloc_regs.rax;
	if(target_buf == 0) {
		restore_state_and_detach(target, addr, backup, inject_shared_lib_size, oldregs);
		free(backup);
		free(newcode);
		pr_err_ns("malloc() failed to allocate memory\n");
	}

	// if we get here, then malloc likely succeeded, so now we need to copy
	// the path to the shared library we want to inject into the buffer
	// that the target process just malloc'd. this is needed so that it can
	// be passed as an argument to __libc_dlopen_mode later on.

	// read the current value of rax, which contains malloc's return value,
	// and copy the name of our shared library to that address inside the
	// target process.
	ptrace_write(target, target_buf, lib_path, lib_path_length);

	// continue the target's execution again in order to call
	// __libc_dlopen_mode.
	ptrace_cont(target);

	// check out what the registers look like after calling dlopen.
	struct user_regs_struct dlopen_regs;
	memset(&dlopen_regs, 0, sizeof(struct user_regs_struct));
	ptrace_getregs(target, &dlopen_regs);
	unsigned long long lib_addr = dlopen_regs.rax;

	// if rax is 0 here, then __libc_dlopen_mode failed, and we should bail
	// out cleanly.
	if(lib_addr == 0) {
		restore_state_and_detach(target, addr, backup, inject_shared_lib_size, oldregs);
		free(backup);
		free(newcode);
		pr_err_ns("__libc_dlopen_mode() failed to load %s\n", libname);
	}

	// now check /proc/pid/maps to see whether injection was successful.
	if(checkloaded(target, libname)) {
		pr_dbg("\"%s\" successfully injected\n", libname);
	}
	else {
		pr_err_ns("could not inject \"%s\"\n", libname);
	}

	// as a courtesy, free the buffer that we allocated inside the target
	// process. we don't really care whether this succeeds, so don't
	// bother checking the return value.
	ptrace_cont(target);

	// at this point, if everything went according to plan, we've loaded
	// the shared library inside the target process, so we're done. restore
	// the old state and detach from the target.
	restore_state_and_detach(target, addr, backup, inject_shared_lib_size, oldregs);
	free(backup);
	free(newcode);

	return 0;
}
