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
#include <wait.h>
#include <sys/time.h>
#include <dirent.h>
#include <stdint.h>
#include <dlfcn.h>

#define PR_FMT		"attach"
#define PR_DOMAIN	DBG_DYNAMIC
#include "utils/inject.h"
#include "utils/utils.h"
#include "utils/inject.h"
#include "utils/ptrace.h"
#include "mcount-arch.h"

#define SO_LIBC_NAME 		"libc.so.6"
#define LIBC_DLOPEN_NAME	"__libc_dlopen_mode"

#define MAX_SO_PATH_LENGTH	128
#define MAX_PID_LENGTH		 16
// define max line that read from /proc/<pid>/map
#define MAX_READ_MAP 4096

#define WORD_SIZE	sizeof(long)
#define WORD_ALIGN(x)	ALIGN(x, WORD_SIZE)

// import from inject-content.S
extern char inject_so_path[MAX_SO_PATH_LENGTH];
extern long long inject_so_loader_ret;
extern long long inject_dlopen_addr;
extern void inject_contents_start(void);
extern void inject_contents_end(void);

pid_t *get_tids(pid_t pid)
{
	DIR *d;
	struct dirent *dir;
	char path[64];
	char strpid[MAX_PID_LENGTH];
	unsigned int thread_count = 0;
	pid_t *tids = NULL;

	snprintf(strpid, sizeof(strpid), "%d", pid);
	snprintf(path, sizeof(path), "/proc/%d/task/", pid);
	d = opendir(path);

	if (d) {
		while ((dir = readdir(d)) != NULL) {
			if (!strncmp(dir->d_name, ".", 1)) {
				continue;
			} else if (!strncmp(dir->d_name, "..", 2)) {
				continue;
			} else if (!strncmp(dir->d_name, strpid,
				   strlen(strpid))) {
				continue;
			}
			thread_count++;
		}
		// Add 1 to identify the last element.
		tids = xcalloc(sizeof(pid_t), thread_count + 1);
		thread_count= 0;

		while ((dir = readdir(d)) != NULL) {
			if (!strncmp(dir->d_name, ".", 1)) {
				continue;
			} else if (!strncmp(dir->d_name, "..", 2)) {
				continue;
			} else if (!strncmp(dir->d_name, strpid,
				   strlen(strpid))) {
				continue;
			}
			tids[thread_count++] = atoi(dir->d_name);
		}
		closedir(d);
	}

	return tids;
}

/*
 * While injecting a shared object, attaching to all the child threads
 * to puts them into a suspended state.
 */
void suspend_child_threads(pid_t pid, uintptr_t injected_addr, pid_t *tids)
{
	pid_t tid;
	long index;

	for (index=0; tids[index] != 0x0; index++) {
		tid = tids[index];
		ptrace_attach(tid);
	}
}

void release_child_threads(pid_t pid, uintptr_t injected_addr, pid_t *tids)
{
	pid_t tid;
	long index;

	for (index=0; tids[index] != 0x0; index++) {
		tid = tids[index];
		ptrace_detach(tid);
	}
}

long get_inject_code_addr(pid_t pid)
{
	FILE *fp;
	char filename[30];
	char line[MAX_READ_MAP];
	long start, end, result = 0;
	char str[20];
	char perms[5];
	char *fmt = "/proc/%d/maps";

	snprintf(filename, sizeof(filename), fmt, pid);
	fp = fopen(filename, "r");
	if (fp == NULL)
		pr_err("cannot open /proc/%d/maps", pid);

	while (fgets(line, sizeof(line), fp) != NULL) {
		sscanf(line, "%lx-%lx %s %*s %s %*d", &start, &end, perms, str);
		if (strstr(perms, "x") != NULL) {
			result = end;
			break;
		}
	}

	fclose(fp);
	return result;
}

long get_so_addr(pid_t pid, char *so_name)
{
	FILE *fp;
	char filename[30];
	char line[PATH_MAX];
	long addr, result=0;

	snprintf(filename, sizeof(filename), "/proc/%d/maps", pid);
	fp = fopen(filename, "r");
	if (fp == NULL)
		pr_err("cannot open /proc/%d/maps", pid);

	while (fgets(line, PATH_MAX, fp) != NULL) {
		sscanf(line, "%lx-%*x %*s %*s %*s %*d", &addr);
		if (strstr(line, so_name) != NULL) {
			result = addr;
			break;
		}
	}

	fclose(fp);
	return result;
}

long get_libc_addr(pid_t pid)
{
	return get_so_addr(pid, "libc-");
}

long get_function_addr(char *so_name, char *func_name)
{
	void *so_addr = dlopen(so_name, RTLD_LAZY);
	void *func_addr = dlsym(so_addr, func_name);

	return (long)func_addr;
}

#if defined (__x86_64__)
int inject(char *libname, pid_t target)
{
	int so_path_length, mypid;
	long my_libc_addr;
	long target_lib_addr, dlopen_addr, dlopen_offset, addr;
	long target_dlopen_addr;
	char *so_path;
	// array of child thread ids.
	pid_t *tids;
	ARCH_REGS regs;

	/*
	 * figure out the size of contents to be injected.
	 * so, we know how big of a buffer to allocate.
	 */
	uintptr_t inject_end = (uintptr_t)&inject_contents_end;
	uintptr_t inject_begin = (uintptr_t)&inject_contents_start;
	uint32_t inject_size = inject_end - inject_begin + 1;
	pr_dbg2("[%llx - %llx] size of code to inject %d\n",
		inject_begin, inject_end, inject_size);

	/*
	 * Ptrace reads the word size at once. so, make sure that
	 * the space to inject is large enough to be read from ptrace.
	 */
	inject_size = WORD_ALIGN(inject_size);
	so_path = realpath(libname, NULL);

	if (!so_path)
		pr_err("could not found shared object from %s", libname);

	so_path_length = strlen(so_path) + 1;
	if (so_path_length > MAX_SO_PATH_LENGTH)
		pr_err("The path to the shared object must be a maximum of 127 characters.");

	memset(inject_so_path, 0x0, sizeof(inject_so_path));
	memcpy(inject_so_path, so_path, so_path_length);
	pr_dbg2("Library Path : %s\n", inject_so_path);

	mypid = getpid();
	my_libc_addr = get_libc_addr(mypid);
	dlopen_addr = get_function_addr(SO_LIBC_NAME, LIBC_DLOPEN_NAME);
	dlopen_offset = dlopen_addr - my_libc_addr;
	target_lib_addr = get_libc_addr(target);
	target_dlopen_addr = target_lib_addr + dlopen_offset;
	inject_dlopen_addr = target_dlopen_addr;

	ptrace_attach(target);
	ptrace_getregs(target, &regs);

	/*
	 * since ELF align each section size by paging size, many section
	 * have padding at its tail. code be load shared object is
	 * injected to here.
	 */
	addr = get_inject_code_addr(target) - inject_size;
	inject_so_loader_ret = get_pc(regs);

	/*
	 * now that we have an address to copy code to, set the target's
	 * rip to it. we have to advance by 2 bytes here because rip gets
	 * incremented by the size of the current instruction, and the
	 * instruction at the start of the function to inject always
	 * happens to be 2 bytes long.
	 */
	set_pc(&regs, addr + 2);
	ptrace_setregs(target, &regs);

	/*
	 * copy inject_so_loader inner assemly code to the target address
	 * inside the target process' address space.
	 */
	ptrace_write(target, addr, (void *)inject_begin, inject_size);

	/*
	 * ptrace continue will make child thread get wake-up.
	 * this can be harmful during injection.
	 * therefore, make all child threads enter the loop
	 * until injecting done.
	 */
	tids = get_tids(target);
	if (tids != NULL)
		suspend_child_threads(target, addr, tids);

	/*
	 * now that the new code is in place, let the target run
	 * our injected code.
	 */
	ptrace_detach(target);
	if (tids != NULL)
		release_child_threads(target, addr, tids);

	return 0;
}
#else
int inject(char *libname, pid_t target)
{
	pr_err("Not supported architecture.");
}
#endif


#ifdef UNIT_TEST
char inject_so_path[MAX_SO_PATH_LENGTH];
long long inject_so_loader_ret;
long long inject_dlopen_addr;
void inject_contents_start(void) {};
void inject_contents_end(void) {};
#endif
