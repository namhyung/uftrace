#include <stdio.h>
#include <stdlib.h>
#include <dirent.h>
#include <string.h>
#include <unistd.h>
#include <dlfcn.h>

#include "inject-utils.h"
#include "utils.h"

/*
 * freespaceaddr()
 *
 * Search the target process' /proc/pid/maps entry and find an executable
 * region of memory that we can use to run code in.
 *
 * args:
 * - pid_t pid: pid of process to inspect
 *
 * returns:
 * - a long containing the address of an executable region of memory inside the
 *   specified process' address space.
 *
 */

long freespaceaddr(pid_t pid)
{
	FILE *fp;
	char filename[30];
	char line[850];
	long addr;
	char str[20];
	char perms[5];
	sprintf(filename, "/proc/%d/maps", pid);
	fp = fopen(filename, "r");
	if(fp == NULL)
		pr_err("cannot open /proc/%d/maps \n", pid);
	while(fgets(line, 850, fp) != NULL) {
		sscanf(line, "%lx-%*x %s %*s %s %*d", &addr, perms, str);
		if(strstr(perms, "x") != NULL) {
			break;
		}
	}
	fclose(fp);
	return addr;
}

/*
 * getlibcaddr()
 *
 * Gets the base address of libc.so inside a process by reading /proc/pid/maps.
 *
 * args:
 * - pid_t pid: the pid of the process whose libc.so base address we should
 *   find
 *
 * returns:
 * - a long containing the base address of libc.so inside that process
 *
 */

long getlibcaddr(pid_t pid)
{
	FILE *fp;
	char filename[30];
	char line[850];
	long addr;
	sprintf(filename, "/proc/%d/maps", pid);
	fp = fopen(filename, "r");
	if(fp == NULL)
		pr_err("cannot open /proc/%d/maps \n", pid);
	while(fgets(line, 850, fp) != NULL) {
		sscanf(line, "%lx-%*x %*s %*s %*s %*d", &addr);
		if(strstr(line, "libc-") != NULL) {
			break;
		}
	}
	fclose(fp);
	return addr;
}

/*
 * checkloaded()
 *
 * Given a process ID and the name of a shared library, check whether that
 * process has loaded the shared library by reading entries in its
 * /proc/[pid]/maps file.
 *
 * args:
 * - pid_t pid: the pid of the process to check
 * - char* libname: the library to search /proc/[pid]/maps for
 *
 * returns:
 * - an int indicating whether or not the library has been loaded into the
 *   process (1 = yes, 0 = no)
 *
 */

int checkloaded(pid_t pid, char* libname)
{
	FILE *fp;
	char filename[30];
	char line[850];
	long addr;
	sprintf(filename, "/proc/%d/maps", pid);
	fp = fopen(filename, "r");
	if(fp == NULL)
		pr_err("cannot open /proc/%d/maps \n", pid);
	while(fgets(line, 850, fp) != NULL) {
		sscanf(line, "%lx-%*x %*s %*s %*s %*d", &addr);
		if(strstr(line, libname) != NULL) {
			fclose(fp);
			return 1;
		}
	}
	fclose(fp);
	return 0;
}

/*
 * get_function_addr()
 *
 * Find the address of a function within our own loaded copy of libc.so.
 *
 * args:
 * - char* funcName: name of the function whose address we want to find
 *
 * returns:
 * - a long containing the address of that function
 *
 */

long get_function_addr(char* func_name)
{
	void* self = dlopen("libc.so.6", RTLD_LAZY);
	void* func_addr = dlsym(self, func_name);
	return (long)func_addr;
}

/*
 * find_ret()
 *
 * Starting at an address somewhere after the end of a function, search for the
 * "ret" instruction that ends it. We do this by searching for a 0xc3 byte, and
 * assuming that it represents that function's "ret" instruction. This should
 * be a safe assumption. Function addresses are word-aligned, and so there's
 * usually extra space at the end of a function. This space is always padded
 * with "nop"s, so we'll end up just searching through a series of "nop"s
 * before finding our "ret". In other words, it's unlikely that we'll run into
 * a 0xc3 byte that corresponds to anything other than an actual "ret"
 * instruction.
 *
 * Note that this function only applies to x86 and x86_64, and not ARM.
 *
 * args:
 * - void* endAddr: the ending address of the function whose final "ret"
 *   instruction we want to find
 *
 * returns:
 * - an unsigned char* pointing to the address of the final "ret" instruction
 *   of the specified function
 *
 */

unsigned char* find_ret(void* end_addr)
{
	unsigned char* ret_inst_addr = end_addr;
	while(*ret_inst_addr != INTEL_RET_INSTRUCTION) {
		ret_inst_addr--;
	}
	return ret_inst_addr;
}
