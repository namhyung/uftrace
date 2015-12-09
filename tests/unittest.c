#include <stdio.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <sys/auxv.h>
#include <sys/wait.h>
#include <gelf.h>
#include <libelf.h>

#include "unittest.h"
#include "../utils/utils.h"


/* example test case */
TEST_CASE(unittest_framework)
{
	static const char hello[] = "Hello";

	TEST_EQ(1 + 1, 2);
	TEST_NE(true, false);
	TEST_GT(1 * 2, 0 * 2);
	TEST_GE(1.0, 1);
	TEST_LT(0 * 2, 1);
	TEST_LE(0.0, 0);

	TEST_STREQ("Hello", hello);
	TEST_MEMEQ("Hello", hello, sizeof(hello));

	return TEST_OK;
}

static const char *retcodes[] = {
	TERM_COLOR_GREEN  "PASS" TERM_COLOR_RESET,
	TERM_COLOR_RED    "FAIL" TERM_COLOR_RESET,
	TERM_COLOR_YELLOW "SKIP" TERM_COLOR_RESET,
	TERM_COLOR_RED    "SIG " TERM_COLOR_RESET,
	TERM_COLOR_RED    "BAD " TERM_COLOR_RESET,
};

static const char *messages[] = {
	"ran successfully",
	"failed",
	"skipped",
	"signal caught",
	"unknown result",
};

static void run_unit_test(struct ftrace_unit_test *test, int *test_stats)
{
	static int count;
	int status;
	int ret = TEST_BAD;

	if (debug) {
		printf("Testing %s...\n", test->name);
		fflush(stdout);
	}

	if (!fork())
		exit(test->func());
	wait(&status);

	if (WIFSIGNALED(status))
		ret = TEST_SIG;
	else if (WIFEXITED(status))
		ret = WEXITSTATUS(status);  /* OK or NG */

	if (ret < 0 || ret >= TEST_MAX)
		ret = TEST_BAD;

	test_stats[ret]++;
	printf("[%03d] %-30s: %s\n", ++count, test->name, retcodes[ret]);
	fflush(stdout);
}

static Elf *setup_unit_test(struct ftrace_unit_test **test_cases, size_t *test_num)
{
	char *exename;
	int fd, len;
	Elf *elf;
	size_t shstr_idx, sec_size;
	Elf_Scn *sec, *test_sec;

	exename = (void *)getauxval(AT_EXECFN);
	fd = open(exename, O_RDONLY);
	if (fd < 0) {
		printf("error during load ELF header: %s: %m\n", exename);
		return NULL;
	}

	elf_version(EV_CURRENT);

	elf = elf_begin(fd, ELF_C_READ_MMAP, NULL);
	if (elf == NULL)
		goto elf_error;

	if (elf_getshdrstrndx(elf, &shstr_idx) < 0)
		goto elf_error;

	sec = test_sec = NULL;
	while ((sec = elf_nextscn(elf, sec)) != NULL) {
		char *shstr;
		GElf_Shdr shdr;

		if (gelf_getshdr(sec, &shdr) == NULL)
			goto elf_error;

		shstr = elf_strptr(elf, shstr_idx, shdr.sh_name);

		if (strcmp(shstr, "ftrace.unit_test") == 0) {
			test_sec = sec;
			sec_size = shdr.sh_size;
			break;
		}
	}

	if (test_sec == NULL)
		goto out;

	*test_cases = elf_getdata(test_sec, NULL)->d_buf;
	*test_num   = sec_size / sizeof(**test_cases);

	return elf;

elf_error:
	printf("ELF error during symbol loading: %s\n",
	       elf_errmsg(elf_errno()));
out:
	elf_end(elf);
	close(fd);

	return NULL;
}

static void finish_unit_test(Elf *elf, int *test_stats)
{
	int i;

	printf("\nunit test stats\n====================\n");

	for (i = 0; i < TEST_MAX; i++)
		printf("%3d %s\n", test_stats[i], messages[i]);

	elf_end(elf);
	printf("\n");
}

int __attribute__((weak)) arch_fill_cpuinfo_model(int fd)
{
	return 0;
}

#undef main
int main(int argc, char *argv[])
{
	struct ftrace_unit_test *test_cases;
	int test_stats[TEST_MAX] = { };
	size_t i, test_num;
	Elf *elf;

	elf = setup_unit_test(&test_cases, &test_num);
	if (elf == NULL) {
		printf("Cannot run unit tests - failed to load test cases\n");
		return -1;
	}

	printf("Running %d test cases\n======================\n", test_num);

	if (argc > 1 && !strcmp(argv[1], "-d"))
		debug = 1;
	outfp = logfp = stdout;

	for (i = 0; i < test_num; i++)
		run_unit_test(&test_cases[i], test_stats);

	finish_unit_test(elf, test_stats);
	return 0;
}
