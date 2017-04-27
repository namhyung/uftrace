#include <stdio.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <sys/wait.h>
#include <gelf.h>
#include <libelf.h>
#include <link.h>

#include "utils/utils.h"
#include "tests/unittest.h"


static bool color = true;

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

static const char *retcodes_nocolor[] = {
	"PASS",
	"FAIL",
	"SKIP",
	"SIG ",
	"BAD ",
};

static const char *messages[] = {
	"ran successfully",
	"failed",
	"skipped",
	"signal caught",
	"unknown result",
};

static void run_unit_test(struct uftrace_unit_test *test, int *test_stats)
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
	printf("[%03d] %-30s: %s\n", ++count, test->name,
	       color ? retcodes[ret] : retcodes_nocolor[ret]);
	fflush(stdout);
}

static unsigned long load_base;

static int find_load_base(struct dl_phdr_info *info,
			  size_t size, void *arg)
{
	unsigned i;

	if (info->dlpi_name[0] != '\0')
		return 0;

	/* not a PIE binary */
	if (info->dlpi_addr == 0)
		return 1;

	for (i = 0; i < info->dlpi_phnum; i++) {
		const ElfW(Phdr) *phdr = info->dlpi_phdr + i;

		if (phdr->p_type == PT_LOAD) {
			load_base = info->dlpi_addr - phdr->p_vaddr;
			break;
		}
	}
	return 1;
}

static int setup_unit_test(struct uftrace_unit_test **test_cases, size_t *test_num)
{
	char *exename;
	int fd, len;
	Elf *elf;
	size_t shstr_idx, sec_size;
	Elf_Scn *sec, *test_sec;
	Elf_Data *data;
	struct uftrace_unit_test *tcases;
	unsigned i, num;
	int ret = -1;

	exename = read_exename();
	fd = open(exename, O_RDONLY);
	if (fd < 0) {
		printf("error during load ELF header: %s: %m\n", exename);
		return -1;
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

		if (strcmp(shstr, "uftrace.unit_test") == 0) {
			test_sec = sec;
			sec_size = shdr.sh_size;
			break;
		}
	}

	if (test_sec == NULL) {
		printf("cannot find unit test data\n");
		goto out;
	}

	dl_iterate_phdr(find_load_base, NULL);

	data   = elf_getdata(test_sec, NULL);
	tcases = xmalloc(sec_size);
	num    = sec_size / sizeof(*tcases);
	memcpy(tcases, data->d_buf, sec_size);

	/* relocate section symbols in case of PIE */
	for (i = 0; i < num; i++) {
		struct uftrace_unit_test *tc = &tcases[i];
		unsigned long faddr = (unsigned long)tc->func;
		unsigned long naddr = (unsigned long)tc->name;

	       faddr += load_base;
	       naddr += load_base;

	       tc->func = (void *)faddr;
	       tc->name = (void *)naddr;
	}

	*test_cases = tcases;
	*test_num   = num;

	ret = 0;

elf_error:
	if (ret < 0) {
		printf("ELF error during symbol loading: %s\n",
		       elf_errmsg(elf_errno()));
	}
out:
	elf_end(elf);
	close(fd);

	return ret;
}

static void finish_unit_test(struct uftrace_unit_test *test_cases, int *test_stats)
{
	int i;

	printf("\nunit test stats\n====================\n");

	for (i = 0; i < TEST_MAX; i++)
		printf("%3d %s\n", test_stats[i], messages[i]);

	printf("\n");
	free(test_cases);
}

int __attribute__((weak)) arch_fill_cpuinfo_model(int fd)
{
	return 0;
}

void mcount_return(void)
{
}

void plthook_return(void)
{
}

void __xray_entry(void)
{
}

void __xray_exit(void)
{
}

#undef main
int main(int argc, char *argv[])
{
	struct uftrace_unit_test *test_cases;
	int test_stats[TEST_MAX] = { };
	size_t i, test_num;
	int c;

	if (setup_unit_test(&test_cases, &test_num) < 0) {
		printf("Cannot run unit tests - failed to load test cases\n");
		return -1;
	}

	printf("Running %zd test cases\n======================\n", test_num);

	while ((c = getopt(argc, argv, "dvnpiO:f:")) != -1) {
		switch (c) {
		case 'd':
		case 'v':
			debug = 1;
			break;
		case 'n':
			color = false;
			break;
		default:
			break;
		}
	}

	outfp = logfp = stdout;

	for (i = 0; i < test_num; i++)
		run_unit_test(&test_cases[i], test_stats);

	finish_unit_test(test_cases, test_stats);
	return 0;
}
