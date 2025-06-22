#include <fcntl.h>
#include <link.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <unistd.h>

#include "tests/unittest.h"
#include "utils/symbol.h"
#include "utils/utils.h"

static bool color = true;

/* example test case */
TEST_CASE(unittest_framework)
{
	static const char hello[] = "Hello";

	pr_dbg("check basic test macro\n");
	TEST_EQ(1 + 1, 2);
	TEST_NE(true, false);
	TEST_GT(1 * 2, 0 * 2);
	TEST_GE(1.0, 1);
	TEST_LT(0 * 2, 1);
	TEST_LE(0.0, 0);

	pr_dbg("check string test macro\n");
	TEST_STREQ("Hello", hello);
	TEST_MEMEQ("Hello", hello, sizeof(hello));

	return TEST_OK;
}

static const char *retcodes[] = {
	TERM_COLOR_GREEN "PASS" TERM_COLOR_RESET,  TERM_COLOR_RED "FAIL" TERM_COLOR_RESET,
	TERM_COLOR_YELLOW "SKIP" TERM_COLOR_RESET, TERM_COLOR_RED "SIG " TERM_COLOR_RESET,
	TERM_COLOR_RED "BAD " TERM_COLOR_RESET,
};

static const char *retcodes_nocolor[] = {
	"PASS", "FAIL", "SKIP", "SIG ", "BAD ",
};

static const char *messages[] = {
	"ran successfully", "failed", "skipped", "signal caught", "unknown result",
};

static void set_debug_domain(struct uftrace_unit_test *test)
{
#define DOMAIN(x)                                                                                  \
	{                                                                                          \
#x, DBG_##x                                                                        \
	}

	struct {
		char *name;
		int domain;
	} domains[] = {
		DOMAIN(SYMBOL),
		DOMAIN(DEMANGLE),
		DOMAIN(FILTER),
		DOMAIN(FSTACK),
		DOMAIN(SESSION),
		DOMAIN(KERNEL),
		DOMAIN(MCOUNT),
		DOMAIN(DYNAMIC),
		DOMAIN(EVENT),
		DOMAIN(SCRIPT),
		DOMAIN(DWARF),
		/* some fixup domains */
		{ "task", DBG_SESSION },
		{ "argspec", DBG_FILTER },
		{ "trigger", DBG_FILTER },
		{ "python", DBG_UFTRACE },
	};
	unsigned int i;
	int count = 0;

	for (i = 0; i < ARRAY_SIZE(domains); i++) {
		if (strcasestr(test->name, domains[i].name)) {
			dbg_domain[domains[i].domain] = debug;
			count++;
		}
	}

	if (count == 0)
		dbg_domain[DBG_UFTRACE] = debug;
}

static void run_unit_test(struct uftrace_unit_test *test, int *test_stats, char *filter)
{
	static int count;
	int status;
	int ret = TEST_BAD;

	if (filter && !strstr(test->name, filter))
		return;

	if (debug) {
		printf("Testing %s...\n", test->name);
		fflush(stdout);
	}

	if (!fork()) {
		set_debug_domain(test);
		exit(test->func());
	}
	wait(&status);

	if (WIFSIGNALED(status))
		ret = TEST_SIG;
	else if (WIFEXITED(status))
		ret = WEXITSTATUS(status); /* OK or NG */

	if (ret < 0 || ret >= TEST_MAX)
		ret = TEST_BAD;

	test_stats[ret]++;
	printf("[%03d] %-30s: %s\n", ++count, test->name,
	       color ? retcodes[ret] : retcodes_nocolor[ret]);
	if (debug)
		printf("-------------\n");
	fflush(stdout);
}

static unsigned long load_base;

static int find_load_base(struct dl_phdr_info *info, size_t size, void *arg)
{
	unsigned i;

	if (info->dlpi_name[0] != '\0')
		return 0;

	/* not a PIE binary */
	if (info->dlpi_addr == 0)
		return 1;

	for (i = 0; i < info->dlpi_phnum; i++) {
		if (info->dlpi_phdr[i].p_type == PT_LOAD) {
			load_base = info->dlpi_addr - info->dlpi_phdr[i].p_vaddr;
			break;
		}
	}
	return 1;
}

static int sort_tests(const void *tc1, const void *tc2)
{
	const struct uftrace_unit_test *test1 = tc1;
	const struct uftrace_unit_test *test2 = tc2;

	/* keep unittest_framework first */
	if (!strcmp(test1->name, "unittest_framework"))
		return -1;
	if (!strcmp(test2->name, "unittest_framework"))
		return 1;

	return strcmp(test1->name, test2->name);
}

static bool free_test_names;

/*
 * RISC-V GCC doesn't set uftrace_unit_test data in the uftrace.test section
 * (#1833).  So it should read the unittest binary to find the symbol table
 * and fill the data manually.
 *
 * Note that the unit test functions are global functions start with "func_"
 * prefix.  Other (global) functions should not start with that.
 */
static void update_test_cases(struct uftrace_unit_test *tcases, int num,
			      struct uftrace_elf_data *elf)
{
	struct uftrace_elf_iter iter;
	int len = strlen(TEST_FUNC_PREFIX_STR);
	int i = 0;

	printf("update test cases from binary\n");
	elf_for_each_shdr(elf, &iter) {
		if (iter.shdr.sh_type != SHT_SYMTAB)
			continue;
		elf_for_each_symbol(elf, &iter) {
			typeof(iter.sym) *sym = &iter.sym;
			const char *name = elf_get_name(elf, &iter, sym->st_name);

			if (elf_symbol_type(sym) != STT_FUNC || elf_symbol_bind(sym) != STB_GLOBAL)
				continue;
			if (strncmp(name, TEST_FUNC_PREFIX_STR, len))
				continue;
			tcases[i].func = (void *)sym->st_value + load_base;
			tcases[i].name = strdup(name + len);
			i++;
		}
		/*
		 * It applied the base address already, make sure not to do it
		 * twice.
		 */
		load_base = 0;
		free_test_names = true;
		break;
	}
}

static int setup_unit_test(struct uftrace_unit_test **test_cases, size_t *test_num, char *filter)
{
	char *exename;
	struct uftrace_elf_data elf;
	struct uftrace_elf_iter iter;
	struct uftrace_unit_test *tcases;
	bool found_unittest = false;
	size_t sec_size;
	unsigned i, num, actual;
	int ret = -1;

	exename = read_exename();
	if (elf_init(exename, &elf) < 0) {
		printf("error during load ELF header: %s\n", exename);
		return -1;
	}

	elf_for_each_shdr(&elf, &iter) {
		char *shstr;

		shstr = elf_get_name(&elf, &iter, iter.shdr.sh_name);

		if (strcmp(shstr, "uftrace.unit_test") == 0) {
			sec_size = iter.shdr.sh_size;
			found_unittest = true;
			break;
		}
	}

	if (!found_unittest) {
		printf("cannot find unit test data\n");
		goto out;
	}

	dl_iterate_phdr(find_load_base, NULL);

	tcases = xmalloc(sec_size);
	num = sec_size / sizeof(*tcases);

	elf_get_secdata(&elf, &iter);
	elf_read_secdata(&elf, &iter, 0, tcases, sec_size);

	/* check if test cases are set properly */
	for (i = 0, actual = 0; i < num; i++) {
		if (tcases[i].func && tcases[i].name)
			actual++;
	}
	if (actual != num)
		update_test_cases(tcases, num, &elf);

	/* relocate section symbols in case of PIE */
	for (i = 0, actual = 0; i < num && (load_base || filter); i++) {
		struct uftrace_unit_test *tc = &tcases[i];
		unsigned long faddr = (unsigned long)tc->func;
		unsigned long naddr = (unsigned long)tc->name;

		if (load_base) {
			faddr += load_base;
			naddr += load_base;

			tc->func = (void *)faddr;
			tc->name = (void *)naddr;
		}

		if (filter && strstr(tc->name, filter))
			actual++;
	}

	if (!filter)
		actual = num;

	printf("Running %u test cases\n======================\n", actual);

	qsort(tcases, num, sizeof(*tcases), sort_tests);

	*test_cases = tcases;
	*test_num = num;

	ret = 0;

out:
	elf_finish(&elf);
	return ret;
}

static int finish_unit_test(struct uftrace_unit_test *test_cases, int test_num, int *test_stats)
{
	int i;

	printf("\nunit test stats\n====================\n");

	for (i = 0; i < TEST_MAX; i++)
		printf("%3d %s\n", test_stats[i], messages[i]);

	printf("\n");

	if (free_test_names) {
		for (i = 0; i < test_num; i++)
			free((void *)test_cases[i].name);
	}
	free(test_cases);
	return test_stats[TEST_NG] + test_stats[TEST_BAD] + test_stats[TEST_SIG] > 0 ?
		       EXIT_FAILURE :
		       EXIT_SUCCESS;
}

int __attribute__((weak)) arch_fill_cpuinfo_model(int fd)
{
	return 0;
}

#undef main
int main(int argc, char *argv[])
{
	struct uftrace_unit_test *test_cases = NULL;
	int test_stats[TEST_MAX] = {};
	size_t i, test_num = 0;
	char *filter = NULL;
	char *term;
	int c;
	bool color_set = false;

	while ((c = getopt(argc, argv, "dvnpiO:f:-:")) != -1) {
		switch (c) {
		case 'd':
		case 'v':
			debug = 1;
			break;
		case 'n':
			color = false;
			color_set = true;
			break;
		case '-':
			/* poor man's getopt_long() */
			if (!strncmp(optarg, "color", 5)) {
				char *arg;
				if (optarg[5] == '=')
					arg = optarg + 6;
				else
					arg = argv[optind++];
				if (!strcmp(arg, "on") || !strcmp(arg, "1"))
					color = true;
				if (!strcmp(arg, "off") || !strcmp(arg, "0"))
					color = false;
				color_set = true;
			}
			break;
		default:
			break;
		}
	}

	if (optind < argc)
		filter = argv[optind];

	outfp = logfp = stdout;

	if (setup_unit_test(&test_cases, &test_num, filter) < 0) {
		printf("Cannot run unit tests - failed to load test cases\n");
		return -1;
	}

	if (!color_set) {
		term = getenv("TERM");
		if (term && !strcmp(term, "dumb"))
			color = false;
		if (!isatty(STDIN_FILENO))
			color = false;
	}

	for (i = 0; i < test_num; i++)
		run_unit_test(&test_cases[i], test_stats, filter);

	return finish_unit_test(test_cases, test_num, test_stats);
}
