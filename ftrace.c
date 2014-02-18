#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <inttypes.h>
#include <errno.h>
#include <argp.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <assert.h>

#include "mcount.h"
#include "symbol.h"
#include "rbtree.h"
#include "utils.h"

const char *argp_program_version = "ftrace v0.1";
const char *argp_program_bug_address = "Namhyung Kim <namhyung@gmail.com>";

#define OPT_flat 	301
#define OPT_plthook 	302
#define OPT_symbols	303

static struct argp_option ftrace_options[] = {
	{ "library-path", 'L', "PATH", 0, "Load libraries from this PATH" },
	{ "filter", 'F', "FUNC[,FUNC,...]", 0, "Only trace those FUNCs" },
	{ "notrace", 'N', "FUNC[,FUNC,...]", 0, "Don't trace those FUNCs" },
	{ "debug", 'd', 0, 0, "Print debug messages" },
	{ "file", 'f', "FILE", 0, "Use this FILE instead of ftrace.data" },
	{ "flat", OPT_flat, 0, 0, "Use flat output format" },
	{ "plthook", OPT_plthook, 0, 0, "Hook library function calls" },
	{ "symbols", OPT_symbols, 0, 0, "Print symbol tables" },
	{ 0 }
};

#define FTRACE_MODE_INVALID 0
#define FTRACE_MODE_RECORD  1
#define FTRACE_MODE_REPLAY  2
#define FTRACE_MODE_LIVE    3
#define FTRACE_MODE_REPORT  4

#define FTRACE_MODE_DEFAULT  FTRACE_MODE_LIVE

struct opts {
	char *lib_path;
	char *filter;
	char *notrace;
	char *exename;
	char *filename;
	int mode;
	int idx;
	bool flat;
	bool want_plthook;
	bool print_symtab;
};

static bool debug;

static error_t parse_option(int key, char *arg, struct argp_state *state)
{
	struct opts *opts = state->input;

	switch (key) {
	case 'L':
		opts->lib_path = arg;
		break;

	case 'F':
		opts->filter = arg;
		break;

	case 'N':
		opts->notrace = arg;
		break;

	case 'd':
		debug = true;
		break;

	case 'f':
		opts->filename = arg;
		break;

	case OPT_flat:
		opts->flat = true;
		break;

	case OPT_plthook:
		opts->want_plthook = true;
		break;

	case OPT_symbols:
		opts->print_symtab = true;
		break;

	case ARGP_KEY_ARG:
		if (state->arg_num) {
			/*
			 * This is a second non-option argument.
			 * Returning ARGP_ERR_UNKNOWN will pass control to
			 * the ARGP_KEY_ARGS case.
			 */
			return ARGP_ERR_UNKNOWN;
		}
		if (!strcmp("record", arg))
			opts->mode = FTRACE_MODE_RECORD;
		else if (!strcmp("replay", arg))
			opts->mode = FTRACE_MODE_REPLAY;
		else if (!strcmp("live", arg))
			opts->mode = FTRACE_MODE_LIVE;
		else if (!strcmp("report", arg))
			opts->mode = FTRACE_MODE_REPORT;
		else
			return ARGP_ERR_UNKNOWN; /* almost same as fall through */
		break;

	case ARGP_KEY_ARGS:
		/*
		 * process remaining non-option arguments
		 */
		if (opts->mode == FTRACE_MODE_INVALID)
			opts->mode = FTRACE_MODE_DEFAULT;

		opts->exename = state->argv[state->next];
		opts->idx = state->next;
		break;

	case ARGP_KEY_NO_ARGS:
	case ARGP_KEY_END:
		if (state->arg_num < 1 || opts->exename == NULL)
			argp_usage(state);
		break;

	default:
		return ARGP_ERR_UNKNOWN;
	}
	return 0;
}

static int command_record(int argc, char *argv[], struct opts *opts);
static int command_replay(int argc, char *argv[], struct opts *opts);
static int command_live(int argc, char *argv[], struct opts *opts);
static int command_report(int argc, char *argv[], struct opts *opts);

int main(int argc, char *argv[])
{
	struct opts opts = {
		.mode = FTRACE_MODE_INVALID,
		.filename = FTRACE_FILE_NAME,
	};
	struct argp argp = {
		.options = ftrace_options,
		.parser = parse_option,
		.args_doc = "[record|replay|live|report] <command> [args...]",
		.doc = "ftrace -- a function tracer",
	};

	argp_parse(&argp, argc, argv, ARGP_IN_ORDER, NULL, &opts);

	if (opts.print_symtab) {
		load_symtabs(opts.exename);
		print_symtabs();
		unload_symtabs();
		exit(0);
	}

	switch (opts.mode) {
	case FTRACE_MODE_RECORD:
		command_record(argc, argv, &opts);
		break;
	case FTRACE_MODE_REPLAY:
		command_replay(argc, argv, &opts);
		break;
	case FTRACE_MODE_LIVE:
		command_live(argc, argv, &opts);
		break;
	case FTRACE_MODE_REPORT:
		command_report(argc, argv, &opts);
		break;
	case FTRACE_MODE_INVALID:
		break;
	}

	return 0;
}

static void build_addrlist(char *buf, char *symlist)
{
	char *p = symlist;
	char *fname = strtok(p, ",:");

	buf[0] = '\0';
	while (fname) {
		struct sym *sym = find_symname(fname);

		if (sym) {
			char tmp[64];

			snprintf(tmp, sizeof(tmp), "%s%#lx",
				 p ? "" : ":", sym->addr);
			strcat(buf, tmp);
		} else if (debug) {
			printf("ftrace: cannot find symbol: %s\n", fname);
			printf("ftrace: skip setting filter..\n");
		}

		p = NULL;
		fname = strtok(p, ",:");
	}
}

static void setup_child_environ(struct opts *opts)
{
	char buf[4096];
	const char *old_preload = getenv("LD_PRELOAD");
	const char *lib_path = opts->lib_path ?: ".";

	if (find_symname("__cyg_profile_func_enter"))
		snprintf(buf, sizeof(buf), "%s/%s", lib_path, "libcygprof.so");
	else
		snprintf(buf, sizeof(buf), "%s/%s", lib_path, "libmcount.so");

	if (old_preload) {
		strcat(buf, ":");
		strcat(buf, old_preload);
	}
	setenv("LD_PRELOAD", buf, 1);

	setenv("LD_BIND_NOT", "1", 1);

	if (opts->filter) {
		build_addrlist(buf, opts->filter);
		setenv("FTRACE_FILTER", buf, 1);
	}

	if (opts->notrace) {
		build_addrlist(buf, opts->notrace);
		setenv("FTRACE_NOTRACE", buf, 1);
	}

	if (opts->want_plthook)
		setenv("FTRACE_PLTHOOK", "1", 1);

	if (strcmp(opts->filename, FTRACE_FILE_NAME))
		setenv("FTRACE_FILE", opts->filename, 1);

	if (debug)
		setenv("FTRACE_DEBUG", "1", 1);
}

static const char mcount_msg[] =
	"ERROR: Can't find '%s' symbol in the '%s'.\n"
	"It seems not to be compiled with -finstrument-functions flag\n"
	"which generates traceable code.  Please check your binary file.\n";

static int command_record(int argc, char *argv[], struct opts *opts)
{
	int pid;
	int status;
	char oldname[512];

	/* backup old 'ftrace.data' file */
	if (strcmp(FTRACE_FILE_NAME, opts->filename) == 0) {
		snprintf(oldname, sizeof(oldname), "%s.old", opts->filename);

		/* don't care about the failure */
		rename(opts->filename, oldname);
	}

	if (load_symtabs(opts->exename) < 0)
		return -1;

	if (!find_symname("mcount") && !find_symname("__fentry__") &&
	    !find_symname("__gnu_mcount_nc") && !find_symname("__cyg_profile_func_enter")) {
		printf(mcount_msg, "mcount", opts->exename);
		return -1;
	}

	fflush(stdout);

	pid = fork();
	if (pid < 0) {
		perror("fork");
		return -1;
	}

	if (pid == 0) {
		setup_child_environ(opts);

		/*
		 * I don't think the traced binary is in PATH.
		 * So use plain 'execv' rather than 'execvp'.
		 */
		execv(opts->exename, &argv[opts->idx]);
		abort();
	}

	waitpid(pid, &status, 0);
	if (WIFSIGNALED(status)) {
		printf("child (%s) was terminated by signal: %d\n",
		       opts->exename, WTERMSIG(status));
	} else if (debug)
		printf("child terminated with %d\n", WEXITSTATUS(status));

	if (access(opts->filename, F_OK) < 0) {
		printf("Cannot generate data file\n");
		return -1;
	}

	/*
	 * Do not unload symbol tables.  It might save some time when used by
	 * 'live' command as it also need to load the symtabs again.
	 */
	//unload_symtabs();
	return 0;
}

static FILE *open_data_file(const char *filename, const char *exename)
{
	FILE *fp;
	struct ftrace_file_header header;

	fp = fopen(filename, "rb");
	if (fp == NULL) {
		if (errno == ENOENT) {
			printf("ERROR: Can't find %s file!\n"
			       "Was '%s' compiled with -finstrument-functions flag\n"
			       "and ran with ftrace record?\n",
			       filename, exename);
		} else {
			perror("ftrace");
		}
		goto out;
	}

	fread(&header, sizeof(header), 1, fp);
	if (memcmp(header.magic, FTRACE_MAGIC_STR, FTRACE_MAGIC_LEN)) {
		printf("invalid magic string found!\n");
		fclose(fp);
		fp = NULL;
		goto out;
	}
	if (header.version != FTRACE_VERSION) {
		printf("invalid vergion number found!\n");
		fclose(fp);
		fp = NULL;
	}

out:
	return fp;
}

static int print_flat_rstack(struct mcount_ret_stack *rstack, FILE *fp)
{
	static int count;
	struct sym *parent = find_symtab(rstack->parent_ip);
	struct sym *child = find_symtab(rstack->child_ip);
	char *parent_name = symbol_getname(parent, rstack->parent_ip);
	char *child_name = symbol_getname(child, rstack->child_ip);

	if (rstack->end_time == 0) {
		printf("[%d] %d/%d: ip (%s -> %s), time (%"PRIu64")\n",
		       count++, rstack->tid, rstack->depth, parent_name,
		       child_name, rstack->start_time);
	} else {
		printf("[%d] %d/%d: ip (%s <- %s), time (%"PRIu64":%"PRIu64")\n",
		       count++, rstack->tid, rstack->depth, parent_name,
		       child_name, rstack->end_time,
		       rstack->end_time - rstack->start_time);
	}

	symbol_putname(parent, parent_name);
	symbol_putname(child, child_name);
	return 0;
}

static void print_time_unit(uint64_t start_nsec, uint64_t end_nsec)
{
	uint64_t delta = 0;
	uint64_t delta_small;
	char *unit[] = { "us", "ms", "s", "m", "h", };
	unsigned limit[] = { 1000, 1000, 1000, 60, 24, INT_MAX, };
	unsigned idx;

	if (start_nsec == 0UL && end_nsec == 0UL) {
		printf(" %7s %2s", "", "");
		return;
	}

	for (idx = 0; idx < ARRAY_SIZE(unit); idx++) {
		if (delta == 0)
			delta = end_nsec - start_nsec;

		delta_small = delta % limit[idx];
		delta = delta / limit[idx];

		if (delta < limit[idx+1])
			break;
	}

	assert(idx < ARRAY_SIZE(unit));

	printf(" %3"PRIu64".%03"PRIu64" %2s", delta, delta_small, unit[idx]);
}

static int print_graph_rstack(struct mcount_ret_stack *rstack, FILE *fp)
{
	struct sym *sym = find_symtab(rstack->child_ip);
	char *symname = symbol_getname(sym, rstack->child_ip);

	if (rstack->end_time == 0) {
		fpos_t pos;
		struct mcount_ret_stack rstack_next;

		fgetpos(fp, &pos);

		if (fread(&rstack_next, sizeof(rstack_next), 1, fp) != 1) {
			perror("error reading rstack");
			symbol_putname(sym, symname);
			return -1;
		}

		if (rstack_next.depth == rstack->depth &&
		    rstack_next.end_time != 0) {
			/* leaf function - also consume return record */
			print_time_unit(rstack->start_time, rstack_next.end_time);
			printf(" [%5d] | %*s%s();\n", rstack->tid,
			       rstack->depth * 2, "", symname);
		} else {
			/* function entry */
			print_time_unit(0UL, 0UL);
			printf(" [%5d] | %*s%s() {\n", rstack->tid,
			       rstack->depth * 2, "", symname);

			/* need to re-process return record */
			fsetpos(fp, &pos);
		}
	} else {
		/* function exit */
		print_time_unit(rstack->start_time, rstack->end_time);
		printf(" [%5d] | %*s} /* %s */\n", rstack->tid,
		       rstack->depth * 2, "", symname);
	}

	symbol_putname(sym, symname);
	return 0;
}

static int command_replay(int argc, char *argv[], struct opts *opts)
{
	FILE *fp;
	int ret;
	struct mcount_ret_stack rstack;

	fp = open_data_file(opts->filename, opts->exename);
	if (fp == NULL)
		return -1;

	ret = load_symtabs(opts->exename);
	if (ret < 0)
		goto out;

	while (fread(&rstack, sizeof(rstack), 1, fp) == 1) {
		if (opts->flat)
			ret = print_flat_rstack(&rstack, fp);
		else
			ret = print_graph_rstack(&rstack, fp);

		if (ret)
			break;
	}

	unload_symtabs();
out:
	fclose(fp);

	return ret;
}

static char *tmp_filename;
static void cleanup_tempfile(void)
{
	if (tmp_filename)
		unlink(tmp_filename);
}

static int command_live(int argc, char *argv[], struct opts *opts)
{
	char template[32] = "/tmp/ftrace-live-XXXXXX";
	int fd = mkstemp(template);
	if (fd < 0) {
		perror("live command cannot be run");
		return -1;
	}
	close(fd);

	tmp_filename = xstrdup(template);
	atexit(cleanup_tempfile);

	opts->filename = template;

	if (command_record(argc, argv, opts) == 0)
		command_replay(argc, argv, opts);

	free(tmp_filename);
	tmp_filename = NULL;

	unlink(template);

	return 0;
}

struct trace_entry {
	struct sym *sym;
	uint64_t time_total;
	uint64_t time_self;
	unsigned long nr_called;
	struct rb_node link;
};

static void insert_entry(struct rb_root *root, struct trace_entry *te)
{
	struct trace_entry *entry;
	struct rb_node *parent = NULL;
	struct rb_node **p = &root->rb_node;

	while (*p) {
		int cmp;

		parent = *p;
		entry = rb_entry(parent, struct trace_entry, link);

		cmp = strcmp(entry->sym->name, te->sym->name);
		if (cmp == 0) {
			entry->time_total += te->time_total;
			entry->time_self  += te->time_self;
			entry->nr_called  += 1;
			return;
		}

		if (cmp < 0)
			p = &parent->rb_left;
		else
			p = &parent->rb_right;
	}

	entry = xmalloc(sizeof(*entry));
	entry->sym = te->sym;
	entry->time_total = te->time_total;
	entry->time_self  = te->time_self;
	entry->nr_called  = 1;

	rb_link_node(&entry->link, parent, p);
	rb_insert_color(&entry->link, root);
}

static void sort_by_time(struct rb_root *root, struct trace_entry *te)
{
	struct trace_entry *entry;
	struct rb_node *parent = NULL;
	struct rb_node **p = &root->rb_node;

	while (*p) {
		parent = *p;
		entry = rb_entry(parent, struct trace_entry, link);

		if (entry->time_total < te->time_total)
			p = &parent->rb_left;
		else
			p = &parent->rb_right;
	}

	rb_link_node(&te->link, parent, p);
	rb_insert_color(&te->link, root);
}

static int command_report(int argc, char *argv[], struct opts *opts)
{
	FILE *fp;
	int ret;
	struct rb_root name_tree = RB_ROOT;
	struct rb_root time_tree = RB_ROOT;
	struct rb_node *node;
	struct trace_entry *entry;
	struct mcount_ret_stack rstack;
	const char h_format[] = "  %-40.40s  %10.10s  %10.10s  %10.10s  \n";
//	const char l_format[] = "  %-40.40s  %10"PRIu64"  %10"PRIu64"  %10lu  \n";
	const char line[] = "=================================================";

	fp = open_data_file(opts->filename, opts->exename);
	if (fp == NULL)
		return -1;

	ret = load_symtabs(opts->exename);
	if (ret < 0)
		goto out;

	while (fread(&rstack, sizeof(rstack), 1, fp) == 1) {
		struct sym *sym;
		struct trace_entry te;

		if (rstack.end_time == 0)
			continue;

		sym = find_symtab(rstack.child_ip);
		assert(sym != NULL);

		te.sym = sym;
		te.time_total = rstack.end_time - rstack.start_time;
		te.time_self = te.time_total - rstack.child_time;

		insert_entry(&name_tree, &te);
	}

	while (!RB_EMPTY_ROOT(&name_tree)) {
		node = rb_first(&name_tree);
		rb_erase(node, &name_tree);

		sort_by_time(&time_tree, rb_entry(node, struct trace_entry, link));
	}

	printf(h_format, "Function", "Total time", "Self time", "Nr. called");
	printf(h_format, line, line, line, line);

	for (node = rb_first(&time_tree); node; node = rb_next(node)) {
		char *symname;

		entry = rb_entry(node, struct trace_entry, link);

		symname = symbol_getname(entry->sym, 0);

		printf("  %-40.40s ", symname);
		print_time_unit(0UL, entry->time_total);
		putchar(' ');
		print_time_unit(0UL, entry->time_self);
		printf("  %10lu  \n", entry->nr_called);

		symbol_putname(entry->sym, symname);
	}

	unload_symtabs();
out:
	fclose(fp);

	return ret;
}
