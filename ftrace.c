#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <errno.h>
#include <argp.h>
#include <unistd.h>
#include <sys/wait.h>
#include <dlfcn.h>

#include "mcount.h"
#include "symbol.h"

const char *argp_program_version = "ftrace v0.1";
const char *argp_program_bug_address = "namhyung@gmail.com";

#define OPT_flat  301

static struct argp_option ftrace_options[] = {
	{ "library-path", 'L', "PATH", 0, "Load libraries from this PATH" },
	{ "filter", 'F', "FUNC[,FUNC,...]", 0, "Only trace those FUNCs" },
	{ "notrace", 'N', "FUNC[,FUNC,...]", 0, "Don't trace those FUNCs" },
	{ "debug", 'd', 0, 0, "Print debug messages" },
	{ "file", 'f', "FILE", 0, "Use this FILE instead of ftrace.data" },
	{ "flat", OPT_flat, 0, 0, "Use flat output format" },
	{ 0 }
};

#define FTRACE_MODE_RECORD  1
#define FTRACE_MODE_REPLAY  2
#define FTRACE_MODE_BOTH    3

struct opts {
	char *lib_path;
	char *filter;
	char *notrace;
	char *filename;
	int mode;
	int flat;
	int idx;
};

char *data_file = FTRACE_FILE_NAME;
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
		data_file = arg;
		break;

	case OPT_flat:
		opts->flat = 1;
		break;

	case ARGP_KEY_ARG:
		if (state->arg_num == 0) {
			if (!strcmp("record", arg))
				opts->mode = FTRACE_MODE_RECORD;
			else if (!strcmp("replay", arg))
				opts->mode = FTRACE_MODE_REPLAY;
			else {
				opts->mode = FTRACE_MODE_BOTH;
				opts->filename = arg;
				opts->idx = state->next - 1;
			}
		} else if (state->arg_num == 1) {
			if (opts->mode != FTRACE_MODE_BOTH) {
				opts->filename = arg;
				opts->idx = state->next - 1;
			}
		}
		break;

	case ARGP_KEY_END:
		if (state->arg_num < 1 || opts->filename == NULL)
			argp_usage(state);
		break;

	default:
		return ARGP_ERR_UNKNOWN;
	}
	return 0;
}

static void print_flat_rstack(struct mcount_ret_stack *rstack)
{
	static int count;
	struct sym *parent = find_symtab(rstack->parent_ip);
	struct sym *child = find_symtab(rstack->child_ip);
	const char *parent_name = parent ? parent->name : NULL;
	const char *child_name = child ? child->name : NULL;

	if (parent_name == NULL) {
		Dl_info info;

		dladdr((void *)rstack->parent_ip, &info);
		parent_name = info.dli_sname ?: "unknown";
	}
	if (child_name == NULL) {
		Dl_info info;

		dladdr((void *)rstack->child_ip, &info);
		child_name = info.dli_sname ?: "unknown";
	}

	if (rstack->end_time == 0) {
		printf("[%d] %d/%d: ip (%s -> %s), time (%lu)\n",
		       count++, rstack->tid, rstack->depth, parent_name,
		       child_name, rstack->start_time);
	} else {
		printf("[%d] %d/%d: ip (%s <- %s), time (%lu:%lu)\n",
		       count++, rstack->tid, rstack->depth, parent_name,
		       child_name, rstack->end_time,
		       rstack->end_time - rstack->start_time);
	}
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
		}
		p = NULL;
		fname = strtok(p, ",:");
	}
}

int main(int argc, char *argv[])
{
	int pid;
	FILE *fp;
	int status;
	struct ftrace_file_header header;
	struct mcount_ret_stack rstack;

	struct opts opts = {
		.mode = FTRACE_MODE_BOTH,
	};
	struct argp argp = {
		.options = ftrace_options,
		.parser = parse_option,
		.args_doc = "[record|replay] <command> [args...]",
		.doc = "ftrace -- a function tracer",
	};

	argp_parse(&argp, argc, argv, 0, NULL, &opts);

	if (load_symtab(opts.filename) < 0)
		return 0;

	if (opts.mode == FTRACE_MODE_REPLAY)
		goto replay;

	/* don't care about the failure */
	rename(FTRACE_FILE_NAME, FTRACE_FILE_NAME".old");

	fflush(stdout);

	pid = fork();
	if (pid < 0) {
		perror("fork");
		exit(1);
	}

	if (pid == 0) {
		char buf[4096];
		const char *old_preload = getenv("LD_PRELOAD");
		const char *old_audit = getenv("LD_AUDIT");
		const char *lib_path = opts.lib_path ?: ".";

		snprintf(buf, sizeof(buf), "%s/%s", lib_path, "libmcount.so");
		if (old_preload) {
			strcat(buf, ":");
			strcat(buf, old_preload);
		}
		setenv("LD_PRELOAD", buf, 1);

		snprintf(buf, sizeof(buf), "%s/%s", lib_path, "librtld-audit.so");
		if (old_audit) {
			strcat(buf, ":");
			strcat(buf, old_audit);
		}
		setenv("LD_AUDIT", buf, 1);

		if (opts.filter) {
			build_addrlist(buf, opts.filter);
			setenv("FTRACE_FILTER", buf, 1);
		}

		if (opts.notrace) {
			build_addrlist(buf, opts.notrace);
			setenv("FTRACE_NOTRACE", buf, 1);
		}

		if (debug)
			setenv("FTRACE_DEBUG", "1", 1);

		/*
		 * I don't think the traced binary is in PATH.
		 * So use plain 'execv' rather than 'execvp'.
		 */
		execv(opts.filename, &argv[opts.idx]);
		abort();
	}

	waitpid(pid, &status, 0);
	if (WIFSIGNALED(status)) {
		printf("child (%s) was terminated by signal: %d\n",
		       opts.filename, WTERMSIG(status));
		return 0;
	}

	if (opts.mode == FTRACE_MODE_RECORD)
		return 0;

replay:
	fp = fopen(FTRACE_FILE_NAME, "rb");
	if (fp == NULL) {
		if (errno == ENOENT) {
			printf("ERROR: Can't find %s file!  "
			       "Was '%s' compiled with -pg flag?\n",
			       FTRACE_FILE_NAME, opts.filename);
		} else {
			perror("ftrace");
		}
		exit(1);
	}

	fread(&header, sizeof(header), 1, fp);
	if (memcmp(header.magic, FTRACE_MAGIC_STR, FTRACE_MAGIC_LEN)) {
		printf("invalid magic string found!\n");
		return 0;
	}
	if (header.version != FTRACE_VERSION) {
		printf("invalid vergion number found!\n");
		return 0;
	}

	while (fread(&rstack, sizeof(rstack), 1, fp) == 1) {
		struct sym *sym = find_symtab(rstack.child_ip);

		if (opts.flat) {
			print_flat_rstack(&rstack);
			continue;
		}

		if (rstack.end_time == 0) {
			fpos_t pos;
			struct mcount_ret_stack rstack_ret;

			fgetpos(fp, &pos);

			if (fread(&rstack_ret, sizeof(rstack_ret), 1, fp) != 1) {
				perror("error reading rstack");
				break;
			}

			if (rstack_ret.depth == rstack.depth &&
			    rstack_ret.end_time != 0) {
				/* leaf function - also consume return record */
				printf("%4lu usec [%5d] | %*s%s();\n",
				       rstack_ret.end_time - rstack.start_time,
				       rstack.tid, rstack.depth * 2, "",
				       sym ? sym->name : "unknown");
			} else {
				/* function entry */
				printf("%9s [%5d] | %*s%s() {\n", "",
				       rstack.tid, rstack.depth * 2, "",
				       sym ? sym->name : "unknown");

				/* need to re-process return record */
				fsetpos(fp, &pos);
			}
		} else {
			/* function exit */
			printf("%4lu usec [%5d] | %*s} /* %s */\n",
			       rstack.end_time - rstack.start_time,
			       rstack.tid, rstack.depth * 2, "",
			       sym ? sym->name : "unknown");
		}
	}

	fclose(fp);
	unload_symtab();

	return 0;
}
