#include <stdio.h>
#include <stdlib.h>

#include "uftrace.h"
#include "version.h"
#include "utils/utils.h"
#include "../argp/argp.h"

/* output of --version option (generated by argp runtime) */
const char *argp_program_version = "demangler " UFTRACE_VERSION;

char *demangle(char *str);

extern enum symbol_demangler demangler;

enum options {
	OPT_simple	= 301,
	OPT_full,
	OPT_no,
};

static struct argp_option demangler_options[] = {
	{ "simple", OPT_simple, 0, 0, "Use internal simple demangler (default)" },
	{ "full", OPT_full, 0, 0, "Use libstdc++ demangler" },
	{ "no", OPT_no, 0, 0, "Do not use demangler" },
	{ "verbose", 'v', 0, 0, "Be verbose" },
	{ 0 }
};

struct demangler_opts {
	int mode;
	int idx;
};

static error_t parse_option(int key, char *arg, struct argp_state *state)
{
	struct demangler_opts *opts = state->input;

	switch (key) {
	case OPT_simple:
		opts->mode = DEMANGLE_SIMPLE;
		break;

	case OPT_full:
		opts->mode = DEMANGLE_FULL;
		break;

	case OPT_no:
		opts->mode = DEMANGLE_NONE;
		break;

	case 'v':
		debug++;
		dbg_domain[DBG_DEMANGLE]++;
		break;

	case ARGP_KEY_ARGS:
		opts->idx = state->next;
		break;

	case ARGP_KEY_NO_ARGS:
	case ARGP_KEY_END:
		break;

	default:
		return ARGP_ERR_UNKNOWN;
	}

	return 0;
}

int main(int argc, char *argv[])
{
	struct demangler_opts opts = {
		.mode = DEMANGLE_SIMPLE,
	};

	struct argp argp = {
		.options = demangler_options,
		.parser = parse_option,
		.args_doc = "[<mangled symbol>]",
		.doc = "demangler -- internal simple demangler",
	};

	argp_parse(&argp, argc, argv, ARGP_IN_ORDER, NULL, &opts);

	demangler = opts.mode;

	outfp = stdout;
	logfp = stdout;

	if (opts.idx) {
		int i;

		for (i = opts.idx; i < argc; i++) {
			char *name = demangle(argv[i]);

			printf("%s\n", name);
			free(name);
		}
	}
	else {
		char buf[4096];

		while (fgets(buf, sizeof(buf), stdin)) {
			char *name;
			char *p;

			buf[sizeof(buf)-1] = '\0';
			p = strchr(buf, '\n');
			if (p)
				*p = '\0';

			name = demangle(buf);
			printf("%s\n", name);
			free(name);
		}
	}

	return 0;
}
