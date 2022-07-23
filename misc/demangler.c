#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "uftrace.h"
#include "utils/utils.h"
#include "version.h"

char *demangle(char *str);

extern enum symbol_demangler demangler;

enum options {
	OPT_simple = 301,
	OPT_full,
	OPT_no,
};

static struct option demangler_options[] = {
	{ "simple", no_argument, 0, OPT_simple },
	{ "full", no_argument, 0, OPT_full },
	{ "no", no_argument, 0, OPT_no },
	{ "verbose", no_argument, 0, 'v' },
};

static const char demangler_usage[] =
	"demangler " UFTRACE_VERSION "\n"
	"\n"
	" OPTION:\n"
	"      --simple           Use internal simple demangler (default)\n"
	"      --full             Use libstdc++ demangler\n"
	"      --no               Do not use demangler\n"
	"  -v, --verbose          Be verbose\n"
	"\n";

struct demangler_opts {
	int mode;
	int idx;
};

static void parse_option(int argc, char **argv, struct demangler_opts *opts)
{
	bool done = false;

	while (!done) {
		int key, tmp;

		key = getopt_long(argc, argv, "v", demangler_options, &tmp);
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

		case -1:
			done = true;
			break;

		default:
			printf("%s", demangler_usage);
			exit(1);
		}
	}

	opts->idx = optind;
}

int main(int argc, char *argv[])
{
	struct demangler_opts opts = {
		.mode = DEMANGLE_SIMPLE,
	};

	parse_option(argc, argv, &opts);

	demangler = opts.mode;

	outfp = stdout;
	logfp = stdout;

	if (opts.idx < argc) {
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

			buf[sizeof(buf) - 1] = '\0';
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
