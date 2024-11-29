#include <getopt.h>
#include <inttypes.h>
#include <unistd.h>

#include "uftrace.h"
#include "utils/arch.h"
#include "utils/dwarf.h"
#include "utils/symbol.h"
#include "utils/utils.h"
#include "version.h"

/* needs to print session info with symbol */
static bool needs_session;

static struct option symbols_options[] = {
	{ "data", required_argument, 0, 'd' },
	{ "verbose", no_argument, 0, 'v' },
};

static const char symbols_usage[] =
	"symbols " UFTRACE_VERSION "\n"
	"\n"
	" OPTION:\n"
	"  -d, --data             Use this DATA instead of uftrace.data\n"
	"  -v, --verbose          Be verbose\n"
	"\n";

struct symbols_opts {
	char *dirname;
	int idx;
};

static void parse_option(int argc, char **argv, struct symbols_opts *opts)
{
	bool done = false;

	while (!done) {
		int key, tmp;

		key = getopt_long(argc, argv, "d:v", symbols_options, &tmp);
		switch (key) {
		case 'd':
			opts->dirname = xstrdup(optarg);
			break;

		case 'v':
			debug++;
			dbg_domain[DBG_SYMBOL]++;
			break;

		case -1:
			done = true;
			break;

		default:
			printf("%s", symbols_usage);
			exit(1);
		}
	}

	opts->idx = optind;
}

static int print_session_symbol(struct uftrace_session *s, void *arg)
{
	uint64_t addr = *(uint64_t *)arg;
	struct uftrace_symbol *sym;
	struct uftrace_dbg_loc *dloc;

	sym = find_symtabs(&s->sym_info, addr);
	if (sym == NULL)
		sym = session_find_dlsym(s, ~0ULL, addr);

	if (sym == NULL)
		return 0;

	printf("  %s", sym->name);

	dloc = find_file_line(&s->sym_info, addr);
	if (dloc && dloc->file)
		printf(" (at %s:%d)", dloc->file->name, dloc->line);

	if (needs_session)
		printf(" [in %.*s]", SESSION_ID_LEN, s->sid);

	return 0;
}

static int read_sessions(struct uftrace_session_link *link, char *dirname)
{
	FILE *fp;
	char *fname = NULL;
	char *line = NULL;
	size_t sz = 0;
	unsigned long sec, nsec;
	struct uftrace_msg_task tmsg;
	struct uftrace_msg_sess smsg;
	struct uftrace_msg_dlopen dlop;
	char *exename, *pos;
	int count = 0;

	xasprintf(&fname, "%s/%s", dirname, "task.txt");

	fp = fopen(fname, "r");
	if (fp == NULL) {
		free(fname);
		return -1;
	}

	pr_dbg("reading %s file\n", fname);
	while (getline(&line, &sz, fp) >= 0) {
		if (!strncmp(line, "TASK", 4)) {
			sscanf(line + 5, "timestamp=%lu.%lu tid=%d pid=%d", &sec, &nsec, &tmsg.tid,
			       &tmsg.pid);

			tmsg.time = (uint64_t)sec * NSEC_PER_SEC + nsec;
			create_task(link, &tmsg, false);
		}
		else if (!strncmp(line, "FORK", 4)) {
			sscanf(line + 5, "timestamp=%lu.%lu pid=%d ppid=%d", &sec, &nsec, &tmsg.tid,
			       &tmsg.pid);

			tmsg.time = (uint64_t)sec * NSEC_PER_SEC + nsec;
			create_task(link, &tmsg, true);
		}
		else if (!strncmp(line, "SESS", 4)) {
			sscanf(line + 5, "timestamp=%lu.%lu %*[^i]id=%d sid=%s", &sec, &nsec,
			       &smsg.task.pid, (char *)&smsg.sid);

			// Get the execname
			pos = strstr(line, "exename=");
			if (pos == NULL)
				pr_err_ns("invalid task.txt format");
			exename = pos + 8 + 1; // skip double-quote
			pos = strrchr(exename, '\"');
			if (pos)
				*pos = '\0';

			smsg.task.tid = smsg.task.pid;
			smsg.task.time = (uint64_t)sec * NSEC_PER_SEC + nsec;
			smsg.namelen = strlen(exename);

			create_session(link, &smsg, dirname, dirname, exename, true, true, false);
			count++;
		}
		else if (!strncmp(line, "DLOP", 4)) {
			struct uftrace_session *s;

			sscanf(line + 5, "timestamp=%lu.%lu tid=%d sid=%s base=%" PRIx64, &sec,
			       &nsec, &dlop.task.tid, (char *)&dlop.sid, &dlop.base_addr);

			pos = strstr(line, "libname=");
			if (pos == NULL)
				pr_err_ns("invalid task.txt format");
			exename = pos + 8 + 1; // skip double-quote
			pos = strrchr(exename, '\"');
			if (pos)
				*pos = '\0';

			dlop.task.pid = dlop.task.tid;
			dlop.task.time = (uint64_t)sec * NSEC_PER_SEC + nsec;
			dlop.namelen = strlen(exename);

			s = get_session_from_sid(link, dlop.sid);
			session_add_dlopen(s, dlop.task.time, dlop.base_addr, exename, false);
		}
	}

	if (count > 1)
		needs_session = true;

	free(line);
	fclose(fp);
	free(fname);
	return 0;
}

int main(int argc, char *argv[])
{
	int ret = 0;
	uint64_t addr;
	struct symbols_opts opts = {
		.dirname = UFTRACE_DIR_NAME,
	};
	struct uftrace_session_link link = {
		.root = RB_ROOT,
		.tasks = RB_ROOT,
	};

	outfp = stdout;
	logfp = stdout;

	parse_option(argc, argv, &opts);

retry:
	if (read_sessions(&link, opts.dirname) < 0) {
		if (!strcmp(opts.dirname, UFTRACE_DIR_NAME)) {
			opts.dirname = ".";
			goto retry;
		}

		printf("read session failed\n");
		ret = -1;
		goto out;
	}

	if (opts.idx < argc) {
		int i;

		for (i = opts.idx; i < argc; i++) {
			sscanf(argv[i], "%" PRIx64, &addr);
			printf("%" PRIx64 ":", addr);

			if (needs_session)
				putchar('\n');
			walk_sessions(&link, print_session_symbol, &addr);
			putchar('\n');
		}
	}
	else {
		char buf[4096];

		while (fgets(buf, sizeof(buf), stdin)) {
			sscanf(buf, "%" PRIx64, &addr);
			printf("%" PRIx64 ":", addr);

			if (needs_session)
				putchar('\n');
			walk_sessions(&link, print_session_symbol, &addr);
			putchar('\n');
		}
	}

out:
	delete_sessions(&link);
	return ret;
}
