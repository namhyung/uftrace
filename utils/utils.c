#include <dirent.h>
#include <errno.h>
#include <libgen.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <unistd.h>

#ifdef HAVE_LIBUNWIND
#define UNW_LOCAL_ONLY
#include <libunwind.h>
#endif

#include "uftrace.h"
#include "utils/kernel.h"
#include "utils/utils.h"

volatile bool uftrace_done;

/* default uftrace options to be applied for analysis commands */
struct strv default_opts = STRV_INIT;

void sighandler(int sig)
{
	uftrace_done = true;
}

void setup_signal(void)
{
	signal(SIGINT, sighandler);
	signal(SIGTERM, sighandler);
	signal(SIGPIPE, sighandler);
}

int read_all(int fd, void *buf, size_t size)
{
	int ret;

	while (size) {
		ret = read(fd, buf, size);
		if (ret < 0 && errno == EINTR)
			continue;
		if (ret <= 0)
			return -1;

		buf += ret;
		size -= ret;
	}
	return 0;
}

int pread_all(int fd, void *buf, size_t size, off_t off)
{
	int ret;

	while (size) {
		ret = pread(fd, buf, size, off);
		if (ret < 0 && errno == EINTR)
			continue;
		if (ret <= 0)
			return -1;

		buf += ret;
		size -= ret;
		off += ret;
	}
	return 0;
}

int fread_all(void *buf, size_t size, FILE *fp)
{
	size_t ret;

	while (size) {
		if (feof(fp))
			return -1;

		ret = fread(buf, 1, size, fp);
		if (ferror(fp))
			return -1;

		buf += ret;
		size -= ret;
	}
	return 0;
}

int write_all(int fd, const void *buf, size_t size)
{
	int ret;

	while (size) {
		ret = write(fd, buf, size);
		if (ret < 0 && errno == EINTR)
			continue;
		if (ret < 0)
			return -1;

		buf += ret;
		size -= ret;
	}
	return 0;
}

int writev_all(int fd, struct iovec *iov, int count)
{
	int i, ret;
	int size = 0;

	for (i = 0; i < count; i++)
		size += iov[i].iov_len;

	while (size) {
		ret = writev(fd, iov, count);
		if (ret < 0 && errno == EINTR)
			continue;
		if (ret < 0)
			return -1;

		size -= ret;
		if (size == 0)
			break;

		while (ret > (int)iov->iov_len) {
			ret -= iov->iov_len;

			if (count == 0)
				pr_err_ns("invalid iovec count?");

			count--;
			iov++;
		}

		iov->iov_base += ret;
		iov->iov_len -= ret;
	}
	return 0;
}

int fwrite_all(const void *buf, size_t size, FILE *fp)
{
	size_t ret;
	while (size) {
		if (feof(fp))
			return -1;

		ret = fwrite(buf, 1, size, fp);
		if (ferror(fp))
			return -1;

		buf += ret;
		size -= ret;
	}
	return 0;
}

int remove_directory(const char *dirname)
{
	DIR *dp;
	struct dirent *ent;
	struct stat statbuf;
	char buf[PATH_MAX];
	int saved_errno = 0;
	int ret = 0;

	dp = opendir(dirname);
	if (dp == NULL)
		return -1;

	pr_dbg("removing %s directory\n", dirname);

	while ((ent = readdir(dp)) != NULL) {
		if (!strcmp(ent->d_name, ".") || !strcmp(ent->d_name, ".."))
			continue;

		snprintf(buf, sizeof(buf), "%s/%s", dirname, ent->d_name);
		ret = stat(buf, &statbuf);
		if (ret < 0)
			goto failed;

		if (S_ISDIR(statbuf.st_mode))
			ret = remove_directory(buf);
		else
			ret = unlink(buf);

		if (ret < 0) {
failed:
			saved_errno = errno;
			break;
		}
	}

	closedir(dp);
	if (rmdir(dirname) < 0 && ret == 0)
		ret = -1;
	else
		errno = saved_errno;
	return ret;
}

static bool is_uftrace_directory(const char *path)
{
	int fd;
	bool ret = false;
	char *info_path = NULL;
	char sig[UFTRACE_MAGIC_LEN] = {
		0,
	};

	/* ensure that there is "info" file in the recorded directory */
	xasprintf(&info_path, "%s/info", path);
	fd = open(info_path, O_RDONLY);
	free(info_path);

	if (fd != -1) {
		if (read(fd, sig, UFTRACE_MAGIC_LEN) != UFTRACE_MAGIC_LEN) {
			/*
			 * partial read() will return false anyway
			 * since memcmp() below cannot success.
			 */
		}
		close(fd);
		return !memcmp(sig, UFTRACE_MAGIC_STR, UFTRACE_MAGIC_LEN);
	}

	/* if "info" file is missing, also check that there is "default.opts" */
	xasprintf(&info_path, "%s/default.opts", path);
	if (!access(info_path, F_OK))
		ret = true;
	free(info_path);

	return ret;
}

static bool is_empty_directory(const char *path)
{
	DIR *dp = opendir(path);
	struct dirent *ent;
	int ret = true;

	if (dp == NULL)
		return false;

	while ((ent = readdir(dp)) != NULL) {
		if (!strcmp(ent->d_name, ".") || !strcmp(ent->d_name, ".."))
			continue;

		ret = false;
		break;
	}
	closedir(dp);

	return ret;
}

static bool can_remove_directory(const char *path)
{
	if (access(path, F_OK) != 0)
		return false;

	return is_uftrace_directory(path) || is_empty_directory(path);
}

static bool create_default_opts(const char *dirname)
{
	char *opts_str = strv_join(&default_opts, " ");
	char opts_filename[PATH_MAX];
	FILE *fp;
	bool ret = false;

	snprintf(opts_filename, PATH_MAX, "%s/default.opts", dirname);
	fp = fopen(opts_filename, "w");
	if (fp == NULL) {
		pr_dbg("Open failed: %s\n", opts_filename);
		goto out;
	}

	if (opts_str)
		fprintf(fp, "%s\n", opts_str);
	fclose(fp);
	ret = true;

out:
	strv_free(&default_opts);
	free(opts_str);
	return ret;
}

int create_directory(const char *dirname)
{
	int ret = -1;
	char *oldname = NULL;

	xasprintf(&oldname, "%s.old", dirname);

	if (can_remove_directory(dirname)) {
		if (can_remove_directory(oldname)) {
			if (remove_directory(oldname) < 0) {
				pr_warn("removing old directory failed: %m\n");
				goto out;
			}
		}

		if (rename(dirname, oldname) < 0) {
			pr_warn("rename %s -> %s failed: %m\n", dirname, oldname);
			goto out;
		}
	}

	ret = mkdir(dirname, 0755);
	if (ret < 0)
		pr_warn("creating directory failed: %m\n");

	create_default_opts(dirname);

out:
	free(oldname);
	return ret;
}

int chown_directory(const char *dirname)
{
	DIR *dp;
	struct dirent *ent;
	char buf[PATH_MAX];
	char *uidstr;
	char *gidstr;
	uid_t uid;
	gid_t gid;
	int ret = 0;

	/* When invoked with sudo, real uid is also 0.  Use env instead. */
	uidstr = getenv("SUDO_UID");
	gidstr = getenv("SUDO_GID");
	if (uidstr == NULL || gidstr == NULL)
		return 0;

	uid = strtol(uidstr, NULL, 0);
	gid = strtol(gidstr, NULL, 0);

	dp = opendir(dirname);
	if (dp == NULL)
		return -1;

	pr_dbg("chown %s directory to (%d:%d)\n", dirname, (int)uid, (int)gid);

	while ((ent = readdir(dp)) != NULL) {
		if (ent->d_name[0] == '.')
			continue;

		snprintf(buf, sizeof(buf), "%s/%s", dirname, ent->d_name);
		if (chown(buf, uid, gid) < 0)
			ret = -1;
	}

	closedir(dp);
	if (chown(dirname, uid, gid) < 0)
		ret = -1;
	return ret;
}

char *read_exename(void)
{
	int len;
	static char exename[PATH_MAX];

	if (!*exename) {
		len = readlink("/proc/self/exe", exename, sizeof(exename) - 1);
		if (len < 0)
			pr_err("cannot read executable name");

		exename[len] = '\0';
	}

	return exename;
}

clockid_t clock_source = CLOCK_MONOTONIC;

static const struct {
	const char *name;
	clockid_t clock_id;
} trace_clocks[] = {
	{ "mono", CLOCK_MONOTONIC },
	{ "mono_raw", CLOCK_MONOTONIC_RAW },
	{ "boot", CLOCK_BOOTTIME },
};

void setup_clock_id(const char *clock_str)
{
	size_t i;

	for (i = 0; i < ARRAY_SIZE(trace_clocks); i++) {
		if (!strcmp(clock_str, trace_clocks[i].name)) {
			clock_source = trace_clocks[i].clock_id;
			break;
		}
	}
}

bool check_time_range(struct uftrace_time_range *range, uint64_t timestamp)
{
	/* maybe it's called before first timestamp set */
	if (!range->first)
		range->first = timestamp;

	if (range->start) {
		uint64_t start = range->start;

		if (range->start_elapsed)
			start += range->first;

		if (start > timestamp)
			return false;
	}

	if (range->stop) {
		uint64_t stop = range->stop;

		if (range->stop_elapsed)
			stop += range->first;

		if (stop < timestamp)
			return false;
	}

	return true;
}

static int get_digits(uint64_t num)
{
	int digits = 0;

	do {
		num /= 10;
		digits++;
	} while (num != 0);

	return digits;
}

static uint64_t parse_min(uint64_t min, uint64_t decimal, int decimal_places)
{
	uint64_t nsec = min * 60 * NSEC_PER_SEC;

	if (decimal) {
		decimal_places += get_digits(decimal);
		decimal *= 6;

		/* decide a unit from the number of decimal places */
		switch (decimal_places) {
		case 1:
			nsec += decimal * NSEC_PER_SEC;
			break;
		case 2:
			decimal *= 10;
			/* fall through */
		case 3:
			decimal *= 10;
			nsec += decimal * NSEC_PER_MSEC;
			break;
		default:
			break;
		}
	}
	return nsec;
}

uint64_t parse_time(char *arg, int limited_digits)
{
	char *unit, *pos;
	int i, decimal_places = 0, exp = 0;
	uint64_t limited, decimal = 0;
	uint64_t val = strtoull(arg, &unit, 10);

	pos = strchr(arg, '.');
	if (pos != NULL) {
		while (*(++pos) == '0')
			decimal_places++;
		decimal = strtoull(pos, &unit, 10);
	}

	limited = 10;
	for (i = 1; i < limited_digits; i++)
		limited *= 10;
	if (val >= limited)
		pr_err_ns("Limited %d digits (before and after decimal point)\n", limited_digits);
	/* ignore more digits than limited digits before decimal point */
	while (decimal >= limited)
		decimal /= 10;

	/*
	 * if the unit is omitted, it is regarded as default unit 'ns'.
	 * so ignore it before decimal point.
	 */
	if (unit == NULL || *unit == '\0')
		return val;

	if (!strcasecmp(unit, "ns") || !strcasecmp(unit, "nsec"))
		return val;
	else if (!strcasecmp(unit, "us") || !strcasecmp(unit, "usec"))
		exp = 3; /* 10^3*/
	else if (!strcasecmp(unit, "ms") || !strcasecmp(unit, "msec"))
		exp = 6; /* 10^6 */
	else if (!strcasecmp(unit, "s") || !strcasecmp(unit, "sec"))
		exp = 9; /* 10^9 */
	else if (!strcasecmp(unit, "m") || !strcasecmp(unit, "min"))
		return parse_min(val, decimal, decimal_places);
	else
		pr_warn("The unit '%s' isn't supported\n", unit);

	for (i = 0; i < exp; i++)
		val *= 10;

	if (decimal) {
		decimal_places += get_digits(decimal);

		for (i = decimal_places; i < exp; i++)
			decimal *= 10;
		val += decimal;
	}
	return val;
}

uint64_t parse_timestamp(char *arg)
{
	char *sep;
	uint64_t ts, tmp;
	int len;

	tmp = strtoull(arg, &sep, 10);
	ts = tmp * NSEC_PER_SEC;

	if (*sep == '.') {
		arg = sep + 1;
		tmp = strtoull(arg, &sep, 10);

		len = 0;
		while (isdigit(*arg)) {
			arg++;
			len++;
		}

		/* if resolution is lower than nsec */
		while (len < 9) {
			tmp *= 10;
			len++;
		}

		/* if resolution is higher than nsec */
		while (len > 9) {
			tmp /= 10;
			len--;
		}

		ts += tmp;
	}

	return ts;
}

/**
 * strjoin - join two strings with a delimiter
 * @left:  string buffer to join (dynamic allocated, can be NULL)
 * @right: string to join
 * @delim: delimiter inserted between the two
 *
 * This function returns a new string that concatenates @left and @right
 * with @delim.  Note that if @left is #NULL, @delim will be omitted and
 * a copy of @right will be returned.  @left must be dynamically allocated
 * buffer so that it can be passed to realloc.
 */
char *strjoin(char *left, char *right, const char *delim)
{
	size_t llen = left ? strlen(left) : 0;
	size_t rlen = strlen(right);
	size_t dlen = strlen(delim);
	size_t len = llen + rlen + 1;
	char *new;

	if (left)
		len += dlen;

	new = xrealloc(left, len);

	if (left)
		strcpy(new + llen, delim);

	strcpy(new + len - rlen - 1, right);
	return new;
}

/**
 * str_ltrim - to trim left spaces
 * @str: input string
 *
 * This function make @str to left trimmed @str
 */
char *str_ltrim(char *str)
{
	if (!str)
		return NULL;
	while (isspace((unsigned char)*str)) {
		str++;
	}
	return str;
}

/**
 * str_rtrim - to trim right spaces
 * @str: input string
 *
 * This function make @str to right trimmed @str
 */
char *str_rtrim(char *str)
{
	char *p = strchr(str, '\0');
	while (--p >= str && isspace(*p))
		;
	*(p + 1) = '\0';
	return str;
}

/**
 * strv_split - split given string and construct a string vector
 * @strv:  string vector
 * @str:   input string
 * @delim: delimiter to split the string
 *
 * This function builds a string vector using @str split by @delim.
 */
void strv_split(struct strv *strv, const char *str, const char *delim)
{
	int c = 1;
	char *saved_str = xstrdup(str);
	char *tmp, *pos;
	size_t len = strlen(delim);

	tmp = saved_str;
	while ((pos = strstr(tmp, delim)) != NULL) {
		tmp = pos + len;
		c++;
	}

	strv->nr = c;
	strv->p = xcalloc(c + 1, sizeof(*strv->p)); /* including NULL at last */

	c = 0;
	tmp = saved_str;

	while ((pos = strstr(tmp, delim)) != NULL) {
		*pos = '\0';
		strv->p[c++] = xstrdup(tmp);
		tmp = pos + len;
	}
	strv->p[c] = xstrdup(tmp);

	free(saved_str);
}

/**
 * strv_copy - copy argc and argv to string vector
 * @strv: string vector
 * @argc: number of input strings
 * @argv: array of strings
 *
 * This function build a string vector using @argc and @argv.
 */
void strv_copy(struct strv *strv, int argc, char *argv[])
{
	int i;

	strv->nr = argc;
	strv->p = xcalloc(argc + 1, sizeof(*strv->p));

	for (i = 0; i < argc; i++)
		strv->p[i] = xstrdup(argv[i]);
}

/**
 * strv_append - add a string to string vector
 * @strv: string vector
 * @str:  input string
 *
 * This function add @str to @strv.
 */
void strv_append(struct strv *strv, const char *str)
{
	strv->p = xrealloc(strv->p, (strv->nr + 2) * sizeof(*strv->p));

	strv->p[strv->nr + 0] = xstrdup(str);
	strv->p[strv->nr + 1] = NULL;
	strv->nr++;
}

/**
 * str_replace - replace a string to a new one
 * @strv: string vector
 * @idx:  index of the (old) string
 * @str:  new string to be replaced
 *
 * This function replaces @strv[@idx] to @str.  Callers should not use the old
 * string after this function.
 */
void strv_replace(struct strv *strv, int idx, const char *str)
{
	free(strv->p[idx]);
	strv->p[idx] = xstrdup(str);
}

/**
 * strv_join - make a string with string vector
 * @strv:  string vector
 * @delim: delimiter inserted between strings
 *
 * This function returns a new string that concatenates all strings in
 * @strv with @delim.  Note that if @strv contains a single string,
 * @delim will be omitted and a copy of @right will be returned.
 */
char *strv_join(struct strv *strv, const char *delim)
{
	int i;
	char *s;
	char *str = NULL;

	strv_for_each(strv, s, i)
		str = strjoin(str, s, delim);

	return str;
}

/**
 * strv_free - release strings in string vector
 * @strv: string vector
 *
 * This function resets @strv and releases all memory in it.
 */
void strv_free(struct strv *strv)
{
	int i;
	char *s;

	strv_for_each(strv, s, i)
		free(s);

	free(strv->p);
	strv->p = NULL;
	strv->nr = 0;
}

#define QUOTE '\''
#define DQUOTE '"'
#define QUOTES "\'\""

/* escape double-quote with backslash - caller should free the returned string */
char *json_quote(char *str, int *len)
{
	char *p = str;
	int quote = 0;
	int i, k;
	int orig_len = *len;

	/* find number of necessary escape */
	while ((p = strchr(p, DQUOTE)) != NULL) {
		quote++;
		p++;
	}

	p = xmalloc(orig_len + quote + 1);

	/* escape double-quotes */
	for (i = k = 0; i < orig_len; i++, k++) {
		if (str[i] == DQUOTE) {
			p[k++] = '\\';
			p[k] = DQUOTE;
		}
		else
			p[k] = str[i];
	}
	p[k] = '\0';
	*len = k;

	return p;
}

static int setargs(char *args, char **argv)
{
	int count = 0;

	while (*args) {
		/* ignore spaces */
		if (isspace(*args)) {
			++args;
			continue;
		}

		/* consider quotes and update argv */
		if (*args == QUOTE) {
			++args;
			if (*args == QUOTE)
				continue;
			if (argv)
				argv[count] = args;
			while (*args && *args != QUOTE)
				++args;
			if (argv && *args)
				*args = ' ';
		}
		else if (*args == DQUOTE) {
			++args;
			if (*args == DQUOTE)
				continue;
			if (argv)
				argv[count] = args;
			while (*args && *args != DQUOTE)
				++args;
			if (argv && *args)
				*args = ' ';
		}
		else if (*args == '#') {
			/* ignore comment line */
			while (*args != '\n' && *args != '\0')
				++args;
			continue;
		}
		else if (argv) {
			argv[count] = args;
		}
		/* read characters until '\0' or space */
		while (*args && !isspace(*args))
			++args;
		/* set '\0' rather than space */
		if (argv && *args)
			*args++ = '\0';
		/* count up argument */
		count++;
	}

	return count;
}

#undef QUOTE
#undef DQUOTE

/**
 * parse_cmdline - parse given string to be executed via execvp(3)
 * @cmd:  full command line
 * @argc: pointer to number of arguments
 *
 * This function parses @cmd and split it into an array of string
 * to be executed by exec(3) like argv[] in main().  The @argc
 * will be set to number of argument parsed if it's non-NULL.
 * The resulting array contains a copy of input string (@cmd) in
 * the first element which other elements point to.  It returns a
 * pointer to the second element so that it can be used directly
 * in other functions like exec(3).
 *
 * The returned array should be freed by free_parsed_cmdline().
 */
char **parse_cmdline(char *cmd, int *argc)
{
	char **argv = NULL;
	char *cmd_dup = NULL;
	int argn = 0;

	if (!cmd || !*cmd)
		return NULL;

	/* duplicate cmdline to map to argv with modification */
	cmd_dup = xstrdup(cmd);
	/* get count of arguments */
	argn = setargs(cmd_dup, NULL);
	/* create argv array. +1 for cmd_dup, +1 for the last NULL */
	argv = xcalloc(argn + 2, sizeof(char *));

	/* remember cmd_dup to free later */
	argv[0] = cmd_dup;
	/* actual assigning of arguments to argv + 1 */
	argn = setargs(cmd_dup, &argv[1]);
	/* set last one as null for execv */
	argv[argn + 1] = NULL;

	/* pass count of arguments */
	if (argc)
		*argc = argn;

	/* returns +1 addr to hide cmd_dup address */
	return &argv[1];
}

/**
 * free_parsed_cmdline - free memory that was allocated by parse_cmdline
 * @argv: result of parse_cmdline
 *
 * The parse_cmdline uses internal allocation logic so,
 * the pointer should be freed by this function rather than free.
 */
void free_parsed_cmdline(char **argv)
{
	if (argv) {
		/* parse_cmdline() passes &argv[1] */
		argv--;

		/* free cmd_dup */
		free(argv[0]);
		/* free original argv */
		free(argv);
	}
}

/**
 * absolute_dirname - return the canonicalized absolute dirname
 *
 * @path: pathname string that can be either absolute or relative path
 * @resolved_path: input buffer that will store absolute dirname
 *
 * This function parses the @path and sets absolute dirname to @resolved_path.
 *
 * Given @path sets @resolved_path as follows:
 *
 *    @path                   | @resolved_path
 *   -------------------------+----------------
 *    mcount.py               | $PWD
 *    tests/mcount.py         | $PWD/tests
 *    ./tests/mcount.py       | $PWD/./tests
 *    /root/uftrace/mcount.py | /root/uftrace
 */
char *absolute_dirname(const char *path, char *resolved_path)
{
	if (realpath(path, resolved_path) == NULL)
		return NULL;
	dirname(resolved_path);

	return resolved_path;
}

char *uftrace_strerror(int errnum, char *buf, size_t buflen)
{
	long result = (long)strerror_r(errnum, buf, buflen);

	if (result == 0)
		/* XSI-compliant strerror_r succeed */
		return buf;
	else if (result < 4096) {
		/* XSI-compliant strerror_r failed */
		snprintf(buf, buflen, "error: %d", errnum);
		return buf;
	}
	else
		/* GNU-specific strerror_r */
		return (char *)result;
}

void stacktrace(void)
{
#ifdef HAVE_LIBUNWIND
	const int max_depth = 64;
	int i = 0;
	bool out = false;
	unw_cursor_t cursor;
	unw_context_t context;

	unw_getcontext(&context);
	unw_init_local(&cursor, &context);

	pr_yellow("Stack trace:\n");
	while (unw_step(&cursor) && i < max_depth && !out) {
		char symbol[256] = { "<unknown>" };
		char *name = symbol;
		unw_word_t ip, off;

		unw_get_reg(&cursor, UNW_REG_IP, &ip);
		if (!ip)
			break;

		if (!unw_get_proc_name(&cursor, symbol, sizeof(symbol), &off))
			name = symbol;

		pr_yellow("  #%-2d 0x%012" PRIxPTR " %s + 0x%" PRIxPTR "\n", ++i, (uintptr_t)(ip),
			  name, (uintptr_t)(off));

		/*
		 * plt_hooker goes into infinite loop with unwinding.
		 * so stop following the stack below.
		 */
		if (!strcmp(name, "plt_hooker"))
			out = true;

		if (name != symbol)
			free(name);
	}
#endif
	pr_out("\n");
}

int copy_file(const char *path_in, const char *path_out)
{
	char buf[4096];
	FILE *ifp, *ofp;
	int n;

	ifp = fopen(path_in, "r");
	if (ifp == NULL) {
		pr_warn("cannot open file: %s: %m\n", path_in);
		return -1;
	}

	ofp = fopen(path_out, "w");
	if (ofp == NULL) {
		pr_warn("cannot create file: %s: %m\n", path_out);
		fclose(ifp);
		return -1;
	}

	while (true) {
		n = fread(buf, 1, sizeof(buf), ifp);
		if (n == 0)
			break;

		if (fwrite_all(buf, n, ofp) < 0) {
			pr_warn("cannot write to file: %m\n");
			break;
		}
	}

	fclose(ifp);
	fclose(ofp);
	return 0;
}

#ifdef UNIT_TEST
TEST_CASE(utils_parse_cmdline)
{
	char **cmdv;
	int argc = -1;

	cmdv = parse_cmdline(NULL, NULL);
	TEST_EQ(cmdv, NULL);

	pr_dbg("parse_cmdline() should handle quoted stringss\n");
	cmdv = parse_cmdline("uftrace recv --run-cmd 'uftrace replay'", &argc);
	TEST_NE(cmdv, NULL);
	TEST_EQ(argc, 4);
	TEST_STREQ(cmdv[0], "uftrace");
	TEST_STREQ(cmdv[1], "recv");
	TEST_STREQ(cmdv[2], "--run-cmd");
	TEST_STREQ(cmdv[3], "uftrace replay");
	free_parsed_cmdline(cmdv);

	return TEST_OK;
}

TEST_CASE(utils_strv)
{
	struct strv strv = STRV_INIT;
	char *s;
	int i;

	const char test_str[] = "abc;def;xyz";
	const char *test_array[] = { "abc", "def", "xyz" };

	TEST_EQ(strv.nr, 0);
	TEST_EQ(strv.p, NULL);

	pr_dbg("split string into a vector using ';' delimiter\n");
	strv_split(&strv, test_str, ";");
	strv_for_each(&strv, s, i)
		TEST_STREQ(s, test_array[i]);

	pr_dbg("join the string vector into a single string\n");
	s = strv_join(&strv, ";");
	TEST_STREQ(s, test_str);
	free(s);

	TEST_EQ(strv.nr, 3);
	strv_free(&strv);
	TEST_EQ(strv.nr, 0);

	pr_dbg("append string items to string vector\n");
	for (i = 0; i < 3; i++) {
		strv_append(&strv, test_array[i]);
		TEST_STREQ(strv.p[i], test_array[i]);
		TEST_EQ(strv.nr, i + 1);
	}

	s = strv_join(&strv, ";");
	TEST_STREQ(s, test_str);
	free(s);

	TEST_EQ(strv.nr, 3);
	strv_free(&strv);

	return TEST_OK;
}

TEST_CASE(utils_parse_time)
{
	struct TC {
		char *arg;
		int limit;
		uint64_t val;
	} tc[] = {
		{ "10.123ns", 5, 10 },
		{ "50.987us", 5, 50987 },
		{ "100.654ms", 5, 100654000 },
		{ "123.123s", 5, 123123000000 },
		{ "17.1m", 5, 1026000000000 },
		{ "8960070.725168293s", 9, 8960070725168293 },
		{ "8959832.082682731s", 9, 8959832082682731 },
		{ "426883.003490100s", 9, 426883003490100 },
		{ "8107.0641850s", 9, 8107064185000 },
		{ "8107.006418501s", 9, 8107006418501 },
	};
	uint64_t time;
	int i;

	pr_dbg("parsing time with a unit\n");
	for (i = 0; i < sizeof(tc) / sizeof(struct TC); i++) {
		time = parse_time(tc[i].arg, tc[i].limit);
		TEST_EQ(time, tc[i].val);
	}

	return TEST_OK;
}

TEST_CASE(utils_parse_timestamp)
{
	struct TC {
		char *arg;
		uint64_t val;
	} tc[] = {
		{ "8960070.725168293", 8960070725168293 },
		{ "8959832.082682731", 8959832082682731 },
		{ "426883.003490100", 426883003490100 },
		{ "8107.0641850", 8107064185000 },
		{ "8107.006418501234567890", 8107006418501 },
	};
	uint64_t time;
	int i;

	pr_dbg("parsing timestamp in various precisions with leading zeros\n");
	for (i = 0; i < sizeof(tc) / sizeof(struct TC); i++) {
		time = parse_timestamp(tc[i].arg);
		TEST_EQ(time, tc[i].val);
	}

	return TEST_OK;
}

#endif /* UNIT_TEST */
