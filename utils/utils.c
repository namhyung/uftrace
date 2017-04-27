#include <stdio.h>
#include <dirent.h>
#include <stdbool.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <sys/uio.h>
#include <sys/stat.h>

#include "utils/utils.h"


volatile bool uftrace_done;

void sighandler(int sig)
{
	uftrace_done = true;
}

void setup_signal(void)
{
	signal(SIGINT,  sighandler);
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

		buf  += ret;
		size -= ret;
		off  += ret;
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

		buf  += ret;
		size -= ret;
	}
	return 0;
}

int write_all(int fd, void *buf, size_t size)
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
		iov->iov_len  -= ret;
	}
	return 0;
}

int remove_directory(char *dirname)
{
	DIR *dp;
	struct dirent *ent;
	char buf[PATH_MAX];
	int saved_errno = 0;
	int ret = 0;

	dp = opendir(dirname);
	if (dp == NULL)
		return -1;

	pr_dbg("removing %s directory\n", dirname);

	while ((ent = readdir(dp)) != NULL) {
		if (ent->d_name[0] == '.')
			continue;

		snprintf(buf, sizeof(buf), "%s/%s", dirname, ent->d_name);
		if (unlink(buf) < 0) {
			saved_errno = errno;
			ret = -1;
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

int create_directory(char *dirname)
{
	int ret = -1;
	char *oldname = NULL;

	xasprintf(&oldname, "%s.old", dirname);

	if (!access(oldname, F_OK)) {
		if (remove_directory(oldname) < 0) {
			pr_log("removing old directory failed: %m\n");
			goto out;
		}
	}

	if (!access(dirname, F_OK) && rename(dirname, oldname) < 0) {
		pr_log("rename %s -> %s failed: %m\n", dirname, oldname);
		goto out;
	}

	ret = mkdir(dirname, 0755);
	if (ret < 0)
		pr_log("creating directory failed: %m\n");

out:
	free(oldname);
	return ret;
}

int chown_directory(char *dirname)
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
	static char exename[4096];

	if (!*exename) {
		len = readlink("/proc/self/exe", exename, sizeof(exename)-1);
		if (len < 0)
			pr_err("cannot read executable name");

		exename[len] = '\0';
	}

	return exename;
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
	uint64_t val = strtoull(arg, &unit, 0);

	pos = strchr(arg, '.');
	if (pos != NULL) {
		while (*(++pos) == '0')
			decimal_places++;
		decimal = strtoull(pos, &unit, 0);
	}

	limited = 10;
	for (i = 1; i < limited_digits; i++)
		limited *= 10;
	if (val >= limited)
		pr_err_ns("Limited %d digits (before and after decimal point)\n",
			  limited_digits);
	/* ignore more digits than limited digits before decimal point */
	while (decimal >= limited)
		decimal /=10;

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

char * strjoin(char *left, char *right, char *delim)
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
