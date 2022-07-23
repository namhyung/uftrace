/*
 * uftrace info command related routines
 *
 * Copyright (C) 2014-2018, LG Electronics, Namhyung Kim <namhyung.kim@lge.com>
 *
 * Released under the GPL v2.
 */

#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/utsname.h>
#include <time.h>
#include <unistd.h>

#include "libmcount/mcount.h"
#include "uftrace.h"
#include "utils/filter.h"
#include "utils/fstack.h"
#include "utils/symbol.h"
#include "utils/utils.h"
#include "version.h"

struct read_handler_arg {
	struct uftrace_data *handle;
	char buf[PATH_MAX];
};

struct fill_handler_arg {
	int fd;
	int exit_status;
	struct uftrace_opts *opts;
	struct rusage *rusage;
	char *elapsed_time;
	char buf[PATH_MAX];
};

static char *copy_info_str(char *src)
{
	char *dst = xstrdup(src);
	size_t len = strlen(dst);

	if (dst[len - 1] == '\n')
		dst[len - 1] = '\0';

	return dst;
}

static int fill_exe_name(void *arg)
{
	struct fill_handler_arg *fha = arg;
	char *exename;

	exename = realpath(fha->opts->exename, fha->buf);
	if (exename == NULL)
		exename = fha->opts->exename;

	return dprintf(fha->fd, "exename:%s\n", exename);
}

static int read_exe_name(void *arg)
{
	struct read_handler_arg *rha = arg;
	struct uftrace_data *handle = rha->handle;
	struct uftrace_info *info = &handle->info;
	char *buf = rha->buf;

	if (fgets(buf, sizeof(rha->buf), handle->fp) == NULL)
		return -1;

	if (strncmp(buf, "exename:", 8))
		return -1;

	info->exename = copy_info_str(&buf[8]);

	return 0;
}

static int fill_exe_build_id(void *arg)
{
	struct fill_handler_arg *fha = arg;
	char buf[BUILD_ID_STR_SIZE];

	if (read_build_id(fha->opts->exename, buf, sizeof(buf)) < 0) {
		pr_dbg("cannot read build-id section\n");
		return -1;
	}

	return dprintf(fha->fd, "build_id:%s\n", buf);
}

static int convert_to_int(unsigned char hex)
{
	if (!isxdigit(hex))
		return -1;

	if (hex >= '0' && hex <= '9')
		return hex - '0';
	if (hex >= 'a' && hex <= 'f')
		return hex - 'a' + 10;
	if (hex >= 'A' && hex <= 'F')
		return hex - 'A' + 10;

	return -1;
}

static int read_exe_build_id(void *arg)
{
	struct read_handler_arg *rha = arg;
	struct uftrace_data *handle = rha->handle;
	struct uftrace_info *info = &handle->info;
	char build_id_str[BUILD_ID_STR_SIZE];
	char *buf = rha->buf;
	int i;

	if (fgets(buf, sizeof(rha->buf), handle->fp) == NULL)
		return -1;

	if (strncmp(buf, "build_id:", 9))
		return -1;

	memcpy(build_id_str, &buf[9], BUILD_ID_STR_SIZE - 1);
	build_id_str[BUILD_ID_STR_SIZE - 1] = '\0';

	for (i = 0; i < BUILD_ID_SIZE; i++) {
		int c1 = convert_to_int(build_id_str[i * 2]);
		int c2 = convert_to_int(build_id_str[i * 2 + 1]);

		if (c1 < 0 || c2 < 0)
			return -1;

		info->build_id[i] = c1 << 4 | c2;
	}

	return 0;
}

static int fill_exit_status(void *arg)
{
	struct fill_handler_arg *fha = arg;

	return dprintf(fha->fd, "exit_status:%d\n", fha->exit_status);
}

static int read_exit_status(void *arg)
{
	struct read_handler_arg *rha = arg;
	struct uftrace_data *handle = rha->handle;
	struct uftrace_info *info = &handle->info;
	char *buf = rha->buf;

	if (fgets(buf, sizeof(rha->buf), handle->fp) == NULL)
		return -1;

	if (strncmp(buf, "exit_status:", 12))
		return -1;

	sscanf(&buf[12], "%d", &info->exit_status);
	return 0;
}

static int fill_cmdline(void *arg)
{
	struct fill_handler_arg *fha = arg;
	char *buf = fha->buf;
	FILE *fp;
	int err;
	int ret;
	int i;
	char *p;

	fp = fopen("/proc/self/cmdline", "r");
	if (fp == NULL)
		return -1;

	ret = fread(buf, 1, sizeof(fha->buf), fp);
	err = ferror(fp);
	fclose(fp);

	if (!ret && err)
		return -1;

	/* cmdline separated by NUL character - convert to space */
	for (i = 0, p = buf; i < ret; i++, p++) {
		if (*p == '\0' || *p == '\n')
			*p = ' ';
	}

	buf[sizeof(fha->buf) - 1] = '\0';

	p = json_quote(buf, &ret);
	p[ret - 1] = '\n';

	if ((write(fha->fd, "cmdline:", 8) < 8) || (write(fha->fd, p, ret) < ret)) {
		free(p);
		return -1;
	}

	free(p);
	return ret;
}

static int read_cmdline(void *arg)
{
	struct read_handler_arg *rha = arg;
	struct uftrace_data *handle = rha->handle;
	struct uftrace_info *info = &handle->info;
	char *buf = rha->buf;

	if (fgets(buf, sizeof(rha->buf), handle->fp) == NULL)
		return -1;

	if (strncmp(buf, "cmdline:", 8))
		return -1;

	info->cmdline = copy_info_str(&buf[8]);

	return 0;
}

#define NUM_CPU_INFO 2

static int fill_cpuinfo(void *arg)
{
	struct fill_handler_arg *fha = arg;
	unsigned long nr_possible;
	unsigned long nr_online;

	nr_possible = sysconf(_SC_NPROCESSORS_CONF);
	nr_online = sysconf(_SC_NPROCESSORS_ONLN);

	dprintf(fha->fd, "cpuinfo:lines=%d\n", NUM_CPU_INFO);
	dprintf(fha->fd, "cpuinfo:nr_cpus=%lu / %lu (online/possible)\n", nr_online, nr_possible);

	return arch_fill_cpuinfo_model(fha->fd);
}

static int read_cpuinfo(void *arg)
{
	struct read_handler_arg *rha = arg;
	struct uftrace_data *handle = rha->handle;
	struct uftrace_info *info = &handle->info;
	char *buf = rha->buf;
	int i, lines;

	if (fgets(buf, sizeof(rha->buf), handle->fp) == NULL)
		return -1;

	if (strncmp(buf, "cpuinfo:", 8))
		return -1;

	if (sscanf(&buf[8], "lines=%d\n", &lines) == EOF)
		return -1;

	/* old data might have fewer lines */
	if (lines > NUM_CPU_INFO)
		return -1;

	for (i = 0; i < lines; i++) {
		if (fgets(buf, sizeof(rha->buf), handle->fp) == NULL)
			return -1;

		if (strncmp(buf, "cpuinfo:", 8))
			return -1;

		if (!strncmp(&buf[8], "nr_cpus=", 8)) {
			sscanf(&buf[8], "nr_cpus=%d / %d\n", &info->nr_cpus_online,
			       &info->nr_cpus_possible);
		}
		else if (!strncmp(&buf[8], "desc=", 5)) {
			info->cpudesc = copy_info_str(&buf[13]);

			/* guess CPU arch from the description */
			if (!strncmp(info->cpudesc, "ARMv6", 5) ||
			    !strncmp(info->cpudesc, "ARMv7", 5)) {
				handle->arch = UFT_CPU_ARM;
			}
			else if (!strncmp(info->cpudesc, "ARM64", 5)) {
				handle->arch = UFT_CPU_AARCH64;
			}
			else if (data_is_lp64(handle)) {
				handle->arch = UFT_CPU_X86_64;
			}
			else {
				handle->arch = UFT_CPU_I386;
			}
		}
	}

	return 0;
}

static int fill_meminfo(void *arg)
{
	struct fill_handler_arg *fha = arg;
	long mem_total = 0;
	long mem_total_small;
	long mem_free = 0;
	long mem_free_small;
	char *units[] = { "KB", "MB", "GB", "TB" };
	char *unit;
	char *buf = fha->buf;
	size_t i;
	FILE *fp;

	fp = fopen("/proc/meminfo", "r");
	if (fp == NULL)
		return -1;

	while (fgets(buf, sizeof(fha->buf), fp) != NULL) {
		if (!strncmp(buf, "MemTotal:", 9))
			sscanf(&buf[10], "%ld", &mem_total);
		else if (!strncmp(buf, "MemFree:", 8))
			sscanf(&buf[9], "%ld", &mem_free);
		else
			break;
	}
	fclose(fp);

	mem_total_small = (mem_total % 1024) / 103; /* 103 ~= 1024 / 10 */
	mem_free_small = (mem_free % 1024) / 103;

	for (i = 0; i < ARRAY_SIZE(units); i++) {
		unit = units[i];

		if (mem_total < 1024)
			break;

		mem_total_small = (mem_total % 1024) / 103;
		mem_free_small = (mem_free % 1024) / 103;
		mem_total >>= 10;
		mem_free >>= 10;
	}

	dprintf(fha->fd, "meminfo:%ld.%ld / %ld.%ld %s (free / total)\n", mem_free, mem_free_small,
		mem_total, mem_total_small, unit);

	return 0;
}

static int read_meminfo(void *arg)
{
	struct read_handler_arg *rha = arg;
	struct uftrace_data *handle = rha->handle;
	struct uftrace_info *info = &handle->info;
	char *buf = rha->buf;

	if (fgets(buf, sizeof(rha->buf), handle->fp) == NULL)
		return -1;

	if (strncmp(buf, "meminfo:", 8))
		return -1;

	info->meminfo = copy_info_str(&buf[8]);

	return 0;
}

#define NUM_OS_INFO 3

static int fill_osinfo(void *arg)
{
	struct fill_handler_arg *fha = arg;
	struct utsname uts;
	char *buf = fha->buf;
	FILE *fp;
	int ret = -1;

	uname(&uts);

	dprintf(fha->fd, "osinfo:lines=%d\n", NUM_OS_INFO);
	dprintf(fha->fd, "osinfo:kernel=%s %s\n", uts.sysname, uts.release);
	dprintf(fha->fd, "osinfo:hostname=%s\n", uts.nodename);

	fp = fopen("/etc/os-release", "r");
	if (fp != NULL) {
		while (fgets(buf, sizeof(fha->buf), fp) != NULL) {
			if (!strncmp(buf, "PRETTY_NAME=", 12)) {
				dprintf(fha->fd, "osinfo:distro=%s", &buf[12]);
				ret = 0;
				break;
			}
		}
		fclose(fp);
		return ret;
	}

	fp = fopen("/etc/lsb-release", "r");
	if (fp != NULL) {
		while (fgets(buf, sizeof(fha->buf), fp) != NULL) {
			if (!strncmp(buf, "DISTRIB_DESCRIPTION=", 20)) {
				dprintf(fha->fd, "osinfo:distro=%s", &buf[20]);
				ret = 0;
				break;
			}
		}
		fclose(fp);
		return ret;
	}

	dprintf(fha->fd, "osinfo:distro=\"Unknown\"\n");
	return 0;
}

static int read_osinfo(void *arg)
{
	struct read_handler_arg *rha = arg;
	struct uftrace_data *handle = rha->handle;
	struct uftrace_info *info = &handle->info;
	char *buf = rha->buf;
	int i, lines;

	if (fgets(buf, sizeof(rha->buf), handle->fp) == NULL)
		return -1;

	if (strncmp(buf, "osinfo:", 7))
		return -1;

	if (sscanf(&buf[7], "lines=%d\n", &lines) == EOF)
		return -1;

	/* old data might have fewer lines */
	if (lines > NUM_OS_INFO)
		return -1;

	for (i = 0; i < lines; i++) {
		if (fgets(buf, sizeof(rha->buf), handle->fp) == NULL)
			return -1;

		if (strncmp(buf, "osinfo:", 7))
			return -1;

		if (!strncmp(&buf[7], "kernel=", 7)) {
			info->kernel = copy_info_str(&buf[14]);
		}
		else if (!strncmp(&buf[7], "hostname=", 9)) {
			info->hostname = copy_info_str(&buf[16]);
		}
		else if (!strncmp(&buf[7], "distro=", 7)) {
			info->distro = copy_info_str(&buf[14]);
		}
	}

	return 0;
}

struct tid_list {
	int nr;
	int *tid;
};

static int build_tid_list(struct uftrace_task *t, void *arg)
{
	struct tid_list *list = arg;

	list->nr++;
	list->tid = xrealloc(list->tid, list->nr * sizeof(*list->tid));

	list->tid[list->nr - 1] = t->tid;
	return 0;
}

#define NUM_TASK_INFO 2

static int fill_taskinfo(void *arg)
{
	struct fill_handler_arg *fha = arg;
	bool first = true;
	struct tid_list tlist = {
		.nr = 0,
	};
	struct uftrace_session_link link = {
		.root = RB_ROOT,
		.tasks = RB_ROOT,
	};
	int i;

	if (read_task_txt_file(&link, fha->opts->dirname, fha->opts->dirname, false, false, false) <
		    0 &&
	    read_task_file(&link, fha->opts->dirname, false, false, false) < 0)
		return -1;

	walk_tasks(&link, build_tid_list, &tlist);

	dprintf(fha->fd, "taskinfo:lines=%d\n", NUM_TASK_INFO);
	dprintf(fha->fd, "taskinfo:nr_tid=%d\n", tlist.nr);

	dprintf(fha->fd, "taskinfo:tids=");
	for (i = 0; i < tlist.nr; i++) {
		dprintf(fha->fd, "%s%d", first ? "" : ",", tlist.tid[i]);
		first = false;
	}
	dprintf(fha->fd, "\n");

	delete_sessions(&link);
	free(tlist.tid);
	return 0;
}

static int read_taskinfo(void *arg)
{
	struct read_handler_arg *rha = arg;
	struct uftrace_data *handle = rha->handle;
	struct uftrace_info *info = &handle->info;
	int i, lines;
	int ret = -1;
	char *buf = NULL;
	size_t len = 0;

	if (getline(&buf, &len, handle->fp) < 0)
		goto out;

	if (strncmp(buf, "taskinfo:", 9))
		goto out;

	if (sscanf(&buf[9], "lines=%d\n", &lines) == EOF)
		goto out;

	/* old data might have fewer lines */
	if (lines > NUM_TASK_INFO)
		return -1;

	for (i = 0; i < lines; i++) {
		if (getline(&buf, &len, handle->fp) < 0)
			goto out;

		if (strncmp(buf, "taskinfo:", 9))
			goto out;

		if (!strncmp(&buf[9], "nr_tid=", 7)) {
			info->nr_tid = strtol(&buf[16], NULL, 10);
		}
		else if (!strncmp(&buf[9], "tids=", 5)) {
			char *tids_str = &buf[14];
			char *endp = tids_str;
			int *tids = xcalloc(sizeof(*tids), info->nr_tid);
			int nr_tid = 0;

			while (*endp != '\n') {
				int tid = strtol(tids_str, &endp, 10);
				tids[nr_tid++] = tid;

				if (*endp != ',' && *endp != '\n') {
					free(tids);
					goto out;
				}

				tids_str = endp + 1;
			}
			info->tids = tids;

			ASSERT(nr_tid == info->nr_tid);
		}
		else
			goto out;
	}
	ret = 0;
out:
	free(buf);
	return ret;
}

#define NUM_USAGE_INFO 6

static int fill_usageinfo(void *arg)
{
	struct fill_handler_arg *fha = arg;
	struct rusage *r = fha->rusage;
	struct rusage zero = {};

	if (!r || !memcmp(r, &zero, sizeof(*r)))
		return -1;

	dprintf(fha->fd, "usageinfo:lines=%d\n", NUM_USAGE_INFO);
	dprintf(fha->fd, "usageinfo:systime=%lu.%06lu\n", r->ru_stime.tv_sec, r->ru_stime.tv_usec);
	dprintf(fha->fd, "usageinfo:usrtime=%lu.%06lu\n", r->ru_utime.tv_sec, r->ru_utime.tv_usec);
	dprintf(fha->fd, "usageinfo:ctxsw=%ld / %ld (voluntary / involuntary)\n", r->ru_nvcsw,
		r->ru_nivcsw);
	dprintf(fha->fd, "usageinfo:maxrss=%ld\n", r->ru_maxrss);
	dprintf(fha->fd, "usageinfo:pagefault=%ld / %ld (major / minor)\n", r->ru_majflt,
		r->ru_minflt);
	dprintf(fha->fd, "usageinfo:iops=%ld / %ld (read / write)\n", r->ru_inblock, r->ru_oublock);
	return 0;
}

static int read_usageinfo(void *arg)
{
	struct read_handler_arg *rha = arg;
	struct uftrace_data *handle = rha->handle;
	struct uftrace_info *info = &handle->info;
	char *buf = rha->buf;
	int i, lines;

	if (fgets(buf, sizeof(rha->buf), handle->fp) == NULL)
		return -1;

	if (strncmp(buf, "usageinfo:", 10))
		return -1;

	if (sscanf(&buf[10], "lines=%d\n", &lines) == EOF)
		return -1;

	/* old data might have fewer lines */
	if (lines > NUM_USAGE_INFO)
		return -1;

	for (i = 0; i < lines; i++) {
		if (fgets(buf, sizeof(rha->buf), handle->fp) == NULL)
			return -1;

		if (strncmp(buf, "usageinfo:", 10))
			return -1;

		if (!strncmp(&buf[10], "systime=", 8))
			sscanf(&buf[18], "%lf", &info->stime);
		else if (!strncmp(&buf[10], "usrtime=", 8))
			sscanf(&buf[18], "%lf", &info->utime);
		else if (!strncmp(&buf[10], "ctxsw=", 6))
			sscanf(&buf[16], "%ld / %ld", &info->vctxsw, &info->ictxsw);
		else if (!strncmp(&buf[10], "maxrss=", 7))
			sscanf(&buf[17], "%ld", &info->maxrss);
		else if (!strncmp(&buf[10], "pagefault=", 10))
			sscanf(&buf[20], "%ld / %ld", &info->major_fault, &info->minor_fault);
		else if (!strncmp(&buf[10], "iops=", 5))
			sscanf(&buf[15], "%ld / %ld", &info->rblock, &info->wblock);
	}
	return 0;
}

static int fill_loadinfo(void *arg)
{
	struct fill_handler_arg *fha = arg;
	FILE *fp = fopen("/proc/loadavg", "r");
	float loadavg[3];

	if (fp == NULL)
		return -1;

	if (fscanf(fp, "%f %f %f", &loadavg[0], &loadavg[1], &loadavg[2]) != 3) {
		fclose(fp);
		return -1;
	}

	dprintf(fha->fd, "loadinfo:%.02f / %.02f / %.02f\n", loadavg[0], loadavg[1], loadavg[2]);

	fclose(fp);
	return 0;
}

static int read_loadinfo(void *arg)
{
	struct read_handler_arg *rha = arg;
	struct uftrace_data *handle = rha->handle;
	struct uftrace_info *info = &handle->info;
	char *buf = rha->buf;

	if (fgets(buf, sizeof(rha->buf), handle->fp) == NULL)
		return -1;

	if (strncmp(buf, "loadinfo:", 9))
		return -1;

	sscanf(&buf[9], "%f / %f / %f", &info->load1, &info->load5, &info->load15);
	return 0;
}

#define MAX_ARGSPEC_INFO 6

static int fill_arg_spec(void *arg)
{
	struct fill_handler_arg *fha = arg;
	char *argspec = fha->opts->args;
	char *retspec = fha->opts->retval;
	int n;

	n = extract_trigger_args(&argspec, &retspec, fha->opts->trigger);
	if (n == 0 && !fha->opts->auto_args)
		return -1;

	dprintf(fha->fd, "argspec:lines=%d\n", n + 3 + !!fha->opts->auto_args);
	if (argspec) {
		dprintf(fha->fd, "argspec:%s\n", argspec);
		free(argspec);
	}
	if (retspec) {
		dprintf(fha->fd, "retspec:%s\n", retspec);
		free(retspec);
	}

	dprintf(fha->fd, "argauto:%s\n", get_auto_argspec_str());
	dprintf(fha->fd, "retauto:%s\n", get_auto_retspec_str());
	dprintf(fha->fd, "enumauto:%s\n", get_auto_enum_str());

	if (fha->opts->auto_args)
		dprintf(fha->fd, "auto-args:1\n");

	return 0;
}

static int read_arg_spec(void *arg)
{
	struct read_handler_arg *rha = arg;
	struct uftrace_data *handle = rha->handle;
	struct uftrace_info *info = &handle->info;
	int i, lines;
	int ret = -1;
	char *buf = NULL;
	size_t len = 0;

	if (getline(&buf, &len, handle->fp) < 0)
		goto out;

	if (strncmp(buf, "argspec:", 8))
		goto out;

	/* old format only has argspec */
	if (strncmp(&buf[8], "lines", 5)) {
		info->argspec = copy_info_str(&buf[8]);
		ret = 0;
		goto out;
	}

	if (sscanf(&buf[8], "lines=%d\n", &lines) == EOF)
		goto out;

	if (lines > MAX_ARGSPEC_INFO)
		return -1;

	for (i = 0; i < lines; i++) {
		if (getline(&buf, &len, handle->fp) < 0)
			goto out;

		if (!strncmp(buf, "argspec:", 8))
			info->argspec = copy_info_str(&buf[8]);
		else if (!strncmp(buf, "retspec:", 8))
			info->retspec = copy_info_str(&buf[8]);
		else if (!strncmp(buf, "argauto:", 8))
			info->autoarg = copy_info_str(&buf[8]);
		else if (!strncmp(buf, "retauto:", 8))
			info->autoret = copy_info_str(&buf[8]);
		else if (!strncmp(buf, "enumauto:", 9))
			info->autoenum = copy_info_str(&buf[9]);
		else if (!strncmp(buf, "auto-args:1", 11))
			info->auto_args_enabled = 1;
		else
			goto out;
	}
	ret = 0;
out:
	free(buf);
	return ret;
}

static int fill_record_date(void *arg)
{
	struct fill_handler_arg *fha = arg;
	time_t current_time;

	time(&current_time);

	dprintf(fha->fd, "record_date:%s", ctime(&current_time));
	dprintf(fha->fd, "elapsed_time:%s\n", fha->elapsed_time);
	return 0;
}

static int read_record_date(void *arg)
{
	struct read_handler_arg *rha = arg;
	struct uftrace_data *handle = rha->handle;
	struct uftrace_info *info = &handle->info;
	char *buf = rha->buf;

	if (fgets(buf, sizeof(rha->buf), handle->fp) == NULL)
		return -1;

	if (strncmp(buf, "record_date:", 12))
		return -1;

	info->record_date = copy_info_str(&buf[12]);

	if (fgets(buf, sizeof(rha->buf), handle->fp) == NULL)
		return -1;

	if (strncmp(buf, "elapsed_time:", 13))
		return -1;

	info->elapsed_time = copy_info_str(&buf[13]);

	return 0;
}

static int fill_pattern_type(void *arg)
{
	struct fill_handler_arg *fha = arg;

	dprintf(fha->fd, "pattern_type:%s\n", get_filter_pattern(fha->opts->patt_type));

	return 0;
}

static int read_pattern_type(void *arg)
{
	struct read_handler_arg *rha = arg;
	struct uftrace_data *handle = rha->handle;
	struct uftrace_info *info = &handle->info;
	char *buf = rha->buf;
	size_t len;

	if (fgets(buf, sizeof(rha->buf), handle->fp) == NULL)
		return -1;

	if (strncmp(buf, "pattern_type:", 13))
		return -1;

	len = strlen(&buf[13]);
	if (buf[13 + len - 1] == '\n')
		buf[13 + len - 1] = '\0';

	info->patt_type = parse_filter_pattern(&buf[13]);
	return 0;
}

static int fill_uftrace_version(void *arg)
{
	struct fill_handler_arg *fha = arg;

	return dprintf(fha->fd, "uftrace_version:%s\n", UFTRACE_VERSION);
}

static int read_uftrace_version(void *arg)
{
	struct read_handler_arg *rha = arg;
	struct uftrace_data *handle = rha->handle;
	struct uftrace_info *info = &handle->info;
	char *buf = rha->buf;

	if (fgets(buf, sizeof(rha->buf), handle->fp) == NULL)
		return -1;

	if (strncmp(buf, "uftrace_version:", 16))
		return -1;

	info->uftrace_version = copy_info_str(&buf[16]);

	return 0;
}

struct uftrace_info_handler {
	enum uftrace_info_bits bit;
	int (*handler)(void *arg);
};

void fill_uftrace_info(uint64_t *info_mask, int fd, struct uftrace_opts *opts, int status,
		       struct rusage *rusage, char *elapsed_time)
{
	size_t i;
	off_t offset;
	struct fill_handler_arg arg = {
		.fd = fd,
		.opts = opts,
		.exit_status = status,
		.rusage = rusage,
		.elapsed_time = elapsed_time,
	};
	struct uftrace_info_handler fill_handlers[] = {
		{ EXE_NAME, fill_exe_name },
		{ EXE_BUILD_ID, fill_exe_build_id },
		{ EXIT_STATUS, fill_exit_status },
		{ CMDLINE, fill_cmdline },
		{ CPUINFO, fill_cpuinfo },
		{ MEMINFO, fill_meminfo },
		{ OSINFO, fill_osinfo },
		{ TASKINFO, fill_taskinfo },
		{ USAGEINFO, fill_usageinfo },
		{ LOADINFO, fill_loadinfo },
		{ ARG_SPEC, fill_arg_spec },
		{ RECORD_DATE, fill_record_date },
		{ PATTERN_TYPE, fill_pattern_type },
		{ VERSION, fill_uftrace_version },
	};

	for (i = 0; i < ARRAY_SIZE(fill_handlers); i++) {
		errno = 0;
		offset = lseek(fd, 0, SEEK_CUR);
		if (offset == (off_t)-1 && errno) {
			pr_dbg("skip info due to failed lseek: %m\n");
			continue;
		}

		if (fill_handlers[i].handler(&arg) < 0) {
			/* ignore failed info */
			errno = 0;
			if (lseek(fd, offset, SEEK_SET) == (off_t)-1 && errno)
				pr_warn("fail to reset uftrace info: %m\n");

			continue;
		}
		*info_mask |= (1UL << fill_handlers[i].bit);
	}
}

int read_uftrace_info(uint64_t info_mask, struct uftrace_data *handle)
{
	size_t i;
	struct read_handler_arg arg = {
		.handle = handle,
	};
	struct uftrace_info_handler read_handlers[] = {
		{ EXE_NAME, read_exe_name },
		{ EXE_BUILD_ID, read_exe_build_id },
		{ EXIT_STATUS, read_exit_status },
		{ CMDLINE, read_cmdline },
		{ CPUINFO, read_cpuinfo },
		{ MEMINFO, read_meminfo },
		{ OSINFO, read_osinfo },
		{ TASKINFO, read_taskinfo },
		{ USAGEINFO, read_usageinfo },
		{ LOADINFO, read_loadinfo },
		{ ARG_SPEC, read_arg_spec },
		{ RECORD_DATE, read_record_date },
		{ PATTERN_TYPE, read_pattern_type },
		{ VERSION, read_uftrace_version },
	};

	memset(&handle->info, 0, sizeof(handle->info));

	for (i = 0; i < ARRAY_SIZE(read_handlers); i++) {
		if (!(info_mask & (1UL << read_handlers[i].bit)))
			continue;

		if (read_handlers[i].handler(&arg) < 0) {
			pr_dbg("error during read uftrace info (%x)\n",
			       (1U << read_handlers[i].bit));
			return -1;
		}
	}
	return 0;
}

void clear_uftrace_info(struct uftrace_info *info)
{
	free(info->exename);
	free(info->cmdline);
	free(info->cpudesc);
	free(info->meminfo);
	free(info->kernel);
	free(info->hostname);
	free(info->distro);
	free(info->tids);
	free(info->argspec);
	free(info->record_date);
	free(info->elapsed_time);
	free(info->uftrace_version);
	free(info->retspec);
	free(info->autoarg);
	free(info->autoret);
	free(info->autoenum);
}

static void print_info(void *unused, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vfprintf(outfp, fmt, ap);
	va_end(ap);
}

void process_uftrace_info(struct uftrace_data *handle, struct uftrace_opts *opts,
			  void (*process)(void *data, const char *fmt, ...), void *data)
{
	char buf[PATH_MAX];
	struct stat statbuf;
	const char *fmt = "# %-20s: %s\n";
	uint64_t info_mask = handle->hdr.info_mask;
	struct uftrace_info *info = &handle->info;

	if (info_mask == 0)
		return;

	snprintf(buf, sizeof(buf), "%s/info", opts->dirname);

	if (stat(buf, &statbuf) < 0)
		return;

	process(data, "# system information\n");
	process(data, "# ==================\n");

	if (info_mask & (1UL << VERSION))
		process(data, fmt, "program version", info->uftrace_version);

	if (info_mask & (1UL << RECORD_DATE))
		process(data, fmt, "recorded on", info->record_date);
	else
		process(data, "# %-20s: %s", "recorded on", ctime(&statbuf.st_mtime));

	if (info_mask & (1UL << CMDLINE))
		process(data, fmt, "cmdline", info->cmdline);

	if (info_mask & (1UL << CPUINFO)) {
		process(data, fmt, "cpu info", info->cpudesc);
		process(data, "# %-20s: %d / %d (online / possible)\n", "number of cpus",
			info->nr_cpus_online, info->nr_cpus_possible);
	}

	if (info_mask & (1UL << MEMINFO))
		process(data, fmt, "memory info", info->meminfo);

	if (info_mask & (1UL << LOADINFO))
		process(data, "# %-20s: %.02f / %.02f / %.02f (1 / 5 / 15 min)\n", "system load",
			info->load1, info->load5, info->load15);

	if (info_mask & (1UL << OSINFO)) {
		process(data, fmt, "kernel version", info->kernel);
		process(data, fmt, "hostname", info->hostname);
		process(data, fmt, "distro", info->distro);
	}

	process(data, "#\n");
	process(data, "# process information\n");
	process(data, "# ===================\n");

	if (info_mask & (1UL << TASKINFO)) {
		int i;
		int nr = info->nr_tid;
		bool first = true;
		struct uftrace_task *task;
		char *task_list;
		int sz, len;
		char *p;

		/* ignore errors */
		read_task_txt_file(&handle->sessions, opts->dirname, opts->dirname, false, false,
				   false);

		process(data, "# %-20s: %d\n", "number of tasks", nr);

		if (handle->hdr.feat_mask & PERF_EVENT) {
			if (setup_perf_data(handle) == 0)
				update_perf_task_comm(handle);
		}

		sz = nr * 32; /* 32 > strlen("tid (comm)") */
		len = 0;
		p = task_list = xmalloc(sz);

		for (i = 0; i < nr; i++) {
			int tid = info->tids[i];

			task = find_task(&handle->sessions, tid);

			len = snprintf(p, sz, "%s%d(%s)", first ? "" : ", ", tid,
				       task ? task->comm : "");
			p += len;
			sz -= len;

			first = false;
		}
		process(data, "# %-20s: %s\n", "task list", task_list);
		free(task_list);
	}

	if (info_mask & (1UL << EXE_NAME))
		process(data, fmt, "exe image", info->exename);

	if (info_mask & (1UL << EXE_BUILD_ID)) {
		int i;
		char bid[BUILD_ID_SIZE * 2 + 1];

		for (i = 0; i < BUILD_ID_SIZE; i++)
			snprintf(bid + i * 2, 3, "%02x", info->build_id[i]);

		process(data, "# %-20s: %s\n", "build id", bid);
	}

	if (info_mask & (1UL << ARG_SPEC)) {
		if (info->argspec)
			process(data, fmt, "arguments", info->argspec);
		if (info->retspec)
			process(data, fmt, "return values", info->retspec);
		if (info->auto_args_enabled)
			process(data, fmt, "auto-args", "true");
	}

	if (info_mask & (1UL << PATTERN_TYPE))
		process(data, fmt, "pattern", get_filter_pattern(info->patt_type));

	if (info_mask & (1UL << EXIT_STATUS)) {
		int status = info->exit_status;

		if (status == UFTRACE_EXIT_FINISHED) {
			snprintf(buf, sizeof(buf), "terminated by finish trigger");
		}
		else if (WIFEXITED(status)) {
			snprintf(buf, sizeof(buf), "exited with code: %d", WEXITSTATUS(status));
		}
		else if (WIFSIGNALED(status)) {
			snprintf(buf, sizeof(buf), "terminated by signal: %d (%s)",
				 WTERMSIG(status), strsignal(WTERMSIG(status)));
		}
		else {
			snprintf(buf, sizeof(buf), "unknown exit status: %d", status);
		}
		process(data, fmt, "exit status", buf);
	}

	if (info_mask & (1UL << RECORD_DATE))
		process(data, fmt, "elapsed time", info->elapsed_time);

	if (info_mask & (1UL << USAGEINFO)) {
		process(data, "# %-20s: %.3lf / %.3lf sec (sys / user)\n", "cpu time", info->stime,
			info->utime);
		process(data, "# %-20s: %ld / %ld (voluntary / involuntary)\n", "context switch",
			info->vctxsw, info->ictxsw);
		process(data, "# %-20s: %ld KB\n", "max rss", info->maxrss);
		process(data, "# %-20s: %ld / %ld (major / minor)\n", "page fault",
			info->major_fault, info->minor_fault);
		process(data, "# %-20s: %ld / %ld (read / write)\n", "disk iops", info->rblock,
			info->wblock);
	}

	snprintf(buf, sizeof(buf), "%s/note.txt", opts->dirname);
	if (!access(buf, R_OK)) {
		size_t size;
		char *note_buf;
		FILE *fp = fopen(buf, "r");

		if (fstat(fileno(fp), &statbuf) < 0) {
			pr_dbg("failed to get the size of note.txt\n");
			goto out;
		}
		size = (size_t)statbuf.st_size;

		note_buf = xmalloc(size + 1);
		if (fread(note_buf, size, 1, fp) != size)
			pr_dbg("couldn't read the whole note.txt contents");
		note_buf[size] = '\0';

		process(data, "#\n");
		process(data, "# extra note information\n");
		process(data, "# ======================\n");
		process(data, "%s", note_buf);
		free(note_buf);
out:
		fclose(fp);
	}
	process(data, "\n");
}

static void print_task(struct uftrace_data *handle, struct uftrace_task *t)
{
	char flags[6] = "     ";
	struct stat stbuf;
	char *filename = NULL;
	struct uftrace_sess_ref *sref = &t->sref;

	xasprintf(&filename, "%s/%d.dat", handle->dirname, t->tid);
	if (stat(filename, &stbuf) < 0)
		stbuf.st_size = 0;

	if (t->tid == t->pid)
		flags[0] = 'F'; /* FORK */
	while (sref != NULL) {
		if (sref->sess->tid == t->tid) {
			flags[1] = 'S'; /* SESSION */
			break;
		}

		sref = sref->next;
	}

	/* TIMESTAMP */
	pr_out(" %13lu.%09lu ", t->time.stamp / NSEC_PER_SEC, t->time.stamp % NSEC_PER_SEC);
	/* FLAGS  TID  COMM */
	pr_out(" %s  [%6d]  %-16s ", flags, t->tid, t->comm);
	/* DATA SIZE */
	if (stbuf.st_size) {
		uint64_t size_kb = stbuf.st_size / 1024;
		uint64_t size_rem = size_kb % 1024;

		pr_out(" %5" PRIu64 ".%03" PRIu64 " MB\n", size_kb / 1024,
		       size_rem >= 1000 ? 999 : size_rem);
	}
	else
		pr_out("\n");

	free(filename);
}

static void print_task_info(struct uftrace_data *handle)
{
	struct rb_node *n;
	struct uftrace_task *t;

	pr_out("#%23s  %5s  %8s  %-16s  %s\n", "TIMESTAMP     ", "FLAGS", "  TID  ", "TASK",
	       "DATA SIZE");

	n = rb_first(&handle->sessions.tasks);
	while (n != NULL) {
		t = rb_entry(n, struct uftrace_task, node);
		n = rb_next(n);

		print_task(handle, t);
	}
}

int command_info(int argc, char *argv[], struct uftrace_opts *opts)
{
	int ret;
	struct uftrace_data handle;

	ret = open_info_file(opts, &handle);
	if (ret < 0) {
		pr_warn("cannot open record data: %s: %m\n", opts->dirname);
		return -1;
	}

	if (opts->print_symtab) {
		struct uftrace_sym_info sinfo = {
			.dirname = opts->dirname,
			.filename = opts->exename,
			.flags = SYMTAB_FL_USE_SYMFILE | SYMTAB_FL_DEMANGLE,
		};
		struct uftrace_module *mod;
		char build_id[BUILD_ID_STR_SIZE];
		int i;

		if (!opts->exename) {
			pr_use("Usage: uftrace info --symbols [COMMAND]\n");
			return -1;
		}

		for (i = 0; i < BUILD_ID_SIZE; i++) {
			snprintf(build_id + i * 2, 3, "%02x", handle.info.build_id[i]);
		}
		mod = load_module_symtab(&sinfo, sinfo.filename, build_id);
		if (mod == NULL)
			goto out;

		print_symtab(&mod->symtab);
		unload_module_symtabs();
		goto out;
	}

	fstack_setup_task(opts->tid, &handle);
	if (opts->show_task) {
		/* ignore errors */
		read_task_txt_file(&handle.sessions, opts->dirname, opts->dirname, false, false,
				   false);

		if (handle.hdr.feat_mask & PERF_EVENT) {
			if (setup_perf_data(&handle) == 0)
				update_perf_task_comm(&handle);
		}

		print_task_info(&handle);
		goto out;
	}

	process_uftrace_info(&handle, opts, print_info, NULL);

out:
	close_data_file(opts, &handle);

	return 0;
}
