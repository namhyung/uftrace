/*
 * uftrace info command related routines
 *
 * Copyright (C) 2014-2016, LG Electronics, Namhyung Kim <namhyung.kim@lge.com>
 *
 * Released under the GPL v2.
 */

#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <assert.h>
#include <ctype.h>
#include <sys/utsname.h>
#include <sys/stat.h>
#include <sys/resource.h>
#include <time.h>
#include <gelf.h>
#include <argp.h>
#include <fcntl.h>

#include "uftrace.h"
#include "libmcount/mcount.h"
#include "utils/utils.h"


struct fill_handler_arg {
	int fd;
	int exit_status;
	struct opts *opts;
	struct rusage *rusage;
};

static char *copy_info_str(char *src)
{
	char *dst = xstrdup(src);
	size_t len = strlen(dst);

	if (dst[len-1] == '\n')
		dst[len-1] = '\0';

	return dst;
}

static int fill_exe_name(void *arg)
{
	struct fill_handler_arg *fha = arg;
	char buf[4096];
	char *exename;

	exename = realpath(fha->opts->exename, buf);
	if (exename == NULL)
		exename = fha->opts->exename;

	return dprintf(fha->fd, "exename:%s\n", exename);
}

static int read_exe_name(void *arg)
{
	struct ftrace_file_handle *handle = arg;
	struct ftrace_info *info = &handle->info;
	char buf[4096];

	if (fgets(buf, sizeof(buf), handle->fp) == NULL)
		return -1;

	if (strncmp(buf, "exename:", 8))
		return -1;

	info->exename = copy_info_str(&buf[8]);

	return 0;
}

static int fill_exe_build_id(void *arg)
{
	struct fill_handler_arg *fha = arg;
	unsigned char build_id[20];
	char build_id_str[41];
	int fd;
	Elf *elf;
	Elf_Scn *sec = NULL;
	Elf_Data *data;
	GElf_Nhdr nhdr;
	size_t shdrstr_idx;
	size_t offset = 0;
	size_t name_offset, desc_offset;

	fd = open(fha->opts->exename, O_RDONLY);
	if (fd < 0)
		return -1;

	elf_version(EV_CURRENT);

	elf = elf_begin(fd, ELF_C_READ_MMAP, NULL);
	if (elf == NULL)
		goto close_fd;

	if (elf_getshdrstrndx(elf, &shdrstr_idx) < 0)
		goto end_elf;

	while ((sec = elf_nextscn(elf, sec)) != NULL) {
		GElf_Shdr shdr;
		char *str;

		if (gelf_getshdr(sec, &shdr) == NULL)
			goto end_elf;

		str = elf_strptr(elf, shdrstr_idx, shdr.sh_name);
		if (!strcmp(str, ".note.gnu.build-id"))
			break;
	}

	if (sec == NULL)
		goto end_elf;

	data = elf_getdata(sec, NULL);
	if (data == NULL)
		goto end_elf;

	while ((offset = gelf_getnote(data, offset, &nhdr,
				      &name_offset, &desc_offset)) != 0) {
		if (nhdr.n_type == NT_GNU_BUILD_ID &&
		    !strcmp((char *)data->d_buf + name_offset, "GNU")) {
			memcpy(build_id, (void *)data->d_buf + desc_offset, 20);
			break;
		}
	}
end_elf:
	elf_end(elf);
close_fd:
	close(fd);

	if (offset == 0) {
		if (sec == NULL)
			pr_dbg("cannot find build-id section\n");
		else
			pr_dbg("error during ELF processing: %s\n",
			       elf_errmsg(elf_errno()));
		return -1;
	}

	for (offset = 0; offset < 20; offset++) {
		unsigned char c = build_id[offset];
		sprintf(&build_id_str[offset*2], "%02x", c);
	}
	build_id_str[40] = '\0';

	return dprintf(fha->fd, "build_id:%s\n", build_id_str);
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
	struct ftrace_file_handle *handle = arg;
	struct ftrace_info *info = &handle->info;
	unsigned char build_id_str[41];
	char buf[4096];
	int i;

	if (fgets(buf, sizeof(buf), handle->fp) == NULL)
		return -1;

	if (strncmp(buf, "build_id:", 9))
		return -1;

	memcpy(build_id_str, &buf[9], 40);
	build_id_str[40] = '\0';

	for (i = 0; i < 20; i++) {
		int c1 = convert_to_int(build_id_str[i*2]);
		int c2 = convert_to_int(build_id_str[i*2 + 1]);

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
	struct ftrace_file_handle *handle = arg;
	struct ftrace_info *info = &handle->info;
	char buf[4096];

	if (fgets(buf, sizeof(buf), handle->fp) == NULL)
		return -1;

	if (strncmp(buf, "exit_status:", 12))
		return -1;

	sscanf(&buf[12], "%d", &info->exit_status);
	return 0;
}

static int fill_cmdline(void *arg)
{
	struct fill_handler_arg *fha = arg;
	char buf[4096];
	FILE *fp;
	int ret;
	char *p;

	fp = fopen("/proc/self/cmdline", "r");
	if (fp == NULL)
		return -1;

	strcpy(buf, "cmdline:");
	ret = fread(&buf[8], 1, sizeof(buf)-8, fp);
	buf[8+ret] = '\n';
	fclose(fp);

	for (p = buf; *p != '\n'; p++) {
		if (*p == '\0')
			*p = ' ';
	}
	return write(fha->fd, buf, 8+ret+1);
}

static int read_cmdline(void *arg)
{
	struct ftrace_file_handle *handle = arg;
	struct ftrace_info *info = &handle->info;
	char buf[4096];

	if (fgets(buf, sizeof(buf), handle->fp) == NULL)
		return -1;

	if (strncmp(buf, "cmdline:", 8))
		return -1;

	info->cmdline = copy_info_str(&buf[8]);

	return 0;
}

static int fill_cpuinfo(void *arg)
{
	struct fill_handler_arg *fha = arg;
	long nr_possible;
	long nr_online;

	nr_possible = sysconf(_SC_NPROCESSORS_CONF);
	nr_online = sysconf(_SC_NPROCESSORS_ONLN);

	dprintf(fha->fd, "cpuinfo:lines=2\n");
	dprintf(fha->fd, "cpuinfo:nr_cpus=%lu / %lu (online/possible)\n",
		nr_online, nr_possible);

	return arch_fill_cpuinfo_model(fha->fd);
}

static int read_cpuinfo(void *arg)
{
	struct ftrace_file_handle *handle = arg;
	struct ftrace_info *info = &handle->info;
	char buf[4096];
	int i, lines;

	if (fgets(buf, sizeof(buf), handle->fp) == NULL)
		return -1;

	if (strncmp(buf, "cpuinfo:", 8))
		return -1;

	if (sscanf(&buf[8], "lines=%d\n", &lines) == EOF)
		return -1;

	for (i = 0; i < lines; i++) {
		if (fgets(buf, sizeof(buf), handle->fp) == NULL)
			return -1;

		if (strncmp(buf, "cpuinfo:", 8))
			return -1;

		if (!strncmp(&buf[8], "nr_cpus=", 7)) {
			sscanf(&buf[8], "nr_cpus=%d / %d\n",
			       &info->nr_cpus_online, &info->nr_cpus_possible);
		} else if (!strncmp(&buf[8], "desc=", 5)) {
			info->cpudesc = copy_info_str(&buf[13]);
		}
	}

	return 0;
}

static int fill_meminfo(void *arg)
{
	struct fill_handler_arg *fha = arg;
	long mem_total, mem_total_small;
	long mem_free, mem_free_small;
	char *units[] = { "KB", "MB", "GB", "TB" };
	char *unit;
	char buf[1024];
	size_t i;
	FILE *fp;

	fp = fopen("/proc/meminfo", "r");
	if (fp == NULL)
		return -1;

	while (fgets(buf, sizeof(buf), fp) != NULL) {
		if (!strncmp(buf, "MemTotal:", 9))
			sscanf(&buf[10], "%ld", &mem_total);
		else if (!strncmp(buf, "MemFree:", 8))
			sscanf(&buf[9], "%ld", &mem_free);
		else
			break;
	}

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

	dprintf(fha->fd, "meminfo:%ld.%ld / %ld.%ld %s (free / total)\n",
		mem_free, mem_free_small, mem_total, mem_total_small, unit);

	return 0;
}

static int read_meminfo(void *arg)
{
	struct ftrace_file_handle *handle = arg;
	struct ftrace_info *info = &handle->info;
	char buf[4096];

	if (fgets(buf, sizeof(buf), handle->fp) == NULL)
		return -1;

	if (strncmp(buf, "meminfo:", 8))
		return -1;

	info->meminfo = copy_info_str(&buf[8]);

	return 0;
}

static int fill_osinfo(void *arg)
{
	struct fill_handler_arg *fha = arg;
	struct utsname uts;
	char buf[1024];
	FILE *fp;
	int ret = -1;

	uname(&uts);

	dprintf(fha->fd, "osinfo:lines=3\n");
	dprintf(fha->fd, "osinfo:kernel=%s %s\n", uts.sysname, uts.release);
	dprintf(fha->fd, "osinfo:hostname=%s\n", uts.nodename);

	fp = fopen("/etc/os-release", "r");
	if (fp != NULL) {
		while (fgets(buf, sizeof(buf), fp) != NULL) {
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
		while (fgets(buf, sizeof(buf), fp) != NULL) {
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
	struct ftrace_file_handle *handle = arg;
	struct ftrace_info *info = &handle->info;
	char buf[4096];
	int i, lines;

	if (fgets(buf, sizeof(buf), handle->fp) == NULL)
		return -1;

	if (strncmp(buf, "osinfo:", 7))
		return -1;

	if (sscanf(&buf[7], "lines=%d\n", &lines) == EOF)
		return -1;

	for (i = 0; i < lines; i++) {
		if (fgets(buf, sizeof(buf), handle->fp) == NULL)
			return -1;

		if (strncmp(buf, "osinfo:", 7))
			return -1;

		if (!strncmp(&buf[7], "kernel=", 7)) {
			info->kernel = copy_info_str(&buf[14]);
		} else if (!strncmp(&buf[7], "hostname=", 9)) {
			info->hostname = copy_info_str(&buf[16]);
		} else if (!strncmp(&buf[7], "distro=", 7)) {
			info->distro = copy_info_str(&buf[14]);
		}
	}

	return 0;
}

struct tid_list {
	int nr;
	int *tid;
};

static int build_tid_list(struct ftrace_task *t, void *arg)
{
	struct tid_list *list = arg;

	list->nr++;
	list->tid = xrealloc(list->tid, list->nr * sizeof(list->tid));

	list->tid[list->nr - 1] = t->tid;
	return 0;
}

static int fill_taskinfo(void *arg)
{
	struct fill_handler_arg *fha = arg;
	bool first = true;
	struct tid_list tlist = {
		.nr = 0,
	};
	int i;

	if (read_task_txt_file(fha->opts->dirname) < 0 &&
	    read_task_file(fha->opts->dirname) < 0)
		return -1;

	walk_tasks(build_tid_list, &tlist);

	dprintf(fha->fd, "taskinfo:lines=2\n");
	dprintf(fha->fd, "taskinfo:nr_tid=%d\n", tlist.nr);

	dprintf(fha->fd, "taskinfo:tids=");
	for (i = 0; i < tlist.nr; i++) {
		dprintf(fha->fd, "%s%d", first ? "" : ",", tlist.tid[i]);
		first = false;
	}
	dprintf(fha->fd, "\n");

	free(tlist.tid);
	return 0;
}

static int read_taskinfo(void *arg)
{
	struct ftrace_file_handle *handle = arg;
	struct ftrace_info *info = &handle->info;
	char buf[4096];
	int i, lines;

	if (fgets(buf, sizeof(buf), handle->fp) == NULL)
		return -1;

	if (strncmp(buf, "taskinfo:", 9))
		return -1;

	if (sscanf(&buf[9], "lines=%d\n", &lines) == EOF)
		return -1;

	for (i = 0; i < lines; i++) {
		if (fgets(buf, sizeof(buf), handle->fp) == NULL)
			return -1;

		if (strncmp(buf, "taskinfo:", 9))
			return -1;

		if (!strncmp(&buf[9], "nr_tid=", 7)) {
			info->nr_tid = strtol(&buf[16], NULL, 10);
		} else if (!strncmp(&buf[9], "tids=", 5)) {
			char *tids_str = &buf[14];
			char *endp = tids_str;
			int *tids = xcalloc(sizeof(*tids), info->nr_tid);
			int nr_tid = 0;

			while (*endp != '\n') {
				int tid = strtol(tids_str, &endp, 10);
				tids[nr_tid++] = tid;

				if (*endp != ',' && *endp != '\n')
					return -1;

				tids_str = endp + 1;
			}
			info->tids = tids;

			assert(nr_tid == info->nr_tid);
		}
	}
	return 0;
}

static int fill_usageinfo(void *arg)
{
	struct fill_handler_arg *fha = arg;
	struct rusage *r = fha->rusage;

	dprintf(fha->fd, "usageinfo:lines=6\n");
	dprintf(fha->fd, "usageinfo:systime=%lu.%06lu\n",
		r->ru_stime.tv_sec, r->ru_stime.tv_usec);
	dprintf(fha->fd, "usageinfo:usrtime=%lu.%06lu\n",
		r->ru_utime.tv_sec, r->ru_utime.tv_usec);
	dprintf(fha->fd, "usageinfo:ctxsw=%ld / %ld (voluntary / involuntary)\n",
		r->ru_nvcsw, r->ru_nivcsw);
	dprintf(fha->fd, "usageinfo:maxrss=%ld\n", r->ru_maxrss);
	dprintf(fha->fd, "usageinfo:pagefault=%ld / %ld (major / minor)\n",
		r->ru_majflt, r->ru_minflt);
	dprintf(fha->fd, "usageinfo:iops=%ld / %ld (read / write)\n",
		r->ru_inblock, r->ru_oublock);
	return 0;
}

static int read_usageinfo(void *arg)
{
	struct ftrace_file_handle *handle = arg;
	struct ftrace_info *info = &handle->info;
	char buf[4096];
	int i, lines;

	if (fgets(buf, sizeof(buf), handle->fp) == NULL)
		return -1;

	if (strncmp(buf, "usageinfo:", 10))
		return -1;

	if (sscanf(&buf[10], "lines=%d\n", &lines) == EOF)
		return -1;

	for (i = 0; i < lines; i++) {
		if (fgets(buf, sizeof(buf), handle->fp) == NULL)
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
			sscanf(&buf[20], "%ld / %ld",
			       &info->major_fault, &info->minor_fault);
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

	if (fscanf(fp, "%f %f %f", &loadavg[0], &loadavg[1], &loadavg[2]) != 3)
		return -1;

	dprintf(fha->fd, "loadinfo:%.02f / %.02f / %.02f\n",
		loadavg[0], loadavg[1], loadavg[2]);

	fclose(fp);
	return 0;
}

static int read_loadinfo(void *arg)
{
	struct ftrace_file_handle *handle = arg;
	struct ftrace_info *info = &handle->info;
	char buf[4096];

	if (fgets(buf, sizeof(buf), handle->fp) == NULL)
		return -1;

	if (strncmp(buf, "loadinfo:", 9))
		return -1;

	sscanf(&buf[9], "%f / %f / %f", &info->load1, &info->load5, &info->load15);
	return 0;
}

static int fill_arg_spec(void *arg)
{
	struct fill_handler_arg *fha = arg;

	if (!(fha->opts->args || fha->opts->retval))
		return -1;

	dprintf(fha->fd, "argspec:");
	if (fha->opts->args)
		dprintf(fha->fd, "%s;", fha->opts->args);
	if (fha->opts->retval)
		dprintf(fha->fd, "%s;", fha->opts->retval);

	return 0;
}

static int read_arg_spec(void *arg)
{
	struct ftrace_file_handle *handle = arg;
	struct ftrace_info *info = &handle->info;
	char buf[4096];

	if (fgets(buf, sizeof(buf), handle->fp) == NULL)
		return -1;

	if (strncmp(buf, "argspec:", 8))
		return -1;

	info->argspec = copy_info_str(&buf[8]);
	return 0;
}

struct ftrace_info_handler {
	enum ftrace_info_bits bit;
	int (*handler)(void *arg);
};

void fill_ftrace_info(uint64_t *info_mask, int fd, struct opts *opts, int status,
		      struct rusage *rusage)
{
	size_t i;
	off_t offset;
	struct fill_handler_arg arg = {
		.fd = fd,
		.opts = opts,
		.exit_status = status,
		.rusage = rusage,
	};
	struct ftrace_info_handler fill_handlers[] = {
		{ EXE_NAME,	fill_exe_name },
		{ EXE_BUILD_ID,	fill_exe_build_id },
		{ EXIT_STATUS,	fill_exit_status },
		{ CMDLINE,	fill_cmdline },
		{ CPUINFO,	fill_cpuinfo },
		{ MEMINFO,	fill_meminfo },
		{ OSINFO,	fill_osinfo },
		{ TASKINFO,	fill_taskinfo },
		{ USAGEINFO,	fill_usageinfo },
		{ LOADINFO,	fill_loadinfo },
		{ ARG_SPEC,	fill_arg_spec },
	};

	for (i = 0; i < ARRAY_SIZE(fill_handlers); i++) {
		offset = lseek(fd, 0, SEEK_CUR);

		if (fill_handlers[i].handler(&arg) < 0) {
			/* ignore failed info */
			lseek(fd, offset, SEEK_SET);
			continue;
		}
		*info_mask |= (1UL << fill_handlers[i].bit);
	}
}

int read_ftrace_info(uint64_t info_mask, struct ftrace_file_handle *handle)
{
	size_t i;
	struct ftrace_info_handler read_handlers[] = {
		{ EXE_NAME,	read_exe_name },
		{ EXE_BUILD_ID,	read_exe_build_id },
		{ EXIT_STATUS,	read_exit_status },
		{ CMDLINE,	read_cmdline },
		{ CPUINFO,	read_cpuinfo },
		{ MEMINFO,	read_meminfo },
		{ OSINFO,	read_osinfo },
		{ TASKINFO,	read_taskinfo },
		{ USAGEINFO,	read_usageinfo },
		{ LOADINFO,	read_loadinfo },
		{ ARG_SPEC,	read_arg_spec },
	};

	memset(&handle->info, 0, sizeof(handle->info));

	for (i = 0; i < ARRAY_SIZE(read_handlers); i++) {
		if (!(info_mask & (1UL << read_handlers[i].bit)))
			continue;

		if (read_handlers[i].handler(handle) < 0) {
			pr_dbg("error during read ftrace info (%x)\n",
			       (1U << read_handlers[i].bit));
			return -1;
		}
	}
	return 0;
}

void clear_ftrace_info(struct ftrace_info *info)
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
}

int command_info(int argc, char *argv[], struct opts *opts)
{
	int ret;
	char buf[PATH_MAX];
	struct stat statbuf;
	struct ftrace_file_handle handle;
	const char *fmt = "# %-20s: %s\n";

	ret = open_data_file(opts, &handle);
	if (ret < 0)
		return -1;

	snprintf(buf, sizeof(buf), "%s/info", opts->dirname);

	if (stat(buf, &statbuf) < 0)
		return -1;

	if (opts->print_symtab) {
		struct symtabs symtabs = {
			.loaded = false,
		};

		load_symtabs(&symtabs, opts->dirname, opts->exename);
		print_symtabs(&symtabs);
		unload_symtabs(&symtabs);
		goto out;
	}

	pr_out("# system information\n");
	pr_out("# ==================\n");
	pr_out(fmt, "program version", argp_program_version);
	pr_out("# %-20s: %s", "recorded on", ctime(&statbuf.st_mtime));

	if (handle.hdr.info_mask & (1UL << CMDLINE))
		pr_out(fmt, "cmdline", handle.info.cmdline);

	if (handle.hdr.info_mask & (1UL << CPUINFO)) {
		pr_out(fmt, "cpu info", handle.info.cpudesc);
		pr_out("# %-20s: %d / %d (online / possible)\n",
		       "number of cpus", handle.info.nr_cpus_online,
		       handle.info.nr_cpus_possible);
	}

	if (handle.hdr.info_mask & (1UL << MEMINFO))
		pr_out(fmt, "memory info", handle.info.meminfo);

	if (handle.hdr.info_mask & (1UL << LOADINFO))
		pr_out("# %-20s: %.02f / %.02f / %.02f (1 / 5 / 15 min)\n", "system load",
		       handle.info.load1, handle.info.load5, handle.info.load15);

	if (handle.hdr.info_mask & (1UL << OSINFO)) {
		pr_out(fmt, "kernel version", handle.info.kernel);
		pr_out(fmt, "hostname", handle.info.hostname);
		pr_out(fmt, "distro", handle.info.distro);
	}

	pr_out("#\n");
	pr_out("# process information\n");
	pr_out("# ===================\n");

	if (handle.hdr.info_mask & (1UL << TASKINFO)) {
		int nr = handle.info.nr_tid;
		bool first = true;

		pr_out("# %-20s: %d\n", "number of tasks", nr);

		pr_out("# %-20s: ", "task list");
		while (nr--) {
			pr_out("%s%d", first ? "" : ", ", handle.info.tids[nr]);
			first = false;
		}
		pr_out("\n");
	}

	if (handle.hdr.info_mask & (1UL << EXE_NAME))
		pr_out(fmt, "exe image", handle.info.exename);

	if (handle.hdr.info_mask & (1UL << EXE_BUILD_ID)) {
		int i;
		pr_out("# %-20s: ", "build id");
		for (i = 0; i < 20; i++)
			pr_out("%02x", handle.info.build_id[i]);
		pr_out("\n");
	}

	if (handle.hdr.info_mask & (1UL << ARG_SPEC))
		pr_out(fmt, "arguments/retval", handle.info.argspec);

	if (handle.hdr.info_mask & (1UL << EXIT_STATUS)) {
		int status = handle.info.exit_status;

		if (WIFEXITED(status)) {
			snprintf(buf, sizeof(buf), "exited with code: %d",
				 WEXITSTATUS(status));
		} else if (WIFSIGNALED(status)) {
			snprintf(buf, sizeof(buf), "terminated by signal: %d",
				 WTERMSIG(status));
		} else {
			snprintf(buf, sizeof(buf), "unknown exit status: %d",
				 status);
		}
		pr_out(fmt, "exit status", buf);
	}

	if (handle.hdr.info_mask & (1UL << USAGEINFO)) {
		pr_out("# %-20s: %.3lf / %.3lf sec (sys / user)\n", "cpu time",
		       handle.info.stime, handle.info.utime);
		pr_out("# %-20s: %ld / %ld (voluntary / involuntary)\n",
		       "context switch", handle.info.vctxsw, handle.info.ictxsw);
		pr_out("# %-20s: %ld KB\n", "max rss",
		       handle.info.maxrss);
		pr_out("# %-20s: %ld / %ld (major / minor)\n", "page fault",
		       handle.info.major_fault, handle.info.minor_fault);
		pr_out("# %-20s: %ld / %ld (read / write)\n", "disk iops",
		       handle.info.rblock, handle.info.wblock);
	}
	pr_out("\n");

out:
	close_data_file(opts, &handle);

	return ret;
}
