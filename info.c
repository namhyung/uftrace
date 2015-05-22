/*
 * ftrace info command related routines
 *
 * Copyright (C) 2014-2015, LG Electronics, Namhyung Kim <namhyung.kim@lge.com>
 *
 * Released under the GPL v2.
 */

#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <assert.h>
#include <ctype.h>
#include <sys/utsname.h>
#include <gelf.h>

#include "mcount.h"
#include "utils.h"

struct fill_handler_arg {
	int fd;
	Elf *elf;
	char *exename;
	int exit_status;
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

	exename = realpath(fha->exename, buf);
	if (exename == NULL)
		exename = fha->exename;

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
	Elf_Scn *sec;
	Elf_Data *data;
	GElf_Nhdr nhdr;
	size_t shdrstr_idx;
	size_t offset, name_offset, desc_offset;

	if (elf_getshdrstrndx(fha->elf, &shdrstr_idx) < 0)
		return -1;

	sec = NULL;
	while ((sec = elf_nextscn(fha->elf, sec)) != NULL) {
		GElf_Shdr shdr;
		char *str;

		if (gelf_getshdr(sec, &shdr) == NULL)
			return -1;

		str = elf_strptr(fha->elf, shdrstr_idx, shdr.sh_name);
		if (!strcmp(str, ".note.gnu.build-id"))
			break;
	}

	if (sec == NULL)
		return -1;

	data = elf_getdata(sec, NULL);
	if (data == NULL)
		return -1;

	offset = 0;
	while ((offset = gelf_getnote(data, offset, &nhdr,
				      &name_offset, &desc_offset)) != 0) {
		if (nhdr.n_type == NT_GNU_BUILD_ID &&
		    !strcmp((char *)data->d_buf + name_offset, "GNU")) {
			memcpy(build_id, (void *)data->d_buf + desc_offset, 20);
			break;
		}
	}
	if (offset == 0)
		return -1;

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
	dprintf(fha->fd, "cpuinfo:nr_cpus=%lu/%lu (online/possible)\n",
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
			sscanf(&buf[8], "nr_cpus=%d/%d\n",
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

	dprintf(fha->fd, "meminfo:%ld.%ld/%ld.%ld %s (free/total)\n",
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

static int fill_taskinfo(void *arg)
{
	struct fill_handler_arg *fha = arg;
	bool first = true;
	int i, nr, *tids;

	nr = read_tid_list(NULL, true);

	tids = xcalloc(sizeof(*tids), nr);
	read_tid_list(tids, true);

	dprintf(fha->fd, "taskinfo:lines=2\n");
	dprintf(fha->fd, "taskinfo:nr_tid=%d\n", nr);

	dprintf(fha->fd, "taskinfo:tids=");
	for (i = 0; i < nr; i++) {
		dprintf(fha->fd, "%s%d", first ? "" : ",", tids[i]);
		first = false;
	}
	dprintf(fha->fd, "\n");

	free_tid_list();
	free(tids);
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

struct ftrace_info_handler {
	enum ftrace_info_bits bit;
	int (*handler)(void *arg);
};

void fill_ftrace_info(uint64_t *info_mask, int fd, char *exename, Elf *elf,
		      int status)
{
	size_t i;
	off_t offset;
	struct fill_handler_arg arg = {
		.fd = fd,
		.elf = elf,
		.exename = exename,
		.exit_status = status,
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
	};

	for (i = 0; i < ARRAY_SIZE(read_handlers); i++) {
		if (!(info_mask & (1UL << read_handlers[i].bit)))
			continue;

		if (read_handlers[i].handler(handle) < 0) {
			pr_log("error during read ftrace info (%x)\n",
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
}
