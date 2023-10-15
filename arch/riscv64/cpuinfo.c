#include <stdio.h>
#include <string.h>

int arch_fill_cpuinfo_model(int fd)
{
	char buf[1024];
	FILE *fp;
	int ret = -1;

	fp = fopen("/proc/cpuinfo", "r");
	if (fp == NULL)
		return -1;

	while (fgets(buf, sizeof(buf), fp) != NULL) {
		if (!strncmp(buf, "isa\t\t: rv64", 11)) {
			dprintf(fd, "cpuinfo:desc=RISCV64_%s", &buf[12]);
			ret = 0;
			break;
		}
	}

	fclose(fp);
	return ret;
}
