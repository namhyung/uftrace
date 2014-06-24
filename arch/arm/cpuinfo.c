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
		if (!strncmp(buf, "Processor\t:", 11)) {
			dprintf(fd, "cpuinfo:desc=%s", &buf[12]);
			ret = 0;
			break;
		} else if (!strncmp(buf, "model name\t:", 12)) {
			dprintf(fd, "cpuinfo:desc=%s", &buf[13]);
			ret = 0;
			break;
		}
	}

	if (ret < 0)
		dprintf(fd, "cpuinfo:desc=ARM (unknown)\n");

	fclose(fp);
	return ret;
}
