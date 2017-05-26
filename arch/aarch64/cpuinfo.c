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
		if (!strncmp(buf, "CPU architecture:", 17)) {
			int v = 8;

			sscanf(&buf[18], "%d", &v);
			dprintf(fd, "cpuinfo:desc=ARM64 (v%d)\n", v);
			ret = 0;
			break;
		}
	}

	fclose(fp);
	return ret;
}

