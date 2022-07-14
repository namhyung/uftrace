#include <stdio.h>
#include <string.h>

#include "utils/tracefs.h"
#include "utils/utils.h"

#define PROC_MOUNTINFO "/proc/self/mountinfo"

bool find_tracing_dir(char **trace_dir)
{
	FILE *fp;
	char *line = NULL, fs_type[NAME_MAX], mount_point[PATH_MAX];
	static char debugfs_suffix[] = "tracing";
	bool debugfs_found = false;
	size_t len;

	if (*trace_dir)
		return false;

	fp = fopen(PROC_MOUNTINFO, "r");
	if (fp == NULL)
		return false;

	while (getline(&line, &len, fp) > 0) {
		/*
		 * /proc/<pid>/mountinfo format:
		 * 36 35 98:0 /mnt1 /mnt2 rw,noatime master:1 - ext3 .... ....
		 * (1)(2)(3)   (4)   (5)      (6)      (7)   (8) (9) (10) (11)
		 *                mount_point                  fs_type
		 *
		 * (9) is the file system type, (5) is the mount point relative
		 * to self's root directory.
		 */
		sscanf(line, "%*i %*i %*u:%*u %*s %s %*s %*s - %s %*s %*s\n", mount_point, fs_type);

		if (!strcmp(fs_type, "tracefs")) {
			/* discard previously kept debugfs tracing dir */
			if (*trace_dir)
				free(*trace_dir);
			xasprintf(trace_dir, "%s", mount_point);
			pr_dbg2("Found tracefs at %s\n", mount_point);
			pr_dbg2("Use %s as TRACING_DIR\n", *trace_dir);
			return true;
		}

		if (!strcmp(fs_type, "debugfs")) {
			xasprintf(trace_dir, "%s/%s", mount_point, debugfs_suffix);
			pr_dbg2("Found debugfs at %s\n", mount_point);
			pr_dbg2("Keep searching for tracefs...\n");
			debugfs_found = true;
		}
	}

	/* we couldn't find a tracefs, but found a debugfs... */
	if (debugfs_found) {
		pr_dbg2("Use %s as TRACING_DIR\n", *trace_dir);
		return true;
	}

	pr_dbg2("No tracefs or debugfs found..!\n");
	return false;
}
