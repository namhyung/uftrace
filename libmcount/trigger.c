#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <stdbool.h>
#include <inttypes.h>

#include "libmcount/mcount.h"
#include "utils/env-file.h"
#include "utils/utils.h"


#define ERROR_LIBRARY_NOT_EXIST \
"%s does not exist libmcount shared object .\n" 			\
"\tmake sure that the file exists. \n\n"				\
"\t[notification]\n"							\
"\twhen you use dynamic tracing to the process, you must specify the\n"	\
"\tabsolute path of 'libmcount-dynamic.so' not the relative path.\n\n" 	\
"\tfor example:\n" 							\
"\t[BADD]./uftrace dynamic -L. --pid=xxxx \n"				\
"\t[GOOD]./uftrace dynaimc -L/home/m/uftrace  --pid=xxxx \n"

#define ERROR_DATADIR_NOT_EXIST \
"Cannot access to the %s for saving uftrace datas.\n"  			\
"\tmake sure that the path exists. \n\n" 				\
"\t[notification]\n"							\
"\twhen you use dynamic tracing to the process, you must specify the\n"	\
"\tabsolute path of data-dir.\n\n" 					\
"\tfor example:\n" 							\
"\t[BADD]./uftrace dynamic -L/home/m/uftrace --pid=xxxx \n" 		\
"\t[GOOD]./uftrace dynaimc -L/home/m/uftrace"				\
"--data=/home/m/uftrace/data --pid=xxxx \n"

#define ERROR_ENVFILE_NOT_EXIST \
"\tCannot access to the %s which contain environment variable.\n"


__attribute__((weak)) void build_debug_domain(char *dbg_domain_str)
{
        int i, len;

        if (dbg_domain_str == NULL)
                return;

        len = strlen(dbg_domain_str);
        for (i = 0; i < len; i += 2) {
                const char *pos;
                char domain = dbg_domain_str[i];
                int level = dbg_domain_str[i+1] - '0';
                int d;

                pos = strchr(DBG_DOMAIN_STR, domain);
                if (pos == NULL)
                        continue;

                d = pos - DBG_DOMAIN_STR;
                dbg_domain[d] = level;
        }
}

__attribute__((constructor)) void so_main() {
	char* debug_str;
	char* preload_library_path;
	char* data_dir_path;
	int fd_envfile;
	struct stat file;

	outfp = stdout;
	logfp = stderr;

        /*
        the Process output is delayed for unknown reasons when using
        dynamic tracing. cannot found the reason of delay but below code
        can mitigation the symptom.
        */
        setvbuf(stdout, NULL, _IONBF, 1024);
        setvbuf(stderr, NULL, _IONBF, 1024);

	fd_envfile = open_env_file();
	if (fd_envfile < 0) {
		printf(ERROR_ENVFILE_NOT_EXIST, ENV_FILE);
	}
	set_env_from_file(fd_envfile);
	preload_library_path = getenv("LD_PRELOAD");
	data_dir_path = getenv("UFTRACE_DIR");

	debug_str = getenv("UFTRACE_DEBUG");
        if (debug_str) {
                debug = strtol(debug_str, NULL, 0);
                build_debug_domain(getenv("UFTRACE_DEBUG_DOMAIN"));
        }

	pr_dbg("LIBRARY PATH : %s\n", preload_library_path);
	pr_dbg("DATADIR PATH : %s\n", data_dir_path);

	if (stat(data_dir_path, &file) == 0) {
		pr_dbg("DATA-DIR EXIST : %s\n", data_dir_path);
	} else {
		pr_err_ns(ERROR_DATADIR_NOT_EXIST, data_dir_path);
	}

	if (stat(preload_library_path, &file) == 0) {
		pr_dbg("LIBRARY EXIST : %s\n", preload_library_path);
	} else {
		pr_err_ns(ERROR_LIBRARY_NOT_EXIST, preload_library_path);
	}

	void* handle = dlopen(preload_library_path, RTLD_LAZY);
	if (!handle) {
		pr_err_ns("%s\n", dlerror());
        }
}


