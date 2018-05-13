#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <assert.h>
#include <dirent.h>
#include <pthread.h>
#include <signal.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/ioctl.h>
#include <sys/eventfd.h>
#include <sys/resource.h>
#include <sys/epoll.h>
#include <fnmatch.h>
#include <linux/limits.h>
#include <sys/ptrace.h>
#include <sys/time.h>

#include "uftrace.h"
#include "libmcount/mcount.h"
#include "utils/utils.h"
#include "utils/symbol.h"
#include "utils/list.h"
#include "utils/filter.h"
#include "utils/kernel.h"
#include "utils/perf.h"
#include "utils/compiler.h"
#include "utils/env-file.h"


// define which method to use.
#define DYNAMIC_TO_PROCESS 0

static bool has_perf_event;
static char absolute_file_path[PATH_MAX];
extern int do_main_loop(int pfd[2], int ready, struct opts *opts, int pid);
extern bool check_linux_schedule_event(char *events,
				       enum uftrace_pattern_type ptype);
extern bool check_linux_perf_event(char *events);
extern char *build_debug_domain_string(void);
extern int inject(char* libname, pid_t pid);

#define ERROR_WITHOUT_LDPRELOAD \
"you must specify LD_PRELOAD path by using '-L' option if want use \n"	\
"\tdynamic tracing to the process.\n"

/*
 * Create a temporary file to save the environment variable for uftrace.
 *
 * in case for dynamic tracing to processes, we use file to passing
 * environment variable for uftrace because LD_PRELOAD not work.
 */
static void make_uftrace_environ_file(struct opts *opts, int pfd)
{
	char buf[4096];
	char *old_preload, *old_libpath;
	int env_fd;
	int method = DYNAMIC_TO_PROCESS;

	env_fd = create_env_file();
	if (env_fd < 0)
		pr_err_ns("FILE OPEN FAILED\n");

	if (opts->pid) {
		method = DYNAMIC_TO_PROCESS;
	}

	if (opts->lib_path) {
		strcpy(buf, opts->lib_path);
		strcat(buf, "/libmcount:");
	} else {
		if (method == DYNAMIC_TO_PROCESS) {
			pr_err_ns(ERROR_WITHOUT_LDPRELOAD);
		}
		/* to make strcat() work */
		buf[0] = '\0';
	}

#ifdef INSTALL_LIB_PATH
	strcat(buf, INSTALL_LIB_PATH);
#endif

	old_libpath = getenv("LD_LIBRARY_PATH");
	if (old_libpath) {
		size_t len = strlen(buf) + strlen(old_libpath) + 2;
		char *libpath = xmalloc(len);

		snprintf(libpath, len, "%s:%s", buf, old_libpath);
		set_env_to_file(env_fd, "LD_LIBRARY_PATH", libpath);
		free(libpath);
	}
	else {
		set_env_to_file(env_fd, "LD_LIBRARY_PATH", buf);
	}

	if (opts->filter) {
		char *filter_str = uftrace_clear_kernel(opts->filter);

		if (filter_str) {
			set_env_to_file(env_fd, "UFTRACE_FILTER", filter_str);
			free(filter_str);
		}
	}

	if (opts->trigger) {
		char *trigger_str = uftrace_clear_kernel(opts->trigger);

		if (trigger_str) {
			set_env_to_file(env_fd, "UFTRACE_TRIGGER", trigger_str);
			free(trigger_str);
		}
	}

	if (opts->retval) {
		char *retval_str = uftrace_clear_kernel(opts->retval);

		if (retval_str) {
			set_env_to_file(env_fd, "UFTRACE_RETVAL", retval_str);
			free(retval_str);
		}
	}

	if (opts->auto_args) {
		set_env_to_file(env_fd, "UFTRACE_AUTO_ARGS", "1");
	}

	if (opts->patch) {
		char *patch_str = uftrace_clear_kernel(opts->patch);

		if (patch_str) {
			set_env_to_file(env_fd, "UFTRACE_PATCH", patch_str);
			free(patch_str);
		}
	}

	if (opts->event) {
		char *event_str = uftrace_clear_kernel(opts->event);

		if (event_str) {
			set_env_to_file(env_fd, "UFTRACE_EVENT", event_str);
			free(event_str);
		}
	}

	if (opts->depth != OPT_DEPTH_DEFAULT) {
		snprintf(buf, sizeof(buf), "%d", opts->depth);
		set_env_to_file(env_fd, "UFTRACE_DEPTH", buf);
	}

	if (opts->max_stack != OPT_RSTACK_DEFAULT) {
		snprintf(buf, sizeof(buf), "%d", opts->max_stack);
		set_env_to_file(env_fd, "UFTRACE_MAX_STACK", buf);
	}

	if (opts->threshold) {
		snprintf(buf, sizeof(buf), "%"PRIu64, opts->threshold);
		set_env_to_file(env_fd, "UFTRACE_THRESHOLD", buf);
	}

	if (opts->libcall) {
		set_env_to_file(env_fd, "UFTRACE_PLTHOOK", "1");

		if (opts->want_bind_not) {
			/* do not update GOTPLT after resolving symbols */
			set_env_to_file(env_fd, "LD_BIND_NOT", "1");
		}

		if (opts->nest_libcall) {
			set_env_to_file(env_fd, "UFTRACE_NEST_LIBCALL", "1");
		}
	}

	if (strcmp(opts->dirname, UFTRACE_DIR_NAME)) {
		set_env_to_file(env_fd, "UFTRACE_DIR", opts->dirname);
	}

	if (opts->bufsize != SHMEM_BUFFER_SIZE) {
		snprintf(buf, sizeof(buf), "%lu", opts->bufsize);
		set_env_to_file(env_fd, "UFTRACE_BUFFER", buf);
	}

	if (opts->logfile) {
		snprintf(buf, sizeof(buf), "%d", fileno(logfp));
		set_env_to_file(env_fd, "UFTRACE_LOGFD", buf);
	}

	snprintf(buf, sizeof(buf), "%d", pfd);
	set_env_to_file(env_fd, "UFTRACE_PIPE", buf);
	set_env_to_file(env_fd, "UFTRACE_SHMEM", "1");

	if (debug) {
		snprintf(buf, sizeof(buf), "%d", debug);
		set_env_to_file(env_fd, "UFTRACE_DEBUG", buf);
		set_env_to_file(env_fd, "UFTRACE_DEBUG_DOMAIN", build_debug_domain_string());
	}

	if(opts->disabled) {
		set_env_to_file(env_fd, "UFTRACE_DISABLED", "1");
	}

	if (log_color == COLOR_ON) {
		snprintf(buf, sizeof(buf), "%d", log_color);
		set_env_to_file(env_fd, "UFTRACE_COLOR", buf);
	}

	snprintf(buf, sizeof(buf), "%d", demangler);
	set_env_to_file(env_fd, "UFTRACE_DEMANGLE", buf);

	if ((opts->kernel || has_kernel_event(opts->event)) &&
	    check_kernel_pid_filter()) {
		set_env_to_file(env_fd, "UFTRACE_KERNEL_PID_UPDATE", "1");
	}

	if (opts->script_file) {
		set_env_to_file(env_fd, "UFTRACE_SCRIPT", opts->script_file);
	}

	if (opts->lib_path)
		snprintf(buf, sizeof(buf), "%s/libmcount/", opts->lib_path);
	else
		buf[0] = '\0';  /* to make strcat() work */

	strcat(buf, "libmcount-dynamic.so");
	pr_dbg("using %s library for tracing\n", buf);

	old_preload = getenv("LD_PRELOAD");
	if (old_preload) {
		size_t len = strlen(buf) + strlen(old_preload) + 2;
		char *preload = xmalloc(len);

		snprintf(preload, len, "%s:%s", buf, old_preload);
		set_env_to_file(env_fd, "LD_PRELOAD", preload);
		free(preload);
	}
	else {
		set_env_to_file(env_fd, "LD_PRELOAD", buf);
	}

	// The process ID to inject the shared object.
	snprintf(buf, sizeof(buf), "%d", getpid());
	set_env_to_file(env_fd, "UFTRACE_PID", buf);

	// The below code should be placed at the end.
	set_env_to_file(env_fd, "XRAY_OPTIONS", "patch_premain=false");
	close(env_fd);
}

// settings for using dynamic tracing feature.
void setup_uftrace_environ(struct opts *opts, int pfd)
{
	make_uftrace_environ_file(opts, pfd);
}


char* get_libtrigger_path(struct opts *opts)
{
	char *lib = xmalloc(PATH_MAX);
	char *libtrigger = "libtrigger.so";
        if (opts->lib_path) {
                snprintf(lib, PATH_MAX, "%s/libmcount/%s", opts->lib_path, libtrigger);

                if (access(lib, F_OK) == 0) {
                        return lib;
                }
                else if (errno == ENOENT) {
                        snprintf(lib, PATH_MAX, "%s/%s", opts->lib_path, libtrigger);                        if (access(lib, F_OK) == 0)
                                return lib;
                }
                free(lib);
                return NULL;
        }

#ifdef INSTALL_LIB_PATH
        snprintf(lib, PATH_MAX, "%s/%s", INSTALL_LIB_PATH, libtrigger);
        if (access(lib, F_OK) != 0 && errno == ENOENT)
                pr_warn("Didn't you run 'make install' ?\n");
#endif
        strcpy(lib, libtrigger);
	return lib;
}


/*
 * inject the shared object 'libtrigger.so' to processes.
 *
 * inject libtrigger.so using '__libc_dlopen_mode' which export
 * from 'libc.so'. This is because libc.so is always loaded.
 * Another option is to use 'dlopen' which exported from libdl.so,
 * but 'libdl.so' will not always load.
 *
 * we must  have to load 'libmcount-dynamic.so' but '__libc_dlopen_mode'
 * will failed to load it. maybe there is some complex issue.
 *
 * therefore, we inject 'libtrigger.so' to the process first.
 * after it loaded, it will load 'libmcount-dynamic.so' continuly
 * with using 'dlopen'.
 */
void do_inject(int pfd[2], int ready, struct opts *opts, char *argv[])
{
	int target_pid = opts->pid;
	char* libtrigger_path;
        uint64_t dummy;
        close(pfd[0]);
	setup_uftrace_environ(opts, pfd[1]);

        if (read(ready, &dummy, sizeof(dummy)) != (ssize_t)sizeof(dummy))
                pr_err("waiting for parent failed");

	libtrigger_path = get_libtrigger_path(opts);

	if(libtrigger_path == NULL)
		pr_err("connot found libtrigger.so at %s\n", libtrigger_path);
	pr_dbg("libtrigger found at : %s\n", libtrigger_path);
	inject(libtrigger_path, target_pid);
}

/*
find the executable file for the process you want to inject.
Local symbol informations are required to use dynamic tracing.
*/
int find_exefile(struct opts *opts) {
	DIR *directory = opendir("/proc/");
	char* exePath;
	int exePathLen = 0x1000;
	ssize_t len;
	pid_t pid = opts->pid;

	if (!directory)
		return 0;
	exePath = malloc(exePathLen * sizeof(char));
	sprintf(exePath, "/proc/%d/exe", pid);
	exePath[exePathLen-1] = '\0';
	len = readlink(exePath, absolute_file_path, PATH_MAX - 1);
	if(len == -1) {
		free(exePath);
		return 0;
	}
	absolute_file_path[len] = '\0';
	free(exePath);
	closedir(directory);
	opts->exename = absolute_file_path;
	return 1;
}

#define UFTRACE_MSG  "Cannot trace '%s': No such executable file\n"	\
"\tNote that uftrace doesn't search $PATH for you.\n"			\
"\tIf you really want to trace executables in the $PATH,\n"		\
"\tplease give it the absolute pathname (like /usr/bin/%s).\n"

#define UFTRACE_ELF_MSG  "Cannot trace '%s': Invalid file\n"		\
"\tThis file doesn't look like an executable ELF file.\n"		\
"\tPlease check whether it's a kind of script or shell functions.\n"

#define MACHINE_MSG  "Cannot trace '%s': Unsupported machine\n"		\
"\tThis machine type (%u) is not supported currently.\n"		\
"\tSorry about that!\n"

#define STATIC_MSG  "Cannot trace static binary: %s\n"			\
"\tIt seems to be compiled with -static, rebuild the binary without it.\n"

#ifndef  EM_AARCH64
# define EM_AARCH64  183
#endif

static void check_binary_dynamic_avilable(struct opts *opts)
{
	int fd;
	int chk;
	size_t i;
	char elf_ident[EI_NIDENT];
	uint16_t e_type;
	uint16_t e_machine;
	uint16_t supported_machines[] = {
		EM_X86_64, EM_ARM, EM_AARCH64, EM_386
	};

	pr_dbg3("checking binary %s\n", opts->exename);

	if (access(opts->exename, X_OK) < 0) {
		if (errno == ENOENT && opts->exename[0] != '/') {
			pr_err_ns(UFTRACE_MSG, opts->exename, opts->exename);
		}
		pr_err("Cannot trace '%s'", opts->exename);
	}

	fd = open(opts->exename, O_RDONLY);
	if (fd < 0)
		pr_err("Cannot open '%s'", opts->exename);

	if (read(fd, elf_ident, sizeof(elf_ident)) < 0)
		pr_err("Cannot read '%s'", opts->exename);

	if (memcmp(elf_ident, ELFMAG, SELFMAG))
		pr_err_ns(UFTRACE_ELF_MSG, opts->exename);

	if (read(fd, &e_type, sizeof(e_type)) < 0)
		pr_err("Cannot read '%s'", opts->exename);

	if (e_type != ET_EXEC && e_type != ET_DYN)
		pr_err_ns(UFTRACE_ELF_MSG, opts->exename);

	if (read(fd, &e_machine, sizeof(e_machine)) < 0)
		pr_err("Cannot read '%s'", opts->exename);

	for (i = 0; i < ARRAY_SIZE(supported_machines); i++) {
		if (e_machine == supported_machines[i])
			break;
	}
	if (i == ARRAY_SIZE(supported_machines))
		pr_err_ns(MACHINE_MSG, opts->exename, e_machine);

	chk = check_static_binary(opts->exename);
	if (chk) {
		if (chk < 0)
			pr_err_ns("Cannot check '%s'\n", opts->exename);
		else
			pr_err_ns(STATIC_MSG, opts->exename);
	}

	close(fd);
}

int command_dynamic(int argc, char *argv[], struct opts *opts)
{
	int pid;
	int pfd[2];
	int efd;
	int ret = -1;

	if (pipe(pfd) < 0)
		pr_err("cannot setup internal pipe");

	if (create_directory(opts->dirname) < 0)
		return -1;

	/* apply script-provided options */
	if (opts->script_file)
		parse_script_opt(opts);


	if (!find_exefile(opts))
		pr_err("Cannot find executable file path\n");

	pr_dbg("FIND EXECUTABLE FILE PATH : %s\n", opts->exename);

	// Check the binary to ensure that
	// dynamic tracing is available.
	check_binary_dynamic_avilable(opts);

	has_perf_event = check_linux_schedule_event(opts->event,
						    opts->patt_type);

	fflush(stdout);

	efd = eventfd(0, EFD_CLOEXEC | EFD_SEMAPHORE);
	if (efd < 0)
		pr_dbg("creating eventfd failed: %d\n", efd);

	pid = fork();

        if (pid < 0)
                pr_err("cannot start child process");

	// Dynamic to process
	if (pid == 0)
		do_inject(pfd, efd, opts, argv);
	else
		ret = do_main_loop(pfd, efd, opts, pid);
	return ret;
}
