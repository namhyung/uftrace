/*
 * Arguments / return type option tables for automatic value display
 *
 * This file is auto-generated by "gen-autoargs.py" based on prototypes.h
 */

static char *auto_enum_list =
	"enum uft_mmap_prot { PROT_NONE, PROT_READ, PROT_WRITE, PROT_EXEC = 4, };"
	"enum uft_mmap_flag {MAP_SHARED = 0x1,MAP_PRIVATE = 0x2,MAP_FIXED = 0x10,MAP_ANON = 0x20,MAP_GROWSDOWN = 0x100,MAP_DENYWRITE = 0x800,MAP_EXECUTABLE = 0x1000,MAP_LOCKED = 0x2000,MAP_NORESERVE = 0x4000,MAP_POPULATE = 0x8000,MAP_NONBLOCK = 0x10000,MAP_STACK = 0x20000,MAP_HUGETLB = 0x40000,};"
	"enum uft_madvise {MADV_NORMAL = 0,MADV_RANDOM = 1,MADV_SEQUENTIAL = 2,MADV_WILLNEED = 3,MADV_DONTNEED = 4,MADV_FREE = 8,MADV_REMOVE = 9,MADV_DONTFORK = 10,MADV_DOFORK = 11,MADV_MERGEABLE = 12,MADV_UNMERGEABLE = 13,MADV_HUGEPAGE = 14,MADV_NOHUGEPAGE = 15,MADV_DONTDUMP = 16,MADV_DODUMP = 17,MADV_HWPOISON = 100,};"
	"enum uft_posix_madvise {POSIX_MADV_NORMAL = 0,POSIX_MADV_RANDOM = 1,POSIX_MADV_SEQUENTIAL = 2,POSIX_MADV_WILLNEED = 3,POSIX_MADV_DONTNEED = 4,};"
	"enum uft_posix_fadvise {POSIX_FADV_NORMAL = 0,POSIX_FADV_RANDOM = 1,POSIX_FADV_SEQUENTIAL = 2,POSIX_FADV_WILLNEED = 3,POSIX_FADV_DONTNEED = 4,POSIX_FADV_NOREUSE = 5,};"
	"enum uft_open_flag {O_RDONLY = 00,O_WRONLY = 01,O_RDWR = 02,O_CREAT = 0100,O_EXCL = 0200,O_NOCTTY = 0400,O_TRUNC = 01000,O_APPEND = 02000,O_NONBLOCK = 04000,O_DSYNC = 010000,O_ASYNC = 020000,O_DIRECT = 040000,O_LARGEFILE = 0100000,O_DIRECTORY = 0200000,O_NOFOLLOW = 0400000,O_NOATIME = 01000000,O_CLOEXEC = 02000000,O_SYNC = 04010000,O_PATH = 010000000,};"
	"enum uft_fcntl_cmd {F_DUPFD, F_GETFD, F_SETFD, F_GETFL, F_SETFL,F_GETLK, F_SETLK, F_SETLKW,F_SETOWN, F_GETOWN, F_SEGSIG, F_GETSIG,F_GETLK64, F_SETLK64, F_SETLKW64,F_SETOWN_EX, F_GETOWN_EX,};"
	"enum uft_seek_whence { SEEK_SET, SEEK_CUR, SEEK_END, SEEK_DATA, SEEK_HOLE, };"
	"enum uft_falloc_mde {FALLOC_FL_KEEP_SIZE = 1,FALLOC_FL_PUNCH_HOLE = 2,FALLOC_FL_NO_HIDE_STALE = 4,FALLOC_FL_COLLAPSE_RANGE = 8,FALLOC_FL_ZERO_RANGE = 16,FALLOC_FL_INSERT_RANGE = 32,FALLOC_FL_UNSHARE_RANGE = 64,};"
	"enum uft_access_flag {F_OK = 0, X_OK = 1, W_OK = 2, R_OK = 4,};"
	"enum uft_dlopen_flag {RTLD_LOCAL = 0,RTLD_LAZY = 1,RTLD_NOW = 2,RTLD_NOLOAD = 4,RTLD_DEEPBIND = 8,RTLD_GLOBAL = 0x100,RTLD_NODELETE = 0x1000,};"
	"enum uft_socket_domain {AF_UNSPEC = 0, AF_UNIX, AF_INET, AF_AX25, AF_IPX, AF_APPLETALK, AF_NETROM, AF_BRIDGE,AF_ATMPVC = 8, AF_X25, AF_INET6, AF_ROSE, AF_DECnet, AF_NETBEUI, AF_SECURITY, AF_KEY,AF_NETLINK = 16, AF_PACKET, AF_ASH, AF_ECONET, AF_ATMSVC, AF_RDS, AF_SNA, AF_IRDA,AF_PPPOX = 24, AF_WANPIPE, AF_LLC, AF_IB, AF_MPLS, AF_CAN, AF_TPIC, AF_BLUETOOTH,AF_IUCV = 32, AF_RXRPC, AF_ISDN, AF_PHONET, AF_IEEE802154, AF_CAIF, AF_ALG, AF_NFC,AF_VSOCK = 40, AF_KCM, AF_QIPCRTR, AF_SMC,};"
	"enum uft_socket_type {SOCK_STREAM = 1, SOCK_DGRAM, SOCK_RAW, SOCK_RDM, SOCK_SEQPACKET, SOCK_DCCP,SOCK_PACKET = 10,};"
	"enum uft_socket_flag {SOCK_NONBLOCK = 04000, SOCK_CLOEXEC = 02000000,};"
	"enum uft_signal {SIGNULL = 0, SIGHUP, SIGINT, SIGQUIT, SIGILL, SIGTRAP, SIGABRT, SIGBUS, SIGFPE,SIGKILL = 9, SIGUSR1, SIGSEGV, SIGUSR2, SIGPIPE, SIGALRM, SIGTERM, SIGSTKFLT,SIGCHLD = 17, SIGCONT, SIGSTOP, SIGTSTP, SIGTTIN, SIGTTOU, SIGURG, SIGXCPU,SIGXFSZ = 25, SIGVTALRM, SIGPROF, SIGWINCH, SIGPOLL, SIGPWR, SIGSYS,SIGRTMIN = 32, SIGRTMAX = 64,};"
	"enum uft_sigmask { SIG_BLOCK, SIG_UNBLOCK, SIG_SETMASK };"
	"enum uft_prctl_op {PR_SET_PDEATHSIG = 1, PR_GET_PDEATHSIG, PR_GET_DUMPABLE, PR_SET_DUMPABLE,PR_GET_UNALIGN = 5, PR_SET_UNALIGN, PR_GET_KEEPCAPS, PR_SET_KEEPCAPS,PR_GET_FPEMU = 9, PR_SET_FPEMU, PR_GET_FPEXC, PR_SET_FPEXC,PR_GET_TIMING = 13, PR_SET_TIMING, PR_SET_NAME, PR_GET_NAME,PR_GET_ENDIAN = 19, PR_SET_ENDIAN, PR_GET_SECCOMP, PR_SET_SECCOMP,PR_CAPBSET_READ = 23, PR_CAPBSET_DROP, PR_GET_TSC, PR_SET_TSC,PR_GET_SECUREBITS = 27, PR_SET_SECUREBITS, PR_SET_TIMERSLACK, PR_GET_TIMERSLACK,PR_TASK_PERF_EVENTS_DISABLE = 31, PR_TASK_PERF_EVENTS_ENABLE,PR_MCE_KILL = 33, PR_MCE_KILL_GET, PR_SET_MM,PR_SET_CHILD_SUBREAPER = 36, PR_GET_CHILD_SUBREAPER,PR_SET_NO_NEW_PRIVS = 38, PR_GET_NO_NEW_PRIVS, PR_GET_TID_ADDRESS,PR_SET_THP_DISABLE = 41, PR_GET_THP_DISABLE,PR_MPX_ENABLE_MANAGEMENT = 43, PR_MPX_DISABLE_MANAGEMENT,PR_SET_FP_MODE = 45, PR_GET_FP_MODE, PR_CAP_AMBIENT,};"
	"enum uft_epoll_op { EPOLL_CTL_ADD = 1, EPOLL_CTL_DEL, EPOLL_CTL_MOD };"
	"enum uft_locale {LC_TYPE = 0, LC_NUMERIC, LC_TIME, LC_COLLATE, LC_MONETARY, LC_MESSAGES,LC_ALL, LC_PAPER, LC_NAME, LC_ADDRESS, LC_TELEPHONE, LC_MEASUREMENT,LC_IDENTIFICATION,};"
	"enum uft_mode {mod_777 = 0777, mod_755 = 0755, mod_666 = 0666, mod_644 = 0644,mod_400 = 0400, mod_600 = 0600, mod_660 = 0660, mod_640 = 0640,mod_444 = 0444, mod_022 = 0022, mod_440 = 0440, mod_222 = 0222,mod_111 = 0111, mod_011 = 0011, mod_033 = 0033, mod_077 = 0077,};"
	"enum uft_clockid_t {CLOCK_REALTIME = 0,CLOCK_MONOTONIC,CLOCK_PROCESS_CPUTIME_ID,CLOCK_THREAD_CPUTIME_ID,CLOCK_MONOTONIC_RAW,CLOCK_REALTIME_COARSE,CLOCK_MONOTONIC_COARSE,CLOCK_BOOTTIME,CLOCK_REALTIME_ALARM,CLOCK_BOOTTIME_ALARM,CLOCK_TAI = 11,};";

static char *auto_args_list =
	"_Znwm@arg1/u;"
	"_Znam@arg1/u;"
	"_ZdlPv@arg1/x;"
	"_ZdaPv@arg1/x;"
	"atoi@arg1/s;"
	"atol@arg1/s;"
	"atof@arg1/s;"
	"strtol@arg1/s,arg2/p,arg3/d32;"
	"strtoul@arg1/s,arg2/p,arg3/d32;"
	"strtod@arg1/s,arg2/p;"
	"strtof@arg1/s,arg2/p;"
	"qsort@arg1/p,arg2/u,arg3/u,arg4/p;"
	"qsort_r@arg1/p,arg2/u,arg3/u,arg4/p,arg5/p;"
	"bsearch@arg1/p,arg2/p,arg3/u,arg4/u,arg5/p;"
	"exit@arg1/d32;"
	"malloc@arg1/u;"
	"free@arg1/p;"
	"calloc@arg1/u,arg2/u;"
	"realloc@arg1/p,arg2/u;"
	"mmap@arg1/p,arg2/u,arg3/e:uft_mmap_prot,arg4/e:uft_mmap_flag,arg5/d32,arg6;"
	"mmap64@arg1/p,arg2/u,arg3/e:uft_mmap_prot,arg4/e:uft_mmap_flag,arg5/d32,arg6/d64;"
	"munmap@arg1/p,arg2/u;"
	"mprotect@arg1/p,arg2/u,arg3/e:uft_mmap_prot;"
	"madvise@arg1/p,arg2/u,arg3/e:uft_madvise;"
	"posix_madvise@arg1/p,arg2/u,arg3/e:uft_posix_madvise;"
	"posix_fadvise@arg1/d32,arg2,arg3,arg4/e:uft_posix_fadvise;"
	"brk@arg1/p;"
	"sbrk@arg1;"
	"memalign@arg1/u,arg2/u;"
	"pvalloc@arg1/u;"
	"posix_memalign@arg1/p,arg2/u,arg3/u;"
	"aligned_alloc@arg1/u,arg2/u;"
	"valloc@arg1/u;"
	"strcat@arg1/s,arg2/s;"
	"strncat@arg1/s,arg2/s,arg3/u;"
	"strcpy@arg1/p,arg2/s;"
	"strncpy@arg1/p,arg2/s,arg3/u;"
	"strlen@arg1/s;"
	"strnlen@arg1/s,arg2/u;"
	"strcmp@arg1/s,arg2/s;"
	"strncmp@arg1/s,arg2/s,arg3/u;"
	"strcasecmp@arg1/s,arg2/s;"
	"strncasecmp@arg1/s,arg2/s,arg3/u;"
	"strdup@arg1/s;"
	"strndup@arg1/s,arg2/u;"
	"strdupa@arg1/s;"
	"strndupa@arg1/s,arg2/u;"
	"strcoll@arg1/s,arg2/s;"
	"strstr@arg1/s,arg2/s;"
	"strcasestr@arg1/s,arg2/s;"
	"strchr@arg1/s,arg2/c;"
	"strrchr@arg1/s,arg2/c;"
	"strchrnul@arg1/s,arg2/c;"
	"strtok@arg1/s,arg2/s;"
	"strtok_r@arg1/s,arg2/s,arg3/p;"
	"strpbrk@arg1/s,arg2/s;"
	"strspn@arg1/s,arg2/s;"
	"strcspn@arg1/s,arg2/s;"
	"strsep@arg1/p,arg2/s;"
	"memcpy@arg1/p,arg2/p,arg3/u;"
	"memset@arg1/p,arg2/d32,arg3/u;"
	"memcmp@arg1/p,arg2/p,arg3/u;"
	"memmove@arg1/p,arg2/p,arg3/u;"
	"memchr@arg1/p,arg2/d32,arg3/u;"
	"memrchr@arg1/p,arg2/d32,arg3/u;"
	"rawmemchr@arg1/p,arg2/d32;"
	"printf@arg1/s;"
	"fprintf@arg1/p,arg2/s;"
	"dprintf@arg1/d32,arg2/s;"
	"sprintf@arg1/p,arg2/s;"
	"snprintf@arg1/p,arg2/u,arg3/s;"
	"fputc@arg1/c,arg2/p;"
	"fputs@arg1/s,arg2/p;"
	"putc@arg1/c,arg2/p;"
	"putchar@arg1/c;"
	"puts@arg1/s;"
	"fgetc@arg1/p;"
	"fgets@arg1/p,arg2/d32,arg3/p;"
	"getc@arg1/p;"
	"ungetc@arg1/c,arg2/p;"
	"getenv@arg1/s;"
	"setenv@arg1/s,arg2/s,arg3/d32;"
	"unsetenv@arg1/s;"
	"open@arg1/s,arg2/e:uft_open_flag;"
	"open64@arg1/s,arg2/e:uft_open_flag;"
	"openat@arg1/d32,arg2/s,arg3/e:uft_open_flag;"
	"open64at@arg1/d32,arg2/s,arg3/e:uft_open_flag;"
	"close@arg1/d32;"
	"fcntl@arg1/d32,arg2/e:uft_fcntl_cmd;"
	"fcntl64@arg1/d32,arg2/e:uft_fcntl_cmd;"
	"lseek@arg1/d32,arg2,arg3/e:uft_seek_whence;"
	"fallocate@arg1/d32,arg2/e:uft_falloc_mode,arg3,arg4;"
	"fsync@arg1/d32;"
	"fdatasync@arg1/d32;"
	"fopen@arg1/s,arg2/s;"
	"fopen64@arg1/s,arg2/s;"
	"fdopen@arg1/d32,arg2/s;"
	"freopen@arg1/s,arg2/s,arg3/p;"
	"fclose@arg1/p;"
	"fseek@arg1/p,arg2,arg3/d32;"
	"ftell@arg1/p;"
	"fflush@arg1/p;"
	"read@arg1/d32,arg2/p,arg3/u;"
	"write@arg1/d32,arg2/p,arg3/u;"
	"fread@arg1/p,arg2/u,arg3/u,arg4/p;"
	"fwrite@arg1/p,arg2/u,arg3/u,arg4/p;"
	"feof@arg1/p;"
	"ferror@arg1/p;"
	"fileno@arg1/p;"
	"access@arg1/s,arg2/e:uft_access_flag;"
	"unlink@arg1/s;"
	"unlinkat@arg1/d32,arg2/s,arg3/d32;"
	"mkdir@arg1/s;"
	"rmdir@arg1/s;"
	"chdir@arg1/s;"
	"opendir@arg1/s;"
	"closedir@arg1/p;"
	"getcwd@arg1/p,arg2/u;"
	"dirname@arg1/s;"
	"basename@arg1/s;"
	"execl@arg1/s,arg2/s;"
	"execlp@arg1/s,arg2/s;"
	"execle@arg1/s,arg2/s;"
	"execv@arg1/s;"
	"execvp@arg1/s;"
	"execve@arg1/s;"
	"execvpe@arg1/s;"
	"wait@arg1/p;"
	"waitpid@arg1/i32,arg2/p,arg3/d32;"
	"dlopen@arg1/s,arg2/e:uft_dlopen_flag;"
	"dlmopen@arg1,arg2/s,arg3/d32;"
	"dlsym@arg1/p,arg2/s;"
	"dlvsym@arg1/p,arg2/s,arg3/s;"
	"dlclose@arg1/p;"
	"pthread_create@arg1/p,arg2/p,arg3/p,arg4/p;"
	"pthread_once@arg1/p,arg2/p;"
	"pthread_join@arg1,arg2/p;"
	"pthread_detach@arg1;"
	"pthread_kill@arg1,arg2/d32;"
	"pthread_cancel@arg1;"
	"pthread_exit@arg1/p;"
	"pthread_mutex_lock@arg1/p;"
	"pthread_mutex_trylock@arg1/p;"
	"pthread_mutex_unlock@arg1/p;"
	"pthread_mutex_destroy@arg1/p;"
	"pthread_mutex_init@arg1/p,arg2/p;"
	"pthread_cond_wait@arg1/p,arg2/p;"
	"pthread_cond_timedwait@arg1/p,arg2/p,arg3/p;"
	"pthread_cond_signal@arg1/p;"
	"pthread_cond_broadcast@arg1/p;"
	"socket@arg1/e:uft_socket_domain,arg2/e:uft_socket_type,arg3/d32;"
	"connect@arg1/d32,arg2/p,arg3;"
	"bind@arg1/d32,arg2/p,arg3;"
	"accept@arg1/d32,arg2/p,arg3/p;"
	"accept4@arg1/d32,arg2/p,arg3/p,arg4/e:uft_socket_flag;"
	"gethostbyname@arg1/s;"
	"gethostbyaddr@arg1/p,arg2,arg3/e:uft_socket_domain;"
	"getaddrinfo@arg1/s,arg2/s,arg3/p,arg4/p;"
	"freeaddrinfo@arg1/p;"
	"inet_pton@arg1/e:uft_socket_domain,arg2/s,arg3/p;"
	"inet_ntop@arg1/e:uft_socket_domain,arg2/p,arg3/s,arg4;"
	"inet_aton@arg1/s,arg2/p;"
	"inet_ntoa@arg1;"
	"inet_addr@arg1/s;"
	"inet_network@arg1/s;"
	"kill@arg1/i32,arg2/e:uft_signal;"
	"raise@arg1/e:uft_signal;"
	"signal@arg1/e:uft_signal,arg2/p;"
	"sigaction@arg1/e:uft_signal,arg2/p,arg3/p;"
	"sigemptyset@arg1/p;"
	"sigfillset@arg1/p;"
	"sigaddset@arg1/p,arg2/e:uft_signal;"
	"sigdelset@arg1/p,arg2/e:uft_signal;"
	"sigismember@arg1/p,arg2/e:uft_signal;"
	"sigprocmask@arg1/e:uft_sigmask,arg2/p,arg3/p;"
	"pthread_sigmask@arg1/e:uft_sigmask,arg2/p,arg3/p;"
	"prctl@arg1/e:uft_prctl_op,arg2/u,arg3,arg4/u,arg5,arg6/u,arg7,arg8/u,arg9;"
	"select@arg1/d32,arg2/p,arg3/p,arg4/p,arg5/p;"
	"pselect@arg1/d32,arg2/p,arg3/p,arg4/p,arg5/p,arg6/p;"
	"poll@arg1/p,arg2,arg3/d32;"
	"ppoll@arg1/p,arg2,arg3/p,arg4/p;"
	"epoll_create@arg1/d32;"
	"epoll_create1@arg1/d32;"
	"epoll_ctl@arg1/d32,arg2/e:uft_epoll_op,arg3/d32,arg4/p;"
	"epoll_wait@arg1/d32,arg2/p,arg3/d32,arg4/d32;"
	"epoll_pwait@arg1/d32,arg2/p,arg3/d32,arg4/d32,arg5/p;"
	"syscall@arg1;"
	"ioctl@arg1/d32,arg2/u,arg3;"
	"textdomain@arg1/s;"
	"bindtextdomain@arg1/s,arg2/s;"
	"gettext@arg1/s;"
	"dgettext@arg1/s,arg2/s;"
	"dcgettext@arg1/s,arg2/s,arg3/d32;"
	"setlocale@arg1/e:uft_locale,arg2/s;"
	"getopt@arg1/d32,arg2/p,arg3/s;"
	"getopt_long@arg1/d32,arg2/p,arg3/s;"
	"getopt_long_only@arg1/d32,arg2/p,arg3/s;"
	"stat@arg1/s,arg2/p;"
	"fstat@arg1/d32,arg2/p;"
	"lstat@arg1/s,arg2/p;"
	"chmod@arg1/s,arg2/e:uft_mode;"
	"fchmod@arg1/d32,arg2/e:uft_mode;"
	"umask@arg1/e:uft_mode;"
	"creat@arg1/s,arg2/e:uft_mode;"
	"creat64@arg1/s,arg2/e:uft_mode;"
	"isatty@arg1/d32;"
	"setuid@arg1/i32;"
	"setgid@arg1/i32;"
	"seteuid@arg1/i32;"
	"setegid@arg1/i32;"
	"setreuid@arg1/i32,arg2/i32;"
	"setregid@arg1/i32,arg2/i32;"
	"setresuid@arg1/i32,arg2/i32,arg3/i32;"
	"setresgid@arg1/i32,arg2/i32,arg3/i32;"
	"chown@arg1/s,arg2/i32,arg3/i32;"
	"lchown@arg1/s,arg2/i32,arg3/i32;"
	"fchown@arg1/d32,arg2/i32,arg3/i32;"
	"dup@arg1/d32;"
	"dup2@arg1/d32,arg2/d32;"
	"sleep@arg1/u;"
	"usleep@arg1/u;"
	"clock_getres@arg1/e:uft_clockid_t,arg2/p;"
	"clock_gettime@arg1/e:uft_clockid_t,arg2/p;"
	"clock_settime@arg1/e:uft_clockid_t,arg2/p;";

static char *auto_retvals_list = "_Znwm@retval/x;"
				 "_Znam@retval/x;"
				 "atoi@retval/d32;"
				 "atol@retval;"
				 "atof@retval/f64;"
				 "strtol@retval;"
				 "strtoul@retval/u;"
				 "strtod@retval/f64;"
				 "strtof@retval/f32;"
				 "bsearch@retval/p;"
				 "malloc@retval/p;"
				 "calloc@retval/p;"
				 "realloc@retval/p;"
				 "mmap@retval/p;"
				 "mmap64@retval/p;"
				 "munmap@retval/d32;"
				 "mprotect@retval/d32;"
				 "madvise@retval/d32;"
				 "posix_madvise@retval/d32;"
				 "posix_fadvise@retval/d32;"
				 "brk@retval/d32;"
				 "sbrk@retval/p;"
				 "memalign@retval/p;"
				 "pvalloc@retval/p;"
				 "posix_memalign@retval/d32;"
				 "aligned_alloc@retval/p;"
				 "valloc@retval/p;"
				 "strcat@retval/s;"
				 "strncat@retval/s;"
				 "strlen@retval/u;"
				 "strnlen@retval/u;"
				 "strcmp@retval/d32;"
				 "strncmp@retval/d32;"
				 "strcasecmp@retval/d32;"
				 "strncasecmp@retval/d32;"
				 "strdup@retval/s;"
				 "strndup@retval/s;"
				 "strdupa@retval/s;"
				 "strndupa@retval/s;"
				 "strcoll@retval/d32;"
				 "strstr@retval/s;"
				 "strcasestr@retval/s;"
				 "strchr@retval/s;"
				 "strrchr@retval/s;"
				 "strchrnul@retval/s;"
				 "strtok@retval/s;"
				 "strtok_r@retval/s;"
				 "strpbrk@retval/s;"
				 "strspn@retval/u;"
				 "strcspn@retval/u;"
				 "strsep@retval/s;"
				 "memcmp@retval/d32;"
				 "memchr@retval/p;"
				 "memrchr@retval/p;"
				 "rawmemchr@retval/p;"
				 "printf@retval/d32;"
				 "fprintf@retval/d32;"
				 "dprintf@retval/d32;"
				 "sprintf@retval/d32;"
				 "snprintf@retval/d32;"
				 "fputc@retval/d32;"
				 "fputs@retval/d32;"
				 "putc@retval/d32;"
				 "putchar@retval/d32;"
				 "puts@retval/d32;"
				 "fgetc@retval/c;"
				 "fgets@retval/s;"
				 "getc@retval/c;"
				 "getchar@retval/c;"
				 "ungetc@retval/c;"
				 "getenv@retval/s;"
				 "setenv@retval/d32;"
				 "unsetenv@retval/d32;"
				 "open@retval/d32;"
				 "open64@retval/d32;"
				 "openat@retval/d32;"
				 "open64at@retval/d32;"
				 "close@retval/d32;"
				 "fcntl@retval/d32;"
				 "fcntl64@retval/d32;"
				 "lseek@retval;"
				 "fallocate@retval/d32;"
				 "fsync@retval/d32;"
				 "fdatasync@retval/d32;"
				 "fopen@retval/p;"
				 "fopen64@retval/p;"
				 "fdopen@retval/p;"
				 "freopen@retval/p;"
				 "fclose@retval/d32;"
				 "fseek@retval/d32;"
				 "ftell@retval;"
				 "fflush@retval/d32;"
				 "read@retval;"
				 "write@retval;"
				 "fread@retval/u;"
				 "fwrite@retval/u;"
				 "feof@retval/d32;"
				 "ferror@retval/d32;"
				 "fileno@retval/d32;"
				 "access@retval/d32;"
				 "unlink@retval/d32;"
				 "unlinkat@retval/d32;"
				 "mkdir@retval/d32;"
				 "rmdir@retval/d32;"
				 "chdir@retval/d32;"
				 "opendir@retval/p;"
				 "closedir@retval/d32;"
				 "getcwd@retval/s;"
				 "dirname@retval/s;"
				 "basename@retval/s;"
				 "fork@retval/i32;"
				 "vfork@retval/i32;"
				 "execl@retval/d32;"
				 "execlp@retval/d32;"
				 "execle@retval/d32;"
				 "execv@retval/d32;"
				 "execvp@retval/d32;"
				 "execve@retval/d32;"
				 "execvpe@retval/d32;"
				 "wait@retval/i32;"
				 "waitpid@retval/i32;"
				 "getpid@retval/i32;"
				 "getppid@retval/i32;"
				 "gettid@retval/i32;"
				 "dlopen@retval/p;"
				 "dlmopen@retval/p;"
				 "dlsym@retval/p;"
				 "dlvsym@retval/p;"
				 "dlclose@retval/d32;"
				 "dlerror@retval/s;"
				 "pthread_create@retval/d32;"
				 "pthread_once@retval/d32;"
				 "pthread_join@retval/d32;"
				 "pthread_detach@retval/d32;"
				 "pthread_kill@retval/d32;"
				 "pthread_cancel@retval/d32;"
				 "pthread_mutex_lock@retval/d32;"
				 "pthread_mutex_trylock@retval/d32;"
				 "pthread_mutex_unlock@retval/d32;"
				 "pthread_mutex_destroy@retval/d32;"
				 "pthread_mutex_init@retval/d32;"
				 "pthread_cond_wait@retval/d32;"
				 "pthread_cond_timedwait@retval/d32;"
				 "pthread_cond_signal@retval/d32;"
				 "pthread_cond_broadcast@retval/d32;"
				 "socket@retval/d32;"
				 "connect@retval/d32;"
				 "bind@retval/d32;"
				 "accept@retval/d32;"
				 "accept4@retval/d32;"
				 "gethostbyname@retval/p;"
				 "gethostbyaddr@retval/p;"
				 "getaddrinfo@retval/d32;"
				 "inet_pton@retval/d32;"
				 "inet_ntop@retval/s;"
				 "inet_aton@retval/d32;"
				 "inet_ntoa@retval/s;"
				 "inet_addr@retval;"
				 "inet_network@retval;"
				 "kill@retval/d32;"
				 "raise@retval/d32;"
				 "signal@retval;"
				 "sigaction@retval/d32;"
				 "sigemptyset@retval/d32;"
				 "sigfillset@retval/d32;"
				 "sigaddset@retval/d32;"
				 "sigdelset@retval/d32;"
				 "sigismember@retval/d32;"
				 "sigprocmask@retval/d32;"
				 "pthread_sigmask@retval/d32;"
				 "prctl@retval/d32;"
				 "select@retval/d32;"
				 "pselect@retval/d32;"
				 "poll@retval/d32;"
				 "ppoll@retval/d32;"
				 "epoll_create@retval/d32;"
				 "epoll_create1@retval/d32;"
				 "epoll_ctl@retval/d32;"
				 "epoll_wait@retval/d32;"
				 "epoll_pwait@retval/d32;"
				 "syscall@retval;"
				 "ioctl@retval/d32;"
				 "gettext@retval/s;"
				 "dgettext@retval/s;"
				 "dcgettext@retval/s;"
				 "setlocale@retval/s;"
				 "getopt@retval/d32;"
				 "getopt_long@retval/d32;"
				 "getopt_long_only@retval/d32;"
				 "stat@retval/d32;"
				 "fstat@retval/d32;"
				 "lstat@retval/d32;"
				 "chmod@retval/d32;"
				 "fchmod@retval/d32;"
				 "creat@retval/d32;"
				 "creat64@retval/d32;"
				 "isatty@retval/d32;"
				 "getuid@retval/i32;"
				 "getgid@retval/i32;"
				 "geteuid@retval/i32;"
				 "getegid@retval/i32;"
				 "setuid@retval/d32;"
				 "setgid@retval/d32;"
				 "seteuid@retval/d32;"
				 "setegid@retval/d32;"
				 "setreuid@retval/d32;"
				 "setregid@retval/d32;"
				 "setresuid@retval/d32;"
				 "setresgid@retval/d32;"
				 "chown@retval/d32;"
				 "lchown@retval/d32;"
				 "fchown@retval/d32;"
				 "dup@retval/d32;"
				 "dup2@retval/d32;"
				 "sleep@retval/u;"
				 "usleep@retval/d32;"
				 "clock_getres@retval/d32;"
				 "clock_gettime@retval/d32;"
				 "clock_settime@retval/d32;";
