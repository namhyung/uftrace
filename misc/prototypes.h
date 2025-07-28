//
// Prototype functions for automatic arguments / return value display
//
// Copyright (C) 2017, LG Electronics, Honggyu Kim <hong.gyu.kim@lge.com>
//
// Released under the GPL v2.
//
// This file is processed by gen-autoargs.py and it generates autoargs.h to be
// used for --auto-args option.  Due to the limitation of space, it cannot
// contain more function prototypes as of now.
//

// clang-format off

#include <stdlib.h>
int atoi(const char *str);
long atol(const char *str);
double atof(const char *str);

long strtol(const char *str, void *endp, int base);
unsigned long strtoul(const char *str, void *endp, int base);
double strtod(const char *str, void *endp);
float strtof(const char *str, void *endp);

void qsort(void *base, size_t nmemb, size_t size, funcptr_t compar);
void qsort_r(void *base, size_t nmemb, size_t size, funcptr_t compar, void *arg);
void *bsearch(const void *key, const void *base, size_t nmemb, size_t size, funcptr_t compar);

void exit(int status);

////////////////////////////////////////////////////////////////////////////////
// memory
void *malloc(size_t size);
void free(void* ptr);
void* calloc(size_t nmemb, size_t size);
void* realloc(void* ptr, size_t size);

#include <sys/mman.h>
enum uft_mmap_prot { PROT_NONE, PROT_READ, PROT_WRITE, PROT_EXEC = 4, };
enum uft_mmap_flag {
	MAP_SHARED      = 0x1,
	MAP_PRIVATE     = 0x2,
	MAP_SHARED_VALIDATE = 0x3,
	MAP_FIXED       = 0x10,
	MAP_ANON        = 0x20,
	MAP_GROWSDOWN   = 0x100,
	MAP_DENYWRITE   = 0x800,
	MAP_EXECUTABLE  = 0x1000,
	MAP_LOCKED      = 0x2000,
	MAP_NORESERVE   = 0x4000,
	MAP_POPULATE    = 0x8000,
	MAP_NONBLOCK    = 0x10000,
	MAP_STACK       = 0x20000,
	MAP_HUGETLB     = 0x40000,
	MAP_SYNC        = 0x80000,
	MAP_FIXED_NOREPLACE = 0x100000,
};
void *mmap(void *addr, size_t length, enum uft_mmap_prot prot, enum uft_mmap_flag flags, int fd, off_t offset);
void *mmap64(void *addr, size_t length, enum uft_mmap_prot prot, enum uft_mmap_flag flags, int fd, off64_t offset);
int munmap(void *addr, size_t length);
int mprotect(void *addr, size_t len, enum uft_mmap_prot prot);

enum uft_madvise {
    MADV_NORMAL      = 0,
    MADV_RANDOM      = 1,
    MADV_SEQUENTIAL  = 2,
    MADV_WILLNEED    = 3,
    MADV_DONTNEED    = 4,
    MADV_FREE        = 8,
    MADV_REMOVE      = 9,
    MADV_DONTFORK    = 10,
    MADV_DOFORK      = 11,
    MADV_MERGEABLE   = 12,
    MADV_UNMERGEABLE = 13,
    MADV_HUGEPAGE    = 14,
    MADV_NOHUGEPAGE  = 15,
    MADV_DONTDUMP    = 16,
    MADV_DODUMP      = 17,
    MADV_WIPEONFORK  = 18,
    MADV_KEEPONFORK  = 19,
    MADV_COLD        = 20,
    MADV_PAGEOUT     = 21,
    MADV_POPULATE_READ   = 22,
    MADV_POPULATE_WRITE  = 23,
    MADV_POPULATE_LOCKED = 24,
    MADV_COLLAPSE    = 25,
    MADV_HWPOISON    = 100,
};
int madvise(void *addr, size_t length, enum uft_madvise advice);

enum uft_posix_madvise {
    POSIX_MADV_NORMAL     = 0,
    POSIX_MADV_RANDOM     = 1,
    POSIX_MADV_SEQUENTIAL = 2,
    POSIX_MADV_WILLNEED   = 3,
    POSIX_MADV_DONTNEED   = 4,
};
int posix_madvise(void *addr, size_t len, enum uft_posix_madvise advice);

enum uft_posix_fadvise {
    POSIX_FADV_NORMAL     = 0,
    POSIX_FADV_RANDOM     = 1,
    POSIX_FADV_SEQUENTIAL = 2,
    POSIX_FADV_WILLNEED   = 3,
    POSIX_FADV_DONTNEED   = 4,
    POSIX_FADV_NOREUSE    = 5,
};
int posix_fadvise(int fd, off_t offset, off_t len, enum uft_posix_fadvise advice);

int brk(void *addr);
void *sbrk(intptr_t increment);

#include <malloc.h>
void *memalign(size_t alignment, size_t size);
void *pvalloc(size_t size);
int posix_memalign(void **memptr, size_t alignment, size_t size);
void *aligned_alloc(size_t alignment, size_t size);
void *valloc(size_t size);
////////////////////////////////////////////////////////////////////////////////



////////////////////////////////////////////////////////////////////////////////
// string
#include <string.h>
char* strcat(char *dest, const char *src);
char* strncat(char *dest, const char *src, size_t n);
void strcpy(void* dest, const char* src);
void strncpy(void* dest, const char* src, size_t n);
size_t strlen(const char *s);
size_t strnlen(const char *s, size_t maxlen);
int strcmp(const char *s1, const char *s2);
int strncmp(const char *s1, const char *s2, size_t n);
int strcasecmp(const char *s1, const char *s2);
int strncasecmp(const char *s1, const char *s2, size_t n);

char *strdup(const char *s);
char *strndup(const char *s, size_t n);
char *strdupa(const char *s);
char *strndupa(const char *s, size_t n);

int strcoll(const char *s1, const char *s2);

char *strstr(const char *haystack, const char *needle);
char *strcasestr(const char *haystack, const char *needle);
char *strchr(const char *s, char c);
char *strrchr(const char *s, char c);
char *strchrnul(const char *s, char c);

char* strtok(char *str, const char *delim);
char* strtok_r(char *str, const char *delim, char **saveptr);
char* strpbrk(const char *s, const char *accept);
size_t strspn(const char *s, const char *accept);
size_t strcspn(const char *s, const char *reject);
char* strsep(char **stringp, const char *delim);

void memcpy(void *dest, const void *src, size_t n);
void memset(void *s, int c, size_t n);
int memcmp(const void *s1, const void *s2, size_t n);
void memmove(void *dest, const void *src, size_t n);

void *memchr(const void *s, int c, size_t n);
void *memrchr(const void *s, int c, size_t n);
void *rawmemchr(const void *s, int c);
////////////////////////////////////////////////////////////////////////////////



////////////////////////////////////////////////////////////////////////////////
// stdio
#include <stdio.h>
int printf(const char *format, ...);
int fprintf(FILE *stream, const char *format, ...);
int dprintf(int fd, const char *format, ...);
int sprintf(void *dest, const char *format, ...);
int snprintf(void *dest, size_t size, const char *format, ...);

int fputc(char c, FILE *stream);
int fputs(const char *s, FILE *stream);
int putc(char c, FILE *stream);
int putchar(char c);
int puts(const char *s);

char fgetc(FILE *stream);
char *fgets(void *s, int size, FILE *stream);
char getc(FILE *stream);
char getchar(void);
char ungetc(char c, FILE *stream);

char *getenv(const char *name);
int setenv(const char *name, const char *value, int overwrite);
int unsetenv(const char *name);
////////////////////////////////////////////////////////////////////////////////



////////////////////////////////////////////////////////////////////////////////
// file
#include <sys/stat.h>
#include <fcntl.h>
enum uft_open_flag {
	O_RDONLY    = 00,
	O_WRONLY    = 01,
	O_RDWR      = 02,
	O_CREAT     = 0100,
	O_EXCL      = 0200,
	O_NOCTTY    = 0400,
	O_TRUNC     = 01000,
	O_APPEND    = 02000,
	O_NONBLOCK  = 04000,
	O_DSYNC     = 010000,
	O_ASYNC     = 020000,
	O_DIRECT    = 040000,
	O_LARGEFILE = 0100000,
	O_DIRECTORY = 0200000,
	O_NOFOLLOW  = 0400000,
	O_NOATIME   = 01000000,
	O_CLOEXEC   = 02000000,
	O_SYNC      = 04010000,
	O_PATH      = 010000000,
	O_TMPFILE   = 020200000,
};
int open(const char* pathname, enum uft_open_flag flags);
int open64(const char* pathname, enum uft_open_flag flags);
int openat(int fd, const char* pathname, enum uft_open_flag flags);
int open64at(int fd, const char* pathname, enum uft_open_flag flags);
int close(int fd);

enum uft_fcntl_cmd {
	F_DUPFD, F_GETFD, F_SETFD, F_GETFL, F_SETFL,
	F_GETLK, F_SETLK, F_SETLKW,
	F_SETOWN, F_GETOWN, F_SEGSIG, F_GETSIG,
	F_GETLK64, F_SETLK64, F_SETLKW64,
	F_SETOWN_EX, F_GETOWN_EX,
	F_SETLEASE = 1024, F_GETLEASE, F_NOTIFY,
	F_DUPFD_CLOEXEC = 1030,
	F_SETPIPE_SZ = 1031, F_GETPIPE_SZ, F_ADD_SEALS, F_GET_SEALS,
	F_GET_RW_HINT = 1035, F_SET_RW_HINT,
	F_GET_FILE_RW_HINT = 1037, F_SET_FILE_RW_HINT,
};
int fcntl(int fd, enum uft_fcntl_cmd);
int fcntl64(int fd, enum uft_fcntl_cmd);

enum uft_seek_whence { SEEK_SET, SEEK_CUR, SEEK_END, SEEK_DATA, SEEK_HOLE, };
off_t lseek(int fd, off_t offset, enum uft_seek_whence whence);

enum uft_falloc_mde {
	FALLOC_FL_KEEP_SIZE         = 1,
	FALLOC_FL_PUNCH_HOLE        = 2,
	FALLOC_FL_NO_HIDE_STALE     = 4,
	FALLOC_FL_COLLAPSE_RANGE    = 8,
	FALLOC_FL_ZERO_RANGE        = 16,
	FALLOC_FL_INSERT_RANGE      = 32,
	FALLOC_FL_UNSHARE_RANGE     = 64,
};
int fallocate(int fd, enum uft_falloc_mode mode, off_t off, off_t len);

int fsync(int fd);
int fdatasync(int fd);

FILE *fopen(const char *path, const char *mode);
FILE *fopen64(const char *filename, const char *type);
FILE *fdopen(int fd, const char *mode);
FILE *freopen(const char *path, const char *mode, FILE *stream);
int fclose(FILE *stream);
int fseek(FILE *stream, long offset, int whence);
long ftell(FILE *stream);
int fflush(FILE *stream);

ssize_t read(int fd, void *buf, size_t count);
ssize_t write(int fd, const void *buf, size_t count);
size_t fread(void *ptr, size_t size, size_t nmemb, FILE *stream);
size_t fwrite(const void *ptr, size_t size, size_t nmemb, FILE *stream);

int feof(FILE *stream);
int ferror(FILE *stream);
int fileno(FILE *stream);

enum uft_access_flag {
	F_OK = 0, X_OK = 1, W_OK = 2, R_OK = 4,
};
int access(const char *pathname, enum uft_access_flag mode);

int unlink(const char *pathname);
int unlinkat(int dirfd, const char *pathname, int flags);
int mkdir(const char *pathname, mode_t mode);
int rmdir(const char *pathname);
int chdir(const char *pathname);

#include <dirent.h>
void * opendir(const char *name);
int closedir(void *dirp);

char * getcwd(void *buf, size_t size);

#include <libgen.h>
char *dirname(char *path);
char *basename(char *path);
////////////////////////////////////////////////////////////////////////////////



////////////////////////////////////////////////////////////////////////////////
// fork and exec
pid_t fork(void);
pid_t vfork(void);

int execl(const char *path, const char *arg, ...);
int execlp(const char *file, const char *arg, ...);
int execle(const char *path, const char *arg, ...);

//int execv(const char *path, char *const argv[]);  // cannot understand argv type
int execv(const char *path, ...);
//int execvp(const char *file, char *const argv[]); // cannot understand argv type
int execvp(const char *file, ...);
//int execve(const char *file, char *const argv[], char *const envp[]);
int execve(const char *file, ...);
//int execvpe(const char *file, char *const argv[], char *const envp[]);
int execvpe(const char *file, ...);

#include <sys/wait.h>
pid_t wait(int *status);
pid_t waitpid(pid_t pid, int *status, int options);

pid_t getpid(void);
pid_t getppid(void);
pid_t gettid(void);

#include <dlfcn.h>
enum uft_dlopen_flag {
	RTLD_LOCAL = 0,
	RTLD_LAZY = 1,
	RTLD_NOW = 2,
	RTLD_NOLOAD = 4,
	RTLD_DEEPBIND = 8,
	RTLD_GLOBAL = 0x100,
	RTLD_NODELETE = 0x1000,
};
void *dlopen(const char *filename, enum uft_dlopen_flag flags);
void *dlmopen (Lmid_t lmid, const char *filename, int flags);
void *dlsym(void *handle, const char *symbol);
void *dlvsym(void *handle, char *symbol, char *version);
int dlclose(void *handle);
char *dlerror(void);
////////////////////////////////////////////////////////////////////////////////



////////////////////////////////////////////////////////////////////////////////
// pthread
#include <pthread.h>
//int pthread_create(pthread_t *thread, const pthread_attr_t *attr, void *(*start_routine) (void *), void *arg);
int pthread_create(pthread_t *thread, const pthread_attr_t *attr, funcptr_t start_routine, void *arg);
//int pthread_once(pthread_once_t *once_control, void (*init_routine)(void));
int pthread_once(pthread_once_t *once_control, funcptr_t init_routine);
int pthread_join(pthread_t thread, void **retval);
int pthread_detach(pthread_t thread);
int pthread_kill(pthread_t thread, int sig);
int pthread_cancel(pthread_t thread);
void pthread_exit(void *retval);

int pthread_mutex_lock(pthread_mutex_t *mutex);
int pthread_mutex_trylock(pthread_mutex_t *mutex);
int pthread_mutex_unlock(pthread_mutex_t *mutex);
int pthread_mutex_destroy(pthread_mutex_t *mutex);
int pthread_mutex_init(pthread_mutex_t *restrict mutex, const pthread_mutexattr_t *restrict attr);

int pthread_cond_wait(pthread_cond_t *cond, pthread_mutex_t *mutex);
int pthread_cond_timedwait(pthread_cond_t *cond, pthread_mutex_t *mutex, const struct timespec *abstime);

int pthread_cond_signal(pthread_cond_t *cond);
int pthread_cond_broadcast(pthread_cond_t *cond);
////////////////////////////////////////////////////////////////////////////////



////////////////////////////////////////////////////////////////////////////////
// socket
#include <sys/socket.h>
enum uft_socket_domain {
	AF_UNSPEC = 0, AF_UNIX, AF_INET, AF_AX25, AF_IPX, AF_APPLETALK, AF_NETROM, AF_BRIDGE,
	AF_ATMPVC = 8, AF_X25, AF_INET6, AF_ROSE, AF_DECnet, AF_NETBEUI, AF_SECURITY, AF_KEY,
	AF_NETLINK = 16, AF_PACKET, AF_ASH, AF_ECONET, AF_ATMSVC, AF_RDS, AF_SNA, AF_IRDA,
	AF_PPPOX = 24, AF_WANPIPE, AF_LLC, AF_IB, AF_MPLS, AF_CAN, AF_TPIC, AF_BLUETOOTH,
	AF_IUCV = 32, AF_RXRPC, AF_ISDN, AF_PHONET, AF_IEEE802154, AF_CAIF, AF_ALG, AF_NFC,
	AF_VSOCK = 40, AF_KCM, AF_QIPCRTR, AF_SMC, AF_XDP, AF_MCTP,
};
enum uft_socket_type {
	SOCK_STREAM = 1, SOCK_DGRAM, SOCK_RAW, SOCK_RDM, SOCK_SEQPACKET, SOCK_DCCP,
	SOCK_PACKET = 10,
	SOCK_NONBLOCK = 04000, SOCK_CLOEXEC = 02000000,
};
enum uft_socket_flag {
	SOCK_NONBLOCK = 04000, SOCK_CLOEXEC = 02000000,
};
int socket(enum uft_socket_domain domain, enum uft_socket_type type, int protocol);
int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
int bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
int accept4(int sockfd, struct sockaddr *addr, socklen_t *addrlen, enum uft_socket_flag flags);

#include <netdb.h>
struct hostent *gethostbyname(const char *name);
struct hostent *gethostbyaddr(const void *addr, socklen_t len, enum uft_socket_domain type);
int getaddrinfo(const char *node, const char *service, const struct addrinfo *hints, struct addrinfo **res);
void freeaddrinfo(struct addrinfo *res);

#include <netinet/in.h>
#include <arpa/inet.h>
int inet_pton(enum uft_socket_domain af, const char *src, void *dst);
const char *inet_ntop(enum uft_socket_domain af, const void *src, char *dst, socklen_t size);
int inet_aton(const char *cp, struct in_addr *inp);
char *inet_ntoa(struct in_addr in);

in_addr_t inet_addr(const char *cp);
in_addr_t inet_network(const char *cp);
////////////////////////////////////////////////////////////////////////////////



////////////////////////////////////////////////////////////////////////////////
// signal
#include <signal.h>
// linux signal number
enum uft_signal {
	SIGNULL = 0, SIGHUP, SIGINT, SIGQUIT, SIGILL, SIGTRAP, SIGABRT, SIGBUS, SIGFPE,
	SIGKILL = 9, SIGUSR1, SIGSEGV, SIGUSR2, SIGPIPE, SIGALRM, SIGTERM, SIGSTKFLT,
	SIGCHLD = 17, SIGCONT, SIGSTOP, SIGTSTP, SIGTTIN, SIGTTOU, SIGURG, SIGXCPU,
	SIGXFSZ = 25, SIGVTALRM, SIGPROF, SIGWINCH, SIGPOLL, SIGPWR, SIGSYS,
	SIGRTMIN = 32, SIGRTMAX = 64,
};
int kill(pid_t pid, enum uft_signal sig);
int raise(enum uft_signal sig);
long signal(enum uft_signal sig, funcptr_t handler);
int sigaction(enum uft_signal signum, const struct sigaction *act, struct sigaction *oldact);
int sigemptyset(sigset_t *set);
int sigfillset(sigset_t *set);
int sigaddset(sigset_t *set, enum uft_signal signum);
int sigdelset(sigset_t *set, enum uft_signal signum);
int sigismember(const sigset_t *set, enum uft_signal signum);

enum uft_sigmask { SIG_BLOCK, SIG_UNBLOCK, SIG_SETMASK };
int sigprocmask(enum uft_sigmask how, const sigset_t *set, sigset_t *oldset);
int pthread_sigmask(enum uft_sigmask how, const sigset_t *set, sigset_t *oldset);
////////////////////////////////////////////////////////////////////////////////



////////////////////////////////////////////////////////////////////////////////
// etc.
#include <sys/prctl.h>
enum uft_prctl_op {
	PR_SET_PDEATHSIG = 1, PR_GET_PDEATHSIG, PR_GET_DUMPABLE, PR_SET_DUMPABLE,
	PR_GET_UNALIGN = 5, PR_SET_UNALIGN, PR_GET_KEEPCAPS, PR_SET_KEEPCAPS,
	PR_GET_FPEMU = 9, PR_SET_FPEMU, PR_GET_FPEXC, PR_SET_FPEXC,
	PR_GET_TIMING = 13, PR_SET_TIMING, PR_SET_NAME, PR_GET_NAME,
	PR_GET_ENDIAN = 19, PR_SET_ENDIAN, PR_GET_SECCOMP, PR_SET_SECCOMP,
	PR_CAPBSET_READ = 23, PR_CAPBSET_DROP, PR_GET_TSC, PR_SET_TSC,
	PR_GET_SECUREBITS = 27, PR_SET_SECUREBITS, PR_SET_TIMERSLACK, PR_GET_TIMERSLACK,
	PR_TASK_PERF_EVENTS_DISABLE = 31, PR_TASK_PERF_EVENTS_ENABLE,
	PR_MCE_KILL = 33, PR_MCE_KILL_GET, PR_SET_MM,
	PR_SET_CHILD_SUBREAPER = 36, PR_GET_CHILD_SUBREAPER,
	PR_SET_NO_NEW_PRIVS = 38, PR_GET_NO_NEW_PRIVS, PR_GET_TID_ADDRESS,
	PR_SET_THP_DISABLE = 41, PR_GET_THP_DISABLE,
	PR_MPX_ENABLE_MANAGEMENT = 43, PR_MPX_DISABLE_MANAGEMENT,
	PR_SET_FP_MODE = 45, PR_GET_FP_MODE, PR_CAP_AMBIENT,
	PR_SVE_SET_VL = 50, PR_SVE_GET_VL,
	PR_GET_SPECULATION_CTRL = 52, PR_SET_SPECULATION_CTRL, PR_PAC_RESET_KEYS,
	PR_SET_TAGGED_ADDR_CTRL = 55, PR_GET_TAGGED_ADDR_CTRL,
	PR_SET_IO_FLUSHER = 57, PR_GET_IO_FLUSHER, PR_SET_SYSCALL_USER_DISPATCH,
	PR_PAC_SET_ENABLED_KEYS = 60, PR_PAC_GET_ENABLED_KEYS, PR_SCHED_CORE,
	PR_SME_SET_VL = 63, PR_SME_GET_VL, PR_SET_MDWE, PR_GET_MDWE,
	PR_SET_MEMORY_MERGE = 67, PR_GET_MEMORY_MERGE,
	PR_RISCV_V_SET_CONTROL = 69, PR_RISCV_V_GET_CONTROL, PR_RISCV_SET_ICACHE_FLUSH_CTX,
	PR_PPC_GET_DEXCR = 72, PR_PPC_SET_DEXCR,
	PR_GET_SHADOW_STACK_STATUS = 74, PR_SET_SHADOW_STACK_STATUS, PR_LOCK_SHADOW_STACK_STATUS,
	PR_TIMER_CREATE_RESTORE_IDS = 77,
	PR_GET_AUXV = 0x41555856,
	PR_SET_VMA = 0x53564d41,
};
int prctl(enum uft_prctl_op option, unsigned long arg2, unsigned long arg3, unsigned long arg4, unsigned long arg5);

#include <sys/select.h>
int select(int nfds, void *rset, void *wset, void *eset, void *timeout);
int pselect(int nfds, void *rset, void *wset, void *eset, void *timeout, sigset_t *mask);

#include <poll.h>
int poll(struct pollfd *fds, nfds_t nfds, int timeout);
int ppoll(struct pollfd *fds, nfds_t nfds, void *timeout, sigset_t *mask);

#include <sys/epoll.h>
enum uft_epoll_op { EPOLL_CTL_ADD = 1, EPOLL_CTL_DEL, EPOLL_CTL_MOD };

int epoll_create(int size);
int epoll_create1(int flags);
int epoll_ctl(int efd, enum uft_epoll_op op, int fd, void *event);
int epoll_wait(int efd, void *events, int max_event, int timeout);
int epoll_pwait(int efd, void *events, int max_event, int timeout, sigset_t *mask);

#include <sys/syscall.h>   /* For SYS_xxx definitions */
long syscall(long number, ...);

#include <sys/ioctl.h>
int ioctl(int fd, unsigned long request, ...);

#include <libintl.h>
void textdomain(const char * domainname);
void bindtextdomain(const char * domainname, const char * dirname);
char *gettext (const char * msgid);
char *dgettext (const char * domainname, const char * msgid);
char *dcgettext (const char * domainname, const char * msgid, int category);

#include <locale.h>
enum uft_locale {
	LC_TYPE = 0, LC_NUMERIC, LC_TIME, LC_COLLATE, LC_MONETARY, LC_MESSAGES,
	LC_ALL, LC_PAPER, LC_NAME, LC_ADDRESS, LC_TELEPHONE, LC_MEASUREMENT,
	LC_IDENTIFICATION,
};
char * setlocale(enum uft_locale category, const char * locale);

#include <getopt.h>
int getopt(int argc, void *argv, const char * optstr);
/* ignore struct option for longopts for now */
int getopt_long(int argc, void *argv, const char * optstr);
int getopt_long_only(int argc, void *argv, const char * optstr);

#include <sys/stat.h>
int stat(const char *pathname, void *statbuf);
int fstat(int fd, void *statbuf);
int lstat(const char *pathname, void *statbuf);

int chmod(const char *pathname, oct_mode_t mode);
int fchmod(int fd, oct_mode_t mode);
int fchmodat(int dirfd, const char *pathname, oct_mode_t mode, int flags);
void umask(oct_mode_t mask);

int creat(const char *file, oct_mode_t mode);
int creat64(const char *file, oct_mode_t mode);

#include <unistd.h>
int isatty(int fd);

uid_t getuid(void);
uid_t getgid(void);
uid_t geteuid(void);
uid_t getegid(void);
int setuid(uid_t id);
int setgid(uid_t id);
int seteuid(uid_t id);
int setegid(uid_t id);
int setreuid(uid_t ruid, uid_t euid);
int setregid(uid_t rgid, uid_t egid);
int setresuid(uid_t ruid, uid_t euid, uid_t suid);
int setresgid(uid_t rgid, uid_t egid, uid_t sgid);

int chown(const char *path, uid_t uid, uid_t gid);
int lchown(const char *path, uid_t uid, uid_t gid);
int fchown(int fd, uid_t uid, uid_t gid);

int dup(int oldfd);
int dup2(int oldfd, int newfd);

unsigned sleep(unsigned seconds);
int usleep(unsigned usec);

#include <time.h>
enum uft_clockid_t {
	CLOCK_REALTIME = 0,
	CLOCK_MONOTONIC,
	CLOCK_PROCESS_CPUTIME_ID,
	CLOCK_THREAD_CPUTIME_ID,
	CLOCK_MONOTONIC_RAW,
	CLOCK_REALTIME_COARSE,
	CLOCK_MONOTONIC_COARSE,
	CLOCK_BOOTTIME,
	CLOCK_REALTIME_ALARM,
	CLOCK_BOOTTIME_ALARM,
	CLOCK_TAI = 11,
};
int clock_getres(enum uft_clockid_t clk_id, struct timespec *res);
int clock_gettime(enum uft_clockid_t clk_id, struct timespec *tp);
int clock_settime(enum uft_clockid_t clk_id, const struct timespec *tp);
////////////////////////////////////////////////////////////////////////////////

// clang-format on
