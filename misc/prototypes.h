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

#include <sys/types.h>
#include <unistd.h>


////////////////////////////////////////////////////////////////////////////////
// memory
#include <stdlib.h>
void *malloc(size_t size);
void free(void* ptr);
void* calloc(size_t nmemb, size_t size);
void* realloc(void* ptr, size_t size);

#include <sys/mman.h>
enum uft_mmap_prot { PROT_NONE, PROT_READ, PROT_WRITE, PROT_EXEC = 4, };
enum uft_mmap_flag {
	MAP_SHARED      = 0x1,
	MAP_PRIVATE     = 0x2,
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
};
void *mmap(void *addr, size_t length, enum uft_mmap_prot prot, enum uft_mmap_flag flags, int fd, off_t offset);
void *mmap64(void *addr, size_t length, enum uft_mmap_prot prot, enum uft_mmap_flag flags, int fd, off64_t offset);
int munmap(void *addr, size_t length);
int mprotect(void *addr, size_t len, enum uft_mmap_prot prot);

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

void *memcpy(void *dest, const void *src, size_t n);
void *memset(void *s, int c, size_t n);
int memcmp(const void *s1, const void *s2, size_t n);
void *memmove(void *dest, const void *src, size_t n);

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
int sprintf(char *str, const char *format, ...);
int snprintf(char *str, size_t size, const char *format, ...);

int fputc(char c, FILE *stream);
int fputs(const char *s, FILE *stream);
int putc(char c, FILE *stream);
int putchar(char c);
int puts(const char *s);

char fgetc(FILE *stream);
char *fgets(char *s, int size, FILE *stream);
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
	O_NOATIME   = 01000000,
	O_CLOEXEC   = 02000000,
	O_SYNC      = 04010000,
	O_PATH      = 010000000,
};
int open(const char* pathname, enum uft_open_flag flags);
int open64(const char* pathname, enum uft_open_flag flags);
int close(int fd);

enum uft_seek_whence { SEEK_SET, SEEK_CUR, SEEK_END, SEEK_DATA, SEEK_HOLE, };
off_t lseek(int fd, off_t offset, enum uft_seek_whence whence);

FILE *fopen(const char *path, const char *mode);
FILE *fopen64(const char *filename, const char *type);
FILE *fdopen(int fd, const char *mode);
FILE *freopen(const char *path, const char *mode, FILE *stream);
int fclose(FILE *stream);
int fseek(FILE *stream, long offset, int whence);
long ftell(FILE *stream);

ssize_t read(int fd, void *buf, size_t count);
ssize_t write(int fd, const void *buf, size_t count);
size_t fread(void *ptr, size_t size, size_t nmemb, FILE *stream);
size_t fwrite(const void *ptr, size_t size, size_t nmemb, FILE *stream);

enum uft_access_flag {
	F_OK = 0, X_OK = 1, W_OK = 2, R_OK = 4,
};
int access(const char *pathname, enum uft_access_flag mode);
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
void *dlsym(void *handle, const char *symbol);
void *dlvsym(void *handle, char *symbol, char *version);
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
	AF_VSOCK = 40, AF_KCM, AF_QIPCRTR, AF_SMC,
};
enum uft_socket_type {
	SOCK_STREAM = 1, SOCK_DGRAM, SOCK_RAW, SOCK_RDM, SOCK_SEQPACKET, SOCK_DCCP,
	SOCK_PACKET = 10,
};
enum uft_socket_flag {
	 SOCK_NONBLOCK = 04000, SOCK_CLOEXEC = 02000000,
};
int socket(enum uft_socket_domain domain, enum eft_socket_type type, int protocol);
int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
int bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
int accept4(int sockfd, struct sockaddr *addr, socklen_t *addrlen, enum uft_socket_flag flags);

#include <netdb.h>
struct hostent *gethostbyname(const char *name);
struct hostent *gethostbyaddr(const void *addr, socklen_t len, enum uft_socket_domain type);
int getaddrinfo(const char *node, const char *service, const struct addrinfo *hints, struct addrinfo **res);
void freeaddrinfo(struct addrinfo *res);
////////////////////////////////////////////////////////////////////////////////



////////////////////////////////////////////////////////////////////////////////
// signal
#include <signal.h>
// linux signal number
enum uft_signal {
	SIGHUP = 1, SIGINT, SIGQUIT, SIGILL, SIGTRAP, SIGABRT, SIGBUS, SIGFPE,
	SIGKILL = 9, SIGUSR1, SIGSEGV, SIGUSR2, SIGPIPE, SIGALRM, SIGTERM, SIGSTKFLT,
	SIGCHLD = 17, SIGCONT, SIGSTOP, SIGTSTP, SIGTTIN, SIGTTOU, SIGURG, SIGXCPU,
	SIGXFSZ = 25, SIGVTALRM, SIGPROF, SIGWINCH, SIGPOLL, SIGPWR, SIGSYS,
	SIGRTMIN = 32, SIGRTMAX = 64,
};
int kill(pid_t pid, enum uft_signal sig);
long signal(enum uft_signal sig, funcptr_t handler);
int sigaction(enum uft_signal signum, const struct sigaction *act, struct sigaction *oldact);
int sigemptyset(sigset_t *set);
int sigfillset(sigset_t *set);
int sigaddset(sigset_t *set, enum uft_signal signum);
int sigdelset(sigset_t *set, enum uft_signal signum);
int sigismember(const sigset_t *set, enum uft_signal signum);
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
};
int prctl(enum uft_prctl_op option, unsigned long arg2, unsigned long arg3, unsigned long arg4, unsigned long arg5);

#include <poll.h>
int poll(struct pollfd *fds, nfds_t nfds, int timeout);

#include <sys/syscall.h>   /* For SYS_xxx definitions */
long syscall(long number, ...);

#include <sys/ioctl.h>
int ioctl(int fd, unsigned long request, ...);
////////////////////////////////////////////////////////////////////////////////
