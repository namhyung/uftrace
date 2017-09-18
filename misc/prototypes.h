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
void *mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset);
int munmap(void *addr, size_t length);
int mprotect(void *addr, size_t len, int prot);

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
const char* strcpy(char* dest, const char* src);
char* strncpy(char* dest, const char* src, size_t n);
size_t strlen(const char *s);
size_t strnlen(const char *s, size_t maxlen);
int strcmp(const char *s1, const char *s2);
int strncmp(const char *s1, const char *s2, size_t n);

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
int open(const char* pathname, int flags);
int close(int fd);
off_t lseek(int fd, off_t offset, int whence);

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
void *dlopen(const char *filename, int flags);
////////////////////////////////////////////////////////////////////////////////



////////////////////////////////////////////////////////////////////////////////
// pthread
#include <pthread.h>
//int pthread_create(pthread_t *thread, const pthread_attr_t *attr, void *(*start_routine) (void *), void *arg);
int pthread_create(pthread_t *thread, const pthread_attr_t *attr, void* *start_routine(), void *arg);
//int pthread_once(pthread_once_t *once_control, void (*init_routine)(void));
int pthread_once(pthread_once_t *once_control, void *init_routine());
int pthread_join(pthread_t thread, void **retval);
int pthread_detach(pthread_t thread);

int pthread_mutex_lock(pthread_mutex_t *mutex);
int pthread_mutex_trylock(pthread_mutex_t *mutex);
int pthread_mutex_unlock(pthread_mutex_t *mutex);
int pthread_mutex_destroy(pthread_mutex_t *mutex);
int pthread_mutex_init(pthread_mutex_t *restrict mutex, const pthread_mutexattr_t *restrict attr);
////////////////////////////////////////////////////////////////////////////////



////////////////////////////////////////////////////////////////////////////////
// socket
#include <sys/socket.h>
int socket(int domain, int type, int protocol);
int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
int bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
int accept4(int sockfd, struct sockaddr *addr, socklen_t *addrlen, int flags);

#include <netdb.h>
struct hostent *gethostbyname(const char *name);
struct hostent *gethostbyaddr(const void *addr, socklen_t len, int type);
int getaddrinfo(const char *node, const char *service, const struct addrinfo *hints, struct addrinfo **res);
void freeaddrinfo(struct addrinfo *res);
////////////////////////////////////////////////////////////////////////////////



////////////////////////////////////////////////////////////////////////////////
// signal
#include <signal.h>
int kill(pid_t pid, int sig);
int sigaction(int signum, const struct sigaction *act, struct sigaction *oldact);
int sigemptyset(sigset_t *set);
int sigfillset(sigset_t *set);
int sigaddset(sigset_t *set, int signum);
int sigdelset(sigset_t *set, int signum);
int sigismember(const sigset_t *set, int signum);
////////////////////////////////////////////////////////////////////////////////



////////////////////////////////////////////////////////////////////////////////
// etc.
#include <sys/prctl.h>
int prctl(int option, unsigned long arg2, unsigned long arg3, unsigned long arg4, unsigned long arg5);

#include <poll.h>
int poll(struct pollfd *fds, nfds_t nfds, int timeout);

#include <sys/syscall.h>   /* For SYS_xxx definitions */
long syscall(long number, ...);

#include <sys/ioctl.h>
int ioctl(int fd, unsigned long request, ...);
////////////////////////////////////////////////////////////////////////////////
