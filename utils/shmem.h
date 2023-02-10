#ifndef UFTRACE_SHMEM_H
#define UFTRACE_SHMEM_H

int uftrace_shmem_open(const char *name, int oflag, mode_t mode);
int uftrace_shmem_unlink(const char *name);
const char *uftrace_shmem_root(void);

#endif /* UFTRACE_SHMEM_H */
