#include <sys/ptrace.h>
#include <sys/user.h>
#include <wait.h>
#include <time.h>

#ifdef ARM
	#define REG_TYPE user_regs
#else
	#define REG_TYPE user_regs_struct
#endif

void ptrace_attach(pid_t target);
void ptrace_detach(pid_t target);
void ptrace_getregs(pid_t target, struct REG_TYPE* regs);
void ptrace_cont(pid_t target);
void ptrace_setregs(pid_t target, struct REG_TYPE* regs);
siginfo_t ptrace_getsiginfo(pid_t target);
void ptrace_read(int pid, unsigned long addr, void *vptr, int len);
void ptrace_write(int pid, unsigned long addr, void *vptr, int len);
void checktargetsig(int pid);
void restore_state_and_detach(pid_t target, unsigned long addr, void* backup, int datasize, struct REG_TYPE oldregs);
