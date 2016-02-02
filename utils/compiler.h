#ifndef __FTRACE_COMPILER_H__
#define __FTRACE_COMPILER_H__

#define compiler_barrier()  asm volatile("" :::"memory")

#if defined(__x86_64__)
# define cpu_relax()	asm volatile("rep; nop" ::: "memory")
#endif

#if defined(__arm__)
# define cpu_relax()	compiler_barrier()
#endif

#define __weak  __attribute__((weak))

#endif /* __FTRACE_COMPILER_H__ */
