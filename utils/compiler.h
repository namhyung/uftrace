#ifndef __FTRACE_COMPILER_H__
#define __FTRACE_COMPILER_H__

#define compiler_barrier()  asm volatile("" :::"memory")

#if defined(__x86_64__)
# define cpu_relax()	asm volatile("rep; nop" ::: "memory")
#endif

#if defined(__aarch64__)
# define cpu_relax()	asm volatile("yield" ::: "memory")
#endif

#ifndef cpu_relax
# define cpu_relax()	compiler_barrier()
#endif

#define __weak  __attribute__((weak))
#define __visible_default  __attribute__((visibility("default")))
#define __alias(func)  __attribute__((alias(#func)))

#endif /* __FTRACE_COMPILER_H__ */
