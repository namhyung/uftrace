#ifndef UFTRACE_COMPILER_H
#define UFTRACE_COMPILER_H

#define compiler_barrier()	asm volatile("" :::"memory")

#if defined(__x86_64__)
# define cpu_relax()		asm volatile("rep; nop" ::: "memory")
# define full_memory_barrier()	asm volatile("mfence" ::: "memory")
# define read_memory_barrier()  asm volatile("lfence" ::: "memory")
# define write_memory_barrier()	asm volatile("sfence" ::: "memory")
#endif

#if defined(__aarch64__)
# define cpu_relax()		asm volatile("yield" ::: "memory")
# define full_memory_barrier()	asm volatile("dmb ish" ::: "memory")
# define read_memory_barrier()  asm volatile("dmb ishld" ::: "memory")
# define write_memory_barrier()	asm volatile("dmb ishst" ::: "memory")
#endif

#if defined(__arm__)
# define cpu_relax()		compiler_barrier()
# define full_memory_barrier()	asm volatile("dmb ish" ::: "memory")
# define read_memory_barrier()  asm volatile("dmb ish" ::: "memory")
# define write_memory_barrier()	asm volatile("dmb ishst" ::: "memory")
#endif

/* ignore 'restrict' keyword if not supported (before C99) */
#if !defined(__STDC_VERSION__) || __STDC_VERSION__ < 199901L
# define restrict
#endif

#define __weak  __attribute__((weak))
#define __visible_default  __attribute__((visibility("default")))
#define __alias(func)  __attribute__((alias(#func)))
#define __maybe_unused  __attribute__((unused))

#endif /* UFTRACE_COMPILER_H */
