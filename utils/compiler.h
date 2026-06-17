#ifndef UFTRACE_COMPILER_H
#define UFTRACE_COMPILER_H

#define compiler_barrier() asm volatile("" ::: "memory")

#if defined(__i386__)
#define cpu_relax() asm volatile("rep; nop" ::: "memory")
#define full_memory_barrier() asm volatile("mfence" ::: "memory")
#define read_memory_barrier() asm volatile("lfence" ::: "memory")
#define write_memory_barrier() asm volatile("sfence" ::: "memory")
#endif

#if defined(__x86_64__)
#define cpu_relax() asm volatile("rep; nop" ::: "memory")
#define full_memory_barrier() asm volatile("mfence" ::: "memory")
#define read_memory_barrier() asm volatile("lfence" ::: "memory")
#define write_memory_barrier() asm volatile("sfence" ::: "memory")
#endif

#if defined(__aarch64__)
#define cpu_relax() asm volatile("yield" ::: "memory")
#define full_memory_barrier() asm volatile("dmb ish" ::: "memory")
#define read_memory_barrier() asm volatile("dmb ishld" ::: "memory")
#define write_memory_barrier() asm volatile("dmb ishst" ::: "memory")
#endif

#if defined(__arm__)
#define cpu_relax() compiler_barrier()
#if __ARM_ARCH == 7
#define full_memory_barrier() asm volatile("dmb ish" ::: "memory")
#define read_memory_barrier() asm volatile("dmb ish" ::: "memory")
#define write_memory_barrier() asm volatile("dmb ishst" ::: "memory")
#else
#define full_memory_barrier() asm volatile("mcr p15, 0, %0, c7, c10, 5" ::"r"(0) : "memory")
#define read_memory_barrier() full_memory_barrier()
#define write_memory_barrier() full_memory_barrier()
#endif
#endif

#if defined(__riscv)
/*
 * These are data memory ordering barriers using the 'fence' instruction
 * (RV I Extension).  'fence p, s' orders the predecessor set 'p' before the
 * successor set 'r'(read) and 'w'(write).  They only need to order normal
 * memory accesses (not device I/O), so the rw/r/w sets are used.
 *
 * Note: the 'fence.i' instruction (Zifencei) is a separate concern.  It
 * synchronizes the instruction stream and is needed only when patching code
 * at runtime; that is handled in the dynamic tracing code (via
 * __builtin___clear_cache), not by these data barriers.
 */
#define cpu_relax() compiler_barrier()
#define full_memory_barrier() asm volatile("fence rw, rw" ::: "memory")
#define read_memory_barrier() asm volatile("fence r, r" ::: "memory")
#define write_memory_barrier() asm volatile("fence w, w" ::: "memory")
#endif

/* ignore 'restrict' keyword if not supported (before C99) */
#if !defined(__STDC_VERSION__) || __STDC_VERSION__ < 199901L
#define restrict
#endif

#define __weak __attribute__((weak))
#define __visible_default __attribute__((visibility("default")))
#define __alias(func) __attribute__((alias(#func)))
#define __maybe_unused __attribute__((unused))
#ifndef __used
#define __used __attribute__((used))
#endif
#ifndef __noreturn
#define __noreturn __attribute__((noreturn))
#endif
#define __align(n) __attribute__((aligned(n)))

#endif /* UFTRACE_COMPILER_H */
