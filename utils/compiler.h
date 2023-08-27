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

/* TODO: not implemented yet (Start)
 *
 *	From RISC-V's "The RISC-V Instruction Set Manual, Volume I: User-Level
 *	ISA, Document Version 20191213", the G Extension consists of "I, M, A,
 *	F, D, Zicsr, Zifencei".
 *
 *	In RISC-V, two instructions exist for memory barriers: the fence
 *	instruction, defined in the I Extension, and the fence.i instruction,
 *	defined in the Zifencei Extension.
 *
 *	So the memory barrier commands we can use are fence, fence.i, and
 *	we'll have to figure out which one we need later when we implement
 *	the functions that call those macro functions.
 *
 */
#if defined(__riscv)
#define cpu_relax() asm volatile("nop" ::: "memory")
#define full_memory_barrier() asm volatile("nop" ::: "memory")
#define read_memory_barrier() asm volatile("nop" ::: "memory")
#define write_memory_barrier() asm volatile("nop" ::: "memory")
#endif
/* TODO: not implemented yet (End) */

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
