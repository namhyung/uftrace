/*
 * Architecture specific code and data
 */
#ifndef UFTRACE_ARCH_H
#define UFTRACE_ARCH_H

#include <stdbool.h>

enum uftrace_cpu_arch {
	UFT_CPU_NONE,
	UFT_CPU_X86_64,
	UFT_CPU_ARM,
	UFT_CPU_AARCH64,
	UFT_CPU_I386,
};

static inline enum uftrace_cpu_arch host_cpu_arch(void)
{
#if defined (__x86_64__)
	return UFT_CPU_X86_64;
#elif defined (__arm__)
	return UFT_CPU_ARM;
#elif defined (__aarch64__)
	return UFT_CPU_AARCH64;
#elif defined (__i386__)
	return UFT_CPU_I386;
#else
	return UFT_CPU_NONE;
#endif
}

static inline bool arch_is_lp64(enum uftrace_cpu_arch arch)
{
	switch (arch) {
	case UFT_CPU_X86_64:
	case UFT_CPU_AARCH64:
		return true;
	default:
		return false;
	}
}

enum uftrace_x86_64_reg_index {
	UFT_X86_64_REG_INT_BASE = 0,
	/* integer registers */
	UFT_X86_64_REG_RDI,
	UFT_X86_64_REG_RSI,
	UFT_X86_64_REG_RDX,
	UFT_X86_64_REG_RCX,
	UFT_X86_64_REG_R8,
	UFT_X86_64_REG_R9,

	UFT_X86_64_REG_FLOAT_BASE = 100,
	/* floating-point registers */
	UFT_X86_64_REG_XMM0,
	UFT_X86_64_REG_XMM1,
	UFT_X86_64_REG_XMM2,
	UFT_X86_64_REG_XMM3,
	UFT_X86_64_REG_XMM4,
	UFT_X86_64_REG_XMM5,
	UFT_X86_64_REG_XMM6,
	UFT_X86_64_REG_XMM7,
};

enum uftrace_arm_reg_index {
	UFT_ARM_REG_INT_BASE = 0,
	/* integer registers */
	UFT_ARM_REG_R0,
	UFT_ARM_REG_R1,
	UFT_ARM_REG_R2,
	UFT_ARM_REG_R3,

	UFT_ARM_REG_FLOAT_BASE = 100,
	/* (single-precision) floating-point registers */
	UFT_ARM_REG_S0,
	UFT_ARM_REG_S1,
	UFT_ARM_REG_S2,
	UFT_ARM_REG_S3,
	UFT_ARM_REG_S4,
	UFT_ARM_REG_S5,
	UFT_ARM_REG_S6,
	UFT_ARM_REG_S7,
	UFT_ARM_REG_S8,
	UFT_ARM_REG_S9,
	UFT_ARM_REG_S10,
	UFT_ARM_REG_S11,
	UFT_ARM_REG_S12,
	UFT_ARM_REG_S13,
	UFT_ARM_REG_S14,
	UFT_ARM_REG_S15,
	/* double-precision registers */
	UFT_ARM_REG_DOUBLE_BASE = 200,
	UFT_ARM_REG_D0,
	UFT_ARM_REG_D1,
	UFT_ARM_REG_D2,
	UFT_ARM_REG_D3,
	UFT_ARM_REG_D4,
	UFT_ARM_REG_D5,
	UFT_ARM_REG_D6,
	UFT_ARM_REG_D7,
};

enum uftrace_aarch64_reg_index {
	UFT_AARCH64_REG_INT_BASE = 0,
	/* integer registers */
	UFT_AARCH64_REG_X0,
	UFT_AARCH64_REG_X1,
	UFT_AARCH64_REG_X2,
	UFT_AARCH64_REG_X3,
	UFT_AARCH64_REG_X4,
	UFT_AARCH64_REG_X5,
	UFT_AARCH64_REG_X6,
	UFT_AARCH64_REG_X7,

	UFT_AARCH64_REG_FLOAT_BASE = 100,
	/* (single-precision) floating-point registers */
	UFT_AARCH64_REG_S0,
	UFT_AARCH64_REG_S1,
	UFT_AARCH64_REG_S2,
	UFT_AARCH64_REG_S3,
	UFT_AARCH64_REG_S4,
	UFT_AARCH64_REG_S5,
	UFT_AARCH64_REG_S6,
	UFT_AARCH64_REG_S7,

	UFT_AARCH64_REG_DOUBLE_BASE = 200,
	/* (double-precision) floating-point registers */
	UFT_AARCH64_REG_D0,
	UFT_AARCH64_REG_D1,
	UFT_AARCH64_REG_D2,
	UFT_AARCH64_REG_D3,
	UFT_AARCH64_REG_D4,
	UFT_AARCH64_REG_D5,
	UFT_AARCH64_REG_D6,
	UFT_AARCH64_REG_D7,
};

enum uftrace_i386_reg_index {
	UFT_I386_REG_INT_BASE = 0,
	/* integer registers */
	UFT_I386_REG_ECX,
	UFT_I386_REG_EDX,

	UFT_I386_REG_FLOAT_BASE = 100,
	/* floating-point registers */
	UFT_I386_REG_XMM0,
	UFT_I386_REG_XMM1,
	UFT_I386_REG_XMM2,
	UFT_I386_REG_XMM3,
	UFT_I386_REG_XMM4,
	UFT_I386_REG_XMM5,
	UFT_I386_REG_XMM6,
	UFT_I386_REG_XMM7,
};

int arch_register_number(enum uftrace_cpu_arch arch, char *reg_name);
int arch_register_at(enum uftrace_cpu_arch arch, bool integer, int idx);
int arch_register_index(enum uftrace_cpu_arch arch, int idx);

const char * arch_register_dwarf_name(enum uftrace_cpu_arch arch, int dwarf_reg);
const char * arch_register_argspec_name(enum uftrace_cpu_arch arch,
					bool integer, int idx);

#endif /* UFTRACE_ARCH_H */
