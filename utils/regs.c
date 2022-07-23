
#include "utils/arch.h"
#include "utils/utils.h"

struct uftrace_reg_table {
	const char *name;
	int reg;
};

static const struct uftrace_reg_table uft_x86_64_reg_table[] = {
#define X86_REG(_r)                                                                                \
	{                                                                                          \
#_r, UFT_X86_64_REG_##_r                                                           \
	}

	/* integer registers */
	X86_REG(RDI),
	X86_REG(RSI),
	X86_REG(RDX),
	X86_REG(RCX),
	X86_REG(R8),
	X86_REG(R9),
	/* floating-point registers */
	X86_REG(XMM0),
	X86_REG(XMM1),
	X86_REG(XMM2),
	X86_REG(XMM3),
	X86_REG(XMM4),
	X86_REG(XMM5),
	X86_REG(XMM6),
	X86_REG(XMM7),

#undef X86_REG
};

static const struct uftrace_reg_table uft_arm_reg_table[] = {
#define ARM_REG(_r)                                                                                \
	{                                                                                          \
#_r, UFT_ARM_REG_##_r                                                              \
	}

	/* integer registers */
	ARM_REG(R0),
	ARM_REG(R1),
	ARM_REG(R2),
	ARM_REG(R3),
	/* floating-point registers */
	ARM_REG(S0),
	ARM_REG(S1),
	ARM_REG(S2),
	ARM_REG(S3),
	ARM_REG(S4),
	ARM_REG(S5),
	ARM_REG(S6),
	ARM_REG(S7),
	ARM_REG(S8),
	ARM_REG(S9),
	ARM_REG(S10),
	ARM_REG(S11),
	ARM_REG(S12),
	ARM_REG(S13),
	ARM_REG(S14),
	ARM_REG(S15),
	ARM_REG(D0),
	ARM_REG(D1),
	ARM_REG(D2),
	ARM_REG(D3),
	ARM_REG(D4),
	ARM_REG(D5),
	ARM_REG(D6),
	ARM_REG(D7),

#undef ARM_REG
};

static const struct uftrace_reg_table uft_aarch64_reg_table[] = {
#define ARM64_REG(_r)                                                                              \
	{                                                                                          \
#_r, UFT_AARCH64_REG_##_r                                                          \
	}

	/* integer registers */
	ARM64_REG(X0),
	ARM64_REG(X1),
	ARM64_REG(X2),
	ARM64_REG(X3),
	ARM64_REG(X4),
	ARM64_REG(X5),
	ARM64_REG(X6),
	ARM64_REG(X7),
	/* floating-point registers */
	ARM64_REG(S0),
	ARM64_REG(S1),
	ARM64_REG(S2),
	ARM64_REG(S3),
	ARM64_REG(S4),
	ARM64_REG(S5),
	ARM64_REG(S6),
	ARM64_REG(S7),
	ARM64_REG(D0),
	ARM64_REG(D1),
	ARM64_REG(D2),
	ARM64_REG(D3),
	ARM64_REG(D4),
	ARM64_REG(D5),
	ARM64_REG(D6),
	ARM64_REG(D7),

#undef ARM64_REG
};

static const struct uftrace_reg_table uft_i386_reg_table[] = {
#define X86_REG(_r)                                                                                \
	{                                                                                          \
#_r, UFT_I386_REG_##_r                                                             \
	}

	/* integer registers */
	X86_REG(ECX),
	X86_REG(EDX),
	/* floating-point registers */
	X86_REG(XMM0),
	X86_REG(XMM1),
	X86_REG(XMM2),
	X86_REG(XMM3),
	X86_REG(XMM4),
	X86_REG(XMM5),
	X86_REG(XMM6),
	X86_REG(XMM7),

#undef X86_REG
};

static const struct uftrace_reg_table *arch_reg_tables[] = {
	NULL, uft_x86_64_reg_table, uft_arm_reg_table, uft_aarch64_reg_table, uft_i386_reg_table,
};

static const size_t arch_reg_sizes[] = {
	0,
	ARRAY_SIZE(uft_x86_64_reg_table),
	ARRAY_SIZE(uft_arm_reg_table),
	ARRAY_SIZE(uft_aarch64_reg_table),
	ARRAY_SIZE(uft_i386_reg_table),
};

/* number of integer reigsters */
static const int arch_reg_int_sizes[] = {
	0, 6, 4, 8, 2,
};

/* returns uftrace register number for the architecture */
int arch_register_number(enum uftrace_cpu_arch arch, char *reg_name)
{
	unsigned i;
	const struct uftrace_reg_table *table;

	ASSERT(arch < ARRAY_SIZE(arch_reg_tables));

	table = arch_reg_tables[arch];
	for (i = 0; i < arch_reg_sizes[arch]; i++) {
		if (!strcasecmp(reg_name, table[i].name))
			return table[i].reg;
	}
	return -1;
}

/* return uftrace register number at the given index (for argspec) */
int arch_register_at(enum uftrace_cpu_arch arch, bool integer, int idx)
{
	int int_regs;
	const struct uftrace_reg_table *table;

	ASSERT(arch < ARRAY_SIZE(arch_reg_tables));
	int_regs = arch_reg_int_sizes[arch];
	table = arch_reg_tables[arch];

	if (idx < 0)
		return -1;
	if (integer && idx >= int_regs)
		return -1;

	if (!integer)
		idx += int_regs;
	if (idx >= (int)arch_reg_sizes[arch])
		return -1;

	return table[idx].reg;
}

/* returns argspec register index from uftrace register number */
int arch_register_index(enum uftrace_cpu_arch arch, int reg)
{
	unsigned i;
	const struct uftrace_reg_table *table;

	ASSERT(arch < ARRAY_SIZE(arch_reg_tables));

	table = arch_reg_tables[arch];
	for (i = 0; i < arch_reg_sizes[arch]; i++) {
		if (table[i].reg != reg)
			continue;

		if (i >= (unsigned)arch_reg_int_sizes[arch])
			i -= arch_reg_int_sizes[arch];
		return i;
	}
	return -1;
}

const char *arch_register_argspec_name(enum uftrace_cpu_arch arch, bool integer, int idx)
{
	const struct uftrace_reg_table *table;

	ASSERT(arch < ARRAY_SIZE(arch_reg_tables));

	table = arch_reg_tables[arch];

	if (!integer)
		idx += arch_reg_int_sizes[arch];

	if ((unsigned)idx >= arch_reg_sizes[arch])
		return NULL;

	return table[idx].name;
}

#ifdef HAVE_LIBDW

#include <dwarf.h>

static const struct uftrace_reg_table uft_x86_64_dwarf_table[] = {
	/* support registers used for arguments */
	{
		"rdx",
		DW_OP_reg1,
	},
	{
		"rcx",
		DW_OP_reg2,
	},
	{
		"rsi",
		DW_OP_reg4,
	},
	{
		"rdi",
		DW_OP_reg5,
	},
	{
		"r8",
		DW_OP_reg8,
	},
	{
		"r9",
		DW_OP_reg9,
	},
	{
		"xmm0",
		DW_OP_reg17,
	},
	{
		"xmm1",
		DW_OP_reg18,
	},
	{
		"xmm2",
		DW_OP_reg19,
	},
	{
		"xmm3",
		DW_OP_reg20,
	},
	{
		"xmm4",
		DW_OP_reg21,
	},
	{
		"xmm5",
		DW_OP_reg22,
	},
	{
		"xmm6",
		DW_OP_reg23,
	},
	{
		"xmm7",
		DW_OP_reg24,
	},
};

#define ARM_REG_VFPv3_BASE 256
static const struct uftrace_reg_table uft_arm_dwarf_table[] = {
	/* support registers used for arguments */
	{
		"r0",
		DW_OP_reg0,
	},
	{
		"r1",
		DW_OP_reg1,
	},
	{
		"r2",
		DW_OP_reg2,
	},
	{
		"r3",
		DW_OP_reg3,
	},
	{
		"d0",
		ARM_REG_VFPv3_BASE + 0,
	},
	{
		"d1",
		ARM_REG_VFPv3_BASE + 1,
	},
	{
		"d2",
		ARM_REG_VFPv3_BASE + 2,
	},
	{
		"d3",
		ARM_REG_VFPv3_BASE + 3,
	},
	{
		"d4",
		ARM_REG_VFPv3_BASE + 4,
	},
	{
		"d5",
		ARM_REG_VFPv3_BASE + 5,
	},
	{
		"d6",
		ARM_REG_VFPv3_BASE + 6,
	},
	{
		"d7",
		ARM_REG_VFPv3_BASE + 7,
	},
};

#define AARCH64_REG_FP_BASE 64
static const struct uftrace_reg_table uft_aarch64_dwarf_table[] = {
	/* support registers used for arguments */
	{
		"x0",
		DW_OP_reg0,
	},
	{
		"x1",
		DW_OP_reg1,
	},
	{
		"x2",
		DW_OP_reg2,
	},
	{
		"x3",
		DW_OP_reg3,
	},
	{
		"x4",
		DW_OP_reg4,
	},
	{
		"x5",
		DW_OP_reg5,
	},
	{
		"x6",
		DW_OP_reg6,
	},
	{
		"x7",
		DW_OP_reg7,
	},
	{
		"d0",
		AARCH64_REG_FP_BASE + 0,
	},
	{
		"d1",
		AARCH64_REG_FP_BASE + 1,
	},
	{
		"d2",
		AARCH64_REG_FP_BASE + 2,
	},
	{
		"d3",
		AARCH64_REG_FP_BASE + 3,
	},
	{
		"d4",
		AARCH64_REG_FP_BASE + 4,
	},
	{
		"d5",
		AARCH64_REG_FP_BASE + 5,
	},
	{
		"d6",
		AARCH64_REG_FP_BASE + 6,
	},
	{
		"d7",
		AARCH64_REG_FP_BASE + 7,
	},
};

static const struct uftrace_reg_table uft_i386_dwarf_table[] = {};

static const struct uftrace_reg_table *arch_dwarf_tables[] = {
	NULL,
	uft_x86_64_dwarf_table,
	uft_arm_dwarf_table,
	uft_aarch64_dwarf_table,
	uft_i386_dwarf_table,
};

static const size_t arch_dwarf_sizes[] = {
	0,
	ARRAY_SIZE(uft_x86_64_dwarf_table),
	ARRAY_SIZE(uft_arm_dwarf_table),
	ARRAY_SIZE(uft_aarch64_dwarf_table),
	ARRAY_SIZE(uft_i386_dwarf_table),
};

const char *arch_register_dwarf_name(enum uftrace_cpu_arch arch, int dwarf_reg)
{
	unsigned i;

	const struct uftrace_reg_table *table;

	ASSERT(arch < ARRAY_SIZE(arch_dwarf_tables));

	table = arch_dwarf_tables[arch];
	for (i = 0; i < arch_dwarf_sizes[arch]; i++) {
		if (dwarf_reg == table[i].reg)
			return table[i].name;
	}
	return "invalid register";
}

#endif /* HAVE_LIBDW */
