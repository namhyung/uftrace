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

static const struct uftrace_reg_table uft_riscv64_reg_table[] = {
#define RISCV64_REG(_r)                                                                            \
	{                                                                                          \
#_r, UFT_RISCV64_REG_##_r                                                          \
	}

	/* integer registers */
	RISCV64_REG(A0),
	RISCV64_REG(A1),
	RISCV64_REG(A2),
	RISCV64_REG(A3),
	RISCV64_REG(A4),
	RISCV64_REG(A5),
	RISCV64_REG(A6),
	RISCV64_REG(A7),

	/* floating-point registers */
	RISCV64_REG(FA0),
	RISCV64_REG(FA1),
	RISCV64_REG(FA2),
	RISCV64_REG(FA3),
	RISCV64_REG(FA4),
	RISCV64_REG(FA5),
	RISCV64_REG(FA6),
	RISCV64_REG(FA7),

#undef RISCV64_REG
};

static const struct uftrace_reg_table *arch_reg_tables[] = {
	NULL,
	uft_x86_64_reg_table,
	uft_arm_reg_table,
	uft_aarch64_reg_table,
	uft_i386_reg_table,
	uft_riscv64_reg_table,
};

static const size_t arch_reg_sizes[] = {
	0,
	ARRAY_SIZE(uft_x86_64_reg_table),
	ARRAY_SIZE(uft_arm_reg_table),
	ARRAY_SIZE(uft_aarch64_reg_table),
	ARRAY_SIZE(uft_i386_reg_table),
	ARRAY_SIZE(uft_riscv64_reg_table),
};

/* number of integer registers */
static const int arch_reg_int_sizes[] = {
	0, 6, 4, 8, 2, 8,
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
	else if (idx >= arch_reg_int_sizes[arch])
		return NULL;

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

#define RISCV64_REG_FP_BASE 32
static const struct uftrace_reg_table uft_riscv64_dwarf_table[] = {
	/* support registers used for arguments */
	{
		"a0",
		DW_OP_reg10,
	},
	{
		"a1",
		DW_OP_reg11,
	},
	{
		"a2",
		DW_OP_reg12,
	},
	{
		"a3",
		DW_OP_reg13,
	},
	{
		"a4",
		DW_OP_reg14,
	},
	{
		"a5",
		DW_OP_reg15,
	},
	{
		"a6",
		DW_OP_reg16,
	},
	{
		"a7",
		DW_OP_reg17,
	},
	{
		"fa0",
		RISCV64_REG_FP_BASE + 0,
	},
	{
		"fa1",
		RISCV64_REG_FP_BASE + 1,
	},
	{
		"fa2",
		RISCV64_REG_FP_BASE + 2,
	},
	{
		"fa3",
		RISCV64_REG_FP_BASE + 3,
	},
	{
		"fa4",
		RISCV64_REG_FP_BASE + 4,
	},
	{
		"fa5",
		RISCV64_REG_FP_BASE + 5,
	},
	{
		"fa6",
		RISCV64_REG_FP_BASE + 6,
	},
	{
		"fa7",
		RISCV64_REG_FP_BASE + 7,
	},
};

static const struct uftrace_reg_table *arch_dwarf_tables[] = {
	NULL,
	uft_x86_64_dwarf_table,
	uft_arm_dwarf_table,
	uft_aarch64_dwarf_table,
	uft_i386_dwarf_table,
	uft_riscv64_dwarf_table,
};

static const size_t arch_dwarf_sizes[] = {
	0,
	ARRAY_SIZE(uft_x86_64_dwarf_table),
	ARRAY_SIZE(uft_arm_dwarf_table),
	ARRAY_SIZE(uft_aarch64_dwarf_table),
	ARRAY_SIZE(uft_i386_dwarf_table),
	ARRAY_SIZE(uft_riscv64_dwarf_table),
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

#ifdef UNIT_TEST

TEST_CASE(registers_integer)
{
	pr_dbg("check invalid architecture\n");
	TEST_EQ(arch_register_number(UFT_CPU_NONE, "reg"), -1);
	TEST_EQ(arch_register_at(UFT_CPU_NONE, true, 0), -1);

	pr_dbg("check x86_64 registers\n");
	TEST_EQ(arch_register_number(UFT_CPU_X86_64, "rdi"), UFT_X86_64_REG_RDI);
	TEST_EQ(arch_register_number(UFT_CPU_X86_64, "rsi"), UFT_X86_64_REG_RSI);
	TEST_EQ(arch_register_number(UFT_CPU_X86_64, "rdx"), UFT_X86_64_REG_RDX);
	TEST_EQ(arch_register_number(UFT_CPU_X86_64, "rcx"), UFT_X86_64_REG_RCX);
	TEST_EQ(arch_register_number(UFT_CPU_X86_64, "r8"), UFT_X86_64_REG_R8);
	TEST_EQ(arch_register_number(UFT_CPU_X86_64, "r9"), UFT_X86_64_REG_R9);
	TEST_EQ(arch_register_number(UFT_CPU_X86_64, "rax"), -1);
	TEST_EQ(arch_register_number(UFT_CPU_X86_64, "rbx"), -1);

	TEST_EQ(arch_register_at(UFT_CPU_X86_64, true, 0), UFT_X86_64_REG_RDI);
	TEST_EQ(arch_register_at(UFT_CPU_X86_64, true, 1), UFT_X86_64_REG_RSI);
	TEST_EQ(arch_register_at(UFT_CPU_X86_64, true, 2), UFT_X86_64_REG_RDX);
	TEST_EQ(arch_register_at(UFT_CPU_X86_64, true, 3), UFT_X86_64_REG_RCX);
	TEST_EQ(arch_register_at(UFT_CPU_X86_64, true, 4), UFT_X86_64_REG_R8);
	TEST_EQ(arch_register_at(UFT_CPU_X86_64, true, 5), UFT_X86_64_REG_R9);
	TEST_EQ(arch_register_at(UFT_CPU_X86_64, true, 6), -1);

	TEST_EQ(arch_register_index(UFT_CPU_X86_64, UFT_X86_64_REG_RDI), 0);
	TEST_EQ(arch_register_index(UFT_CPU_X86_64, UFT_X86_64_REG_RSI), 1);
	TEST_EQ(arch_register_index(UFT_CPU_X86_64, UFT_X86_64_REG_RDX), 2);
	TEST_EQ(arch_register_index(UFT_CPU_X86_64, UFT_X86_64_REG_RCX), 3);
	TEST_EQ(arch_register_index(UFT_CPU_X86_64, UFT_X86_64_REG_R8), 4);
	TEST_EQ(arch_register_index(UFT_CPU_X86_64, UFT_X86_64_REG_R9), 5);

	TEST_STREQ(arch_register_argspec_name(UFT_CPU_X86_64, true, 0), "RDI");
	TEST_STREQ(arch_register_argspec_name(UFT_CPU_X86_64, true, 1), "RSI");
	TEST_STREQ(arch_register_argspec_name(UFT_CPU_X86_64, true, 2), "RDX");
	TEST_STREQ(arch_register_argspec_name(UFT_CPU_X86_64, true, 3), "RCX");
	TEST_STREQ(arch_register_argspec_name(UFT_CPU_X86_64, true, 4), "R8");
	TEST_STREQ(arch_register_argspec_name(UFT_CPU_X86_64, true, 5), "R9");
	TEST_EQ(arch_register_argspec_name(UFT_CPU_X86_64, true, 6), NULL);

	pr_dbg("check aarch64 registers\n");
	TEST_EQ(arch_register_number(UFT_CPU_AARCH64, "x0"), UFT_AARCH64_REG_X0);
	TEST_EQ(arch_register_number(UFT_CPU_AARCH64, "x1"), UFT_AARCH64_REG_X1);
	TEST_EQ(arch_register_number(UFT_CPU_AARCH64, "x2"), UFT_AARCH64_REG_X2);
	TEST_EQ(arch_register_number(UFT_CPU_AARCH64, "x3"), UFT_AARCH64_REG_X3);
	TEST_EQ(arch_register_number(UFT_CPU_AARCH64, "x4"), UFT_AARCH64_REG_X4);
	TEST_EQ(arch_register_number(UFT_CPU_AARCH64, "x5"), UFT_AARCH64_REG_X5);
	TEST_EQ(arch_register_number(UFT_CPU_AARCH64, "x6"), UFT_AARCH64_REG_X6);
	TEST_EQ(arch_register_number(UFT_CPU_AARCH64, "x7"), UFT_AARCH64_REG_X7);
	TEST_EQ(arch_register_number(UFT_CPU_AARCH64, "x8"), -1);
	TEST_EQ(arch_register_number(UFT_CPU_AARCH64, "sp"), -1);

	TEST_EQ(arch_register_at(UFT_CPU_AARCH64, true, 0), UFT_AARCH64_REG_X0);
	TEST_EQ(arch_register_at(UFT_CPU_AARCH64, true, 1), UFT_AARCH64_REG_X1);
	TEST_EQ(arch_register_at(UFT_CPU_AARCH64, true, 2), UFT_AARCH64_REG_X2);
	TEST_EQ(arch_register_at(UFT_CPU_AARCH64, true, 3), UFT_AARCH64_REG_X3);
	TEST_EQ(arch_register_at(UFT_CPU_AARCH64, true, 4), UFT_AARCH64_REG_X4);
	TEST_EQ(arch_register_at(UFT_CPU_AARCH64, true, 5), UFT_AARCH64_REG_X5);
	TEST_EQ(arch_register_at(UFT_CPU_AARCH64, true, 6), UFT_AARCH64_REG_X6);
	TEST_EQ(arch_register_at(UFT_CPU_AARCH64, true, 7), UFT_AARCH64_REG_X7);
	TEST_EQ(arch_register_at(UFT_CPU_AARCH64, true, 8), -1);

	TEST_EQ(arch_register_index(UFT_CPU_AARCH64, UFT_AARCH64_REG_X0), 0);
	TEST_EQ(arch_register_index(UFT_CPU_AARCH64, UFT_AARCH64_REG_X1), 1);
	TEST_EQ(arch_register_index(UFT_CPU_AARCH64, UFT_AARCH64_REG_X2), 2);
	TEST_EQ(arch_register_index(UFT_CPU_AARCH64, UFT_AARCH64_REG_X3), 3);
	TEST_EQ(arch_register_index(UFT_CPU_AARCH64, UFT_AARCH64_REG_X4), 4);
	TEST_EQ(arch_register_index(UFT_CPU_AARCH64, UFT_AARCH64_REG_X5), 5);
	TEST_EQ(arch_register_index(UFT_CPU_AARCH64, UFT_AARCH64_REG_X6), 6);
	TEST_EQ(arch_register_index(UFT_CPU_AARCH64, UFT_AARCH64_REG_X7), 7);

	TEST_STREQ(arch_register_argspec_name(UFT_CPU_AARCH64, true, 0), "X0");
	TEST_STREQ(arch_register_argspec_name(UFT_CPU_AARCH64, true, 1), "X1");
	TEST_STREQ(arch_register_argspec_name(UFT_CPU_AARCH64, true, 2), "X2");
	TEST_STREQ(arch_register_argspec_name(UFT_CPU_AARCH64, true, 3), "X3");
	TEST_STREQ(arch_register_argspec_name(UFT_CPU_AARCH64, true, 4), "X4");
	TEST_STREQ(arch_register_argspec_name(UFT_CPU_AARCH64, true, 5), "X5");
	TEST_STREQ(arch_register_argspec_name(UFT_CPU_AARCH64, true, 6), "X6");
	TEST_STREQ(arch_register_argspec_name(UFT_CPU_AARCH64, true, 7), "X7");
	TEST_EQ(arch_register_argspec_name(UFT_CPU_AARCH64, true, 8), NULL);

	pr_dbg("check i386 registers\n");
	TEST_EQ(arch_register_number(UFT_CPU_I386, "ecx"), UFT_I386_REG_ECX);
	TEST_EQ(arch_register_number(UFT_CPU_I386, "edx"), UFT_I386_REG_EDX);
	TEST_EQ(arch_register_number(UFT_CPU_I386, "eax"), -1);
	TEST_EQ(arch_register_number(UFT_CPU_I386, "ebx"), -1);

	TEST_EQ(arch_register_at(UFT_CPU_I386, true, 0), UFT_I386_REG_ECX);
	TEST_EQ(arch_register_at(UFT_CPU_I386, true, 1), UFT_I386_REG_EDX);

	TEST_EQ(arch_register_index(UFT_CPU_I386, UFT_I386_REG_ECX), 0);
	TEST_EQ(arch_register_index(UFT_CPU_I386, UFT_I386_REG_EDX), 1);

	TEST_STREQ(arch_register_argspec_name(UFT_CPU_I386, true, 0), "ECX");
	TEST_STREQ(arch_register_argspec_name(UFT_CPU_I386, true, 1), "EDX");
	TEST_EQ(arch_register_argspec_name(UFT_CPU_I386, true, 2), NULL);

	pr_dbg("check arm registers\n");
	TEST_EQ(arch_register_number(UFT_CPU_ARM, "r0"), UFT_ARM_REG_R0);
	TEST_EQ(arch_register_number(UFT_CPU_ARM, "r1"), UFT_ARM_REG_R1);
	TEST_EQ(arch_register_number(UFT_CPU_ARM, "r2"), UFT_ARM_REG_R2);
	TEST_EQ(arch_register_number(UFT_CPU_ARM, "r3"), UFT_ARM_REG_R3);
	TEST_EQ(arch_register_number(UFT_CPU_ARM, "r4"), -1);
	TEST_EQ(arch_register_number(UFT_CPU_ARM, "fp"), -1);

	TEST_EQ(arch_register_at(UFT_CPU_ARM, true, 0), UFT_ARM_REG_R0);
	TEST_EQ(arch_register_at(UFT_CPU_ARM, true, 1), UFT_ARM_REG_R1);
	TEST_EQ(arch_register_at(UFT_CPU_ARM, true, 2), UFT_ARM_REG_R2);
	TEST_EQ(arch_register_at(UFT_CPU_ARM, true, 3), UFT_ARM_REG_R3);

	TEST_EQ(arch_register_index(UFT_CPU_ARM, UFT_ARM_REG_R0), 0);
	TEST_EQ(arch_register_index(UFT_CPU_ARM, UFT_ARM_REG_R1), 1);
	TEST_EQ(arch_register_index(UFT_CPU_ARM, UFT_ARM_REG_R2), 2);
	TEST_EQ(arch_register_index(UFT_CPU_ARM, UFT_ARM_REG_R3), 3);

	TEST_STREQ(arch_register_argspec_name(UFT_CPU_ARM, true, 0), "R0");
	TEST_STREQ(arch_register_argspec_name(UFT_CPU_ARM, true, 1), "R1");
	TEST_STREQ(arch_register_argspec_name(UFT_CPU_ARM, true, 2), "R2");
	TEST_STREQ(arch_register_argspec_name(UFT_CPU_ARM, true, 3), "R3");
	TEST_EQ(arch_register_argspec_name(UFT_CPU_ARM, true, 4), NULL);

	pr_dbg("check ricsv64 registers\n");
	TEST_EQ(arch_register_number(UFT_CPU_RISCV64, "a0"), UFT_RISCV64_REG_A0);
	TEST_EQ(arch_register_number(UFT_CPU_RISCV64, "a1"), UFT_RISCV64_REG_A1);
	TEST_EQ(arch_register_number(UFT_CPU_RISCV64, "a2"), UFT_RISCV64_REG_A2);
	TEST_EQ(arch_register_number(UFT_CPU_RISCV64, "a3"), UFT_RISCV64_REG_A3);
	TEST_EQ(arch_register_number(UFT_CPU_RISCV64, "a4"), UFT_RISCV64_REG_A4);
	TEST_EQ(arch_register_number(UFT_CPU_RISCV64, "a5"), UFT_RISCV64_REG_A5);
	TEST_EQ(arch_register_number(UFT_CPU_RISCV64, "a6"), UFT_RISCV64_REG_A6);
	TEST_EQ(arch_register_number(UFT_CPU_RISCV64, "a7"), UFT_RISCV64_REG_A7);
	TEST_EQ(arch_register_number(UFT_CPU_RISCV64, "a8"), -1);
	TEST_EQ(arch_register_number(UFT_CPU_RISCV64, "gp"), -1);

	TEST_EQ(arch_register_at(UFT_CPU_RISCV64, true, 0), UFT_RISCV64_REG_A0);
	TEST_EQ(arch_register_at(UFT_CPU_RISCV64, true, 1), UFT_RISCV64_REG_A1);
	TEST_EQ(arch_register_at(UFT_CPU_RISCV64, true, 2), UFT_RISCV64_REG_A2);
	TEST_EQ(arch_register_at(UFT_CPU_RISCV64, true, 3), UFT_RISCV64_REG_A3);
	TEST_EQ(arch_register_at(UFT_CPU_RISCV64, true, 4), UFT_RISCV64_REG_A4);
	TEST_EQ(arch_register_at(UFT_CPU_RISCV64, true, 5), UFT_RISCV64_REG_A5);
	TEST_EQ(arch_register_at(UFT_CPU_RISCV64, true, 6), UFT_RISCV64_REG_A6);
	TEST_EQ(arch_register_at(UFT_CPU_RISCV64, true, 7), UFT_RISCV64_REG_A7);

	TEST_EQ(arch_register_index(UFT_CPU_RISCV64, UFT_RISCV64_REG_A0), 0);
	TEST_EQ(arch_register_index(UFT_CPU_RISCV64, UFT_RISCV64_REG_A1), 1);
	TEST_EQ(arch_register_index(UFT_CPU_RISCV64, UFT_RISCV64_REG_A2), 2);
	TEST_EQ(arch_register_index(UFT_CPU_RISCV64, UFT_RISCV64_REG_A3), 3);
	TEST_EQ(arch_register_index(UFT_CPU_RISCV64, UFT_RISCV64_REG_A4), 4);
	TEST_EQ(arch_register_index(UFT_CPU_RISCV64, UFT_RISCV64_REG_A5), 5);
	TEST_EQ(arch_register_index(UFT_CPU_RISCV64, UFT_RISCV64_REG_A6), 6);
	TEST_EQ(arch_register_index(UFT_CPU_RISCV64, UFT_RISCV64_REG_A7), 7);

	TEST_STREQ(arch_register_argspec_name(UFT_CPU_RISCV64, true, 0), "A0");
	TEST_STREQ(arch_register_argspec_name(UFT_CPU_RISCV64, true, 1), "A1");
	TEST_STREQ(arch_register_argspec_name(UFT_CPU_RISCV64, true, 2), "A2");
	TEST_STREQ(arch_register_argspec_name(UFT_CPU_RISCV64, true, 3), "A3");
	TEST_STREQ(arch_register_argspec_name(UFT_CPU_RISCV64, true, 4), "A4");
	TEST_STREQ(arch_register_argspec_name(UFT_CPU_RISCV64, true, 5), "A5");
	TEST_STREQ(arch_register_argspec_name(UFT_CPU_RISCV64, true, 6), "A6");
	TEST_STREQ(arch_register_argspec_name(UFT_CPU_RISCV64, true, 7), "A7");
	TEST_EQ(arch_register_argspec_name(UFT_CPU_RISCV64, true, 8), NULL);

	return TEST_OK;
}

TEST_CASE(registers_float)
{
	pr_dbg("check invalid architecture\n");
	TEST_EQ(arch_register_number(UFT_CPU_NONE, "fpreg"), -1);
	TEST_EQ(arch_register_at(UFT_CPU_NONE, false, 0), -1);

	pr_dbg("check x86_64 registers\n");
	TEST_EQ(arch_register_number(UFT_CPU_X86_64, "xmm0"), UFT_X86_64_REG_XMM0);
	TEST_EQ(arch_register_number(UFT_CPU_X86_64, "xmm1"), UFT_X86_64_REG_XMM1);
	TEST_EQ(arch_register_number(UFT_CPU_X86_64, "xmm2"), UFT_X86_64_REG_XMM2);
	TEST_EQ(arch_register_number(UFT_CPU_X86_64, "xmm3"), UFT_X86_64_REG_XMM3);
	TEST_EQ(arch_register_number(UFT_CPU_X86_64, "xmm4"), UFT_X86_64_REG_XMM4);
	TEST_EQ(arch_register_number(UFT_CPU_X86_64, "xmm5"), UFT_X86_64_REG_XMM5);
	TEST_EQ(arch_register_number(UFT_CPU_X86_64, "xmm6"), UFT_X86_64_REG_XMM6);
	TEST_EQ(arch_register_number(UFT_CPU_X86_64, "xmm7"), UFT_X86_64_REG_XMM7);
	TEST_EQ(arch_register_number(UFT_CPU_X86_64, "xmm8"), -1);

	TEST_EQ(arch_register_at(UFT_CPU_X86_64, false, 0), UFT_X86_64_REG_XMM0);
	TEST_EQ(arch_register_at(UFT_CPU_X86_64, false, 1), UFT_X86_64_REG_XMM1);
	TEST_EQ(arch_register_at(UFT_CPU_X86_64, false, 2), UFT_X86_64_REG_XMM2);
	TEST_EQ(arch_register_at(UFT_CPU_X86_64, false, 3), UFT_X86_64_REG_XMM3);
	TEST_EQ(arch_register_at(UFT_CPU_X86_64, false, 4), UFT_X86_64_REG_XMM4);
	TEST_EQ(arch_register_at(UFT_CPU_X86_64, false, 5), UFT_X86_64_REG_XMM5);
	TEST_EQ(arch_register_at(UFT_CPU_X86_64, false, 6), UFT_X86_64_REG_XMM6);
	TEST_EQ(arch_register_at(UFT_CPU_X86_64, false, 7), UFT_X86_64_REG_XMM7);

	TEST_EQ(arch_register_index(UFT_CPU_X86_64, UFT_X86_64_REG_XMM0), 0);
	TEST_EQ(arch_register_index(UFT_CPU_X86_64, UFT_X86_64_REG_XMM1), 1);
	TEST_EQ(arch_register_index(UFT_CPU_X86_64, UFT_X86_64_REG_XMM2), 2);
	TEST_EQ(arch_register_index(UFT_CPU_X86_64, UFT_X86_64_REG_XMM3), 3);
	TEST_EQ(arch_register_index(UFT_CPU_X86_64, UFT_X86_64_REG_XMM4), 4);
	TEST_EQ(arch_register_index(UFT_CPU_X86_64, UFT_X86_64_REG_XMM5), 5);
	TEST_EQ(arch_register_index(UFT_CPU_X86_64, UFT_X86_64_REG_XMM6), 6);
	TEST_EQ(arch_register_index(UFT_CPU_X86_64, UFT_X86_64_REG_XMM7), 7);

	TEST_STREQ(arch_register_argspec_name(UFT_CPU_X86_64, false, 0), "XMM0");
	TEST_STREQ(arch_register_argspec_name(UFT_CPU_X86_64, false, 1), "XMM1");
	TEST_STREQ(arch_register_argspec_name(UFT_CPU_X86_64, false, 2), "XMM2");
	TEST_STREQ(arch_register_argspec_name(UFT_CPU_X86_64, false, 3), "XMM3");
	TEST_STREQ(arch_register_argspec_name(UFT_CPU_X86_64, false, 4), "XMM4");
	TEST_STREQ(arch_register_argspec_name(UFT_CPU_X86_64, false, 5), "XMM5");
	TEST_STREQ(arch_register_argspec_name(UFT_CPU_X86_64, false, 6), "XMM6");
	TEST_STREQ(arch_register_argspec_name(UFT_CPU_X86_64, false, 7), "XMM7");
	TEST_EQ(arch_register_argspec_name(UFT_CPU_X86_64, false, 8), NULL);

	pr_dbg("check aarch64 registers\n");
	TEST_EQ(arch_register_number(UFT_CPU_AARCH64, "s0"), UFT_AARCH64_REG_S0);
	TEST_EQ(arch_register_number(UFT_CPU_AARCH64, "s1"), UFT_AARCH64_REG_S1);
	TEST_EQ(arch_register_number(UFT_CPU_AARCH64, "s2"), UFT_AARCH64_REG_S2);
	TEST_EQ(arch_register_number(UFT_CPU_AARCH64, "s3"), UFT_AARCH64_REG_S3);
	TEST_EQ(arch_register_number(UFT_CPU_AARCH64, "s4"), UFT_AARCH64_REG_S4);
	TEST_EQ(arch_register_number(UFT_CPU_AARCH64, "s5"), UFT_AARCH64_REG_S5);
	TEST_EQ(arch_register_number(UFT_CPU_AARCH64, "s6"), UFT_AARCH64_REG_S6);
	TEST_EQ(arch_register_number(UFT_CPU_AARCH64, "s7"), UFT_AARCH64_REG_S7);

	TEST_EQ(arch_register_at(UFT_CPU_AARCH64, false, 0), UFT_AARCH64_REG_S0);
	TEST_EQ(arch_register_at(UFT_CPU_AARCH64, false, 1), UFT_AARCH64_REG_S1);
	TEST_EQ(arch_register_at(UFT_CPU_AARCH64, false, 2), UFT_AARCH64_REG_S2);
	TEST_EQ(arch_register_at(UFT_CPU_AARCH64, false, 3), UFT_AARCH64_REG_S3);
	TEST_EQ(arch_register_at(UFT_CPU_AARCH64, false, 4), UFT_AARCH64_REG_S4);
	TEST_EQ(arch_register_at(UFT_CPU_AARCH64, false, 5), UFT_AARCH64_REG_S5);
	TEST_EQ(arch_register_at(UFT_CPU_AARCH64, false, 6), UFT_AARCH64_REG_S6);
	TEST_EQ(arch_register_at(UFT_CPU_AARCH64, false, 7), UFT_AARCH64_REG_S7);

	TEST_EQ(arch_register_index(UFT_CPU_AARCH64, UFT_AARCH64_REG_S0), 0);
	TEST_EQ(arch_register_index(UFT_CPU_AARCH64, UFT_AARCH64_REG_S1), 1);
	TEST_EQ(arch_register_index(UFT_CPU_AARCH64, UFT_AARCH64_REG_S2), 2);
	TEST_EQ(arch_register_index(UFT_CPU_AARCH64, UFT_AARCH64_REG_S3), 3);
	TEST_EQ(arch_register_index(UFT_CPU_AARCH64, UFT_AARCH64_REG_S4), 4);
	TEST_EQ(arch_register_index(UFT_CPU_AARCH64, UFT_AARCH64_REG_S5), 5);
	TEST_EQ(arch_register_index(UFT_CPU_AARCH64, UFT_AARCH64_REG_S6), 6);
	TEST_EQ(arch_register_index(UFT_CPU_AARCH64, UFT_AARCH64_REG_S7), 7);

	TEST_STREQ(arch_register_argspec_name(UFT_CPU_AARCH64, false, 0), "S0");
	TEST_STREQ(arch_register_argspec_name(UFT_CPU_AARCH64, false, 1), "S1");
	TEST_STREQ(arch_register_argspec_name(UFT_CPU_AARCH64, false, 2), "S2");
	TEST_STREQ(arch_register_argspec_name(UFT_CPU_AARCH64, false, 3), "S3");
	TEST_STREQ(arch_register_argspec_name(UFT_CPU_AARCH64, false, 4), "S4");
	TEST_STREQ(arch_register_argspec_name(UFT_CPU_AARCH64, false, 5), "S5");
	TEST_STREQ(arch_register_argspec_name(UFT_CPU_AARCH64, false, 6), "S6");
	TEST_STREQ(arch_register_argspec_name(UFT_CPU_AARCH64, false, 7), "S7");

	pr_dbg("check i386 registers\n");
	TEST_EQ(arch_register_number(UFT_CPU_I386, "xmm0"), UFT_I386_REG_XMM0);
	TEST_EQ(arch_register_number(UFT_CPU_I386, "xmm1"), UFT_I386_REG_XMM1);
	TEST_EQ(arch_register_number(UFT_CPU_I386, "xmm2"), UFT_I386_REG_XMM2);
	TEST_EQ(arch_register_number(UFT_CPU_I386, "xmm3"), UFT_I386_REG_XMM3);
	TEST_EQ(arch_register_number(UFT_CPU_I386, "xmm4"), UFT_I386_REG_XMM4);
	TEST_EQ(arch_register_number(UFT_CPU_I386, "xmm5"), UFT_I386_REG_XMM5);
	TEST_EQ(arch_register_number(UFT_CPU_I386, "xmm6"), UFT_I386_REG_XMM6);
	TEST_EQ(arch_register_number(UFT_CPU_I386, "xmm7"), UFT_I386_REG_XMM7);
	TEST_EQ(arch_register_number(UFT_CPU_I386, "xmm8"), -1);

	TEST_EQ(arch_register_at(UFT_CPU_I386, false, 0), UFT_I386_REG_XMM0);
	TEST_EQ(arch_register_at(UFT_CPU_I386, false, 1), UFT_I386_REG_XMM1);
	TEST_EQ(arch_register_at(UFT_CPU_I386, false, 2), UFT_I386_REG_XMM2);
	TEST_EQ(arch_register_at(UFT_CPU_I386, false, 3), UFT_I386_REG_XMM3);
	TEST_EQ(arch_register_at(UFT_CPU_I386, false, 4), UFT_I386_REG_XMM4);
	TEST_EQ(arch_register_at(UFT_CPU_I386, false, 5), UFT_I386_REG_XMM5);
	TEST_EQ(arch_register_at(UFT_CPU_I386, false, 6), UFT_I386_REG_XMM6);
	TEST_EQ(arch_register_at(UFT_CPU_I386, false, 7), UFT_I386_REG_XMM7);

	TEST_EQ(arch_register_index(UFT_CPU_I386, UFT_I386_REG_XMM0), 0);
	TEST_EQ(arch_register_index(UFT_CPU_I386, UFT_I386_REG_XMM1), 1);
	TEST_EQ(arch_register_index(UFT_CPU_I386, UFT_I386_REG_XMM2), 2);
	TEST_EQ(arch_register_index(UFT_CPU_I386, UFT_I386_REG_XMM3), 3);
	TEST_EQ(arch_register_index(UFT_CPU_I386, UFT_I386_REG_XMM4), 4);
	TEST_EQ(arch_register_index(UFT_CPU_I386, UFT_I386_REG_XMM5), 5);
	TEST_EQ(arch_register_index(UFT_CPU_I386, UFT_I386_REG_XMM6), 6);
	TEST_EQ(arch_register_index(UFT_CPU_I386, UFT_I386_REG_XMM7), 7);

	TEST_STREQ(arch_register_argspec_name(UFT_CPU_I386, false, 0), "XMM0");
	TEST_STREQ(arch_register_argspec_name(UFT_CPU_I386, false, 1), "XMM1");
	TEST_STREQ(arch_register_argspec_name(UFT_CPU_I386, false, 2), "XMM2");
	TEST_STREQ(arch_register_argspec_name(UFT_CPU_I386, false, 3), "XMM3");
	TEST_STREQ(arch_register_argspec_name(UFT_CPU_I386, false, 4), "XMM4");
	TEST_STREQ(arch_register_argspec_name(UFT_CPU_I386, false, 5), "XMM5");
	TEST_STREQ(arch_register_argspec_name(UFT_CPU_I386, false, 6), "XMM6");
	TEST_STREQ(arch_register_argspec_name(UFT_CPU_I386, false, 7), "XMM7");
	TEST_EQ(arch_register_argspec_name(UFT_CPU_I386, false, 8), NULL);

	pr_dbg("check arm registers\n");
	TEST_EQ(arch_register_number(UFT_CPU_ARM, "s0"), UFT_ARM_REG_S0);
	TEST_EQ(arch_register_number(UFT_CPU_ARM, "s1"), UFT_ARM_REG_S1);
	TEST_EQ(arch_register_number(UFT_CPU_ARM, "s2"), UFT_ARM_REG_S2);
	TEST_EQ(arch_register_number(UFT_CPU_ARM, "s3"), UFT_ARM_REG_S3);
	TEST_EQ(arch_register_number(UFT_CPU_ARM, "s4"), UFT_ARM_REG_S4);
	TEST_EQ(arch_register_number(UFT_CPU_ARM, "s5"), UFT_ARM_REG_S5);
	TEST_EQ(arch_register_number(UFT_CPU_ARM, "s6"), UFT_ARM_REG_S6);
	TEST_EQ(arch_register_number(UFT_CPU_ARM, "s7"), UFT_ARM_REG_S7);
	TEST_EQ(arch_register_number(UFT_CPU_ARM, "s8"), UFT_ARM_REG_S8);
	TEST_EQ(arch_register_number(UFT_CPU_ARM, "s9"), UFT_ARM_REG_S9);
	TEST_EQ(arch_register_number(UFT_CPU_ARM, "s10"), UFT_ARM_REG_S10);
	TEST_EQ(arch_register_number(UFT_CPU_ARM, "s11"), UFT_ARM_REG_S11);
	TEST_EQ(arch_register_number(UFT_CPU_ARM, "s12"), UFT_ARM_REG_S12);
	TEST_EQ(arch_register_number(UFT_CPU_ARM, "s13"), UFT_ARM_REG_S13);
	TEST_EQ(arch_register_number(UFT_CPU_ARM, "s14"), UFT_ARM_REG_S14);
	TEST_EQ(arch_register_number(UFT_CPU_ARM, "s15"), UFT_ARM_REG_S15);

	TEST_EQ(arch_register_at(UFT_CPU_ARM, false, 0), UFT_ARM_REG_S0);
	TEST_EQ(arch_register_at(UFT_CPU_ARM, false, 1), UFT_ARM_REG_S1);
	TEST_EQ(arch_register_at(UFT_CPU_ARM, false, 2), UFT_ARM_REG_S2);
	TEST_EQ(arch_register_at(UFT_CPU_ARM, false, 3), UFT_ARM_REG_S3);
	TEST_EQ(arch_register_at(UFT_CPU_ARM, false, 4), UFT_ARM_REG_S4);
	TEST_EQ(arch_register_at(UFT_CPU_ARM, false, 5), UFT_ARM_REG_S5);
	TEST_EQ(arch_register_at(UFT_CPU_ARM, false, 6), UFT_ARM_REG_S6);
	TEST_EQ(arch_register_at(UFT_CPU_ARM, false, 7), UFT_ARM_REG_S7);
	TEST_EQ(arch_register_at(UFT_CPU_ARM, false, 8), UFT_ARM_REG_S8);
	TEST_EQ(arch_register_at(UFT_CPU_ARM, false, 9), UFT_ARM_REG_S9);
	TEST_EQ(arch_register_at(UFT_CPU_ARM, false, 10), UFT_ARM_REG_S10);
	TEST_EQ(arch_register_at(UFT_CPU_ARM, false, 11), UFT_ARM_REG_S11);
	TEST_EQ(arch_register_at(UFT_CPU_ARM, false, 12), UFT_ARM_REG_S12);
	TEST_EQ(arch_register_at(UFT_CPU_ARM, false, 13), UFT_ARM_REG_S13);
	TEST_EQ(arch_register_at(UFT_CPU_ARM, false, 14), UFT_ARM_REG_S14);
	TEST_EQ(arch_register_at(UFT_CPU_ARM, false, 15), UFT_ARM_REG_S15);

	TEST_EQ(arch_register_index(UFT_CPU_ARM, UFT_ARM_REG_S0), 0);
	TEST_EQ(arch_register_index(UFT_CPU_ARM, UFT_ARM_REG_S1), 1);
	TEST_EQ(arch_register_index(UFT_CPU_ARM, UFT_ARM_REG_S2), 2);
	TEST_EQ(arch_register_index(UFT_CPU_ARM, UFT_ARM_REG_S3), 3);
	TEST_EQ(arch_register_index(UFT_CPU_ARM, UFT_ARM_REG_S4), 4);
	TEST_EQ(arch_register_index(UFT_CPU_ARM, UFT_ARM_REG_S5), 5);
	TEST_EQ(arch_register_index(UFT_CPU_ARM, UFT_ARM_REG_S6), 6);
	TEST_EQ(arch_register_index(UFT_CPU_ARM, UFT_ARM_REG_S7), 7);
	TEST_EQ(arch_register_index(UFT_CPU_ARM, UFT_ARM_REG_S8), 8);
	TEST_EQ(arch_register_index(UFT_CPU_ARM, UFT_ARM_REG_S9), 9);
	TEST_EQ(arch_register_index(UFT_CPU_ARM, UFT_ARM_REG_S10), 10);
	TEST_EQ(arch_register_index(UFT_CPU_ARM, UFT_ARM_REG_S11), 11);
	TEST_EQ(arch_register_index(UFT_CPU_ARM, UFT_ARM_REG_S12), 12);
	TEST_EQ(arch_register_index(UFT_CPU_ARM, UFT_ARM_REG_S13), 13);
	TEST_EQ(arch_register_index(UFT_CPU_ARM, UFT_ARM_REG_S14), 14);
	TEST_EQ(arch_register_index(UFT_CPU_ARM, UFT_ARM_REG_S15), 15);

	TEST_STREQ(arch_register_argspec_name(UFT_CPU_ARM, false, 0), "S0");
	TEST_STREQ(arch_register_argspec_name(UFT_CPU_ARM, false, 1), "S1");
	TEST_STREQ(arch_register_argspec_name(UFT_CPU_ARM, false, 2), "S2");
	TEST_STREQ(arch_register_argspec_name(UFT_CPU_ARM, false, 3), "S3");
	TEST_STREQ(arch_register_argspec_name(UFT_CPU_ARM, false, 4), "S4");
	TEST_STREQ(arch_register_argspec_name(UFT_CPU_ARM, false, 5), "S5");
	TEST_STREQ(arch_register_argspec_name(UFT_CPU_ARM, false, 6), "S6");
	TEST_STREQ(arch_register_argspec_name(UFT_CPU_ARM, false, 7), "S7");
	TEST_STREQ(arch_register_argspec_name(UFT_CPU_ARM, false, 8), "S8");
	TEST_STREQ(arch_register_argspec_name(UFT_CPU_ARM, false, 9), "S9");
	TEST_STREQ(arch_register_argspec_name(UFT_CPU_ARM, false, 10), "S10");
	TEST_STREQ(arch_register_argspec_name(UFT_CPU_ARM, false, 11), "S11");
	TEST_STREQ(arch_register_argspec_name(UFT_CPU_ARM, false, 12), "S12");
	TEST_STREQ(arch_register_argspec_name(UFT_CPU_ARM, false, 13), "S13");
	TEST_STREQ(arch_register_argspec_name(UFT_CPU_ARM, false, 14), "S14");
	TEST_STREQ(arch_register_argspec_name(UFT_CPU_ARM, false, 15), "S15");

	pr_dbg("check riscv64 registers\n");
	TEST_EQ(arch_register_number(UFT_CPU_RISCV64, "fa0"), UFT_RISCV64_REG_FA0);
	TEST_EQ(arch_register_number(UFT_CPU_RISCV64, "fa1"), UFT_RISCV64_REG_FA1);
	TEST_EQ(arch_register_number(UFT_CPU_RISCV64, "fa2"), UFT_RISCV64_REG_FA2);
	TEST_EQ(arch_register_number(UFT_CPU_RISCV64, "fa3"), UFT_RISCV64_REG_FA3);
	TEST_EQ(arch_register_number(UFT_CPU_RISCV64, "fa4"), UFT_RISCV64_REG_FA4);
	TEST_EQ(arch_register_number(UFT_CPU_RISCV64, "fa5"), UFT_RISCV64_REG_FA5);
	TEST_EQ(arch_register_number(UFT_CPU_RISCV64, "fa6"), UFT_RISCV64_REG_FA6);
	TEST_EQ(arch_register_number(UFT_CPU_RISCV64, "fa7"), UFT_RISCV64_REG_FA7);
	TEST_EQ(arch_register_number(UFT_CPU_RISCV64, "fa8"), -1);

	TEST_EQ(arch_register_at(UFT_CPU_RISCV64, false, 0), UFT_RISCV64_REG_FA0);
	TEST_EQ(arch_register_at(UFT_CPU_RISCV64, false, 1), UFT_RISCV64_REG_FA1);
	TEST_EQ(arch_register_at(UFT_CPU_RISCV64, false, 2), UFT_RISCV64_REG_FA2);
	TEST_EQ(arch_register_at(UFT_CPU_RISCV64, false, 3), UFT_RISCV64_REG_FA3);
	TEST_EQ(arch_register_at(UFT_CPU_RISCV64, false, 4), UFT_RISCV64_REG_FA4);
	TEST_EQ(arch_register_at(UFT_CPU_RISCV64, false, 5), UFT_RISCV64_REG_FA5);
	TEST_EQ(arch_register_at(UFT_CPU_RISCV64, false, 6), UFT_RISCV64_REG_FA6);
	TEST_EQ(arch_register_at(UFT_CPU_RISCV64, false, 7), UFT_RISCV64_REG_FA7);

	TEST_EQ(arch_register_index(UFT_CPU_RISCV64, UFT_RISCV64_REG_FA0), 0);
	TEST_EQ(arch_register_index(UFT_CPU_RISCV64, UFT_RISCV64_REG_FA1), 1);
	TEST_EQ(arch_register_index(UFT_CPU_RISCV64, UFT_RISCV64_REG_FA2), 2);
	TEST_EQ(arch_register_index(UFT_CPU_RISCV64, UFT_RISCV64_REG_FA3), 3);
	TEST_EQ(arch_register_index(UFT_CPU_RISCV64, UFT_RISCV64_REG_FA4), 4);
	TEST_EQ(arch_register_index(UFT_CPU_RISCV64, UFT_RISCV64_REG_FA5), 5);
	TEST_EQ(arch_register_index(UFT_CPU_RISCV64, UFT_RISCV64_REG_FA6), 6);
	TEST_EQ(arch_register_index(UFT_CPU_RISCV64, UFT_RISCV64_REG_FA7), 7);

	TEST_STREQ(arch_register_argspec_name(UFT_CPU_RISCV64, false, 0), "FA0");
	TEST_STREQ(arch_register_argspec_name(UFT_CPU_RISCV64, false, 1), "FA1");
	TEST_STREQ(arch_register_argspec_name(UFT_CPU_RISCV64, false, 2), "FA2");
	TEST_STREQ(arch_register_argspec_name(UFT_CPU_RISCV64, false, 3), "FA3");
	TEST_STREQ(arch_register_argspec_name(UFT_CPU_RISCV64, false, 4), "FA4");
	TEST_STREQ(arch_register_argspec_name(UFT_CPU_RISCV64, false, 5), "FA5");
	TEST_STREQ(arch_register_argspec_name(UFT_CPU_RISCV64, false, 6), "FA6");
	TEST_STREQ(arch_register_argspec_name(UFT_CPU_RISCV64, false, 7), "FA7");
	TEST_EQ(arch_register_argspec_name(UFT_CPU_RISCV64, false, 8), NULL);

	return TEST_OK;
}

#ifdef HAVE_LIBDW
TEST_CASE(registers_dwarf)
{
	pr_dbg("check invalid architecture\n");
	TEST_STREQ(arch_register_dwarf_name(UFT_CPU_NONE, 0), "invalid register");

	pr_dbg("check x86_64 registers\n");
	TEST_STREQ(arch_register_dwarf_name(UFT_CPU_X86_64, DW_OP_reg1), "rdx");
	TEST_STREQ(arch_register_dwarf_name(UFT_CPU_X86_64, DW_OP_reg2), "rcx");
	TEST_STREQ(arch_register_dwarf_name(UFT_CPU_X86_64, DW_OP_reg4), "rsi");
	TEST_STREQ(arch_register_dwarf_name(UFT_CPU_X86_64, DW_OP_reg5), "rdi");
	TEST_STREQ(arch_register_dwarf_name(UFT_CPU_X86_64, DW_OP_reg8), "r8");
	TEST_STREQ(arch_register_dwarf_name(UFT_CPU_X86_64, DW_OP_reg9), "r9");

	pr_dbg("check aarch64 registers\n");
	TEST_STREQ(arch_register_dwarf_name(UFT_CPU_AARCH64, DW_OP_reg0), "x0");
	TEST_STREQ(arch_register_dwarf_name(UFT_CPU_AARCH64, DW_OP_reg1), "x1");
	TEST_STREQ(arch_register_dwarf_name(UFT_CPU_AARCH64, DW_OP_reg2), "x2");
	TEST_STREQ(arch_register_dwarf_name(UFT_CPU_AARCH64, DW_OP_reg3), "x3");
	TEST_STREQ(arch_register_dwarf_name(UFT_CPU_AARCH64, DW_OP_reg4), "x4");
	TEST_STREQ(arch_register_dwarf_name(UFT_CPU_AARCH64, DW_OP_reg5), "x5");
	TEST_STREQ(arch_register_dwarf_name(UFT_CPU_AARCH64, DW_OP_reg6), "x6");
	TEST_STREQ(arch_register_dwarf_name(UFT_CPU_AARCH64, DW_OP_reg7), "x7");

	/* No i386 registers? */

	pr_dbg("check arm registers\n");
	TEST_STREQ(arch_register_dwarf_name(UFT_CPU_ARM, DW_OP_reg0), "r0");
	TEST_STREQ(arch_register_dwarf_name(UFT_CPU_ARM, DW_OP_reg1), "r1");
	TEST_STREQ(arch_register_dwarf_name(UFT_CPU_ARM, DW_OP_reg2), "r2");
	TEST_STREQ(arch_register_dwarf_name(UFT_CPU_ARM, DW_OP_reg3), "r3");

	pr_dbg("check riscv64 registers\n");
	TEST_STREQ(arch_register_dwarf_name(UFT_CPU_RISCV64, DW_OP_reg10), "a0");
	TEST_STREQ(arch_register_dwarf_name(UFT_CPU_RISCV64, DW_OP_reg11), "a1");
	TEST_STREQ(arch_register_dwarf_name(UFT_CPU_RISCV64, DW_OP_reg12), "a2");
	TEST_STREQ(arch_register_dwarf_name(UFT_CPU_RISCV64, DW_OP_reg13), "a3");
	TEST_STREQ(arch_register_dwarf_name(UFT_CPU_RISCV64, DW_OP_reg14), "a4");
	TEST_STREQ(arch_register_dwarf_name(UFT_CPU_RISCV64, DW_OP_reg15), "a5");
	TEST_STREQ(arch_register_dwarf_name(UFT_CPU_RISCV64, DW_OP_reg16), "a6");
	TEST_STREQ(arch_register_dwarf_name(UFT_CPU_RISCV64, DW_OP_reg17), "a7");

	return TEST_OK;
}
#endif /* HAVE_LIBDW */

#endif /* UNIT_TEST */
