#include "mcount-arch.h"
#include "utils/utils.h"

struct arm_reg_table {
	const char	*name;
	int		idx;
};

static const struct arm_reg_table reg_table[] = {
#define ARM_REG(_r)  { #_r, ARM_REG_##_r }

	/* integer registers */
	ARM_REG(R0), ARM_REG(R1), ARM_REG(R2), ARM_REG(R3),
	/* floating-point registers */
	ARM_REG(S0),  ARM_REG(S1),  ARM_REG(S2),  ARM_REG(S3),
	ARM_REG(S4),  ARM_REG(S5),  ARM_REG(S6),  ARM_REG(S7),
	ARM_REG(S8),  ARM_REG(S9),  ARM_REG(S10), ARM_REG(S11),
	ARM_REG(S12), ARM_REG(S13), ARM_REG(S14), ARM_REG(S15),
	ARM_REG(D0),  ARM_REG(D1),  ARM_REG(D2),  ARM_REG(D3),
	ARM_REG(D4),  ARM_REG(D5),  ARM_REG(D6),  ARM_REG(D7),

#undef ARM_REG
};

int arch_register_index(char *reg_name)
{
	unsigned i;

	for (i = 0; i < ARRAY_SIZE(reg_table); i++) {
		if (!strcasecmp(reg_name, reg_table[i].name))
			return reg_table[i].idx;
	}
	return -1;
}

#ifdef HAVE_LIBDW

#include <dwarf.h>

#define ARM_REG_VFPv3_BASE  256
static const struct x86_reg_table dwarf_table[] = {
	/* support registers used for arguments */
	{ "r0", DW_OP_reg0, },
	{ "r1", DW_OP_reg1, },
	{ "r2", DW_OP_reg2, },
	{ "r3", DW_OP_reg3, },
	{ "d0", ARM_REG_VFPv3_BASE + 0, },
	{ "d1", ARM_REG_VFPv3_BASE + 1, },
	{ "d2", ARM_REG_VFPv3_BASE + 2, },
	{ "d3", ARM_REG_VFPv3_BASE + 3, },
	{ "d4", ARM_REG_VFPv3_BASE + 4, },
	{ "d5", ARM_REG_VFPv3_BASE + 5, },
	{ "d6", ARM_REG_VFPv3_BASE + 6, },
	{ "d7", ARM_REG_VFPv3_BASE + 7, },
};

const char * arch_register_dwarf_name(int dwarf_reg)
{
	unsigned i;

	for (i = 0; i < ARRAY_SIZE(dwarf_table); i++) {
		if (dwarf_reg == dwarf_table[i].idx)
			return dwarf_table[i].name;
	}
	return "invalid register";
}

#endif /* HAVE_LIBDW */
