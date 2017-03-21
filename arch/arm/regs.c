#include "mcount-arch.h"
#include "utils/utils.h"

struct arm_reg_table {
	const char		*name;
	enum arm_reg_index	idx;
} reg_table[] = {

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
