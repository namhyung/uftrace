#include "mcount-arch.h"
#include "utils/utils.h"

struct x86_reg_table {
	const char		*name;
	enum x86_reg_index	idx;
} reg_table[] = {

#define X86_REG(_r)  { #_r, X86_REG_##_r }

	/* integer registers */
	X86_REG(ECX), X86_REG(EDX),
	/* floating-point registers */
	X86_REG(XMM0), X86_REG(XMM1), X86_REG(XMM2), X86_REG(XMM3),
	X86_REG(XMM4), X86_REG(XMM5), X86_REG(XMM6), X86_REG(XMM7),

#undef X86_REG
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
