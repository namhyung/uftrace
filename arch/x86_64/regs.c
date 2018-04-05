#include "mcount-arch.h"
#include "utils/utils.h"

struct x86_reg_table {
	const char	*name;
	int		idx;
};

static const struct x86_reg_table reg_table[] = {
#define X86_REG(_r)  { #_r, X86_REG_##_r }

	/* integer registers */
	X86_REG(RDI), X86_REG(RSI), X86_REG(RDX),
	X86_REG(RCX), X86_REG(R8),  X86_REG(R9),
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

#ifdef HAVE_LIBDW

#include <dwarf.h>

static const struct x86_reg_table dwarf_table[] = {
	/* support registers used for arguments */
	{ "rdx",  DW_OP_reg1,  },
	{ "rcx",  DW_OP_reg2,  },
	{ "rsi",  DW_OP_reg4,  },
	{ "rdi",  DW_OP_reg5,  },
	{ "r8",   DW_OP_reg8,  },
	{ "r9",   DW_OP_reg9,  },
	{ "xmm0", DW_OP_reg17, },
	{ "xmm1", DW_OP_reg18, },
	{ "xmm2", DW_OP_reg19, },
	{ "xmm3", DW_OP_reg20, },
	{ "xmm4", DW_OP_reg21, },
	{ "xmm5", DW_OP_reg22, },
	{ "xmm6", DW_OP_reg23, },
	{ "xmm7", DW_OP_reg24, },
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
