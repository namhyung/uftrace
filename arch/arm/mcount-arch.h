#ifndef MCOUNT_ARCH_H
#define MCOUNT_ARCH_H

#define mcount_regs mcount_regs

struct mcount_regs {
	unsigned long r0;
	unsigned long r1;
	unsigned long r2;
	unsigned long r3;
};

#define ARG1(a) ((a)->r0)
#define ARG2(a) ((a)->r1)
#define ARG3(a) ((a)->r2)
#define ARG4(a) ((a)->r3)

#define ARCH_MAX_REG_ARGS 4
#define ARCH_MAX_FLOAT_REGS 16
#define ARCH_MAX_DOUBLE_REGS 8

struct mcount_arch_context {};

struct uftrace_sym_info;

#define FIX_PARENT_LOC
unsigned long *mcount_arch_parent_location(struct uftrace_sym_info *symtabs,
					   unsigned long *parent_loc, unsigned long child_ip);

#define ARCH_PLT0_SIZE 20
#define ARCH_PLTHOOK_ADDR_OFFSET 0

/* index of module-ID in the PLTGOT table */
#define ARCH_PLTGOT_MOD_ID 1
/* index of resolver address in the PLTGOT table */
#define ARCH_PLTGOT_RESOLVE 2
/* number of reserved entries in the PLTGOT table */
#define ARCH_PLTGOT_OFFSET 3

#define NOP_INSN_SIZE 4

struct mcount_disasm_engine;
struct mcount_dynamic_info;
struct mcount_disasm_info;

int disasm_check_insns(struct mcount_disasm_engine *disasm,
		       struct mcount_dynamic_info *mdi,
		       struct mcount_disasm_info *info);

#endif /* MCOUNT_ARCH_H */
