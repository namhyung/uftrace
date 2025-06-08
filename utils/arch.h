/*
 * Architecture specific code and data
 */
#ifndef UFTRACE_ARCH_H
#define UFTRACE_ARCH_H

#include <stdbool.h>

struct mcount_dynamic_info;
struct mcount_disasm_engine;
struct mcount_disasm_info;
struct mcount_event_info;
struct mcount_orig_insn;
struct plthook_data;
struct uftrace_elf_data;
struct uftrace_symtab;
struct uftrace_symbol;

enum mcount_arch_ops_entry {
	UFT_ARCH_OPS_MCOUNT,
	UFT_ARCH_OPS_PLTHOOK,
	UFT_ARCH_OPS_FENTRY,
	UFT_ARCH_OPS_DYNAMIC,
	UFT_ARCH_OPS_XRAY,

	UFT_ARCH_OPS_NUM,
};

/* Arch-specific callback functions for libmcount. */
struct mcount_arch_ops {
	/*
	 * Save address of arch-specific assembly functions for tracing entry and exit paths.
	 * MCOUNT and PLTHOOK are required and others are optional.
	 */
	unsigned long entry[UFT_ARCH_OPS_NUM];
	unsigned long exit[UFT_ARCH_OPS_NUM];

	/*
	 * Functions to support non-standard PLT hooking.
	 */
	/* Prepare arch-specific PLT handling and save necessary info to pd->arch. */
	void (*plthook_setup)(struct plthook_data *pd, struct uftrace_elf_data *elf);
	/* Return the address of PLT function at the given index. */
	unsigned long (*plthook_addr)(struct plthook_data *pd, int idx);
	/* Adjust and return the index of PLT function. */
	unsigned long (*child_idx)(unsigned long idx);
	/* Setup an artificial PLT if the module doesn't have one, and return a new plthook_data. */
	struct plthook_data *(*hook_no_plt)(struct uftrace_elf_data *elf, const char *module,
					    unsigned long offset);

	/* Optional functions for event processing (e.g. SDT).  Returns 0 or negative error. */
	int (*enable_event)(struct mcount_event_info *mei);

	/*
	 * Functions to support dynamic tracing.  If 'disasm_init' is defined, it assumes others
	 * (except for the last two) are defined too.
	 */
	/* Initialize the (capstone) disassembly engine. */
	void (*disasm_init)(struct mcount_disasm_engine *disasm);
	/* Finalize the (capstone) disassembly engine. */
	void (*disasm_finish)(struct mcount_disasm_engine *disasm);
	/* Setup a trampoline to jump to the entry function. Return 0 or negative error. */
	int (*setup_trampoline)(struct mcount_dynamic_info *mdi);
	/* Cleanup the trampoline if it's setup. */
	void (*cleanup_trampoline)(struct mcount_dynamic_info *mdi);
	/* Update code in the function entry to jump to the trampoline. */
	int (*patch_func)(struct mcount_dynamic_info *mdi, struct uftrace_symbol *sym,
			  struct mcount_disasm_engine *disasm, unsigned min_size);
	/* Update code in the function entry not to jump to the entry. */
	int (*unpatch_func)(struct mcount_dynamic_info *mdi, struct uftrace_symbol *sym,
			    struct mcount_disasm_engine *disasm);
	/* Check binary (module) for the mdi and set mdi->type properly. */
	void (*find_module)(struct mcount_dynamic_info *mdi, struct uftrace_symtab *symtab);
	/* Restore original code in the mdi when something bad happen. */
	void (*dynamic_recover)(struct mcount_dynamic_info *mdi,
				struct mcount_disasm_engine *disasm);
	/* Optional function to calculate size of branch tables for the original code. */
	int (*branch_table_size)(struct mcount_disasm_info *info);
	/* Optional function to handle branch instructions in the original code. */
	void (*patch_branch)(struct mcount_disasm_info *, struct mcount_orig_insn *);
};

/* Arch-specific operations used by both uftrace and libmcount */
struct uftrace_arch_ops {
	/*
	 * Load dynamic symbols from ELF data when they are not in the PLT relocation table.
	 * It may reset the symbol table.  It should return the number of symbols loaded.
	 */
	int (*load_dynsymtab)(struct uftrace_symtab *symtab, struct uftrace_elf_data *elf,
			      unsigned long offset, unsigned long flags);
};

/* Each architecture should provide these. */
extern const struct mcount_arch_ops mcount_arch_ops;
extern const struct uftrace_arch_ops uftrace_arch_ops;

enum uftrace_cpu_arch {
	UFT_CPU_NONE,
	UFT_CPU_X86_64,
	UFT_CPU_ARM,
	UFT_CPU_AARCH64,
	UFT_CPU_I386,
	UFT_CPU_RISCV64,
};

static inline enum uftrace_cpu_arch host_cpu_arch(void)
{
#if defined(__x86_64__)
	return UFT_CPU_X86_64;
#elif defined(__arm__)
	return UFT_CPU_ARM;
#elif defined(__aarch64__)
	return UFT_CPU_AARCH64;
#elif defined(__i386__)
	return UFT_CPU_I386;
#elif defined(__riscv) && __riscv_xlen == 64
	return UFT_CPU_RISCV64;
#else
	return UFT_CPU_NONE;
#endif
}

static inline bool arch_is_lp64(enum uftrace_cpu_arch arch)
{
	switch (arch) {
	case UFT_CPU_X86_64:
	case UFT_CPU_AARCH64:
	case UFT_CPU_RISCV64:
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

enum uftrace_riscv64_reg_index {
	UFT_RISCV64_REG_INT_BASE = 0,
	/* integer argument registers */
	UFT_RISCV64_REG_A0,
	UFT_RISCV64_REG_A1,
	UFT_RISCV64_REG_A2,
	UFT_RISCV64_REG_A3,
	UFT_RISCV64_REG_A4,
	UFT_RISCV64_REG_A5,
	UFT_RISCV64_REG_A6,
	UFT_RISCV64_REG_A7,

	UFT_RISCV64_REG_FLOAT_BASE = 100,
	/* floating-point argument registers */
	UFT_RISCV64_REG_FA0,
	UFT_RISCV64_REG_FA1,
	UFT_RISCV64_REG_FA2,
	UFT_RISCV64_REG_FA3,
	UFT_RISCV64_REG_FA4,
	UFT_RISCV64_REG_FA5,
	UFT_RISCV64_REG_FA6,
	UFT_RISCV64_REG_FA7,
};

int arch_register_number(enum uftrace_cpu_arch arch, char *reg_name);
int arch_register_at(enum uftrace_cpu_arch arch, bool integer, int idx);
int arch_register_index(enum uftrace_cpu_arch arch, int idx);

const char *arch_register_dwarf_name(enum uftrace_cpu_arch arch, int dwarf_reg);
const char *arch_register_argspec_name(enum uftrace_cpu_arch arch, bool integer, int idx);

#endif /* UFTRACE_ARCH_H */
