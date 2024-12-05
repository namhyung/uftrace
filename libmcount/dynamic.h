#ifndef UFTRACE_MCOUNT_DYNAMIC_H
#define UFTRACE_MCOUNT_DYNAMIC_H

#include <link.h>
#include <stdlib.h>

#ifdef HAVE_LIBCAPSTONE
#include <capstone/capstone.h>
#endif

#include "utils/symbol.h"

#ifndef PAGE_SIZE
#define PAGE_SIZE 4096
#endif

#define PAGE_ADDR(a) ((void *)((a) & ~(PAGE_SIZE - 1)))
#define PAGE_LEN(a, l) (a + l - (unsigned long)PAGE_ADDR(a))

#define XRAY_SECT "xray_instr_map"
#define MCOUNTLOC_SECT "__mcount_loc"
#define PATCHABLE_SECT "__patchable_function_entries"

/* target instrumentation function it needs to call */
extern void __fentry__(void);
extern void __dentry__(void);
extern void __xray_entry(void);
extern void __xray_exit(void);

struct xray_instr_map {
	uint64_t address;
	uint64_t function;
	uint8_t kind;
	uint8_t always_instrument;
	uint8_t version;
	uint8_t padding[13];
};

enum mcount_dynamic_type {
	DYNAMIC_NONE,
	DYNAMIC_PG,
	DYNAMIC_FENTRY,
	DYNAMIC_FENTRY_NOP,
	DYNAMIC_XRAY,
	DYNAMIC_PATCHABLE,
};

__maybe_unused static const char *mdi_type_names[] = {
	"none", "pg", "fentry", "fentry-nop", "xray", "fpatchable",
};

struct mcount_dynamic_info {
	struct mcount_dynamic_info *next;
	struct uftrace_mmap *map;
	unsigned long base_addr;
	unsigned long text_addr;
	int text_size;
	unsigned long trampoline;
	struct list_head bad_syms;
	enum mcount_dynamic_type type;
	void *patch_target;
	unsigned nr_patch_target;
};

struct mcount_disasm_engine {
#ifdef HAVE_LIBCAPSTONE
	csh engine;
#endif
};

#define INSTRUMENT_SUCCESS 0
#define INSTRUMENT_FAILED -1
#define INSTRUMENT_SKIPPED -2

/*
 * Supposing the size of smallest conditional branch is 2 byte.
 * We can replace, at most, 3 of them by the instrumentation
 * instruction.
 */
#define MAX_COND_BRANCH 3

int mcount_dynamic_update(struct uftrace_sym_info *sinfo, char *patch_funcs,
			  enum uftrace_pattern_type ptype);
void mcount_dynamic_dlopen(struct uftrace_sym_info *sinfo, struct dl_phdr_info *info, char *path,
			   struct uftrace_mmap *map);
void mcount_dynamic_finish(void);

struct mcount_orig_insn {
	struct rb_node node;
	unsigned long addr;
	void *orig;
	void *insn;
	int orig_size;
	int insn_size;
};

struct cond_branch_info {
	/* where the insn starts in the out-of-line exec buffer*/
	unsigned long insn_index;
	/* the original target address of the branch */
	unsigned long branch_target;
	unsigned long insn_addr;
	unsigned long insn_size;
};

/*
 * mcount_disasm_info - information for dynamic patch
 * @sym : symbol for the function
 * @addr : currently targeted function address.
 * @insns : byte array to store instruction.
 * @orig_size : size of original instructions
 * @copy_size : size of copied instructions (may be modified)
 * @modified : whether instruction is changed
 * @has_jump : whether jump_target should be added
 */
struct mcount_disasm_info {
	struct uftrace_symbol *sym;
	unsigned long addr;
	unsigned char insns[64];
	int orig_size;
	int copy_size;
	bool modified;
	bool has_jump;
	bool has_intel_cet;
	uint8_t nr_branch;
	struct cond_branch_info branch_info[MAX_COND_BRANCH];
};

void mcount_save_code(struct mcount_disasm_info *info, unsigned call_size, void *jmp_insn,
		      unsigned jmp_size);
void *mcount_find_code(unsigned long addr);
struct mcount_orig_insn *mcount_find_insn(unsigned long addr);
void mcount_freeze_code(void);

/* these should be implemented for each architecture */
int mcount_setup_trampoline(struct mcount_dynamic_info *adi);
void mcount_cleanup_trampoline(struct mcount_dynamic_info *mdi);

int mcount_patch_func(struct mcount_dynamic_info *mdi, struct uftrace_symbol *sym,
		      struct mcount_disasm_engine *disasm, unsigned min_size);

void mcount_disasm_init(struct mcount_disasm_engine *disasm);
void mcount_disasm_finish(struct mcount_disasm_engine *disasm);

int mcount_arch_branch_table_size(struct mcount_disasm_info *info);
void mcount_arch_patch_branch(struct mcount_disasm_info *info, struct mcount_orig_insn *orig);

struct dynamic_bad_symbol {
	struct list_head list;
	struct uftrace_symbol *sym;
	bool reverted;
};

struct dynamic_bad_symbol *mcount_find_badsym(struct mcount_dynamic_info *mdi, unsigned long addr);
bool mcount_add_badsym(struct mcount_dynamic_info *mdi, unsigned long callsite,
		       unsigned long target);
void mcount_free_badsym(struct mcount_dynamic_info *mdi);

#endif /* UFTRACE_MCOUNT_DYNAMIC_H */
