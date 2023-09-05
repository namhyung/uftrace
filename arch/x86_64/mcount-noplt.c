#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>

/* This should be defined before #include "utils.h" */
#define PR_FMT "mcount"
#define PR_DOMAIN DBG_MCOUNT

#include "libmcount/internal.h"
#include "libmcount/mcount.h"
#include "uftrace.h"
#include "utils/symbol.h"
#include "utils/utils.h"

#define TRAMP_ENT_SIZE 16 /* size of trampoilne for each entry */
#define TRAMP_PLT0_SIZE 32 /* module id + address of plthook_addr() */
#define TRAMP_PCREL_JMP 10 /* PC_relative offset for JMP */
#define TRAMP_IDX_OFFSET 1
#define TRAMP_JMP_OFFSET 6

extern void __weak plt_hooker(void);
struct plthook_data *mcount_arch_hook_no_plt(struct uftrace_elf_data *elf, const char *modname,
					     unsigned long offset)
{
	struct plthook_data *pd;
	void *trampoline;
	size_t tramp_len;
	uint32_t i;
	/* clang-format off */
	const uint8_t tramp_plt0[] = {  /* followed by module_id + plthook_addr */
		/* PUSH module_id */
		0xff, 0x35, 0xa, 0, 0, 0,
		/* JMP plthook_addr */
		0xff, 0x25, 0xc, 0, 0, 0,
		0xcc, 0xcc, 0xcc, 0xcc,
	};
	const uint8_t tramp_insns[] = {  /* make stack what plt_hooker expect */
		/* PUSH child_idx */
		0x68, 0, 0, 0, 0,
		/* JMP plt0 */
		0xe9, 0, 0, 0, 0,
		/* should never reach here */
		0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc,
	};
	/* clang-format on */
	void *plthook_addr = plt_hooker;
	void *tramp;

	pd = xzalloc(sizeof(*pd));
	pd->module_id = (unsigned long)pd;
	pd->base_addr = offset;

	if (arch_load_dynsymtab_noplt(&pd->dsymtab, elf, offset, 0) < 0 ||
	    pd->dsymtab.nr_sym == 0) {
		free(pd);
		return NULL;
	}

	tramp_len = TRAMP_PLT0_SIZE + pd->dsymtab.nr_sym * TRAMP_ENT_SIZE;
	trampoline =
		mmap(NULL, tramp_len, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (trampoline == MAP_FAILED) {
		pr_dbg("mmap failed: %m: ignore libcall hooking\n");
		free(pd);
		return NULL;
	}

	pd->pltgot_ptr = trampoline;
	pd->resolved_addr = xcalloc(pd->dsymtab.nr_sym, sizeof(long));

	/* add trampoline - save orig addr and replace GOT */
	pr_dbg2("module: %s (id: %lx), addr = %lx, TRAMPOLINE = %p\n", pd->mod_name, pd->module_id,
		pd->base_addr, pd->pltgot_ptr);

	/* setup PLT0 */
	memcpy(trampoline, tramp_plt0, sizeof(tramp_plt0));
	tramp = trampoline + sizeof(tramp_plt0);
	memcpy(tramp, &pd->module_id, sizeof(pd->module_id));
	tramp += sizeof(long);
	memcpy(tramp, &plthook_addr, sizeof(plthook_addr));
	tramp += sizeof(long);

	for (i = 0; i < pd->dsymtab.nr_sym; i++) {
		uint32_t pcrel;
		Elf64_Rela *rela;
		struct uftrace_symbol *sym;
		unsigned k;
		bool skip = false;

		sym = &pd->dsymtab.sym[i];

		for (k = 0; k < plt_skip_nr; k++) {
			if (!strcmp(sym->name, plt_skip_syms[k].name)) {
				skip = true;
				break;
			}
		}
		if (skip)
			continue;

		/* copy trampoline instructions */
		memcpy(tramp, tramp_insns, TRAMP_ENT_SIZE);

		/* update offset (child id) */
		memcpy(tramp + TRAMP_IDX_OFFSET, &i, sizeof(i));

		/* update jump offset */
		pcrel = trampoline - (tramp + TRAMP_PCREL_JMP);
		memcpy(tramp + TRAMP_JMP_OFFSET, &pcrel, sizeof(pcrel));

		rela = (void *)sym->addr;
		/* save resolved address in GOT */
		memcpy(&pd->resolved_addr[i], (void *)rela->r_offset + offset, sizeof(long));
		/* update GOT to point the trampoline */
		memcpy((void *)rela->r_offset + offset, &tramp, sizeof(long));

		tramp += TRAMP_ENT_SIZE;
	}

	mprotect(trampoline, tramp_len, PROT_READ | PROT_EXEC);

	pd->mod_name = xstrdup(modname);

	return pd;
}
