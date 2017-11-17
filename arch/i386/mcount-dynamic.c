#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

/* This should be defined before #include "utils.h" */
#define PR_FMT     "dynamic"
#define PR_DOMAIN  DBG_DYNAMIC

#include "libmcount/internal.h"
#include "utils/utils.h"
#include "utils/symbol.h"

#define PAGE_SIZE  4096
#define XRAY_SECT  "xray_instr_map"

/* target instrumentation function it needs to call */
extern void __fentry__(void);

struct xray_instr_map {
	unsigned long addr;
	unsigned long entry;
	unsigned long type;
	unsigned long count;
};

struct arch_dynamic_info {
	struct xray_instr_map *xrmap;
	unsigned xrmap_count;
};

int mcount_setup_trampoline(struct mcount_dynamic_info *mdi)
{
	/*
	 * in i386, it is not possible to refer to eip.
	 * so need a little trick. 
	 * 
	 * call 0x5
	 * pop eax
	 * jmp dword ptr [eax + 4]
	 * 
	 */
	unsigned char trampoline[] = { 0xe8, 0x00, 0x00, 0x00, 0x00, 0x58, 0xff, 0x60, 0x04 };
	unsigned long fentry_addr = (unsigned long)__fentry__;
	struct arch_dynamic_info *adi = mdi->arch;
	size_t trampoline_size = 16;

	if (adi && adi->xrmap_count)
		trampoline_size *= 2;

	/* find unused 16-byte at the end of the code segment */
	mdi->trampoline = ALIGN(mdi->addr + mdi->size, PAGE_SIZE) - trampoline_size;

	if (unlikely(mdi->trampoline < mdi->addr + mdi->size)) {
		mdi->trampoline += trampoline_size;
		mdi->size += PAGE_SIZE;

		pr_dbg2("adding a page for fentry trampoline at %#lx\n",
			mdi->trampoline);

		mmap((void *)mdi->trampoline, PAGE_SIZE, PROT_READ | PROT_WRITE,
		     MAP_FIXED | MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	}

	if (mprotect((void *)mdi->addr, mdi->size, PROT_READ | PROT_WRITE)) {
		pr_dbg("cannot setup trampoline due to protection: %m\n");
		return -1;
	}

	/* jmpq  *0x2(%rip)     # <fentry_addr> */
	memcpy((void *)mdi->trampoline, trampoline, sizeof(trampoline));
	memcpy((void *)mdi->trampoline + sizeof(trampoline),
	       &fentry_addr, sizeof(fentry_addr));
	return 0;
}

void mcount_cleanup_trampoline(struct mcount_dynamic_info *mdi)
{
	if (mprotect((void *)mdi->addr, mdi->size, PROT_EXEC))
		pr_err("cannot restore trampoline due to protection");
}

void mcount_arch_find_module(struct mcount_dynamic_info *mdi)
{
	Elf32_Ehdr ehdr;
	Elf32_Shdr shdr;
	char *mod_name = mdi->mod_name;
	char *names = NULL;
	int fd;
	unsigned i;
	off_t pos;

	mdi->arch = NULL;

	if (*mod_name == '\0')
		mod_name = read_exename();

	fd = open(mod_name, O_RDONLY);
	if (fd < 0)
		pr_err("cannot open %s", mod_name);

	if (read_all(fd, &ehdr, sizeof(ehdr)) < 0)
		goto out;
	if (memcmp(ehdr.e_ident, ELFMAG, SELFMAG))
		goto out;

	/* read section header name */
	if (pread_all(fd, &shdr, sizeof(shdr),
		      ehdr.e_shoff + (ehdr.e_shstrndx * ehdr.e_shentsize)) < 0)
		goto out;

	names = xmalloc(shdr.sh_size);
	if (pread_all(fd, names, shdr.sh_size, shdr.sh_offset) < 0)
		goto out;

	pos = ehdr.e_shoff;
	for (i = 0; i < ehdr.e_shnum; i++, pos += ehdr.e_shentsize) {
		struct arch_dynamic_info *adi;

		if (pread_all(fd, &shdr, sizeof(shdr), pos) < 0)
			goto out;

		if (strcmp(&names[shdr.sh_name], XRAY_SECT))
			continue;

		adi = xmalloc(sizeof(*adi));
		adi->xrmap_count = shdr.sh_size / sizeof(*adi->xrmap);
		adi->xrmap = xmalloc(adi->xrmap_count * sizeof(*adi->xrmap));

		if (pread_all(fd, adi->xrmap, shdr.sh_size, shdr.sh_offset) < 0) {
			free(adi);
			goto out;
		}

		/* handle position independent code */
		if (ehdr.e_type == ET_DYN) {
			struct xray_instr_map *xrmap;

			for (i = 0; i < adi->xrmap_count; i++) {
				xrmap = &adi->xrmap[i];

				xrmap->addr  += mdi->addr;
				xrmap->entry += mdi->addr;
			}
		}

		mdi->arch = adi;
		break;
	}

out:
	close(fd);
	free(names);
}

#define CALL_INSN_SIZE 5

static unsigned long get_target_addr(struct mcount_dynamic_info *mdi, unsigned long addr)
{
	while (mdi) {
		if (mdi->addr <= addr && addr < mdi->addr + mdi->size)
			return mdi->trampoline - (addr + CALL_INSN_SIZE);

		mdi = mdi->next;
	}
	return 0;
}

static int patch_fentry_func(struct mcount_dynamic_info *mdi, struct sym *sym)
{
	// In case of "gcc" which is not patched because of old version, 
	// it may not create 5 byte nop.
	unsigned char nop[] = { 0x0f, 0x1f, 0x44, 0x00, 0x00 };
	unsigned char *insn = (void *)sym->addr;
	unsigned int target_addr;

	/* only support calls to __fentry__ at the beginning */
	if (memcmp(insn, nop, sizeof(nop))) {
		pr_dbg2("skip non-applicable functions: %s\n", sym->name);
		return -2;
	}

	/* get the jump offset to the trampoline */
	target_addr = get_target_addr(mdi, sym->addr);
	if (target_addr == 0)
		return -2;

	/* make a "call" insn with 4-byte offset */
	insn[0] = 0xe8;
	/* hopefully we're not patching 'memcpy' itself */
	memcpy(&insn[1], &target_addr, sizeof(target_addr));

	pr_dbg3("update function '%s' dynamically to call __fentry__\n",
		sym->name);

	return 0;
}

int mcount_patch_func(struct mcount_dynamic_info *mdi, struct sym *sym)
{
	return patch_fentry_func(mdi, sym);
}

