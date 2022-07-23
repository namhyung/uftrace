#ifndef HAVE_LIBELF

#include <fcntl.h>
#include <stdio.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

/* This should be defined before #include "utils.h" */
#define PR_FMT "symbol"
#define PR_DOMAIN DBG_SYMBOL

#include "utils/symbol-rawelf.h"
#include "utils/utils.h"

/*
 *  ELF File Header validation logic.
 */
int elf_validate(struct uftrace_elf_data *elf)
{
	Elf_Ehdr *ehdr;
	int eclass, data, version;
	unsigned long size, offset;

	ehdr = &elf->ehdr;
	elf->has_shdr = false;

	// validate ELF Magic.
	if (memcmp(ehdr, ELFMAG, SELFMAG)) {
		pr_dbg2("ELF Signature not matched\n");
		return -1;
	}

	// validate some field of elf header.
	eclass = (int)ehdr->e_ident[EI_CLASS];
	data = (int)ehdr->e_ident[EI_DATA];
	version = (int)ehdr->e_ident[EI_VERSION];

	if (eclass != get_elf_class()) {
		pr_dbg2("Unsupported eclass : [%d]\n", eclass);
		return -1;
	}

	if (data != get_elf_endian()) {
		pr_dbg2("Unsupported endian : [%d]\n", data);
		return -1;
	}

	if (!(version > EV_NONE && version < EV_NUM)) {
		pr_dbg2("Invalid ELF version : [%d]\n", version);
		return -1;
	}

	if (ehdr->e_phnum == 0 || ehdr->e_phentsize == 0) {
		pr_dbg2("Invalid Program header. Num:[%d] Size:[%d]\n", ehdr->e_phnum,
			ehdr->e_phentsize);
		return -1;
	}

	if (ehdr->e_shnum > 0 && ehdr->e_shentsize == 0) {
		pr_dbg2("Section Header entry size cannot be 0.\n");
		return -1;
	}

	// validate program header offset.
	size = (long)elf->file_size;
	offset = ehdr->e_phoff + ehdr->e_phnum * ehdr->e_phentsize;

	if (offset > size) {
		pr_dbg2("Invalid Program Header offset:[%lu], size:[%lu]\n", offset, size);
		return -1;
	}

	// section header is optional.
	offset = ehdr->e_shoff + ehdr->e_shnum * ehdr->e_shentsize;

	if (offset <= size)
		elf->has_shdr = true;

	return 0;
}

int elf_init(const char *filename, struct uftrace_elf_data *elf)
{
	struct stat stbuf;

	elf->fd = open(filename, O_RDONLY);
	if (elf->fd < 0)
		goto err;

	if (fstat(elf->fd, &stbuf) < 0)
		goto err_close;

	elf->file_size = stbuf.st_size;

	elf->file_map = mmap(NULL, elf->file_size, PROT_READ, MAP_PRIVATE, elf->fd, 0);
	if (elf->file_map == MAP_FAILED)
		goto err_close;

	memcpy(&elf->ehdr, elf->file_map, sizeof(elf->ehdr));

	if (elf_validate(elf) < 0)
		goto err_unmap;

	return 0;

err_unmap:
	munmap(elf->file_map, elf->file_size);

err_close:
	close(elf->fd);
	elf->fd = -1;

err:
	elf->file_map = NULL;
	return -1;
}

void elf_finish(struct uftrace_elf_data *elf)
{
	if (elf->fd < 0)
		return;

	munmap(elf->file_map, elf->file_size);
	elf->file_map = NULL;

	close(elf->fd);
	elf->fd = -1;
}

void elf_get_strtab(struct uftrace_elf_data *elf, struct uftrace_elf_iter *iter, int shidx)
{
	if (elf->has_shdr) {
		Elf_Shdr *shdr = elf->file_map + elf->ehdr.e_shoff;
		iter->strtab = elf->file_map + shdr[shidx].sh_offset;
	}
}

void elf_get_secdata(struct uftrace_elf_data *elf, struct uftrace_elf_iter *iter)
{
	iter->ent_size = iter->shdr.sh_entsize;
	iter->data = elf->file_map + iter->shdr.sh_offset;
}

void elf_read_secdata(struct uftrace_elf_data *elf, struct uftrace_elf_iter *iter, unsigned offset,
		      void *buf, size_t len)
{
	memcpy(buf, &iter->data[offset], len);
}

#ifdef UNIT_TEST

TEST_CASE(rawelf_validate)
{
	struct uftrace_elf_data elf;
	struct uftrace_elf_iter iter;
	Elf_Ehdr *ehdr;
	unsigned int count;

	/* elf_init() calls elf_validate() internally */
	if (elf_init("/proc/self/exe", &elf) < 0)
		return TEST_NG;

	ehdr = &elf.ehdr;

	count = 0;
	elf_for_each_phdr(&elf, &iter)
		count++;
	TEST_EQ(ehdr->e_phnum, count);

	count = 0;
	elf_for_each_shdr(&elf, &iter)
		count++;
	TEST_EQ(ehdr->e_shnum, count);

	elf_finish(&elf);
	return TEST_OK;
}

#endif /* UNIT_TEST */

#endif /* HAVE_LIBELF */
