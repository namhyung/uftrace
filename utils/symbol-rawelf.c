#ifndef HAVE_LIBELF

#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/mman.h>

/* This should be defined before #include "utils.h" */
#define PR_FMT     "symbol"
#define PR_DOMAIN  DBG_SYMBOL

#include "utils/utils.h"
#include "utils/symbol-rawelf.h"

int elf_init(const char *filename, struct uftrace_elf_data *elf)
{
	struct stat stbuf;

	elf->fd = open(filename, O_RDONLY);
	if (elf->fd < 0)
		return -1;

	if (fstat(elf->fd, &stbuf) < 0)
		goto err;

	elf->file_size = stbuf.st_size;

	elf->file_map = mmap(NULL, elf->file_size, PROT_READ, MAP_PRIVATE,
			     elf->fd, 0);
	if (elf->file_map == MAP_FAILED)
		goto err;

	memcpy(&elf->ehdr, elf->file_map, sizeof(elf->ehdr));

	return 0;

err:
	close(elf->fd);
	elf->fd = -1;

	elf->file_map = NULL;
	return -1;
}

void elf_finish(struct uftrace_elf_data *elf)
{
	munmap(elf->file_map, elf->file_size);
	elf->file_map = NULL;

	close(elf->fd);
	elf->fd = -1;
}

void elf_get_strtab(struct uftrace_elf_data *elf,
		    struct uftrace_elf_iter *iter,
		    int shidx)
{
	Elf_Shdr *shdr = elf->file_map + elf->ehdr.e_shoff;

	iter->strtab = elf->file_map + shdr[shidx].sh_offset;
}

void elf_get_secdata(struct uftrace_elf_data *elf,
		     struct uftrace_elf_iter *iter)
{
	iter->ent_size = iter->shdr.sh_entsize;
	iter->data = elf->file_map + iter->shdr.sh_offset;
}

void elf_read_secdata(struct uftrace_elf_data *elf,
		      struct uftrace_elf_iter *iter,
		      unsigned offset, void *buf, size_t len)
{
	memcpy(buf, &iter->data[offset], len);
}

#endif  /* HAVE_LIBELF */
