#ifdef HAVE_LIBELF

#include <fcntl.h>
#include <gelf.h>
#include <unistd.h>

/* This should be defined before #include "utils.h" */
#define PR_FMT "symbol"
#define PR_DOMAIN DBG_SYMBOL

#include "utils/symbol-libelf.h"
#include "utils/utils.h"

int elf_init(const char *filename, struct uftrace_elf_data *elf)
{
	elf->fd = open(filename, O_RDONLY);
	if (elf->fd < 0) {
		pr_dbg("error during open ELF file: %s: %m\n", filename);
		goto err;
	}

	elf_version(EV_CURRENT);

	elf->handle = elf_begin(elf->fd, ELF_C_READ_MMAP, NULL);
	if (elf->handle == NULL)
		goto err_close;

	if (gelf_getehdr(elf->handle, &elf->ehdr) == NULL)
		goto err_end;

	return 0;

err_end:
	elf_end(elf->handle);

err_close:
	pr_dbg("ELF error when loading symbols: %s\n", elf_errmsg(elf_errno()));

	close(elf->fd);
	elf->fd = -1;

err:
	elf->handle = NULL;
	return -1;
}

void elf_finish(struct uftrace_elf_data *elf)
{
	if (elf->fd < 0)
		return;

	elf_end(elf->handle);
	elf->handle = NULL;

	close(elf->fd);
	elf->fd = -1;
}

void elf_get_secdata(struct uftrace_elf_data *elf, struct uftrace_elf_iter *iter)
{
	iter->data = elf_getdata((iter)->scn, NULL);
}

void elf_read_secdata(struct uftrace_elf_data *elf, struct uftrace_elf_iter *iter, unsigned offset,
		      void *buf, size_t len)
{
	memcpy(buf, iter->data->d_buf + offset, len);
}

#endif /* HAVE_LIBELF */
