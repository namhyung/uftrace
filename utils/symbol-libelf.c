#ifdef HAVE_LIBELF

#include <gelf.h>
#include <fcntl.h>
#include <unistd.h>

/* This should be defined before #include "utils.h" */
#define PR_FMT     "symbol"
#define PR_DOMAIN  DBG_SYMBOL

#include "utils/utils.h"
#include "utils/symbol-libelf.h"

int elf_init(const char *filename, struct uftrace_elf_data *elf)
{
	elf->fd = open(filename, O_RDONLY);
	if (elf->fd < 0) {
		pr_dbg("error during open symbol file: %s: %m\n", filename);
		return -1;
	}

	elf_version(EV_CURRENT);

	elf->handle = elf_begin(elf->fd, ELF_C_READ_MMAP, NULL);
	if (elf->handle == NULL) {
		pr_dbg("ELF error during symbol loading: %s\n",
		       elf_errmsg(elf_errno()));
		return -1;
	}

	if (gelf_getehdr(elf->handle, &elf->ehdr) == NULL) {
		pr_dbg("ELF error during symbol loading: %s\n",
		       elf_errmsg(elf_errno()));
		return -1;
	}

	return 0;
}

void elf_finish(struct uftrace_elf_data *elf)
{
	elf_end(elf->handle);
	elf->handle = NULL;

	close(elf->fd);
	elf->fd = -1;
}

void elf_get_secdata(struct uftrace_elf_data *elf,
		     struct uftrace_elf_iter *iter)
{
	iter->data = elf_getdata((iter)->scn, NULL);
}

void elf_read_secdata(struct uftrace_elf_data *elf,
		      struct uftrace_elf_iter *iter,
		      unsigned offset, void *buf, size_t len)
{
	memcpy(buf, iter->data->d_buf + offset, len);
}

#endif  /* HAVE_LIBELF */
