#ifdef HAVE_LIBELF

#include <fcntl.h>
#include <gelf.h>
#include <unistd.h>

/* This should be defined before #include "utils.h" */
#define PR_FMT "symbol"
#define PR_DOMAIN DBG_SYMBOL

#include "utils/dwarf.h"
#include "utils/symbol-libelf.h"
#include "utils/utils.h"

int elf_init(const char *filename, struct uftrace_elf_data *elf)
{
	/* it will be set only in elf_retry() */
	elf->dwfl = NULL;

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

#ifdef HAVE_LIBDW
	if (elf->dwfl) {
		/* it'll close ELF handle and FD */
		dwfl_end(elf->dwfl);
		return;
	}
#endif

	elf_end(elf->handle);
	elf->handle = NULL;

	close(elf->fd);
	elf->fd = -1;
}

/* return 1 if it wants to retry with libdwfl, 0 otherwise */
int elf_retry(const char *filename, struct uftrace_elf_data *elf)
{
#ifdef HAVE_LIBDW
	Dwfl *dwfl;
	Dwfl_Module *mod;
	Dwarf_Addr bias;
	Dwarf *dw;

	/* it already tried (and failed), no retry */
	if (elf->dwfl)
		return 0;

	dwfl = dwfl_begin(&dwfl_callbacks);
	if (dwfl == NULL) {
		pr_dbg("dwfl_begin() failed\n");
		return 0;
	}

	mod = dwfl_report_offline(dwfl, filename, filename, elf->fd);
	if (mod == NULL) {
		pr_dbg("cannot report file: %s\n", dwfl_errmsg(dwfl_errno()));
		goto out;
	}

	dw = dwfl_module_getdwarf(mod, &bias);
	if (dw == NULL) {
		pr_dbg("cannot find debug file: %s\n", dwfl_errmsg(dwfl_errno()));
		goto out;
	}

	/* invalidate the existing ELF */
	elf_end(elf->handle);

	/* update the ELF handle from the (separate) debug file */
	elf->handle = dwarf_getelf(dw);

	if (elf->handle) {
		elf->dwfl = dwfl;
		return 1;
	}

out:
	dwfl_end(dwfl);
#endif
	return 0;
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
