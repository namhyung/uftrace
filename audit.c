#include <link.h>
#include <stdio.h>
#include <string.h>

uintptr_t main_cookie;

unsigned la_version(unsigned version)
{
	return version; /* LAV_CURRENT */
}

unsigned la_objopen(struct link_map *map, Lmid_t lmid, uintptr_t *cookie)
{
	if (strlen(map->l_name) == 0) {
		main_cookie = *cookie;
		return LA_FLG_BINDFROM;
	}
	return LA_FLG_BINDTO;
}

unsigned la_objclose(uintptr_t *cookie)
{
	return 0;
}

void la_preinit(uintptr_t *cookie)
{
	/* initialization */
}

uintptr_t la_symbind64(Elf64_Sym *sym, unsigned idx,
		       uintptr_t *refcook, uintptr_t *defcook,
		       unsigned *flags, const char *symname)
{
	if (*refcook != main_cookie)
		printf("%s: different cookie\n", __func__);
	//printf("%s: %s (flags: %u)\n", __func__, symname, *flags);
	/* cache (defcook + idx) ==> sym->st_value */
	return sym->st_value;
}

uintptr_t la_x86_64_gnu_pltenter(Elf64_Sym *sym, unsigned idx,
				 uintptr_t *refcook, uintptr_t *defcook,
				 La_x86_64_regs *regs, unsigned *flags,
				 const char *symname, long *framesizep)
{
//	printf("%s: %s\n", __func__, symname);
	return sym->st_value;
}

unsigned la_x86_64_gnu_pltexit(Elf64_Sym *sym, unsigned idx,
			       uintptr_t *refcook, uintptr_t *defcook,
			       const La_x86_64_regs *inregs, La_x86_64_retval *ret,
			       const char *symname)
{
	printf("%s: %s\n", __func__, symname);
	return 0;
}
