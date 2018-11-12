#ifndef UFTRACE_SYMBOL_LIBELF_H
#define UFTRACE_SYMBOL_LIBELF_H

#include <gelf.h>

struct uftrace_elf_data {
	int 		fd;
	Elf		*handle;
	GElf_Ehdr	ehdr;
};

struct uftrace_elf_iter {
	size_t i;
	size_t nr;

	union {
		GElf_Phdr phdr;
		GElf_Shdr shdr;
		GElf_Nhdr nhdr;
		GElf_Sym  sym;
		GElf_Dyn  dyn;
		GElf_Rel  rel;
		GElf_Rela rela;
	};

	void *note_name;
	void *note_desc;

	/* hidden */
	int      type;
	size_t   str_idx;
	Elf_Scn  *scn;
	Elf_Data *data;
};

#define elf_get_name(elf, iter, name)				\
		elf_strptr((elf)->handle, (iter)->str_idx, name)

#define elf_get_symbol(elf, iter, idx)				\
		gelf_getsym((iter)->data, idx, &(iter)->sym)

#define elf_get_strtab(elf, iter, idx)				\
		(iter)->str_idx = idx

#define elf_symbol_type(sym)  GELF_ST_TYPE((sym)->st_info)
#define elf_symbol_bind(sym)  GELF_ST_BIND((sym)->st_info)
#define elf_rel_symbol(rel)   GELF_R_SYM((rel)->r_info)
#define elf_rel_type(rel)     GELF_R_TYPE((rel)->r_info)

#define elf_for_each_phdr(elf, iter)					\
	for ((iter)->i = 0, (iter)->nr = (elf)->ehdr.e_phnum;		\
	     (iter)->i < (iter)->nr &&					\
		     gelf_getphdr((elf)->handle, (iter)->i, &(iter)->phdr); \
	     (iter)->i++)

#define elf_for_each_shdr(elf, iter)					\
	for (elf_getshdrstrndx((elf)->handle, &(iter)->str_idx), 	\
		     (iter)->scn = elf_nextscn((elf)->handle, NULL);	\
	     (iter)->scn && gelf_getshdr((iter)->scn, &(iter)->shdr);	\
	     (iter)->scn = elf_nextscn((elf)->handle, (iter)->scn))

/* iter->scn and iter->shdr must point DYNAMIC section */
#define elf_for_each_dynamic(elf, iter)					\
	for ((iter)->i = 0, (iter)->nr = (iter)->shdr.sh_size / (iter)->shdr.sh_entsize, \
		     (iter)->str_idx = (iter)->shdr.sh_link,		\
		     (iter)->type = (iter)->shdr.sh_type,		\
		     (iter)->data = elf_getdata((iter)->scn, NULL);	\
	     (iter)->type == SHT_DYNAMIC && (iter)->i < (iter)->nr &&	\
		     gelf_getdyn((iter)->data, (iter)->i, &(iter)->dyn); \
	     (iter)->i++)

/* iter->scn and iter->shdr must point SYMTAB section */
#define elf_for_each_symbol(elf, iter)					\
	for ((iter)->i = 0, (iter)->nr = (iter)->shdr.sh_size / (iter)->shdr.sh_entsize, \
		     (iter)->str_idx = (iter)->shdr.sh_link,		\
		     (iter)->type = (iter)->shdr.sh_type,		\
		     (iter)->data = elf_getdata((iter)->scn, NULL);	\
	     (iter)->type == SHT_SYMTAB && (iter)->i < (iter)->nr &&	\
		     gelf_getsym((iter)->data, (iter)->i, &(iter)->sym); \
	     (iter)->i++)

/* iter->sec and iter->shdr must point DYNSYM section */
#define elf_for_each_dynamic_symbol(elf, iter)				\
	for ((iter)->i = 0, (iter)->nr = (iter)->shdr.sh_size / (iter)->shdr.sh_entsize, \
		     (iter)->str_idx = (iter)->shdr.sh_link,		\
		     (iter)->type = (iter)->shdr.sh_type,		\
		     (iter)->data = elf_getdata((iter)->scn, NULL);	\
	     (iter)->type == SHT_DYNSYM && (iter)->i < (iter)->nr &&	\
		     gelf_getsym((iter)->data, (iter)->i, &(iter)->sym); \
	     (iter)->i++)

/* iter->sec and iter->shdr must point REL section */
#define elf_for_each_rel(elf, iter)					\
	for ((iter)->i = 0, (iter)->nr = (iter)->shdr.sh_size / (iter)->shdr.sh_entsize, \
		     (iter)->type = (iter)->shdr.sh_type,		\
		     (iter)->data = elf_getdata((iter)->scn, NULL);	\
	     (iter)->type == SHT_REL && (iter)->i < (iter)->nr &&	\
		     gelf_getrel((iter)->data, (iter)->i, &(iter)->rel); \
	     (iter)->i++)

/* iter->sec and iter->shdr must point RELA section */
#define elf_for_each_rela(elf, iter)					\
	for ((iter)->i = 0, (iter)->nr = (iter)->shdr.sh_size / (iter)->shdr.sh_entsize, \
		     (iter)->type = (iter)->shdr.sh_type,		\
		     (iter)->data = elf_getdata((iter)->scn, NULL);	\
	     (iter)->type == SHT_RELA && (iter)->i < (iter)->nr &&	\
		     gelf_getrela((iter)->data, (iter)->i, &(iter)->rela); \
	     (iter)->i++)

/* iter->sec and iter->shdr must point NOTE section */
#define elf_for_each_note(elf, iter)					\
	for ((iter)->i = 0, (iter)->type = (iter)->shdr.sh_type,	\
		     (iter)->data = elf_getdata((iter)->scn, NULL);	\
	     (iter)->type == SHT_NOTE &&				\
		     ((iter)->nr = gelf_getnote((iter)->data, (iter)->i, \
					       &(iter)->nhdr,		\
					       (size_t*)&(iter)->note_name, \
						(size_t*)&(iter)->note_desc)) && \
		     ((iter)->note_name = (iter)->data->d_buf + (size_t)(iter)->note_name) && \
		     ((iter)->note_desc = (iter)->data->d_buf + (size_t)(iter)->note_desc); \
	     (iter)->i = (iter)->nr)

int elf_init(const char *filename, struct uftrace_elf_data *elf);
void elf_finish(struct uftrace_elf_data *elf);

void elf_get_secdata(struct uftrace_elf_data *elf,
		     struct uftrace_elf_iter *iter);
void elf_read_secdata(struct uftrace_elf_data *elf,
		      struct uftrace_elf_iter *iter,
		      unsigned offset, void *buf, size_t len);

#endif  /* UFTRACE_SYMBOL_LIBELF_H */
