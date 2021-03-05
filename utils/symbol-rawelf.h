#ifndef UFTRACE_SYMBOL_RAWELF_H
#define UFTRACE_SYMBOL_RAWELF_H

#include <elf.h>

#ifdef __LP64__
# define ELF_SIZE  64
#else
# define ELF_SIZE  32
#endif

/* re-define Elf64_Addr as Elf_Addr */
#define ElfT(name)       ElfT1(ELF_SIZE, name)
#define ElfT1(N, name)   ElfType(N, name)
#define ElfType(N, name) Elf ## N ## _ ## name

typedef ElfT(Ehdr)  Elf_Ehdr;
typedef ElfT(Phdr)  Elf_Phdr;
typedef ElfT(Shdr)  Elf_Shdr;
typedef ElfT(Nhdr)  Elf_Nhdr;

typedef ElfT(Sym)   Elf_Sym;
typedef ElfT(Dyn)   Elf_Dyn;
typedef ElfT(Rel)   Elf_Rel;
typedef ElfT(Rela)  Elf_Rela;

/* re-define ELF32_ST_TYPE() as ELF_ST_TYPE() */
#define ELF_M(ACT)         ELF_M1(ELF_SIZE, ACT)
#define ELF_M1(N, ACT)     ELF_MACRO(N, ACT)
#define ELF_MACRO(N, ACT)  ELF ## N ## _ ## ACT

#define ELF_ST_BIND(v)  ELF_M(ST_BIND) (v)
#define ELF_ST_TYPE(v)  ELF_M(ST_TYPE) (v)
#define ELF_R_SYM(i)    ELF_M(R_SYM) (i)
#define ELF_R_TYPE(i)   ELF_M(R_TYPE) (i)


struct uftrace_elf_data {
	int 		fd;
	void		*file_map;
	size_t		file_size;
	Elf_Ehdr	ehdr;
	unsigned long	flags;
	bool		has_shdr;
};

struct uftrace_elf_iter {
	size_t i;
	size_t nr;

	union {
		Elf_Phdr phdr;
		Elf_Shdr shdr;
		Elf_Nhdr nhdr;
		Elf_Sym  sym;
		Elf_Dyn  dyn;
		Elf_Rel  rel;
		Elf_Rela rela;
	};

	void	*note_name;
	void	*note_desc;

	/* hidden */
	int      type;
	int      ent_size;
	char     *strtab;
	char     *data;
};

#define elf_get_name(elf, iter, name)					\
		(char *)(iter)->strtab + name

#define elf_get_symbol(elf, iter, idx)					\
		memcpy(&(iter)->sym,					\
		       &(iter)->data[idx * (iter)->ent_size],		\
		       (iter)->ent_size)

#define elf_symbol_type(sym)  ELF_ST_TYPE((sym)->st_info)
#define elf_symbol_bind(sym)  ELF_ST_BIND((sym)->st_info)
#define elf_rel_symbol(rel)   ELF_R_SYM((rel)->r_info)
#define elf_rel_type(rel)     ELF_R_TYPE((rel)->r_info)


#define elf_for_each_phdr(elf, iter)					\
	for ((iter)->i = 0, (iter)->nr = (elf)->ehdr.e_phnum;		\
	     (iter)->i < (iter)->nr &&					\
		     memcpy(&(iter)->phdr,				\
			    (elf)->file_map + (elf)->ehdr.e_phoff +	\
			    (iter)->i * (elf)->ehdr.e_phentsize,	\
			    (elf)->ehdr.e_phentsize);			\
	     (iter)->i++)

#define elf_for_each_shdr(elf, iter)					\
	for (elf_get_strtab((elf), (iter), (elf)->ehdr.e_shstrndx),	\
		     (iter)->i = 0, (iter)->nr = (elf)->ehdr.e_shnum;	\
	     (iter)->i < (iter)->nr && (elf)->has_shdr &&		\
		     memcpy(&(iter)->shdr,				\
			    (elf)->file_map + (elf)->ehdr.e_shoff +	\
			    (iter)->i * (elf)->ehdr.e_shentsize,	\
			    (elf)->ehdr.e_shentsize);			\
	     (iter)->i++)

/* iter->shdr must point DYNAMIC section */
#define elf_for_each_dynamic(elf, iter)					\
	for (elf_get_secdata((elf), (iter)),				\
		     elf_get_strtab((elf), (iter), (iter)->shdr.sh_link), \
		     (iter)->type = (iter)->shdr.sh_type,		\
		     (iter)->ent_size = (iter)->shdr.sh_entsize,	\
		     (iter)->i = 0,					\
		     (iter)->nr = (iter)->shdr.sh_size / (iter)->ent_size; \
	     (iter)->type == SHT_DYNAMIC && (iter)->i < (iter)->nr &&	\
		     memcpy(&(iter)->dyn,				\
			    &(iter)->data[(iter)->i * (iter)->ent_size], \
			    (iter)->ent_size);				\
	     (iter)->i++)

/* iter->shdr must point SYMTAB section */
#define elf_for_each_symbol(elf, iter)					\
	for (elf_get_secdata((elf), (iter)),				\
		     elf_get_strtab((elf), (iter), (iter)->shdr.sh_link), \
		     (iter)->type = (iter)->shdr.sh_type,		\
		     (iter)->ent_size = (iter)->shdr.sh_entsize,	\
		     (iter)->i = 0,					\
		     (iter)->nr = (iter)->shdr.sh_size / (iter)->ent_size; \
	     (iter)->type == SHT_SYMTAB && (iter)->i < (iter)->nr &&	\
		     memcpy(&(iter)->sym,				\
			    &(iter)->data[(iter)->i * (iter)->ent_size], \
			    (iter)->ent_size);				\
	     (iter)->i++)

/* iter->shdr must point DYNSYM section */
#define elf_for_each_dynamic_symbol(elf, iter)				\
	for (elf_get_secdata((elf), (iter)),				\
		     elf_get_strtab((elf), (iter), (iter)->shdr.sh_link), \
		     (iter)->type = (iter)->shdr.sh_type,		\
		     (iter)->ent_size = (iter)->shdr.sh_entsize,	\
		     (iter)->i = 0,					\
		     (iter)->nr = (iter)->shdr.sh_size / (iter)->ent_size; \
	     (iter)->type == SHT_DYNSYM && (iter)->i < (iter)->nr &&	\
		     memcpy(&(iter)->sym,				\
			    &(iter)->data[(iter)->i * (iter)->ent_size], \
			    (iter)->ent_size);				\
	     (iter)->i++)

/* iter->shdr must point REL section */
#define elf_for_each_rel(elf, iter)					\
	for (elf_get_secdata((elf), (iter)),				\
		     (iter)->type = (iter)->shdr.sh_type,		\
		     (iter)->ent_size = (iter)->shdr.sh_entsize,	\
		     (iter)->i = 0,					\
		     (iter)->nr = (iter)->shdr.sh_size / (iter)->ent_size; \
	     (iter)->type == SHT_REL && (iter)->i < (iter)->nr &&	\
		     memcpy(&(iter)->rel,				\
			    &(iter)->data[(iter)->i * (iter)->ent_size], \
			    (iter)->ent_size);				\
	     (iter)->i++)

/* iter->shdr must point RELA section */
#define elf_for_each_rela(elf, iter)					\
	for (elf_get_secdata((elf), (iter)),				\
		     (iter)->type = (iter)->shdr.sh_type,		\
		     (iter)->ent_size = (iter)->shdr.sh_entsize,	\
		     (iter)->i = 0,					\
		     (iter)->nr = (iter)->shdr.sh_size / (iter)->ent_size; \
	     (iter)->type == SHT_RELA && (iter)->i < (iter)->nr &&	\
		     memcpy(&(iter)->rela,				\
			    &(iter)->data[(iter)->i * (iter)->ent_size], \
			    (iter)->ent_size);				\
	     (iter)->i++)

/* iter->shdr must point NOTE section */
#define elf_for_each_note(elf, iter)					\
	for (elf_get_secdata((elf), (iter)),				\
		     (iter)->type = (iter)->shdr.sh_type,		\
		     (iter)->ent_size = (iter)->shdr.sh_entsize,	\
		     (iter)->i = 0,					\
		     (iter)->nr = (iter)->shdr.sh_size;			\
	     (iter)->type == SHT_NOTE &&				\
		     (iter)->i < (iter)->nr - sizeof((iter)->nhdr) &&	\
		     memcpy(&(iter)->nhdr, (iter)->data + (iter)->i,	\
			    sizeof((iter)->nhdr)) &&			\
		     ((iter)->note_name = (iter)->data + (iter)->i +	\
					sizeof((iter)->nhdr)) &&	\
		     ((iter)->note_desc = (iter)->note_name +		\
					ALIGN((iter)->nhdr.n_namesz, 4)); \
	     (iter)->i += sizeof((iter)->nhdr) +			\
		     ALIGN((iter)->nhdr.n_namesz, 4) +			\
		     ALIGN((iter)->nhdr.n_descsz, 4))


int elf_init(const char *filename, struct uftrace_elf_data *elf);
void elf_finish(struct uftrace_elf_data *elf);

void elf_get_strtab(struct uftrace_elf_data *elf,
		    struct uftrace_elf_iter *iter, int shidx);
void elf_get_secdata(struct uftrace_elf_data *elf,
		     struct uftrace_elf_iter *iter);
void elf_read_secdata(struct uftrace_elf_data *elf,
		      struct uftrace_elf_iter *iter,
		      unsigned offset, void *buf, size_t len);

#endif  /* UFTRACE_SYMBOL_LIBELF_H */
