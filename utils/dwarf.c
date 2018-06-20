#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

/* This should be defined before #include "utils.h" */
#define PR_FMT     "dwarf"
#define PR_DOMAIN  DBG_DWARF

#include "uftrace.h"
#include "utils/utils.h"
#include "utils/dwarf.h"
#include "utils/symbol.h"
#include "utils/filter.h"

bool debug_info_available(struct debug_info *dinfo)
{
	if (dinfo == NULL)
		return false;

	/* dinfo has some debug entries? */
	return !RB_EMPTY_ROOT(&dinfo->args) || !RB_EMPTY_ROOT(&dinfo->rets);
}

struct debug_entry {
	struct rb_node	node;
	uint64_t	offset;
	char		*name;
	char		*spec;
};

static int add_debug_entry(struct rb_root *root, char *func, uint64_t offset,
			   char *argspec)
{
	struct debug_entry *entry, *iter;
	struct rb_node *parent = NULL;
	struct rb_node **p = &root->rb_node;

	entry = xmalloc(sizeof(*entry));
	entry->name = xstrdup(func);

	entry->spec = xstrdup(argspec);
	entry->offset = offset;

	pr_dbg3("debug entry: %x %s%s\n", entry->offset, entry->name, entry->spec);

	while (*p) {
		parent = *p;
		iter = rb_entry(parent, struct debug_entry, node);

		if (iter->offset > entry->offset)
			p = &parent->rb_left;
		else
			p = &parent->rb_right;
	}

	rb_link_node(&entry->node, parent, p);
	rb_insert_color(&entry->node, root);

	return 0;
}

static struct debug_entry * find_debug_entry(struct rb_root *root, uint64_t offset)
{
	struct debug_entry *iter;
	struct rb_node *parent = NULL;
	struct rb_node **p = &root->rb_node;
	int ret;

	while (*p) {
		parent = *p;
		iter = rb_entry(parent, struct debug_entry, node);

		ret = iter->offset - offset;
		if (ret == 0) {
			pr_dbg3("found debug entry at %x (%s%s)\n",
				offset, iter->name, iter->spec);
			return iter;
		}

		if (ret > 0)
			p = &parent->rb_left;
		else
			p = &parent->rb_right;
	}

	return NULL;
}

static void free_debug_entry(struct rb_root *root)
{
	struct debug_entry *entry;
	struct rb_node *node;

	while (!RB_EMPTY_ROOT(root)) {
		node = rb_first(root);
		entry = rb_entry(node, typeof(*entry), node);

		rb_erase(node, root);
		free(entry->name);
		free(entry->spec);
		free(entry);
	}
}

#ifdef HAVE_LIBDW

#include <libelf.h>
#include <gelf.h>
#include <dwarf.h>

static int elf_file_type(struct debug_info *dinfo)
{
	GElf_Ehdr ehdr;

	if (dinfo->dw && gelf_getehdr(dwarf_getelf(dinfo->dw), &ehdr))
		return ehdr.e_type;

	return ET_NONE;
}

/* setup dwarf info from filename, return 0 for success */
static int setup_dwarf_info(const char *filename, struct debug_info *dinfo,
			    unsigned long offset)
{
	int fd;

	if (!check_trace_functions(filename))
		return 0;

	pr_dbg2("setup dwarf debug info for %s\n", filename);

	fd = open(filename, O_RDONLY);
	if (fd < 0) {
		pr_dbg2("cannot open debug info for %s: %m\n", filename);
		return -1;
	}

	dinfo->dw = dwarf_begin(fd, DWARF_C_READ);
	close(fd);

	if (dinfo->dw == NULL) {
		pr_dbg2("failed to setup debug info: %s\n",
			dwarf_errmsg(dwarf_errno()));
		return -1;
	}

	/*
	 * symbol address was adjusted to add offset already
	 * but it needs to use address in file (for shared libraries).
	 */
	if (elf_file_type(dinfo) == ET_DYN)
		dinfo->offset = offset;
	else
		dinfo->offset = 0;

	return 0;
}

static void release_dwarf_info(struct debug_info *dinfo)
{
	if (dinfo->dw == NULL)
		return;

	dwarf_end(dinfo->dw);
	dinfo->dw = NULL;
}

struct type_data {
	enum uftrace_arg_format		fmt;
	size_t				size;
	int				pointer;
	bool				ignore;
	char 				*enum_name;
	struct debug_info		*dinfo;
};

static char * fill_enum_str(Dwarf_Die *die)
{
	char *str = NULL;
	Dwarf_Die e_val;

	if (dwarf_child(die, &e_val) != 0) {
		pr_dbg2("no enum values\n");
		return NULL;
	}

	while (dwarf_tag(&e_val) == DW_TAG_enumerator) {
		char buf[256];
		Dwarf_Attribute attr_val;
		Dwarf_Sword val;

		dwarf_attr(&e_val, DW_AT_const_value, &attr_val);
		dwarf_formsdata(&attr_val, &val);
		snprintf(buf, sizeof(buf), "%s=%ld", dwarf_diename(&e_val), (long)val);

		str = strjoin(str, buf, ",");

		if (dwarf_siblingof(&e_val, &e_val) != 0)
			break;
	}

	return str;
}

static char * make_enum_name(Dwarf_Die *die)
{
	Dwarf_Die cudie;
	const char *cu_name = NULL;
	unsigned long off;
	char *enum_name;
	char *tmp;

	if (dwarf_diecu (die, &cudie, NULL, NULL))
		cu_name = dwarf_diename(&cudie);

	if (cu_name == NULL)
		cu_name = "unnamed";

	off = dwarf_cuoffset(die);

	xasprintf(&enum_name, "%s_%lx", basename(cu_name), off);

	/* replace forbidden characters */
	tmp = enum_name;
	while ((tmp = strpbrk(tmp, "+-.() ")) != NULL)
		*tmp++ = '_';

	return enum_name;
}

/* returns size in bit */
static size_t type_size(Dwarf_Die *die)
{
	Dwarf_Attribute size_type;
	Dwarf_Word size_val;

	/* just guess it's word size */
	if (!dwarf_hasattr(die, DW_AT_byte_size))
		return sizeof(long) * 8;

	dwarf_attr(die, DW_AT_byte_size, &size_type);
	dwarf_formudata(&size_type, &size_val);

	return size_val * 8;
}

static bool is_empty_aggregate(Dwarf_Die *die)
{
	Dwarf_Die child;
	Dwarf_Die parent;
	bool inherited = false;

	/* C++ defines size of an empty struct as 1 byte */
	if (type_size(die) > 8)
		return false;

retry:
	if (dwarf_child(die, &child) != 0)
		return true;  /* no child = no member */

	do {
		Dwarf_Attribute type;

		switch (dwarf_tag(&child)) {
		case DW_TAG_member:
			return false;

		case DW_TAG_subprogram:
			/* probably a lambda function */
			return false;

		case DW_TAG_inheritance:
			dwarf_attr(&child, DW_AT_type, &type);
			dwarf_formref_die(&type, &parent);
			inherited = true;
			break;

		default:
			break;
		}
	}
	while (dwarf_siblingof(&child, &child) == 0);

	if (inherited) {
		inherited = false;
		die = &parent;
		goto retry;
	}

	return true;
}

static bool resolve_type_info(Dwarf_Die *die, struct type_data *td)
{
	Dwarf_Die ref;
	Dwarf_Attribute type;
	unsigned aform;
	const char *tname;
	char *enum_def;
	char *enum_str;

	/*
	 * type refers to another type in a chain like:
	 *   (pointer) -> (const) -> (char)
	 */
	while (dwarf_hasattr(die, DW_AT_type)) {
		dwarf_attr(die, DW_AT_type, &type);
		aform = dwarf_whatform(&type);

		switch (aform) {
		case DW_FORM_ref1:
		case DW_FORM_ref2:
		case DW_FORM_ref4:
		case DW_FORM_ref8:
		case DW_FORM_ref_udata:
		case DW_FORM_ref_addr:
		case DW_FORM_ref_sig8:
		case DW_FORM_GNU_ref_alt:
			dwarf_formref_die(&type, &ref);
			die = &ref;
			break;
		default:
			pr_dbg2("unhandled type form: %u\n", aform);
			return false;
		}

		switch (dwarf_tag(die)) {
		case DW_TAG_enumeration_type:
			enum_str = fill_enum_str(die);
			if (enum_str == NULL)
				return false;  /* use default format */

			td->fmt = ARG_FMT_ENUM;
			tname = dwarf_diename(die);
			if (tname)
				td->enum_name = xstrdup(tname);
			else
				td->enum_name = make_enum_name(die);

			xasprintf(&enum_def, "enum %s { %s }",
				  td->enum_name, enum_str);
			pr_dbg3("type: %s\n", enum_str);

			parse_enum_string(enum_def, &td->dinfo->enums);
			free(enum_def);
			free(enum_str);
			return true;

		case DW_TAG_structure_type:
		case DW_TAG_union_type:
		case DW_TAG_class_type:
			pr_dbg3("type: struct/union/class\n");
			/* ignore struct with no member (when called-by-value) */
			if (!td->pointer && is_empty_aggregate(die))
				td->ignore = true;
			return false;

		case DW_TAG_pointer_type:
		case DW_TAG_ptr_to_member_type:
		case DW_TAG_reference_type:
		case DW_TAG_rvalue_reference_type:
			td->pointer++;
			pr_dbg3("type: pointer/reference\n");
			break;
		case DW_TAG_array_type:
			pr_dbg3("type: array\n");
			break;
		case DW_TAG_const_type:
			pr_dbg3("type: const\n");
			break;
		case DW_TAG_subroutine_type:
			if (td->pointer == 1) {
				td->fmt = ARG_FMT_FUNC_PTR;
				pr_dbg3("type: function pointer\n");
				/* prevent to look up (return) type more */
				return true;
			}
			break;
		default:
			pr_dbg3("type: %s (tag %d)\n",
				dwarf_diename(die), dwarf_tag(die));
			break;
		}
	}

	tname = dwarf_diename(die);

	if (td->pointer) {
		td->size = sizeof(long) * 8;

		/* treat 'char *' as string */
		if (td->pointer == 1 && tname && !strcmp(tname, "char")) {
			td->fmt = ARG_FMT_STR;
			return true;
		}
		return false;
	}

	td->size = type_size(die);

	if (dwarf_tag(die) != DW_TAG_base_type)
		return false;

	if (!strcmp(tname, "char"))
		td->fmt = ARG_FMT_CHAR;
	else if (!strcmp(tname, "float"))
		td->fmt = ARG_FMT_FLOAT;
	else if (!strcmp(tname, "double"))
		td->fmt = ARG_FMT_FLOAT;

	return true;
}

struct arg_data {
	const char		*name;
	unsigned long		addr;
	char			*argspec;
	int			idx;
	int			fpidx;
	struct debug_info	*dinfo;
};

static bool add_type_info(char *spec, size_t len, Dwarf_Die *die,
			  struct arg_data *ad)
{
	struct type_data data = {
		.fmt = ARG_FMT_AUTO,
		.dinfo = ad->dinfo,
	};
	Dwarf_Die origin;

	if (!dwarf_hasattr(die, DW_AT_type)) {
		Dwarf_Attribute attr;

		if (!dwarf_hasattr(die, DW_AT_abstract_origin))
			return false;

		dwarf_attr(die, DW_AT_abstract_origin, &attr);
		dwarf_formref_die(&attr, &origin);
		die = &origin;
	}

	if (!resolve_type_info(die, &data))
		return !data.ignore;

	switch (data.fmt) {
	case ARG_FMT_CHAR:
		strcat(spec, "/c");
		break;
	case ARG_FMT_STR:
		strcat(spec, "/s");
		break;
	case ARG_FMT_FLOAT:
		if (ad->idx) {  /* for arguments */
			snprintf(spec, len, "fparg%d/%zu",
				 ++ad->fpidx, data.size);
			/* do not increase index of integer arguments */
			--ad->idx;
		}
		else {  /* for return values */
			char sz[4];

			snprintf(sz, sizeof(sz), "%zu", data.size);
			strcat(spec, "/f");
			strcat(spec, sz);
		}
		break;
	case ARG_FMT_FUNC_PTR:
		strcat(spec, "/p");
		break;
	case ARG_FMT_ENUM:
		strcat(spec, "/e:");
		strcat(spec, data.enum_name);
		break;
	default:
		break;
	}

	return true;
}

struct location_data {
	int		type;
	int		reg;    // DWARF register number
	int		offset; // stack offset
};

static bool get_arg_location(Dwarf_Die *die, struct location_data *ld)
{
	Dwarf_Attribute loc;
	Dwarf_Op *ops = NULL;
	size_t len = 0;

	if (!dwarf_hasattr(die, DW_AT_location))
		return false;

	dwarf_attr(die, DW_AT_location, &loc);

	if (dwarf_getlocation(&loc, &ops, &len) == -1) {
		Dwarf_Addr base, start, end;

		/* try to get the first entry in the location list */
		if (dwarf_getlocations(&loc, 0, &base, &start, &end,
				       &ops, &len) == -1)
			return false;
	}

	while (len--) {
		switch (ops->atom) {
		case DW_OP_fbreg:
			/*
			 * ignore minus offsets since it doesn't set the
			 * frame-pointer yet (we're before the prologue).
			 */
			if ((int)ops->number > 0) {
				ld->type = ARG_TYPE_STACK;
				ld->offset = DIV_ROUND_UP(ops->number,
							  sizeof(long)) + 1;
				pr_dbg3("location: stack (%d)\n", ld->offset);
			}
			break;

		case DW_OP_reg0...DW_OP_reg31:
			ld->type = ARG_TYPE_REG;
			ld->reg = ops->atom;
			pr_dbg3("location: reg (%d)\n", ld->reg);
			break;

		case DW_OP_regx:
			ld->type = ARG_TYPE_REG;
			ld->reg = ops->number;
			pr_dbg3("location: reg (%d)\n", ld->reg);
			break;
		}
	}

	return true;
}

__weak const char * arch_register_dwarf_name(int dwarf_reg)
{
	return "invalid register";
}

static void add_location(char *spec, size_t len, Dwarf_Die *die,
			 struct arg_data *ad)
{
	struct location_data data = {
		.type = ARG_TYPE_INDEX,
	};
	char buf[32];
	const char *reg;

	if (!get_arg_location(die, &data))
		return;

	switch (data.type) {
	case ARG_TYPE_REG:
		reg = arch_register_dwarf_name(data.reg);

		if (strcmp(reg, "invalid register")) {
			snprintf(buf, sizeof(buf), "%%%s", reg);
			strcat(spec, buf);
		}
		break;
	case ARG_TYPE_STACK:
		snprintf(buf, sizeof(buf), "%%stack+%d", data.offset);
		strcat(spec, buf);
		break;
	default:
		break;
	}
}

static int get_argspec(Dwarf_Die *die, void *data)
{
	struct arg_data *ad = data;
	Dwarf_Die arg;
	Dwarf_Addr offset = 0;
	int count = 0;

	dwarf_lowpc(die, &offset);
	pr_dbg2("found '%s' function for argspec (%#lx)\n", ad->name, offset);

	if (dwarf_child(die, &arg) != 0) {
		pr_dbg2("has no argument (children)\n");
		return 0;
	}

	do {
		char buf[256];

		if (dwarf_tag(&arg) != DW_TAG_formal_parameter)
			continue;

		snprintf(buf, sizeof(buf), "arg%d", ++ad->idx);
		if (!add_type_info(buf, sizeof(buf), &arg, ad)) {
			/* ignore this argument */
			ad->idx--;
			continue;
		}
		add_location(buf, sizeof(buf), &arg, ad);

		if (ad->argspec == NULL)
			xasprintf(&ad->argspec, "@%s", buf);
		else
			ad->argspec = strjoin(ad->argspec, buf, ",");

		count++;
	}
	while (dwarf_siblingof(&arg, &arg) == 0);

	return count;
}

static int get_retspec(Dwarf_Die *die, void *data)
{
	struct arg_data *ad = data;
	char buf[256];
	Dwarf_Die spec;

	pr_dbg2("found '%s' function for retspec\n", ad->name);

	/* for C++ programs */
	if (!dwarf_hasattr(die, DW_AT_type)) {
		Dwarf_Attribute attr;

		if (!dwarf_hasattr(die, DW_AT_specification))
			return 0;

		dwarf_attr(die, DW_AT_specification, &attr);
		dwarf_formref_die(&attr, &spec);
		die = &spec;

		if (!dwarf_hasattr(die, DW_AT_type))
			return 0;
	}

	snprintf(buf, sizeof(buf), "@retval");
	add_type_info(buf, sizeof(buf), die, ad);
	ad->argspec = xstrdup(buf);

	return 1;
}

struct build_data {
	struct debug_info	*dinfo;
	struct symtab		*symtab;
	int			nr_args;
	int			nr_rets;
	struct uftrace_pattern	*args;
	struct uftrace_pattern	*rets;
};

static int get_dwarfspecs_cb(Dwarf_Die *die, void *data)
{
	struct build_data *bd = data;
	struct arg_data ad = {
		.argspec = NULL,
		.dinfo = bd->dinfo,
	};
	Dwarf_Attribute attr;
	char *name = NULL;
	bool needs_free = false;
	Dwarf_Addr offset;
	struct sym *sym;
	int i;

	if (uftrace_done)
		return DWARF_CB_ABORT;

	if (dwarf_tag(die) != DW_TAG_subprogram)
		return DWARF_CB_OK;

	/* XXX: old libdw might call with decl DIE */
	if (dwarf_hasattr(die, DW_AT_declaration))
		return DWARF_CB_OK;

	/* XXX: this assumes symbol->addr is same as the lowpc */
	if (!dwarf_hasattr(die, DW_AT_low_pc))
		return DWARF_CB_OK;

	dwarf_lowpc(die, &offset);
	offset += bd->dinfo->offset;

	if (dwarf_attr_integrate(die, DW_AT_linkage_name, &attr)) {
		name = demangle((char *)dwarf_formstring(&attr));
		needs_free = true;
	}
	if (name == NULL)
		name = (char *)dwarf_diename(die);
	if (unlikely(name == NULL))
		return DWARF_CB_OK;

	/* double-check symbol table has same info */
	sym = find_sym(bd->symtab, offset);
	if (sym == NULL || strcmp(sym->name, name)) {
		pr_dbg2("skip unknown debug info: %s (%lx)\n",
			sym ? sym->name : "no name", offset);
		goto out;
	}

	ad.name = name;
	ad.addr = offset;

	for (i = 0; i < bd->nr_args; i++) {
		if (!match_filter_pattern(&bd->args[i], name))
			continue;

		if (get_argspec(die, &ad)) {
			add_debug_entry(&bd->dinfo->args, name, offset,
					ad.argspec);
		}

		free(ad.argspec);
		ad.argspec = NULL;
		break;
	}

	ad.idx = RETVAL_IDX;
	for (i = 0; i < bd->nr_rets; i++) {
		if (!match_filter_pattern(&bd->rets[i], name))
			continue;

		if (get_retspec(die, &ad)) {
			add_debug_entry(&bd->dinfo->rets, name, offset,
					ad.argspec);
		}

		free(ad.argspec);
		ad.argspec = NULL;
		break;
	}

out:
	if (needs_free)
		free(name);
	return DWARF_CB_OK;
}

static void build_dwarf_info(struct debug_info *dinfo, struct symtab *symtab,
			     enum uftrace_pattern_type ptype,
			     struct strv *args, struct strv *rets)
{
	Dwarf_Off curr = 0;
	Dwarf_Off next = 0;
	size_t header_sz = 0;
	struct uftrace_pattern *arg_patt;
	struct uftrace_pattern *ret_patt;
	char *s;
	int i;

	if (dinfo->dw == NULL)
		return;

	arg_patt = xcalloc(args->nr, sizeof(*arg_patt));
	strv_for_each(args, s, i)
		init_filter_pattern(ptype, &arg_patt[i], s);

	ret_patt = xcalloc(rets->nr, sizeof(*ret_patt));
	strv_for_each(rets, s, i)
		init_filter_pattern(ptype, &ret_patt[i], s);

	/* traverse every CU to find debug info */
	while (dwarf_nextcu(dinfo->dw, curr, &next,
			    &header_sz, NULL, NULL, NULL) == 0) {
		Dwarf_Die cudie;
		struct build_data bd = {
			.dinfo   = dinfo,
			.symtab  = symtab,
			.args    = arg_patt,
			.rets    = ret_patt,
			.nr_args = args->nr,
			.nr_rets = rets->nr,
		};

		if (dwarf_offdie(dinfo->dw, curr + header_sz, &cudie) == NULL)
			break;

		if (dwarf_tag(&cudie) != DW_TAG_compile_unit)
			break;

		if (uftrace_done)
			break;

		dwarf_getfuncs(&cudie, get_dwarfspecs_cb, &bd, 0);

		curr = next;
	}

	for (i = 0; i < args->nr; i++)
		free_filter_pattern(&arg_patt[i]);
	free(arg_patt);
	for (i = 0; i < rets->nr; i++)
		free_filter_pattern(&ret_patt[i]);
	free(ret_patt);
}

#else  /* !HAVE_LIBDW */

static int elf_file_type(struct debug_info *dinfo)
{
	return ET_NONE;
}

static int setup_dwarf_info(const char *filename, struct debug_info *dinfo,
			    unsigned long offset)
{
	dinfo->dw = NULL;
	return 0;
}

static void build_dwarf_info(struct debug_info *dinfo, struct symtab *symtab,
			     enum uftrace_pattern_type ptype,
			     struct strv *args, struct strv *rets)
{
}

static void release_dwarf_info(struct debug_info *dinfo)
{
}

#endif  /* !HAVE_LIBDW */

static int setup_debug_info(const char *filename, struct debug_info *dinfo,
			    unsigned long offset)
{
	dinfo->args = RB_ROOT;
	dinfo->rets = RB_ROOT;
	dinfo->enums = RB_ROOT;

	return setup_dwarf_info(filename, dinfo, offset);
}

static void release_debug_info(struct debug_info *dinfo)
{
	free_debug_entry(&dinfo->args);
	free_debug_entry(&dinfo->rets);
	release_enum_def(&dinfo->enums);

	release_dwarf_info(dinfo);
}

/* find argspecs only have function name (pattern) */
static void extract_dwarf_args(char *argspec, char *retspec,
			       struct strv *pargs, struct strv *prets)
{
	if (argspec) {
		struct strv tmp = STRV_INIT;
		char *arg;
		int i;

		strv_split(&tmp, argspec, ";");
		strv_for_each(&tmp, arg, i) {
			if (strchr(arg, '@'))
				continue;

			strv_append(pargs, arg);
		}
		strv_free(&tmp);
	}

	if (retspec) {
		struct strv tmp = STRV_INIT;
		char *ret;
		int i;

		strv_split(&tmp, retspec, ";");
		strv_for_each(&tmp, ret, i) {
			if (strchr(ret, '@'))
				continue;

			strv_append(prets, ret);
		}
		strv_free(&tmp);
	}
}

void prepare_debug_info(struct symtabs *symtabs,
			enum uftrace_pattern_type ptype,
			char *argspec, char *retspec)
{
	struct uftrace_mmap *map;
	struct strv dwarf_args = STRV_INIT;
	struct strv dwarf_rets = STRV_INIT;

	if (symtabs->loaded_debug)
		return;

	extract_dwarf_args(argspec, retspec, &dwarf_args, &dwarf_rets);
	if (dwarf_args.nr == 0 && dwarf_rets.nr == 0) {
		/* nothing to do */
		return;
	}

	pr_dbg("prepare debug info\n");

	setup_debug_info(symtabs->filename, &symtabs->dinfo, symtabs->exec_base);
	build_dwarf_info(&symtabs->dinfo, &symtabs->symtab, ptype,
			 &dwarf_args, &dwarf_rets);

	map = symtabs->maps;
	while (map) {
		/* avoid loading of main executable or libmcount */
		if (strcmp(map->libname, symtabs->filename) &&
		    strncmp(basename(map->libname), "libmcount", 9)) {
			setup_debug_info(map->libname, &map->dinfo, map->start);
			build_dwarf_info(&map->dinfo, &map->symtab, ptype,
					 &dwarf_args, &dwarf_rets);
		}
		map = map->next;
	}

	strv_free(&dwarf_args);
	strv_free(&dwarf_rets);

	symtabs->loaded_debug = true;
}

void finish_debug_info(struct symtabs *symtabs)
{
	struct uftrace_mmap *map;

	if (!symtabs->loaded_debug)
		return;

	release_debug_info(&symtabs->dinfo);

	map = symtabs->maps;
	while (map) {
		release_debug_info(&map->dinfo);
		map = map->next;
	}

	symtabs->loaded_debug = false;
}

static FILE * create_debug_file(char *dirname, const char *filename)
{
	FILE *fp;
	char *tmp;

	xasprintf(&tmp, "%s/%s.dbg", dirname, filename);

	fp = fopen(tmp, "ax");

	free(tmp);
	return fp;
}

static void close_debug_file(FILE *fp, char *dirname, const char *filename)
{
	bool delete = !ftell(fp);
	char *tmp;

	fclose(fp);

	if (!delete)
		return;

	pr_dbg2("delete debug file for %s\n", filename);

	xasprintf(&tmp, "%s/%s.dbg", dirname, filename);
	unlink(tmp);
	free(tmp);
}

void save_debug_file(FILE *fp, char code, char *str, unsigned long val)
{
	fprintf(fp, "%c: ", code);

	switch (code) {
	case 'F':
		fprintf(fp, "%lx %s\n", val, str);
		break;
	case 'A':
	case 'R':
		fprintf(fp, "%s\n", str);
		break;
	case 'E':
		/* this format is compatible with parse_enum_string() */
		fprintf(fp, "enum %s {%s}\n", str, (char *)val);
		break;
	default:
		fprintf(fp, "unknown debug info\n");
		break;
	}
}

static void save_debug_entries(struct debug_info *dinfo,
			       char *dirname, const char *filename)
{
	FILE *fp;
	struct rb_node *anode = rb_first(&dinfo->args);
	struct rb_node *rnode = rb_first(&dinfo->rets);

	fp = create_debug_file(dirname, basename(filename));
	if (fp == NULL)
		return;  /* somebody already did that! */

	save_enum_def(&dinfo->enums, fp);

	/*
	 * save spec of debug entry which has smaller offset first. 
	 * unify argument and return value only if they have same offset.
	 */
	while (anode || rnode) {
		struct debug_entry *arg = NULL;
		struct debug_entry *ret = NULL;

		if (anode)
			arg = rb_entry(anode, typeof(*arg), node);
		if (rnode)
			ret = rb_entry(rnode, typeof(*ret), node);

		if (arg == NULL || (ret && ret->offset < arg->offset)) {
			save_debug_file(fp, 'F', ret->name,
					ret->offset - dinfo->offset);
			save_debug_file(fp, 'R', ret->spec, 0);
			rnode = rb_next(rnode);
		}
		else {
			save_debug_file(fp, 'F', arg->name,
					arg->offset - dinfo->offset);
			save_debug_file(fp, 'A', arg->spec, 0);
			anode = rb_next(anode);

			if (ret && (arg->offset == ret->offset)) {
				save_debug_file(fp, 'R', ret->spec, 0);
				rnode = rb_next(rnode);
			}
		}
	}

	close_debug_file(fp, dirname, basename(filename));
}

void save_debug_info(struct symtabs *symtabs, char *dirname)
{
	struct uftrace_mmap *map;

	if (!symtabs->loaded_debug)
		return;

	/* use file-offset for main executable */
	if (elf_file_type(&symtabs->dinfo) == ET_EXEC)
		symtabs->dinfo.offset = symtabs->exec_base;

	/* XXX: libmcount doesn't set symtabs->dirname */
	save_debug_entries(&symtabs->dinfo, dirname, symtabs->filename);

	map = symtabs->maps;
	while (map) {
		if (strcmp(map->libname, symtabs->filename) &&
		    strncmp(basename(map->libname), "libmcount", 9))
			save_debug_entries(&map->dinfo, dirname, map->libname);

		map = map->next;
	}
}

static int load_debug_file(struct debug_info *dinfo,
			   const char *dirname, const char *filename)
{
	char *pathname;
	FILE *fp;
	char *line = NULL;
	size_t len = 0;
	int ret = -1;
	char *func = NULL;
	uint64_t offset = 0;

	dinfo->args = RB_ROOT;
	dinfo->rets = RB_ROOT;
	dinfo->enums = RB_ROOT;

	xasprintf(&pathname, "%s/%s.dbg", dirname, basename(filename));

	fp = fopen(pathname, "r");
	if (fp == NULL) {
		if (errno == ENOENT) {
			free(pathname);
			return -1;
		}

		pr_err("failed to open: %s", pathname);
	}

	pr_dbg2("load debug info from %s\n", pathname);

	while (getline(&line, &len, fp) >= 0) {
		char *pos;
		struct rb_root *root = &dinfo->args;

		if (line[1] != ':' || line[2] != ' ')
			goto out;

		/* remove trailing newline */
		line[strlen(line) - 1] = '\0';

		switch (line[0]) {
		case 'F':
			offset = strtoul(&line[3], &pos, 16);
			offset += dinfo->offset;

			if (*pos == ' ')
				pos++;

			free(func);
			func = xstrdup(pos);
			break;
		case 'A':
		case 'R':
			if (line[0] == 'R')
				root = &dinfo->rets;

			if (add_debug_entry(root, func, offset, &line[3]) < 0)
				goto out;
			break;
		case 'E':
			if (parse_enum_string(&line[3], &dinfo->enums))
				goto out;
			break;
		default:
			goto out;
		}
	}
	ret = 0;

out:
	if (ret < 0) {
		pr_dbg("invalid dbg file: %s: %s\n", pathname, line);

		free_debug_entry(&dinfo->args);
		free_debug_entry(&dinfo->rets);
	}

	fclose(fp);
	free(pathname);
	free(func);
	return ret;
}

void load_debug_info(struct symtabs *symtabs)
{
	struct uftrace_mmap *map;

	symtabs->dinfo.offset = symtabs->exec_base;
	load_debug_file(&symtabs->dinfo, symtabs->dirname, symtabs->filename);

	map = symtabs->maps;
	while (map) {
		if (strcmp(map->libname, symtabs->filename) &&
		    strncmp(basename(map->libname), "libmcount", 9)) {
			map->dinfo.offset = map->start;
			load_debug_file(&map->dinfo, symtabs->dirname,
					map->libname);
		}
		map = map->next;
	}

	symtabs->loaded_debug = true;
}

char * get_dwarf_argspec(struct debug_info *dinfo, char *name, unsigned long addr)
{
	struct debug_entry *entry = find_debug_entry(&dinfo->args, addr);

	return entry ? entry->spec : NULL;
}

char * get_dwarf_retspec(struct debug_info *dinfo, char *name, unsigned long addr)
{
	struct debug_entry *entry = find_debug_entry(&dinfo->rets, addr);

	return entry ? entry->spec : NULL;
}
