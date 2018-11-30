#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <dlfcn.h>

/* This should be defined before #include "utils.h" */
#define PR_FMT     "dwarf"
#define PR_DOMAIN  DBG_DWARF

#include "uftrace.h"
#include "utils/utils.h"
#include "utils/dwarf.h"
#include "utils/symbol.h"
#include "utils/filter.h"

bool debug_info_has_argspec(struct debug_info *dinfo)
{
	if (dinfo == NULL)
		return false;

	/* dinfo has some debug entries? */
	return !RB_EMPTY_ROOT(&dinfo->args) || !RB_EMPTY_ROOT(&dinfo->rets);
}

bool debug_info_has_location(struct debug_info *dinfo)
{
	if (dinfo == NULL)
		return false;

	/* dinfo has some debug entries? */
	return dinfo->nr_locs_used;
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

	pr_dbg3("add debug entry: %x %s%s\n", offset, func, argspec);

	while (*p) {
		parent = *p;
		iter = rb_entry(parent, struct debug_entry, node);

		if (unlikely(iter->offset == offset)) {
			pr_dbg3("debug entry: conflict!\n");

			/* mark it broken by using NULL spec */
			free(iter->spec);
			iter->spec = NULL;

			return 0;
		}

		if (iter->offset > offset)
			p = &parent->rb_left;
		else
			p = &parent->rb_right;
	}

	entry = xmalloc(sizeof(*entry));
	entry->name = xstrdup(func);
	entry->spec = xstrdup(argspec);
	entry->offset = offset;

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

static struct debug_file * get_debug_file(struct debug_info *dinfo,
					  const char *filename)
{
	struct debug_file *df;

	if (filename == NULL)
		return NULL;

	list_for_each_entry(df, &dinfo->files, list) {
		if (!strcmp(df->name, filename))
			return df;
	}

	df = xmalloc(sizeof(*df));
	df->name = xstrdup(filename);
	list_add(&df->list, &dinfo->files);

	return df;
}

#ifdef HAVE_LIBDW

#include <libelf.h>
#include <gelf.h>
#include <dwarf.h>

struct cu_files {
	Dwarf_Files		*files;
	size_t			num;     /* number of files */
};

static int elf_file_type(struct debug_info *dinfo)
{
	GElf_Ehdr ehdr;

	if (dinfo->dw && gelf_getehdr(dwarf_getelf(dinfo->dw), &ehdr))
		return ehdr.e_type;

	return ET_NONE;
}

static bool get_attr(Dwarf_Die *die, int attr, bool follow,
		     Dwarf_Attribute *da)
{
	if (follow) {
		if (!dwarf_hasattr_integrate(die, attr))
			return false;
		dwarf_attr_integrate(die, attr, da);
	}
	else {
		if (!dwarf_hasattr(die, attr))
			return false;
		dwarf_attr(die, attr, da);
	}

	return true;
}

static long int_attr(Dwarf_Die *die, int attr, bool follow)
{
	Dwarf_Attribute da;
	Dwarf_Sword data;

	if (!get_attr(die, attr, follow, &da))
		return 0;

	dwarf_formsdata(&da, &data);
	return data;
}

static char * str_attr(Dwarf_Die *die, int attr, bool follow)
{
	Dwarf_Attribute da;

	if (!get_attr(die, attr, follow, &da))
		return NULL;

	return (char *) dwarf_formstring(&da);
}

/* setup dwarf info from filename, return 0 for success */
static int setup_dwarf_info(const char *filename, struct debug_info *dinfo,
			    unsigned long offset, bool force)
{
	int fd;

	if (!force && check_trace_functions(filename) != TRACE_MCOUNT)
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

	pr_dbg2("setup dwarf debug info for %s\n", filename);

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
	bool				broken;
	char 				*enum_name;
	struct debug_info		*dinfo;
};

static char * fill_enum_str(Dwarf_Die *die)
{
	char *str = NULL;
	Dwarf_Die e_val;

	if (dwarf_child(die, &e_val) != 0)
		goto out;

	do {
		if (dwarf_tag(&e_val) == DW_TAG_enumerator) {
			char buf[256];
			Dwarf_Sword val;

			val = int_attr(&e_val, DW_AT_const_value, false);
			snprintf(buf, sizeof(buf), "%s=%ld",
				 dwarf_diename(&e_val), (long)val);

			str = strjoin(str, buf, ",");
		}
	}
	while (dwarf_siblingof(&e_val, &e_val) == 0);

out:
	if (str == NULL)
		pr_dbg2("no enum values\n");

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
	while ((tmp = strpbrk(tmp, "+-.()<> ")) != NULL)
		*tmp++ = '_';

	return enum_name;
}

/* returns size in bit */
static size_t type_size(Dwarf_Die *die)
{
	int size;

	/* just guess it's word size */
	size = dwarf_bytesize(die);
	if (size <= 0)
		size = sizeof(long);

	return size * 8;
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
			if (tname && (isalpha(*tname) || *tname == '_'))
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
			break;

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
	/* TODO: handle aggregate types correctly */
	if (td->size > sizeof(long) * 8)
		td->broken = true;

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
	bool			broken;
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

	if (!resolve_type_info(die, &data)) {
		if (data.broken)
			ad->broken = true;
		return !data.ignore;
	}

	switch (data.fmt) {
	case ARG_FMT_CHAR:
		strcat(spec, "/c");
		break;
	case ARG_FMT_STR:
		if (!ad->broken)
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
			char sz[16];

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
		int (*get_location_list)(Dwarf_Attribute *loc, Dwarf_Off offset,
					 Dwarf_Addr *base, Dwarf_Addr *start,
					 Dwarf_Addr *end, Dwarf_Op **ops,
					 size_t *len);
		Dwarf_Addr base, start, end;

		get_location_list = dlsym(RTLD_DEFAULT, "dwarf_getlocations");
		if (get_location_list == NULL)
			return false;

		/* try to get the first entry in the location list */
		if (get_location_list(&loc, 0, &base, &start, &end,
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
	struct cu_files		files;
};

/* caller should free the return value */
static char *find_last_component(char *name)
{
	char *tmp, *p, *last;
	int count = 0;

	tmp = p = last = xstrdup(name);

	while (*p) {
		if (strchr("<(", *p))
			*p = '\0', count++;
		else if (strchr(">)", *p))
			count--;

		if (p[0] == ':' && p[1] == ':' && count == 0)
			last = p + 2;

		p++;
	}

	p = xstrdup(last);
	free(tmp);

	return p;
}

static bool match_name(struct sym *sym, char *name, bool demangled)
{
	char *last_sym;
	char *last_name;
	bool ret;

	if (sym == NULL)
		return false;

	if (!strcmp(sym->name, name))
		return true;

	if (demangled || demangler != DEMANGLE_SIMPLE)
		return false;

	last_sym = find_last_component(sym->name);
	last_name = find_last_component(name);

	ret = !strcmp(last_sym, last_name);

	free(last_sym);
	free(last_name);
	return ret;
}

static void get_source_location(Dwarf_Die *die, struct build_data *bd,
				struct sym *sym)
{
	ptrdiff_t sym_idx;
	const char *filename;
	struct debug_info *dinfo = bd->dinfo;
	struct debug_file *dfile = NULL;
	int dline = 0;

	sym_idx = sym - bd->symtab->sym;

	if (dwarf_hasattr(die, DW_AT_decl_file)) {
		if (dwarf_decl_line(die, &dline) == 0) {
			filename = dwarf_decl_file(die);
			dfile = get_debug_file(dinfo, filename);
		}
	}
	else {
		Dwarf_Die cudie;
		Dwarf_Line *line;

		dwarf_diecu(die, &cudie, NULL, NULL);
		line = dwarf_getsrc_die(&cudie, sym->addr - dinfo->offset);
		filename = dwarf_linesrc(line, NULL, NULL);
		dfile = get_debug_file(dinfo, filename);
		dwarf_lineno(line, &dline);
	}

	if (dfile == NULL)
		return;

	dinfo->locs[sym_idx].sym  = sym;
	dinfo->locs[sym_idx].file = dfile;
	dinfo->locs[sym_idx].line = dline;
}

static int get_dwarfspecs_cb(Dwarf_Die *die, void *data)
{
	struct build_data *bd = data;
	struct arg_data ad = {
		.argspec = NULL,
		.dinfo = bd->dinfo,
	};
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

	if (dwarf_hasattr_integrate(die, DW_AT_linkage_name)) {
		name = demangle(str_attr(die, DW_AT_linkage_name, true));
		needs_free = true;
	}
	if (name == NULL)
		name = (char *)dwarf_diename(die);
	if (unlikely(name == NULL))
		return DWARF_CB_OK;

	/*
	 * double-check symbol table has same info.
	 * we add 1 to the offset because of ARM(THUMB) symbols
	 * but DWARF doesn't know about it.
	 */
	sym = find_sym(bd->symtab, offset + 1);
	if (sym == NULL || !match_name(sym, name, needs_free)) {
		pr_dbg2("skip unknown debug info: %s / %s (%lx)\n",
			sym ? sym->name : "no name", name, offset);
		goto out;
	}

	get_source_location(die, bd, sym);

	ad.name = name;
	ad.addr = offset;

	for (i = 0; i < bd->nr_rets; i++) {
		if (!match_filter_pattern(&bd->rets[i], name))
			continue;

		if (get_retspec(die, &ad)) {
			add_debug_entry(&bd->dinfo->rets, name, sym->addr,
					ad.argspec);
		}

		free(ad.argspec);
		ad.argspec = NULL;
		break;
	}

	for (i = 0; i < bd->nr_args; i++) {
		if (!match_filter_pattern(&bd->args[i], name))
			continue;

		if (get_argspec(die, &ad)) {
			add_debug_entry(&bd->dinfo->args, name, sym->addr,
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

	dinfo->nr_locs = symtab->nr_sym;
	dinfo->locs = xcalloc(dinfo->nr_locs, sizeof(*dinfo->locs));

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

		dwarf_getsrcfiles(&cudie, &bd.files.files, &bd.files.num);

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
			    unsigned long offset, bool force)
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
			    unsigned long offset, bool force)
{
	dinfo->args = RB_ROOT;
	dinfo->rets = RB_ROOT;
	dinfo->enums = RB_ROOT;
	INIT_LIST_HEAD(&dinfo->files);

	return setup_dwarf_info(filename, dinfo, offset, force);
}

static void release_debug_info(struct debug_info *dinfo)
{
	struct debug_file *df, *tmp;

	free_debug_entry(&dinfo->args);
	free_debug_entry(&dinfo->rets);
	release_enum_def(&dinfo->enums);

	free(dinfo->locs);
	dinfo->locs = NULL;

	list_for_each_entry_safe(df, tmp, &dinfo->files, list) {
		list_del(&df->list);
		free(df->name);
		free(df);
	}

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
			char *argspec, char *retspec,
			bool auto_args, bool force)
{
	struct uftrace_mmap *map;
	struct strv dwarf_args = STRV_INIT;
	struct strv dwarf_rets = STRV_INIT;

	if (symtabs->loaded_debug)
		return;

	extract_dwarf_args(argspec, retspec, &dwarf_args, &dwarf_rets);

	if (auto_args) {
		if (ptype == PATT_REGEX) {
			strv_append(&dwarf_args, ".");
			strv_append(&dwarf_rets, ".");
		}
		else {  /* PATT_GLOB */
			strv_append(&dwarf_args, "*");
			strv_append(&dwarf_rets, "*");
		}
	}

	/* file and line info need be saved regardless of argspec */
	pr_dbg("prepare debug info\n");

	setup_debug_info(symtabs->filename, &symtabs->dinfo, symtabs->exec_base,
			 force);
	build_dwarf_info(&symtabs->dinfo, &symtabs->symtab, ptype,
			 &dwarf_args, &dwarf_rets);

	map = symtabs->maps;
	while (map) {
		/* avoid loading of main executable or libmcount */
		if (strcmp(map->libname, symtabs->filename) &&
		    strncmp(basename(map->libname), "libmcount", 9)) {
			setup_debug_info(map->libname, &map->dinfo, map->start,
					 force);
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
		if (strcmp(map->libname, symtabs->filename) &&
		    strncmp(basename(map->libname), "libmcount", 9))
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
		/* symbol address and name */
		fprintf(fp, "%lx %s\n", val, str);
		break;
	case 'A':
	case 'R':
		/* argument and return value spec */
		fprintf(fp, "%s\n", str);
		break;
	case 'E':
		/*
		 * enum definition: this format is compatible with
		 * parse_enum_string()
		 */
		fprintf(fp, "enum %s {%s}\n", str, (char *)val);
		break;
	case 'L':
		/* line number and file name */
		fprintf(fp, "%ld %s\n", val, str);
		break;
	default:
		fprintf(fp, "unknown debug info\n");
		break;
	}
}

static void save_debug_entries(struct debug_info *dinfo,
			       char *dirname, const char *filename)
{
	int i;
	FILE *fp;

	fp = create_debug_file(dirname, basename(filename));
	if (fp == NULL)
		return;  /* somebody already did that! */

	save_enum_def(&dinfo->enums, fp);

	for (i = 0; i < dinfo->nr_locs; i++) {
		struct debug_location *loc = &dinfo->locs[i];
		struct debug_entry *entry;

		if (loc->sym == NULL)
			continue;

		save_debug_file(fp, 'F', loc->sym->name,
				loc->sym->addr - dinfo->offset);
		save_debug_file(fp, 'L', loc->file->name, loc->line);

		entry = find_debug_entry(&dinfo->args, loc->sym->addr);
		if (entry)
			save_debug_file(fp, 'A', entry->spec, 0);

		entry = find_debug_entry(&dinfo->rets, loc->sym->addr);
		if (entry)
			save_debug_file(fp, 'R', entry->spec, 0);
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

static int load_debug_file(struct debug_info *dinfo, struct symtab *symtab,
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
	INIT_LIST_HEAD(&dinfo->files);
	dinfo->nr_locs = symtab->nr_sym;
	dinfo->locs = xcalloc(dinfo->nr_locs, sizeof(*dinfo->locs));

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
		struct sym *sym;
		ptrdiff_t sym_idx;
		unsigned long lineno;

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
			
			if (func == NULL)
				goto out;

			if (add_debug_entry(root, func, offset, &line[3]) < 0)
				goto out;
			break;
		case 'E':
			if (parse_enum_string(&line[3], &dinfo->enums))
				goto out;
			break;
		case 'L':
			sym = find_sym(symtab, offset);
			if (sym == NULL)
				goto out;

			lineno = strtoul(&line[3], &pos, 0);

			sym_idx = sym - symtab->sym;
			dinfo->locs[sym_idx].line = lineno;
			dinfo->locs[sym_idx].file = get_debug_file(dinfo, pos + 1);
			dinfo->nr_locs_used++;
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

	free(line);
	fclose(fp);
	free(pathname);
	free(func);
	return ret;
}

void load_debug_info(struct symtabs *symtabs)
{
	struct uftrace_mmap *map;

	symtabs->dinfo.offset = symtabs->exec_base;
	load_debug_file(&symtabs->dinfo, &symtabs->symtab,
			symtabs->dirname, symtabs->filename);

	map = symtabs->maps;
	while (map) {
		if (strcmp(map->libname, symtabs->filename) &&
		    strncmp(basename(map->libname), "libmcount", 9)) {
			map->dinfo.offset = map->start;
			load_debug_file(&map->dinfo, &map->symtab,
					symtabs->dirname, map->libname);
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

struct debug_location *find_file_line(struct symtabs *symtabs, uint64_t addr)
{
	struct uftrace_mmap *map;
	struct symtab *symtab;
	struct debug_info *dinfo;
	struct sym *sym = NULL;
	ptrdiff_t idx;

	map = find_map(symtabs, addr);

	if (map == MAP_MAIN) {
		symtab = &symtabs->symtab;
		dinfo = &symtabs->dinfo;
	}
	else if (map == MAP_KERNEL) {
		map = NULL;
		dinfo = NULL;
	}
	else if (map != NULL) {
		symtab = &map->symtab;
		dinfo = &map->dinfo;
	}

	if (map && debug_info_has_location(dinfo))
		sym = find_sym(symtab, addr);

	if (map == NULL || sym == NULL)
		return NULL;

	idx = sym - symtab->sym;
	return &dinfo->locs[idx];
}
