#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* This should be defined before #include "utils.h" */
#define PR_FMT "dwarf"
#define PR_DOMAIN DBG_DWARF

#include "mcount-arch.h"
#include "uftrace.h"
#include "utils/dwarf.h"
#include "utils/filter.h"
#include "utils/symbol.h"
#include "utils/utils.h"

bool debug_info_has_argspec(struct uftrace_dbg_info *dinfo)
{
	if (dinfo == NULL)
		return false;

	/* dinfo has some debug entries? */
	return !RB_EMPTY_ROOT(&dinfo->args) || !RB_EMPTY_ROOT(&dinfo->rets);
}

bool debug_info_has_location(struct uftrace_dbg_info *dinfo)
{
	if (dinfo == NULL)
		return false;

	/* dinfo has some debug entries? */
	return dinfo->nr_locs_used;
}

struct debug_entry {
	struct rb_node node;
	uint64_t offset;
	char *name;
	char *spec;
};

static int add_debug_entry(struct rb_root *root, char *func, uint64_t offset, char *argspec)
{
	struct debug_entry *entry, *iter;
	struct rb_node *parent = NULL;
	struct rb_node **p = &root->rb_node;

	pr_dbg3("add debug entry: %" PRIx64 " %s%s\n", offset, func, argspec);

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

static struct debug_entry *find_debug_entry(struct rb_root *root, uint64_t offset)
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
			pr_dbg3("found debug entry at %" PRIx64 " (%s%s)\n", offset, iter->name,
				iter->spec);
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

static struct uftrace_dbg_file *get_debug_file(struct uftrace_dbg_info *dinfo, const char *filename)
{
	struct uftrace_dbg_file *df;
	struct rb_node *parent = NULL;
	struct rb_node **p = &dinfo->files.rb_node;
	int ret;

	if (filename == NULL)
		return NULL;

	while (*p) {
		parent = *p;
		df = rb_entry(parent, struct uftrace_dbg_file, node);

		ret = strcmp(df->name, filename);

		if (ret == 0)
			return df;

		if (ret < 0)
			p = &parent->rb_left;
		else
			p = &parent->rb_right;
	}

	df = xmalloc(sizeof(*df));
	df->name = xstrdup(filename);

	rb_link_node(&df->node, parent, p);
	rb_insert_color(&df->node, &dinfo->files);

	return df;
}

static void release_debug_file(struct rb_root *root)
{
	struct uftrace_dbg_file *df;
	struct rb_node *node;

	while (!RB_EMPTY_ROOT(root)) {
		node = rb_first(root);
		df = rb_entry(node, typeof(*df), node);

		rb_erase(node, root);
		free(df->name);
		free(df);
	}
}

#ifdef HAVE_LIBDW

#include <dwarf.h>
#include <gelf.h>
#include <libelf.h>

/*
 * Used by libdwfl in build_debug_info_cb after setup_dwarf_info returns,
 * so this may not be allocated temporary on setup_debug_info's stack (which is freed)
 */
static char *debuginfo_path = NULL;
Dwfl_Callbacks dwfl_callbacks = {
	.find_elf = dwfl_linux_proc_find_elf,
	.find_debuginfo = dwfl_standard_find_debuginfo,
	.debuginfo_path = &debuginfo_path,
};

/*
 * symbol table contains normalized (zero-based) relative address.
 * but some other info in non-PIE executable has different base
 * address so it needs to convert back and forth.
 */
static inline unsigned long sym_to_dwarf_addr(struct uftrace_dbg_info *dinfo, unsigned long addr)
{
	if (dinfo->file_type == ET_EXEC)
		addr += dinfo->offset;
	return addr;
}

static inline unsigned long dwarf_to_sym_addr(struct uftrace_dbg_info *dinfo, unsigned long addr)
{
	if (dinfo->file_type == ET_EXEC)
		addr -= dinfo->offset;
	return addr;
}

struct cu_files {
	Dwarf_Files *files;
	size_t num; /* number of files */
};

static int elf_file_type(struct uftrace_dbg_info *dinfo)
{
	GElf_Ehdr ehdr;

	if (dinfo->dw && gelf_getehdr(dwarf_getelf(dinfo->dw), &ehdr))
		return ehdr.e_type;

	return ET_NONE;
}

static bool get_attr(Dwarf_Die *die, int attr, bool follow, Dwarf_Attribute *da)
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
	switch (dwarf_whatform(&da)) {
	case DW_FORM_data1:
		data &= 0xff;
		break;
	case DW_FORM_data2:
		data &= 0xffff;
		break;
	case DW_FORM_data4:
		data &= 0xffffffff;
		break;
	default:
		break;
	}
	return data;
}

static char *str_attr(Dwarf_Die *die, int attr, bool follow)
{
	Dwarf_Attribute da;

	if (!get_attr(die, attr, follow, &da))
		return NULL;

	return (char *)dwarf_formstring(&da);
}

/* setup dwarf info from filename, return 0 for success */
static int setup_dwarf_info(const char *filename, struct uftrace_dbg_info *dinfo,
			    unsigned long offset, bool force)
{
	int fd;
	Dwfl_Module *mod;
	Dwarf_Addr bias;

	if (force || check_trace_functions(filename) != TRACE_CYGPROF)
		dinfo->needs_args = true;

	fd = open(filename, O_RDONLY);
	if (fd < 0) {
		pr_dbg2("cannot open debug info for %s: %m\n", filename);
		return -1;
	}

	dinfo->dw = dwarf_begin(fd, DWARF_C_READ);
	if (dinfo->dw != NULL)
		goto ok;

	dinfo->dwfl = dwfl_begin(&dwfl_callbacks);
	if (dinfo->dwfl == NULL) {
		pr_dbg2("failed to begin libdwfl: %s\n", dwfl_errmsg(dwfl_errno()));
		close(fd);
		return -1;
	}

	mod = dwfl_report_offline(dinfo->dwfl, filename, filename, fd);
	dinfo->dw = dwfl_module_getdwarf(mod, &bias);
	if (dinfo->dw == NULL) {
		pr_dbg2("failed to setup debug info: %s\n", dwfl_errmsg(dwfl_errno()));
		dwfl_end(dinfo->dwfl);
		dinfo->dwfl = NULL;
		return -1;
	}

ok:
	pr_dbg2("setup dwarf debug info for %s\n", filename);

	/*
	 * symbol table already uses relative address but non-PIE
	 * executable needs to use absolute address for DWARF info.
	 * Also as filter entry uses absolute address, it needs to
	 * keep the offset to recover relative address back.
	 */
	dinfo->offset = offset;

	dinfo->file_type = elf_file_type(dinfo);

	return 0;
}

static void release_dwarf_info(struct uftrace_dbg_info *dinfo)
{
	if (dinfo->dwfl != NULL) {
		/* this will also free dinfo->dw */
		dwfl_end(dinfo->dwfl);
		dinfo->dwfl = NULL;
		dinfo->dw = NULL;
	}

	if (dinfo->dw != NULL) {
		dwarf_end(dinfo->dw);
		dinfo->dw = NULL;
	}
}

#define ARGSPEC_MAX_SIZE 256
#define MAX_STRUCT_REGS 4

/* arg_data contains argument passing info for single function */
struct arg_data {
	/* name of the function (symbol name) */
	const char *name;

	/* (result) argspec, should be freed after used */
	char *argspec;

	/* (normal) argument index */
	int idx;

	/* floating-point argument index */
	int fpidx;

	/* arg format of the last argument */
	int last_fmt;

	/* arg size (in byte) of the last argument */
	int last_size;

	/* number of available core registers */
	int reg_max;

	/* number of available FP registers */
	int fpreg_max;

	/* index of next core register to be used */
	int reg_pos;

	/* index of next FP register to be used */
	int fpreg_pos;

	/* position of next available stack */
	int stack_ofs;

	/* whether we have retspec for this function */
	bool has_retspec;

	/* argument info parsing failed or unsupported */
	bool broken;

	/* struct is passed by value, location needs update */
	bool struct_passed;

	/* struct passed-by-value will be replaced to a pointer */
	bool struct_arg_needs_ptr;

	/* struct passed-by-value will be replaced to a pointer */
	bool struct_return_needs_ptr;

	/* struct containing FP types will use FP registers */
	bool struct_uses_fpreg;

	/* pass class via stack if it has a MEMORY class member */
	bool has_mem_class;

	/*
	 * class containing non-trivial copy constructor or destructor, or
	 * virtual functions will be passed by a invisible reference.
	 */
	bool class_via_ptr;

	/* struct_param_class if argument is struct and passed by value */
	char struct_regs[MAX_STRUCT_REGS];

	/* number of registers used above */
	int struct_reg_cnt;

	/* uftrace debug info */
	struct uftrace_dbg_info *dinfo;
};

static void setup_arg_data(struct arg_data *ad, const char *name, struct uftrace_dbg_info *dinfo)
{
	memset(ad, 0, sizeof(*ad));

	ad->name = name;
	ad->dinfo = dinfo;

	switch (host_cpu_arch()) {
	case UFT_CPU_X86_64:
		ad->reg_max = 6;
		ad->fpreg_max = 8;
		ad->struct_uses_fpreg = true;
		ad->struct_return_needs_ptr = true;
		ad->class_via_ptr = true;
		ad->has_mem_class = true;
		break;
	case UFT_CPU_AARCH64:
		ad->reg_max = 8;
		ad->fpreg_max = 8;
		ad->struct_arg_needs_ptr = true;
		/* struct return will use 'x8' register */
		break;
	case UFT_CPU_RISCV64:
		ad->reg_max = 8;
		ad->fpreg_max = 8;
		ad->struct_arg_needs_ptr = true;
		ad->struct_return_needs_ptr = true;
		ad->struct_uses_fpreg = true;
		break;
	default:
		/* TODO */
		ad->broken = true;
		break;
	}
}

/* struct parameter class to determine argument passing method */
enum struct_param_class {
	PARAM_CLASS_NONE = 0,
	PARAM_CLASS_MEM = 'm',
	PARAM_CLASS_INT = 'i',
	PARAM_CLASS_FP = 'f',
	PARAM_CLASS_PTR = 'p',
};

/* type_data contains info about single argument */
struct type_data {
	struct arg_data *arg_data;
	enum uftrace_arg_format fmt;
	size_t size; /* in bit */
	int pointer;
	bool ignore;
	bool broken;
	char *name;
};

static char *fill_enum_str(Dwarf_Die *die)
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
			snprintf(buf, sizeof(buf), "%s=%ld", dwarf_diename(&e_val), (long)val);

			str = strjoin(str, buf, ",");
		}
	} while (dwarf_siblingof(&e_val, &e_val) == 0);

out:
	if (str == NULL)
		pr_dbg2("no enum values\n");

	return str;
}

static char *make_enum_name(Dwarf_Die *die)
{
	Dwarf_Die cudie;
	const char *cu_name = NULL;
	unsigned long off;
	char *enum_name;
	char *tmp;

	if (dwarf_diecu(die, &cudie, NULL, NULL))
		cu_name = dwarf_diename(&cudie);

	if (cu_name == NULL)
		cu_name = "unnamed";

	off = dwarf_cuoffset(die);

	xasprintf(&enum_name, "_%s_%lx", uftrace_basename(cu_name), off);

	/* replace forbidden characters */
	tmp = enum_name;
	while ((tmp = strpbrk(tmp, "+-.()<> ")) != NULL)
		*tmp++ = '_';

	return enum_name;
}

/* returns size in bit */
static size_t type_size(Dwarf_Die *die, size_t default_size)
{
	Dwarf_Word size;

	if (dwarf_aggregate_size(die, &size) >= 0)
		return size * 8;

	/* just guess it's word size */
	size = dwarf_bytesize(die);
	if ((long)size <= 0)
		size = default_size;

	return size * 8;
}

static bool is_empty_aggregate(Dwarf_Die *die)
{
	Dwarf_Die child;
	Dwarf_Die parent;
	bool inherited = false;

	/* C++ defines size of an empty struct as 1 byte */
	if (type_size(die, sizeof(long)) > 1 * 8)
		return false;

retry:
	if (dwarf_child(die, &child) != 0)
		return true; /* no child = no member */

	do {
		Dwarf_Attribute type;
		Dwarf_Die type_die;

		switch (dwarf_tag(&child)) {
		case DW_TAG_member:
			if (dwarf_attr(die, DW_AT_type, &type) == NULL)
				return false;
			if (dwarf_formref_die(&type, &type_die) == NULL)
				return false;
			return is_empty_aggregate(&type_die);

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
	} while (dwarf_siblingof(&child, &child) == 0);

	if (inherited) {
		inherited = false;
		die = &parent;
		goto retry;
	}

	return true;
}

/* param_data contains addition info about a struct passed by value */
struct param_data {
	/* position in byte, in case two or more fields are merged into one */
	int pos;

	/* maximum size to pass an argument in registers */
	unsigned max_struct_size;

	/* maximum allowed register count */
	int reg_max;

	/* current allocated register count */
	int reg_cnt;

	/* allocated register classes */
	char regs[MAX_STRUCT_REGS];

	/* if it's set, FP registers are allowed */
	bool use_fpregs;

	/* check member name (for std::string detection) */
	bool lookup_string;

	/* previous (or current) register class in case of merge */
	int prev_class;
};

static void setup_param_data(struct param_data *data)
{
	memset(data, 0, sizeof(*data));

	switch (host_cpu_arch()) {
	case UFT_CPU_X86_64:
		/* TODO: check availability of __m256 type */
		data->max_struct_size = 16 * 8;
		data->use_fpregs = true;
		break;
	case UFT_CPU_AARCH64:
		data->max_struct_size = 16 * 8;
		break;
	case UFT_CPU_RISCV64:
		data->max_struct_size = 16 * 8;
		data->use_fpregs = true;
		break;
	default:
		/* TODO */
		break;
	}

	data->reg_max = data->max_struct_size / 64;
}

static int get_param_class(Dwarf_Die *die, struct arg_data *ad, struct param_data *pd)
{
	Dwarf_Die ref;
	Dwarf_Attribute type;
	unsigned aform;
	const char *tname;
	int size;
	int this_class;

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
			return PARAM_CLASS_MEM;
		}

		switch (dwarf_tag(die)) {
		case DW_TAG_pointer_type:
		case DW_TAG_ptr_to_member_type:
		case DW_TAG_reference_type:
		case DW_TAG_rvalue_reference_type:
			/* align start address (TODO: handle packed struct) */
			if (pd->pos % sizeof(long))
				pd->reg_cnt++;
			pd->pos = ROUND_UP(pd->pos, sizeof(long));

			if (pd->reg_cnt >= pd->reg_max)
				return PARAM_CLASS_MEM;

			pd->pos += sizeof(long);
			pd->regs[pd->reg_cnt++] = PARAM_CLASS_INT;
			return PARAM_CLASS_INT;

		case DW_TAG_structure_type:
		case DW_TAG_union_type:
		case DW_TAG_class_type:
			/* TODO */
			return PARAM_CLASS_MEM;

		case DW_TAG_array_type:
			/* TODO */
			break;

		case DW_TAG_enumeration_type:
			return PARAM_CLASS_INT;

		case DW_TAG_base_type:
			tname = dwarf_diename(die);

			/* make 'size' in byte (by dividing by 8 ) */
			size = type_size(die, sizeof(int)) / 8;
			if (size == 0)
				size = 1;
			/* align start address (TODO: handle packed struct) */
			if (pd->pos % size) {
				if ((pd->pos % sizeof(long)) + size >= sizeof(long)) {
					pd->reg_cnt++;
					pd->prev_class = PARAM_CLASS_NONE;
				}
			}
			pd->pos = ROUND_UP(pd->pos, size);

			if (pd->reg_cnt >= pd->reg_max)
				return PARAM_CLASS_MEM;

			if (!strcmp(tname, "double") && pd->use_fpregs) {
				pd->regs[pd->reg_cnt++] = PARAM_CLASS_FP;
				pd->pos += sizeof(double);
				pd->prev_class = PARAM_CLASS_NONE;
				return PARAM_CLASS_FP;
			}
			else if (!strcmp(tname, "float") && pd->use_fpregs) {
				/* if it's already "int", don't change */
				if (pd->prev_class != PARAM_CLASS_INT)
					pd->prev_class = PARAM_CLASS_FP;
			}
			else {
				/* default to integer class */
				pd->prev_class = PARAM_CLASS_INT;
			}

			this_class = pd->prev_class;
			pd->regs[pd->reg_cnt] = this_class;
			if ((pd->pos % sizeof(long)) + size >= sizeof(long)) {
				pd->reg_cnt++;
				pd->prev_class = PARAM_CLASS_NONE;
			}
			pd->pos += size;
			return this_class == PARAM_CLASS_INT ? this_class : PARAM_CLASS_FP;

		default:
			break;
		}
	}
	return PARAM_CLASS_MEM;
}

static void place_struct_members(Dwarf_Die *die, struct arg_data *ad, struct type_data *td)
{
	Dwarf_Die child;
	int param_class = PARAM_CLASS_NONE;
	struct param_data pd;
	int i, reg_cnt = 0, fp_cnt = 0;
	const char *sname;
	bool found_mem_class = false;
	bool check_class_ptr_only = false;

	setup_param_data(&pd);
	ad->struct_reg_cnt = 0;
	ad->struct_passed = true;

	sname = dwarf_diename(die);
	if (sname) {
		char *p;

		td->name = xstrdup(sname);

		/* remove long C++ type name to prevent confusion */
		p = strpbrk(td->name + 1, "< ({[");
		if (p)
			*p = '\0';

		if (!strcmp(td->name, "basic_string"))
			pd.lookup_string = true;
	}

	if (dwarf_child(die, &child) != 0)
		return; /* no child = no member */

	if (td->size > pd.max_struct_size && !pd.lookup_string) {
		if (ad->class_via_ptr)
			check_class_ptr_only = true;
		else
			goto pass_via_stack;
	}

	do {
		switch (dwarf_tag(&child)) {
		case DW_TAG_member:
			if (!check_class_ptr_only) {
				param_class = get_param_class(&child, ad, &pd);
				if (param_class == PARAM_CLASS_MEM)
					found_mem_class = true;

				if (!pd.lookup_string)
					break;

				sname = dwarf_diename(&child);
				if (sname && !strcmp(sname, "_M_dataplus")) {
					td->fmt = ARG_FMT_STD_STRING;
					td->size = sizeof(long) * 8;
					return;
				}
			}
			break;

		case DW_TAG_inheritance:
			/* TODO */
			break;

		case DW_TAG_subprogram:
			/*
			 * FIXME: assume pass via stack if it has a (probably
			 * non-trivial) destructor or a virtual function
			 */
			if (!ad->class_via_ptr)
				break;

			if (ad->reg_pos >= ad->reg_max)
				goto pass_via_stack;

			sname = dwarf_diename(&child);
			if ((sname && sname[0] == '~') || dwarf_hasattr(die, DW_AT_virtuality)) {
				pr_dbg3("non-trivial class passed via pointer\n");
				ad->struct_regs[0] = PARAM_CLASS_PTR;
				ad->struct_reg_cnt = 1;
				return;
			}
			break;

		default:
			break;
		}
	} while (dwarf_siblingof(&child, &child) == 0);

	if (td->size > pd.max_struct_size)
		goto pass_via_stack;
	if (ad->has_mem_class && found_mem_class)
		goto pass_via_stack;

	if (pd.pos % sizeof(long))
		pd.reg_cnt++;

	for (i = 0; i < pd.reg_cnt; i++) {
		if (pd.regs[i] == PARAM_CLASS_FP)
			fp_cnt++;
		else
			reg_cnt++;
	}

	if (ad->reg_pos + reg_cnt > ad->reg_max)
		goto pass_via_stack;
	if (ad->fpreg_pos + fp_cnt > ad->fpreg_max)
		goto pass_via_stack;

	memcpy(ad->struct_regs, pd.regs, sizeof(pd.regs));
	ad->struct_reg_cnt = pd.reg_cnt;
	return;

pass_via_stack:
	pr_dbg3("struct passed via stack: size = %zd bytes\n", td->size / 8);
	ad->struct_reg_cnt = 0;

	if (((ad->has_retspec && ad->struct_return_needs_ptr) ||
	     (!ad->has_retspec && ad->struct_arg_needs_ptr)) &&
	    ad->reg_pos < ad->reg_max) {
		ad->struct_regs[ad->struct_reg_cnt++] = PARAM_CLASS_PTR;
	}
}

static bool resolve_type_info(Dwarf_Die *die, struct arg_data *ad, struct type_data *td)
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
			if (td->pointer)
				break;

			enum_str = fill_enum_str(die);
			if (enum_str == NULL)
				return false; /* use default format */

			td->fmt = ARG_FMT_ENUM;
			tname = dwarf_diename(die);
			if (tname && (isalpha(*tname) || *tname == '_'))
				td->name = xstrdup(tname);
			else
				td->name = make_enum_name(die);

			xasprintf(&enum_def, "enum %s { %s }", td->name, enum_str);
			pr_dbg3("type: %s\n", enum_str);

			td->size = type_size(die, sizeof(int));

			parse_enum_string(enum_def, &td->arg_data->dinfo->enums);
			free(enum_def);
			free(enum_str);
			return true;

		case DW_TAG_structure_type:
		case DW_TAG_union_type:
		case DW_TAG_class_type:
			/* ignore struct with no member (when called-by-value) */
			if (td->pointer)
				break;

			td->fmt = ARG_FMT_STRUCT;
			if (is_empty_aggregate(die))
				td->size = 0;
			else
				td->size = type_size(die, sizeof(long));
			place_struct_members(die, ad, td);
			pr_dbg3("type: struct/union/class: %s\n", td->name ?: "(no name)");
			return true;

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
				td->fmt = ARG_FMT_PTR;
				pr_dbg3("type: function pointer\n");
				/* prevent to look up (return) type more */
				return true;
			}
			break;
		default:
			pr_dbg3("type: %s (tag %d)\n", dwarf_diename(die), dwarf_tag(die));
			break;
		}
	}

	tname = dwarf_diename(die);

	if (td->pointer) {
		td->size = sizeof(long) * 8;

		/* treat 'char *' as string */
		if (td->pointer == 1 && tname && !strcmp(tname, "char"))
			td->fmt = ARG_FMT_STR;
		else
			td->fmt = ARG_FMT_PTR;
		return true;
	}

	td->size = type_size(die, sizeof(long));

	if (dwarf_tag(die) != DW_TAG_base_type)
		return false;

	if (!strcmp(tname, "char"))
		td->fmt = ARG_FMT_CHAR;
	else if (!strcmp(tname, "float"))
		td->fmt = ARG_FMT_FLOAT;
	else if (!strcmp(tname, "double"))
		td->fmt = ARG_FMT_FLOAT;
	else if (!strcmp(tname, "long double")) {
		td->fmt = ARG_FMT_FLOAT;
		td->size = 80;
	}

	return true;
}

static bool add_type_info(char *spec, size_t len, Dwarf_Die *die, struct arg_data *ad)
{
	struct type_data data = {
		.fmt = ARG_FMT_AUTO,
		.arg_data = ad,
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

	if (!resolve_type_info(die, ad, &data)) {
		ad->broken = data.broken;
		return false;
	}

	ad->last_fmt = data.fmt;
	ad->last_size = data.size / 8;

	switch (data.fmt) {
	case ARG_FMT_CHAR:
		strcat(spec, "/c");
		break;
	case ARG_FMT_STR:
		if (!ad->broken)
			strcat(spec, "/s");
		break;
	case ARG_FMT_STD_STRING:
		strcat(spec, "/S");
		break;
	case ARG_FMT_FLOAT:
		if (ad->idx) { /* for arguments */
			snprintf(spec, len, "fparg%d/%zu", ++ad->fpidx, data.size);
			/* do not increase index of integer arguments */
			--ad->idx;
		}
		else { /* for return values */
			char sz[16];

			snprintf(sz, sizeof(sz), "%d", (int)data.size);
			strcat(spec, "/f");
			strcat(spec, sz);
		}
		break;
	case ARG_FMT_PTR:
		strcat(spec, "/p");
		break;
	case ARG_FMT_ENUM:
		strcat(spec, "/e:");
		strcat(spec, data.name);
		break;
	case ARG_FMT_STRUCT:
		if (ad->idx) { /* for arguments */
			snprintf(spec, len, "arg%d/t%d", ad->idx, ad->last_size);
		}
		else { /* for return valus */
			char sz[16];

			snprintf(sz, sizeof(sz), "/t%d", ad->last_size);
			strcat(spec, sz);
		}
		if (data.name) {
			int len1 = strlen(spec) + 1;
			int len2 = strlen(data.name);

			strcat(spec, ":");
			if (len1 + len2 >= ARGSPEC_MAX_SIZE) {
				strncat(spec, data.name, ARGSPEC_MAX_SIZE - len1 - 1);
				spec[ARGSPEC_MAX_SIZE - 1] = '\0';
			}
			else {
				strcat(spec, data.name);
			}
		}
		break;
	default:
		break;
	}

	free(data.name);
	return true;
}

struct location_data {
	int type;
	int reg; // DWARF register number
	int offset; // stack offset
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
		int (*get_location_list)(Dwarf_Attribute * loc, Dwarf_Off offset, Dwarf_Addr * base,
					 Dwarf_Addr * start, Dwarf_Addr * end, Dwarf_Op * *ops,
					 size_t * len);
		Dwarf_Addr base, start, end;

		get_location_list = dlsym(RTLD_DEFAULT, "dwarf_getlocations");
		if (get_location_list == NULL)
			return false;

		/* try to get the first entry in the location list */
		if (get_location_list(&loc, 0, &base, &start, &end, &ops, &len) == -1)
			return false;
	}

	while (len--) {
		switch (ops->atom) {
		case DW_OP_fbreg:
			/*
			 * ignore minus offsets since it doesn't set the
			 * frame-pointer yet (we're before the prologue).
			 */
			if ((int)ops->number >= 0) {
				ld->type = ARG_TYPE_STACK;
				ld->offset = DIV_ROUND_UP(ops->number, sizeof(long)) + 1;
				pr_dbg3("location: stack (%d)\n", ld->offset);
			}
			break;

		case DW_OP_reg0 ... DW_OP_reg31:
			ld->type = ARG_TYPE_REG;
			ld->reg = ops->atom;
			pr_dbg3("location: reg (%d)\n", ld->reg);
			break;

		case DW_OP_regx:
			ld->type = ARG_TYPE_REG;
			ld->reg = ops->number;
			pr_dbg3("location: reg (%d)\n", ld->reg);
			break;
		default:
			pr_dbg3("unsupported exprloc (%d)\n", ops->atom);
			break;
		}
	}

	return true;
}

static void add_location(char *spec, size_t len, Dwarf_Die *die, struct arg_data *ad)
{
	struct location_data data = {
		.type = ARG_TYPE_INDEX,
	};
	char buf[32];
	const char *reg = NULL;
	enum uftrace_cpu_arch arch = host_cpu_arch();
	int i;

	get_arg_location(die, &data);

	/*
	 * If a struct argument was passed by value, all the remaining arguments
	 * need to have specific location info because the index-based location
	 * would be incorrect.
	 */
	if (ad->struct_passed && data.type == ARG_TYPE_INDEX) {
		switch (ad->last_fmt) {
		case ARG_FMT_STRUCT:
			if (ad->struct_reg_cnt == 0)
				break;

			/*
			 * If struct_reg_cnt is set, it's guaranteed
			 * that enough registers are ready.
			 */
			for (i = 0; i < ad->struct_reg_cnt; i++) {
				int param = ad->struct_regs[i];
				if (param == PARAM_CLASS_INT || param == PARAM_CLASS_PTR) {
					reg = arch_register_argspec_name(arch, true, ad->reg_pos);
					ad->reg_pos++;
				}
				else {
					reg = arch_register_argspec_name(arch, false,
									 ad->fpreg_pos);
					ad->fpreg_pos++;
				}
				snprintf(buf, sizeof(buf), "%s%s", i ? "+" : "%", reg);
				strcat(spec, buf);
			}
			/* we are done now */
			return;
		case ARG_FMT_FLOAT:
			if (ad->fpreg_pos < ad->fpreg_max) {
				reg = arch_register_argspec_name(arch, false, ad->fpreg_pos);
				ad->fpreg_pos++;
			}
			break;
		default:
			if (ad->reg_pos < ad->reg_max) {
				reg = arch_register_argspec_name(arch, true, ad->reg_pos);
				ad->reg_pos++;
			}
			break;
		}

		if (reg) {
			snprintf(buf, sizeof(buf), "%%%s", reg);
			strcat(spec, buf);
		}
		return;
	}

	switch (data.type) {
	case ARG_TYPE_REG:
		reg = arch_register_dwarf_name(host_cpu_arch(), data.reg);

		if (strcmp(reg, "invalid register")) {
			snprintf(buf, sizeof(buf), "%%%s", reg);
			strcat(spec, buf);

			if (ad->last_fmt == ARG_FMT_FLOAT)
				ad->fpreg_pos++;
			else
				ad->reg_pos++;
		}
		break;
	case ARG_TYPE_STACK:
		snprintf(buf, sizeof(buf), "%%stack+%d", data.offset);
		strcat(spec, buf);

		ad->stack_ofs = data.offset + ALIGN(ad->last_size, sizeof(long));
		break;
	default:
		if (ad->last_fmt == ARG_FMT_FLOAT)
			ad->fpreg_pos++;
		else
			ad->reg_pos++;
		break;
	}
}

static int get_retspec(Dwarf_Die *die, void *data, bool found)
{
	struct arg_data *ad = data;
	char buf[ARGSPEC_MAX_SIZE];
	Dwarf_Die spec;

	ad->has_retspec = true;

	if (found)
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

	if (ad->last_fmt == ARG_FMT_STRUCT && ad->struct_return_needs_ptr &&
	    ad->struct_reg_cnt == 1 && ad->struct_regs[0] == PARAM_CLASS_PTR) {
		ad->struct_passed = true;
		ad->reg_pos = 1;
	}
	else if (ad->last_fmt == ARG_FMT_STD_STRING) {
		ad->struct_passed = true;
		ad->reg_pos = 1;
	}

	return 1;
}

static int get_argspec(Dwarf_Die *die, void *data)
{
	struct arg_data *ad = data;
	Dwarf_Die arg;
	Dwarf_Addr offset = 0;
	int count = 0;

	dwarf_lowpc(die, &offset);
	pr_dbg2("found '%s' function for argspec (%#lx)\n", ad->name, offset);

	if (!ad->has_retspec) {
		/* update the return type info first */
		get_retspec(die, ad, false);

		free(ad->argspec);
		ad->argspec = NULL;
	}
	ad->has_retspec = false;

	if (dwarf_child(die, &arg) != 0) {
		pr_dbg2("has no argument (children)\n");
		return 0;
	}

	do {
		char buf[ARGSPEC_MAX_SIZE];

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
	} while (dwarf_siblingof(&arg, &arg) == 0);

	return count;
}

struct build_data {
	struct uftrace_dbg_info *dinfo;
	struct uftrace_symtab *symtab;
	int nr_args;
	int nr_rets;
	struct uftrace_pattern *args;
	struct uftrace_pattern *rets;
	struct cu_files files;
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

static bool match_name(struct uftrace_symbol *sym, char *name)
{
	bool ret;

	if (sym == NULL)
		return false;

	if (!strcmp(sym->name, name))
		return true;

	/* name is mangled C++/Rust symbol */
	if (name[0] == '_' && name[1] == 'Z') {
		char *demangled_name = demangle(name);

		ret = !strcmp(sym->name, demangled_name);
		free(demangled_name);
		return ret;
	}

	/* name is already (fully) demangled */
	if (strpbrk(name, "(<:>)")) {
		char *demangled_sym = NULL;
		char *last_sym;
		char *last_name;

		if (demangler == DEMANGLE_FULL)
			return !strcmp(sym->name, name);

		if (demangler == DEMANGLE_NONE)
			demangled_sym = demangle(sym->name);

		last_sym = find_last_component(sym->name);
		last_name = find_last_component(name);

		ret = !strcmp(last_sym, last_name);

		free(last_sym);
		free(last_name);
		free(demangled_sym);
		return ret;
	}

	return false;
}

static void get_source_location(Dwarf_Die *die, struct build_data *bd, struct uftrace_symbol *sym)
{
	ptrdiff_t sym_idx;
	const char *filename;
	struct uftrace_dbg_info *dinfo = bd->dinfo;
	struct uftrace_dbg_file *dfile = NULL;
	int dline = 0;

	sym_idx = sym - bd->symtab->sym;

	if (dwarf_hasattr(die, DW_AT_decl_file)) {
		if (dwarf_decl_line(die, &dline) == 0) {
			filename = dwarf_decl_file(die);
			/*
			 * The dwarf_decl_file() can return 0 for DWARF-5 as it allows
			 * file index of 0 (for default file) which is treated invalid
			 * in libdw.  This is unfortunate but we can access the file
			 * table with index 0 directly since we checked the DIE has the
			 * both decl file and decl line.
			 */
			if (filename == NULL)
				filename = dwarf_filesrc(bd->files.files, 0, NULL, NULL);
			dfile = get_debug_file(dinfo, filename);
		}
	}
	else {
		Dwarf_Die cudie;
		Dwarf_Line *line;
		unsigned long dwarf_addr = sym_to_dwarf_addr(dinfo, sym->addr);
		unsigned long limit_addr = dwarf_addr + sym->size;
		int search_limit = 10;

		dwarf_diecu(die, &cudie, NULL, NULL);

		/*
		 * This loop is needed because gcc doesn't create dwarf info at NOP
		 * instruction address so dwarf_getsrc_die() returns NULL.
		 * To avoid this problem, we move forward until we see the first actual
		 * instruction address of the function, which has a valid dwarf info.
		 * The search is limited to the function size.
		 */
		do {
			line = dwarf_getsrc_die(&cudie, dwarf_addr);
			dwarf_addr += NOP_INSN_SIZE;
		} while (line == NULL && --search_limit > 0 && dwarf_addr < limit_addr);

		filename = dwarf_linesrc(line, NULL, NULL);
		dfile = get_debug_file(dinfo, filename);
		dwarf_lineno(line, &dline);
	}

	if (dfile == NULL)
		return;

	dinfo->locs[sym_idx].sym = sym;
	dinfo->locs[sym_idx].file = dfile;
	dinfo->locs[sym_idx].line = dline;
	dinfo->nr_locs_used++;
}

static int get_dwarfspecs_cb(Dwarf_Die *die, void *data)
{
	struct build_data *bd = data;
	struct arg_data ad;
	char *name = NULL;
	Dwarf_Addr offset;
	struct uftrace_symbol *sym;
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
	offset = dwarf_to_sym_addr(bd->dinfo, offset);

	if (dwarf_hasattr_integrate(die, DW_AT_linkage_name))
		name = str_attr(die, DW_AT_linkage_name, true);
	if (name == NULL)
		name = (char *)dwarf_diename(die);
	if (unlikely(name == NULL))
		return DWARF_CB_OK;

	pr_dbg3("func %s (at %lx)\n", name, offset);

	/*
	 * double-check symbol table has same info.
	 * we add 1 to the offset because of ARM(THUMB) symbols
	 * but DWARF doesn't know about it.
	 */
	sym = find_sym(bd->symtab, offset + 1);
	if (sym == NULL || !match_name(sym, name)) {
		pr_dbg4("skip unknown debug info: %s / %s (%lx)\n", sym ? sym->name : "no name",
			name, offset);
		goto out;
	}

	get_source_location(die, bd, sym);

	setup_arg_data(&ad, sym->name, bd->dinfo);

	for (i = 0; i < bd->nr_rets; i++) {
		if (!match_filter_pattern(&bd->rets[i], sym->name))
			continue;

		if (get_retspec(die, &ad, true)) {
			add_debug_entry(&bd->dinfo->rets, sym->name, sym->addr, ad.argspec);
		}

		free(ad.argspec);
		ad.argspec = NULL;
		break;
	}

	for (i = 0; i < bd->nr_args; i++) {
		if (!match_filter_pattern(&bd->args[i], sym->name))
			continue;

		if (get_argspec(die, &ad)) {
			add_debug_entry(&bd->dinfo->args, sym->name, sym->addr, ad.argspec);
		}

		free(ad.argspec);
		ad.argspec = NULL;
		break;
	}

out:
	return DWARF_CB_OK;
}

struct comp_dir_entry {
	struct rb_node node;
	char *name;
	int nr_used; /* number of times comp_dir is used in module */
	int nr_locs; /* number of source locations built into comp_dir */
};

static int add_comp_dir(struct rb_root *root, char *name, int nr_locs)
{
	struct comp_dir_entry *entry, *iter;
	struct rb_node *parent = NULL;
	struct rb_node **p = &root->rb_node;
	int cmp;

	pr_dbg3("add dir entry: %s (%d)\n", name, nr_locs);

	while (*p) {
		parent = *p;
		iter = rb_entry(parent, struct comp_dir_entry, node);

		cmp = strcmp(iter->name, name);
		if (cmp == 0) {
			iter->nr_used++;
			iter->nr_locs += nr_locs;
			return 0;
		}

		if (cmp > 0)
			p = &parent->rb_left;
		else
			p = &parent->rb_right;
	}

	entry = xmalloc(sizeof(*entry));
	entry->name = xstrdup(name);
	entry->nr_locs = nr_locs;
	entry->nr_used = 1;

	rb_link_node(&entry->node, parent, p);
	rb_insert_color(&entry->node, root);

	return 0;
}

static void free_comp_dir(struct rb_root *root)
{
	struct comp_dir_entry *entry;
	struct rb_node *node;

	while (!RB_EMPTY_ROOT(root)) {
		node = rb_first(root);
		entry = rb_entry(node, typeof(*entry), node);

		rb_erase(node, root);
		free(entry->name);
		free(entry);
	}
}

static struct comp_dir_entry *get_max_comp_dir(struct comp_dir_entry *a, struct comp_dir_entry *b)
{
	if (a->nr_used > b->nr_used || (a->nr_used == b->nr_used && a->nr_locs > b->nr_locs))
		return a;
	else
		return b;
}

static char *get_base_comp_dir(struct rb_root *dirs)
{
	struct rb_node *rbnode;
	struct comp_dir_entry *e;
	struct comp_dir_entry *prev = NULL;
	struct comp_dir_entry *max;

	if (RB_EMPTY_ROOT(dirs))
		return NULL;

	rbnode = rb_first(dirs);
	max = rb_entry(rbnode, typeof(*e), node);
	prev = max;
	rbnode = rb_next(rbnode);

	while (rbnode != NULL) {
		e = rb_entry(rbnode, typeof(*e), node);

		if (!strncmp(e->name, prev->name, strlen(prev->name))) {
			prev->nr_used += e->nr_used;
			prev->nr_locs += e->nr_locs;
		}
		else {
			max = get_max_comp_dir(prev, max);
			prev = e;
		}

		rbnode = rb_next(rbnode);
	}

	max = get_max_comp_dir(prev, max);

	return max->name;
}

static void build_dwarf_info(struct uftrace_dbg_info *dinfo, struct uftrace_symtab *symtab,
			     enum uftrace_pattern_type ptype, struct strv *args, struct strv *rets)
{
	Dwarf_Off curr = 0;
	Dwarf_Off next = 0;
	size_t header_sz = 0;
	struct uftrace_pattern *arg_patt;
	struct uftrace_pattern *ret_patt;
	struct rb_root comp_dirs = RB_ROOT;
	char *dir;
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
	while (dwarf_nextcu(dinfo->dw, curr, &next, &header_sz, NULL, NULL, NULL) == 0) {
		Dwarf_Die cudie;
		struct build_data bd = {
			.dinfo = dinfo,
			.symtab = symtab,
			.args = arg_patt,
			.rets = ret_patt,
			.nr_args = args->nr,
			.nr_rets = rets->nr,
		};

		if (dwarf_offdie(dinfo->dw, curr + header_sz, &cudie) == NULL)
			break;

		if (dwarf_tag(&cudie) != DW_TAG_compile_unit &&
		    dwarf_tag(&cudie) != DW_TAG_partial_unit)
			break;

		if (uftrace_done)
			break;

		/* do not read arguments when it's not needed */
		if (!dinfo->needs_args) {
			bd.nr_args = 0;
			bd.nr_rets = 0;
		}

		dwarf_getsrcfiles(&cudie, &bd.files.files, &bd.files.num);

		dwarf_getfuncs(&cudie, get_dwarfspecs_cb, &bd, 0);

		if (dwarf_hasattr(&cudie, DW_AT_comp_dir)) {
			dir = str_attr(&cudie, DW_AT_comp_dir, false);
			add_comp_dir(&comp_dirs, dir, dinfo->nr_locs_used);
			dinfo->nr_locs_used = 0;
		}

		curr = next;
	}

	dir = get_base_comp_dir(&comp_dirs);
	if (dir) {
		pr_dbg3("base dir: %s\n", dir);
		dinfo->base_dir = xstrdup(dir);
		free_comp_dir(&comp_dirs);
	}
	else {
		dinfo->base_dir = NULL;
	}

	for (i = 0; i < args->nr; i++)
		free_filter_pattern(&arg_patt[i]);
	free(arg_patt);
	for (i = 0; i < rets->nr; i++)
		free_filter_pattern(&ret_patt[i]);
	free(ret_patt);
}

#else /* !HAVE_LIBDW */

static int setup_dwarf_info(const char *filename, struct uftrace_dbg_info *dinfo,
			    unsigned long offset, bool force)
{
	dinfo->dw = NULL;
	dinfo->dwfl = NULL;
	return 0;
}

static void build_dwarf_info(struct uftrace_dbg_info *dinfo, struct uftrace_symtab *symtab,
			     enum uftrace_pattern_type ptype, struct strv *args, struct strv *rets)
{
}

static void release_dwarf_info(struct uftrace_dbg_info *dinfo)
{
}

#endif /* !HAVE_LIBDW */

static void setup_debug_info(struct uftrace_dbg_info *dinfo)
{
	memset(dinfo, 0, sizeof(*dinfo));
	dinfo->loaded = true;
}

static void release_debug_info(struct uftrace_dbg_info *dinfo)
{
	free_debug_entry(&dinfo->args);
	free_debug_entry(&dinfo->rets);
	release_enum_def(&dinfo->enums);
	release_debug_file(&dinfo->files);

	free(dinfo->locs);
	dinfo->locs = NULL;

	free(dinfo->base_dir);
	dinfo->base_dir = NULL;

	dinfo->loaded = false;
}

/* find argspecs only have function name (pattern) */
static void extract_dwarf_args(char *argspec, char *retspec, struct strv *pargs, struct strv *prets)
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

void prepare_debug_info(struct uftrace_sym_info *sinfo, enum uftrace_pattern_type ptype,
			char *argspec, char *retspec, bool auto_args, bool force)
{
	struct uftrace_mmap *map;
	struct strv dwarf_args = STRV_INIT;
	struct strv dwarf_rets = STRV_INIT;

	if (sinfo->flags & SYMTAB_FL_SYMS_DIR) {
		load_debug_info(sinfo, true);
		return;
	}

	extract_dwarf_args(argspec, retspec, &dwarf_args, &dwarf_rets);

	if (auto_args) {
		if (ptype == PATT_REGEX) {
			strv_append(&dwarf_args, ".");
			strv_append(&dwarf_rets, ".");
		}
		else { /* PATT_GLOB */
			strv_append(&dwarf_args, "*");
			strv_append(&dwarf_rets, "*");
		}
	}

	/* file and line info need be saved regardless of argspec */
	pr_dbg("prepare debug info\n");

	for_each_map(sinfo, map) {
		struct uftrace_symtab *stab = &map->mod->symtab;
		struct uftrace_dbg_info *dinfo = &map->mod->dinfo;

		if (map->mod == NULL || map->mod->dinfo.loaded)
			continue;

		setup_debug_info(dinfo);

		setup_dwarf_info(map->libname, dinfo, map->start, force);
		build_dwarf_info(dinfo, stab, ptype, &dwarf_args, &dwarf_rets);
		release_dwarf_info(dinfo);
	}

	strv_free(&dwarf_args);
	strv_free(&dwarf_rets);
}

void finish_debug_info(struct uftrace_sym_info *sinfo)
{
	struct uftrace_mmap *map;

	for_each_map(sinfo, map) {
		if (map->mod == NULL || !map->mod->dinfo.loaded)
			continue;

		release_debug_info(&map->mod->dinfo);
	}
}

static bool match_debug_file(const char *dbgname, const char *pathname, char *build_id)
{
	FILE *fp;
	bool ret = true;
	char *line = NULL;
	size_t len = 0;

	fp = fopen(dbgname, "r");
	if (fp == NULL)
		return false;

	while (getline(&line, &len, fp) >= 0) {
		if (line[0] != '#')
			break;

		/* remove trailing newline */
		line[strlen(line) - 1] = '\0';

		if (!strncmp(line, "# path name: ", 13))
			ret = !strcmp(line + 13, pathname);
		if (!strncmp(line, "# build-id: ", 12))
			ret = !strcmp(line + 12, build_id);
	}
	free(line);
	fclose(fp);
	return ret;
}

static FILE *create_debug_file(const char *dirname, const char *filename, char *build_id)
{
	FILE *fp;
	char *tmp;

	xasprintf(&tmp, "%s/%s.dbg", dirname, uftrace_basename(filename));
	if (match_debug_file(tmp, filename, build_id)) {
		free(tmp);
		return NULL;
	}

	fp = fopen(tmp, "ax");
	if (fp == NULL && errno == EEXIST) {
		char *dbgfile;
		int len;

		dbgfile = make_new_symbol_filename(tmp, filename, build_id);
		len = strlen(dbgfile);
		strncpy(dbgfile + len - 3, "dbg", 4);

		free(tmp);
		tmp = dbgfile;
		fp = fopen(tmp, "ax");
	}

	free(tmp);
	return fp;
}

static void close_debug_file(FILE *fp, const char *dirname, const char *filename, char *build_id)
{
	bool delete = !ftell(fp);
	char *tmp;

	fclose(fp);

	if (!delete)
		return;

	pr_dbg2("delete debug file for %s\n", filename);

	xasprintf(&tmp, "%s/%s.dbg", dirname, filename);
	if (!match_debug_file(tmp, filename, build_id)) {
		char *dbgfile;
		int len;

		dbgfile = make_new_symbol_filename(tmp, filename, build_id);
		len = strlen(dbgfile);
		strncpy(dbgfile + len - 3, "dbg", 4);

		free(tmp);
		tmp = dbgfile;
		delete = false;

		fp = fopen(tmp, "r");
		if (fp != NULL) {
			fseek(fp, 0, SEEK_END);
			delete = !ftell(fp);
			fclose(fp);
		}

		if (!delete) {
			free(tmp);
			return;
		}
	}

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

static void save_debug_entries(struct uftrace_dbg_info *dinfo, const char *dirname,
			       const char *filename, char *build_id)
{
	size_t i;
	FILE *fp;
	int idx;
	int len;

	fp = create_debug_file(dirname, filename, build_id);
	if (fp == NULL)
		return; /* somebody already did that! */

	fprintf(fp, "# path name: %s\n", filename);
	if (strlen(build_id) > 0)
		fprintf(fp, "# build-id: %s\n", build_id);

	save_enum_def(&dinfo->enums, fp);

	for (i = 0; i < dinfo->nr_locs; i++) {
		struct uftrace_dbg_loc *loc = &dinfo->locs[i];
		struct debug_entry *entry;

		if (loc->sym == NULL)
			continue;

		save_debug_file(fp, 'F', loc->sym->name, loc->sym->addr);

		idx = 0;
		if (dinfo->base_dir) {
			len = strlen(dinfo->base_dir);
			if (!strncmp(loc->file->name, dinfo->base_dir, len))
				idx = len + 1;
		}

		/* skip common parts with compile directory  */
		save_debug_file(fp, 'L', loc->file->name + idx, loc->line);

		entry = find_debug_entry(&dinfo->args, loc->sym->addr);
		if (entry && entry->spec)
			save_debug_file(fp, 'A', entry->spec, 0);

		entry = find_debug_entry(&dinfo->rets, loc->sym->addr);
		if (entry && entry->spec)
			save_debug_file(fp, 'R', entry->spec, 0);
	}

	close_debug_file(fp, dirname, uftrace_basename(filename), build_id);
}

void save_debug_info(struct uftrace_sym_info *sinfo, const char *dirname)
{
	struct uftrace_mmap *map;

	for_each_map(sinfo, map) {
		if (map->mod == NULL || !map->mod->dinfo.loaded)
			continue;

		save_debug_entries(&map->mod->dinfo, dirname, map->libname, map->build_id);
	}
}

static int load_debug_file(struct uftrace_dbg_info *dinfo, struct uftrace_symtab *symtab,
			   const char *dirname, const char *filename, char *build_id,
			   bool needs_srcline)
{
	char *pathname;
	FILE *fp;
	char *line = NULL;
	size_t len = 0;
	int ret = -1;
	char *func = NULL;
	uint64_t offset = 0;

	xasprintf(&pathname, "%s/%s.dbg", dirname, uftrace_basename(filename));

	if (!match_debug_file(pathname, filename, build_id)) {
		char *newfile;

		newfile = make_new_symbol_filename(pathname, filename, build_id);
		len = strlen(newfile);
		strcpy(newfile + len - 3, "dbg");

		/* replace pathname */
		free(pathname);
		pathname = newfile;
		len = 0;
	}

	fp = fopen(pathname, "r");
	if (fp == NULL) {
		if (errno == ENOENT) {
			free(pathname);
			return -1;
		}

		pr_err("failed to open: %s", pathname);
	}

	pr_dbg2("load debug info from %s\n", pathname);

	dinfo->args = RB_ROOT;
	dinfo->rets = RB_ROOT;
	dinfo->enums = RB_ROOT;
	dinfo->files = RB_ROOT;
	dinfo->loaded = true;

	if (needs_srcline && dinfo->locs == NULL) {
		dinfo->nr_locs = symtab->nr_sym;
		dinfo->locs = xcalloc(dinfo->nr_locs, sizeof(*dinfo->locs));
	}

	while (getline(&line, &len, fp) >= 0) {
		char *pos;
		struct rb_root *root = &dinfo->args;
		struct uftrace_symbol *sym;
		ptrdiff_t sym_idx;
		unsigned long lineno;

		if (line[0] == '#')
			continue;

		if (line[1] != ':' || line[2] != ' ')
			goto out;

		/* remove trailing newline */
		line[strlen(line) - 1] = '\0';

		switch (line[0]) {
		case 'F':
			offset = strtoul(&line[3], &pos, 16);

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
			if (!needs_srcline)
				break;

			sym = find_sym(symtab, offset);
			if (sym == NULL)
				goto out;

			lineno = strtoul(&line[3], &pos, 0);

			sym_idx = sym - symtab->sym;
			dinfo->locs[sym_idx].sym = sym;
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

void load_module_debug_info(struct uftrace_module *mod, const char *dirname, bool needs_srcline)
{
	struct uftrace_dbg_info *dinfo;

	dinfo = &mod->dinfo;

	if (!debug_info_has_location(dinfo) && !debug_info_has_argspec(dinfo)) {
		load_debug_file(dinfo, &mod->symtab, dirname, mod->name, mod->build_id,
				needs_srcline);
	}
}

void load_debug_info(struct uftrace_sym_info *sinfo, bool needs_srcline)
{
	struct uftrace_mmap *map;

	for_each_map(sinfo, map) {
		struct uftrace_module *mod = map->mod;
		struct uftrace_symtab *stab;
		struct uftrace_dbg_info *dinfo;

		if (map->mod == NULL)
			continue;

		stab = &mod->symtab;
		dinfo = &mod->dinfo;

		if (!debug_info_has_location(dinfo) && !debug_info_has_argspec(dinfo)) {
			load_debug_file(dinfo, stab, sinfo->symdir, map->libname, map->build_id,
					needs_srcline);
		}
	}
}

char *get_dwarf_argspec(struct uftrace_dbg_info *dinfo, char *name, unsigned long addr)
{
	struct debug_entry *entry = find_debug_entry(&dinfo->args, addr);

	return entry ? entry->spec : NULL;
}

char *get_dwarf_retspec(struct uftrace_dbg_info *dinfo, char *name, unsigned long addr)
{
	struct debug_entry *entry = find_debug_entry(&dinfo->rets, addr);

	return entry ? entry->spec : NULL;
}

struct uftrace_dbg_loc *find_file_line(struct uftrace_sym_info *sinfo, uint64_t addr)
{
	struct uftrace_mmap *map;
	struct uftrace_symtab *symtab;
	struct uftrace_dbg_info *dinfo;
	struct uftrace_symbol *sym = NULL;
	ptrdiff_t idx;

	map = find_map(sinfo, addr);

	/* TODO: support kernel debug info */
	if (map == MAP_KERNEL)
		return NULL;

	if (map == NULL || map->mod == NULL)
		return NULL;

	symtab = &map->mod->symtab;
	dinfo = &map->mod->dinfo;

	if (debug_info_has_location(dinfo))
		sym = find_sym(symtab, addr - map->start);

	if (sym == NULL)
		return NULL;

	idx = sym - symtab->sym;
	return &dinfo->locs[idx];
}

#ifdef UNIT_TEST

#ifdef HAVE_LIBDW
struct comp_dir {
	char *name;
	int nr_loc;
};

/* test: same number of compilation unit */
TEST_CASE(dwarf_srcline_prefix1)
{
	struct rb_root dirs = RB_ROOT;
	int i;

	static struct comp_dir test_dirs[] = {
		{ "/home/soft/uftrace/cmds", 1 },
		{ "/home/soft/uftrace/utils", 1 },
		{ "/home/soft/uftrace/libmcount", 1 },
	};

	for (i = 0; i < sizeof(test_dirs) / sizeof(struct comp_dir); i++) {
		pr_dbg("comp_dir=%s (count=%d)\n", test_dirs[i].name, test_dirs[i].nr_loc);
		add_comp_dir(&dirs, test_dirs[i].name, test_dirs[i].nr_loc);
	}

	pr_dbg("selected base_dir=%s\n", "/home/soft/uftrace/cmds");
	TEST_STREQ(get_base_comp_dir(&dirs), "/home/soft/uftrace/cmds");

	free_comp_dir(&dirs);

	return TEST_OK;
}

/* test: number of compilation unit */
TEST_CASE(dwarf_srcline_prefix2)
{
	struct rb_root dirs = RB_ROOT;
	int i;

	static struct comp_dir test_dirs[] = {
		{ "/home/a/tests", 1 },
		{ "/home/soft/uftrace/cmds", 1 },
		{ "/home/soft/uftrace", 1 },
	};

	for (i = 0; i < sizeof(test_dirs) / sizeof(struct comp_dir); i++) {
		pr_dbg("comp_dir=%s (count=%d)\n", test_dirs[i].name, test_dirs[i].nr_loc);
		add_comp_dir(&dirs, test_dirs[i].name, test_dirs[i].nr_loc);
	}

	pr_dbg("selected base_dir=%s\n", "/home/soft/uftrace");
	TEST_STREQ(get_base_comp_dir(&dirs), "/home/soft/uftrace");

	free_comp_dir(&dirs);

	return TEST_OK;
}

/* test: number of debug info of compilation unit */
TEST_CASE(dwarf_srcline_prefix3)
{
	struct rb_root dirs = RB_ROOT;
	int i;

	static struct comp_dir test_dirs[] = {
		{ "/home/a/tests", 1 },
		{ "/home/a/tests", 3 },
		{ "/home/soft/uftrace/cmds", 4 },
		{ "/home/soft/uftrace", 1 },
	};

	for (i = 0; i < sizeof(test_dirs) / sizeof(struct comp_dir); i++) {
		pr_dbg("comp_dir=%s (count=%d)\n", test_dirs[i].name, test_dirs[i].nr_loc);
		add_comp_dir(&dirs, test_dirs[i].name, test_dirs[i].nr_loc);
	}

	pr_dbg("selected base_dir=%s\n", "/home/soft/uftrace");
	TEST_STREQ(get_base_comp_dir(&dirs), "/home/soft/uftrace");

	free_comp_dir(&dirs);

	return TEST_OK;
}

/* test: no compilation unit */
TEST_CASE(dwarf_srcline_prefix4)
{
	struct rb_root dirs = RB_ROOT;

	pr_dbg("check empty comp_dir\n");
	TEST_EQ(get_base_comp_dir(&dirs), NULL);

	return TEST_OK;
}
#endif /* HAVE_LIBDW */

static void setup_test_debug_info(struct uftrace_module *mod)
{
	struct uftrace_dbg_info *dinfo = &mod->dinfo;
	struct uftrace_dbg_file *file;
	int i;

	file = xzalloc(sizeof(*file));
	file->name = xstrdup(mod->name);

	dinfo->files.rb_node = &file->node;
	dinfo->nr_locs = mod->symtab.nr_sym;

	dinfo->locs = xcalloc(dinfo->nr_locs, sizeof(*dinfo->locs));
	for (i = 0; i < dinfo->nr_locs; i++) {
		struct uftrace_symbol *sym = &mod->symtab.sym[i];
		struct uftrace_dbg_loc *loc = &dinfo->locs[i];
		char argspec[32];

		loc->sym = sym;
		loc->file = file;
		loc->line = (i + 1) * 10;

		snprintf(argspec, sizeof(argspec), "arg%d", i + 1);
		add_debug_entry(&dinfo->args, sym->name, sym->addr, argspec);
	}
}

static void init_test_module_info(struct uftrace_module **pmod1, struct uftrace_module **pmod2,
				  bool init_debug_info)
{
	struct uftrace_module *mod1, *mod2;
	const char mod1_name[] = "/some/where/module/name";
	const char mod2_name[] = "/different/path/name";
	const char mod1_build_id[] = "1234567890abcdef";
	const char mod2_build_id[] = "DUMMY-BUILD-ID";
	static struct uftrace_symbol mod1_syms[] = {
		{ 0x1000, 0x1000, ST_PLT_FUNC, "func1" },
		{ 0x2000, 0x1000, ST_LOCAL_FUNC, "func2" },
		{ 0x3000, 0x1000, ST_GLOBAL_FUNC, "func3" },
	};
	static struct uftrace_symbol mod2_syms[] = {
		{ 0x5000, 0x1000, ST_PLT_FUNC, "funcA" },
		{ 0x6000, 0x1000, ST_PLT_FUNC, "funcB" },
		{ 0x7000, 0x1000, ST_PLT_FUNC, "funcC" },
		{ 0x8000, 0x1000, ST_GLOBAL_FUNC, "funcD" },
	};

	mod1 = xzalloc(sizeof(*mod1) + sizeof(mod1_name));
	mod2 = xzalloc(sizeof(*mod2) + sizeof(mod2_name));

	strcpy(mod1->name, mod1_name);
	strcpy(mod2->name, mod2_name);
	strcpy(mod1->build_id, mod1_build_id);
	strcpy(mod2->build_id, mod2_build_id);

	mod1->symtab.sym = mod1_syms;
	mod1->symtab.nr_sym = ARRAY_SIZE(mod1_syms);
	mod2->symtab.sym = mod2_syms;
	mod2->symtab.nr_sym = ARRAY_SIZE(mod2_syms);

	if (init_debug_info) {
		setup_test_debug_info(mod1);
		setup_test_debug_info(mod2);
	}

	*pmod1 = mod1;
	*pmod2 = mod2;
}

static int check_test_debug_info(struct uftrace_dbg_info *dinfo1, struct uftrace_dbg_info *dinfo2)
{
	int i;
	struct rb_node *node;
	struct debug_entry *save_entry, *load_entry;

	TEST_EQ(dinfo1->nr_locs, dinfo2->nr_locs);
	for (i = 0; i < dinfo1->nr_locs; i++) {
		struct uftrace_dbg_loc *save_loc = &dinfo1->locs[i];
		struct uftrace_dbg_loc *load_loc = &dinfo2->locs[i];

		TEST_STREQ(save_loc->sym->name, load_loc->sym->name);
		TEST_STREQ(save_loc->file->name, load_loc->file->name);
		TEST_EQ(save_loc->line, load_loc->line);
	}

	TEST_EQ(RB_EMPTY_ROOT(&dinfo1->args), false);
	TEST_EQ(RB_EMPTY_ROOT(&dinfo2->args), false);

	node = rb_first(&dinfo1->args);
	save_entry = rb_entry(node, struct debug_entry, node);
	node = rb_first(&dinfo2->args);
	load_entry = rb_entry(node, struct debug_entry, node);

	while (save_entry && load_entry) {
		TEST_STREQ(save_entry->name, load_entry->name);
		TEST_STREQ(save_entry->spec, load_entry->spec);
		TEST_EQ(save_entry->offset, load_entry->offset);

		node = rb_next(&save_entry->node);
		save_entry = node ? rb_entry(node, struct debug_entry, node) : NULL;
		node = rb_next(&load_entry->node);
		load_entry = node ? rb_entry(node, struct debug_entry, node) : NULL;
	}
	TEST_EQ(save_entry == NULL, load_entry == NULL);

	return TEST_OK;
}

TEST_CASE(dwarf_same_file_name1)
{
	struct uftrace_module *save_mod[2];
	struct uftrace_module *load_mod[2];
	int ret;

	/* recover from earlier failures */
	if (system("rm -f name*.dbg"))
		return TEST_NG;

	pr_dbg("init debug info and save .dbg files (no build-id)\n");
	init_test_module_info(&save_mod[0], &save_mod[1], true);
	save_debug_entries(&save_mod[0]->dinfo, ".", save_mod[0]->name, "");
	save_debug_entries(&save_mod[1]->dinfo, ".", save_mod[1]->name, "");

	pr_dbg("load .dbg files\n");
	init_test_module_info(&load_mod[0], &load_mod[1], false);

	ret = load_debug_file(&load_mod[0]->dinfo, &load_mod[0]->symtab, ".", load_mod[0]->name, "",
			      true);
	TEST_EQ(ret, 0);

	ret = load_debug_file(&load_mod[1]->dinfo, &load_mod[1]->symtab, ".", load_mod[1]->name, "",
			      true);
	TEST_EQ(ret, 0);

	pr_dbg("compare debug info1\n");
	ret = check_test_debug_info(&save_mod[0]->dinfo, &load_mod[0]->dinfo);
	if (ret == TEST_OK) {
		pr_dbg("compare debug info2\n");
		ret = check_test_debug_info(&save_mod[1]->dinfo, &load_mod[1]->dinfo);
	}

	pr_dbg("release debug info\n");
	release_debug_info(&save_mod[0]->dinfo);
	release_debug_info(&save_mod[1]->dinfo);
	release_debug_info(&load_mod[0]->dinfo);
	release_debug_info(&load_mod[1]->dinfo);
	free(save_mod[0]);
	free(save_mod[1]);
	free(load_mod[0]);
	free(load_mod[1]);

	if (system("rm -f name*.dbg"))
		return TEST_NG;

	return ret;
}

TEST_CASE(dwarf_same_file_name2)
{
	struct uftrace_module *save_mod[2];
	struct uftrace_module *load_mod[2];
	int ret;

	/* recover from earlier failures */
	if (system("rm -f name*.dbg"))
		return TEST_NG;

	pr_dbg("init debug info and save .dbg files (with build-id)\n");
	init_test_module_info(&save_mod[0], &save_mod[1], true);
	/* save them in the opposite order */
	save_debug_entries(&save_mod[1]->dinfo, ".", save_mod[1]->name, save_mod[1]->build_id);
	save_debug_entries(&save_mod[0]->dinfo, ".", save_mod[0]->name, save_mod[0]->build_id);

	pr_dbg("load .dbg files\n");
	init_test_module_info(&load_mod[0], &load_mod[1], false);

	ret = load_debug_file(&load_mod[0]->dinfo, &load_mod[0]->symtab, ".", load_mod[0]->name,
			      load_mod[0]->build_id, true);
	TEST_EQ(ret, 0);

	ret = load_debug_file(&load_mod[1]->dinfo, &load_mod[1]->symtab, ".", load_mod[1]->name,
			      load_mod[1]->build_id, true);
	TEST_EQ(ret, 0);

	pr_dbg("compare debug info1\n");
	ret = check_test_debug_info(&save_mod[0]->dinfo, &load_mod[0]->dinfo);
	if (ret == TEST_OK) {
		pr_dbg("compare debug info2\n");
		ret = check_test_debug_info(&save_mod[1]->dinfo, &load_mod[1]->dinfo);
	}

	pr_dbg("release debug info\n");
	release_debug_info(&save_mod[0]->dinfo);
	release_debug_info(&save_mod[1]->dinfo);
	release_debug_info(&load_mod[0]->dinfo);
	release_debug_info(&load_mod[1]->dinfo);
	free(save_mod[0]);
	free(save_mod[1]);
	free(load_mod[0]);
	free(load_mod[1]);

	if (system("rm -f name*.dbg"))
		return TEST_NG;

	return ret;
}

#endif /* UNIT_TEST */
