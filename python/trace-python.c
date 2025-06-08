/*
 * python extension module to trace python functions for uftrace
 *
 * Copyright (C) 2023,  Namhyung Kim <namhyung@gmail.com>
 *
 * Released under the GPL v2.
 */

#undef _XOPEN_SOURCE
#define PY_SSIZE_T_CLEAN
#include <Python.h>

#include <fcntl.h>
#include <fnmatch.h>
#include <regex.h>
#include <stdint.h>
#include <sys/mman.h>

#include "uftrace.h"
#include "utils/arch.h"
#include "utils/filter.h"
#include "utils/list.h"
#include "utils/rbtree.h"
#include "utils/shmem.h"
#include "utils/symbol.h"
#include "utils/utils.h"

/* python module state */
struct uftrace_py_state {
	PyObject *trace_func;
};

/* pointer to python tracing function (for libpython2.7) */
static PyObject *uftrace_func __maybe_unused;

/* RB tree of python_symbol to map code object to address */
static struct rb_root code_tree = RB_ROOT;

/* name of the python script file it's running */
static char *main_file;

/* pathname where the main python script is loaded from */
static char *main_dir;

/* length of the main_dir (for comparison) */
static int main_dir_len;

/* initial size of the symbol table and unit size for increment */
#define UFTRACE_PYTHON_SYMTAB_SIZE (1 * 1024 * 1024)

/* size of the symbol table header (including the padding) */
#define UFTRACE_PYTHON_SYMTAB_HDRSZ (48)

/* name of the shared memory region for symbol table: /uftrace-python-PID */
static char uftrace_shmem_name[32];

/* name of the shared memory region for debug info : /uftrace-python-dbg-PID */
static char uftrace_shmem_dbg_name[32];

/* file descriptor of the symbol table in a shared memory */
static int uftrace_shmem_fd;

/* file descriptor of the debug info table in a shared memory */
static int uftrace_shmem_dbg_fd;

/* current symbol table size */
static unsigned int uftrace_symtab_size;

/* current debug info table size */
static unsigned int uftrace_dbginfo_size;

/* python3 adds a C function frame for builtins.exec() */
static bool skip_first_frame;

/* whether it should collect srcline info */
static bool need_dbg_info = true;

/*
 * Symbol table header in a shared memory.
 *
 * It consists of count and offset, but they are combined into a val for
 * atomic update in case of multi-processing.  It also has some padding
 * before the actual data, and it will be converted to comments when it
 * writes the symtab to a file.
 *
 * The rest area in the shared memory is the content of the symbol file.
 */
union uftrace_python_symtab {
	uint64_t val; /* for atomic update */
	struct {
		uint32_t count; /* number of symbols */
		uint32_t offset; /* next position to write */
	};
	char padding[UFTRACE_PYTHON_SYMTAB_HDRSZ];
};

/* maintain a symbol table for .sym file */
static union uftrace_python_symtab *symtab;

/* just to maintain the same symbols for .dbg file */
static union uftrace_python_symtab *dbg_info;

/* symbol table entry to maintain mappings from code to addr */
struct uftrace_python_symbol {
	struct rb_node node;
	char *name;
	uint32_t addr;
	uint32_t flag;
};

/* struct uftrace_python_symbol flags */
#define UFT_PYSYM_F_LIBCALL (1U << 0)

/* linked list of filter names */
static LIST_HEAD(filters);

/* filter entry - currently function filters supported only */
struct uftrace_python_filter {
	struct list_head list;
	struct uftrace_pattern p;
	enum filter_mode mode;
};

/* track filter state - depth and time filters are handled in libmcount */
struct uftrace_python_filter_state {
	enum filter_mode mode;
	int count_in;
	int count_out;
};

/* global filter state - multiprocess will have their own copy */
static struct uftrace_python_filter_state filter_state;

/* control tracing of library calls (like python standard library) */
enum uftrace_python_libcall_mode {
	UFT_PY_LIBCALL_NONE,
	UFT_PY_LIBCALL_SINGLE,
	UFT_PY_LIBCALL_NESTED,
};

/* global libcall state */
static enum uftrace_python_libcall_mode libcall_mode = UFT_PY_LIBCALL_SINGLE;

/*
 * maintain the depth of library calls - multiprocess will have their own copy,
 * but it won't work with multi-threaded cases.
 */
static int libcall_count;

/* functions in libmcount.so */
static void (*cygprof_enter)(unsigned long child, unsigned long parent);
static void (*cygprof_exit)(unsigned long child, unsigned long parent);

#ifndef UNIT_TEST
/* dummy arch ops just for build */
const struct uftrace_arch_ops uftrace_arch_ops = {};
#endif

/* main trace function to be called from python interpreter */
static PyObject *uftrace_trace_python(PyObject *self, PyObject *args);

/* hooking function of os._exit() for proper cleanup */
static PyObject *uftrace_trace_python_exit(PyObject *self, PyObject *obj);

static __attribute__((used)) PyMethodDef uftrace_py_methods[] = {
	{ "trace", uftrace_trace_python, METH_VARARGS,
	  PyDoc_STR("trace python function with uftrace.") },
	{ "exit", uftrace_trace_python_exit, METH_O,
	  PyDoc_STR("exit the target program with cleanup.") },
	{ NULL, NULL, 0, NULL },
};

static void find_cygprof_funcs(const char *filename, unsigned long base_addr)
{
	struct uftrace_elf_data elf;
	struct uftrace_elf_iter iter;

	if (elf_init(filename, &elf) < 0)
		return;

	elf_for_each_shdr(&elf, &iter) {
		if (iter.shdr.sh_type == SHT_SYMTAB)
			break;
	}

	elf_for_each_symbol(&elf, &iter) {
		char *name = elf_get_name(&elf, &iter, iter.sym.st_name);

		if (!strcmp(name, "__cyg_profile_func_enter"))
			cygprof_enter = (void *)(intptr_t)(iter.sym.st_value + base_addr);
		if (!strcmp(name, "__cyg_profile_func_exit"))
			cygprof_exit = (void *)(intptr_t)(iter.sym.st_value + base_addr);
	}

	elf_finish(&elf);
}

static void find_libmcount_funcs(void)
{
	char *line = NULL;
	size_t len = 0;
	FILE *fp = fopen("/proc/self/maps", "r");

	if (fp == NULL)
		return;

	while (getline(&line, &len, fp) != -1) {
		unsigned long start, end;
		char prot[5];
		char path[PATH_MAX];

		if (sscanf(line, "%lx-%lx %s %*x %*x:%*x %*d %s\n", &start, &end, prot, path) != 4)
			continue;

		if (strncmp(basename(path), "libmcount", 9))
			continue;

		find_cygprof_funcs(path, start);
		break;
	}

	free(line);
	fclose(fp);
}

static void init_symtab(void)
{
	snprintf(uftrace_shmem_name, sizeof(uftrace_shmem_name), "/uftrace-python-%d", getpid());

	uftrace_shmem_fd = uftrace_shmem_open(uftrace_shmem_name, O_RDWR | O_CREAT | O_TRUNC,
					      UFTRACE_SHMEM_PERMISSION_MODE);
	if (uftrace_shmem_fd < 0)
		pr_err("failed to open shared memory for %s", uftrace_shmem_name);

	if (ftruncate(uftrace_shmem_fd, UFTRACE_PYTHON_SYMTAB_SIZE) < 0)
		pr_err("failed to allocate the shared memory for %s", uftrace_shmem_name);

	symtab = mmap(NULL, UFTRACE_PYTHON_SYMTAB_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED,
		      uftrace_shmem_fd, 0);
	if (symtab == MAP_FAILED)
		pr_err("failed to mmap shared memory for %s", uftrace_shmem_name);

	symtab->count = 0;
	symtab->offset = UFTRACE_PYTHON_SYMTAB_HDRSZ; /* reserve some area for the header */

	uftrace_symtab_size = UFTRACE_PYTHON_SYMTAB_SIZE;
}

static uint32_t get_new_sym_addr(const char *name, bool is_libcall)
{
	union uftrace_python_symtab old_hdr, new_hdr, tmp_hdr;
	char *data = (void *)symtab;
	int entry_size = strlen(name) + 20; /* addr(16) + spaces(2) + type(1) + newline(1) */

	old_hdr.val = symtab->val;

	/* this loop is needed to handle concurrent updates for multi-processing */
	while (true) {
		new_hdr.count = old_hdr.count + 1;
		new_hdr.offset = old_hdr.offset + entry_size;

		/* atomic update of header (count + offset) */
		tmp_hdr.val = __sync_val_compare_and_swap(&symtab->val, old_hdr.val, new_hdr.val);
		if (tmp_hdr.val == old_hdr.val)
			break;

		old_hdr.val = tmp_hdr.val;
	}

	if (new_hdr.offset >= uftrace_symtab_size) {
		unsigned new_symtab_size = uftrace_symtab_size + UFTRACE_PYTHON_SYMTAB_SIZE;

		pr_dbg("try to increase the shared memory for %s (new size=%uMB)\n",
		       uftrace_shmem_name, new_symtab_size / (1024 * 1024));

		/* increase the file size */
		if (ftruncate(uftrace_shmem_fd, new_symtab_size) < 0)
			pr_err("failed to resize the shared memory for %s", uftrace_shmem_name);

		/* remap the symbol table, this might result in a new address  */
		data = mremap(symtab, uftrace_symtab_size, new_symtab_size, MREMAP_MAYMOVE);
		if (data == MAP_FAILED)
			pr_err("failed to mmap shared memory for %s", uftrace_shmem_name);

		/* update the address and size of the symbol table */
		symtab = (void *)data;
		uftrace_symtab_size = new_symtab_size;
	}

	/* add the symbol table contents (in the old format) */
	snprintf(data + old_hdr.offset, entry_size + 1, "%016x %c %s\n", new_hdr.count,
		 is_libcall ? 'P' : 'T', name);
	return new_hdr.count;
}

static void write_symtab(const char *dirname)
{
	char *filename = NULL;
	FILE *fp;
	void *buf = (void *)symtab;
	unsigned len;

	xasprintf(&filename, "%s/%s.sym", dirname, UFTRACE_PYTHON_SYMTAB_NAME);

	fp = fopen(filename, "w");
	free(filename);
	if (fp == NULL) {
		pr_warn("writing symbol table of python program failed: %m");
		return;
	}

	pr_dbg("writing the python symbol table (count=%u)\n", symtab->count);

	/* update the header comment */
	len = fprintf(fp, "# symbols: %u\n", symtab->count);
	len += fprintf(fp, "# path name: %s\n", UFTRACE_PYTHON_SYMTAB_NAME);
	len += fprintf(fp, "#%*s\n", UFTRACE_PYTHON_SYMTAB_HDRSZ - 2 - len, "");

	if (len != UFTRACE_PYTHON_SYMTAB_HDRSZ)
		pr_warn("symbol header size should be 64: %u", len);

	/* copy rest of the shmem buffer to the file */
	buf += UFTRACE_PYTHON_SYMTAB_HDRSZ;
	len = symtab->offset - UFTRACE_PYTHON_SYMTAB_HDRSZ;

	while (len) {
		int size = fwrite(buf, 1, len, fp);

		if (size < 0)
			pr_err("failed to write python symbol file");

		len -= size;
		buf += size;
	}

	/* special symbol needed for the old symbol file format */
	fprintf(fp, "%016x %c %s\n", symtab->count + 1, '?', "__sym_end");
	fclose(fp);

	munmap(symtab, uftrace_symtab_size);
	close(uftrace_shmem_fd);
	uftrace_shmem_unlink(uftrace_shmem_name);
}

static void init_dbginfo(void)
{
	snprintf(uftrace_shmem_dbg_name, sizeof(uftrace_shmem_dbg_name), "/uftrace-python-dbg-%d",
		 getpid());

	uftrace_shmem_dbg_fd = uftrace_shmem_open(
		uftrace_shmem_dbg_name, O_RDWR | O_CREAT | O_TRUNC, UFTRACE_SHMEM_PERMISSION_MODE);
	if (uftrace_shmem_dbg_fd < 0)
		pr_err("failed to open shared memory for %s", uftrace_shmem_dbg_name);

	if (ftruncate(uftrace_shmem_dbg_fd, UFTRACE_PYTHON_SYMTAB_SIZE) < 0)
		pr_err("failed to allocate the shared memory for %s", uftrace_shmem_dbg_name);

	dbg_info = mmap(NULL, UFTRACE_PYTHON_SYMTAB_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED,
			uftrace_shmem_dbg_fd, 0);
	if (dbg_info == MAP_FAILED)
		pr_err("failed to mmap shared memory for %s", uftrace_shmem_dbg_name);

	dbg_info->count = 0;
	dbg_info->offset = UFTRACE_PYTHON_SYMTAB_HDRSZ; /* reserve some area for the header */

	uftrace_dbginfo_size = UFTRACE_PYTHON_SYMTAB_SIZE;
}

static void update_dbg_info(const char *name, uint64_t addr, const char *file, int line)
{
	union uftrace_python_symtab old_hdr, new_hdr, tmp_hdr;
	char *data = (void *)dbg_info;
	char *buf = NULL;
	int entry_size = xasprintf(&buf, "F: %" PRIx64 " %s\nL: %d %s\n", addr, name, line, file);

	old_hdr.val = dbg_info->val;

	/* this loop is needed to handle concurrent updates for multi-processing */
	while (true) {
		new_hdr.count = old_hdr.count + 1;
		new_hdr.offset = old_hdr.offset + entry_size;

		/* atomic update of header (count + offset) */
		tmp_hdr.val = __sync_val_compare_and_swap(&dbg_info->val, old_hdr.val, new_hdr.val);
		if (tmp_hdr.val == old_hdr.val)
			break;

		old_hdr.val = tmp_hdr.val;
	}

	if (new_hdr.offset >= uftrace_dbginfo_size) {
		unsigned new_dbginfo_size = uftrace_dbginfo_size + UFTRACE_PYTHON_SYMTAB_SIZE;

		pr_dbg("try to increase the shared memory for %s (new size=%uMB)\n",
		       uftrace_shmem_dbg_name, new_dbginfo_size / (1024 * 1024));

		/* increase the file size */
		if (ftruncate(uftrace_shmem_dbg_fd, new_dbginfo_size) < 0)
			pr_err("failed to resize the shared memory for %s", uftrace_shmem_dbg_name);

		/* remap the debug info, this might result in a new address  */
		data = mremap(dbg_info, uftrace_dbginfo_size, new_dbginfo_size, MREMAP_MAYMOVE);
		if (data == MAP_FAILED)
			pr_err("failed to mmap shared memory for %s", uftrace_shmem_dbg_name);

		/* update the address and size of the debug info table */
		dbg_info = (void *)data;
		uftrace_dbginfo_size = new_dbginfo_size;
	}

	/* add the debug info file contents */
	snprintf(data + old_hdr.offset, entry_size + 1, "%s", buf);
	free(buf);
}

static void write_dbginfo(const char *dirname)
{
	char *filename = NULL;
	FILE *fp;
	void *buf = (void *)dbg_info;
	unsigned len = 0;

	xasprintf(&filename, "%s/%s.dbg", dirname, UFTRACE_PYTHON_SYMTAB_NAME);

	fp = fopen(filename, "w");
	free(filename);
	if (fp == NULL) {
		pr_warn("writing debug info of python program failed: %m");
		return;
	}

	pr_dbg("writing the python debug info (count=%u)\n", dbg_info->count);

	/* update the header comment */
	len += fprintf(fp, "# path name: %s\n", UFTRACE_PYTHON_SYMTAB_NAME);
	len += fprintf(fp, "#%*s\n", UFTRACE_PYTHON_SYMTAB_HDRSZ - 2 - len, "");

	if (len != UFTRACE_PYTHON_SYMTAB_HDRSZ)
		pr_warn("debug info header size should be %d: %u", UFTRACE_PYTHON_SYMTAB_HDRSZ,
			len);

	/* copy rest of the shmem buffer to the file */
	buf += UFTRACE_PYTHON_SYMTAB_HDRSZ;
	len = dbg_info->offset - UFTRACE_PYTHON_SYMTAB_HDRSZ;

	while (len) {
		int size = fwrite(buf, 1, len, fp);

		if (size < 0)
			pr_err("failed to write python symbol file");

		len -= size;
		buf += size;
	}

	fclose(fp);

	munmap(dbg_info, uftrace_dbginfo_size);
	close(uftrace_shmem_dbg_fd);
	uftrace_shmem_unlink(uftrace_shmem_dbg_name);
}

static void init_filters(void)
{
	char *filter_str = getenv("UFTRACE_FILTER");
	char *pattern_str = getenv("UFTRACE_PATTERN");
	enum uftrace_pattern_type ptype = PATT_REGEX;
	struct strv fsv = STRV_INIT;
	char *str;
	int i;

	if (filter_str == NULL) {
		filter_state.mode = FILTER_MODE_NONE;
		return;
	}

	if (pattern_str) {
		if (!strcmp(pattern_str, "glob"))
			ptype = PATT_GLOB;
		else if (!strcmp(pattern_str, "simple"))
			ptype = PATT_SIMPLE;
	}

	filter_state.mode = FILTER_MODE_OUT;
	strv_split(&fsv, filter_str, ";");
	strv_for_each(&fsv, str, i) {
		struct uftrace_python_filter *filter;

		filter = xmalloc(sizeof(*filter));
		if (*str == '!') {
			filter->mode = FILTER_MODE_OUT;
			str++;
		}
		else {
			filter->mode = FILTER_MODE_IN;
			filter_state.mode = FILTER_MODE_IN;
		}

		if (strpbrk(str, REGEX_CHARS))
			filter->p.type = ptype;
		else
			filter->p.type = PATT_SIMPLE;

		filter->p.patt = xstrdup(str);
		if (filter->p.type == PATT_REGEX)
			regcomp(&filter->p.re, filter->p.patt, REG_NOSUB | REG_EXTENDED);

		list_add_tail(&filter->list, &filters);
	}
	strv_free(&fsv);
}

static bool match_filter(struct uftrace_python_filter *filter, const char *fname)
{
	switch (filter->p.type) {
	case PATT_SIMPLE:
		return !strcmp(filter->p.patt, fname);
	case PATT_REGEX:
		return !regexec(&filter->p.re, fname, 0, NULL, 0);
	case PATT_GLOB:
		return !fnmatch(filter->p.patt, fname, 0);
	default:
		return false;
	}
}

/* returns true if the current event should be skipped */
static bool apply_filters(const char *event, struct uftrace_python_symbol *sym, bool is_pyfunc)
{
	struct uftrace_python_filter *filter;
	bool is_entry = !strcmp(event, "call") || !strcmp(event, "c_call");
	int delta = is_entry ? 1 : -1;

	list_for_each_entry(filter, &filters, list) {
		if (!match_filter(filter, sym->name))
			continue;

		if (filter->mode == FILTER_MODE_IN)
			filter_state.count_in += delta;
		else if (filter->mode == FILTER_MODE_OUT)
			filter_state.count_out += delta;
		break;
	}
	if (list_no_entry(filter, &filters, list))
		filter = NULL;

	if (filter_state.count_out > 0)
		return true;

	if (filter_state.mode == FILTER_MODE_IN) {
		if (filter_state.count_in > 0)
			return false;

		if (filter && filter->mode == FILTER_MODE_IN && !is_entry)
			return false;

		return true;
	}
	if (filter_state.mode == FILTER_MODE_OUT) {
		if (filter && filter->mode == FILTER_MODE_OUT && !is_entry)
			return true;
	}
	return false;
}

static void remove_filters(void)
{
	struct uftrace_python_filter *filter, *tmp;

	list_for_each_entry_safe(filter, tmp, &filters, list) {
		list_del(&filter->list);

		if (filter->p.type == PATT_REGEX)
			regfree(&filter->p.re);
		free(filter->p.patt);
		free(filter);
	}
}

static bool can_trace(bool is_entry, struct uftrace_python_symbol *sym)
{
	/* always trace functions in the main module */
	if ((sym->flag & UFT_PYSYM_F_LIBCALL) == 0)
		return true;

	if (libcall_mode == UFT_PY_LIBCALL_NONE)
		return false;
	if (libcall_mode == UFT_PY_LIBCALL_NESTED)
		return true;

	/* allow single-depth libcalls only */
	if (is_entry) {
		if (libcall_count++ > 0)
			return false;
	}
	else {
		if (--libcall_count > 0)
			return false;
		if (unlikely(libcall_count < 0))
			libcall_count = 0;
	}
	return true;
}

static void init_uftrace(void)
{
	const char *libcall = getenv("UFTRACE_PY_LIBCALL");
	const char *pymain = getenv("UFTRACE_PYMAIN");
	char *p;

	/* check if it's loaded in a uftrace session */
	if (getenv("UFTRACE_SHMEM") == NULL)
		return;

	if (getenv("UFTRACE_DEBUG")) {
		debug = 1;
		dbg_domain[DBG_UFTRACE] = 1;
	}

	if (getenv("UFTRACE_SRCLINE"))
		need_dbg_info = true;

	/* UFTRACE_PYMAIN was set in uftrace.py. */
	if (pymain != NULL) {
		main_file = xstrdup(pymain);
		/* main_dir keeps the dirname of the main file */
		if (main_file[0] != '/')
			main_dir = realpath(main_file, NULL);
		else
			main_dir = xstrdup(main_file);
		/* get dirname of main_file */
		p = strrchr(main_dir, '/');
		if (p && p != main_dir)
			*p = '\0';
		main_dir_len = strlen(main_dir);
		pr_dbg2("main module is loaded from: %s\n", main_dir);
	}

	if (libcall != NULL) {
		if (!strcmp(libcall, "NONE"))
			libcall_mode = UFT_PY_LIBCALL_NONE;
		if (!strcmp(libcall, "NESTED"))
			libcall_mode = UFT_PY_LIBCALL_NESTED;
	}

	init_symtab();
	if (need_dbg_info)
		init_dbginfo();

	find_libmcount_funcs();
	init_filters();
}

/* due to Python API usage, we need to exclude this part for unit testing. */
#ifndef UNIT_TEST

#ifdef HAVE_LIBPYTHON3

/* this is called during GC traversal */
static int uftrace_py_traverse(PyObject *m, visitproc visit, void *arg)
{
	/* do nothing for now */
	return 0;
}

/* this is called before the module is deallocated */
static int uftrace_py_clear(PyObject *m)
{
	/* do nothing for now */
	return 0;
}

static void uftrace_py_free(void *arg)
{
	/* do nothing for now */
}

static struct PyModuleDef uftrace_module = {
	PyModuleDef_HEAD_INIT,
	UFTRACE_PYTHON_MODULE_NAME,
	PyDoc_STR("C extension module to trace python functions with uftrace"),
	sizeof(struct uftrace_py_state),
	uftrace_py_methods,
	NULL, /* slots */
	uftrace_py_traverse,
	uftrace_py_clear,
	uftrace_py_free,
};

static PyObject *get_trace_function(void)
{
	PyObject *mod;
	struct uftrace_py_state *state;

	mod = PyState_FindModule(&uftrace_module);
	if (mod == NULL)
		Py_RETURN_NONE;

	state = PyModule_GetState(mod);

	Py_INCREF(state->trace_func);
	return state->trace_func;
}

static bool is_string_type(PyObject *utf8)
{
	return PyUnicode_Check(utf8);
}

static char *get_c_string(PyObject *utf8)
{
	return (char *)PyUnicode_AsUTF8(utf8);
}

/* the name should be 'PyInit_' + <module name> */
PyMODINIT_FUNC PyInit_uftrace_python(void)
{
	PyObject *m, *d, *f;
	struct uftrace_py_state *s;

	outfp = stdout;
	logfp = stdout;

	m = PyModule_Create(&uftrace_module);
	if (m == NULL)
		return NULL;

	d = PyModule_GetDict(m);
	f = PyDict_GetItemString(d, "trace");

	/* keep the pointer to trace function as it's used as a return value */
	s = PyModule_GetState(m);
	s->trace_func = f;

	skip_first_frame = true;

	init_uftrace();
	return m;
}

#else /* HAVE_LIBPYTHON2 */

/* the name should be 'init' + <module name> */
PyMODINIT_FUNC inituftrace_python(void)
{
	PyObject *m, *d;

	outfp = stdout;
	logfp = stdout;

	m = Py_InitModule(UFTRACE_PYTHON_MODULE_NAME, uftrace_py_methods);
	if (m == NULL)
		return;

	d = PyModule_GetDict(m);

	/* keep the pointer to trace function as it's used as a return value */
	uftrace_func = PyDict_GetItemString(d, "trace");

	init_uftrace();
}

static PyObject *get_trace_function(void)
{
	Py_INCREF(uftrace_func);
	return uftrace_func;
}

static bool is_string_type(PyObject *str)
{
	return PyString_Check(str);
}

static char *get_c_string(PyObject *str)
{
	return (char *)PyString_AsString(str);
}

#endif /* HAVE_LIBPYTHON2 */

static char *get_python_funcname(PyObject *frame, PyObject *code, bool *is_main)
{
	PyObject *name, *global;
	char *func_name = NULL;

	*is_main = false;

	if (PyObject_HasAttrString(code, "co_qualname"))
		name = PyObject_GetAttrString(code, "co_qualname");
	else
		name = PyObject_GetAttrString(code, "co_name");

	/* prepend module name if available */
	global = PyObject_GetAttrString(frame, "f_globals");
	if (global && name) {
		PyObject *mod = PyDict_GetItemString(global, "__name__");
		char *name_str = get_c_string(name);

		/* 'mod' is a borrowed reference */
		if (mod && is_string_type(mod)) {
			char *mod_str = get_c_string(mod);

			/* skip __main__. prefix for functions in the main module */
			if (!strcmp(mod_str, "__main__"))
				*is_main = true;
			if (!*is_main || !strcmp(name_str, "<module>"))
				xasprintf(&func_name, "%s.%s", mod_str, name_str);
		}
		Py_DECREF(global);
	}

	if (func_name == NULL && name)
		func_name = strdup(get_c_string(name));

	Py_XDECREF(name);
	return func_name;
}

static char *get_c_funcname(PyObject *frame, PyObject *code)
{
	PyObject *name, *mod;
	PyCFunctionObject *cfunc;
	char *func_name = NULL;

	if (!PyCFunction_Check(code))
		return NULL;

	cfunc = (void *)code;

	if (PyObject_HasAttrString(code, "__qualname__"))
		name = PyObject_GetAttrString(code, "__qualname__");
	else
		name = PyObject_GetAttrString(code, "__name__");

	/* prepend module name if available */
	mod = cfunc->m_module;

	if (mod && is_string_type(mod))
		xasprintf(&func_name, "%s.%s", get_c_string(mod), get_c_string(name));
	else if (strchr(get_c_string(name), '.'))
		func_name = xstrdup(get_c_string(name));
	else
		xasprintf(&func_name, "%s.%s", "builtins", get_c_string(name));

	Py_XDECREF(name);
	return func_name;
}

static struct uftrace_python_symbol *convert_function_addr(PyObject *frame, PyObject *args,
							   bool is_pyfunc)
{
	struct rb_node *parent = NULL;
	struct rb_node **p = &code_tree.rb_node;
	struct uftrace_python_symbol *iter, *new_sym;
	PyObject *code;
	const char *file_name = NULL;
	char *func_name;
	bool is_main = false;
	int cmp;

	if (is_pyfunc) {
		code = PyObject_GetAttrString(frame, "f_code");
		if (code == NULL)
			return NULL;
	}
	else {
		code = args;
		Py_INCREF(code);
	}

	if (is_pyfunc)
		func_name = get_python_funcname(frame, code, &is_main);
	else
		func_name = get_c_funcname(frame, code);

	/* code is not used anymore */
	Py_DECREF(code);

	if (func_name == NULL)
		return NULL;

	while (*p) {
		parent = *p;
		iter = rb_entry(parent, struct uftrace_python_symbol, node);

		/* compare func_name */
		cmp = strcmp(iter->name, func_name);
		if (cmp == 0) {
			free(func_name);
			return iter;
		}
		if (cmp < 0)
			p = &parent->rb_left;
		else
			p = &parent->rb_right;
	}

	if (main_dir && PyObject_HasAttrString(code, "co_filename")) {
		PyObject *obj;

		obj = PyObject_GetAttrString(code, "co_filename");
		file_name = get_c_string(obj);
		Py_DECREF(obj);

		/* check if this function is from the same directory as the main script */
		if (!strncmp(file_name, main_dir, main_dir_len) && file_name[main_dir_len] == '/')
			is_main = true;
	}

	new_sym = xmalloc(sizeof(*new_sym));
	new_sym->addr = get_new_sym_addr(func_name, !is_main);
	new_sym->name = func_name;
	new_sym->flag = is_main ? 0 : UFT_PYSYM_F_LIBCALL;

	if (need_dbg_info) {
		if (file_name && PyObject_HasAttrString(code, "co_firstlineno")) {
			PyObject *obj;
			int line;

			if (!strcmp(file_name, "<string>") && main_file)
				file_name = main_file;

			obj = PyObject_GetAttrString(code, "co_firstlineno");
			line = PyLong_AsLong(obj);
			Py_DECREF(obj);

			update_dbg_info(func_name, new_sym->addr, file_name, line);
		}
	}

	/* keep the refcount of the code object to keep it alive */

	rb_link_node(&new_sym->node, parent, p);
	rb_insert_color(&new_sym->node, &code_tree);

	return new_sym;
}

/*
 * This is the actual trace function to be called for each python event.
 */
static PyObject *uftrace_trace_python(PyObject *self, PyObject *args)
{
	PyObject *frame, *args_tuple;
	static PyObject *first_frame;
	const char *event;
	struct uftrace_python_symbol *sym;
	bool is_pyfunc;

	if (!PyArg_ParseTuple(args, "OsO", &frame, &event, &args_tuple))
		Py_RETURN_NONE;

	if (first_frame == NULL)
		first_frame = frame;
	/* skip the first frame: builtins.exec() */
	if (skip_first_frame && frame == first_frame)
		Py_RETURN_NONE;

	is_pyfunc = !strcmp(event, "call") || !strcmp(event, "return");
	sym = convert_function_addr(frame, args_tuple, is_pyfunc);
	if (sym == NULL)
		Py_RETURN_NONE;

	if (filter_state.mode != FILTER_MODE_NONE && apply_filters(event, sym, is_pyfunc))
		Py_RETURN_NONE;

	if (!strcmp(event, "call") || !strcmp(event, "c_call")) {
		if (can_trace(true, sym))
			cygprof_enter(sym->addr, 0);
		else
			Py_RETURN_NONE;
	}
	else if (!strcmp(event, "return") || !strcmp(event, "c_return")) {
		if (can_trace(false, sym))
			cygprof_exit(0, 0);
		else
			Py_RETURN_NONE;
	}
	else if (!strcmp(event, "c_exception")) {
		/* C code exception doesn't generate c_return */
		if (can_trace(false, sym))
			cygprof_exit(0, 0);
		else
			Py_RETURN_NONE;
	}

	return get_trace_function();
}

static void __attribute__((destructor)) uftrace_trace_python_finish(void)
{
	const char *dirname;

	dirname = getenv("UFTRACE_DIR");
	if (dirname == NULL)
		dirname = UFTRACE_DIR_NAME;

	write_symtab(dirname);

	if (need_dbg_info)
		write_dbginfo(dirname);

	remove_filters();

	free(main_file);
	free(main_dir);
}

static PyObject *uftrace_trace_python_exit(PyObject *self, PyObject *obj)
{
	int n = PyLong_AsLong(obj);
	uftrace_trace_python_finish();
	_exit(n);
	return NULL;
}

#else /* UNIT_TEST */

static PyObject *uftrace_trace_python(PyObject *self, PyObject *args)
{
	/* just to suppress compiler warnings */
	skip_first_frame = false;
	code_tree = code_tree;

	return NULL;
}

static PyObject *uftrace_trace_python_exit(PyObject *self, PyObject *obj)
{
	return NULL;
}

TEST_CASE(python_symtab)
{
	char buf[32];

	/* should have no effect */
	init_uftrace();

	pr_dbg("initialize symbol table on a shared memory\n");
	init_symtab();
	TEST_NE(symtab, MAP_FAILED);

	TEST_EQ(get_new_sym_addr("a", true), 1);
	TEST_EQ(get_new_sym_addr("b", true), 2);
	TEST_EQ(get_new_sym_addr("c", false), 3);
	write_symtab(".");

	snprintf(buf, sizeof(buf), "%s.sym", UFTRACE_PYTHON_SYMTAB_NAME);
	unlink(buf);
	pr_dbg("unlink the symbol table: %s\n", buf);

	return TEST_OK;
}

TEST_CASE(python_dbginfo)
{
	char buf[32];

	/* should have no effect */
	init_uftrace();

	need_dbg_info = true;

	pr_dbg("initialize debug info on a shared memory\n");
	init_dbginfo();
	TEST_NE(dbg_info, MAP_FAILED);

	update_dbg_info("a", 1, __FILE__, __LINE__);
	TEST_EQ(dbg_info->count, 1);
	update_dbg_info("b", 2, __FILE__, __LINE__);
	TEST_EQ(dbg_info->count, 2);
	update_dbg_info("c", 3, __FILE__, __LINE__);
	TEST_EQ(dbg_info->count, 3);
	write_dbginfo(".");

	snprintf(buf, sizeof(buf), "%s.dbg", UFTRACE_PYTHON_SYMTAB_NAME);
	unlink(buf);
	pr_dbg("unlink the debug info: %s\n", buf);

	return TEST_OK;
}

TEST_CASE(python_filter)
{
	struct uftrace_python_symbol sym = {
		.name = "test.sym",
	};
	struct uftrace_python_filter *filter;

	setenv("UFTRACE_FILTER", "^test", 1);

	init_filters();
	TEST_EQ(list_empty(&filters), false);
	filter = list_first_entry(&filters, struct uftrace_python_filter, list);

	pr_dbg("match filter patterns\n");
	TEST_EQ(match_filter(filter, "test.abc"), true);
	TEST_EQ(match_filter(filter, "xyz.test"), false);

	pr_dbg("apply filters\n");
	TEST_EQ(apply_filters("call", &sym, true), false);

	remove_filters();

	return TEST_OK;
}

TEST_CASE(python_libcall)
{
	struct uftrace_python_symbol syms[] = {
		{
			.name = "foo",
		},
		{
			.name = "bar",
			.flag = UFT_PYSYM_F_LIBCALL,
		},
		{
			.name = "baz",
			.flag = UFT_PYSYM_F_LIBCALL,
		},
	};
	int results_none[] = { 1, 0, 0 };
	int results_single[] = { 1, 1, 0 };
	int results_nested[] = { 1, 1, 1 };

	pr_dbg("checking no libcall\n");
	libcall_mode = UFT_PY_LIBCALL_NONE;
	libcall_count = 0;
	for (unsigned i = 0; i < ARRAY_SIZE(syms); i++)
		TEST_EQ(can_trace(true, &syms[i]), results_none[i]);

	pr_dbg("checking single libcall\n");
	libcall_mode = UFT_PY_LIBCALL_SINGLE;
	libcall_count = 0;
	for (unsigned i = 0; i < ARRAY_SIZE(syms); i++)
		TEST_EQ(can_trace(true, &syms[i]), results_single[i]);

	pr_dbg("checking nested libcall\n");
	libcall_mode = UFT_PY_LIBCALL_NESTED;
	libcall_count = 0;
	for (unsigned i = 0; i < ARRAY_SIZE(syms); i++)
		TEST_EQ(can_trace(true, &syms[i]), results_nested[i]);

	return TEST_OK;
}

#endif /* UNIT_TEST */
