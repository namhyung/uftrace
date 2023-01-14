/*
 * python extension module to trace python functions for uftrace
 *
 * Copyright (C) 2023,  Namhyung Kim <namhyung@gmail.com>
 *
 * Released under the GPL v2.
 */
#include <Python.h>

#include <fcntl.h>
#include <stdint.h>
#include <sys/mman.h>

#include "uftrace.h"
#include "utils/rbtree.h"
#include "utils/shmem.h"
#include "utils/symbol.h"

/* python module state */
struct uftrace_py_state {
	PyObject *trace_func;
};

/* pointer to python tracing function (for libpython2.7) */
static PyObject *uftrace_func __attribute__((unused));

/* RB tree of python_symbol to map function name to address */
static struct rb_root name_tree = RB_ROOT;

#define UFTRACE_PYTHON_SYMTAB_SIZE (1 * 1024 * 1024)
#define UFTRACE_PYTHON_SYMTAB_HDRSZ (48)

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
};

static union uftrace_python_symtab *symtab;

/* symbol table entry to maintain mappings from code to addr */
struct uftrace_python_symbol {
	struct rb_node node;
	PyObject *code;
	uint32_t addr;
};

/* functions in libmcount.so */
static void (*cygprof_enter)(unsigned long child, unsigned long parent);
static void (*cygprof_exit)(unsigned long child, unsigned long parent);

/* main trace function to be called from python interpreter */
static PyObject *uftrace_trace_python(PyObject *self, PyObject *args);

static PyMethodDef uftrace_py_methods[] = {
	{ "trace", uftrace_trace_python, METH_VARARGS,
	  PyDoc_STR("trace python function with uftrace.") },
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
			cygprof_enter = (void *)(iter.sym.st_value + base_addr);
		if (!strcmp(name, "__cyg_profile_func_exit"))
			cygprof_exit = (void *)(iter.sym.st_value + base_addr);
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
	int shm_fd;

	shm_fd = uftrace_shmem_open("/python.sym", O_RDWR | O_CREAT | O_TRUNC, 0600);
	if (shm_fd < 0)
		pr_err("failed to open shared memory for python symtab");

	if (ftruncate(shm_fd, UFTRACE_PYTHON_SYMTAB_SIZE) < 0)
		pr_err("failed to resize the shared memory for python symtab");

	symtab = mmap(NULL, UFTRACE_PYTHON_SYMTAB_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, shm_fd,
		      0);
	if (symtab == MAP_FAILED)
		pr_err("failed to mmap shared memory for python symtab");

	symtab->count = 0;
	symtab->offset = UFTRACE_PYTHON_SYMTAB_HDRSZ; /* reserve some area for the header */

	close(shm_fd);
}

static uint32_t get_new_sym_addr(const char *name)
{
	union uftrace_python_symtab old_hdr, new_hdr, tmp_hdr;
	char *data = (void *)symtab;
	int entry_size = strlen(name) + 20; /* addr(16) + spaces(2) + type(1) + newline(1) */

	old_hdr.val = symtab->val;

	while (true) {
		new_hdr.count = old_hdr.count + 1;
		new_hdr.offset = old_hdr.offset + entry_size;

		/* atomic update of header (count + offset) */
		tmp_hdr.val = __sync_val_compare_and_swap(&symtab->val, old_hdr.val, new_hdr.val);
		if (tmp_hdr.val == old_hdr.val)
			break;

		old_hdr.val = tmp_hdr.val;
	}

	if (new_hdr.offset >= UFTRACE_PYTHON_SYMTAB_SIZE)
		pr_warn("symbol table is too big!");

	/* add the symbol table contents (in the old format) */
	snprintf(data + old_hdr.offset, entry_size + 1, "%016x t %s\n", new_hdr.count, name);
	return new_hdr.count;
}

/* manage function name -> address (or index) */
static unsigned long resolve_func_addr(struct rb_root *root, PyObject *code, const char *name)
{
	struct rb_node *parent = NULL;
	struct rb_node **p = &root->rb_node;
	struct uftrace_python_symbol *iter, *new;
	int cmp;

	while (*p) {
		parent = *p;
		iter = rb_entry(parent, struct uftrace_python_symbol, node);

		if (iter->code == code)
			return iter->addr;
		else
			cmp = iter->code > code ? 1 : -1;

		if (cmp < 0)
			p = &parent->rb_left;
		else
			p = &parent->rb_right;
	}

	new = xmalloc(sizeof(*new));
	new->code = code;
	new->addr = get_new_sym_addr(name);

	/* increase the refcount to keep the code object alive */
	Py_INCREF(code);

	rb_link_node(&new->node, parent, p);
	rb_insert_color(&new->node, root);

	return new->addr;
}

static void write_symtab(const char *dirname)
{
	char *filename = NULL;
	FILE *fp;
	void *buf = (void *)symtab;
	unsigned len;

	xasprintf(&filename, "%s/%s.sym", dirname, UFTRACE_PYTHON_SYMTAB_NAME);

	fp = fopen(filename, "w");
	if (fp == NULL) {
		pr_warn("writing symbol table of python program failed: %m");
		return;
	}

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

	munmap(symtab, UFTRACE_PYTHON_SYMTAB_SIZE);
	uftrace_shmem_unlink("/python.sym");
}

static void init_uftrace(void)
{
	/* check if it's loaded in a uftrace session */
	if (getenv("UFTRACE_SHMEM") == NULL)
		return;

	init_symtab();
	find_libmcount_funcs();
}

#ifdef HAVE_LIBPYTHON3

/* this is called during GC traversal */
static int uftrace_py_traverse(PyObject *m, visitproc visit, void *arg)
{
	struct uftrace_py_state *state;

	state = PyModule_GetState(m);

	Py_VISIT(state->trace_func);

	return 0;
}

/* this is called before the module is deallocated */
static int uftrace_py_clear(PyObject *m)
{
	struct uftrace_py_state *state;

	state = PyModule_GetState(m);

	Py_CLEAR(state->trace_func);

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

static unsigned long convert_function_addr(PyObject *frame)
{
	PyObject *code, *name, *global;
	char *func_name = NULL;
	unsigned long addr = 0;
	bool needs_free = false;

	code = PyObject_GetAttrString(frame, "f_code");
	if (code == NULL)
		return 0;

	if (PyObject_HasAttrString(code, "co_qualname"))
		name = PyObject_GetAttrString(code, "co_qualname");
	else
		name = PyObject_GetAttrString(code, "co_name");

	/* prepend module name if available */
	global = PyObject_GetAttrString(frame, "f_globals");
	if (global) {
		PyObject *mod = PyDict_GetItemString(global, "__name__");
		char *name_str = get_c_string(name);

		/* 'mod' is a borrowed reference */
		if (mod && is_string_type(mod)) {
			char *mod_str = get_c_string(mod);

			/* skip __main__. prefix for functions in the main module */
			if (strcmp(mod_str, "__main__") || !strcmp(name_str, "<module>")) {
				xasprintf(&func_name, "%s.%s", mod_str, name_str);
				needs_free = true;
			}
		}
		Py_DECREF(global);
	}

	if (func_name == NULL && name)
		func_name = get_c_string(name);
	if (func_name)
		addr = resolve_func_addr(&name_tree, code, func_name);

	if (needs_free)
		free(func_name);
	Py_XDECREF(code);
	Py_XDECREF(name);
	return addr;
}

/*
 * This is the actual function when called for each function.
 */
static PyObject *uftrace_trace_python(PyObject *self, PyObject *args)
{
	PyObject *frame, *args_tuple;
	const char *event;

	if (!PyArg_ParseTuple(args, "OsO", &frame, &event, &args_tuple))
		Py_RETURN_NONE;

	if (!strcmp(event, "call")) {
		unsigned long addr;

		addr = convert_function_addr(frame);
		cygprof_enter(addr, 0);
	}
	else if (!strcmp(event, "return"))
		cygprof_exit(0, 0);

	return get_trace_function();
}

static void __attribute__((destructor)) uftrace_trace_python_finish(void)
{
	const char *dirname;

	dirname = getenv("UFTRACE_DIR");
	if (dirname == NULL)
		dirname = UFTRACE_DIR_NAME;

	write_symtab(dirname);
}
