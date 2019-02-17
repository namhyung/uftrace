#include <Python.h>

#include "uftrace.h"
#include "utils/symbol.h"
#include "utils/rbtree.h"

/* compatibility layers for both python2 and python3 */
char *get_py_string(PyObject *object);
int check_py_string(PyObject *object);

/* pointer to python tracing function */
PyObject *uftrace_func;

/* RB tree of python_symbol to map function name to address */
static struct rb_root name_tree = RB_ROOT;

/* simple sequence number to be used as symbol address */
static unsigned sym_num = 1;

struct uftrace_python_symbol {
	struct rb_node		node;
	unsigned int		addr;
	char			*name;
};

static void (*cygprof_enter)(unsigned long child, unsigned long parent);
static void (*cygprof_exit) (unsigned long child, unsigned long parent);

static PyObject *uftrace_trace_python(PyObject *self, PyObject *args);

PyMethodDef uftrace_methods[] = {
	{ "trace", uftrace_trace_python, METH_VARARGS,
	  "trace python function with uftrace." },
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

void find_libmcount_funcs(void)
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

		if (sscanf(line, "%lx-%lx %s %*x %*x:%*x %*d %s\n",
			   &start, &end, prot, path) != 4)
			continue;

		if (strncmp(basename(path), "libmcount", 9))
			continue;

		find_cygprof_funcs(path, start);
		break;
	}

	free(line);
	fclose(fp);
}

static unsigned long find_function(struct rb_root *root, const char *name)
{
	struct rb_node *parent = NULL;
	struct rb_node **p = &root->rb_node;
	struct uftrace_python_symbol *iter, *new;
	int cmp;

	while (*p) {
		parent = *p;
		iter = rb_entry(parent, struct uftrace_python_symbol, node);

		cmp = strcmp(iter->name, name);
		if (cmp == 0)
			return iter->addr;

		if (cmp < 0)
			p = &parent->rb_left;
		else
			p = &parent->rb_right;
	}

	new = xmalloc(sizeof(*new));
	new->name = xstrdup(name);
	new->addr = sym_num++;

	rb_link_node(&new->node, parent, p);
	rb_insert_color(&new->node, root);

	return new->addr;
}

/* resort symbol table by address */
static void sort_address(struct rb_root *root, struct uftrace_python_symbol *entry)
{
	struct rb_node *parent = NULL;
	struct rb_node **p = &root->rb_node;
	struct uftrace_python_symbol *iter;
	int cmp;

	while (*p) {
		parent = *p;
		iter = rb_entry(parent, struct uftrace_python_symbol, node);

		cmp = iter->addr - entry->addr;
		if (cmp > 0)
			p = &parent->rb_left;
		else
			p = &parent->rb_right;
	}

	rb_link_node(&entry->node, parent, p);
	rb_insert_color(&entry->node, root);
}

static void write_symtab(const char *dirname)
{
	struct rb_node *node;
	struct rb_root addr_tree = RB_ROOT;
	struct uftrace_python_symbol *sym;
	char *filename = NULL;
	FILE *fp;

	xasprintf(&filename, "%s/%s", dirname, PYTHON_SYMTAB_NAME);

	fp = fopen(filename, "a");
	if (fp == NULL) {
		pr_warn("writing symbol table of python program failed: %m");
		return;
	}

	/* symbol table assumes it's sorted by address */
	while (!RB_EMPTY_ROOT(&name_tree)) {
		node = rb_first(&name_tree);
		rb_erase(node, &name_tree);

		/* move it from name_tree to addr_tree */
		sym = rb_entry(node, struct uftrace_python_symbol, node);
		sort_address(&addr_tree, sym);
	}

	while (!RB_EMPTY_ROOT(&addr_tree)) {
		node = rb_first(&addr_tree);
		rb_erase(node, &addr_tree);

		sym = rb_entry(node, struct uftrace_python_symbol, node);
		fprintf(fp, "%x %c %s\n", sym->addr, 't', sym->name);

		free(sym->name);
		free(sym);
	}

	fprintf(fp, "%x %c %s\n", sym_num, 't', "__sym_end");
	fclose(fp);
}

static unsigned long convert_function_addr(PyObject *frame)
{
	PyObject *code, *name;
	char *str_name;
	unsigned long addr = 0;
	bool needs_free = false;

	code = PyObject_GetAttrString(frame, "f_code");
	if (code == NULL)
		return 0;

	name = PyObject_GetAttrString(code, "co_name");
	if (name == NULL)
		goto out;

	str_name = get_py_string(name);

	if (!strcmp(str_name, "<module>")) {
		PyObject *global = PyEval_GetGlobals();

		if (global != NULL) {
			PyObject *mod = PyDict_GetItemString(global, "__name__");
			if (mod && check_py_string(mod)) {
				xasprintf(&str_name, "<module:%s>", get_py_string(mod));
				needs_free = true;
			}
		}
	}

	addr = find_function(&name_tree, str_name);

out:
	if (needs_free)
		free(str_name);
	Py_XDECREF(code);
	Py_XDECREF(name);
	return addr;
}

static PyObject *uftrace_trace_python(PyObject *self, PyObject *args)
{
	PyObject *frame, *args_tuple;
	const char *event;

	if (!PyArg_ParseTuple(args, "OsO", &frame, &event, &args_tuple))
		Py_RETURN_NONE;

	if (!strcmp(event, "line"))
		Py_RETURN_NONE;

	if (!strcmp(event, "call")) {
		unsigned long addr;

		addr = convert_function_addr(frame);
		cygprof_enter(addr, 0);
	}
	else if (!strcmp(event, "return"))
		cygprof_exit(0, 0);

	Py_INCREF(uftrace_func);
	return uftrace_func;
}

static void __attribute__((destructor)) uftrace_trace_python_finish(void)
{
	const char *dirname;

	dirname = getenv("UFTRACE_DIR");
	if (dirname == NULL)
		dirname = UFTRACE_DIR_NAME;

	write_symtab(dirname);
}
