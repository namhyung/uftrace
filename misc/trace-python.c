#include <python2.7/Python.h>

#include "utils/symbol.h"

/* pointer to python tracing function */
static PyObject *uftrace_func;

static void (*cygprof_enter)(unsigned long child, unsigned long parent);
static void (*cygprof_exit) (unsigned long child, unsigned long parent);

static PyObject *uftrace_trace_python(PyObject *self, PyObject *args);

static PyMethodDef uftrace_methods[] = {
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

/* the name should be 'init' + <module name> */
PyMODINIT_FUNC inittrace_python(void)
{
	PyObject *m, *d;

	m = Py_InitModule("trace_python", uftrace_methods);
	if (m == NULL)
		return;

	d = PyModule_GetDict(m);

	/* keep the pointer to trace function as it's used as a return value */
	uftrace_func = PyDict_GetItemString(d, "trace");

	/* check if it's loaded in a uftrace session */
	if (getenv("UFTRACE_SHMEM") == NULL)
		return;

	find_libmcount_funcs();
}

static PyObject *uftrace_trace_python(PyObject *self, PyObject *args)
{
	PyObject *frame, *args_tuple;
	const char *event;

	if (!PyArg_ParseTuple(args, "OsO", &frame, &event, &args_tuple))
		Py_RETURN_NONE;

	if (!strcmp(event, "line"))
		Py_RETURN_NONE;

	if (!strcmp(event, "call"))
		cygprof_enter(1, 2);
	else if (!strcmp(event, "return"))
		cygprof_exit(1, 2);

	Py_INCREF(uftrace_func);
	return uftrace_func;
}
