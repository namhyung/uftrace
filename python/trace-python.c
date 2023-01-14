/*
 * python extension module to trace python functions for uftrace
 *
 * Copyright (C) 2023,  Namhyung Kim <namhyung@gmail.com>
 *
 * Released under the GPL v2.
 */
#include <Python.h>

#include "utils/symbol.h"

/* python module state */
struct uftrace_py_state {
	PyObject *trace_func;
};

/* pointer to python tracing function (for libpython2.7) */
static PyObject *uftrace_func __attribute__((unused));

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

static void init_uftrace(void)
{
	/* check if it's loaded in a uftrace session */
	if (getenv("UFTRACE_SHMEM") == NULL)
		return;

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
	"uftrace_python",
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

	m = Py_InitModule("uftrace_python", uftrace_py_methods);
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

#endif /* HAVE_LIBPYTHON2 */

/*
 * This is the actual function when called for each function.
 */
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

	return get_trace_function();
}
