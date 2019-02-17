#include <Python.h>

#include "utils/utils.h"

/* pointer to python tracing function */
extern PyObject *uftrace_func;

extern PyMethodDef uftrace_methods[2];

void find_libmcount_funcs(void);

char *get_py_string(PyObject *object)
{
	return PyString_AsString(object);
}

int check_py_string(PyObject *object)
{
	return PyString_Check(object);
}

/* the name should be 'init' + <module name> */
PyMODINIT_FUNC inittrace_python2(void)
{
	PyObject *m, *d;

	outfp = stdout;
	logfp = stdout;

	m = Py_InitModule("trace_python2", uftrace_methods);
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
