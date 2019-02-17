#include <Python.h>

#include "utils/utils.h"

/* pointer to python tracing function */
extern PyObject *uftrace_func;

extern PyMethodDef uftrace_methods[2];

void find_libmcount_funcs(void);

char *get_py_string(PyObject *object)
{
	return PyUnicode_AsUTF8(object);
}

int check_py_string(PyObject *object)
{
	return PyUnicode_Check(object);
}

static struct PyModuleDef moduledef = {
	PyModuleDef_HEAD_INIT,
	"trace_python3",
	"A Python module for uftrace.",
	-1,
	uftrace_methods
};

/* the name should be 'PyInit_' + <module name> */
PyMODINIT_FUNC PyInit_trace_python3(void)
{
	PyObject *m, *d;

	outfp = stdout;
	logfp = stdout;

	m = PyModule_Create(&moduledef);
	if (m == NULL)
		return NULL;

	d = PyModule_GetDict(m);

	/* keep the pointer to trace function as it's used as a return value */
	uftrace_func = PyDict_GetItemString(d, "trace");

	/* check if it's loaded in a uftrace session */
	if (getenv("UFTRACE_SHMEM") == NULL)
		return NULL;

	find_libmcount_funcs();

	return m;
}
