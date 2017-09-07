/*
 * Python script binding for function entry and exit
 *
 * Copyright (C) 2017, LG Electronics, Honggyu Kim <hong.gyu.kim@lge.com>
 *
 * Released under the GPL v2.
 */

#ifdef HAVE_LIBPYTHON2

#include <dlfcn.h>
#include "utils/symbol.h"
#include "utils/fstack.h"
#include "utils/script.h"
#include "utils/script-python.h"

/* python library name, it only supports python 2.7 as of now */
static const char *libpython = "libpython2.7.so";

/* python library handle returned by dlopen() */
static void *python_handle;

static PyAPI_FUNC(void) (*__Py_Initialize)(void);
static PyAPI_FUNC(void) (*__PySys_SetPath)(char *);
static PyAPI_FUNC(PyObject *) (*__PyImport_Import)(PyObject *name);

static PyAPI_FUNC(PyObject *) (*__PyErr_Occurred)(void);
static PyAPI_FUNC(void) (*__PyErr_Print)(void);

static PyAPI_FUNC(PyObject *) (*__PyObject_GetAttrString)(PyObject *, const char *);
static PyAPI_FUNC(int) (*__PyCallable_Check)(PyObject *);
static PyAPI_FUNC(PyObject *) (*__PyObject_CallObject)(PyObject *callable_object, PyObject *args);

static PyAPI_FUNC(PyObject *) (*__PyString_FromString)(const char *);
static PyAPI_FUNC(PyObject *) (*__PyInt_FromLong)(long);
static PyAPI_FUNC(PyObject *) (*__PyLong_FromLong)(long);
static PyAPI_FUNC(PyObject *) (*__PyLong_FromUnsignedLongLong)(unsigned PY_LONG_LONG);

static PyAPI_FUNC(char *) (*__PyString_AsString)(PyObject *);
static PyAPI_FUNC(long) (*__PyLong_AsLong)(PyObject *);

static PyAPI_FUNC(PyObject *) (*__PyTuple_New)(Py_ssize_t size);
static PyAPI_FUNC(int) (*__PyTuple_SetItem)(PyObject *, Py_ssize_t, PyObject *);

static PyAPI_FUNC(PyObject *) (*__PyDict_New)(void);
static PyAPI_FUNC(int) (*__PyDict_SetItem)(PyObject *mp, PyObject *key, PyObject *item);
static PyAPI_FUNC(int) (*__PyDict_SetItemString)(PyObject *dp, const char *key, PyObject *item);
static PyAPI_FUNC(PyObject *) (*__PyDict_GetItem)(PyObject *mp, PyObject *key);

static PyObject *pName, *pModule, *pFuncEntry, *pFuncExit, *pFuncEnd;

extern struct symtabs symtabs;

enum py_args {
	PY_ARG_TID = 0,
	PY_ARG_DEPTH,
	PY_ARG_TIMESTAMP,
	PY_ARG_DURATION,
	PY_ARG_ADDRESS,
	PY_ARG_SYMNAME,
};

/* The order has to be aligned with enum py_args above. */
static const char *py_args_table[] = {
	"tid",
	"depth",
	"timestamp",
	"duration",
	"address",
	"symname",
};

#define INIT_PY_API_FUNC(func) \
	do { \
		__##func = dlsym(python_handle, #func); \
		if (!__##func) { \
			pr_err("dlsym for \"" #func "\" is failed!\n"); \
			return -1; \
		} \
	} while (0)

static char *remove_py_suffix(char *py_name)
{
	char *ext = strrchr(py_name, '.');

	if (!ext)
		return NULL;

	*ext = '\0';
	return py_name;
}

/* Import python module that is given by -p option. */
static int import_python_module(char *py_pathname)
{
	char py_sysdir[PATH_MAX];
	if (absolute_dirname(py_pathname, py_sysdir) == NULL)
		return -1;

	/* Set path to import a python module. */
	__PySys_SetPath(py_sysdir);
	pr_dbg("PySys_SetPath(\"%s\") is done!\n", py_sysdir);

	char *py_basename = basename(py_pathname);
	remove_py_suffix(py_basename);

	pName = __PyString_FromString(py_basename);
	pModule = __PyImport_Import(pName);
	if (pModule == NULL) {
		__PyErr_Print();
		pr_warn("%s.py cannot be imported!\n", py_pathname);
		return -1;
	}

	return 0;
}

static void setup_common_args_in_dict(PyObject **pDict,
				      struct script_args *sc_args)
{
	int tid = sc_args->tid;
	int depth = sc_args->depth;
	uint64_t timestamp = sc_args->timestamp;
	unsigned long address = sc_args->address;
	char *symname = sc_args->symname;

	PyObject *pTid = __PyInt_FromLong(tid);
	PyObject *pDepth = __PyInt_FromLong(depth);
	PyObject *pTimeStamp = __PyLong_FromUnsignedLongLong(timestamp);
	PyObject *pAddress = __PyInt_FromLong(address);
	PyObject *pSym  = __PyString_FromString(symname);

	__PyDict_SetItemString(*pDict, py_args_table[PY_ARG_TID], pTid);
	__PyDict_SetItemString(*pDict, py_args_table[PY_ARG_DEPTH], pDepth);
	__PyDict_SetItemString(*pDict, py_args_table[PY_ARG_TIMESTAMP], pTimeStamp);
	__PyDict_SetItemString(*pDict, py_args_table[PY_ARG_ADDRESS], pAddress);
	__PyDict_SetItemString(*pDict, py_args_table[PY_ARG_SYMNAME], pSym);

	/* Py_XDECREF() frees the object when the count reaches zero. */
	Py_XDECREF(pTid);
	Py_XDECREF(pDepth);
	Py_XDECREF(pTimeStamp);
	Py_XDECREF(pAddress);
	Py_XDECREF(pSym);
}

int python_uftrace_entry(struct script_args *sc_args)
{
	if (unlikely(!pFuncEntry))
		return -1;

	/* Entire arguments are passed into a single dictionary. */
	PyObject *pDict = __PyDict_New();

	/* Setup common arguments in both entry and exit into a dictionary */
	setup_common_args_in_dict(&pDict, sc_args);

	/* Argument list must be passed in a tuple. */
	PyObject *pythonArgument = __PyTuple_New(1);
	__PyTuple_SetItem(pythonArgument, 0, pDict);

	/* Call python function "uftrace_entry". */
	__PyObject_CallObject(pFuncEntry, pythonArgument);

	/* Free PyTuple. */
	Py_XDECREF(pythonArgument);

	return 0;
}

int python_uftrace_exit(struct script_args *sc_args)
{
	if (unlikely(!pFuncExit))
		return -1;

	/* Entire arguments are passed into a single dictionary. */
	PyObject *pDict = __PyDict_New();

	/* Setup common arguments in both entry and exit into a dictionary */
	setup_common_args_in_dict(&pDict, sc_args);

	/* Add time duration info */
	uint64_t duration = sc_args->duration;
	PyObject *pDuration = __PyLong_FromUnsignedLongLong(duration);
	__PyDict_SetItemString(pDict, py_args_table[PY_ARG_DURATION], pDuration);
	Py_XDECREF(pDuration);

	/* Argument list must be passed in a tuple. */
	PyObject *pythonArgument = __PyTuple_New(1);
	__PyTuple_SetItem(pythonArgument, 0, pDict);

	/* Call python function "uftrace_exit". */
	__PyObject_CallObject(pFuncExit, pythonArgument);

	/* Free PyTuple. */
	Py_XDECREF(pythonArgument);

	return 0;
}

int python_uftrace_end(void)
{
	if (unlikely(!pFuncEnd))
		return -1;

	/* Call python function "uftrace_end". */
	__PyObject_CallObject(pFuncEnd, NULL);

	return 0;
}

int script_init_for_python(char *py_pathname)
{
	pr_dbg("initialize python\n");

	/* Bind script_uftrace functions to python's. */
	script_uftrace_entry = python_uftrace_entry;
	script_uftrace_exit = python_uftrace_exit;
	script_uftrace_end = python_uftrace_end;

	python_handle = dlopen(libpython, RTLD_LAZY | RTLD_GLOBAL);
	if (!python_handle) {
		pr_warn("%s cannot be loaded!\n", libpython);
		return -1;
	}

	INIT_PY_API_FUNC(Py_Initialize);
	INIT_PY_API_FUNC(PySys_SetPath);
	INIT_PY_API_FUNC(PyImport_Import);

	INIT_PY_API_FUNC(PyErr_Occurred);
	INIT_PY_API_FUNC(PyErr_Print);

	INIT_PY_API_FUNC(PyObject_GetAttrString);
	INIT_PY_API_FUNC(PyCallable_Check);
	INIT_PY_API_FUNC(PyObject_CallObject);

	INIT_PY_API_FUNC(PyString_FromString);
	INIT_PY_API_FUNC(PyInt_FromLong);
	INIT_PY_API_FUNC(PyLong_FromLong);
	INIT_PY_API_FUNC(PyLong_FromUnsignedLongLong);

	INIT_PY_API_FUNC(PyString_AsString);
	INIT_PY_API_FUNC(PyLong_AsLong);

	INIT_PY_API_FUNC(PyTuple_New);
	INIT_PY_API_FUNC(PyTuple_SetItem);

	INIT_PY_API_FUNC(PyDict_New);
	INIT_PY_API_FUNC(PyDict_SetItem);
	INIT_PY_API_FUNC(PyDict_SetItemString);
	INIT_PY_API_FUNC(PyDict_GetItem);

	__Py_Initialize();

	/* Import python module that is passed by -p option. */
	if (import_python_module(py_pathname) < 0)
		return -1;


	/* Call python function "uftrace_begin" immediately if possible. */
	PyObject *pFuncBegin = __PyObject_GetAttrString(pModule, "uftrace_begin");
	if (pFuncBegin && __PyCallable_Check(pFuncBegin))
		__PyObject_CallObject(pFuncBegin, NULL);

	pFuncEntry = __PyObject_GetAttrString(pModule, "uftrace_entry");
	if (!pFuncEntry || !__PyCallable_Check(pFuncEntry)) {
		if (__PyErr_Occurred())
			__PyErr_Print();
		pr_dbg("uftrace_entry is not callable!\n");
		pFuncEntry = NULL;
	}
	pFuncExit = __PyObject_GetAttrString(pModule, "uftrace_exit");
	if (!pFuncExit || !__PyCallable_Check(pFuncExit)) {
		if (__PyErr_Occurred())
			__PyErr_Print();
		pr_dbg("uftrace_exit is not callable!\n");
		pFuncExit = NULL;
	}
	pFuncEnd = __PyObject_GetAttrString(pModule, "uftrace_end");
	if (!pFuncEnd || !__PyCallable_Check(pFuncEnd)) {
		pr_dbg("uftrace_end is not callable!\n");
		pFuncEnd = NULL;
	}

	pr_dbg("script_init_for_python for \"%s.py\" is done!\n", py_pathname);

	return 0;
}

#endif /* !HAVE_LIBPYTHON2 */
