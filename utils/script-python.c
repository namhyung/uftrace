/*
 * Python script binding for function entry and exit
 *
 * Copyright (C) 2017, LG Electronics, Honggyu Kim <hong.gyu.kim@lge.com>
 *
 * Released under the GPL v2.
 */

#ifdef HAVE_LIBPYTHON2

/* This should be defined before #include "utils.h" */
#define PR_FMT     "script"
#define PR_DOMAIN  DBG_SCRIPT

#include <dlfcn.h>
#include <pthread.h>
#include "utils/utils.h"
#include "utils/symbol.h"
#include "utils/fstack.h"
#include "utils/filter.h"
#include "utils/script.h"
#include "utils/script-python.h"

/* python library name, it only supports python 2.7 as of now */
static const char *libpython = "libpython2.7.so";

/* python library handle returned by dlopen() */
static void *python_handle;

/* global mutex for python interpreter */
static pthread_mutex_t python_interpreter_lock = PTHREAD_MUTEX_INITIALIZER;

/* whether error in script was reported to user */
static bool python_error_reported = false;

static PyAPI_FUNC(void) (*__Py_Initialize)(void);
static PyAPI_FUNC(void) (*__Py_Finalize)(void);
static PyAPI_FUNC(void) (*__PySys_SetPath)(char *);
static PyAPI_FUNC(PyObject *) (*__PyImport_Import)(PyObject *name);

static PyAPI_FUNC(PyObject *) (*__PyErr_Occurred)(void);
static PyAPI_FUNC(void) (*__PyErr_Print)(void);
static PyAPI_FUNC(void) (*__PyErr_Clear)(void);

static PyAPI_FUNC(PyObject *) (*__PyObject_GetAttrString)(PyObject *, const char *);
static PyAPI_FUNC(int) (*__PyCallable_Check)(PyObject *);
static PyAPI_FUNC(PyObject *) (*__PyObject_CallObject)(PyObject *callable_object, PyObject *args);
static PyAPI_FUNC(int) (*__PyRun_SimpleStringFlags)(const char *, PyCompilerFlags *);

static PyAPI_FUNC(PyObject *) (*__PyString_FromString)(const char *);
static PyAPI_FUNC(PyObject *) (*__PyInt_FromLong)(long);
static PyAPI_FUNC(PyObject *) (*__PyLong_FromLong)(long);
static PyAPI_FUNC(PyObject *) (*__PyLong_FromUnsignedLongLong)(unsigned PY_LONG_LONG);
static PyAPI_FUNC(PyObject *) (*__PyFloat_FromDouble)(double);

static PyAPI_FUNC(char *) (*__PyString_AsString)(PyObject *);
static PyAPI_FUNC(long) (*__PyLong_AsLong)(PyObject *);

static PyAPI_FUNC(PyObject *) (*__PyTuple_New)(Py_ssize_t size);
static PyAPI_FUNC(int) (*__PyTuple_SetItem)(PyObject *, Py_ssize_t, PyObject *);
static PyAPI_FUNC(PyObject *) (*__PyTuple_GetItem)(PyObject *, Py_ssize_t);

static PyAPI_FUNC(Py_ssize_t) (*__PyList_Size)(PyObject *);
static PyAPI_FUNC(PyObject *) (*__PyList_GetItem)(PyObject *, Py_ssize_t);

static PyAPI_FUNC(PyObject *) (*__PyDict_New)(void);
static PyAPI_FUNC(int) (*__PyDict_SetItem)(PyObject *mp, PyObject *key, PyObject *item);
static PyAPI_FUNC(int) (*__PyDict_SetItemString)(PyObject *dp, const char *key, PyObject *item);
static PyAPI_FUNC(PyObject *) (*__PyDict_GetItem)(PyObject *mp, PyObject *key);

static PyObject *pModule, *pFuncEntry, *pFuncExit, *pFuncEnd;

enum py_context_idx {
	PY_CTX_TID = 0,
	PY_CTX_DEPTH,
	PY_CTX_TIMESTAMP,
	PY_CTX_DURATION,
	PY_CTX_ADDRESS,
	PY_CTX_NAME,
	PY_CTX_ARGS,
	PY_CTX_RETVAL,
};

/* The order has to be aligned with enum py_args above. */
static const char *py_context_table[] = {
	"tid",
	"depth",
	"timestamp",
	"duration",
	"address",
	"name",
	"args",
	"retval",
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

static int set_python_path(char *py_pathname)
{
	char py_sysdir[PATH_MAX];
	char *old_sysdir = getenv("PYTHONPATH");
	char *new_sysdir = NULL;

	pr_dbg2("%s(\"%s\")\n", __func__, py_pathname);

	if (absolute_dirname(py_pathname, py_sysdir) == NULL)
		return -1;

	if (old_sysdir)
		xasprintf(&new_sysdir, "%s:%s", old_sysdir, py_sysdir);
	else
		new_sysdir = xstrdup(py_sysdir);

	setenv("PYTHONPATH", new_sysdir, 1);
	free(new_sysdir);

	return 0;
}

/* Import python module that is given by -S option. */
static int import_python_module(char *py_pathname)
{
	PyObject *pName;
	char *py_basename = xstrdup(basename(py_pathname));

	remove_py_suffix(py_basename);

	pName = __PyString_FromString(py_basename);
	free(py_basename);

	pModule = __PyImport_Import(pName);
	if (pModule == NULL) {
		__PyErr_Print();
		pr_warn("\"%s\" cannot be imported!\n", py_pathname);
		return -1;
	}

	Py_XDECREF(pName);

	/* import sys by default */
	__PyRun_SimpleStringFlags("import sys", NULL);

	pr_dbg("python module \"%s\" is imported.\n", py_pathname);

	return 0;
}

union python_val {
	long			l;
	unsigned long long	ull;
	char			*s;
	double			f;
};

static void python_insert_tuple(PyObject *tuple, char type, int idx,
				union python_val val)
{
	PyObject *obj;

	switch (type) {
	case 'l':
		obj = __PyInt_FromLong(val.l);
		break;
	case 'U':
		obj = __PyLong_FromUnsignedLongLong(val.ull);
		break;
	case 's':
		obj = __PyString_FromString(val.s);
		break;
	case 'f':
		obj = __PyFloat_FromDouble(val.f);
		break;
	default:
		pr_warn("unsupported data type was added to tuple\n");
		obj = NULL;
		break;
	}

	__PyTuple_SetItem(tuple, idx, obj);
}

static void python_insert_dict(PyObject *dict, char type, const char *key,
			       union python_val val)
{
	PyObject *obj;

	switch (type) {
	case 'l':
		obj = __PyInt_FromLong(val.l);
		break;
	case 'U':
		obj = __PyLong_FromUnsignedLongLong(val.ull);
		break;
	case 's':
		obj = __PyString_FromString(val.s);
		break;
	default:
		pr_warn("unsupported data type was added to dict\n");
		obj = NULL;
		break;
	}

	__PyDict_SetItemString(dict, key, obj);
	Py_XDECREF(obj);
}

static void insert_tuple_long(PyObject *tuple, int idx, long v)
{
	union python_val val = { .l = v, };
	python_insert_tuple(tuple, 'l', idx, val);
}

static void insert_tuple_ull(PyObject *tuple, int idx, unsigned long long v)
{
	union python_val val = { .ull = v, };
	python_insert_tuple(tuple, 'U', idx, val);
}

static void insert_tuple_string(PyObject *tuple, int idx, char *v)
{
	union python_val val = { .s = v, };
	python_insert_tuple(tuple, 's', idx, val);
}

static void insert_tuple_double(PyObject *tuple, int idx, double v)
{
	union python_val val = { .f = v, };
	python_insert_tuple(tuple, 'f', idx, val);
}

static void insert_dict_long(PyObject *dict, const char *key, long v)
{
	union python_val val = { .l = v, };
	python_insert_dict(dict, 'l', key, val);
}

static void insert_dict_ull(PyObject *dict, const char *key, unsigned long long v)
{
	union python_val val = { .ull = v, };
	python_insert_dict(dict, 'U', key, val);
}

static void insert_dict_string(PyObject *dict, const char *key, char *v)
{
	union python_val val = { .s = v, };
	python_insert_dict(dict, 's', key, val);
}

#define PYCTX(_item)  py_context_table[PY_CTX_##_item]

static void setup_common_context(PyObject **pDict, struct script_context *sc_ctx)
{
	insert_dict_long(*pDict, PYCTX(TID), sc_ctx->tid);
	insert_dict_long(*pDict, PYCTX(DEPTH), sc_ctx->depth);
	insert_dict_ull(*pDict, PYCTX(TIMESTAMP), sc_ctx->timestamp);
	insert_dict_long(*pDict, PYCTX(ADDRESS), sc_ctx->address);
	insert_dict_string(*pDict, PYCTX(NAME), sc_ctx->name);
}

static void setup_argument_context(PyObject **pDict, bool is_retval,
				   struct script_context *sc_ctx)
{
	struct uftrace_arg_spec *spec;
	void *data = sc_ctx->argbuf;
	PyObject *args;
	union {
		char          c;
		short         s;
		int           i;
		long          l;
		long long     L;
		float         f;
		double        d;
		long double   D;
		unsigned char v[16];
	} val;
	int count = 0;

	list_for_each_entry(spec, sc_ctx->argspec, list) {
		/* skip unwanted arguments or retval */
		if (is_retval != (spec->idx == RETVAL_IDX))
			continue;

		count++;
	}

	if (count == 0)
		return;

	args = __PyTuple_New(count);
	if (args == NULL)
		pr_err("failed to allocate python tuple for argument");

	count = 0;
	list_for_each_entry(spec, sc_ctx->argspec, list) {
		const int null_str = -1;
		unsigned short slen;
		char ch_str[2];
		char *str;
		double dval;

		/* skip unwanted arguments or retval */
		if (is_retval != (spec->idx == RETVAL_IDX))
			continue;

		/* reset the value */
		memset(val.v, 0, sizeof(val));

		switch (spec->fmt) {
		case ARG_FMT_AUTO:
		case ARG_FMT_SINT:
		case ARG_FMT_UINT:
		case ARG_FMT_HEX:
		case ARG_FMT_FUNC_PTR:
		case ARG_FMT_ENUM:
			memcpy(val.v, data, spec->size);
			switch (spec->size) {
			case 1:
				insert_tuple_long(args, count++, val.c);
				break;
			case 2:
				insert_tuple_long(args, count++, val.s);
				break;
			case 4:
				insert_tuple_long(args, count++, val.i);
				break;
			case 8:
				insert_tuple_ull(args, count++, val.L);
				break;
			default:
				pr_warn("invalid integer size: %d\n", spec->size);
				break;
			}
			data += ALIGN(spec->size, 4);
			break;

		case ARG_FMT_FLOAT:
			memcpy(val.v, data, spec->size);
			switch (spec->size) {
			case 4:
				dval = val.f;
				break;
			case 8:
				dval = val.d;
				break;
			case 10:
				dval = (double)val.D;
				break;
			default:
				pr_dbg("invalid floating-point type size %d\n",
				       spec->size);
				dval = 0;
				break;
			}
			insert_tuple_double(args, count++, dval);
			data += ALIGN(spec->size, 4);
			break;

		case ARG_FMT_STR:
		case ARG_FMT_STD_STRING:
			/* get string length (2 bytes in the beginning) */
			memcpy(&slen, data, 2);

			str = xmalloc(slen + 1);

			/* copy real string contents */
			memcpy(str, data + 2, slen);
			str[slen] = '\0';

			/* NULL string is encoded as '0xffffffff' */
			if (!memcmp(str, &null_str, sizeof(null_str)))
				strcpy(str, "NULL");

			insert_tuple_string(args, count++, str);
			free(str);
			data += ALIGN(slen + 2, 4);
			break;

		case ARG_FMT_CHAR:
			/* make it a string */
			memcpy(ch_str, data, 1);
			ch_str[1] = '\0';

			insert_tuple_string(args, count++, ch_str);
			data += 4;
			break;

		default:
			pr_warn("invalid argument format: %d\n", spec->fmt);
			break;
		}
	}

	if (is_retval) {
		PyObject *retval = __PyTuple_GetItem(args, 0);

		/* single return value doesn't need a tuple */
		__PyDict_SetItemString(*pDict, PYCTX(RETVAL), retval);
	}
	else {
		/* arguments will be returned in a tuple */
		__PyDict_SetItemString(*pDict, PYCTX(ARGS), args);
	}
	Py_XDECREF(args);
}

int python_uftrace_entry(struct script_context *sc_ctx)
{
	if (unlikely(!pFuncEntry))
		return -1;

	pthread_mutex_lock(&python_interpreter_lock);

	/* Entire arguments are passed into a single dictionary. */
	PyObject *pDict = __PyDict_New();

	/* Setup common info in both entry and exit into a dictionary */
	setup_common_context(&pDict, sc_ctx);

	if (sc_ctx->arglen)
		setup_argument_context(&pDict, false, sc_ctx);

	/* Python function arguments must be passed in a tuple. */
	PyObject *pythonContext = __PyTuple_New(1);
	__PyTuple_SetItem(pythonContext, 0, pDict);

	/* Call python function "uftrace_entry". */
	__PyObject_CallObject(pFuncEntry, pythonContext);
	if (debug) {
		if (__PyErr_Occurred() && !python_error_reported) {
			pr_dbg("uftrace_entry failed:\n");
			__PyErr_Print();

			python_error_reported = true;
		}
	}

	/* Free PyTuple. */
	Py_XDECREF(pythonContext);

	pthread_mutex_unlock(&python_interpreter_lock);

	return 0;
}

int python_uftrace_exit(struct script_context *sc_ctx)
{
	if (unlikely(!pFuncExit))
		return -1;

	pthread_mutex_lock(&python_interpreter_lock);

	/* Entire arguments are passed into a single dictionary. */
	PyObject *pDict = __PyDict_New();

	/* Setup common info in both entry and exit into a dictionary */
	setup_common_context(&pDict, sc_ctx);

	/* Add time duration info */
	insert_dict_ull(pDict, PYCTX(DURATION), sc_ctx->duration);

	if (sc_ctx->arglen)
		setup_argument_context(&pDict, true, sc_ctx);

	/* Python function arguments must be passed in a tuple. */
	PyObject *pythonContext = __PyTuple_New(1);
	__PyTuple_SetItem(pythonContext, 0, pDict);

	/* Call python function "uftrace_exit". */
	__PyObject_CallObject(pFuncExit, pythonContext);
	if (debug) {
		if (__PyErr_Occurred() && !python_error_reported) {
			pr_dbg("uftrace_exit failed:\n");
			__PyErr_Print();

			python_error_reported = true;
		}
	}

	/* Free PyTuple. */
	Py_XDECREF(pythonContext);

	pthread_mutex_unlock(&python_interpreter_lock);

	return 0;
}

int python_uftrace_end(void)
{
	if (unlikely(!pFuncEnd))
		return -1;

	pr_dbg("%s()\n", __func__);

	pthread_mutex_lock(&python_interpreter_lock);

	/* Call python function "uftrace_end". */
	__PyObject_CallObject(pFuncEnd, NULL);

	pthread_mutex_unlock(&python_interpreter_lock);

	return 0;
}

int python_atfork_prepare(void)
{
	pr_dbg("flush python buffer in %s()\n", __func__);

	pthread_mutex_lock(&python_interpreter_lock);

	__PyRun_SimpleStringFlags("sys.stdout.flush()", NULL);

	pthread_mutex_unlock(&python_interpreter_lock);

	return 0;
}

int script_init_for_python(char *py_pathname,
			   enum uftrace_pattern_type ptype)
{
	pr_dbg("%s(\"%s\")\n", __func__, py_pathname);

	/* Bind script_uftrace functions to python's. */
	script_uftrace_entry = python_uftrace_entry;
	script_uftrace_exit = python_uftrace_exit;
	script_uftrace_end = python_uftrace_end;
	script_atfork_prepare = python_atfork_prepare;

	python_handle = dlopen(libpython, RTLD_LAZY | RTLD_GLOBAL);
	if (!python_handle) {
		pr_warn("%s cannot be loaded!\n", libpython);
		return -1;
	}

	INIT_PY_API_FUNC(Py_Initialize);
	INIT_PY_API_FUNC(Py_Finalize);
	INIT_PY_API_FUNC(PySys_SetPath);
	INIT_PY_API_FUNC(PyImport_Import);

	INIT_PY_API_FUNC(PyErr_Occurred);
	INIT_PY_API_FUNC(PyErr_Print);
	INIT_PY_API_FUNC(PyErr_Clear);

	INIT_PY_API_FUNC(PyObject_GetAttrString);
	INIT_PY_API_FUNC(PyCallable_Check);
	INIT_PY_API_FUNC(PyObject_CallObject);
	INIT_PY_API_FUNC(PyRun_SimpleStringFlags);

	INIT_PY_API_FUNC(PyString_FromString);
	INIT_PY_API_FUNC(PyInt_FromLong);
	INIT_PY_API_FUNC(PyLong_FromLong);
	INIT_PY_API_FUNC(PyLong_FromUnsignedLongLong);
	INIT_PY_API_FUNC(PyFloat_FromDouble);

	INIT_PY_API_FUNC(PyString_AsString);
	INIT_PY_API_FUNC(PyLong_AsLong);

	INIT_PY_API_FUNC(PyTuple_New);
	INIT_PY_API_FUNC(PyTuple_SetItem);
	INIT_PY_API_FUNC(PyTuple_GetItem);

	INIT_PY_API_FUNC(PyList_Size);
	INIT_PY_API_FUNC(PyList_GetItem);

	INIT_PY_API_FUNC(PyDict_New);
	INIT_PY_API_FUNC(PyDict_SetItem);
	INIT_PY_API_FUNC(PyDict_SetItemString);
	INIT_PY_API_FUNC(PyDict_GetItem);

	set_python_path(py_pathname);

	pthread_mutex_lock(&python_interpreter_lock);

	__Py_Initialize();

	/* Import python module that is passed by -p option. */
	if (import_python_module(py_pathname) < 0) {
		pthread_mutex_unlock(&python_interpreter_lock);
		return -1;
	}

	/* check if script has its own list of functions to run */
	PyObject *filter_list = __PyObject_GetAttrString(pModule, "UFTRACE_FUNCS");
	if (filter_list) {
		int i, len;

		/* XXX: type checking is hard */
		len = __PyList_Size(filter_list);

		for (i = 0; i < len; i++) {
			PyObject *func = __PyList_GetItem(filter_list, i);

			script_add_filter(__PyString_AsString(func), ptype);
		}
	}

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

	__PyErr_Clear();

	pthread_mutex_unlock(&python_interpreter_lock);

	pr_dbg("python initialization finished\n");

	return 0;
}

void script_finish_for_python(void)
{
	pr_dbg("%s()\n", __func__);

	pthread_mutex_lock(&python_interpreter_lock);

	__Py_Finalize();

	pthread_mutex_unlock(&python_interpreter_lock);
}

#endif /* !HAVE_LIBPYTHON2 */
