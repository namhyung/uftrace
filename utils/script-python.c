/*
 * Python script binding for function entry and exit
 *
 * Copyright (C) 2017, LG Electronics, Honggyu Kim <hong.gyu.kim@lge.com>
 *
 * Released under the GPL v2.
 */

#if defined(HAVE_LIBPYTHON2) || defined(HAVE_LIBPYTHON3)

/* This should be defined before #include "utils.h" */
#define PR_FMT "script"
#define PR_DOMAIN DBG_SCRIPT

#include "utils/script-python.h"
#include "utils/filter.h"
#include "utils/fstack.h"
#include "utils/script.h"
#include "utils/symbol.h"
#include "utils/utils.h"
#include <dlfcn.h>
#include <pthread.h>

/* python library name, it should support any version python v2 or v3 */
static const char libpython[] = "libpython" stringify(LIBPYTHON_VERSION) ".so";

/* python library handle returned by dlopen() */
static void *python_handle;

/* global mutex for python interpreter */
static pthread_mutex_t python_interpreter_lock = PTHREAD_MUTEX_INITIALIZER;

/* whether error in script was reported to user */
static bool python_error_reported = false;

/* whether script_init() was done successfully */
static bool python_initialized;

static void (*__Py_Initialize)(void);
static void (*__Py_Finalize)(void);
static void (*__PySys_SetPath)(char *);
static PyObject *(*__PyImport_Import)(PyObject *name);

static PyObject *(*__PyErr_Occurred)(void);
static void (*__PyErr_Print)(void);
static void (*__PyErr_Clear)(void);

static int (*__PyObject_HasAttrString)(PyObject *, const char *);
static PyObject *(*__PyObject_GetAttrString)(PyObject *, const char *);
static int (*__PyCallable_Check)(PyObject *);
static PyObject *(*__PyObject_CallObject)(PyObject *callable_object, PyObject *args);
static int (*__PyRun_SimpleStringFlags)(const char *, PyCompilerFlags *);

static PyObject *(*__PyString_FromString)(const char *);
static PyObject *(*__PyInt_FromLong)(long);
static PyObject *(*__PyLong_FromLong)(long);
static PyObject *(*__PyLong_FromUnsignedLongLong)(unsigned PY_LONG_LONG);
static PyObject *(*__PyFloat_FromDouble)(double);
static PyObject *(*__PyBool_FromLong)(long);

static char *(*__PyString_AsString)(PyObject *);
static long (*__PyLong_AsLong)(PyObject *);

static PyObject *(*__PyTuple_New)(Py_ssize_t size);
static int (*__PyTuple_SetItem)(PyObject *, Py_ssize_t, PyObject *);
static PyObject *(*__PyTuple_GetItem)(PyObject *, Py_ssize_t);

static Py_ssize_t (*__PyList_Size)(PyObject *);
static PyObject *(*__PyList_GetItem)(PyObject *, Py_ssize_t);

static PyObject *(*__PyDict_New)(void);
static int (*__PyDict_SetItem)(PyObject *mp, PyObject *key, PyObject *item);
static int (*__PyDict_SetItemString)(PyObject *dp, const char *key, PyObject *item);
static PyObject *(*__PyDict_GetItem)(PyObject *mp, PyObject *key);

/* for python3.8+ compatibility */
static void (*__Py_Dealloc)(PyObject *);

#if PY_VERSION_HEX >= 0x03080000

static inline void __Py_DECREF(PyObject *obj)
{
	if (--obj->ob_refcnt == 0)
		__Py_Dealloc(obj);
}

#undef Py_DECREF
#define Py_DECREF(obj) __Py_DECREF((PyObject *)obj))

static inline void __Py_XDECREF(PyObject *obj)
{
	if (obj)
		__Py_DECREF(obj);
}

#undef Py_XDECREF
#define Py_XDECREF(obj) __Py_XDECREF((PyObject *)obj)

#endif /* PY_VERSION_HEX >= 0x03080000 */

static PyObject *pModule, *pFuncBegin, *pFuncEntry, *pFuncExit, *pFuncEvent, *pFuncEnd;

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
	"tid", "depth", "timestamp", "duration", "address", "name", "args", "retval",
};

#define INIT_PY_API_FUNC(func)                                                                     \
	do {                                                                                       \
		__##func = dlsym(python_handle, #func);                                            \
		if (!__##func) {                                                                   \
			pr_err("dlsym for \"" #func "\" is failed");                               \
			return -1;                                                                 \
		}                                                                                  \
	} while (0)

#define INIT_PY_API_FUNC2(func, name)                                                              \
	do {                                                                                       \
		__##func = dlsym(python_handle, #name);                                            \
		if (!__##func) {                                                                   \
			pr_err("dlsym for \"" #name "\" is failed");                               \
			return -1;                                                                 \
		}                                                                                  \
	} while (0)

static int load_python_api_funcs(void)
{
	python_handle = dlopen(libpython, RTLD_LAZY | RTLD_GLOBAL);
	if (!python_handle) {
		pr_warn("%s cannot be loaded!\n", libpython);
		return -1;
	}
	pr_dbg("%s is loaded\n", libpython);

	INIT_PY_API_FUNC(Py_Initialize);
	INIT_PY_API_FUNC(PyImport_Import);
	INIT_PY_API_FUNC(Py_Finalize);

#ifdef HAVE_LIBPYTHON2
	INIT_PY_API_FUNC(PySys_SetPath);
	INIT_PY_API_FUNC(PyString_FromString);
	INIT_PY_API_FUNC(PyInt_FromLong);
	INIT_PY_API_FUNC(PyString_AsString);
	/* just to suppress compiler warning */
	__Py_Dealloc = NULL;
#else
	INIT_PY_API_FUNC2(PySys_SetPath, Py_SetPath);
	INIT_PY_API_FUNC2(PyString_FromString, PyUnicode_FromString);
	INIT_PY_API_FUNC2(PyInt_FromLong, PyLong_FromLong);
	INIT_PY_API_FUNC2(PyString_AsString, PyUnicode_AsUTF8);
	INIT_PY_API_FUNC2(Py_Dealloc, _Py_Dealloc);
#endif

	INIT_PY_API_FUNC(PyErr_Occurred);
	INIT_PY_API_FUNC(PyErr_Print);
	INIT_PY_API_FUNC(PyErr_Clear);

	INIT_PY_API_FUNC(PyObject_HasAttrString);
	INIT_PY_API_FUNC(PyObject_GetAttrString);
	INIT_PY_API_FUNC(PyCallable_Check);
	INIT_PY_API_FUNC(PyObject_CallObject);
	INIT_PY_API_FUNC(PyRun_SimpleStringFlags);

	INIT_PY_API_FUNC(PyLong_FromLong);
	INIT_PY_API_FUNC(PyLong_FromUnsignedLongLong);
	INIT_PY_API_FUNC(PyFloat_FromDouble);
	INIT_PY_API_FUNC(PyBool_FromLong);

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

	return 0;
}

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
	Py_XDECREF(pName);

	if (pModule == NULL) {
		__PyErr_Print();
		pr_warn("\"%s\" cannot be imported!\n", py_pathname);
		return -1;
	}

	/* import sys by default */
	__PyRun_SimpleStringFlags("import sys", NULL);

	pr_dbg("python module \"%s\" is imported.\n", py_pathname);

	return 0;
}

union python_val {
	long l;
	unsigned long long ull;
	char *s;
	double f;
};

static void python_insert_tuple(PyObject *tuple, char type, int idx, union python_val val)
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
		if (__PyErr_Occurred()) {
			Py_XDECREF(obj);
			obj = __PyString_FromString("<invalid value>");
			__PyErr_Clear();
		}
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

static void python_insert_dict(PyObject *dict, char type, const char *key, union python_val val)
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
		if (__PyErr_Occurred()) {
			Py_XDECREF(obj);
			obj = __PyString_FromString("<invalid value>");
			__PyErr_Clear();
		}
		break;
	case 'b':
		obj = __PyBool_FromLong(val.l);
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
	union python_val val = {
		.l = v,
	};
	python_insert_tuple(tuple, 'l', idx, val);
}

static void insert_tuple_ull(PyObject *tuple, int idx, unsigned long long v)
{
	union python_val val = {
		.ull = v,
	};
	python_insert_tuple(tuple, 'U', idx, val);
}

static void insert_tuple_string(PyObject *tuple, int idx, char *v)
{
	union python_val val = {
		.s = v,
	};
	python_insert_tuple(tuple, 's', idx, val);
}

static void insert_tuple_double(PyObject *tuple, int idx, double v)
{
	union python_val val = {
		.f = v,
	};
	python_insert_tuple(tuple, 'f', idx, val);
}

static void insert_dict_long(PyObject *dict, const char *key, long v)
{
	union python_val val = {
		.l = v,
	};
	python_insert_dict(dict, 'l', key, val);
}

static void insert_dict_ull(PyObject *dict, const char *key, unsigned long long v)
{
	union python_val val = {
		.ull = v,
	};
	python_insert_dict(dict, 'U', key, val);
}

static void insert_dict_string(PyObject *dict, const char *key, char *v)
{
	union python_val val = {
		.s = v,
	};
	python_insert_dict(dict, 's', key, val);
}

static void insert_dict_bool(PyObject *dict, const char *key, bool v)
{
	union python_val val = {
		.l = v,
	};
	python_insert_dict(dict, 'b', key, val);
}

#define PYCTX(_item) py_context_table[PY_CTX_##_item]

static void setup_common_context(PyObject **pDict, struct script_context *sc_ctx)
{
	insert_dict_long(*pDict, PYCTX(TID), sc_ctx->tid);
	insert_dict_long(*pDict, PYCTX(DEPTH), sc_ctx->depth);
	insert_dict_ull(*pDict, PYCTX(TIMESTAMP), sc_ctx->timestamp);
	insert_dict_long(*pDict, PYCTX(ADDRESS), sc_ctx->address);
	insert_dict_string(*pDict, PYCTX(NAME), sc_ctx->name);
}

static void setup_argument_context(PyObject **pDict, bool is_retval, struct script_context *sc_ctx)
{
	struct uftrace_arg_spec *spec;
	void *data = sc_ctx->argbuf;
	PyObject *args;
	union script_arg_val val;
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
		case ARG_FMT_PTR:
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
				pr_dbg("invalid floating-point type size %d\n", spec->size);
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
			if (slen == 4 && !memcmp(str, &null_str, sizeof(null_str)))
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

		case ARG_FMT_STRUCT:
			str = NULL;
			xasprintf(&str, "struct: %s{}", spec->type_name ? spec->type_name : "");
			insert_tuple_string(args, count++, str);
			free(str);
			data += ALIGN(spec->size, 4);
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

static void setup_event_argument(PyObject *pDict, struct script_context *sc_ctx)
{
	char *data = sc_ctx->argbuf;
	PyObject *args;

	if (data == NULL)
		data = "";

	args = __PyString_FromString(data);
	if (__PyErr_Occurred()) {
		Py_XDECREF(args);
		args = __PyString_FromString("<invalid value>");
		__PyErr_Clear();
	}

	/* arguments will be returned in a tuple */
	__PyDict_SetItemString(pDict, PYCTX(ARGS), args);

	Py_XDECREF(args);
}

int python_uftrace_begin(struct script_info *info)
{
	PyObject *dict;
	PyObject *cmds;
	PyObject *ctx;
	int i;
	char *s;

	if (unlikely(!pFuncBegin))
		return -1;

	/* python_interpreter_lock is already held */
	dict = __PyDict_New();

	insert_dict_bool(dict, "record", info->record);
	insert_dict_string(dict, "version", info->version);

	cmds = __PyTuple_New(info->cmds.nr);

	strv_for_each(&info->cmds, s, i)
		insert_tuple_string(cmds, i, s);

	__PyDict_SetItemString(dict, "cmds", cmds);
	Py_XDECREF(cmds);

	ctx = __PyTuple_New(1);

	__PyTuple_SetItem(ctx, 0, dict);
	__PyObject_CallObject(pFuncBegin, ctx);

	if (debug) {
		if (__PyErr_Occurred()) {
			pr_dbg("uftrace_begin failed:\n");
			__PyErr_Print();
		}
	}

	Py_XDECREF(ctx);
	return 0;
}

int python_uftrace_entry(struct script_context *sc_ctx)
{
	PyObject *pDict;
	PyObject *pythonContext;

	if (unlikely(!pFuncEntry))
		return -1;

	pthread_mutex_lock(&python_interpreter_lock);

	/* Entire arguments are passed into a single dictionary. */
	pDict = __PyDict_New();

	/* Setup common info in both entry and exit into a dictionary */
	setup_common_context(&pDict, sc_ctx);

	if (sc_ctx->arglen)
		setup_argument_context(&pDict, false, sc_ctx);

	/* Python function arguments must be passed in a tuple. */
	pythonContext = __PyTuple_New(1);
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
	PyObject *pDict;
	PyObject *pythonContext;

	if (unlikely(!pFuncExit))
		return -1;

	pthread_mutex_lock(&python_interpreter_lock);

	/* Entire arguments are passed into a single dictionary. */
	pDict = __PyDict_New();

	/* Setup common info in both entry and exit into a dictionary */
	setup_common_context(&pDict, sc_ctx);

	/* Add time duration info */
	insert_dict_ull(pDict, PYCTX(DURATION), sc_ctx->duration);

	if (sc_ctx->arglen)
		setup_argument_context(&pDict, true, sc_ctx);

	/* Python function arguments must be passed in a tuple. */
	pythonContext = __PyTuple_New(1);
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

int python_uftrace_event(struct script_context *sc_ctx)
{
	PyObject *pDict;
	PyObject *pythonContext;

	if (unlikely(!pFuncEvent))
		return -1;

	pthread_mutex_lock(&python_interpreter_lock);

	/* Entire arguments are passed into a single dictionary. */
	pDict = __PyDict_New();

	/* Setup common info into a dictionary */
	setup_common_context(&pDict, sc_ctx);
	setup_event_argument(pDict, sc_ctx);

	/* Python function arguments must be passed in a tuple. */
	pythonContext = __PyTuple_New(1);
	__PyTuple_SetItem(pythonContext, 0, pDict);

	/* Call python function "uftrace_exit". */
	__PyObject_CallObject(pFuncEvent, pythonContext);
	if (debug) {
		if (__PyErr_Occurred() && !python_error_reported) {
			pr_dbg("uftrace_event failed:\n");
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

	pthread_mutex_lock(&python_interpreter_lock);

	/* Call python function "uftrace_end". */
	__PyObject_CallObject(pFuncEnd, NULL);

	if (debug) {
		if (__PyErr_Occurred()) {
			pr_dbg("uftrace_end failed:\n");
			__PyErr_Print();
		}
	}

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

static PyObject *get_python_callback(char *name)
{
	PyObject *func;

	if (!__PyObject_HasAttrString(pModule, name))
		return NULL;

	func = __PyObject_GetAttrString(pModule, name);
	if (!func || !__PyCallable_Check(func)) {
		if (__PyErr_Occurred())
			__PyErr_Print();

		pr_dbg("%s is not callable!\n", name);
		func = NULL;
	}

	return func;
}

int script_init_for_python(struct script_info *info, enum uftrace_pattern_type ptype)
{
	char *py_pathname = info->name;

	pr_dbg("%s(\"%s\")\n", __func__, py_pathname);

	/* Bind script_uftrace functions to python's. */
	script_uftrace_entry = python_uftrace_entry;
	script_uftrace_exit = python_uftrace_exit;
	script_uftrace_event = python_uftrace_event;
	script_uftrace_end = python_uftrace_end;
	script_atfork_prepare = python_atfork_prepare;

	if (load_python_api_funcs() < 0)
		return -1;

	if (set_python_path(py_pathname) < 0) {
		dlclose(python_handle);
		return -1;
	}

	pthread_mutex_lock(&python_interpreter_lock);

	__Py_Initialize();
	python_initialized = true;

	/* Import python module that is passed by -p option. */
	if (import_python_module(py_pathname) < 0) {
		pthread_mutex_unlock(&python_interpreter_lock);
		/* script_finish() will release resources */
		return -1;
	}

	/* check if script has its own list of functions to run */
	if (__PyObject_HasAttrString(pModule, "UFTRACE_FUNCS")) {
		int i, len;
		PyObject *filter_list = __PyObject_GetAttrString(pModule, "UFTRACE_FUNCS");
		/* XXX: type checking is hard */
		len = __PyList_Size(filter_list);

		for (i = 0; i < len; i++) {
			PyObject *func = __PyList_GetItem(filter_list, i);

			script_add_filter(__PyString_AsString(func), ptype);
		}
	}

	pFuncBegin = get_python_callback("uftrace_begin");
	pFuncEntry = get_python_callback("uftrace_entry");
	pFuncExit = get_python_callback("uftrace_exit");
	pFuncEvent = get_python_callback("uftrace_event");
	pFuncEnd = get_python_callback("uftrace_end");

	/* Call python function "uftrace_begin" immediately if possible. */
	python_uftrace_begin(info);

	__PyErr_Clear();

	pthread_mutex_unlock(&python_interpreter_lock);

	pr_dbg("python initialization finished\n");

	return 0;
}

void script_finish_for_python(void)
{
	pr_dbg("%s()\n", __func__);

	if (!python_initialized)
		return;

	pthread_mutex_lock(&python_interpreter_lock);

	__Py_Finalize();

	pthread_mutex_unlock(&python_interpreter_lock);

	dlclose(python_handle);
	python_handle = NULL;
}

#endif /* !(HAVE_LIBPYTHON2 || HAVE_LIBPYTHON3) */
