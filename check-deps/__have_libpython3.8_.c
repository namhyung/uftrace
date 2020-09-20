#define PY_SSIZE_T_CLEAN
#include <Python.h>

#if PY_MAJOR_VERSION != 3
#error python version is not 3
#endif

int main(void)
{
       Py_Initialize();
       return 0;
}
