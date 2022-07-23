#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char *argv[])
{
	void *handle;
	void (*sym)(int);
	int n = 1;

	if (argc > 1)
		n = atoi(argv[1]);

	handle = dlopen("./libabc_test_lib.so", RTLD_LAZY);

	if (!handle)
		return -1;

	sym = dlsym(handle, "lib_a");
	sym(n);
	dlclose(handle);

	handle = dlopen("./libfoo.so", RTLD_LAZY);

	if (!handle)
		return -1;

	sym = dlsym(handle, "foo");
	sym(n);
	dlclose(handle);

	return 0;
}
