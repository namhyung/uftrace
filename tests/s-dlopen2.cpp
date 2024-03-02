#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>

class Parent {
    public:
	int virtual bar(int);
	int virtual func(int);
};

int main(int argc, char *argv[])
{
	void *handle;
	Parent *(*create)();
	Parent *p;
	int n = 1;

	if (argc > 1)
		n = atoi(argv[1]);

	handle = dlopen("./libbaz.so", RTLD_LAZY);

	if (!handle)
		return -1;

	create = (Parent * (*)()) dlsym(handle, "create");
	p = create();
	p->bar(n); // calls func() which is defined in Child
	dlclose(handle);

	return 0;
}
