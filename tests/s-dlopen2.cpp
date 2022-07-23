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
	Parent *(*creat)();
	Parent *p;
	int n = 1;

	if (argc > 1)
		n = atoi(argv[1]);

	handle = dlopen("./libbaz.so", RTLD_LAZY);

	if (!handle)
		return -1;

	creat = (Parent * (*)()) dlsym(handle, "creat");
	p = creat();
	p->bar(n);
	dlclose(handle);

	return 0;
}
