extern char *__cxa_demangle(const char *name, char *output,
			    long *len, int *status);

int main(void)
{
	__cxa_demangle("_Z1fv", 0, 0, 0);
	return 0;
}
