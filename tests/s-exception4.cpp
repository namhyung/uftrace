int foo(volatile int i)
{
	if (i)
		throw 1;
	return 0;
}

int main()
{
	int i = 1;

	try {
		foo(i);
	}
	catch (int n) {
	}
	return 0;
}
