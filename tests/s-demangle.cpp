#include <iostream>

class ABC {
private:
  int n;
  int bar(void);
  int baz(void);

public:
  ABC(int n);
  int foo(void);
};

int ABC::foo(void)
{
	return bar() + 1;
}

int ABC::bar(void)
{
	return baz() - 1;
}

int ABC::baz(void)
{
	return n;
}

ABC::ABC(int c)
{
	n = c;
}

int main(int argc, char *argv[])
{
	int n = 0;
	ABC *abc;

	if (argc > 1)
		std::cin >> n;

	abc = new ABC(n);

	if (n == abc->foo())
		return 0;
	return 1;
}
