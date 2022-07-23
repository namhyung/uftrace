#include <algorithm>
#include <iostream>

enum xxx {
	FOO = 3,
	BAR,
};
struct empty {};

class A {
    public:
	A(empty e, enum xxx x, long i, const char *s)
		: E(e)
		, X(x)
		, I(i)
		, S(s)
	{
	}

    private:
	empty E;
	enum xxx X;
	long I;
	const char *S;
};

bool myless(int a, int b)
{
	return a < b;
}

int main()
{
	int x[5] = { 5, 3, 9, 2, 7 };
	empty E;

	A(E, FOO, BAR, "debug info test");

	std::sort(x, x + 5, myless);
	std::sort(x, x + 5, std::less<int>());
	std::sort(x, x + 5, [](int a, int b) { return a < b; });

	return 0;
}
