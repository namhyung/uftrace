volatile int a = 0;

class AAA
{
public:
	static void bar(int n)
	{
		a = n;
	}
};

extern "C" {
	void foo(int n)
	{
		a = n;
		AAA::bar(n);
	}
}
