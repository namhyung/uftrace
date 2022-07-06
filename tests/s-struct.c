// The sizeof(Option) is 11 in 64-bit, 7 in 32-bit.
struct __attribute__((packed)) Option {
	char m; // 1
	long n; // 8 or 4
	short k; // 2
};

// empty struct
struct StringRef {};

// global variables to suppress compiler optimization
struct Option g_opt;
struct StringRef g_sr;
unsigned g_index;
int g_value1;
int g_value2;

__attribute__((noinline)) void foo(const struct Option Opt, struct StringRef S, unsigned Index,
				   const int Value1, const int Value2)
{
	g_opt = Opt;
	g_sr = S;
	g_index = Index;
	g_value1 = Value1;
	g_value2 = Value2;
}

int main(void)
{
	struct Option Opt = { 11, 22, 33 };
	struct StringRef S;

	foo(Opt, S, 44, 55, 66);
	return 0;
}
