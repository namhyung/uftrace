#include <algorithm>
#include <iostream>

template <typename T>
class C {
    public:
	C(T v, const char *s)
	{
		construct(v, s);
	}

	C(const C<T> &t)
	{
		copy(t.val, t.str);
	}

	void construct(T v, const char *s);
	void copy(T v, const char *s);

	T val;
	const char *str;
};

template <typename T>
void C<T>::construct(T val, const char *str)
{
	this->val = val;
	this->str = str;
}

template <typename T>
void C<T>::copy(T val, const char *str)
{
	this->val = val;
	this->str = str;
}

template <typename T>
C<T> foo(C<T> c1, C<T> &c2, const char *str, float f)
{
	return C<T>(c1.val + c2.val + f, str);
}

int main()
{
	C<int> c1(1, "debug info");
	C<int> c2(2, (const char *)0x1234); /* should not crash */

	/* 'c1' is passed by value (for each member) */
	C<int> c3 = foo(c1, c2, "passed by value", 0.001f);

	return c3.val == 3 ? 0 : 1;
}
