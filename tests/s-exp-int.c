int int_add(int a, long b)
{
	return a + b;
}

int int_sub(char a, short b)
{
	return a - b;
}

int int_mul(long long a, int b)
{
	return a * b;
}

int int_div(int a, long b)
{
	return a / b;
}

int main(int argc, char *argv[])
{
	int a, b, c, d;

	a = int_add(-1, 2);
	b = int_sub(1, 2);
	c = int_mul(3, 4);
	d = int_div(4, -2);

	return (a + b + c + d) ? 0 : 1;
}
