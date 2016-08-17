float float_add(float a, float b)
{
	return a + b;
}

float float_sub(float a, double b)
{
	return a - b;
}

double float_mul(double a, float b)
{
	return a * b;
}

double float_div(double a, double b)
{
	return a / b;
}

int main(int argc, char *argv[])
{
	double a, b, c, d;

	a = float_add(-0.1, 0.2);
	b = float_sub(0.1, 0.2);
	c = float_mul(300, 400);
	d = float_div(4e10, -0.02);

	return (a + b + c + d) ? 0 : 1;
}
