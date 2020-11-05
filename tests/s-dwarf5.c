#include <stdio.h>
#include <stdlib.h>

struct int1 { int a; };
struct int3 { int a, b, c; };
struct lng1 { long a; };
struct lng3 { long a, b, c; };
struct dbl1 { double a; };
struct dbl3 { double a, b, c; };
struct mix1 { int a; float b; };
struct mix2 { int a; float b; double c; };
struct mix3 { int a; float b; double c; long d; };

int pass_int1(struct int1 a, int x, char *y, double z) {
	return (a.a == z) ? 0 : 1;
}

int pass_int3(struct int3 a, int x, char *y, double z) {
	return (a.a + a.b + a.c) == z ? 0 : 1;
}

long pass_lng1(struct lng1 a, int x, char *y, double z) {
	return (a.a == z) ? 0 : 1;
}

long pass_lng3(struct lng3 a, int x, char *y, double z) {
	return (a.a + a.b + a.c) == z ? 0 : 1;
}

double pass_dbl1(struct dbl1 a, int x, char *y, double z) {
	return (a.a == z) ? 0 : 1;
}

double pass_dbl3(struct dbl3 a, int x, char *y, double z) {
	return (a.a + a.b + a.c) == z ? 0 : 1;
}

float pass_mix1(struct mix1 a, int x, char *y, double z) {
	return (a.a + a.b == z) ? 0 : 1;
}

float pass_mix2(struct mix2 a, int x, char *y, double z) {
	return (a.a + a.b + a.c) == z ? 0 : 1;
}

int pass_mix3(struct mix3 a, int x, char *y, double z) {
	return (a.a + a.b + a.c + a.d) == z ? 0 : 1;
}

int main(int argc, char *argv[])
{
	double z = 3.0;
	int s = 0;

	if (argc > 1)
		z = atof(argv[1]);

	s += pass_int1((struct int1) { 1 }, 1, "2", z);
	s += pass_int3((struct int3) { 1, 2, 3 }, 1, "2", z);
	s += pass_lng1((struct lng1) { 1 }, 1, "2", z);
	s += pass_lng3((struct lng3) { 1, 2, 3 }, 1 , "2", z);
	s += pass_dbl1((struct dbl1) { 1 }, 1, "2", z);
	s += pass_dbl3((struct dbl3) { 1, 2, 3 }, 1 , "2", z);
	s += pass_mix1((struct mix1) { 1, 2 }, 1 , "2", z);
	s += pass_mix2((struct mix2) { 1, 2, 3 }, 1 , "2", z);
	s += pass_mix3((struct mix3) { 1, 2, 3, 4 }, 1 , "2", z);

	return s == 9;
}
