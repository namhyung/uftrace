#include <math.h>

int main(int argc, char *argv[])
{
	float e = expf(1.0f);
	double one = log(e);

	return one - 1;
}
