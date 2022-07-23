#include <capstone/capstone.h>
#include <capstone/platform.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>

int main()
{
	cs_insn insn;
	printf("size: %zu\n", sizeof(insn));
	return 0;
}
