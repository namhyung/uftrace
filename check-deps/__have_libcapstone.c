#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include <capstone/platform.h>
#include <capstone/capstone.h>


int main()
{
	cs_insn insn;
	printf("size: %lu\n", sizeof(insn));
	return 0;
}
