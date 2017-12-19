#include "utils/asm.h"

ENTRY(get_pc_thunk)
	movl 0(%esp), %eax
	ret
END(get_pc_thunk)
