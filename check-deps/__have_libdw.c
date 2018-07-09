#include <elfutils/libdw.h>

int main(void)
{
	Dwarf *dw;

	dw = dwarf_begin(0, DWARF_C_READ);
	dwarf_end(dw);

	return 0;
}
