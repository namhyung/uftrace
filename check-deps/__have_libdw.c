#include <elfutils/libdw.h>

int main(void)
{
	Dwarf *dw;
	Dwarf_Die die;

	dw = dwarf_begin(0, DWARF_C_READ);

	if (dwarf_offdie(dw, 0, &die)) {
		Dwarf_Word size;
		/* require elfutils 0.144+ */
		dwarf_aggregate_size(&die, &size);
	}

	dwarf_end(dw);
	return 0;
}
