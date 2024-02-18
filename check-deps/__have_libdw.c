#include <elfutils/libdw.h>
#include <elfutils/libdwfl.h>

int main(void)
{
	Dwarf *dw;
	Dwarf_Die die;
	Dwfl *dwfl;
	Dwfl_Callbacks dwfl_callbacks;

	/* libdw API test */
	dw = dwarf_begin(0, DWARF_C_READ);

	if (dwarf_offdie(dw, 0, &die)) {
		Dwarf_Word size;
		/* require elfutils 0.144+ */
		dwarf_aggregate_size(&die, &size);
	}

	dwarf_end(dw);

	/* libdwfl API test (in elfutils/libdw 0.122) */
	dwfl = dwfl_begin(&dwfl_callbacks);
	dwfl_report_offline(dwfl, "", "", -1);
	dwfl_end(dwfl);

	return 0;
}
