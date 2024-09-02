#include <gelf.h>
#include <libelf.h>

int main(void)
{
	Elf *elf;

	elf_version(EV_CURRENT);

	/* check that the gelf function */
	elf = elf_begin(0, ELF_C_READ, (Elf *)0);
	gelf_checksum(elf);
	elf_end(elf);

	return 0;
}
