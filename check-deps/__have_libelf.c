#include <gelf.h>
#include <libelf.h>

int main(void)
{
	GElf_Ehdr ehdr;

	elf_version(EV_CURRENT);
	return 0;
}
