#include <libelf.h>
#include <gelf.h>

int main(void)
{
	GElf_Ehdr ehdr;

	elf_version(EV_CURRENT);
	return 0;
}
