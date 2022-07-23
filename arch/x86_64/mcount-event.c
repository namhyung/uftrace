#include <signal.h>
#include <stdbool.h>
#include <sys/mman.h>
#include <ucontext.h>

/* This should be defined before #include "utils.h" */
#define PR_FMT "event"
#define PR_DOMAIN DBG_EVENT

#include "libmcount/internal.h"

#define INVALID_OPCODE 0xce
#define PAGE_SIZE 4096
#define PAGE_ADDR(a) ((void *)((a) & ~(PAGE_SIZE - 1)))

static void sdt_handler(int sig, siginfo_t *info, void *arg)
{
	ucontext_t *ctx = arg;
	unsigned long addr = ctx->uc_mcontext.gregs[REG_RIP];
	struct mcount_event_info *mei;

	mei = mcount_lookup_event(addr);
	ASSERT(mei != NULL);

	/* TODO: collect and write arguments */
	mcount_save_event(mei);

	/* skip the invalid insn and continue */
	ctx->uc_mcontext.gregs[REG_RIP] = addr + 1;
}

int mcount_arch_enable_event(struct mcount_event_info *mei)
{
	static bool sdt_handler_set = false;

	if (!sdt_handler_set) {
		struct sigaction act = {
			.sa_flags = SA_SIGINFO,
			.sa_sigaction = sdt_handler,
		};

		sigemptyset(&act.sa_mask);
		sigaction(SIGILL, &act, NULL);

		sdt_handler_set = true;
	}

	if (mprotect(PAGE_ADDR(mei->addr), PAGE_SIZE, PROT_READ | PROT_WRITE)) {
		pr_dbg("cannot enable event due to protection: %m\n");
		return -1;
	}

	/* replace NOP to an invalid OP so that it can catch SIGILL,
	   then it will fall into sdt_handler() above. */
	memset((void *)mei->addr, INVALID_OPCODE, 1);

	if (mprotect(PAGE_ADDR(mei->addr), PAGE_SIZE, PROT_READ | PROT_EXEC))
		pr_err("cannot setup event due to protection");

	return 0;
}
