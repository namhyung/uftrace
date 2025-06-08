#include <stdlib.h>
#include <string.h>
#include <sys/uio.h>
#include <time.h>
#include <unistd.h>

/* This should be defined before #include "utils.h" */
#define PR_FMT "mcount"
#define PR_DOMAIN DBG_MCOUNT

#include "libmcount/internal.h"
#include "libmcount/mcount.h"
#include "utils/tracefs.h"
#include "utils/utils.h"

/* old kernel never updates pid filter for a forked child */
void update_kernel_tid(int tid)
{
	char buf[8];

	if (!kernel_pid_update)
		return;

	snprintf(buf, sizeof(buf), "%d", tid);

	/* update pid filter for function tracing */
	if (append_tracing_file("set_ftrace_pid", buf) < 0)
		pr_dbg("write to kernel ftrace pid filter failed\n");

	/* update pid filter for event tracing */
	if (append_tracing_file("set_event_pid", buf) < 0)
		pr_dbg("write to kernel ftrace pid filter failed\n");
}

const char *mcount_session_name(void)
{
	static char session[SESSION_ID_LEN + 1];
	static uint64_t session_id;
	int fd;

	if (!session_id) {
		fd = open("/dev/urandom", O_RDONLY);
		if (fd >= 0) {
			if (read(fd, &session_id, sizeof(session_id)) != 8)
				pr_err("reading from urandom");

			close(fd);
		}
		else {
			srandom(time(NULL));
			session_id = random();
			session_id <<= 32;
			session_id |= random();
		}

		snprintf(session, sizeof(session), "%0*" PRIx64, SESSION_ID_LEN, session_id);
	}
	return session;
}

void uftrace_send_message(int type, void *data, size_t len)
{
	struct uftrace_msg msg = {
		.magic = UFTRACE_MSG_MAGIC,
		.type = type,
		.len = len,
	};
	struct iovec iov[2] = {
		{
			.iov_base = &msg,
			.iov_len = sizeof(msg),
		},
		{
			.iov_base = data,
			.iov_len = len,
		},
	};

	if (mcount_pfd < 0)
		return;

	len += sizeof(msg);
	if (writev(mcount_pfd, iov, 2) != (ssize_t)len) {
		if (!mcount_should_stop())
			pr_err("send msg (type %d) failed", type);
	}
}

void build_debug_domain(char *dbg_domain_str)
{
	int i, len;

	if (dbg_domain_str == NULL)
		return;

	len = strlen(dbg_domain_str);
	for (i = 0; i < len; i += 2) {
		const char *pos;
		char domain = dbg_domain_str[i];
		int level = dbg_domain_str[i + 1] - '0';
		int d;

		pos = strchr(DBG_DOMAIN_STR, domain);
		if (pos == NULL)
			continue;

		d = pos - DBG_DOMAIN_STR;
		dbg_domain[d] = level;
	}
}

bool mcount_rstack_has_plthook(struct mcount_thread_data *mtdp)
{
	int idx;

	for (idx = 0; idx < mtdp->idx; idx++) {
		if (mtdp->rstack[idx].dyn_idx != MCOUNT_INVALID_DYNIDX)
			return true;
	}
	return false;
}

/* restore saved original return address */
void mcount_rstack_restore(struct mcount_thread_data *mtdp)
{
	int idx;
	struct mcount_ret_stack *rstack;

	if (unlikely(mcount_estimate_return))
		return;

	/* reverse order due to tail calls */
	for (idx = mtdp->idx - 1; idx >= 0; idx--) {
		rstack = &mtdp->rstack[idx];

		if (rstack->parent_ip == mcount_return_fn || rstack->parent_ip == plthook_return_fn)
			continue;

		if (!ARCH_CAN_RESTORE_PLTHOOK && rstack->dyn_idx != MCOUNT_INVALID_DYNIDX) {
			/*
			 * We don't know exact location where the return address
			 * was saved (on ARM/AArch64).  But we know that the
			 * return address itself was changed to plthook_return_fn
			 * by the plt_hooker().  So it needs to scan the stack to
			 * look up the value.
			 */
			unsigned long *loc, *end;

			if (idx < mtdp->idx - 1) {
				struct mcount_ret_stack *next_rstack;

				next_rstack = rstack + 1;
				/* skip rstacks for -finstrument-functions */
				while (next_rstack->parent_loc == &mtdp->cygprof_dummy &&
				       next_rstack < &mtdp->rstack[mtdp->idx])
					next_rstack++;

				if (next_rstack == &mtdp->rstack[mtdp->idx])
					goto last_rstack;

				/* special case: same as tail-call */
				if (next_rstack->parent_ip == plthook_return_fn) {
					rstack->parent_loc = next_rstack->parent_loc;
					*rstack->parent_loc = rstack->parent_ip;
					continue;
				}

				end = next_rstack->parent_loc;
			}
			else {
last_rstack:
				/* just check 32 stack slots */
				end = rstack->parent_loc - 32;
			}

			for (loc = rstack->parent_loc; loc < end; loc--) {
				if (*loc != plthook_return_fn)
					continue;

				rstack->parent_loc = loc;
				*loc = rstack->parent_ip;
				break;
			}
			continue;
		}

		*rstack->parent_loc = rstack->parent_ip;
	}
}

/* hook return address again (used after mcount_rstack_restore) */
void mcount_rstack_rehook(struct mcount_thread_data *mtdp)
{
	int idx;
	struct mcount_ret_stack *rstack;

	if (unlikely(mcount_estimate_return))
		return;

	for (idx = mtdp->idx - 1; idx >= 0; idx--) {
		rstack = &mtdp->rstack[idx];

		if (rstack->dyn_idx == MCOUNT_INVALID_DYNIDX)
			*rstack->parent_loc = mcount_return_fn;
		else if (ARCH_CAN_RESTORE_PLTHOOK)
			*rstack->parent_loc = plthook_return_fn;
	}
}

void mcount_auto_restore(struct mcount_thread_data *mtdp)
{
	struct mcount_ret_stack *curr_rstack;
	struct mcount_ret_stack *prev_rstack;

	/* auto recover is meaningful only if parent rstack is hooked */
	if (mtdp->idx < 2)
		return;

	if (mtdp->in_exception)
		return;

	curr_rstack = &mtdp->rstack[mtdp->idx - 1];
	prev_rstack = &mtdp->rstack[mtdp->idx - 2];

	if (!ARCH_CAN_RESTORE_PLTHOOK && prev_rstack->dyn_idx != MCOUNT_INVALID_DYNIDX)
		return;

	/* ignore tail calls */
	if (curr_rstack->parent_loc == prev_rstack->parent_loc)
		return;

	while (prev_rstack >= mtdp->rstack) {
		unsigned long parent_ip = prev_rstack->parent_ip;

		/* parent also can be tail-called; skip */
		if (parent_ip == mcount_return_fn || parent_ip == plthook_return_fn) {
			prev_rstack--;
			continue;
		}

		*prev_rstack->parent_loc = parent_ip;
		return;
	}
}

void mcount_auto_rehook(struct mcount_thread_data *mtdp)
{
	struct mcount_ret_stack *curr_rstack;
	struct mcount_ret_stack *prev_rstack;

	/* auto recover is meaningful only if parent rstack is hooked */
	if (mtdp->idx < 2)
		return;

	if (mtdp->in_exception)
		return;

	curr_rstack = &mtdp->rstack[mtdp->idx - 1];
	prev_rstack = &mtdp->rstack[mtdp->idx - 2];

	if (!ARCH_CAN_RESTORE_PLTHOOK && prev_rstack->dyn_idx != MCOUNT_INVALID_DYNIDX)
		return;

	/* ignore tail calls */
	if (curr_rstack->parent_loc == prev_rstack->parent_loc)
		return;

	if (prev_rstack->dyn_idx == MCOUNT_INVALID_DYNIDX)
		*prev_rstack->parent_loc = mcount_return_fn;
	else
		*prev_rstack->parent_loc = plthook_return_fn;
}

#ifdef UNIT_TEST

TEST_CASE(mcount_debug_domain)
{
	int i;
	char dbg_str[DBG_DOMAIN_MAX * 2 + 1];

	/* ensure domain string matches to current domain bit */
	TEST_EQ(DBG_DOMAIN_MAX, (int)strlen(DBG_DOMAIN_STR));

	pr_dbg("initially all domains are off\n");
	for (i = 0; i < DBG_DOMAIN_MAX; i++) {
		if (i != PR_DOMAIN)
			TEST_EQ(dbg_domain[i], 0);
	}

	pr_dbg("turn on all domains\n");
	for (i = 0; i < DBG_DOMAIN_MAX; i++) {
		dbg_str[i * 2] = DBG_DOMAIN_STR[i];
		dbg_str[i * 2 + 1] = '1';
	}
	dbg_str[i * 2] = '\0';

	build_debug_domain(dbg_str);

	for (i = 0; i < DBG_DOMAIN_MAX; i++)
		TEST_EQ(dbg_domain[i], 1);

	/* increase mcount debug domain to 2 */
	strcpy(dbg_str, "M2");
	build_debug_domain(dbg_str);

	TEST_EQ(dbg_domain[PR_DOMAIN], 2);

	return TEST_OK;
}

#endif /* UNIT_TEST */
