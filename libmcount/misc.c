#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/uio.h>

/* This should be defined before #include "utils.h" */
#define PR_FMT     "mcount"
#define PR_DOMAIN  DBG_MCOUNT

#include "libmcount/mcount.h"
#include "libmcount/internal.h"
#include "utils/utils.h"

/* old kernel never updates pid filter for a forked child */
void update_kernel_tid(int tid)
{
	static const char TRACING_DIR[] = "/sys/kernel/debug/tracing";
	char *filename = NULL;
	char buf[8];
	int fd;
	ssize_t len;

	if (!kernel_pid_update)
		return;

	/* update pid filter for function tracing */
	xasprintf(&filename, "%s/set_ftrace_pid", TRACING_DIR);
	fd = open(filename, O_WRONLY | O_APPEND);
	if (fd < 0)
		return;

	snprintf(buf, sizeof(buf), "%d", tid);
	len = strlen(buf);
	if (write(fd, buf, len) != len)
		pr_dbg("update kernel ftrace tid filter failed\n");

	close(fd);

	free(filename);

	/* update pid filter for event tracing */
	xasprintf(&filename, "%s/set_event_pid", TRACING_DIR);
	fd = open(filename, O_WRONLY | O_APPEND);
	if (fd < 0)
		return;

	snprintf(buf, sizeof(buf), "%d", tid);
	len = strlen(buf);
	if (write(fd, buf, len) != len)
		pr_dbg("update kernel ftrace tid filter failed\n");

	close(fd);

	free(filename);
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

		snprintf(session, sizeof(session), "%0*"PRIx64,
			 SESSION_ID_LEN, session_id);
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
		{ .iov_base = &msg, .iov_len = sizeof(msg), },
		{ .iov_base = data, .iov_len = len, },
	};

	if (pfd < 0)
		return;

	len += sizeof(msg);
	if (writev(pfd, iov, 2) != (ssize_t)len) {
		if (!mcount_should_stop())
			pr_err("writing shmem name to pipe");
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
		int level = dbg_domain_str[i+1] - '0';
		int d;

		pos = strchr(DBG_DOMAIN_STR, domain);
		if (pos == NULL)
			continue;

		d = pos - DBG_DOMAIN_STR;
		dbg_domain[d] = level;
	}
}

/* restore saved original return address */
void mcount_rstack_restore(struct mcount_thread_data *mtdp)
{
	int idx;

	/* reverse order due to tail calls */
	for (idx = mtdp->idx - 1; idx >= 0; idx--) {
		unsigned long parent_ip = mtdp->rstack[idx].parent_ip;

		if (parent_ip == (unsigned long)mcount_return ||
		    parent_ip == (unsigned long)plthook_return)
			continue;

		*mtdp->rstack[idx].parent_loc = parent_ip;
	}
}

/* hook return address again (used after mcount_rstack_restore) */
void mcount_rstack_reset(struct mcount_thread_data *mtdp)
{
	int idx;
	struct mcount_ret_stack *rstack;

	for (idx = mtdp->idx - 1; idx >= 0; idx--) {
		rstack = &mtdp->rstack[idx];

		if (rstack->dyn_idx == MCOUNT_INVALID_DYNIDX)
			*rstack->parent_loc = (unsigned long)mcount_return;
		else
			*rstack->parent_loc = (unsigned long)plthook_return;
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

	/* ignore tail calls */
	if (curr_rstack->parent_loc == prev_rstack->parent_loc)
		return;

	while (prev_rstack >= mtdp->rstack) {
		unsigned long parent_ip = prev_rstack->parent_ip;

		/* parent also can be tail-called; skip */
		if (parent_ip == (unsigned long)mcount_return ||
		    parent_ip == (unsigned long)plthook_return) {
			prev_rstack--;
			continue;
		}

		*prev_rstack->parent_loc = parent_ip;
		return;
	}
}

void mcount_auto_reset(struct mcount_thread_data *mtdp)
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

	/* ignore tail calls */
	if (curr_rstack->parent_loc == prev_rstack->parent_loc)
		return;

	if (prev_rstack->dyn_idx == MCOUNT_INVALID_DYNIDX)
		*prev_rstack->parent_loc = (unsigned long)mcount_return;
	else
		*prev_rstack->parent_loc = (unsigned long)plthook_return;
}

#ifdef UNIT_TEST

TEST_CASE(mcount_debug_domain)
{
	int i;
	char dbg_str[DBG_DOMAIN_MAX * 2 + 1];

	/* ensure domain string matches to current domain bit */
	TEST_EQ(DBG_DOMAIN_MAX, (int)strlen(DBG_DOMAIN_STR));

	for (i = 0; i < DBG_DOMAIN_MAX; i++) {
		if (i != PR_DOMAIN)
			TEST_EQ(dbg_domain[i], 0);
	}

	for (i = 0; i < DBG_DOMAIN_MAX; i++) {
		dbg_str[i * 2]     = DBG_DOMAIN_STR[i];
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
