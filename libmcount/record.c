#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <assert.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>

/* This should be defined before #include "utils.h" */
#define PR_FMT     "mcount"
#define PR_DOMAIN  DBG_MCOUNT

#include "libmcount/mcount.h"
#include "mcount-arch.h"
#include "utils/utils.h"
#include "utils/filter.h"

#define SHMEM_SESSION_FMT  "/uftrace-%s-%d-%03d" /* session-id, tid, seq */

static struct mcount_shmem_buffer *allocate_shmem_buffer(char *buf, size_t size,
							 int tid, int idx)
{
	int fd;
	struct mcount_shmem_buffer *buffer = NULL;

	snprintf(buf, size, SHMEM_SESSION_FMT, session_name(), tid, idx);

	fd = shm_open(buf, O_RDWR | O_CREAT | O_TRUNC, 0600);
	if (fd < 0) {
		pr_dbg("failed to open shmem buffer: %s\n", buf);
		goto out;
	}

	if (ftruncate(fd, shmem_bufsize) < 0) {
		pr_dbg("failed to resizing shmem buffer: %s\n", buf);
		goto out;
	}

	buffer = mmap(NULL, shmem_bufsize, PROT_READ | PROT_WRITE,
		      MAP_SHARED, fd, 0);
	if (buffer == MAP_FAILED) {
		pr_dbg("failed to mmap shmem buffer: %s\n", buf);
		buffer = NULL;
		goto out;
	}

	close(fd);

out:
	return buffer;
}

void prepare_shmem_buffer(struct mcount_thread_data *mtdp)
{
	char buf[128];
	int idx;
	int tid = gettid(mtdp);
	struct mcount_shmem *shmem = &mtdp->shmem;

	pr_dbg2("preparing shmem buffers\n");

	shmem->nr_buf = 2;
	shmem->max_buf = 2;
	shmem->buffer = xcalloc(sizeof(*shmem->buffer), 2);

	for (idx = 0; idx < shmem->nr_buf; idx++) {
		shmem->buffer[idx] = allocate_shmem_buffer(buf, sizeof(buf),
							   tid, idx);
		if (shmem->buffer[idx] == NULL)
			pr_err("mmap shmem buffer");
	}

	/* set idx 0 as current buffer */
	snprintf(buf, sizeof(buf), SHMEM_SESSION_FMT, session_name(), tid, 0);
	ftrace_send_message(FTRACE_MSG_REC_START, buf, strlen(buf));

	shmem->done = false;
	shmem->curr = 0;
	shmem->buffer[0]->flag = SHMEM_FL_RECORDING | SHMEM_FL_NEW;
}

void get_new_shmem_buffer(struct mcount_thread_data *mtdp)
{
	char buf[128];
	struct mcount_shmem *shmem = &mtdp->shmem;
	struct mcount_shmem_buffer *curr_buf = NULL;
	struct mcount_shmem_buffer **new_buffer;
	int idx;

	/* always use first buffer available */
	for (idx = 0; idx < shmem->nr_buf; idx++) {
		curr_buf = shmem->buffer[idx];
		if (!(curr_buf->flag & SHMEM_FL_RECORDING))
			goto reuse;
	}

	new_buffer = realloc(shmem->buffer, sizeof(*new_buffer) * (idx + 1));
	if (new_buffer) {
		/*
		 * it already free'd the old buffer, keep the new buffer
		 * regardless of allocation failure.
		 */
		shmem->buffer = new_buffer;

		curr_buf = allocate_shmem_buffer(buf, sizeof(buf),
						 gettid(mtdp), idx);
	}

	if (new_buffer == NULL || curr_buf == NULL) {
		shmem->losts++;
		shmem->curr = -1;
		return;
	}

	shmem->buffer[idx] = curr_buf;
	shmem->nr_buf++;
	if (shmem->nr_buf > shmem->max_buf)
		shmem->max_buf = shmem->nr_buf;

reuse:
	/*
	 * Start a new buffer and mark it recording data.
	 * See cmd-record.c::writer_thread().
	 */
	__sync_fetch_and_or(&curr_buf->flag, SHMEM_FL_RECORDING);

	shmem->seqnum++;
	shmem->curr = idx;
	curr_buf->size = 0;

	/* shrink unused buffers */
	if (idx + 3 <= shmem->nr_buf) {
		int i;
		int count = 0;
		struct mcount_shmem_buffer *b;

		for (i = idx + 1; i < shmem->nr_buf; i++) {
			b = shmem->buffer[i];
			if (b->flag == SHMEM_FL_WRITTEN)
				count++;
		}

		/* if 3 or more buffers are unused, free the last one */
		if (count >= 3 && b->flag == SHMEM_FL_WRITTEN) {
			shmem->nr_buf--;
			munmap(b, shmem_bufsize);
		}
	}

	snprintf(buf, sizeof(buf), SHMEM_SESSION_FMT,
		 session_name(), gettid(mtdp), idx);

	pr_dbg2("new buffer: [%d] %s\n", idx, buf);
	ftrace_send_message(FTRACE_MSG_REC_START, buf, strlen(buf));

	if (shmem->losts) {
		struct ftrace_ret_stack *frstack = (void *)curr_buf->data;

		frstack->time   = 0;
		frstack->type   = FTRACE_LOST;
		frstack->unused = FTRACE_UNUSED;
		frstack->more   = 0;
		frstack->addr   = shmem->losts;

		ftrace_send_message(FTRACE_MSG_LOST, &shmem->losts,
				    sizeof(shmem->losts));

		curr_buf->size = sizeof(*frstack);
		shmem->losts = 0;
	}
}

void finish_shmem_buffer(struct mcount_thread_data *mtdp, int idx)
{
	char buf[64];

	snprintf(buf, sizeof(buf), SHMEM_SESSION_FMT,
		 session_name(), gettid(mtdp), idx);

	ftrace_send_message(FTRACE_MSG_REC_END, buf, strlen(buf));
}

void clear_shmem_buffer(struct mcount_thread_data *mtdp)
{
	struct mcount_shmem *shmem = &mtdp->shmem;
	int i;

	pr_dbg2("releasing all shmem buffers for task %d\n", gettid(mtdp));

	for (i = 0; i < shmem->nr_buf; i++)
		munmap(shmem->buffer[i], shmem_bufsize);

	free(shmem->buffer);
	shmem->buffer = NULL;
	shmem->nr_buf = 0;
}

void shmem_finish(struct mcount_thread_data *mtdp)
{
	struct mcount_shmem *shmem = &mtdp->shmem;
	struct mcount_shmem_buffer *curr_buf;
	int curr = shmem->curr;

	if (curr >= 0 && shmem->buffer) {
		curr_buf = shmem->buffer[curr];

		if (curr_buf->flag & SHMEM_FL_RECORDING)
			finish_shmem_buffer(mtdp, curr);
	}

	shmem->done = true;
	shmem->curr = -1;

	pr_dbg("%s: tid: %d seqnum = %u curr = %d, nr_buf = %d max_buf = %d\n",
	       __func__, gettid(mtdp), shmem->seqnum, curr,
	       shmem->nr_buf, shmem->max_buf);

	clear_shmem_buffer(mtdp);
}

#ifndef DISABLE_MCOUNT_FILTER
void *get_argbuf(struct mcount_thread_data *mtdp,
		 struct mcount_ret_stack *rstack)
{
	ptrdiff_t idx = rstack - mtdp->rstack;

	return mtdp->argbuf + (idx * ARGBUF_SIZE);
}

static unsigned save_to_argbuf(void *argbuf, struct list_head *args_spec,
			       struct mcount_arg_context *ctx)
{
	struct ftrace_arg_spec *spec;
	unsigned size, total_size = 0;
	unsigned max_size = ARGBUF_SIZE - sizeof(size);
	bool is_retval = !!ctx->retval;
	void *ptr;

	ptr = argbuf + sizeof(total_size);
	list_for_each_entry(spec, args_spec, list) {
		if (is_retval != (spec->idx == RETVAL_IDX))
			continue;

		if (is_retval)
			mcount_arch_get_retval(ctx, spec);
		else
			mcount_arch_get_arg(ctx, spec);

		if (spec->fmt == ARG_FMT_STR) {
			unsigned short len;
			char *str = ctx->val.p;

			if (str) {
				unsigned i;
				char *dst = ptr + 2;

				/*
				 * Calling strlen() might clobber floating-point
				 * registers (on x86) depends on the internal
				 * implementation.  Do it manually.
				 */
				len = 0;
				for (i = 0; i < max_size - total_size; i++) {
					dst[i] = str[i];
					if (!str[i])
						break;
					len++;
				}
				/* store 2-byte length before string */
				*(unsigned short *)ptr = len;
			}
			else {
				/* mark NULL pointer with -1 */
				len = 4;
				memcpy(ptr, &len, sizeof(len));
				memset(ptr + 2, 0xff, 4);
			}
			size = ALIGN(len + 2, 4);
		}
		else {
			memcpy(ptr, ctx->val.v, spec->size);
			size = ALIGN(spec->size, 4);
		}
		ptr += size;
		total_size += size;
	}

	if (total_size > max_size)
		return -1U;

	return total_size;
}

void save_argument(struct mcount_thread_data *mtdp,
		   struct mcount_ret_stack *rstack,
		   struct list_head *args_spec,
		   struct mcount_regs *regs)
{
	void *argbuf = get_argbuf(mtdp, rstack);
	unsigned size;
	struct mcount_arg_context ctx = {
		.regs = regs,
		.stack_base = rstack->parent_loc,
	};

	size = save_to_argbuf(argbuf, args_spec, &ctx);
	if (size == -1U) {
		pr_log("argument data is too big\n");
		return;
	}

	*(unsigned *)argbuf = size;
	rstack->flags |= MCOUNT_FL_ARGUMENT;
}

void save_retval(struct mcount_thread_data *mtdp,
		 struct mcount_ret_stack *rstack, long *retval)
{
	struct list_head *args_spec = rstack->pargs;
	void *argbuf = get_argbuf(mtdp, rstack);
	unsigned size;
	struct mcount_arg_context ctx = {
		.retval = retval,
	};

	size = save_to_argbuf(argbuf, args_spec, &ctx);
	if (size == -1U) {
		pr_log("retval data is too big\n");
		rstack->flags &= ~MCOUNT_FL_RETVAL;
		return;
	}

	*(unsigned *)argbuf = size;
}
#else
void *get_argbuf(struct mcount_thread_data *mtdp,
		 struct mcount_ret_stack *rstack)
{
	return NULL;
}

void save_retval(struct mcount_thread_data *mtdp,
		 struct mcount_ret_stack *rstack, long *retval)
{
}
#endif

static int record_ret_stack(struct mcount_thread_data *mtdp,
			    enum ftrace_ret_stack_type type,
			    struct mcount_ret_stack *mrstack)
{
	struct ftrace_ret_stack *frstack;
	uint64_t timestamp = mrstack->start_time;
	struct mcount_shmem *shmem = &mtdp->shmem;
	const size_t maxsize = (size_t)shmem_bufsize - sizeof(**shmem->buffer);
	struct mcount_shmem_buffer *curr_buf = shmem->buffer[shmem->curr];
	size_t size = sizeof(*frstack);
	void *argbuf = NULL;
	uint64_t *buf;
	uint64_t rec;

	if ((type == FTRACE_ENTRY && mrstack->flags & MCOUNT_FL_ARGUMENT) ||
	    (type == FTRACE_EXIT  && mrstack->flags & MCOUNT_FL_RETVAL)) {
		argbuf = get_argbuf(mtdp, mrstack);
		if (argbuf)
			size += *(unsigned *)argbuf;
	}

	if (unlikely(shmem->curr == -1 || curr_buf->size + size > maxsize)) {
		if (shmem->done)
			return 0;
		if (shmem->curr > -1)
			finish_shmem_buffer(mtdp, shmem->curr);
		get_new_shmem_buffer(mtdp);

		if (shmem->curr == -1) {
			shmem->losts++;
			return -1;
		}

		curr_buf = shmem->buffer[shmem->curr];
	}

	if (type == FTRACE_EXIT)
		timestamp = mrstack->end_time;

#if 0
	frstack = (void *)(curr_buf->data + curr_buf->size);

	frstack->time   = timestamp;
	frstack->type   = type;
	frstack->unused = FTRACE_UNUSED;
	frstack->more   = !!argbuf;
	frstack->depth  = mrstack->depth;
	frstack->addr   = mrstack->child_ip;
#else
	/*
	 * instead of set bitfields, do the bit operations manually.
	 * this would be good both for performance and portability.
	 */
	rec  = type | FTRACE_UNUSED << 3;
	rec += argbuf ? 4 : 0;
	rec += mrstack->depth << 6;
	rec += mrstack->child_ip << 16;

	buf = (void *)(curr_buf->data + curr_buf->size);
	buf[0] = timestamp;
	buf[1] = rec;
#endif

	curr_buf->size += sizeof(*frstack);
	mrstack->flags |= MCOUNT_FL_WRITTEN;

	if (argbuf) {
		unsigned int *ptr = (void *)curr_buf->data + curr_buf->size;
		unsigned i;

		size -= sizeof(*frstack);

		/*
		 * Calling memcpy() here (esp. with a large size) can
		 * clobber floating-point registers (SSE registers on x86).
		 * As the argbuf was aligned to 4-bytes, copy the words.
		 */
		for (i = 0; i < size; i += 4, ptr++)
			*ptr = *(unsigned int *)(argbuf + sizeof(unsigned) + i);

		curr_buf->size += ALIGN(size, 8);
	}

	pr_dbg3("rstack[%d] %s %lx\n", mrstack->depth,
	       type == FTRACE_ENTRY? "ENTRY" : "EXIT ", mrstack->child_ip);
	return 0;
}

int record_trace_data(struct mcount_thread_data *mtdp,
		      struct mcount_ret_stack *mrstack,
		      long *retval)
{
	struct mcount_ret_stack *non_written_mrstack = NULL;
	struct ftrace_ret_stack *frstack;
	size_t size = 0;
	int count = 0;

#define SKIP_FLAGS  (MCOUNT_FL_NORECORD | MCOUNT_FL_DISABLED)

	if (mrstack < mtdp->rstack)
		return 0;

	if (!(mrstack->flags & MCOUNT_FL_WRITTEN)) {
		non_written_mrstack = mrstack;

		if (!(non_written_mrstack->flags & SKIP_FLAGS))
			count++;

		while (non_written_mrstack > mtdp->rstack) {
			struct mcount_ret_stack *prev = non_written_mrstack - 1;

			if (prev->flags & MCOUNT_FL_WRITTEN)
				break;

			if (!(prev->flags & SKIP_FLAGS)) {
				count++;

				if (prev->flags & MCOUNT_FL_ARGUMENT) {
					unsigned *argbuf_size;

					argbuf_size = get_argbuf(mtdp, prev);
					if (argbuf_size)
						size += *argbuf_size;
				}
			}

			non_written_mrstack = prev;
		}
	}

	if (mrstack->end_time)
		count++;  /* for exit */

	size += count * sizeof(*frstack);

	pr_dbg3("task %d recorded %zd bytes (record count = %d)\n",
		gettid(mtdp), size, count);

	while (non_written_mrstack && non_written_mrstack < mrstack) {
		if (!(non_written_mrstack->flags & SKIP_FLAGS)) {
			if (record_ret_stack(mtdp, FTRACE_ENTRY,
					     non_written_mrstack)) {
				mtdp->shmem.losts += count - 1;
				return 0;
			}

			count--;
		}
		non_written_mrstack++;
	}

	if (!(mrstack->flags & (MCOUNT_FL_WRITTEN | SKIP_FLAGS))) {
		if (record_ret_stack(mtdp, FTRACE_ENTRY, non_written_mrstack))
			return 0;

		count--;
	}

	if (mrstack->end_time) {
		if (retval)
			save_retval(mtdp, mrstack, retval);

		if (record_ret_stack(mtdp, FTRACE_EXIT, mrstack))
			return 0;

		count--;
	}

	assert(count == 0);
	return 0;
}

void record_proc_maps(char *dirname, const char *sess_id,
		      struct symtabs *symtabs)
{
	FILE *ifp, *ofp;
	char buf[4096];
	struct ftrace_proc_maps *prev_map = NULL;
	char *last_module = NULL;

	ifp = fopen("/proc/self/maps", "r");
	if (ifp == NULL)
		pr_err("cannot open proc maps file");

	snprintf(buf, sizeof(buf), "%s/sid-%s.map", dirname, sess_id);

	ofp = fopen(buf, "w");
	if (ofp == NULL)
		pr_err("cannot open for writing maps file");

	while (fgets(buf, sizeof(buf), ifp)) {
		unsigned long start, end;
		char prot[5];
		char path[PATH_MAX];
		size_t namelen;
		struct ftrace_proc_maps *map;

		/* skip anon mappings */
		if (sscanf(buf, "%lx-%lx %s %*x %*x:%*x %*d %s\n",
			   &start, &end, prot, path) != 4)
			goto next;

		/* skip non-executable mappings */
		if (prot[2] != 'x')
			goto next;

		if (last_module && !strcmp(path, last_module))
			goto next;

		/* save map for the executable */
		namelen = ALIGN(strlen(path) + 1, 4);

		map = xmalloc(sizeof(*map) + namelen);

		map->start = start;
		map->end = end;
		map->len = namelen;
		memcpy(map->prot, prot, 4);
		map->symtab.sym = NULL;
		map->symtab.sym_names = NULL;
		map->symtab.nr_sym = 0;
		map->symtab.nr_alloc = 0;
		memcpy(map->libname, path, namelen);
		map->libname[strlen(path)] = '\0';

		if (prev_map)
			prev_map->next = map;
		else
			symtabs->maps = map;

		map->next = NULL;
		prev_map = map;

next:
		fprintf(ofp, "%s", buf);
	}

	fclose(ifp);
	fclose(ofp);
}
