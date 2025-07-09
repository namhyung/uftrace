#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <sched.h>
#include <stdio.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <unistd.h>

/* This should be defined before #include "utils.h" */
#define PR_FMT "mcount"
#define PR_DOMAIN DBG_MCOUNT

#include "libmcount/internal.h"
#include "libmcount/mcount.h"
#include "mcount-arch.h"
#include "utils/event.h"
#include "utils/filter.h"
#include "utils/shmem.h"
#include "utils/symbol.h"
#include "utils/utils.h"

#define SHMEM_SESSION_FMT "/uftrace-%s-%d-%03d" /* session-id, tid, seq */

#define ARG_STR_MAX 98

static struct mcount_shmem_buffer *allocate_shmem_buffer(char *sess_id, size_t size, int tid,
							 int idx)
{
	int fd;
	int saved_errno = 0;
	struct mcount_shmem_buffer *buffer = NULL;

	snprintf(sess_id, size, SHMEM_SESSION_FMT, mcount_session_name(), tid, idx);

	fd = uftrace_shmem_open(sess_id, O_RDWR | O_CREAT | O_TRUNC, 0600);
	if (fd < 0) {
		saved_errno = errno;
		pr_dbg("failed to open shmem buffer: %s\n", sess_id);
		goto out;
	}

	if (ftruncate(fd, shmem_bufsize) < 0) {
		saved_errno = errno;
		pr_dbg("failed to resizing shmem buffer: %s\n", sess_id);
		goto out;
	}

	buffer = mmap(NULL, shmem_bufsize, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if (buffer == MAP_FAILED) {
		saved_errno = errno;
		pr_dbg("failed to mmap shmem buffer: %s\n", sess_id);
		buffer = NULL;
		goto out;
	}

	close(fd);

out:
	errno = saved_errno;
	return buffer;
}

void prepare_shmem_buffer(struct mcount_thread_data *mtdp)
{
	char buf[128];
	int idx;
	int tid = mcount_gettid(mtdp);
	struct mcount_shmem *shmem = &mtdp->shmem;

	pr_dbg2("preparing shmem buffers: tid = %d\n", tid);

	shmem->nr_buf = 2;
	shmem->max_buf = 2;
	shmem->buffer = xcalloc(2, sizeof(*shmem->buffer));

	for (idx = 0; idx < shmem->nr_buf; idx++) {
		shmem->buffer[idx] = allocate_shmem_buffer(buf, sizeof(buf), tid, idx);
		if (shmem->buffer[idx] == NULL)
			pr_err("mmap shmem buffer");
	}

	/* set idx 0 as current buffer */
	snprintf(buf, sizeof(buf), SHMEM_SESSION_FMT, mcount_session_name(), tid, 0);
	uftrace_send_message(UFTRACE_MSG_REC_START, buf, strlen(buf));

	shmem->done = false;
	shmem->curr = 0;
	shmem->buffer[0]->flag = SHMEM_FL_RECORDING | SHMEM_FL_NEW;
}

static void get_new_shmem_buffer(struct mcount_thread_data *mtdp)
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

		curr_buf = allocate_shmem_buffer(buf, sizeof(buf), mcount_gettid(mtdp), idx);
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
	 * Start a new buffer and mark its recording data.
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

	snprintf(buf, sizeof(buf), SHMEM_SESSION_FMT, mcount_session_name(), mcount_gettid(mtdp),
		 idx);

	pr_dbg2("new buffer: [%d] %s\n", idx, buf);
	uftrace_send_message(UFTRACE_MSG_REC_START, buf, strlen(buf));

	if (shmem->losts) {
		struct uftrace_record *frstack = (void *)curr_buf->data;

		frstack->time = 0;
		frstack->type = UFTRACE_LOST;
		frstack->magic = RECORD_MAGIC;
		frstack->more = 0;
		frstack->addr = shmem->losts;

		uftrace_send_message(UFTRACE_MSG_LOST, &shmem->losts, sizeof(shmem->losts));

		curr_buf->size = sizeof(*frstack);
		shmem->losts = 0;
	}
}

static void finish_shmem_buffer(struct mcount_thread_data *mtdp, int idx)
{
	char buf[64];

	snprintf(buf, sizeof(buf), SHMEM_SESSION_FMT, mcount_session_name(), mcount_gettid(mtdp),
		 idx);

	uftrace_send_message(UFTRACE_MSG_REC_END, buf, strlen(buf));
}

void clear_shmem_buffer(struct mcount_thread_data *mtdp)
{
	struct mcount_shmem *shmem = &mtdp->shmem;
	int i;

	pr_dbg2("releasing all shmem buffers for task %d\n", mcount_gettid(mtdp));

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

	pr_dbg("%s: tid: %d seqnum = %u curr = %d, nr_buf = %d max_buf = %d\n", __func__,
	       mcount_gettid(mtdp), shmem->seqnum, curr, shmem->nr_buf, shmem->max_buf);

	clear_shmem_buffer(mtdp);
}

static struct mcount_event *get_event_pointer(void *base, unsigned idx)
{
	size_t len = 0;
	struct mcount_event *event = base;

	while (idx--) {
		len += EVTBUF_HDR + event->dsize;
		event = base + len;
	}

	return event;
}

#ifndef DISABLE_MCOUNT_FILTER
/*
 * These functions are for regular libmcount with filters.
 */

void *get_argbuf(struct mcount_thread_data *mtdp, struct mcount_ret_stack *rstack)
{
	ptrdiff_t idx = rstack - mtdp->rstack;

	return mtdp->argbuf + (idx * ARGBUF_SIZE);
}

#define HEAP_REGION_UNIT 128 * MB
#define STACK_REGION_UNIT 8 * MB

struct mem_region {
	struct rb_node node;
	unsigned long start;
	unsigned long end;
};

static void add_mem_region(struct rb_root *root, unsigned long start, unsigned long end,
			   bool update_end)
{
	struct rb_node *parent = NULL;
	struct rb_node **p = &root->rb_node;
	struct mem_region *iter, *entry;

	while (*p) {
		parent = *p;
		iter = rb_entry(parent, struct mem_region, node);

		if (update_end) {
			if (iter->start == start) {
				if (iter->end != end)
					iter->end = end;
				return;
			}
		}
		else {
			if (iter->end == end) {
				if (iter->start != start)
					iter->start = start;
				return;
			}
		}

		if (iter->start > start)
			p = &parent->rb_left;
		else
			p = &parent->rb_right;
	}

	entry = xmalloc(sizeof(*entry));
	entry->start = start;
	entry->end = end;

	pr_dbg3("mem region: %lx - %lx\n", start, end);
	rb_link_node(&entry->node, parent, p);
	rb_insert_color(&entry->node, root);
}

static void update_mem_regions(struct mcount_mem_regions *regions)
{
	FILE *fp;
	char buf[PATH_MAX];

	fp = fopen("/proc/self/maps", "r");
	if (fp == NULL)
		return;

	while (fgets(buf, sizeof(buf), fp) != NULL) {
		char *p = buf, *next;
		unsigned long start, end;
		bool is_stack = false;

		/* XXX: cannot use *scanf() due to crash (SSE alignment?) */
		start = strtoul(p, &next, 16);
		if (*next != '-')
			pr_warn("invalid /proc/map format\n");

		p = next + 1;
		end = strtoul(p, &next, 16);

		/* prot: rwxp */
		p = next + 1;
		if (p[0] != 'r')
			continue;

		if (strstr(next, "[heap]")) {
			end = ROUND_UP(end, HEAP_REGION_UNIT);
			if (end > regions->brk)
				regions->brk = end;
			regions->heap = start;
		}
		if (strstr(next, "[stack")) {
			start = ROUND_DOWN(start, STACK_REGION_UNIT);
			is_stack = true;
		}

		add_mem_region(&regions->root, start, end, !is_stack);
	}
	fclose(fp);
}

static bool find_mem_region(struct rb_root *root, unsigned long addr)
{
	struct rb_node *parent = NULL;
	struct rb_node **p = &root->rb_node;
	struct mem_region *iter;

	while (*p) {
		parent = *p;
		iter = rb_entry(parent, struct mem_region, node);

		if (iter->start <= addr && addr < iter->end)
			return true;

		if (iter->start > addr)
			p = &parent->rb_left;
		else
			p = &parent->rb_right;
	}

	pr_dbg2("cannot find mem region: %lx\n", addr);
	return false;
}

bool check_mem_region(struct mcount_arg_context *ctx, unsigned long addr)
{
	bool update = true;
	struct mcount_mem_regions *regions = ctx->regions;

retry:
	if (regions->heap <= addr && addr < regions->brk)
		return true;

	if (find_mem_region(&regions->root, addr))
		return true;

	if (update) {
		mcount_save_arch_context(ctx->arch);
		update_mem_regions(regions);
		mcount_restore_arch_context(ctx->arch);
		update = false;
		goto retry;
	}

	return false;
}

void finish_mem_region(struct mcount_mem_regions *regions)
{
	struct rb_root *root = &regions->root;
	struct rb_node *node;
	struct mem_region *mr;

	while (!RB_EMPTY_ROOT(root)) {
		node = rb_first(root);
		mr = rb_entry(node, typeof(*mr), node);

		rb_erase(node, root);
		free(mr);
	}
}

static unsigned save_to_argbuf(void *argbuf, struct list_head *args_spec,
			       struct mcount_arg_context *ctx)
{
	struct uftrace_arg_spec *spec;
	unsigned size, total_size = 0;
	unsigned max_size = ARGBUF_SIZE - sizeof(size);
	bool is_retval = !!ctx->retval;
	void *ptr;

	ptr = argbuf + sizeof(total_size);
	list_for_each_entry(spec, args_spec, list) {
		if (is_retval != (spec->idx == RETVAL_IDX))
			continue;

		if (spec->fmt == ARG_FMT_STRUCT) {
			if (total_size + spec->size > max_size) {
				/* just to make it fail */
				total_size += spec->size;
				break;
			}
			ctx->val.p = ptr;
		}

		if (is_retval)
			mcount_arch_get_retval(ctx, spec);
		else
			mcount_arch_get_arg(ctx, spec);

		if (spec->fmt == ARG_FMT_STR || spec->fmt == ARG_FMT_STD_STRING) {
			unsigned short len;
			char *str = ctx->val.p;

			if (spec->fmt == ARG_FMT_STD_STRING) {
				/*
				 * This is libstdc++ implementation dependent.
				 * So doesn't work on others such as libc++.
				 */
				long *base = ctx->val.p;
				long *_M_string_length = base + 1;
				if (check_mem_region(ctx, (unsigned long)base)) {
					char *_M_dataplus = (char *)(*base);
					len = *_M_string_length;
					str = _M_dataplus;
				}
			}

			if (str) {
				unsigned i;
				char *dst = ptr + 2;
				char buf[32];

				if (!check_mem_region(ctx, (unsigned long)str)) {
					len = snprintf(buf, sizeof(buf), "<%p>", str);
					str = buf;
				}

				/*
				 * Calling strlen() might clobber floating-point
				 * registers (on x86) depends on the internal
				 * implementation.  Do it manually.
				 */
				len = 0;
				for (i = 0; i < max_size - total_size; i++) {
					dst[i] = str[i];

					/* truncate long string */
					if (i == ARG_STR_MAX) {
						dst[i - 3] = '.';
						dst[i - 2] = '.';
						dst[i - 1] = '.';
						dst[i] = '\0';
					}
					if (!dst[i])
						break;
					len++;
				}
				/* store 2-byte length before string */
				*(unsigned short *)ptr = len;
			}
			else {
				const char null_str[4] = { 'N', 'U', 'L', 'L' };

				len = sizeof(null_str);
				mcount_memcpy1(ptr, &len, sizeof(len));
				mcount_memcpy1(ptr + 2, null_str, len);
			}
			size = ALIGN(len + 2, 4);
		}
		else if (spec->fmt == ARG_FMT_INT_PTR) {
			int val = 0;
			int *ptr_val = (int *)ctx->val.p;
			if (!check_mem_region(ctx, (unsigned long)ptr_val)) {
				val = -1; // orarleave val = 0
			}
			else {
				val = *ptr_val;
			}
			size = ALIGN(sizeof(int), 4);
			mcount_memcpy4(ptr, &val, sizeof(int));
			ptr += size;
			total_size += size;
		}
		else if (spec->fmt == ARG_FMT_STRUCT) {
			/*
			 * It already filled the argbuf in the
			 * mcount_arch_get_arg/retval() above.
			 */
			size = ALIGN(spec->size, 4);
		}
		else {
			size = ALIGN(spec->size, 4);
			mcount_memcpy4(ptr, ctx->val.v, size);
		}
		ptr += size;
		total_size += size;
	}

	if (total_size > max_size)
		return -1U;

	return total_size;
}

void save_argument(struct mcount_thread_data *mtdp, struct mcount_ret_stack *rstack,
		   struct list_head *args_spec, struct mcount_regs *regs)
{
	void *argbuf = get_argbuf(mtdp, rstack);
	unsigned size;
	struct mcount_arg_context ctx;

	mcount_memset4(&ctx, 0, sizeof(ctx));
	ctx.regs = regs;
	ctx.stack_base = rstack->parent_loc;
	ctx.regions = &mtdp->mem_regions;
	ctx.arch = &mtdp->arch;

	size = save_to_argbuf(argbuf, args_spec, &ctx);
	if (size == -1U) {
		pr_warn("argument data is too big\n");
		return;
	}

	*(unsigned *)argbuf = size;
	rstack->flags |= MCOUNT_FL_ARGUMENT;
}

void save_retval(struct mcount_thread_data *mtdp, struct mcount_ret_stack *rstack, long *retval)
{
	struct list_head *args_spec = rstack->pargs;
	void *argbuf = get_argbuf(mtdp, rstack);
	unsigned size;
	struct mcount_arg_context ctx;

	mcount_memset4(&ctx, 0, sizeof(ctx));
	ctx.retval = retval;
	ctx.regions = &mtdp->mem_regions;
	ctx.arch = &mtdp->arch;

	size = save_to_argbuf(argbuf, args_spec, &ctx);
	if (size == -1U) {
		pr_warn("retval data is too big\n");
		rstack->flags &= ~MCOUNT_FL_RETVAL;
		return;
	}

	*(uint32_t *)argbuf = size;
}

static int save_proc_statm(void *ctx, void *buf)
{
	FILE *fp;
	struct uftrace_proc_statm *statm = buf;

	fp = fopen("/proc/self/statm", "r");
	if (fp == NULL)
		pr_err("failed to open /proc/self/statm");

	if (fscanf(fp, "%" SCNu64 " %" SCNu64 " %" SCNu64, &statm->vmsize, &statm->vmrss,
		   &statm->shared) != 3)
		pr_err("failed to scan /proc/self/statm");

	/*
	 * Since /proc/[pid]/statm prints the number of pages for each field,
	 * it'd be better to keep the memory size in KB.
	 */
	statm->vmsize *= page_size_in_kb;
	statm->vmrss *= page_size_in_kb;
	statm->shared *= page_size_in_kb;

	fclose(fp);
	return 0;
}

static void diff_proc_statm(void *ctx, void *dst, void *src)
{
	struct uftrace_proc_statm *dst_statm = dst;
	struct uftrace_proc_statm *src_statm = src;

	dst_statm->vmsize -= src_statm->vmsize;
	dst_statm->vmrss -= src_statm->vmrss;
	dst_statm->shared -= src_statm->shared;
}

static int save_page_fault(void *ctx, void *buf)
{
	struct rusage ru;
	struct uftrace_page_fault *page_fault = buf;

	/* getrusage provides faults info in a single syscall */
	if (getrusage(RUSAGE_SELF, &ru) < 0)
		return -1;

	page_fault->major = ru.ru_majflt;
	page_fault->minor = ru.ru_minflt;
	return 0;
}

static void diff_page_fault(void *ctx, void *dst, void *src)
{
	struct uftrace_page_fault *dst_pgflt = dst;
	struct uftrace_page_fault *src_pgflt = src;

	dst_pgflt->major -= src_pgflt->major;
	dst_pgflt->minor -= src_pgflt->minor;
}

static int save_pmu_cycle(void *ctx, void *buf)
{
	return read_pmu_event(ctx, EVENT_ID_READ_PMU_CYCLE, buf);
}

static void diff_pmu_cycle(void *ctx, void *dst, void *src)
{
	struct uftrace_pmu_cycle *dst_cycle = dst;
	struct uftrace_pmu_cycle *src_cycle = src;

	dst_cycle->cycles -= src_cycle->cycles;
	dst_cycle->instrs -= src_cycle->instrs;

	release_pmu_event(ctx, EVENT_ID_READ_PMU_CYCLE);
}

static int save_pmu_cache(void *ctx, void *buf)
{
	return read_pmu_event(ctx, EVENT_ID_READ_PMU_CACHE, buf);
}

static void diff_pmu_cache(void *ctx, void *dst, void *src)
{
	struct uftrace_pmu_cache *dst_cache = dst;
	struct uftrace_pmu_cache *src_cache = src;

	dst_cache->refers -= src_cache->refers;
	dst_cache->misses -= src_cache->misses;

	release_pmu_event(ctx, EVENT_ID_READ_PMU_CACHE);
}

static int save_pmu_branch(void *ctx, void *buf)
{
	return read_pmu_event(ctx, EVENT_ID_READ_PMU_BRANCH, buf);
}

static void diff_pmu_branch(void *ctx, void *dst, void *src)
{
	struct uftrace_pmu_branch *dst_branch = dst;
	struct uftrace_pmu_branch *src_branch = src;

	dst_branch->branch -= src_branch->branch;
	dst_branch->misses -= src_branch->misses;

	release_pmu_event(ctx, EVENT_ID_READ_PMU_BRANCH);
}

/* above functions should follow the name convention to use below macro */
#define TR_ID(_evt) TRIGGER_READ_##_evt, EVENT_ID_READ_##_evt, EVENT_ID_DIFF_##_evt
#define TR_DS(_evt) sizeof(struct uftrace_##_evt)
#define TR_FN(_evt) save_##_evt, diff_##_evt

static struct read_event_data {
	enum trigger_read_type type;
	enum uftrace_event_id id_read;
	enum uftrace_event_id id_diff;
	size_t size;
	int (*save)(void *ctx, void *buf);
	void (*diff)(void *ctx, void *dst, void *src);
} read_events[] = {
	{ TR_ID(PROC_STATM), TR_DS(proc_statm), TR_FN(proc_statm) },
	{ TR_ID(PAGE_FAULT), TR_DS(page_fault), TR_FN(page_fault) },
	{ TR_ID(PMU_CYCLE), TR_DS(pmu_cycle), TR_FN(pmu_cycle) },
	{ TR_ID(PMU_CACHE), TR_DS(pmu_cache), TR_FN(pmu_cache) },
	{ TR_ID(PMU_BRANCH), TR_DS(pmu_branch), TR_FN(pmu_branch) },
};

#undef TR_ID
#undef TR_DS
#undef TR_FN

void save_trigger_read(struct mcount_thread_data *mtdp, struct mcount_ret_stack *rstack,
		       enum trigger_read_type type, bool diff)
{
	void *ptr = get_argbuf(mtdp, rstack) + rstack->event_idx;
	struct mcount_event *event;
	unsigned short evsize;
	void *arg_data = get_argbuf(mtdp, rstack);
	size_t i;

	if (rstack->flags & (MCOUNT_FL_ARGUMENT | MCOUNT_FL_RETVAL))
		arg_data += *(uint32_t *)ptr;

	for (i = 0; i < ARRAY_SIZE(read_events); i++) {
		struct read_event_data *red = &read_events[i];

		if (!(type & red->type))
			continue;

		evsize = EVTBUF_HDR + red->size;
		event = ptr - evsize;

		/* do not overwrite argument data */
		if ((void *)event < arg_data)
			continue;

		event->id = red->id_read;
		event->time = rstack->end_time ?: rstack->start_time;
		event->dsize = red->size;
		event->idx = mtdp->idx;

		if (red->save(mtdp, event->data) < 0)
			continue;

		if (diff) {
			struct mcount_event *old_event = NULL;
			unsigned idx;

			for (idx = 0; idx < rstack->nr_events; idx++) {
				old_event = get_event_pointer(ptr, idx);
				if (old_event->id == event->id)
					break;

				old_event = NULL;
			}

			if (old_event) {
				event->id = red->id_diff;
				red->diff(mtdp, event->data, old_event->data);
			}
		}

		ptr = event;

		rstack->nr_events++;
		rstack->event_idx -= evsize;
	}
}

void save_watchpoint(struct mcount_thread_data *mtdp, struct mcount_ret_stack *rstack,
		     unsigned long watchpoints)
{
	uint64_t timestamp;
	ptrdiff_t rstack_idx;
	bool init_watch;

	timestamp = rstack->end_time ?: rstack->start_time;
	rstack_idx = rstack - mtdp->rstack;
	init_watch = !mtdp->watch.inited;

	if (init_watch) {
		/*
		 * Normally watch point event comes before the rstack (record)
		 * in order to indicate where it's changed precisely.
		 * But first watch point event needs to come after the first
		 * record otherwise it'd not show since 'event-skip' mechanism.
		 * Therefore, add 2(nsec) so that it can be 1 nsec later.
		 */
		timestamp += 2;
		mtdp->watch.inited = true;
	}

	/* save watch event before normal record */
	timestamp -= 1;

	if (watchpoints & MCOUNT_WATCH_CPU) {
		int cpu = sched_getcpu();

		if ((mtdp->watch.cpu != cpu || init_watch) && mtdp->nr_events < MAX_EVENT) {
			struct mcount_event *event;
			event = &mtdp->event[mtdp->nr_events++];

			event->id = EVENT_ID_WATCH_CPU;
			event->time = timestamp;
			event->idx = rstack_idx;
			event->dsize = sizeof(cpu);

			mcount_memcpy4(event->data, &cpu, sizeof(cpu));
		}
		mtdp->watch.cpu = cpu;
	}

	if (watchpoints & MCOUNT_WATCH_VAR) {
		struct mcount_watchpoint_item *w;
		unsigned long watch_data = 0;
		struct mcount_event *event;

		list_for_each_entry(w, &mtdp->watch.list, list) {
			if (mtdp->nr_events >= MAX_EVENT)
				continue;

			/* check the data without lock first */
			mcount_memcpy1(&watch_data, (void *)w->addr, w->size);
			if (!memcmp(&watch_data, w->data, w->size))
				continue;

			/* make sure only one thread updates the watch data */
			if (!mcount_watch_update(w->addr, &watch_data, w->size))
				continue;

			event = &mtdp->event[mtdp->nr_events++];

			event->id = EVENT_ID_WATCH_VAR;
			event->time = timestamp;
			event->idx = rstack_idx;
			event->dsize = sizeof(long) + w->size;

			mcount_memcpy4(event->data, &w->addr, sizeof(long));
			mcount_memcpy1(event->data + sizeof(long), &watch_data, w->size);
		}
	}
}

#else
/*
 * These are for fast libmcount libraries without filters.
 */

void *get_argbuf(struct mcount_thread_data *mtdp, struct mcount_ret_stack *rstack)
{
	return NULL;
}

void save_retval(struct mcount_thread_data *mtdp, struct mcount_ret_stack *rstack, long *retval)
{
}

void save_trigger_read(struct mcount_thread_data *mtdp, struct mcount_ret_stack *rstack,
		       enum trigger_read_type type)
{
}

void save_watchpoint(struct mcount_thread_data *mtdp, struct mcount_ret_stack *rstack,
		     unsigned long watchpoints)
{
}

bool check_mem_region(struct mcount_arg_context *ctx, unsigned long addr)
{
	return true;
}
#endif

static struct mcount_shmem_buffer *get_shmem_buffer(struct mcount_thread_data *mtdp, size_t size)
{
	struct mcount_shmem *shmem = &mtdp->shmem;
	struct mcount_shmem_buffer *curr_buf;
	size_t maxsize = (size_t)shmem_bufsize - sizeof(**shmem->buffer);

	if (unlikely(shmem->curr == -1 || shmem->buffer == NULL))
		goto get_buffer;

	curr_buf = shmem->buffer[shmem->curr];
	if (unlikely(curr_buf->size + size > maxsize)) {
get_buffer:
		if (shmem->done)
			return NULL;
		if (shmem->curr > -1)
			finish_shmem_buffer(mtdp, shmem->curr);
		get_new_shmem_buffer(mtdp);

		if (shmem->curr == -1) {
			shmem->losts++;
			return NULL;
		}

		curr_buf = shmem->buffer[shmem->curr];
	}

	return curr_buf;
}

static int record_event(struct mcount_thread_data *mtdp, struct mcount_event *event)
{
	struct mcount_shmem_buffer *curr_buf;
	struct {
		uint64_t time;
		uint64_t data;
	} * rec;
	size_t size = sizeof(*rec);
	uint16_t data_size = event->dsize;

	if (data_size)
		size += ALIGN(data_size + 2, 8);

	curr_buf = get_shmem_buffer(mtdp, size);
	if (curr_buf == NULL)
		return mtdp->shmem.done ? 0 : -1;

	rec = (void *)(curr_buf->data + curr_buf->size);

	/*
	 * instead of set bit fields, do the bit operations manually.
	 * this would be good for both performance and portability,
	 * and should be equivalent to the following:
	 *
	 *	struct uftrace_record *data = curr_buf->data + curr_buf->size;
	 *
	 *	data->time   = event->time;
	 *	data->type   = UFTRACE_EVENT;
	 *	data->magic  = RECORD_MAGIC;
	 *	data->more   = 0;
	 *	data->depth  = 0;
	 *	data->addr   = event->id;
	 */
	rec->data = UFTRACE_EVENT | RECORD_MAGIC << 3;
	rec->data += (uint64_t)event->id << 16;
	rec->time = event->time;

	if (data_size) {
		void *ptr = rec + 1;

		rec->data += 4; /* set 'more' bit in uftrace_record */

		*(uint16_t *)ptr = data_size;
		mcount_memcpy1(ptr + 2, event->data, data_size);
	}

	curr_buf->size += size;

	return 0;
}

static int record_ret_stack(struct mcount_thread_data *mtdp, enum uftrace_record_type type,
			    struct mcount_ret_stack *mrstack)
{
	struct uftrace_record *frstack;
	uint64_t timestamp = mrstack->start_time;
	struct mcount_shmem_buffer *curr_buf;
	size_t size = sizeof(*frstack);
	void *argbuf = NULL;
	uint64_t *buf;
	uint64_t rec;

	if (type == UFTRACE_EXIT)
		timestamp = mrstack->end_time;

	if (unlikely(mtdp->nr_events)) {
		/* save async events first (if any) */
		while (mtdp->nr_events && mtdp->event[0].time < timestamp) {
			record_event(mtdp, &mtdp->event[0]);
			mtdp->nr_events--;

			mcount_memcpy4(&mtdp->event[0], &mtdp->event[1],
				       sizeof(*mtdp->event) * mtdp->nr_events);
		}
	}

	if (type == UFTRACE_EXIT && unlikely(mrstack->nr_events)) {
		int i;
		unsigned evidx;
		struct mcount_event *event;

		argbuf = get_argbuf(mtdp, mrstack) + mrstack->event_idx;

		for (i = 0; i < mrstack->nr_events; i++) {
			evidx = mrstack->nr_events - i - 1;
			event = get_event_pointer(argbuf, evidx);

			if (event->time != timestamp)
				continue;

			/* save read2 trigger before exit record */
			record_event(mtdp, event);
		}

		mrstack->nr_events = 0;
		argbuf = NULL;
	}

	if ((type == UFTRACE_ENTRY && mrstack->flags & MCOUNT_FL_ARGUMENT) ||
	    (type == UFTRACE_EXIT && mrstack->flags & MCOUNT_FL_RETVAL)) {
		argbuf = get_argbuf(mtdp, mrstack);
		if (argbuf)
			size += *(unsigned *)argbuf;
	}

	curr_buf = get_shmem_buffer(mtdp, size);
	if (curr_buf == NULL)
		return mtdp->shmem.done ? 0 : -1;

	/*
	 * instead of set bit fields, do the bit operations manually.
	 * this would be good for both performance and portability,
	 * and should be equivalent to the following:
	 *
	 *	frstack = (void *)(curr_buf->data + curr_buf->size);
	 *
	 *	frstack->time   = timestamp;
	 *	frstack->type   = type;
	 *	frstack->magic  = RECORD_MAGIC;
	 *	frstack->more   = !!argbuf;
	 *	frstack->depth  = mrstack->depth;
	 *	frstack->addr   = mrstack->child_ip;
	 */
	rec = type | RECORD_MAGIC << 3;
	rec += argbuf ? 4 : 0;
	rec += mrstack->depth << 6;
	rec += (uint64_t)mrstack->child_ip << 16;

	buf = (void *)(curr_buf->data + curr_buf->size);
	buf[0] = timestamp;
	buf[1] = rec;

	curr_buf->size += sizeof(*frstack);
	mrstack->flags |= MCOUNT_FL_WRITTEN;

	if (argbuf) {
		unsigned int *ptr = (void *)curr_buf->data + curr_buf->size;

		size -= sizeof(*frstack);

		mcount_memcpy4(ptr, argbuf + 4, size);

		curr_buf->size += ALIGN(size, 8);
	}

	pr_dbg3("rstack[%d] %s %lx\n", mrstack->depth, type == UFTRACE_ENTRY ? "ENTRY" : "EXIT ",
		mrstack->child_ip);

	if (unlikely(mrstack->nr_events) && type == UFTRACE_ENTRY) {
		int i;
		unsigned evidx;
		struct mcount_event *event;

		argbuf = get_argbuf(mtdp, mrstack) + mrstack->event_idx;

		for (i = 0; i < mrstack->nr_events; i++) {
			evidx = mrstack->nr_events - i - 1;
			event = get_event_pointer(argbuf, evidx);

			if (event->time != timestamp)
				break;

			/* save read trigger after entry record */
			record_event(mtdp, event);
		}
	}

	return 0;
}

/*
 * For performance reasons and time filter, it doesn't record trace data one at
 * a time.  Instead it usually writes the data when an EXIT record is ready so
 * it needs to record ENTRY data in the current and may in the parent functions.
 *
 * For example, if it has a time filter for 1 usec.
 *
 * foo() {
 *   bar() {
 *     leaf1();   // takes 0.5 usec
 *     leaf2();   // takes 1.2 usec
 *
 * Then it can start to record when leaf2 function returns (at this moment,
 * mcount_ret_stack for leaf1 is gone) then it'd save the following records
 * (unless ENTRY foo or bar is saved by an earlier child before leaf[12]).
 *
 *   ENTRY (foo)
 *   ENTRY (bar)
 *   ENTRY (leaf2)
 *   EXIT  (leaf2)
 *
 * Then it adds MCOUNT_FL_WRITTEN flag to parent (foo and bar) so that they
 * never be written anymore by other child function.
 */
int record_trace_data(struct mcount_thread_data *mtdp, struct mcount_ret_stack *mrstack,
		      long *retval)
{
	struct mcount_ret_stack *non_written_mrstack = NULL;
	struct uftrace_record *frstack;
	size_t size = 0;
	int count = 0;

#define SKIP_FLAGS (MCOUNT_FL_NORECORD | MCOUNT_FL_DISABLED)

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
		count++; /* for exit */

	size += count * sizeof(*frstack);

	pr_dbg3("task %d recorded %zd bytes (record count = %d)\n", mcount_gettid(mtdp), size,
		count);

	while (non_written_mrstack && non_written_mrstack < mrstack) {
		if (!(non_written_mrstack->flags & SKIP_FLAGS)) {
			if (record_ret_stack(mtdp, UFTRACE_ENTRY, non_written_mrstack)) {
				mtdp->shmem.losts += count - 1;
				return 0;
			}

			count--;
		}
		non_written_mrstack++;
	}

	if (!(mrstack->flags & (MCOUNT_FL_WRITTEN | SKIP_FLAGS))) {
		if (record_ret_stack(mtdp, UFTRACE_ENTRY, mrstack))
			return 0;

		count--;
	}

	if (mrstack->end_time) {
		if (retval)
			save_retval(mtdp, mrstack, retval);
		else
			mrstack->flags &= ~MCOUNT_FL_RETVAL;

		if (record_ret_stack(mtdp, UFTRACE_EXIT, mrstack))
			return 0;

		count--;
	}

	ASSERT(count == 0);
	return 0;
}

static void write_map(FILE *out, struct uftrace_mmap *map, unsigned char major, unsigned char minor,
		      uint32_t ino, uint64_t off)
{
	/* write prev_map when it finds a new map */
	fprintf(out, "%" PRIx64 "-%" PRIx64 " %.4s %08" PRIx64 " %02x:%02x %-26u %s\n", map->start,
		map->end, map->prot, off, major, minor, ino, map->libname);
}

struct uftrace_mmap *new_map(const char *path, uint64_t start, uint64_t end, const char *prot)
{
	size_t namelen;
	struct uftrace_mmap *map;

	namelen = strlen(path) + 1;

	map = xzalloc(sizeof(*map) + ALIGN(namelen, 4));

	map->start = start;
	map->end = end;
	map->len = namelen;
	mcount_memcpy1(map->prot, prot, 4);
	mcount_memcpy1(map->libname, path, namelen);

	read_build_id(path, map->build_id, sizeof(map->build_id));

	return map;
}

void record_proc_maps(char *dirname, const char *sess_id, struct uftrace_sym_info *sinfo)
{
	FILE *ifp, *ofp;
	char buf[PATH_MAX];
	struct uftrace_mmap *prev_map = NULL;
	bool prev_written = false;

	ifp = fopen("/proc/self/maps", "r");
	if (ifp == NULL)
		pr_err("cannot open proc maps file");

	snprintf(buf, sizeof(buf), "%s/sid-%s.map", dirname, sess_id);

	ofp = fopen(buf, "w");
	if (ofp == NULL)
		pr_err("cannot open for writing maps file");

	sinfo->kernel_base = -1ULL;

	while (fgets(buf, sizeof(buf), ifp)) {
		unsigned long start, end;
		char prot[5];
		unsigned char major, minor;
		unsigned char prev_major = 0, prev_minor = 0;
		uint32_t ino, prev_ino = 0;
		uint64_t off, prev_off = 0;
		char path[PATH_MAX];
		struct uftrace_mmap *map;

		/* skip anon mappings */
		if (sscanf(buf, "%lx-%lx %s %" SCNx64 " %hhx:%hhx %u %s\n", &start, &end, prot,
			   &off, &major, &minor, &ino, path) != 8)
			continue;

		/*
		 * skip special mappings like [heap], [vdso] etc.
		 * but [stack] is still needed to get kernel base address.
		 */
		if (path[0] == '[') {
			if (prev_map && !prev_written) {
				write_map(ofp, prev_map, prev_major, prev_minor, prev_ino,
					  prev_off);
				prev_written = true;
			}
			if (strncmp(path, "[stack", 6) == 0) {
				sinfo->kernel_base = guess_kernel_base(buf);
				fprintf(ofp, "%s", buf);
			}
			continue;
		}

		if (prev_map != NULL) {
			/* extend prev_map to have all segments */
			if (!strcmp(path, prev_map->libname)) {
				prev_map->end = end;
				if (prot[2] == 'x')
					mcount_memcpy1(prev_map->prot, prot, 4);
				continue;
			}

			/* write prev_map when it finds a new map */
			if (!prev_written) {
				write_map(ofp, prev_map, prev_major, prev_minor, prev_ino,
					  prev_off);
				prev_written = true;
			}
		}

		map = new_map(path, start, end, prot);

		/* save map for the executable */
		if (!strcmp(path, sinfo->filename))
			sinfo->exec_map = map;

		if (prev_map)
			prev_map->next = map;
		else
			sinfo->maps = map;

		map->next = NULL;
		prev_map = map;
		prev_off = off;
		prev_ino = ino;
		prev_major = major;
		prev_minor = minor;
		prev_written = false;
	}

	fclose(ifp);
	fclose(ofp);
}
