#ifdef HAVE_LIBTRACEEVENT
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

/* This should be defined before #include "utils.h" */
#define PR_FMT "kernel"
#define PR_DOMAIN DBG_KERNEL

#include "uftrace.h"
#include "utils/kernel-parser.h"
#include "utils/kernel.h"
#include "utils/utils.h"

/* To check if there's (user) data for the task (tid) after read kernel data */
extern struct uftrace_task_reader *get_task_handle(struct uftrace_data *handle, int tid);

int kparser_init(struct uftrace_kernel_parser *kp)
{
	memset(kp, 0, sizeof(*kp));

	kp->tep = tep_alloc();
	if (kp->tep == NULL)
		return -1;

	trace_seq_init(&kp->seqbuf);
	return 0;
}

int kparser_exit(struct uftrace_kernel_parser *kp)
{
	tep_free(kp->tep);
	trace_seq_destroy(&kp->seqbuf);
	memset(kp, 0, sizeof(*kp));

	return 0;
}

bool kparser_ready(struct uftrace_kernel_parser *kp)
{
	return kp->tep != NULL;
}

int kparser_strerror(struct uftrace_kernel_parser *kp, int err, char *buf, int len)
{
	return tep_strerror(kp->tep, err, buf, len);
}

void kparser_set_info(struct uftrace_kernel_parser *kp, int page_size, int long_size,
		      bool is_big_endian)
{
	bool is_host_bigendian = (strcmp(get_endian_str(), "BE") == 0);

	kp->pagesize = page_size;

	tep_set_page_size(kp->tep, page_size);
	tep_set_long_size(kp->tep, long_size);
	tep_set_file_bigendian(kp->tep, is_big_endian);
	tep_set_local_bigendian(kp->tep, is_host_bigendian);
}

int kparser_read_header(struct uftrace_kernel_parser *kp, char *buf, int len)
{
	int long_size = tep_get_long_size(kp->tep);

	return tep_parse_header_page(kp->tep, buf, len, long_size);
}

int kparser_read_event(struct uftrace_kernel_parser *kp, const char *sys, char *buf, int len)
{
	return tep_parse_event(kp->tep, buf, len, sys);
}

int kparser_prepare_buffers(struct uftrace_kernel_parser *kp, int nr_cpus)
{
	kp->kbufs = xcalloc(nr_cpus, sizeof(*kp->kbufs));
	kp->fds = xcalloc(nr_cpus, sizeof(*kp->fds));
	kp->sizes = xcalloc(nr_cpus, sizeof(*kp->sizes));
	kp->mmaps = xcalloc(nr_cpus, sizeof(*kp->mmaps));
	kp->offsets = xcalloc(nr_cpus, sizeof(*kp->offsets));
	kp->missed_events = xcalloc(nr_cpus, sizeof(*kp->missed_events));

	return 0;
}

int kparser_release_buffers(struct uftrace_kernel_parser *kp, int nr_cpus)
{
	free(kp->kbufs);
	free(kp->fds);
	free(kp->sizes);
	free(kp->mmaps);
	free(kp->offsets);
	free(kp->missed_events);

	return 0;
}

static int kparser_prepare_kbuffer(struct uftrace_kernel_parser *kp, int cpu)
{
	kp->mmaps[cpu] =
		mmap(NULL, kp->pagesize, PROT_READ, MAP_PRIVATE, kp->fds[cpu], kp->offsets[cpu]);
	if (kp->mmaps[cpu] == MAP_FAILED) {
		pr_dbg("loading kbuffer for cpu %d (fd: %d, offset: %lu, pagesize: %zd) failed\n",
		       cpu, kp->fds[cpu], kp->offsets[cpu], kp->pagesize);
		return -1;
	}

	kbuffer_load_subbuffer(kp->kbufs[cpu], kp->mmaps[cpu]);
	kp->missed_events[cpu] = kbuffer_missed_events(kp->kbufs[cpu]);

	return 0;
}

int kparser_prepare_cpu(struct uftrace_kernel_parser *kp, const char *filename, int cpu)
{
	struct stat stbuf;
	enum kbuffer_endian endian = KBUFFER_ENDIAN_LITTLE;
	enum kbuffer_long_size longsize = KBUFFER_LSIZE_8;

	if (tep_is_file_bigendian(kp->tep))
		endian = KBUFFER_ENDIAN_BIG;
	if (tep_get_long_size(kp->tep) == 4)
		longsize = KBUFFER_LSIZE_4;

	kp->fds[cpu] = open(filename, O_RDONLY);
	if (kp->fds[cpu] < 0)
		return -1;

	if (fstat(kp->fds[cpu], &stbuf) < 0)
		return -1;

	kp->sizes[cpu] = stbuf.st_size;

	kp->kbufs[cpu] = kbuffer_alloc(longsize, endian);
	if (kp->kbufs[cpu] == NULL)
		return -1;

	if (tep_is_old_format(kp->tep))
		kbuffer_set_old_format(kp->kbufs[cpu]);

	if (!kp->sizes[cpu])
		return 0;

	return kparser_prepare_kbuffer(kp, cpu);
}

int kparser_release_cpu(struct uftrace_kernel_parser *kp, int cpu)
{
	close(kp->fds[cpu]);
	kp->fds[cpu] = -1;

	munmap(kp->mmaps[cpu], kp->pagesize);
	kp->mmaps[cpu] = NULL;

	kbuffer_free(kp->kbufs[cpu]);
	kp->kbufs[cpu] = NULL;
	return 0;
}

/* kernel trace event handlers */
static int funcgraph_entry_handler(struct trace_seq *s, struct tep_record *record,
				   struct tep_event *event, void *context)
{
	struct uftrace_kernel_parser *kp = context;
	unsigned long long depth;
	unsigned long long addr;

	if (tep_get_any_field_val(s, event, "depth", record, &depth, 1))
		return -1;

	if (tep_get_any_field_val(s, event, "func", record, &addr, 1))
		return -1;

	kp->rec.type = UFTRACE_ENTRY;
	kp->rec.time = record->ts;
	kp->rec.addr = addr;
	kp->rec.depth = depth;
	kp->rec.more = 0;

	return 0;
}

static int funcgraph_exit_handler(struct trace_seq *s, struct tep_record *record,
				  struct tep_event *event, void *context)
{
	struct uftrace_kernel_parser *kp = context;
	unsigned long long depth;
	unsigned long long addr;

	if (tep_get_any_field_val(s, event, "depth", record, &depth, 1))
		return -1;

	if (tep_get_any_field_val(s, event, "func", record, &addr, 1))
		return -1;

	kp->rec.type = UFTRACE_EXIT;
	kp->rec.time = record->ts;
	kp->rec.addr = addr;
	kp->rec.depth = depth;
	kp->rec.more = 0;

	return 0;
}

static int generic_event_handler(struct trace_seq *s, struct tep_record *record,
				 struct tep_event *event, void *context)
{
	struct uftrace_kernel_parser *kp = context;

	kp->rec.type = UFTRACE_EVENT;
	kp->rec.time = record->ts;
	kp->rec.addr = event->id;
	kp->rec.depth = 0;
	kp->rec.more = 1;

	/* for trace_seq to be filled according to its print_fmt */
	return 1;
}

void kparser_register_handler(struct uftrace_kernel_parser *kp, const char *sys, const char *event)
{
	if (!strcmp(sys, "ftrace")) {
		if (!strcmp(event, "funcgraph_entry"))
			tep_register_event_handler(kp->tep, -1, sys, event, funcgraph_entry_handler,
						   kp);
		else if (!strcmp(event, "funcgraph_exit"))
			tep_register_event_handler(kp->tep, -1, sys, event, funcgraph_exit_handler,
						   kp);
	}
	else
		tep_register_event_handler(kp->tep, -1, sys, event, generic_event_handler, kp);
}

static int kparser_next_page(struct uftrace_kernel_parser *kp, int cpu)
{
	munmap(kp->mmaps[cpu], kp->pagesize);
	kp->mmaps[cpu] = NULL;

	kp->offsets[cpu] += kp->pagesize;

	if (kp->offsets[cpu] >= (loff_t)kp->sizes[cpu])
		return 1;

	return kparser_prepare_kbuffer(kp, cpu);
}

/* return 0 on success, 1 on EOF or -1 on error */
int kparser_read_data(struct uftrace_kernel_parser *kp, struct uftrace_data *handle, int cpu,
		      int *ptid)
{
	void *data;
	int type, tid;
	unsigned long long timestamp;
	struct tep_record record;
	struct tep_event *event;
	struct kbuffer *kbuf = kp->kbufs[cpu];

	data = kbuffer_read_event(kbuf, &timestamp);
	while (!data) {
		int ret = kparser_next_page(kp, cpu);

		if (ret)
			return ret;
		data = kbuffer_read_event(kbuf, &timestamp);
	}

	record.ts = timestamp;
	record.cpu = cpu;
	record.data = data;
	record.offset = kbuffer_curr_offset(kbuf);
	record.missed_events = kbuffer_missed_events(kbuf);
	record.size = kbuffer_event_size(kbuf);
	record.record_size = kbuffer_curr_size(kbuf);
	//	record.ref_count = 1;
	//	record.locked = 1;

	type = tep_data_type(kp->tep, &record);
	if (type == 0)
		return -1; // padding

	event = tep_find_event(kp->tep, type);
	if (event == NULL) {
		pr_dbg("cannot find event for type: %d\n", type);
		return -1;
	}

	trace_seq_reset(&kp->seqbuf);
	/* this will call event handlers */
	tep_print_event(kp->tep, &kp->seqbuf, &record, "%s", TEP_PRINT_INFO);

	tid = tep_data_pid(kp->tep, &record);

	/*
	 * some event might be saved for unrelated task.  In this case
	 * pid for our child would be in a different field (not common_pid).
	 */
	if (kp->rec.type == UFTRACE_EVENT && get_task_handle(handle, tid) == NULL) {
		unsigned long long try_tid;

		/* for sched_switch event */
		if (tep_get_field_val(NULL, event, "next_pid", &record, &try_tid, 0) == 0 &&
		    get_task_handle(handle, try_tid) != NULL)
			tid = try_tid;
		/* for sched_wakeup event (or others) */
		else if (tep_get_field_val(NULL, event, "pid", &record, &try_tid, 0) == 0 &&
			 get_task_handle(handle, try_tid) != NULL)
			tid = try_tid;
	}

	*ptid = tid;
	kbuffer_next_event(kbuf, NULL);
	return 0;
}

int kparser_data_size(struct uftrace_kernel_parser *kp, int cpu)
{
	return kp->sizes[cpu];
}

/* This is valid only after kparser_read_data() */
void *kparser_trace_buffer(struct uftrace_kernel_parser *kp)
{
	return kp->seqbuf.buffer;
}

/* This is valid only after kparser_read_data() */
int kparser_trace_buflen(struct uftrace_kernel_parser *kp)
{
	return kp->seqbuf.len;
}

int kparser_missed_events(struct uftrace_kernel_parser *kp, int cpu)
{
	return kp->missed_events[cpu];
}

void kparser_clear_missed(struct uftrace_kernel_parser *kp, int cpu)
{
	kp->missed_events[cpu] = 0;
}

void *kparser_find_event(struct uftrace_kernel_parser *kp, int evt_id)
{
	return tep_find_event(kp->tep, evt_id);
}

char *kparser_event_name(struct uftrace_kernel_parser *kp, void *evt, char *buf, int len)
{
	struct tep_event *event = evt;

	snprintf(buf, len, "%s:%s", event->system, event->name);
	buf[len - 1] = '\0';
	return buf;
}

int64_t __kparser_curr_offset(struct uftrace_kernel_parser *kp, int cpu)
{
	return kp->offsets[cpu] + kbuffer_curr_offset(kp->kbufs[cpu]);
}

void *__kparser_read_offset(struct uftrace_kernel_parser *kp, int cpu, int64_t off)
{
	return kbuffer_read_at_offset(kp->kbufs[cpu], off, NULL);
}

void *__kparser_next_event(struct uftrace_kernel_parser *kp, int cpu)
{
	return kbuffer_next_event(kp->kbufs[cpu], NULL);
}

int __kparser_event_size(struct uftrace_kernel_parser *kp, int cpu)
{
	return kbuffer_event_size(kp->kbufs[cpu]);
}
#endif /* HAVE_LIBTRACEEVENT */
