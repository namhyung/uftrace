#ifndef UFTRACE_KERNEL_PARSER_H
#define UFTRACE_KERNEL_PARSER_H

#include <stdbool.h>
#include <stdint.h>

#include "libtraceevent/event-parse.h"
#include "libtraceevent/kbuffer.h"
#include "uftrace.h"

/*
 * Wrappers for kernel function/event parser (using libtraceevent).
 */
struct uftrace_kernel_parser {
	/* global data */
	struct pevent *pevent;
	struct trace_seq seqbuf;
	struct uftrace_record rec;
	size_t pagesize;
	/* per-cpu data */
	struct kbuffer **kbufs;
	int *fds;
	void **mmaps;
	int64_t *offsets;
	int64_t *sizes;
	int *missed_events;
};

int kparser_init(struct uftrace_kernel_parser *kp);
int kparser_exit(struct uftrace_kernel_parser *kp);

bool kparser_ready(struct uftrace_kernel_parser *kp);
int kparser_strerror(struct uftrace_kernel_parser *kp, int err, char *buf, int len);

void kparser_set_info(struct uftrace_kernel_parser *kp, int page_size, int long_size,
		      bool is_big_endian);

int kparser_read_header(struct uftrace_kernel_parser *kp, char *buf, int len);
int kparser_read_event(struct uftrace_kernel_parser *kp, const char *sys, char *buf, int len);

int kparser_prepare_buffers(struct uftrace_kernel_parser *kp, int nr_cpus);
int kparser_release_buffers(struct uftrace_kernel_parser *kp, int nr_cpus);
int kparser_prepare_cpu(struct uftrace_kernel_parser *kp, const char *filename, int cpu);
int kparser_release_cpu(struct uftrace_kernel_parser *kp, int cpu);

void kparser_register_handler(struct uftrace_kernel_parser *kp, const char *sys, const char *event);
int kparser_read_data(struct uftrace_kernel_parser *kp, struct uftrace_data *handle, int cpu,
		      int *tid);
int kparser_data_size(struct uftrace_kernel_parser *kp, int cpu);
int kparser_missed_events(struct uftrace_kernel_parser *kp, int cpu);
void kparser_clear_missed(struct uftrace_kernel_parser *kp, int cpu);

void *kparser_trace_buffer(struct uftrace_kernel_parser *kp);
int kparser_trace_buflen(struct uftrace_kernel_parser *kp);

void *kparser_find_event(struct uftrace_kernel_parser *kp, int evt_id);
char *kparser_event_name(struct uftrace_kernel_parser *kp, void *evt, char *buf, int len);

/* low-level APIs - not encouraged to use */
int64_t __kparser_curr_offset(struct uftrace_kernel_parser *kp, int cpu);
void *__kparser_read_offset(struct uftrace_kernel_parser *kp, int cpu, int64_t off);
void *__kparser_next_event(struct uftrace_kernel_parser *kp, int cpu);
int __kparser_event_size(struct uftrace_kernel_parser *kp, int cpu);

#endif /* UFTRACE_KERNEL_PARSER_H */
