#ifndef UFTRACE_FIELD_H
#define UFTRACE_FIELD_H

#include "utils/fstack.h"
#include "utils/list.h"

enum align_pos {
	ALIGN_LEFT,
	ALIGN_RIGHT,
};

/* data for field display */
struct field_data {
	struct uftrace_task_reader *task;
	struct uftrace_fstack *fstack;
	void *arg;
};

enum display_field_id {
	DISPLAY_F_NONE = -1,

	REPLAY_F_DURATION = 0,
	REPLAY_F_TID,
	REPLAY_F_ADDR,
	REPLAY_F_TIMESTAMP,
	REPLAY_F_TIMEDELTA,
	REPLAY_F_ELAPSED,
	REPLAY_F_TASK,
	REPLAY_F_MODULE,

	GRAPH_F_TOTAL_TIME = 0,
	GRAPH_F_SELF_TIME,
	GRAPH_F_ADDR,
	GRAPH_F_TOTAL_AVG,
	GRAPH_F_TOTAL_MAX,
	GRAPH_F_TOTAL_MIN,
	GRAPH_F_SELF_AVG,
	GRAPH_F_SELF_MAX,
	GRAPH_F_SELF_MIN,

	GRAPH_F_TASK_TOTAL_TIME = 0,
	GRAPH_F_TASK_SELF_TIME,
	GRAPH_F_TASK_TID,

	REPORT_F_TOTAL_TIME = 0,
	REPORT_F_TOTAL_TIME_AVG,
	REPORT_F_TOTAL_TIME_MIN,
	REPORT_F_TOTAL_TIME_MAX,

	REPORT_F_SELF_TIME,
	REPORT_F_SELF_TIME_AVG,
	REPORT_F_SELF_TIME_MIN,
	REPORT_F_SELF_TIME_MAX,

	REPORT_F_CALL,
	REPORT_F_SIZE,

	REPORT_F_TOTAL_TIME_STDV,
	REPORT_F_SELF_TIME_STDV,

	REPORT_F_TASK_TOTAL_TIME = 0,
	REPORT_F_TASK_SELF_TIME,
	REPORT_F_TASK_TID,
	REPORT_F_TASK_NR_FUNC,
};

struct display_field {
	struct list_head list;
	enum display_field_id id;
	const char *name;
	const char *header;
	int length;
	bool used;
	void (*print)(struct field_data *fd);
	const char *alias;
};

typedef void (*setup_default_field_t)(struct list_head *fields, struct uftrace_opts *,
				      struct display_field *p_field_table[]);

static inline uint64_t effective_addr(uint64_t addr)
{
	/* return 48-bit truncated address info */
	return addr & ((1ULL << 48) - 1);
}

void print_header(struct list_head *output_fields, const char *prefix, const char *postfix,
		  int space, bool new_line);
void print_header_align(struct list_head *output_fields, const char *prefix, const char *postfix,
			int space, enum align_pos align, bool new_line);
int print_field_data(struct list_head *output_fields, struct field_data *fd, int space);
int print_empty_field(struct list_head *output_fields, int space);
void add_field(struct list_head *output_fields, struct display_field *field);
void del_field(struct display_field *field);
void setup_field(struct list_head *output_fields, struct uftrace_opts *opts,
		 setup_default_field_t setup_default_field, struct display_field *field_table[],
		 size_t field_table_size);

#endif /* UFTRACE_FIELD_H */
