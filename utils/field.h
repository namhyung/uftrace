#ifndef UFTRACE_FIELD_H
#define UFTRACE_FIELD_H

#include "utils/fstack.h"
#include "utils/list.h"

/* data for field display */
struct field_data {
	struct ftrace_task_handle *task;
	struct fstack *fstack;
	void *arg;
};

enum display_field_id {
	DISPLAY_F_NONE          = -1,

	REPLAY_F_DURATION       = 0,
	REPLAY_F_TID,
	REPLAY_F_ADDR,
	REPLAY_F_TIMESTAMP,
	REPLAY_F_TIMEDELTA,
	REPLAY_F_ELAPSED,
	REPLAY_F_TASK,
	REPLAY_F_MODULE,

	GRAPH_F_TOTAL_TIME      = 0,
	GRAPH_F_SELF_TIME,
	GRAPH_F_ADDR,
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

void print_header(struct list_head *output_fields, const char *prefix,
		  int space);
int print_field_data(struct list_head *output_fields, struct field_data *fd,
		     int space);
int print_empty_field(struct list_head *output_fields, int space);
void add_field(struct list_head *output_fields, struct display_field *field);
void setup_field(struct list_head *output_fields, struct opts *opts,
		 void (*setup_default_field)(struct list_head *fields, struct opts*),
		 struct display_field *field_table[], size_t field_table_size);

#endif /* UFTRACE_FIELD_H */
