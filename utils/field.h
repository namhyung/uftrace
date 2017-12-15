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

enum replay_field_id {
	REPLAY_F_NONE           = -1,
	REPLAY_F_DURATION,
	REPLAY_F_TID,
	REPLAY_F_ADDR,
	REPLAY_F_TIMESTAMP,
	REPLAY_F_TIMEDELTA,
	REPLAY_F_ELAPSED,
};

struct replay_field {
	struct list_head list;
	enum replay_field_id id;
	const char *name;
	const char *header;
	int length;
	bool used;
	void (*print)(struct field_data *fd);
};

void print_header(struct list_head *output_fields);
int print_field_data(struct list_head *output_fields, struct field_data *fd);
int print_empty_field(struct list_head *output_fields);
void add_field(struct list_head *output_fields, struct replay_field *field);

#endif /* UFTRACE_DISPLAY_FIELD_H */
