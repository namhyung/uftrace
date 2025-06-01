#ifndef UFTRACE_GRAPH_H
#define UFTRACE_GRAPH_H

#include <stdbool.h>
#include <stdint.h>

#include "uftrace.h"
#include "utils/fstack.h"
#include "utils/list.h"
#include "utils/rbtree.h"

struct graph_time_stat {
	uint64_t max;
	uint64_t min;
};

struct uftrace_graph_node {
	uint64_t addr;
	char *name;
	int nr_edges;
	int nr_calls;
	uint64_t time;
	uint64_t child_time;
	uint32_t id;
	struct list_head head;
	struct list_head list;
	struct uftrace_graph_node *parent;
	struct uftrace_dbg_loc *loc;
	struct graph_time_stat total;
	struct graph_time_stat self;
};

enum uftrace_graph_node_type {
	NODE_T_NORMAL,
	NODE_T_FORK,
	NODE_T_EXEC,
};

struct uftrace_special_node {
	struct list_head list;
	struct uftrace_graph_node *node;
	enum uftrace_graph_node_type type;
	int pid;
};

struct uftrace_graph {
	bool kernel_only;
	struct uftrace_session *sess;
	struct list_head special_nodes;
	struct uftrace_graph_node root;
};

struct uftrace_task_graph {
	bool lost;
	bool new_sess;
	struct uftrace_task_reader *task;
	struct uftrace_graph *graph;
	struct uftrace_graph_node *node;
	struct rb_node link;
};

typedef void (*graph_fn)(struct uftrace_task_graph *tg, void *arg);

void graph_init(struct uftrace_graph *graph, struct uftrace_session *s);
void graph_init_callbacks(graph_fn entry, graph_fn exit, graph_fn event, void *arg);
void graph_destroy(struct uftrace_graph *graph);

struct uftrace_task_graph *graph_get_task(struct uftrace_task_reader *task, size_t tg_size);
void graph_remove_task(void);

int graph_add_node(struct uftrace_task_graph *tg, int type, char *name, size_t node_size,
		   struct uftrace_dbg_loc *loc);
struct uftrace_graph_node *graph_find_node(struct uftrace_graph_node *parent, uint64_t addr);

#endif /* UFTRACE_GRAPH_H */
