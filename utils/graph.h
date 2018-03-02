#ifndef UFTRACE_GRAPH_H
#define UFTRACE_GRAPH_H

#include <stdint.h>
#include <stdbool.h>

#include "uftrace.h"
#include "utils/list.h"
#include "utils/rbtree.h"
#include "utils/fstack.h"

struct uftrace_graph_node {
	uint64_t			addr;
	char				*name;
	int				nr_edges;
	int				nr_calls;
	uint64_t			time;
	uint64_t			child_time;
	struct list_head		head;
	struct list_head		list;
	struct uftrace_graph_node	*parent;
};

enum uftrace_graph_node_type {
	NODE_T_NORMAL,
	NODE_T_FORK,
	NODE_T_EXEC,
};

struct uftrace_special_node {
	struct list_head		list;
	struct uftrace_graph_node	*node;
	enum uftrace_graph_node_type	type;
	int				pid;
};

struct uftrace_graph {
	bool				kernel_only;
	struct uftrace_session		*sess;
	struct list_head		special_nodes;
	struct uftrace_graph_node	root;
};

struct uftrace_task_graph {
	bool				lost;
	bool				new_sess;
	struct ftrace_task_handle	*task;
	struct uftrace_graph		*graph;
	struct uftrace_graph_node	*node;
	struct rb_node			link;
};

typedef void(*graph_fn)(struct uftrace_task_graph *tg, void *arg);

void graph_init(struct uftrace_graph *graph, struct uftrace_session *s);
void graph_init_callbacks(graph_fn entry, graph_fn exit, graph_fn event,
			  void *arg);
void graph_destroy(struct uftrace_graph *graph);

struct uftrace_task_graph * graph_get_task(struct ftrace_task_handle *task,
					   size_t tg_size);
void graph_remove_task(void);

int graph_add_node(struct uftrace_task_graph *tg, int type, char *name);

#endif /* UFTRACE_GRAPH_H */
